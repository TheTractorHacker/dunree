package main

import (
	"log"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

/*
	Graceful stop (SIGTERM / SIGINT, Fleet restart, history restore, updater).

	- The state that lives in files and the database (blocked request log, visitor list, statistics, bandwidth
	  counters) is checkpointed first, so a supervisor that kills the process during the drain (docker stop
	  waits 10 s) loses almost nothing.
	- The proxy listeners are then closed and in-flight requests get -shutdown_drain seconds (default 8,
	  capped at 15 on SIGTERM and 10 for the updater, 0 = do not drain, the pre fork.21 behaviour) before they
	  are cut. Nothing can bind a listener again once this has started (dynamicproxy.ErrProxyStopping).
	- Every later step is bounded: a hung module is abandoned after shutdownStepLimit and the
	  whole tail of the sequence shares shutdownStepBudget.
	- A second SIGTERM / SIGINT while stopping is a force quit (two signals that arrive before the first one is read count
	  as a second one). It still tries to close the system database for at most one second before it exits.
	- Worst case of a SIGTERM stop: 2 s checkpoint + 15 s drain + 3 s guard + 8 s steps = 28 s, inside the 30 s
	  TimeoutStopSec of docs/deploy/zoraxy.service; a typical stop takes milliseconds.
	- Hijacked connections (WebSocket and other upgrades) are not tracked by net/http: they are
	  closed when the process exits, which is best effort and not drained.
*/

const (
	defaultShutdownDrain = 8 * time.Second
	signalDrainCap       = 15 * time.Second // the SIGTERM / restart path never drains longer, whatever -shutdown_drain says
	checkpointBudget     = 2 * time.Second
	shutdownStepLimit    = 3 * time.Second
	shutdownStepBudget   = 8 * time.Second
	updaterDrainCap      = 10 * time.Second // updater waits 20 s for its hook: 10 s drain + 8 s steps
)

var (
	loggerClosed    atomic.Bool // set by the last step: later messages go to the standard logger
	forceQuitHook   = closeDBOnForceQuit
	shutdownMu      sync.Mutex
	shutdownRunning bool
	shutdownDone    chan struct{}
)

func shutdownDrainDuration() time.Duration {
	if shutdownDrain == nil {
		return defaultShutdownDrain
	}
	if *shutdownDrain < 0 {
		return defaultShutdownDrain
	}
	return time.Duration(*shutdownDrain) * time.Second
}

type proxyDrainer interface {
	StopProxyServiceWithin(time.Duration) error
}

// drainProxy stops the proxy listeners and waits at most drain (plus a small guard) for in-flight
// requests. It reports whether it had to give up waiting.
func drainProxy(p proxyDrainer, drain time.Duration, logf func(string)) (gaveUp bool) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recover() }()
		p.StopProxyServiceWithin(drain)
	}()
	select {
	case <-done:
		return false
	case <-time.After(drain + 3*time.Second):
		logf("Proxy drain did not finish in time, continuing shutdown")
		return true
	}
}

// stepRunner runs shutdown steps, each in its own goroutine with a time limit, and stops running
// further steps once the shared budget is used up.
type stepRunner struct {
	deadline time.Time
	logf     func(string)
	limit    time.Duration
}

func newStepRunner(budget time.Duration, logf func(string)) *stepRunner {
	return &stepRunner{deadline: time.Now().Add(budget), logf: logf, limit: shutdownStepLimit}
}

func (s *stepRunner) run(name string, fn func()) bool {
	left := time.Until(s.deadline)
	if left <= 0 {
		s.logf("Shutdown budget used up, skipping: " + name)
		return false
	}
	limit := s.limit
	if left < limit {
		limit = left
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				s.logf("Shutdown step " + name + " panicked")
			}
		}()
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(limit):
		s.logf("Shutdown step timed out, abandoning: " + name)
		return false
	}
}

// stopOnSignals waits for the first signal, runs seq, and exits 0 when it finishes. A second signal
// while seq runs exits immediately with status 1 (force quit). exit and the channel are injectable for tests.
func stopOnSignals(c <-chan os.Signal, before func(), seq func(), exit func(int), logf func(string)) {
	<-c
	if before != nil {
		before()
	}
	done := make(chan struct{})
	go func() { seq(); close(done) }()
	select {
	case <-done:
		exit(0)
	case <-c:
		logf("Second stop signal received, forcing exit")
		if forceQuitHook != nil {
			forceQuitHook()
		}
		exit(1)
	}
}

var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// closeDBOnForceQuit gives the system database one second to close cleanly before a forced exit
func closeDBOnForceQuit() {
	if sysdb == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recover() }()
		sysdb.Close()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

// signalDrain is the drain of the SIGTERM / restart path: -shutdown_drain, but never more than signalDrainCap
func signalDrain() time.Duration {
	d := shutdownDrainDuration()
	if d > signalDrainCap {
		shutdownLog("-shutdown_drain " + d.String() + " is longer than " + signalDrainCap.String() + ", using " + signalDrainCap.String() + " so the stop fits a service manager timeout")
		d = signalDrainCap
	}
	return d
}

func shutdownLog(m string) {
	if loggerClosed.Load() {
		log.Println(m) //the logger step already ran
	} else if SystemWideLogger != nil {
		SystemWideLogger.Println(m)
	} else {
		log.Println(m)
	}
}
