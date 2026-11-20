package main

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type fakeDrainer struct {
	delay time.Duration
	got   atomic.Int64
}

func (f *fakeDrainer) StopProxyServiceWithin(d time.Duration) error {
	f.got.Store(int64(d))
	time.Sleep(f.delay)
	return nil
}

func TestShutdownDrainDefaultsToEightSeconds(t *testing.T) {
	old := shutdownDrain
	defer func() { shutdownDrain = old }()
	if shutdownDrain == nil || *shutdownDrain != 8 {
		t.Fatalf("the -shutdown_drain default must be 8 (fits docker stop), got %v", shutdownDrain)
	}
	if shutdownDrainDuration() != 8*time.Second {
		t.Fatal("default drain is not 8 s")
	}
	zero, neg, forty := 0, -3, 40
	shutdownDrain = &zero
	if shutdownDrainDuration() != 0 {
		t.Error("0 must mean no drain")
	}
	shutdownDrain = &neg
	if shutdownDrainDuration() != defaultShutdownDrain {
		t.Error("a negative value falls back to the default")
	}
	shutdownDrain = &forty
	if shutdownDrainDuration() != 40*time.Second {
		t.Error("configured drain ignored")
	}
	if signalDrain() != signalDrainCap {
		t.Errorf("the SIGTERM path must cap the drain at %v, got %v", signalDrainCap, signalDrain())
	}
}

func TestDrainProxyIsBounded(t *testing.T) {
	var msgs []string
	var mu sync.Mutex
	logf := func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	fast := &fakeDrainer{delay: 20 * time.Millisecond}
	if gave := drainProxy(fast, time.Second, logf); gave || time.Duration(fast.got.Load()) != time.Second {
		t.Error("normal drain misreported")
	}
	// a drainer that hangs far beyond its deadline cannot hold the shutdown up
	hung := &fakeDrainer{delay: time.Minute}
	t0 := time.Now()
	gave := drainProxy(hung, 100*time.Millisecond, logf)
	if !gave || time.Since(t0) > 5*time.Second {
		t.Errorf("hung drain not abandoned: gave=%v after %v", gave, time.Since(t0))
	}
	// a panicking drainer is contained
	if drainProxy(panicDrainer{}, time.Second, logf) {
		t.Error("panic mishandled")
	}
}

type panicDrainer struct{}

func (panicDrainer) StopProxyServiceWithin(time.Duration) error { panic("boom") }

func TestStepRunnerBoundsEveryStep(t *testing.T) {
	var logged atomic.Int64
	s := newStepRunner(2*time.Second, func(string) { logged.Add(1) })
	s.limit = 100 * time.Millisecond
	ran := false
	t0 := time.Now()
	if s.run("hang", func() { time.Sleep(time.Minute) }) {
		t.Error("a hung step reported success")
	}
	if time.Since(t0) > time.Second {
		t.Errorf("hung step held shutdown for %v", time.Since(t0))
	}
	if !s.run("next", func() { ran = true }) || !ran {
		t.Error("the step after a hung one must still run")
	}
	if !s.run("panics", func() { panic("x") }) {
		// a panic is recovered and the step counts as finished
		t.Error("panicking step must not abort shutdown")
	}
	if logged.Load() == 0 {
		t.Error("nothing logged for the abandoned step")
	}
	// budget exhausted: remaining steps are skipped, not run
	b := newStepRunner(50*time.Millisecond, func(string) {})
	b.limit = time.Second
	b.run("eats budget", func() { time.Sleep(80 * time.Millisecond) })
	skipped := true
	if b.run("late", func() { skipped = false }) || !skipped {
		t.Error("a step past the overall budget must be skipped")
	}
}

func TestSecondSignalForcesQuit(t *testing.T) {
	c := make(chan os.Signal, 2)
	codes := make(chan int, 2)
	release := make(chan struct{})
	var before atomic.Bool
	go stopOnSignals(c, func() { before.Store(true) }, func() { <-release }, func(code int) { codes <- code }, func(string) {})
	c <- syscall.SIGTERM
	time.Sleep(100 * time.Millisecond)
	if !before.Load() {
		t.Error("stopping hook not run")
	}
	select {
	case <-codes:
		t.Fatal("exited before the sequence finished and without a second signal")
	default:
	}
	c <- syscall.SIGINT
	select {
	case code := <-codes:
		if code != 1 {
			t.Errorf("force quit code %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second signal ignored")
	}
	close(release)
}

func TestFirstSignalExitsZeroWhenSequenceFinishes(t *testing.T) {
	c := make(chan os.Signal, 2)
	codes := make(chan int, 1)
	go stopOnSignals(c, nil, func() { time.Sleep(50 * time.Millisecond) }, func(code int) { codes <- code }, func(string) {})
	c <- syscall.SIGTERM
	select {
	case code := <-codes:
		if code != 0 {
			t.Errorf("exit code %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no exit")
	}
}

// the force quit path still closes the database (bounded), and a message after the logger step does not touch the closed logger
func TestForceQuitRunsTheBoundedDBHookAndLateLogsUseTheStdLogger(t *testing.T) {
	c := make(chan os.Signal, 2)
	codes := make(chan int, 1)
	var hooked atomic.Bool
	old := forceQuitHook
	forceQuitHook = func() { hooked.Store(true) }
	defer func() { forceQuitHook = old }()
	go stopOnSignals(c, nil, func() { time.Sleep(5 * time.Second) }, func(code int) { codes <- code }, func(string) {})
	c <- syscall.SIGTERM
	time.Sleep(50 * time.Millisecond)
	c <- syscall.SIGTERM
	if code := <-codes; code != 1 || !hooked.Load() {
		t.Fatalf("code %d, hook %v", code, hooked.Load())
	}
	loggerClosed.Store(true)
	defer loggerClosed.Store(false)
	shutdownLog("late message after the logger closed") //must not panic or write to the closed logger
}
