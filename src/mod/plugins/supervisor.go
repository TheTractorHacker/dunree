package plugins

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"
)

/*
	Plugin supervisor (phase 1 of docs/plugins/reliability-plan.md)

	Optional, per plugin, off by default (PluginPolicy.Restart = never):

	- restart after an exit nobody asked for, with exponential backoff and jitter;
	- stop restarting when the plugin keeps dying (crash loop);
	- readiness: attach the plugin to the request path only once its port answers;
	- health check: probe the plugin and optionally end it when it stops answering.

	With the default policy nothing here acts: it only keeps the exit history and
	logs what a restart policy would have done.

	Locking: Plugin.lifeMu is held around every decision (start, stop, exit handling,
	the restart timer), Plugin.sup.mu only guards the small record below.
*/

const (
	defaultBackoffBase     = 1 * time.Second
	defaultBackoffMax      = 5 * time.Minute
	defaultCrashLoopMax    = 5 //unexpected exits ...
	defaultCrashLoopWindow = 10 * time.Minute
	defaultStableRun       = 1 * time.Minute //a process that ran this long resets the backoff
	defaultReadyPoll       = 100 * time.Millisecond
	defaultReadyTimeout    = 10 * time.Second
	defaultHealthInterval  = 10 * time.Second
	defaultHealthTimeout   = 2 * time.Second
	defaultHealthFailures  = 3
	backoffJitter          = 0.2 //each delay is multiplied by a random factor in [0.8, 1.2]
	exitHistoryMax         = 20
	unhealthyKillGrace     = 2 * time.Second
)

// supTunables can be overridden in tests, zero values = defaults
type supTunables struct {
	BackoffBase     time.Duration
	BackoffMax      time.Duration
	CrashLoopMax    int
	CrashLoopWindow time.Duration
	StableRun       time.Duration
	ReadyPoll       time.Duration
	ReadyTimeout    time.Duration
	HealthInterval  time.Duration
	HealthTimeout   time.Duration
	HealthFailures  int
}

func durOr(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func intOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func (c supTunables) backoffBase() time.Duration { return durOr(c.BackoffBase, defaultBackoffBase) }
func (c supTunables) backoffMax() time.Duration  { return durOr(c.BackoffMax, defaultBackoffMax) }
func (c supTunables) crashLoopMax() int          { return intOr(c.CrashLoopMax, defaultCrashLoopMax) }
func (c supTunables) crashLoopWindow() time.Duration {
	return durOr(c.CrashLoopWindow, defaultCrashLoopWindow)
}
func (c supTunables) stableRun() time.Duration    { return durOr(c.StableRun, defaultStableRun) }
func (c supTunables) readyPoll() time.Duration    { return durOr(c.ReadyPoll, defaultReadyPoll) }
func (c supTunables) readyTimeout() time.Duration { return durOr(c.ReadyTimeout, defaultReadyTimeout) }
func (c supTunables) healthInterval() time.Duration {
	return durOr(c.HealthInterval, defaultHealthInterval)
}
func (c supTunables) healthTimeout() time.Duration {
	return durOr(c.HealthTimeout, defaultHealthTimeout)
}
func (c supTunables) healthFailures() int { return intOr(c.HealthFailures, defaultHealthFailures) }

// backoffDelay is the wait before restart number step+1 in a row: base, 2x, 4x ... capped, without jitter
func (c supTunables) backoffDelay(step int) time.Duration {
	d := c.backoffBase()
	for i := 0; i < step; i++ {
		d *= 2
		if d >= c.backoffMax() {
			return c.backoffMax()
		}
	}
	if d > c.backoffMax() {
		d = c.backoffMax()
	}
	return d
}

// plainDuration words a duration for a message: "10 minutes", "45 seconds"
func plainDuration(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		if d == time.Minute {
			return "1 minute"
		}
		return strconv.Itoa(int(d/time.Minute)) + " minutes"
	}
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + " seconds"
}

func withJitter(d time.Duration) time.Duration {
	f := 1 - backoffJitter + rand.Float64()*2*backoffJitter
	return time.Duration(float64(d) * f)
}

// ExitRecord is one entry of the exit history of a plugin. Times are Unix seconds.
type ExitRecord struct {
	At          int64
	Kind        string //crashed | exited | stopped | failed_to_start | unhealthy
	ExitCode    int    //-1 when ended by a signal or when there was no process
	Reason      string //e.g. "exit status 3", "signal: killed"; worded by the OS or by Zoraxy, never plugin output
	UptimeSec   int64  //how long the process ran
	RestartInMs int64  //delay of the automatic restart that was planned after this exit, 0 = none
	Action      string //what the supervisor decided: restart | crash_loop | would_restart (policy never: log only) | none
	WouldInMs   int64  //Action would_restart: the delay a restart policy would have used
	Note        string //the same in words (English, for the log)
}

// Supervisor decisions (ExitRecord.Action)
const (
	ActionRestart      = "restart"
	ActionCrashLoop    = "crash_loop"
	ActionWouldRestart = "would_restart"
	ActionNone         = "none"
)

// supervisorState is the supervisor record of one plugin
type supervisorState struct {
	mu           sync.Mutex
	gen          uint64      //changes whenever the administrator starts or stops the plugin: an older pending restart is void
	timer        *time.Timer //pending automatic restart
	nextAt       time.Time
	step         int         //restarts in a row without a stable run in between
	recent       []time.Time //unexpected exits and failed automatic starts inside the crash-loop window
	crashLoop    bool
	loopMax      int //crash-loop limit that applied to the last decision (for the status)
	autoRestarts int
	history      []ExitRecord //oldest first, at most exitHistoryMax
}

func (s *supervisorState) addHistory(rec ExitRecord) {
	s.mu.Lock()
	if len(s.history) >= exitHistoryMax {
		copy(s.history, s.history[1:])
		s.history = s.history[:exitHistoryMax-1]
	}
	s.history = append(s.history, rec)
	s.mu.Unlock()
}

// annotateLast adds the decision of the supervisor to the newest history entry
func (s *supervisorState) annotateLast(action string, delay time.Duration, note string) {
	s.mu.Lock()
	if n := len(s.history); n > 0 {
		s.history[n-1].Action = action
		switch action {
		case ActionRestart:
			s.history[n-1].RestartInMs = delay.Milliseconds()
		case ActionWouldRestart:
			s.history[n-1].WouldInMs = delay.Milliseconds()
		}
		s.history[n-1].Note = note
	}
	s.mu.Unlock()
}

func (s *supervisorState) historyCopy() []ExitRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ExitRecord, len(s.history))
	copy(out, s.history)
	return out
}

// resetByAdmin voids a pending restart and forgets the crash loop. Called under lifeMu
// when the administrator (or an update / rebuild) starts or stops the plugin.
// It returns true when a restart was pending or the plugin was in a crash loop.
func (s *supervisorState) resetByAdmin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	had := s.timer != nil || s.crashLoop
	s.gen++
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.nextAt = time.Time{}
	s.step = 0
	s.recent = nil
	s.crashLoop = false
	return had
}

// cancelPendingRestart voids a waiting automatic restart (lifeMu held)
func (m *Manager) cancelPendingRestart(p *Plugin, why string) {
	p.sup.mu.Lock()
	pending := p.sup.timer != nil
	if pending {
		p.sup.timer.Stop()
		p.sup.timer = nil
		p.sup.gen++
		p.sup.nextAt = time.Time{}
	}
	p.sup.mu.Unlock()
	if !pending {
		return
	}
	p.mu.Lock()
	if p.status.state == StateRestarting {
		p.status.state = StateCrashed
		if p.status.hasExited && p.status.exitCode == 0 {
			p.status.state = StateExited
		}
	}
	p.mu.Unlock()
	m.Log("plugin "+p.Spec.ID+": the pending automatic restart was cancelled, "+why, nil)
}

// superviseFailure decides what happens after a plugin process ended without being
// asked to, or after an automatic start failed. lifeMu is held. failure is false for
// a clean exit (code 0). ranFor is how long the process ran (0 for a failed start).
func (m *Manager) superviseFailure(p *Plugin, failure bool, ranFor time.Duration) {
	if m.closing.Load() {
		return
	}
	cfg := m.supCfg
	pol := p.policy()
	want := pol.Restart == RestartAlways || (pol.Restart == RestartOnFailure && failure)
	now := time.Now()

	s := &p.sup
	s.mu.Lock()
	if ranFor >= cfg.stableRun() {
		s.step = 0
	}
	//Keep only the exits inside the crash-loop window
	keep := s.recent[:0]
	for _, t := range s.recent {
		if now.Sub(t) < cfg.crashLoopWindow() {
			keep = append(keep, t)
		}
	}
	s.recent = append(keep, now)
	recent := len(s.recent)
	s.loopMax = cfg.crashLoopMax()
	delay := withJitter(cfg.backoffDelay(s.step))
	gen := s.gen

	if !want {
		s.mu.Unlock()
		if failure && pol.Restart == RestartNever {
			//Log-only: say what the supervisor would have done
			note := fmt.Sprintf("not restarted (restart policy: never). With the policy on-failure it would be started again in about %s", delay.Round(10*time.Millisecond))
			p.sup.annotateLast(ActionWouldRestart, delay, note)
			m.Log("plugin "+p.Spec.ID+" "+note, nil)
		} else {
			p.sup.annotateLast(ActionNone, 0, "not restarted (restart policy: "+pol.Restart+")")
		}
		return
	}

	if recent >= cfg.crashLoopMax() {
		s.crashLoop = true
		s.nextAt = time.Time{}
		s.mu.Unlock()
		msg := fmt.Sprintf("Stopped restarting: the plugin ended %d times within %s. Fix the plugin, then press Start", recent, plainDuration(cfg.crashLoopWindow()))
		p.mu.Lock()
		if p.proc == nil {
			p.status.state = StateCrashLoop
			p.status.lastError = msg
			p.status.lastErrorAt = now
		}
		p.mu.Unlock()
		p.sup.annotateLast(ActionCrashLoop, 0, "crash loop: no more automatic restarts")
		m.Log("plugin "+p.Spec.ID+" is in a crash loop. "+msg, nil)
		return
	}

	s.step++
	s.nextAt = now.Add(delay)
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(delay, func() { m.autoRestart(p, gen) })
	s.mu.Unlock()

	p.mu.Lock()
	if p.proc == nil {
		p.status.state = StateRestarting
	}
	p.mu.Unlock()
	note := fmt.Sprintf("restart %d of at most %d in %s planned in %s", recent, cfg.crashLoopMax()-1, plainDuration(cfg.crashLoopWindow()), delay.Round(10*time.Millisecond))
	p.sup.annotateLast(ActionRestart, delay, note)
	m.Log("plugin "+p.Spec.ID+": "+note+" (restart policy: "+pol.Restart+")", nil)
}

// autoRestart runs when the backoff timer of a plugin fires
func (m *Manager) autoRestart(p *Plugin, gen uint64) {
	if m.closing.Load() {
		return
	}
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	p.sup.mu.Lock()
	if p.sup.gen != gen {
		//The administrator started or stopped the plugin in the meantime
		p.sup.mu.Unlock()
		return
	}
	p.sup.timer = nil
	p.sup.nextAt = time.Time{}
	p.sup.mu.Unlock()

	if m.closing.Load() || p.IsRunning() || p.policy().Restart == RestartNever {
		return
	}
	//The plugin may have been uninstalled while the timer was waiting
	if cur, err := m.GetPluginByID(p.Spec.ID); err != nil || cur != p {
		return
	}

	m.Log("plugin "+p.Spec.ID+": automatic restart", nil)
	if err := m.startPluginProcess(p); err != nil {
		p.noteStartFailure(err)
		m.revokePluginAPIKeys(p)
		p.sup.addHistory(ExitRecord{At: time.Now().Unix(), Kind: StateFailedToStart, ExitCode: -1, Reason: "automatic restart failed"})
		m.Log("plugin "+p.Spec.ID+": automatic restart failed", err)
		m.superviseFailure(p, true, 0)
		return
	}
	p.sup.mu.Lock()
	p.sup.autoRestarts++
	p.sup.mu.Unlock()
	m.UpdateTagsToPluginMaps()
}

/* Readiness and health */

// tcpAccepts reports whether the loopback port accepts a TCP connection
func tcpAccepts(port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeHealth asks the plugin whether it is alive: GET on the health path of its
// manifest when it declares one (any 2xx answer counts), else a TCP connect.
func (m *Manager) probeHealth(ctx context.Context, p *Plugin, port int) error {
	timeout := m.supCfg.healthTimeout()
	if p.Spec.HealthPath == "" {
		if !tcpAccepts(port, timeout) {
			return errors.New("the port of the plugin does not accept connections")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + normalizeEndpoint(p.Spec.HealthPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if tok := p.invokeToken(); tok != "" {
		req.Header.Set("X-Zoraxy-Plugin-Token", tok)
	}
	resp, err := hookHTTPClient.Do(req)
	if err != nil {
		return errors.New("the health endpoint did not answer")
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the health endpoint answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// watchProcess is the readiness / health goroutine of one plugin process. It is only
// started when the policy asks for the readiness gate or a health check.
func (m *Manager) watchProcess(p *Plugin, proc *pluginProc, pol PluginPolicy, port int) {
	cfg := m.supCfg
	started := time.Now()
	sleep := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-proc.done:
			return false
		case <-t.C:
			return true
		}
	}

	//Phase 1: wait for the port
	lateLogged := false
	for !tcpAccepts(port, portProbeTimeout) {
		late := time.Since(started) >= cfg.readyTimeout()
		if late && !lateLogged {
			lateLogged = true
			m.Log("plugin "+p.Spec.ID+" has not opened its port "+strconv.Itoa(port)+" after "+plainDuration(cfg.readyTimeout()), nil)
			p.noteError("The plugin did not open its port within " + plainDuration(cfg.readyTimeout()))
			if pol.HealthCheck == HealthCheckRestart {
				m.endUnhealthy(p, proc, "it did not open its port within "+plainDuration(cfg.readyTimeout()))
				return
			}
		}
		wait := cfg.readyPoll()
		if late {
			wait *= 10
		}
		if !sleep(wait) {
			return
		}
	}
	readyAfter := time.Since(started)
	attach := false
	p.mu.Lock()
	if p.proc == proc {
		p.status.readyKnown = true
		p.status.readyAfter = readyAfter
		if p.notReady {
			p.notReady = false
			attach = true
		}
	}
	p.mu.Unlock()
	if attach {
		m.Log("plugin "+p.Spec.ID+" is ready after "+readyAfter.Round(time.Millisecond).String()+", attached to the request path", nil)
		m.UpdateTagsToPluginMaps()
	} else {
		m.Log("plugin "+p.Spec.ID+" opened its port after "+readyAfter.Round(time.Millisecond).String(), nil)
	}

	//Phase 2: liveness
	if pol.HealthCheck == HealthCheckOff {
		return
	}
	for sleep(cfg.healthInterval()) {
		err := m.probeHealth(proc.ctx, p, port)
		if proc.exited() {
			return
		}
		if err == nil {
			if p.obs.healthFails.Swap(0) >= int32(cfg.healthFailures()) {
				m.Log("plugin "+p.Spec.ID+" passes its health check again", nil)
			}
			p.obs.healthOK.Add(1)
			p.noteAlive()
			continue
		}
		p.obs.healthFailTotal.Add(1)
		n := int(p.obs.healthFails.Add(1))
		if n == cfg.healthFailures() {
			p.noteError("The health check failed " + strconv.Itoa(n) + " times in a row: " + publicCallError(err))
			m.Log("plugin "+p.Spec.ID+" failed its health check "+strconv.Itoa(n)+" times in a row", err)
			if pol.HealthCheck == HealthCheckRestart {
				m.endUnhealthy(p, proc, "its health check failed "+strconv.Itoa(n)+" times in a row")
				return
			}
		}
	}
}

// endUnhealthy ends a plugin process that fails its health check. The exit is not
// "requested", so it is recorded as a failure and the restart policy applies.
func (m *Manager) endUnhealthy(p *Plugin, proc *pluginProc, why string) {
	if !proc.unhealthyWhy.CompareAndSwap(nil, &why) {
		return
	}
	m.Log("plugin "+p.Spec.ID+": ending the process (pid "+strconv.Itoa(proc.pid)+") because "+why, nil)
	signalPluginProcess(proc, syscall.SIGTERM)
	if !waitProcDone(proc, unhealthyKillGrace) {
		signalPluginProcess(proc, syscall.SIGKILL)
	}
}
