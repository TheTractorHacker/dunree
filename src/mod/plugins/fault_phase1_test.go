package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/info/logger"
	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin/events"
)

/*
	Fault-injection suite, phase 1 of docs/plugins/reliability-plan.md: supervision.

	Same method as fault_test.go: the real chaos plugin, started through the real
	lifecycle code. Every option tested here is off by default, and each group has
	one test that shows the default did not change.
*/

// fastSupervisor shortens the supervisor timings so the suite stays quick
func fastSupervisor(m *Manager) {
	m.supCfg = supTunables{
		BackoffBase:     100 * time.Millisecond,
		BackoffMax:      2 * time.Second,
		CrashLoopMax:    5,
		CrashLoopWindow: time.Minute,
		StableRun:       10 * time.Second,
		ReadyPoll:       20 * time.Millisecond,
		ReadyTimeout:    600 * time.Millisecond,
		HealthInterval:  80 * time.Millisecond,
		HealthTimeout:   150 * time.Millisecond,
		HealthFailures:  3,
	}
}

func setPolicy(t testing.TB, m *Manager, p *Plugin, change func(pp *PluginPolicy)) {
	t.Helper()
	if err := m.SetPluginPolicy(p.Spec.ID, change); err != nil {
		t.Fatalf("SetPluginPolicy: %v", err)
	}
}

// loadChaosStopped is loadChaos with the port probe of the suite on, without starting the plugin
func loadChaosStopped(t *testing.T, m *Manager, folder string, conf string, tags ...string) *Plugin {
	t.Helper()
	m.Options.ProbePluginPorts = true
	return loadChaos(t, m, folder, conf, tags...)
}

func mustStart(t *testing.T, m *Manager, p *Plugin) {
	t.Helper()
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatalf("StartPlugin: %v", err)
	}
}

// endSupervision makes sure no restart timer of the test outlives it
func endSupervision(t *testing.T, m *Manager) {
	t.Cleanup(func() { m.Close() })
}

/* Restart policy */

func TestFaultRestartPolicyNeverIsTheDefaultAndOnlyLogs(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := startChaos(t, m, "norestart", "mode=crash\ndelay=50ms\n", "t")
	if pol := p.policy(); pol.Restart != RestartNever || pol.HealthCheck != HealthCheckOff || pol.ReadinessGate || pol.BlockWhenDown ||
		pol.CaptureTimeoutMs != 0 || pol.LogTarget != LogTargetMain || pol.LogRateLimit != 0 || pol.hasLimits() {
		t.Fatalf("the default policy must switch everything off, got %+v", pol)
	}
	waitState(t, p, StateCrashed)
	time.Sleep(600 * time.Millisecond) //several backoff delays of this test
	st := p.Status()
	if st.State != StateCrashed || st.StartCount != 1 || st.AutoRestartCount != 0 || st.NextRestartAt != 0 {
		t.Fatalf("with the default policy a crashed plugin must stay crashed: %+v", st)
	}
	hist := p.sup.historyCopy()
	if len(hist) != 1 || hist[0].Kind != StateCrashed || hist[0].ExitCode != 3 || hist[0].RestartInMs != 0 {
		t.Fatalf("unexpected exit history %+v", hist)
	}
	if !strings.Contains(hist[0].Note, "not restarted (restart policy: never)") || !strings.Contains(hist[0].Note, "it would be started again in about") {
		t.Fatalf("the log-only note is missing: %q", hist[0].Note)
	}
}

func TestFaultCrashRestartsWithBackoffThenCrashLoopStops(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "looper", "mode=crash\ndelay=30ms\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	begin := time.Now()
	mustStart(t, m, p)

	eventually(t, 15*time.Second, "the crash loop to be detected", func() bool { return p.Status().State == StateCrashLoop })
	elapsed := time.Since(begin)
	st := p.Status()
	if st.StartCount != 5 || st.AutoRestartCount != 4 || st.RecentFailures != 5 || st.CrashLoopLimit != 5 {
		t.Fatalf("5 exits must end the restarts after 4 automatic restarts: %+v", st)
	}
	if !strings.Contains(st.LastError, "Stopped restarting") {
		t.Fatalf("the status must say why nothing is restarted: %q", st.LastError)
	}

	//Backoff: 100, 200, 400, 800 ms, each with at most 20 % jitter
	hist := p.sup.historyCopy()
	if len(hist) != 5 {
		t.Fatalf("expected 5 history entries, got %d: %+v", len(hist), hist)
	}
	var planned time.Duration
	for i, want := range []int64{100, 200, 400, 800} {
		got := hist[i].RestartInMs
		if got < want*8/10 || got > want*12/10 {
			t.Fatalf("restart %d was planned in %d ms, want %d ms +/- 20 %%. History: %+v", i+1, got, want, hist)
		}
		planned += time.Duration(got) * time.Millisecond
	}
	if hist[4].RestartInMs != 0 || !strings.Contains(hist[4].Note, "crash loop") {
		t.Fatalf("the last exit must not plan a restart: %+v", hist[4])
	}
	if elapsed < planned {
		t.Fatalf("the restarts came faster (%s) than the planned delays (%s)", elapsed, planned)
	}

	//Nothing is started any more
	time.Sleep(1200 * time.Millisecond)
	if got := p.Status(); got.StartCount != 5 || got.State != StateCrashLoop || m.PluginIsRunning(p.Spec.ID) {
		t.Fatalf("a plugin in a crash loop was started again: %+v", got)
	}

	//The administrator can: Start resets the loop
	mustStart(t, m, p)
	if got := p.Status(); got.StartCount != 6 || got.RecentFailures != 0 {
		t.Fatalf("a manual start must reset the crash loop: %+v", got)
	}
}

func TestFaultBackoffDelaysAndCap(t *testing.T) {
	var def supTunables
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second, 128 * time.Second, 256 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for step, w := range want {
		if got := def.backoffDelay(step); got != w {
			t.Fatalf("default backoff step %d = %s, want %s", step, got, w)
		}
	}
	if got := def.backoffDelay(500); got != 5*time.Minute {
		t.Fatalf("the backoff must stay at its cap, got %s", got)
	}
	lo, hi := time.Hour, time.Duration(0)
	for i := 0; i < 2000; i++ {
		d := withJitter(time.Second)
		if d < lo {
			lo = d
		}
		if d > hi {
			hi = d
		}
	}
	if lo < 800*time.Millisecond || hi > 1200*time.Millisecond || hi-lo < 200*time.Millisecond {
		t.Fatalf("jitter must spread a 1 s delay over 0.8 s to 1.2 s, got %s to %s", lo, hi)
	}
}

func TestFaultCrashOnceIsRestartedAndWorksAgain(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "phoenix", "mode=crash_once\ndelay=40ms\nfeatures=hooks,static,api\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	mustStart(t, m, p)

	eventually(t, 5*time.Second, "the plugin to be restarted by the supervisor", func() bool {
		st := p.Status()
		return st.State == StateRunning && st.AutoRestartCount == 1
	})
	waitHealth(t, p, HealthOK)
	st := p.Status()
	if st.StartCount != 2 || st.RestartCount != 1 || !st.Attached {
		t.Fatalf("unexpected status after the automatic restart: %+v", st)
	}
	//The restarted process is fully attached again: filter, capture and a fresh API key
	before := p.obs.calls.Load()
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("an allow verdict must not handle the request")
	}
	if p.obs.calls.Load() != before+1 || p.obs.callFails.Load() != 0 {
		t.Fatalf("the restarted plugin was not called: calls %d fails %d", p.obs.calls.Load(), p.obs.callFails.Load())
	}
	rec := httptest.NewRecorder()
	r := newReq(http.MethodGet, "http://app.example/chaos-static/x", "")
	r.RequestURI = "/chaos-static/x"
	if !m.HandleRoute(rec, r, []string{"t"}, "198.51.100.9") || !strings.Contains(rec.Body.String(), "captured by chaos plugin") {
		t.Fatalf("static capture after the automatic restart: status %d body %q", rec.Code, rec.Body.String())
	}
	if key := configuredAPIKey(p.RootDir); key == "" {
		t.Fatal("no API key after the restart")
	} else if _, err := m.Options.APIKeyManager.ValidateAPIKey(key); err != nil {
		t.Fatalf("the API key of the restarted plugin is not valid: %v", err)
	}
	//It keeps running: no further restart
	time.Sleep(400 * time.Millisecond)
	if got := p.Status(); got.StartCount != 2 || got.State != StateRunning {
		t.Fatalf("a healthy plugin was restarted again: %+v", got)
	}
}

func TestFaultCleanExitOnFailureStaysDownAlwaysRestarts(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "quitter", "mode=exit0\ndelay=40ms\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	mustStart(t, m, p)
	waitState(t, p, StateExited)
	time.Sleep(400 * time.Millisecond)
	if st := p.Status(); st.State != StateExited || st.StartCount != 1 {
		t.Fatalf("on-failure must not restart a plugin that exited with code 0: %+v", st)
	}

	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartAlways })
	mustStart(t, m, p)
	eventually(t, 5*time.Second, "always to restart a clean exit", func() bool { return p.Status().AutoRestartCount >= 1 })
}

func TestFaultStopAndPolicyChangeCancelAPendingRestart(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	m.supCfg.BackoffBase = 500 * time.Millisecond
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "waiter", "mode=crash\ndelay=30ms\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	mustStart(t, m, p)

	st := waitState(t, p, StateRestarting)
	if st.NextRestartAt == 0 {
		t.Fatalf("a waiting restart must say when it happens: %+v", st)
	}
	//Stop (the button calls DisablePlugin) wins over the waiting restart
	if err := m.DisablePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if got := p.Status(); got.State != StateStopped || got.NextRestartAt != 0 {
		t.Fatalf("after Stop the plugin must be plain stopped: %+v", got)
	}
	time.Sleep(900 * time.Millisecond)
	if got := p.Status(); got.StartCount != 1 || got.State != StateStopped {
		t.Fatalf("a stopped plugin was restarted by an old timer: %+v", got)
	}

	//Setting the policy back to never also cancels it
	mustStart(t, m, p)
	waitState(t, p, StateRestarting)
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartNever })
	if got := p.Status(); got.State != StateCrashed {
		t.Fatalf("with the policy back to never the plugin is simply crashed: %+v", got)
	}
	time.Sleep(900 * time.Millisecond)
	if got := p.Status(); got.StartCount != 2 {
		t.Fatalf("the plugin was restarted after the policy was set to never: %+v", got)
	}
}

func TestFaultCloseEndsSupervision(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	m.supCfg.BackoffBase = 300 * time.Millisecond
	p := loadChaosStopped(t, m, "closer", "mode=crash\ndelay=30ms\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartAlways })
	mustStart(t, m, p)
	waitState(t, p, StateRestarting)
	m.Close()
	time.Sleep(700 * time.Millisecond)
	if got := p.Status(); got.StartCount != 1 || m.PluginIsRunning(p.Spec.ID) {
		t.Fatalf("a plugin was restarted after the manager was closed: %+v", got)
	}
}

/* Readiness and health */

func TestFaultReadinessGateAttachesOnlyWhenListening(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)

	//Default (no gate): attached at once, as always
	plain := loadChaosStopped(t, m, "eager", "mode=slow_start\ndelay=400ms\n", "t")
	mustStart(t, m, plain)
	if st := plain.Status(); !st.Attached || plain.pathState() != pathActive || st.ReadyAfterMs != -1 {
		t.Fatalf("without the readiness gate a plugin is attached at once and nothing is measured: %+v", st)
	}
	m.StopPlugin(plain.Spec.ID)

	p := loadChaosStopped(t, m, "patient", "mode=slow_start\ndelay=400ms\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.ReadinessGate = true })
	mustStart(t, m, p)
	st := p.Status()
	if st.State != StateRunning || st.Attached || st.Health != HealthStarting || p.pathState() != pathDown {
		t.Fatalf("with the gate a plugin that does not listen yet must not be attached: %+v", st)
	}
	//Requests pass without waiting for a refused connection, and the plugin is not called
	if res, _, d := runPreAuth(m); res.Handled || d > 100*time.Millisecond || p.obs.calls.Load() != 0 {
		t.Fatalf("a plugin that is not ready was called: handled=%v after %s, calls=%d", res.Handled, d, p.obs.calls.Load())
	}
	rec := httptest.NewRecorder()
	r := newReq(http.MethodGet, "http://app.example/chaos-static/x", "")
	r.RequestURI = "/chaos-static/x"
	if m.HandleRoute(rec, r, []string{"t"}, "198.51.100.9") {
		t.Fatalf("the capture path of a plugin that is not ready must not be attached: status %d", rec.Code)
	}

	eventually(t, 5*time.Second, "the plugin to be attached when its port opens", func() bool { return p.Status().Attached })
	st = p.Status()
	if st.ReadyAfterMs < 300 || st.ReadyAfterMs > 3000 || st.Health != HealthOK {
		t.Fatalf("time to ready must be measured (about 400 ms): %+v", st)
	}
	if res, _, _ := runPreAuth(m); res.Handled || p.obs.calls.Load() != 1 {
		t.Fatalf("the ready plugin must be called: calls=%d", p.obs.calls.Load())
	}
}

func TestFaultHealthCheckReportsAHungPlugin(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "frozen", "mode=hang\nfeatures=hooks,health\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.HealthCheck = HealthCheckReport })
	mustStart(t, m, p)
	pid := p.Status().PID
	eventually(t, 5*time.Second, "the health check to fail", func() bool { return p.Status().Health == HealthUnhealthy })
	st := p.Status()
	if st.State != StateRunning || st.PID != pid || !pidAlive(pid) || st.Counters.HealthChecksFail < 3 {
		t.Fatalf("report mode must only report: %+v", st)
	}
	if !strings.Contains(st.LastError, "health check failed 3 times") {
		t.Fatalf("LastError %q", st.LastError)
	}
	time.Sleep(400 * time.Millisecond)
	if got := p.Status(); got.StartCount != 1 || got.PID != pid {
		t.Fatalf("report mode ended the plugin: %+v", got)
	}
}

func TestFaultHealthCheckSeesHTTP500(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "sick", "mode=unhealthy\nfeatures=hooks,health\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.HealthCheck = HealthCheckReport })
	mustStart(t, m, p)
	eventually(t, 5*time.Second, "an HTTP 500 from /health to count as unhealthy", func() bool { return p.Status().Health == HealthUnhealthy })

	//A healthy plugin stays healthy
	ok := loadChaosStopped(t, m, "fit", "mode=ok\nfeatures=hooks,health\n", "t")
	setPolicy(t, m, ok, func(pp *PluginPolicy) { pp.HealthCheck = HealthCheckReport })
	mustStart(t, m, ok)
	eventually(t, 5*time.Second, "health checks to pass", func() bool { return ok.Status().Counters.HealthChecksOK >= 3 })
	if st := ok.Status(); st.Health != HealthOK || st.Counters.HealthChecksFail != 0 || st.ReadyAfterMs < 0 {
		t.Fatalf("a healthy plugin: %+v", st)
	}
}

func TestFaultHealthCheckRestartsAHungPlugin(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "zombie", "mode=hang\nfeatures=hooks,health\n", "t")
	if err := m.SetPluginPolicy(p.Spec.ID, func(pp *PluginPolicy) { pp.HealthCheck = HealthCheckRestart }); err == nil {
		t.Fatal("health check 'restart' without a restart policy must be refused: the plugin would stay stopped")
	}
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure; pp.HealthCheck = HealthCheckRestart })
	mustStart(t, m, p)
	firstPID := p.Status().PID
	eventually(t, 8*time.Second, "the hung plugin to be ended and started again", func() bool {
		st := p.Status()
		return st.AutoRestartCount >= 1 && st.State == StateRunning && st.PID != firstPID
	})
	if pidAlive(firstPID) {
		t.Fatal("the hung process is still alive")
	}
	hist := p.sup.historyCopy()
	if len(hist) == 0 || hist[0].Kind != "unhealthy" || hist[0].RestartInMs == 0 {
		t.Fatalf("the history must say the plugin was ended for its health: %+v", hist)
	}
}

// Known limit, documented: without a health path the probe is a TCP connect, which a hung handler passes
func TestFaultHealthCheckTCPOnlyCannotSeeAHungHandler(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "numb", "mode=hang\nfeatures=hooks\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.HealthCheck = HealthCheckReport })
	mustStart(t, m, p)
	eventually(t, 5*time.Second, "TCP health checks to pass", func() bool { return p.Status().Counters.HealthChecksOK >= 3 })
	if st := p.Status(); st.Health != HealthOK {
		t.Fatalf("behaviour changed: a TCP-only probe now sees a hung handler (%+v). Update the known limits in the plan", st)
	}
}

func TestFaultNeverListeningIsEndedByHealthRestart(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "mute", "mode=hang_start\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) {
		pp.Restart = RestartOnFailure
		pp.HealthCheck = HealthCheckRestart
		pp.ReadinessGate = true
	})
	mustStart(t, m, p)
	eventually(t, 15*time.Second, "a plugin that never listens to end in a crash loop", func() bool { return p.Status().State == StateCrashLoop })
	if p.obs.calls.Load() != 0 {
		t.Fatal("a plugin that never became ready was called")
	}
}

/* Timeout and breaker on the capture and UI paths */

func captureOnce(m *Manager, ctx context.Context) (bool, *httptest.ResponseRecorder, time.Duration) {
	rec := httptest.NewRecorder()
	r := newReq(http.MethodGet, "http://app.example/chaos-static/x", "")
	r.RequestURI = "/chaos-static/x"
	if ctx != nil {
		r = r.WithContext(ctx)
	}
	start := time.Now()
	handled := m.HandleRoute(rec, r, []string{"t"}, "198.51.100.9")
	return handled, rec, time.Since(start)
}

func uiOnce(m *Manager, p *Plugin) (*httptest.ResponseRecorder, time.Duration) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/plugin.ui/"+p.Spec.ID+"/", nil)
	req.RequestURI = "/plugin.ui/" + p.Spec.ID + "/"
	start := time.Now()
	m.HandlePluginUI(p.Spec.ID, rec, req)
	return rec, time.Since(start)
}

func TestFaultHungCaptureDefaultStillWaits(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "tarpit", "mode=hang\n", "t")
	waitHealth(t, p, HealthOK)
	//Default: no capture timeout. The request ends only because the visitor gives up
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	handled, rec, d := captureOnce(m, ctx)
	if !handled || d < 450*time.Millisecond {
		t.Fatalf("behaviour changed: a hung capture without a capture timeout returned after %s (status %d)", d, rec.Code)
	}
	if rec.Code == http.StatusOK && rec.Body.Len() == 0 {
		t.Fatal("empty 200 from a hung capture")
	}
	if p.obs.captureRejected.Load() != 0 {
		t.Fatal("the capture breaker acted without a capture timeout")
	}
}

func TestFaultHungCaptureTimesOutAndOpensTheBreaker(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "glue", "mode=hang\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.CaptureTimeoutMs = 200 })
	p.capBreaker.threshold = 3
	p.capBreaker.cooldown = 400 * time.Millisecond
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)

	for i := 0; i < 3; i++ {
		handled, rec, d := captureOnce(m, nil)
		if !handled || rec.Code != http.StatusGatewayTimeout || !strings.Contains(rec.Body.String(), "did not answer in time") {
			t.Fatalf("request %d to a hung capture: handled=%v status=%d body=%q", i, handled, rec.Code, rec.Body.String())
		}
		if d < 150*time.Millisecond || d > 1500*time.Millisecond {
			t.Fatalf("request %d took %s, expected about the 200 ms capture timeout", i, d)
		}
	}
	//Breaker open: answered at once with a clear 503, the plugin is not tried
	for i := 0; i < 5; i++ {
		handled, rec, d := captureOnce(m, nil)
		if !handled || rec.Code != http.StatusServiceUnavailable || rec.Body.Len() == 0 || rec.Header().Get("Retry-After") == "" || d > 100*time.Millisecond {
			t.Fatalf("request with an open capture breaker: handled=%v status=%d body=%q after %s", handled, rec.Code, rec.Body.String(), d)
		}
	}
	c := p.Status().Counters
	if c.CaptureRequests != 3 || c.CaptureFailures != 3 || c.CaptureRejected != 5 {
		t.Fatalf("counters: %+v", c)
	}
	//The Health column must not say OK while captured requests and the UI are refused
	if st := p.Status(); st.State != StateRunning || st.Health != HealthNotResponding {
		t.Fatalf("status with an open capture breaker: state %q health %q, want running / %s", st.State, st.Health, HealthNotResponding)
	}
	//The plugin UI shares the timeout and the breaker, and answers with a page, not with JSON and 200
	if rec, d := uiOnce(m, p); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "<h1>The plugin is not answering</h1>") || d > 100*time.Millisecond {
		t.Fatalf("plugin UI with an open breaker: status %d after %s body %q", rec.Code, d, rec.Body.String())
	}
	//After the cooldown exactly one request probes the plugin again
	time.Sleep(450 * time.Millisecond)
	if _, rec, d := captureOnce(m, nil); rec.Code != http.StatusGatewayTimeout || d < 150*time.Millisecond {
		t.Fatalf("the probe request after the cooldown: status %d after %s", rec.Code, d)
	}
	if _, rec, _ := captureOnce(m, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a failed probe must keep the breaker open: status %d", rec.Code)
	}
}

func TestFaultCaptureTimeoutAppliesToARunningPluginAndUI(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "stuckui", "mode=hang\n", "t")
	waitHealth(t, p, HealthOK)
	//Set while the plugin runs: the proxies are rebuilt
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.CaptureTimeoutMs = 200 })
	rec, d := uiOnce(m, p)
	if rec.Code != http.StatusGatewayTimeout || d > 1500*time.Millisecond || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(rec.Body.String(), "did not answer in time") {
		t.Fatalf("hung plugin UI with a capture timeout: status %d after %s body %q", rec.Code, d, rec.Body.String())
	}
}

func TestFaultSlowCaptureInsideTheTimeoutIsServed(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "steady", "mode=slow\ndelay=100ms\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.CaptureTimeoutMs = 1000 })
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	for i := 0; i < 8; i++ {
		if handled, rec, _ := captureOnce(m, nil); !handled || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "captured by chaos plugin") {
			t.Fatalf("slow capture %d inside the timeout: status %d body %q", i, rec.Code, rec.Body.String())
		}
	}
	if c := p.Status().Counters; c.CaptureFailures != 0 || c.CaptureRejected != 0 || c.CaptureRequests != 8 {
		t.Fatalf("counters: %+v", c)
	}
}

func TestFaultPluginUIErrorsArePagesWithAStatus(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "pageless", "mode=ok\n", "t")
	//Not running
	rec, _ := uiOnce(m, p)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "The plugin is not running") || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("UI of a stopped plugin: status %d body %q", rec.Code, rec.Body.String())
	}
	//Unknown plugin
	rec = httptest.NewRecorder()
	m.HandlePluginUI("no.such.plugin<script>", rec, httptest.NewRequest(http.MethodGet, "/plugin.ui/x/", nil))
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("UI of an unknown plugin: status %d body %q", rec.Code, rec.Body.String())
	}
	//Running but the port is dead: 502 page (the process is frozen so Zoraxy has not noticed an exit)
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	p.mu.Lock()
	realPort := p.AssignedPort
	p.AssignedPort = 1 //nothing listens there
	m.startUIHandlerLocked(p, 1)
	p.mu.Unlock()
	rec, _ = uiOnce(m, p)
	p.mu.Lock()
	p.AssignedPort = realPort
	p.mu.Unlock()
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "could not be loaded") {
		t.Fatalf("UI with a dead port: status %d body %q", rec.Code, rec.Body.String())
	}
}

/* Fail-open and fail-closed, for hangs and for crashes */

func TestFaultFailClosedBlockWhenDownHoldsForCrashes(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	m.supCfg.BackoffBase = 400 * time.Millisecond
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "guard", "mode=ok\nfeatures=hooks,failclosed\n", "t")

	//The option needs the fail-closed consent of the administrator
	if err := m.SetPluginPolicy(p.Spec.ID, func(pp *PluginPolicy) { pp.BlockWhenDown = true }); err == nil {
		t.Fatal("block-when-down without the fail-closed consent must be refused")
	}
	yes, no := true, false
	if err := m.SetHookAdminSettings(p.Spec.ID, nil, &yes); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.BlockWhenDown = true; pp.Restart = RestartOnFailure })

	//Never started / stopped by the administrator: not "down", requests pass
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("a plugin the administrator has not started must not block anything")
	}
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("a healthy fail-closed plugin must let the request pass")
	}

	//Crash: blocked while the restart is waiting ...
	killPID(p.Status().PID)
	waitState(t, p, StateRestarting)
	res, rec, _ := runPreAuth(m)
	if !res.Handled || !res.Denied || rec.Code != http.StatusServiceUnavailable || rec.Body.Len() == 0 || res.PluginID != p.Spec.ID {
		t.Fatalf("crashed fail-closed plugin with block-when-down: %+v status %d", res, rec.Code)
	}
	if c := p.Status().Counters; c.BlockedWhileDown != 1 || c.PassedWhileDown != 0 {
		t.Fatalf("counters: %+v", c)
	}
	// ... and served again once the supervisor has restarted it
	eventually(t, 5*time.Second, "the automatic restart", func() bool { return p.Status().State == StateRunning })
	waitHealth(t, p, HealthOK)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("after the restart requests must pass again")
	}

	//A rule that opted out of the plugin is never blocked by it
	killPID(p.Status().PID)
	waitState(t, p, StateRestarting)
	rec = httptest.NewRecorder()
	if res := m.HandleStage(rec, newReq(http.MethodGet, "http://app.example/", ""), []string{"t", OptOutPluginPrefix + p.Spec.ID}, "198.51.100.9", zp.HookStagePreAuth); res.Handled {
		t.Fatal("a rule with the opt-out tag was blocked by a down plugin")
	}
	rec = httptest.NewRecorder()
	if res := m.HandleStage(rec, newReq(http.MethodGet, "http://app.example/", ""), []string{"other"}, "198.51.100.9", zp.HookStagePreAuth); res.Handled {
		t.Fatal("a rule the plugin is not attached to was blocked")
	}

	//Stop by the administrator: the plugin is out of the path, nothing is blocked
	if err := m.DisablePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("a plugin stopped by the administrator must not block requests")
	}

	//The same when Stop is pressed on a plugin that crashed and is not being restarted
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartNever })
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	killPID(p.Status().PID)
	waitState(t, p, StateCrashed)
	if res, _, _ := runPreAuth(m); !res.Handled {
		t.Fatal("a crashed plugin (policy never) must block with block-when-down")
	}
	if err := m.DisablePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("Stop on a crashed plugin must end the blocking: it is stopped on purpose now")
	}
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })

	//Taking the consent back switches block-when-down off for good
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	if err := m.SetHookAdminSettings(p.Spec.ID, nil, &no); err != nil {
		t.Fatal(err)
	}
	if p.policy().BlockWhenDown {
		t.Fatal("block-when-down survived the withdrawal of the fail-closed consent")
	}
	killPID(p.Status().PID)
	waitState(t, p, StateRestarting)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("without consent a crashed plugin must fail open")
	}
}

func TestFaultBlockWhenDownAlsoCoversNotReadyAndResponseStage(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "sentry", "mode=slow_start\ndelay=400ms\nfeatures=hooks,failclosed\n", "t")
	yes := true
	if err := m.SetHookAdminSettings(p.Spec.ID, nil, &yes); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.BlockWhenDown = true; pp.ReadinessGate = true })
	mustStart(t, m, p)
	if res, rec, _ := runPreAuth(m); !res.Handled || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a fail-closed plugin that is not ready yet must block with block-when-down: %+v", res)
	}
	eventually(t, 5*time.Second, "the plugin to become ready", func() bool { return p.Status().Attached })
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("the ready plugin must let requests pass")
	}

	//Response-only plugin that is down: the upstream response is replaced by a 502
	resp := &Plugin{Spec: &zp.IntroSpect{ID: "test.resp", Name: "resp", Type: zp.PluginType_Router, Hooks: &zp.HookSettings{
		Version: 1, Stages: []zp.HookStage{zp.HookStageResponse}, FilterResponsePath: "/r", FailurePolicy: zp.FailureClosed}}}
	resp.hook.failClosedConsent = true
	resp.hook.global = true
	resp.pol.BlockWhenDown = true
	resp.status.state = StateCrashed
	m.loadedPluginsMutex.Lock()
	m.LoadedPlugins[resp.Spec.ID] = resp
	m.loadedPluginsMutex.Unlock()
	rec := httptest.NewRecorder()
	w := m.WrapResponse(rec, newReq(http.MethodGet, "http://app.example/", ""), []string{"none"}, "198.51.100.9")
	w.Header().Set("Set-Cookie", "secret=1")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("upstream body"))
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "upstream body") || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("down fail-closed response plugin: status %d body %q headers %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if resp.obs.blockedWhileDown.Load() != 1 {
		t.Fatal("the blocked response was not counted")
	}
}

/* Events */

func TestFaultEventQueueIsBoundedForAHungSubscriber(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "deafevents", "mode=hang\nfeatures=events\n", "t")
	waitHealth(t, p, HealthOK)

	const total = 50000
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	start := time.Now()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < total/8; i++ {
				if err := p.Notify(events.Event{Name: events.EventName("blacklistedIpBlocked"), UUID: strconv.Itoa(i)}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	took := time.Since(start)
	if took > 5*time.Second {
		t.Fatalf("queueing %d events took %s: Notify must not wait for the plugin", total, took)
	}
	time.Sleep(100 * time.Millisecond)
	if grown := runtime.NumGoroutine() - before; grown > 10 {
		t.Fatalf("%d events at a hung subscriber left %d extra goroutines (one worker is expected)", total, grown)
	}
	c := p.Status().Counters
	if c.EventsQueued > eventQueueMax || c.EventsQueued < eventQueueMax-1 {
		t.Fatalf("the queue must hold at most %d events, holds %d", eventQueueMax, c.EventsQueued)
	}
	//Everything that did not fit was dropped and counted: total = queued + in flight (1) + dropped
	if c.EventsDropped != int64(total-c.EventsQueued-1) || c.EventsSent != 0 {
		t.Fatalf("counters do not add up: %+v", c)
	}

	//Stopping the plugin ends the delivery that is still waiting and empties the queue
	stopStart := time.Now()
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "the event worker to end", func() bool {
		p.evq.mu.Lock()
		defer p.evq.mu.Unlock()
		return !p.evq.working && p.evq.n == 0
	})
	if d := time.Since(stopStart); d > 8*time.Second {
		t.Fatalf("stop took %s", d)
	}
	if c := p.Status().Counters; c.EventsDropped+c.EventsFailed != total {
		t.Fatalf("after the stop every event must be accounted for: %+v", c)
	}
}

func TestFaultEventsAreDeliveredInOrderWithTheInvokeToken(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "listener", "mode=ok\nfeatures=events\n", "t")
	waitHealth(t, p, HealthOK)
	for i := 0; i < 200; i++ {
		if err := p.Notify(events.Event{Name: events.EventName("blacklistedIpBlocked")}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, 5*time.Second, "200 events to be sent", func() bool { return p.obs.eventsSent.Load() == 200 })
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(p.assignedPort()) + "/ui/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var stats struct {
		Events          int `json:"events"`
		EventsWithToken int `json:"events_with_token"`
	}
	json.NewDecoder(resp.Body).Decode(&stats)
	if stats.Events != 200 || stats.EventsWithToken != 200 {
		t.Fatalf("the plugin saw %d events, %d with the invoke token; want 200 and 200", stats.Events, stats.EventsWithToken)
	}
	if c := p.Status().Counters; c.EventsDropped != 0 || c.EventsFailed != 0 {
		t.Fatalf("counters: %+v", c)
	}
}

func TestEventQueueKeepsTheNewestInOrder(t *testing.T) {
	q := &eventQueue{max: 3}
	q.working = true //no worker in this test
	for i := 0; i < 7; i++ {
		q.push(events.Event{UUID: strconv.Itoa(i)})
	}
	var got []string
	for {
		ev, ok := q.pop()
		if !ok {
			break
		}
		got = append(got, ev.UUID)
	}
	if strings.Join(got, ",") != "4,5,6" {
		t.Fatalf("a full queue must drop the oldest and keep the order, got %v", got)
	}
}

/* Output */

func TestFaultLogFloodIntoASizeLimitedFile(t *testing.T) {
	m := newFaultManager(t)
	m.Options.PluginLogDir = filepath.Join(t.TempDir(), "pluginlogs")
	p := loadChaosStopped(t, m, "floodfile", "mode=logflood\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.LogTarget = LogTargetFile; pp.LogMaxKB = 64 })
	mustStart(t, m, p)
	eventually(t, 5*time.Second, "the plugin to flood", func() bool { return p.obs.logLines.Load() > 20000 })

	path := m.pluginLogPath(p)
	if !strings.HasPrefix(path, m.Options.PluginLogDir) || filepath.Base(path) != p.Spec.ID+".log" {
		t.Fatalf("unexpected log path %q", path)
	}
	total := int64(0)
	for _, f := range []string{path, path + ".1"} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatalf("log file %s: %v", f, err)
		}
		if fi.Size() > 64*1024 {
			t.Fatalf("%s is %d bytes, the limit is 64 KiB", f, fi.Size())
		}
		total += fi.Size()
	}
	entries, _ := os.ReadDir(m.Options.PluginLogDir)
	if len(entries) != 2 {
		t.Fatalf("exactly the log file and one rotated file are expected, found %d files", len(entries))
	}
	if n := p.obs.mainLogLines.Load(); n != 0 {
		t.Fatalf("%d output lines of the plugin went to the main log although its log target is a file", n)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "chaos: flood") {
		t.Fatalf("the log file does not hold the output of the plugin: %q", string(raw[:min(200, len(raw))]))
	}
	t.Logf("%d lines read, %d bytes on disk", p.obs.logLines.Load(), total)
	if len(p.recentOutput()) == 0 {
		t.Fatal("the output ring must still be filled")
	}
}

func TestFaultLogRateLimitDropsAndCounts(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "floodlimit", "mode=logflood\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.LogRateLimit = 50 })
	mustStart(t, m, p)
	start := time.Now()
	eventually(t, 5*time.Second, "the plugin to flood", func() bool { return p.obs.logLines.Load() > 20000 })
	time.Sleep(300 * time.Millisecond)
	elapsed := time.Since(start).Seconds()
	//Stop first, so the counters below are read when no line is on its way any more
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "every kept line to be in the main log", func() bool {
		c := p.Status().Counters
		return p.obs.mainLogLines.Load() == c.LogLines-c.LogLinesDropped
	})
	c := p.Status().Counters
	kept := c.LogLines - c.LogLinesDropped
	//A burst of one second (50) plus 50 per second
	if maxKept := int64(50 + 50*elapsed + 10); kept > maxKept || kept < 40 {
		t.Fatalf("%d lines were kept in %.1f s with a limit of 50 lines per second (at most %d expected). Counters: %+v", kept, elapsed, maxKept, c)
	}
	if got := p.obs.mainLogLines.Load(); got != kept {
		t.Fatalf("%d lines reached the main log, %d were kept", got, kept)
	}
	if c.LogLinesDropped < 10000 {
		t.Fatalf("dropped lines must be counted: %+v", c)
	}
}

func TestFaultLogDefaultIsTheMainLogWithoutLimit(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "talker", "mode=ok\n", "t")
	waitHealth(t, p, HealthOK)
	eventually(t, 3*time.Second, "the start lines of the plugin", func() bool { return p.obs.logLines.Load() >= 2 })
	c := p.Status().Counters
	if c.LogLinesDropped != 0 || p.obs.mainLogLines.Load() != c.LogLines {
		t.Fatalf("by default every output line goes to the main log: main=%d counters=%+v", p.obs.mainLogLines.Load(), c)
	}
	if _, err := os.Stat(m.pluginLogDir()); err == nil {
		t.Fatalf("a plugin log folder (%s) was created although no plugin uses a log file", m.pluginLogDir())
	}
}

func TestLogRateLimiterAndLogFileRotation(t *testing.T) {
	l := &logRateLimiter{perSecond: 10}
	now := time.Unix(1000, 0)
	pass := 0
	for i := 0; i < 100; i++ {
		if ok, _ := l.allow(now); ok {
			pass++
		}
	}
	if pass != 10 {
		t.Fatalf("a burst may pass one second of lines (10), passed %d", pass)
	}
	if ok, _ := l.allow(now.Add(500 * time.Millisecond)); !ok {
		t.Fatal("after half a second 5 more lines may pass")
	}
	_, report := l.allow(now.Add(11 * time.Second))
	if report != 90 {
		t.Fatalf("the drop report must carry the number of dropped lines (90), got %d", report)
	}
	unlimited := &logRateLimiter{}
	for i := 0; i < 1000; i++ {
		if ok, _ := unlimited.allow(now); !ok {
			t.Fatal("no limit must never drop")
		}
	}

	dir := t.TempDir()
	lf := &pluginLogFile{path: filepath.Join(dir, "a.log"), maxSize: 1024}
	f, err := os.Create(lf.path)
	if err != nil {
		t.Fatal(err)
	}
	lf.f = f
	for i := 0; i < 500; i++ {
		if !lf.write(strings.Repeat("x", 99)) {
			t.Fatal("write failed")
		}
	}
	if !lf.write(strings.Repeat("y", 5000)) { //one line larger than the file
		t.Fatal("write of a long line failed")
	}
	lf.close()
	for _, name := range []string{"a.log", "a.log.1"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Size() > 1024 {
			t.Fatalf("%s: %v size %d", name, err, fi.Size())
		}
	}
}

/* Limits (Linux) */

func TestFaultMemoryLimitEndsABalloon(t *testing.T) {
	m := newFaultManager(t)
	if support, note := m.limitsSupport(); support != "systemd" {
		t.Skip("memory limits need systemd scopes on this host: " + note)
	}
	p := loadChaosStopped(t, m, "balloon", "mode=balloon\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.MemoryMaxMB = 96; pp.TasksMax = 200; pp.CPUQuotaPercent = 100 })
	mustStart(t, m, p)
	if st := p.Status(); !strings.Contains(st.LimitsNote, "memory 96 MB") || !strings.Contains(st.LimitsNote, "tasks 200") || !strings.Contains(st.LimitsNote, "CPU 100%") {
		t.Fatalf("the status must say which limits apply: %q", st.LimitsNote)
	}
	st := PluginStatus{}
	eventually(t, 30*time.Second, "the balloon to be ended at its memory limit", func() bool {
		st = p.Status()
		return st.State == StateCrashed
	})
	if !strings.Contains(st.ExitReason, "killed") || !strings.Contains(st.LastError, "memory limit of 96 MB") {
		t.Fatalf("a plugin ended at its memory limit must say so: %+v", st)
	}
	//Zoraxy (this test process) is unaffected and the plugin can be started again
	mustStart(t, m, p)
	if !m.PluginIsRunning(p.Spec.ID) {
		t.Fatal("the plugin could not be started again")
	}
}

func TestFaultOpenFileLimitIsApplied(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rlimits are applied on Linux only")
	}
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "fdlimit", "mode=ok\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.MaxOpenFiles = 64 })
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	st := p.Status()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(st.PID) + "/limits")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			f := strings.Fields(line)
			found = len(f) >= 5 && f[3] == "64" && f[4] == "64"
		}
	}
	if !found || !strings.Contains(st.LimitsNote, "open files 64") {
		t.Fatalf("the open file limit was not applied. Note %q, limits:\n%s", st.LimitsNote, raw)
	}
	//Default: nothing is touched
	q := loadChaosStopped(t, m, "nolimit", "mode=ok\n", "t")
	mustStart(t, m, q)
	if note := q.Status().LimitsNote; note != "" {
		t.Fatalf("a plugin without limits must not carry a limits note: %q", note)
	}
	if cmdline, _ := os.ReadFile("/proc/" + strconv.Itoa(q.Status().PID) + "/cmdline"); strings.Contains(string(cmdline), "systemd-run") {
		t.Fatal("a plugin without limits was started through systemd-run")
	}
}

/* Secrets and process group */

func TestFaultSecretsOnStdinAreNotOnTheCommandLine(t *testing.T) {
	m := newFaultManager(t)
	readConf := func(p *Plugin) (apiKey, token string) {
		eventually(t, 3*time.Second, "the plugin to record its configuration", func() bool {
			raw, err := os.ReadFile(filepath.Join(p.RootDir, "last-configure.json"))
			if err != nil {
				return false
			}
			var c struct {
				APIKey      string `json:"api_key"`
				InvokeToken string `json:"invoke_token"`
			}
			json.Unmarshal(raw, &c)
			apiKey, token = c.APIKey, c.InvokeToken
			return apiKey != "" && token != ""
		})
		return
	}
	cmdline := func(p *Plugin) string {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(p.Status().PID) + "/cmdline")
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	p := startChaos(t, m, "discreet", "mode=ok\nfeatures=hooks,api,stdinconf\n", "t")
	waitHealth(t, p, HealthOK)
	key, token := readConf(p)
	if cl := cmdline(p); strings.Contains(cl, key) || strings.Contains(cl, token) || strings.Contains(cl, "api_key") || !strings.Contains(cl, zp.ConfigureStdinFlag) {
		t.Fatalf("a plugin that declares configure_via stdin must not have its secrets on the command line: %q", cl)
	}
	if token != p.invokeToken() {
		t.Fatal("the plugin did not get the invoke token of this start")
	}
	if _, err := m.Options.APIKeyManager.ValidateAPIKey(key); err != nil {
		t.Fatalf("the API key from stdin is not valid: %v", err)
	}
	if res, _, _ := runPreAuth(m); res.Handled || p.obs.callFails.Load() != 0 {
		t.Fatal("the plugin configured over stdin does not answer filter calls")
	}

	//Compatibility: a plugin that does not declare it gets the configuration as an argument, as always
	old := startChaos(t, m, "classic", "mode=ok\nfeatures=hooks,api\n", "t")
	waitHealth(t, old, HealthOK)
	key, _ = readConf(old)
	if cl := cmdline(old); !strings.Contains(cl, "-configure=") || !strings.Contains(cl, key) {
		t.Fatalf("a legacy plugin must still be configured on the command line: %q", cl)
	}
}

func TestSanitizeSupervisionSpec(t *testing.T) {
	for _, bad := range []string{"health", "/a b", "/x?y=1", "//evil", "/" + strings.Repeat("a", 300), "/a\n"} {
		spec := &zp.IntroSpect{HealthPath: bad, ConfigureVia: "fd3"}
		if warns := sanitizeSupervisionSpec(spec); len(warns) != 2 || spec.HealthPath != "" || spec.ConfigureVia != "" {
			t.Fatalf("health_path %q / configure_via fd3 must be dropped with warnings: %+v %v", bad, spec, warns)
		}
	}
	spec := &zp.IntroSpect{HealthPath: "/api/health-check_1.0", ConfigureVia: "stdin"}
	if warns := sanitizeSupervisionSpec(spec); len(warns) != 0 || spec.HealthPath == "" || spec.ConfigureVia != "stdin" {
		t.Fatalf("valid values must be kept: %+v %v", spec, warns)
	}
}

func TestFaultStopAlsoEndsTheChildrenOfAPlugin(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "parent", "mode=ok\nfeatures=hooks,children\n", "t")
	waitHealth(t, p, HealthOK)
	childPID := 0
	eventually(t, 3*time.Second, "the child of the plugin to start", func() bool {
		raw, err := os.ReadFile(filepath.Join(p.RootDir, "child.pid"))
		if err != nil {
			return false
		}
		childPID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		return pidAlive(childPID)
	})
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "the child to end with the plugin", func() bool { return !pidAlive(childPID) })

	//The same after a crash: nothing of the old process is left when it is started again
	os.Remove(filepath.Join(p.RootDir, "child.pid"))
	mustStart(t, m, p)
	eventually(t, 3*time.Second, "the child of the plugin to start", func() bool {
		raw, err := os.ReadFile(filepath.Join(p.RootDir, "child.pid"))
		if err != nil {
			return false
		}
		childPID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		return pidAlive(childPID)
	})
	killPID(p.Status().PID)
	waitState(t, p, StateCrashed)
	eventually(t, 3*time.Second, "the child to end after the crash of the plugin", func() bool { return !pidAlive(childPID) })
}

/* Policy storage and API */

func TestFaultPolicyAPIValidationAndPersistence(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "policied", "mode=ok\n", "t")

	post := func(form url.Values) map[string]any {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/policy", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		m.HandlePluginPolicy(rec, req)
		body, _ := io.ReadAll(rec.Body)
		var out map[string]any
		if json.Unmarshal(body, &out) != nil {
			return map[string]any{"ok": string(body)}
		}
		return out
	}
	bad := []url.Values{
		{"plugin_id": {p.Spec.ID}, "restart": {"sometimes"}},
		{"plugin_id": {p.Spec.ID}, "health_check": {"restart"}},
		{"plugin_id": {p.Spec.ID}, "block_when_down": {"true"}},
		{"plugin_id": {p.Spec.ID}, "capture_timeout_ms": {"5"}},
		{"plugin_id": {p.Spec.ID}, "memory_max_mb": {"-3"}},
		{"plugin_id": {p.Spec.ID}, "memory_max_mb": {"1"}},
		{"plugin_id": {p.Spec.ID}, "log_target": {"syslog"}},
		{"plugin_id": {p.Spec.ID}, "log_rate_limit": {"abc"}},
		{"plugin_id": {"no.such.plugin"}, "restart": {"always"}},
	}
	for _, form := range bad {
		if out := post(form); out["error"] == nil {
			t.Fatalf("policy %v must be refused, got %v", form, out)
		}
	}
	if pol := p.policy(); pol != (PluginPolicy{}).normalized() {
		t.Fatalf("refused requests changed the policy: %+v", pol)
	}
	good := url.Values{"plugin_id": {p.Spec.ID}, "restart": {"on-failure"}, "health_check": {"restart"}, "readiness_gate": {"true"},
		"capture_timeout_ms": {"30000"}, "log_target": {"file"}, "log_max_kb": {"512"}, "log_rate_limit": {"100"},
		"memory_max_mb": {"256"}, "cpu_quota_percent": {"50"}, "tasks_max": {"64"}, "max_open_files": {"1024"}}
	if out := post(good); out["error"] != nil {
		t.Fatalf("a valid policy was refused: %v", out)
	}
	want := PluginPolicy{Restart: RestartOnFailure, ReadinessGate: true, HealthCheck: HealthCheckRestart, CaptureTimeoutMs: 30000,
		LogTarget: LogTargetFile, LogMaxKB: 512, LogRateLimit: 100, MemoryMaxMB: 256, CPUQuotaPercent: 50, TasksMax: 64, MaxOpenFiles: 1024}
	if got := p.policy(); got != want {
		t.Fatalf("policy\n got %+v\nwant %+v", got, want)
	}
	//One field at a time leaves the others alone
	if out := post(url.Values{"plugin_id": {p.Spec.ID}, "cpu_quota_percent": {"0"}}); out["error"] != nil {
		t.Fatal(out)
	}
	want.CPUQuotaPercent = 0
	if got := p.policy(); got != want {
		t.Fatalf("a single field update changed other fields: %+v", got)
	}

	//GET shows it, the list API carries it, and a new manager on the same database loads it
	rec := httptest.NewRecorder()
	m.HandlePluginPolicy(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/policy?plugin_id="+url.QueryEscape(p.Spec.ID), nil))
	var view pluginPolicyView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || view.Policy != want || view.LimitsSupport == "" {
		t.Fatalf("GET policy: %v %+v", err, view)
	}
	rec = httptest.NewRecorder()
	m.HandleListPlugins(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/list", nil))
	var listedPlugins []struct {
		Status struct {
			Policy   PluginPolicy
			Counters map[string]any
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listedPlugins); err != nil || len(listedPlugins) != 1 || listedPlugins[0].Status.Policy != want {
		t.Fatalf("list API: %v %+v", err, listedPlugins)
	}
	for _, k := range []string{"Calls", "CallFailures", "CallTimeouts", "BreakerOpens", "CaptureRequests", "CaptureFailures", "CaptureRejected", "EventsSent",
		"EventsFailed", "EventsDropped", "EventsQueued", "LogLines", "LogLinesDropped", "PassedWhileDown", "BlockedWhileDown", "HealthChecksOK", "HealthChecksFail"} {
		if _, ok := listedPlugins[0].Status.Counters[k]; !ok {
			t.Fatalf("counter %s is missing from the list API", k)
		}
	}

	m2 := newFaultManager(t)
	m2.Options.Database = &database.Database{Backend: m.Options.Database.Backend}
	m2.Options.PluginDir = m.Options.PluginDir
	p2, err := m2.LoadPluginSpec(p.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := p2.policy(); got != want {
		t.Fatalf("the policy was not loaded from the database: %+v", got)
	}
}

func TestFaultCountersAndExitHistoryInTheStatusAPI(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "counted", "mode=hang\n", "t")
	waitHealth(t, p, HealthOK)
	for i := 0; i < defaultBreakerThreshold; i++ {
		runPreAuth(m)
	}
	c := p.Status().Counters
	if c.Calls != defaultBreakerThreshold || c.CallFailures != defaultBreakerThreshold || c.CallTimeouts != defaultBreakerThreshold || c.BreakerOpens != 1 {
		t.Fatalf("counters after %d timed out calls: %+v", defaultBreakerThreshold, c)
	}
	killPID(p.Status().PID)
	waitState(t, p, StateCrashed)
	mustStart(t, m, p)
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"plugin_id": {p.Spec.ID}}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/status", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	m.HandlePluginStatus(rec, req)
	var detail struct {
		ExitHistory []ExitRecord
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.ExitHistory) != 2 || detail.ExitHistory[0].Kind != StateCrashed || detail.ExitHistory[0].ExitCode != -1 ||
		detail.ExitHistory[1].Kind != StateStopped || detail.ExitHistory[0].At == 0 {
		t.Fatalf("exit history: %+v", detail.ExitHistory)
	}
	//GET (which read-only accounts may call) does not carry the history
	rec = httptest.NewRecorder()
	m.HandlePluginStatus(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/status?plugin_id="+url.QueryEscape(p.Spec.ID), nil))
	if strings.Contains(rec.Body.String(), "ExitHistory") {
		t.Fatal("the exit history must only be in the POST answer")
	}

	//The history is capped
	for i := 0; i < 3*exitHistoryMax; i++ {
		p.sup.addHistory(ExitRecord{At: int64(i)})
	}
	if h := p.sup.historyCopy(); len(h) != exitHistoryMax || h[len(h)-1].At != int64(3*exitHistoryMax-1) {
		t.Fatalf("history must keep the newest %d entries, has %d", exitHistoryMax, len(h))
	}
}

func TestFaultRestartAPI(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "bounce", "mode=ok\n", "t")
	waitHealth(t, p, HealthOK)
	first := p.Status().PID
	call := func(id string) string {
		form := url.Values{"plugin_id": {id}}
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/restart", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		m.HandleRestartPlugin(rec, req)
		return rec.Body.String()
	}
	if out := call(p.Spec.ID); strings.Contains(out, "error") {
		t.Fatal(out)
	}
	st := p.Status()
	if st.State != StateRunning || st.PID == first || pidAlive(first) || st.StartCount != 2 {
		t.Fatalf("restart: %+v", st)
	}
	if out := call("no.such.plugin"); !strings.Contains(out, "error") {
		t.Fatal("restart of an unknown plugin must fail")
	}
	//Restart of a plugin that is not running starts it
	if err := m.StopPlugin(p.Spec.ID); err != nil && !errors.Is(err, ErrPluginNotRunning) {
		t.Fatal(err)
	}
	if out := call(p.Spec.ID); strings.Contains(out, "error") || !m.PluginIsRunning(p.Spec.ID) {
		t.Fatal(out)
	}
}

// The suite uses an in-memory database. The real one (bolt) panics when a table
// that was never created is read, which is what a plugin folder triggered at boot
// before the policy table was created by NewPluginManager (found with a real instance).
func TestFaultBootWithTheRealDatabase(t *testing.T) {
	dir := t.TempDir()
	lg, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	boot := func() (*Manager, *database.Database) {
		db, err := database.NewDatabase(filepath.Join(dir, "sys.db"), dbinc.BackendBoltDB)
		if err != nil {
			t.Fatal(err)
		}
		m := NewPluginManager(&ManagerOptions{
			PluginDir:          filepath.Join(dir, "plugins"),
			PluginGroups:       map[string][]string{},
			PluginGroupsConfig: filepath.Join(dir, "plugin_groups.json"),
			SystemConst:        &zp.RuntimeConstantValue{ZoraxyVersion: "test"},
			Logger:             lg,
			Database:           db,
			APIKeyManager:      auth.NewAPIKeyManager(),
			CSRFTokenGen:       func(*http.Request) string { return "test-csrf" },
		})
		return m, db
	}
	m, db := boot()
	installChaos(t, m.Options.PluginDir, "booted", "mode=ok\n")
	m.Options.Database.Write("plugins", "test.chaos.booted", false) //do not start it at boot
	if err := m.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if err := m.SetPluginPolicy("test.chaos.booted", func(pp *PluginPolicy) { pp.Restart = RestartAlways; pp.LogRateLimit = 7 }); err != nil {
		t.Fatal(err)
	}
	m.Close()
	db.Close()

	m2, db2 := boot()
	defer db2.Close()
	if err := m2.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	p, err := m2.GetPluginByID("test.chaos.booted")
	if err != nil {
		t.Fatal(err)
	}
	if pol := p.policy(); pol.Restart != RestartAlways || pol.LogRateLimit != 7 {
		t.Fatalf("the policy did not survive a restart of Zoraxy: %+v", pol)
	}
	if p.Status().State != StateStopped {
		t.Fatalf("a restart policy must not start a plugin the administrator had stopped: %+v", p.Status())
	}
}
