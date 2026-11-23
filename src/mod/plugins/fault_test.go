package plugins

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	Fault-injection suite, phase 0 of docs/plugins/reliability-plan.md.

	Every test starts the real chaos plugin (testdata/chaosplugin) through the real
	lifecycle code and checks two things: what Zoraxy does with the request, and what
	the read-only status says. Where the behaviour is a known weakness that a later
	phase changes, the test says "today" in its comment: it documents the behaviour,
	it does not bless it.

	Run with the race detector too:  CGO_ENABLED=1 go test -race ./mod/plugins/ -run 'TestFault|TestBug'
*/

// preAuth sends one request through the pre_auth stage of the rules tagged "t"
func runPreAuth(m *Manager) (StageResult, *httptest.ResponseRecorder, time.Duration) {
	rec := httptest.NewRecorder()
	start := time.Now()
	res := m.HandleStage(rec, newReq(http.MethodGet, "http://app.example/", ""), []string{"t"}, "198.51.100.9", zp.HookStagePreAuth)
	return res, rec, time.Since(start)
}

// startChaos starts a chaos plugin with the port probe on (it is off by default,
// see TestFaultPortProbeIsOffByDefault), so waitHealth(HealthOK) means "the port is open".
func startChaos(t *testing.T, m *Manager, folder string, conf string, tags ...string) *Plugin {
	t.Helper()
	m.Options.ProbePluginPorts = true
	p := loadChaos(t, m, folder, conf, tags...)
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatalf("StartPlugin(%s): %v", folder, err)
	}
	return p
}

func waitHealth(t *testing.T, p *Plugin, want string) {
	t.Helper()
	eventually(t, 5*time.Second, "health "+want+" (now "+p.Status().Health+", state "+p.Status().State+")", func() bool {
		p.obs.probeAt.Store(0) //no probe cache in tests
		if p.Status().Health != want {
			return false
		}
		if want == HealthOK {
			//Without the port probe (the default) "ok" does not say that the port is open yet
			p.obs.probeAt.Store(0)
			return p.portOpen(p.assignedPort())
		}
		return true
	})
}

func waitState(t *testing.T, p *Plugin, want string) PluginStatus {
	t.Helper()
	eventually(t, 5*time.Second, "state "+want+" (now "+p.Status().State+")", func() bool { return p.Status().State == want })
	return p.Status()
}

/* Status model */

func TestFaultStatusRunningStoppedRestarted(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "good", "mode=ok\n", "t")

	if st := p.Status(); st.State != StateStopped || st.StartCount != 0 || st.HasExited {
		t.Fatalf("a plugin that never started must be plain stopped, got %+v", st)
	}

	before := time.Now().Unix()
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, p, HealthOK)
	st := p.Status()
	if st.State != StateRunning || !pidAlive(st.PID) || st.StartedAt < before || st.StartCount != 1 || st.RestartCount != 0 {
		t.Fatalf("unexpected running status %+v", st)
	}
	if v := listed(t, m, p.Spec.ID); !v.Enabled || v.Status.State != StateRunning || v.Status.PID != st.PID {
		t.Fatalf("list API disagrees with the status: %+v", v)
	}

	//A second start must not create a second process
	if err := m.StartPlugin(p.Spec.ID); err == nil {
		t.Fatal("starting a running plugin must be refused")
	}
	if got := p.Status(); got.PID != st.PID || got.StartCount != 1 {
		t.Fatalf("second start changed the process: %+v", got)
	}

	//An answered call is a sign of life
	p.obs.lastSeen.Store(0)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("an allow verdict must not handle the request")
	}
	if p.Status().LastSeen == 0 {
		t.Fatal("an answered filter call must update LastSeen")
	}

	pid := st.PID
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	st = p.Status()
	if st.State != StateStopped || st.PID != 0 || !st.HasExited || st.ExitedAt == 0 || pidAlive(pid) {
		t.Fatalf("unexpected status after stop %+v (pid alive: %v)", st, pidAlive(pid))
	}
	if v := listed(t, m, p.Spec.ID); v.Enabled {
		t.Fatal("a stopped plugin is still listed as enabled")
	}
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("a stopped plugin must not take part in requests")
	}

	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(); st.State != StateRunning || st.StartCount != 2 || st.RestartCount != 1 || st.PID == pid {
		t.Fatalf("unexpected status after the second start %+v", st)
	}
}

func TestFaultCrashIsReportedWithExitCode(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "crasher", "mode=crash\ndelay=200ms\n", "t")
	st := waitState(t, p, StateCrashed)
	if !st.HasExited || st.ExitCode != 3 || !strings.Contains(st.ExitReason, "exit status 3") || st.ExitedAt == 0 || st.PID != 0 {
		t.Fatalf("unexpected crash status %+v", st)
	}
	if st.LastError == "" || strings.Contains(st.LastError, "simulated crash") {
		t.Fatalf("LastError must be set by Zoraxy and must not carry plugin output: %q", st.LastError)
	}
	eventually(t, 2*time.Second, "the crashed plugin to be detached", func() bool { return !p.isEnabled() })

	//Today: a crashed plugin is skipped, the request continues (fail open)
	if res, _, d := runPreAuth(m); res.Handled || d > time.Second {
		t.Fatalf("request with a crashed plugin: handled=%v after %s", res.Handled, d)
	}

	//The last lines the plugin printed are kept for the admin
	out := strings.Join(p.recentOutput(), "\n")
	if !strings.Contains(out, "simulated crash") {
		t.Fatalf("the last output of the crashed plugin is missing: %q", out)
	}

	//Stopping what is not running is an error, starting it again works and counts as a restart
	if err := m.StopPlugin(p.Spec.ID); err == nil {
		t.Fatal("stopping a crashed plugin must say it is not running")
	}
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(); st.StartCount != 2 || st.RestartCount != 1 {
		t.Fatalf("restart not counted: %+v", st)
	}
	waitState(t, p, StateCrashed)
}

func TestFaultKilledBySignalIsACrash(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "victim", "mode=ok\n", "t")
	waitHealth(t, p, HealthOK)
	pid := p.Status().PID
	if err := killPID(pid); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, p, StateCrashed)
	if st.ExitCode != -1 || !strings.Contains(st.ExitReason, "killed") {
		t.Fatalf("unexpected status after kill -9: %+v", st)
	}
}

func TestFaultCleanExitIsReported(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "leaver", "mode=exit0\ndelay=200ms\n", "t")
	st := waitState(t, p, StateExited)
	if !st.HasExited || st.ExitCode != 0 || st.LastError == "" {
		t.Fatalf("unexpected status after a clean exit: %+v", st)
	}
	eventually(t, 2*time.Second, "the exited plugin to be detached", func() bool { return !p.isEnabled() })
	//Today (and before): nothing is sent to the dead port any more, the request continues
	if res, _, d := runPreAuth(m); res.Handled || d > time.Second {
		t.Fatalf("request after a clean exit: handled=%v after %s", res.Handled, d)
	}
	if n := p.hookAdminState().ConsecutiveFailure; n != 0 {
		t.Fatalf("calls were still made to the exited plugin (%d failures)", n)
	}
}

func TestFaultFailedToStartIsReported(t *testing.T) {
	m := newFaultManager(t)

	t.Run("binary gone", func(t *testing.T) {
		p := loadChaos(t, m, "vanished", "mode=ok\n")
		os.Remove(filepath.Join(p.RootDir, "vanished"))
		if err := m.StartPlugin(p.Spec.ID); err == nil {
			t.Fatal("start without a binary must fail")
		}
		st := p.Status()
		if st.State != StateFailedToStart || !strings.HasPrefix(st.LastError, "Failed to start: ") || st.StartCount != 0 || p.isEnabled() {
			t.Fatalf("unexpected status %+v", st)
		}
	})
	t.Run("not executable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root may execute anything")
		}
		p := loadChaos(t, m, "noexec", "mode=ok\n")
		os.Chmod(filepath.Join(p.RootDir, "noexec"), 0o644)
		if err := m.StartPlugin(p.Spec.ID); err == nil {
			t.Fatal("start of a non-executable binary must fail")
		}
		if st := p.Status(); st.State != StateFailedToStart || st.LastError == "" {
			t.Fatalf("unexpected status %+v", st)
		}
		//A later successful start clears the state but keeps the history honest
		os.Chmod(filepath.Join(p.RootDir, "noexec"), 0o755)
		if err := m.StartPlugin(p.Spec.ID); err != nil {
			t.Fatal(err)
		}
		if st := p.Status(); st.State != StateRunning || st.StartCount != 1 {
			t.Fatalf("unexpected status %+v", st)
		}
	})
}

/* Hangs */

func TestFaultHangAtStartIsNotListening(t *testing.T) {
	m := newFaultManager(t)
	m.Options.ProbePluginPorts = true //"starting" and "not listening" need the port probe
	p := loadChaos(t, m, "sleeper", "mode=hang_start\n", "t")
	p.startGrace = 400 * time.Millisecond
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(); st.State != StateRunning || st.Health != HealthStarting {
		t.Fatalf("right after the start the plugin should be 'starting', got %+v", st)
	}
	waitHealth(t, p, HealthNotListening)

	//Today: readiness is not checked, the plugin is attached at once. Calls fail fast and the request continues
	res, _, d := runPreAuth(m)
	if res.Handled || d > time.Second {
		t.Fatalf("request with a plugin that never listens: handled=%v after %s", res.Handled, d)
	}
	if !strings.Contains(p.Status().LastError, "call to the plugin failed") {
		t.Fatalf("the failed call is not in LastError: %q", p.Status().LastError)
	}
	pid := p.Status().PID
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if pidAlive(pid) {
		t.Fatal("the hung plugin survived StopPlugin")
	}
}

func hangScenario(t *testing.T, folder string, mode string) {
	m := newFaultManager(t)
	p := startChaos(t, m, folder, "mode="+mode+"\n", "t")
	waitHealth(t, p, HealthOK) //the port is open: from the outside it looks fine until calls fail

	//Today: every request waits for the call timeout of the plugin (300 ms here, 2 s by default) and then continues
	for i := 0; i < defaultBreakerThreshold; i++ {
		res, _, d := runPreAuth(m)
		if res.Handled {
			t.Fatal("a hung fail-open plugin must not block the request")
		}
		if d < 250*time.Millisecond || d > 2*time.Second {
			t.Fatalf("call %d took %s, expected about the 300 ms timeout", i, d)
		}
	}
	//After 5 failures the breaker is open: requests no longer wait
	if res, _, d := runPreAuth(m); res.Handled || d > 200*time.Millisecond {
		t.Fatalf("with an open breaker the request must pass at once: handled=%v after %s", res.Handled, d)
	}
	st := p.Status()
	if st.State != StateRunning || st.Health != HealthNotResponding || st.LastError == "" {
		t.Fatalf("a hung plugin must be shown as running but not responding: %+v", st)
	}
	if v := listed(t, m, p.Spec.ID); v.Status.Health != HealthNotResponding {
		t.Fatalf("list API does not show the hang: %+v", v.Status)
	}
	pid := st.PID
	start := time.Now()
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if pidAlive(pid) || time.Since(start) > 10*time.Second {
		t.Fatalf("stopping the hung plugin: alive=%v after %s", pidAlive(pid), time.Since(start))
	}
}

func TestFaultHangingHandlerIsNotResponding(t *testing.T) { hangScenario(t, "hanger", "hang") }

// never_ready: the port is open but nothing is accepted. A TCP probe cannot tell this from a healthy plugin.
func TestFaultNeverReadyIsNotResponding(t *testing.T) { hangScenario(t, "deaf", "never_ready") }

// Today: fail-closed (with consent) blocks only while the plugin hangs. Once it has crashed, traffic passes unfiltered (F3).
func TestFaultFailClosedHoldsForHangButNotForCrash(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "strict", "mode=hang\nfeatures=hooks,failclosed\n", "t")
	yes := true
	if err := m.SetHookAdminSettings(p.Spec.ID, nil, &yes); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, p, HealthOK)
	res, rec, _ := runPreAuth(m)
	if !res.Handled || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("hung fail-closed plugin with consent: handled=%v status=%d, want 503", res.Handled, rec.Code)
	}
	killPID(p.Status().PID)
	waitState(t, p, StateCrashed)
	eventually(t, 2*time.Second, "the crashed plugin to be detached", func() bool { return !p.isEnabled() })
	//Default (phase 1 keeps it): the request passes, and is now counted. Blocking is the
	//per plugin opt-in "block while not running", see TestFaultFailClosedBlockWhenDownHoldsForCrashes
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("behaviour changed: a crashed fail-closed plugin blocks traffic without the block-when-down option. Update this test and the plan")
	}
	if c := p.Status().Counters; c.PassedWhileDown != 1 || c.BlockedWhileDown != 0 {
		t.Fatalf("a request that passed while a fail-closed plugin was down must be counted: %+v", c)
	}
}

/* Slow and garbage answers */

func TestFaultSlowButInTimeCountsAsSuccess(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "snail", "mode=slow\ndelay=120ms\n", "t")
	waitHealth(t, p, HealthOK)
	for i := 0; i < defaultBreakerThreshold+2; i++ {
		res, _, d := runPreAuth(m)
		if res.Handled || d < 100*time.Millisecond {
			t.Fatalf("slow call %d: handled=%v after %s", i, res.Handled, d)
		}
	}
	//Today: slowness below the timeout never trips the breaker and is not shown anywhere
	if st := p.Status(); st.Health != HealthOK || p.hookAdminState().ConsecutiveFailure != 0 {
		t.Fatalf("a slow plugin inside its timeout must stay healthy: %+v", st)
	}
}

func garbageScenario(t *testing.T, folder string, mode string, wantErr string) {
	m := newFaultManager(t)
	p := startChaos(t, m, folder, "mode="+mode+"\n", "t")
	waitHealth(t, p, HealthOK)
	for i := 0; i < notRespondingFailures; i++ {
		if res, rec, d := runPreAuth(m); res.Handled || rec.Body.Len() != 0 || d > time.Second {
			t.Fatalf("a garbage verdict must leave the request untouched: handled=%v body=%d after %s", res.Handled, rec.Body.Len(), d)
		}
	}
	st := p.Status()
	if !strings.Contains(st.LastError, wantErr) {
		t.Fatalf("LastError %q does not mention %q", st.LastError, wantErr)
	}
	if st.Health != HealthNotResponding {
		t.Fatalf("after %d bad answers the plugin should be shown as not responding: %+v", notRespondingFailures, st)
	}
}

func TestFaultBadJSONVerdictFailsOpen(t *testing.T) {
	garbageScenario(t, "babbler", "badjson", "invalid verdict JSON")
}
func TestFaultHugeVerdictFailsOpen(t *testing.T) {
	garbageScenario(t, "bloater", "huge", "plugin reply too large")
}

/* Output */

func TestFaultLogFloodStaysBounded(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "shouter", "mode=logflood\n", "t")
	waitHealth(t, p, HealthOK)
	time.Sleep(500 * time.Millisecond)

	//Zoraxy keeps working while the plugin floods its output
	start := time.Now()
	if v := listed(t, m, p.Spec.ID); v.Status.State != StateRunning {
		t.Fatalf("flooding plugin is not running: %+v", v.Status)
	}
	if res, _, d := runPreAuth(m); res.Handled || d > time.Second {
		t.Fatalf("request during a log flood: handled=%v after %s", res.Handled, d)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Zoraxy got slow during a log flood")
	}
	out := p.recentOutput()
	if len(out) == 0 || len(out) > outputRingLines {
		t.Fatalf("the output ring holds %d lines, limit is %d", len(out), outputRingLines)
	}
	for _, line := range out {
		if len(line) > outputRingLineMax+32 {
			t.Fatalf("a ring line is %d bytes long", len(line))
		}
	}
	//Today: every line still goes to the main Zoraxy log, there is no rate limit (phase 1)
	pid := p.Status().PID
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if pidAlive(pid) {
		t.Fatal("the flooding plugin survived StopPlugin")
	}
}

func TestReadPluginOutputCutsLongLines(t *testing.T) {
	var lines []string
	in := "first\n" + strings.Repeat("x", 3*maxPluginLineBytes+17) + "\nafter\r\nlast without newline"
	readPluginOutput(strings.NewReader(in), func(l string) { lines = append(lines, l) })
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d", len(lines))
	}
	if lines[0] != "first" || lines[2] != "after" || lines[3] != "last without newline" {
		t.Fatalf("unexpected lines %q %q %q", lines[0], lines[2], lines[3])
	}
	if len(lines[1]) > maxPluginLineBytes+64 || !strings.Contains(lines[1], "[line cut at") {
		t.Fatalf("the long line was not cut: %d bytes", len(lines[1]))
	}

	//A stream that never sends a newline must not be buffered without limit
	lines = nil
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		readPluginOutput(pr, func(l string) { lines = append(lines, l) })
		close(done)
	}()
	chunk := []byte(strings.Repeat("y", 64*1024))
	for i := 0; i < 64; i++ { //4 MiB
		pw.Write(chunk)
	}
	pw.Close()
	<-done
	if len(lines) != 1 || len(lines[0]) > maxPluginLineBytes+64 {
		t.Fatalf("endless line: %d lines emitted", len(lines))
	}
}

/* Stop */

func TestFaultIgnoredSigtermIsKilled(t *testing.T) {
	m := newFaultManager(t)
	m.stopGrace = 500 * time.Millisecond
	p := startChaos(t, m, "stubborn", "mode=ignore_sigterm\n", "t")
	waitHealth(t, p, HealthOK)
	pid := p.Status().PID
	start := time.Now()
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	st := p.Status()
	if pidAlive(pid) || st.State != StateStopped || !strings.Contains(st.ExitReason, "killed") {
		t.Fatalf("a plugin that ignores SIGTERM must be killed: alive=%v status=%+v", pidAlive(pid), st)
	}
	if took < 400*time.Millisecond || took > 4*time.Second {
		t.Fatalf("stop took %s, expected about the 500 ms grace period", took)
	}
	if p.isEnabled() || m.PluginIsRunning(p.Spec.ID) {
		t.Fatal("the killed plugin is still enabled")
	}
}

/* Capture */

func TestFaultStaticCaptureWhileRunningAndAfterCrash(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "catcher", "mode=ok\n", "t")
	waitHealth(t, p, HealthOK)

	capture := func() (bool, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		r := newReq(http.MethodGet, "http://app.example/chaos-static/x", "")
		r.RequestURI = "/chaos-static/x"
		return m.HandleRoute(rec, r, []string{"t"}, "198.51.100.9"), rec
	}
	handled, rec := capture()
	if !handled || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "captured by chaos plugin") {
		t.Fatalf("static capture while running: handled=%v status=%d body=%q", handled, rec.Code, rec.Body.String())
	}

	killPID(p.Status().PID)
	waitState(t, p, StateCrashed)
	eventually(t, 2*time.Second, "the capture path of the crashed plugin to be detached", func() bool {
		handled, _ := capture()
		return !handled
	})
	//Today: the captured path silently falls through to the upstream of the rule once the plugin is gone

	//A plain restart (as the store update and "Rebuild" do) must bring the capture path back
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, p, HealthOK)
	if handled, rec := capture(); !handled || !strings.Contains(rec.Body.String(), "captured by chaos plugin") {
		t.Fatalf("static capture after a restart: handled=%v body=%q", handled, rec.Body.String())
	}
}

// A plugin that dies between routing and proxying must give a 502, never an empty 200
func TestFaultCaptureRaceWithExitGives502(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "racer", "mode=ok\n", "t")
	waitHealth(t, p, HealthOK)
	proxy, port := p.staticProxyFor("/chaos-static")
	if proxy == nil {
		t.Fatal("no static capture router")
	}
	killPID(p.Status().PID)
	waitState(t, p, StateCrashed)
	//Put the stale router back, as a request that was already past the routing decision would see it
	p.mu.Lock()
	p.staticRouteProxy["/chaos-static"] = proxy
	p.AssignedPort = port
	p.mu.Unlock()
	rec := httptest.NewRecorder()
	r := newReq(http.MethodGet, "http://app.example/chaos-static/x", "")
	r.RequestURI = "/chaos-static/x"
	p.HandleStaticRoute(rec, r, "/chaos-static")
	if rec.Code != http.StatusBadGateway || rec.Body.Len() == 0 {
		t.Fatalf("want 502 with a body, got %d with %d body bytes", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(p.Status().LastError, "static capture request failed") {
		t.Fatalf("capture failure not recorded: %q", p.Status().LastError)
	}
}

/* Introspect */

func TestFaultIntrospectGarbageIsListedAsLoadFailure(t *testing.T) {
	m := newFaultManager(t)
	installChaos(t, m.Options.PluginDir, "broken", "mode=introspect_garbage\n")
	installChaos(t, m.Options.PluginDir, "fine", "mode=ok\n")
	m.Options.Database.Write("plugins", "test.chaos.fine", false)
	if err := m.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetPluginByID("test.chaos.fine"); err != nil {
		t.Fatal("the good plugin next to a broken one was not loaded")
	}
	fails := m.ListLoadFailures()
	if len(fails) != 1 || fails[0].Folder != "broken" || fails[0].Error == "" {
		t.Fatalf("unexpected load failures %+v", fails)
	}

	rec := httptest.NewRecorder()
	m.HandlePluginStatus(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/status", nil))
	var resp struct {
		Plugins []struct {
			ID     string
			Status PluginStatus
		}
		LoadFailures []LoadFailure
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Plugins) != 1 || resp.Plugins[0].Status.State != StateStopped || len(resp.LoadFailures) != 1 {
		t.Fatalf("unexpected status API answer: %s", rec.Body.String())
	}

	//Once the folder is repaired the failure disappears
	os.WriteFile(filepath.Join(m.Options.PluginDir, "broken", "chaos.conf"), []byte("mode=ok\n"), 0o644)
	m.ReloadPluginFromDisk()
	if len(m.ListLoadFailures()) != 0 {
		t.Fatalf("load failure not cleared: %+v", m.ListLoadFailures())
	}
}

/* API */

func TestFaultPluginAPIShape(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "shape", "mode=crash\ndelay=150ms\n", "t")
	waitState(t, p, StateCrashed)

	decode := func(body []byte) map[string]json.RawMessage {
		var one map[string]json.RawMessage
		if err := json.Unmarshal(body, &one); err != nil {
			t.Fatalf("not a JSON object: %v\n%s", err, body)
		}
		return one
	}
	wantKeys := []string{"RootDir", "Spec", "Enabled", "AssignedPort", "SupportHotRebuild", "HookAdmin", "Status"}

	//list
	rec := httptest.NewRecorder()
	m.HandleListPlugins(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/list", nil))
	var list []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list: %v %s", err, rec.Body.String())
	}
	//info and the tag listing must have the same shape
	rec2 := httptest.NewRecorder()
	m.HandlePluginInfo(rec2, httptest.NewRequest(http.MethodGet, "/api/plugins/info?plugin_id="+url.QueryEscape(p.Spec.ID), nil))
	rec3 := httptest.NewRecorder()
	m.HandleListPluginGroups(rec3, httptest.NewRequest(http.MethodGet, "/api/plugins/groups/list?tag=t", nil))
	var tagged []json.RawMessage
	if err := json.Unmarshal(rec3.Body.Bytes(), &tagged); err != nil || len(tagged) != 1 {
		t.Fatalf("groups list: %v %s", err, rec3.Body.String())
	}
	for name, body := range map[string][]byte{"list": list[0], "info": rec2.Body.Bytes(), "groups": tagged[0]} {
		obj := decode(body)
		for _, k := range wantKeys {
			if _, ok := obj[k]; !ok {
				t.Fatalf("%s: key %q is missing: %s", name, k, body)
			}
		}
		if strings.Contains(string(body), "simulated crash") || strings.Contains(string(body), "RecentOutput") {
			t.Fatalf("%s: plugin output leaked into an API that plugins and viewers can read", name)
		}
		var st PluginStatus
		json.Unmarshal(obj["Status"], &st)
		if st.State != StateCrashed || st.ExitCode != 3 {
			t.Fatalf("%s: status %+v", name, st)
		}
	}

	//status: GET has no output, POST has it
	get := httptest.NewRecorder()
	m.HandlePluginStatus(get, httptest.NewRequest(http.MethodGet, "/api/plugins/status?plugin_id="+url.QueryEscape(p.Spec.ID), nil))
	if strings.Contains(get.Body.String(), "simulated crash") {
		t.Fatal("GET /api/plugins/status must not return plugin output")
	}
	form := url.Values{"plugin_id": {p.Spec.ID}}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/status", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post := httptest.NewRecorder()
	m.HandlePluginStatus(post, req)
	var detail struct {
		ID           string
		Status       PluginStatus
		RecentOutput []string
	}
	if err := json.Unmarshal(post.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.ID != p.Spec.ID || detail.Status.State != StateCrashed || !strings.Contains(strings.Join(detail.RecentOutput, "\n"), "simulated crash") {
		t.Fatalf("unexpected status detail: %s", post.Body.String())
	}
}

/* Races: meaningful with -race */

func TestFaultConcurrentRequestsDuringStartStopCrash(t *testing.T) {
	m := newFaultManager(t)
	m.stopGrace = time.Second
	p := loadChaos(t, m, "busy", "mode=ok\n", "t")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var stopOnce sync.Once
	stopWorkers := func() {
		stopOnce.Do(func() { close(stop) })
		wg.Wait()
	}
	defer stopWorkers() //also when a t.Fatal below ends the test early
	worker := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}()
	}
	for i := 0; i < 3; i++ {
		worker(func() { runPreAuth(m) })
		worker(func() {
			rec := httptest.NewRecorder()
			r := newReq(http.MethodGet, "http://app.example/chaos-static/x", "")
			r.RequestURI = "/chaos-static/x"
			handled := m.HandleRoute(rec, r, []string{"t"}, "198.51.100.9")
			//Not handled = the plugin is down and the request goes on to the upstream: the recorder is untouched
			if handled && rec.Code == http.StatusOK && rec.Body.Len() == 0 {
				t.Error("empty 200 from a capture")
			}
		})
	}
	worker(func() {
		if _, err := listedErr(m, p.Spec.ID); err != nil {
			t.Error(err) //not Fatal: this is not the test goroutine
		}
		time.Sleep(time.Millisecond)
	})
	worker(func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/plugin.ui/"+p.Spec.ID+"/", nil)
		req.RequestURI = "/plugin.ui/" + p.Spec.ID + "/"
		m.HandlePluginUI(p.Spec.ID, rec, req)
		time.Sleep(time.Millisecond)
	})
	worker(func() { m.PluginIsRunning(p.Spec.ID); p.Status(); time.Sleep(time.Millisecond) })

	for round := 0; round < 4; round++ {
		if err := m.EnablePlugin(p.Spec.ID); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
		if round%2 == 0 {
			if err := m.StopPlugin(p.Spec.ID); err != nil {
				t.Fatal(err)
			}
		} else {
			killPID(p.Status().PID)
			waitState(t, p, StateCrashed)
			eventually(t, 2*time.Second, "detach after the crash", func() bool { return !p.isEnabled() })
		}
	}
	stopWorkers()
	if st := p.Status(); st.StartCount != 4 || st.State == StateRunning {
		t.Fatalf("unexpected final status %+v", st)
	}
}

/* Store folder names */

func TestSafePluginFolderName(t *testing.T) {
	keep := []string{"Data-Shield Blocklist", "zoraxy-cloudflare-waf", "Resource Monitor", "my_plugin.v2", "abc"}
	for _, name := range keep {
		if got, err := safePluginFolderName(name, "id.x"); err != nil || got != name {
			t.Errorf("%q must be kept, got %q (%v)", name, got, err)
		}
	}
	for _, name := range []string{"../../etc", "..", "a/b", `a\b`, "/abs", ".hidden", "nul\x00byte", "..\\..\\x", "x/../../y", " . ", "C:evil"} {
		got, err := safePluginFolderName(name, "com.example.plugin")
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, `/\:`+"\x00") || strings.Contains(got, "..") || strings.HasPrefix(got, ".") || filepath.Base(got) != got {
			t.Errorf("%q became the unsafe folder name %q", name, got)
		}
	}
	if got, _ := safePluginFolderName("..", "com.example.plugin"); got != "com.example.plugin" {
		t.Errorf("an unusable name must fall back to the ID, got %q", got)
	}
	if _, err := safePluginFolderName("///", ""); err == nil {
		t.Error("a plugin without a usable name or ID must be refused")
	}
}

/* Findings of the phase 0 review */

// The port probe is new behaviour, so it is off unless -plugin_port_probe is given:
// by default Zoraxy never connects to a plugin only to look at it.
func TestFaultPortProbeIsOffByDefault(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "unprobed", "mode=hang_start\n", "t")
	p.startGrace = 50 * time.Millisecond
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) //past the start grace
	for i := 0; i < 3; i++ {
		if v := listed(t, m, p.Spec.ID); v.Status.State != StateRunning || v.Status.Health != HealthOK {
			t.Fatalf("without the probe a running plugin is plain ok until calls fail, got %+v", v.Status)
		}
	}
	if p.obs.probeAt.Load() != 0 {
		t.Fatal("the list API probed the port of the plugin although the probe is off")
	}
	//Failed calls still show it, without any probe
	for i := 0; i < notRespondingFailures; i++ {
		runPreAuth(m)
	}
	if st := p.Status(); st.Health != HealthNotResponding {
		t.Fatalf("failed calls must show the plugin as not responding, got %+v", st)
	}
	if p.obs.probeAt.Load() != 0 {
		t.Fatal("the port was probed although the probe is off")
	}
}

// A stop that arrives while the last output of a crashed plugin is drained must
// not turn the crash into a plain "stopped".
func TestFaultStopDuringOutputDrainKeepsCrash(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "latecrash", "mode=crash\ndelay=200ms\n", "t")
	//Runs in the exit watcher after the drain: the moment a StopPlugin / Close() would set the flag
	m.exitDrainHook = func() {
		if pp := p.currentProc(); pp != nil {
			pp.stopRequested.Store(true)
		}
	}
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the plugin to end", func() bool { return p.Status().State != StateRunning })
	st := p.Status()
	if st.State != StateCrashed || st.ExitCode != 3 || !strings.Contains(st.LastError, "ended unexpectedly") {
		t.Fatalf("a crash followed by a late stop request must stay a crash, got %+v", st)
	}
}

// The clean-up after a crash runs under the start / stop lock of the plugin, so it
// cannot revoke the API key or the event subscriptions of a start that is under way.
func TestFaultExitDetachWaitsForStartStopLock(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "locked", "mode=crash\ndelay=400ms\nfeatures=hooks,api\n", "t")
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	apiKey := ""
	eventually(t, 3*time.Second, "the plugin to record its start configuration", func() bool {
		apiKey = configuredAPIKey(p.RootDir)
		return apiKey != ""
	})

	//Stand in for a StartPlugin that is under way when the old process ends
	p.lifeMu.Lock()
	locked := true
	defer func() {
		if locked {
			p.lifeMu.Unlock()
		}
	}()
	waitState(t, p, StateCrashed)
	time.Sleep(150 * time.Millisecond)
	if _, err := m.Options.APIKeyManager.ValidateAPIKey(apiKey); err != nil {
		t.Fatalf("the exit clean-up revoked API keys while a start / stop held the lock: %v", err)
	}
	if !p.isEnabled() {
		t.Fatal("the exit clean-up detached the plugin while a start / stop held the lock")
	}
	p.lifeMu.Unlock()
	locked = false
	eventually(t, 2*time.Second, "the clean-up after the lock is free", func() bool {
		_, err := m.Options.APIKeyManager.ValidateAPIKey(apiKey)
		return err != nil && !p.isEnabled()
	})
}

// Kill the plugin and start it again as soon as it is seen dead: the new process
// must keep its API key (the clean-up of the old one used to be able to revoke it).
func TestFaultRestartRightAfterCrashKeepsNewKey(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "phoenix", "mode=ok\nfeatures=hooks,api\n", "t")
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	key := ""
	for round := 0; round < 5; round++ {
		old := key
		eventually(t, 3*time.Second, "the plugin to record its new start configuration", func() bool {
			key = configuredAPIKey(p.RootDir)
			return key != "" && key != old
		})
		time.Sleep(50 * time.Millisecond) //a late clean-up of the previous process would hit now
		if _, err := m.Options.APIKeyManager.ValidateAPIKey(key); err != nil {
			t.Fatalf("round %d: the API key of the running plugin is not valid: %v", round, err)
		}
		if st := p.Status(); st.State != StateRunning || !p.isEnabled() {
			t.Fatalf("round %d: the restarted plugin is not attached: %+v", round, st)
		}
		killPID(p.Status().PID)
		for p.IsRunning() {
			runtime.Gosched()
		}
		if err := m.StartPlugin(p.Spec.ID); err != nil {
			t.Fatalf("round %d: start right after the crash: %v", round, err)
		}
	}
	if st := p.Status(); st.StartCount != 6 {
		t.Fatalf("expected 6 starts, got %+v", st)
	}
}

// "Stop" on a plugin that is already dead: the stop is stored and reported as done.
func TestFaultDisableOfDeadPluginSucceeds(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "deadalready", "mode=crash\ndelay=100ms\n", "t")
	if err := m.EnablePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	waitState(t, p, StateCrashed)
	eventually(t, 2*time.Second, "detach after the crash", func() bool { return !p.isEnabled() })
	if !m.GetPluginPreviousEnableState(p.Spec.ID) {
		t.Fatal("precondition: the crashed plugin is still marked to start at boot")
	}
	if err := m.StopPlugin(p.Spec.ID); !errors.Is(err, ErrPluginNotRunning) {
		t.Fatalf("StopPlugin of a dead plugin must return ErrPluginNotRunning, got %v", err)
	}
	if err := m.DisablePlugin(p.Spec.ID); err != nil {
		t.Fatalf("DisablePlugin of a crashed plugin worked (the state is stored) and must not report a failure: %v", err)
	}
	if m.GetPluginPreviousEnableState(p.Spec.ID) {
		t.Fatal("DisablePlugin did not store enabled=false")
	}
	if st := p.Status(); st.State != StateCrashed {
		t.Fatalf("disabling a crashed plugin must not hide the crash: %+v", st)
	}

	never := loadChaos(t, m, "neverran", "mode=ok\n")
	if err := m.DisablePlugin(never.Spec.ID); err != nil {
		t.Fatalf("DisablePlugin of a plugin that never ran: %v", err)
	}
	if err := m.DisablePlugin("no.such.plugin"); err == nil {
		t.Fatal("DisablePlugin of an unknown plugin must fail")
	}
}

// The "last problem" of the list API (readable by viewers and by plugins with the
// list permission) must not quote text from the answer of the plugin.
func TestFaultRejectedVerdictTextIsNotInStatus(t *testing.T) {
	m := newFaultManager(t)
	p := startChaos(t, m, "leaky", "mode=badheader\n", "t")
	waitHealth(t, p, HealthOK)
	if res, rec, _ := runPreAuth(m); res.Handled || rec.Body.Len() != 0 {
		t.Fatalf("a rejected verdict must leave the request untouched: handled=%v", res.Handled)
	}
	for _, got := range []string{p.Status().LastError, listed(t, m, p.Spec.ID).Status.LastError} {
		if !strings.Contains(got, "invalid verdict") {
			t.Fatalf("the rejected verdict is not in LastError: %q", got)
		}
		if strings.Contains(got, "Leak") || strings.Contains(got, "from-plugin") || strings.Contains(got, "<b>") {
			t.Fatalf("LastError quotes text chosen by the plugin: %q", got)
		}
	}
	//Same for an answer that is not JSON: the decoder error quotes bytes of the answer
	q := startChaos(t, m, "leaky2", "mode=badjson\n", "t")
	waitHealth(t, q, HealthOK)
	runPreAuth(m)
	if got := q.Status().LastError; !strings.HasSuffix(got, "invalid verdict JSON (the answer of the plugin was rejected)") {
		t.Fatalf("unexpected LastError for a non-JSON answer: %q", got)
	}
}

/* Store installs */

func storeEntry(srvURL string, id string, name string) *DownloadablePlugin {
	return &DownloadablePlugin{
		PluginIntroSpect: zp.IntroSpect{ID: id, Name: name},
		DownloadURLs:     map[string]string{runtime.GOOS + "_" + runtime.GOARCH: srvURL + "/chaos"},
	}
}

// A stored "enabled" left from an earlier install of the same ID (its folder was
// removed by hand, say) must not make the new install start by itself at boot.
func TestFaultReinstallDoesNotInheritEnabledState(t *testing.T) {
	m := newFaultManager(t)
	if err := os.MkdirAll(m.Options.PluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := storeFixture(t)
	const id = "test.chaos.comeback"
	m.Options.Database.Write("plugins", id, true) //the earlier install was enabled
	if err := m.InstallPlugin(storeEntry(srv.URL, id, "comeback")); err != nil {
		t.Fatal(err)
	}
	if m.PluginIsRunning(id) {
		t.Fatal("a freshly installed plugin must not be running")
	}
	if m.GetPluginPreviousEnableState(id) {
		t.Fatal("the reinstalled plugin inherited enabled=true and would start by itself at the next boot")
	}
}

// Two store names that map to the same folder, and a failed download.
func TestFaultInstallNeverWritesIntoAnOccupiedFolder(t *testing.T) {
	m := newFaultManager(t)
	if err := os.MkdirAll(m.Options.PluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := storeFixture(t)
	if err := m.InstallPlugin(storeEntry(srv.URL, "test.chaos.foo_bar", "Foo/Bar")); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(m.Options.PluginDir, "Foo_Bar", "Foo_Bar")
	if err := os.WriteFile(binPath+".marker", []byte("first"), 0o644); err != nil {
		t.Fatalf("the first plugin was not installed under Foo_Bar: %v", err)
	}
	before, err := os.Stat(binPath)
	if err != nil {
		t.Fatal(err)
	}

	//Another plugin (other ID) whose name ends up as the same folder
	err = m.InstallPlugin(storeEntry(srv.URL, "test.chaos.other", "Foo_Bar"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("an install into the folder of another plugin must be refused, got %v", err)
	}
	after, err := os.Stat(binPath)
	if err != nil || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the binary of the first plugin was touched (%v)", err)
	}
	if _, err := os.Stat(binPath + ".marker"); err != nil {
		t.Fatal("the folder of the first plugin was removed by the refused install")
	}
	if m.Options.Database.KeyExists("plugins", "test.chaos.other") {
		t.Fatal("the refused install stored a state")
	}

	//A failed download leaves nothing behind, so the next attempt is not refused
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusInternalServerError) }))
	defer bad.Close()
	if err := m.InstallPlugin(storeEntry(bad.URL, "test.chaos.retry", "retry")); err == nil {
		t.Fatal("a failed download must fail the install")
	}
	if _, err := os.Stat(filepath.Join(m.Options.PluginDir, "retry")); !os.IsNotExist(err) {
		t.Fatalf("a failed install left its folder behind (%v)", err)
	}
	if err := m.InstallPlugin(storeEntry(srv.URL, "test.chaos.retry", "retry")); err != nil {
		t.Fatalf("install after a failed attempt: %v", err)
	}
}
