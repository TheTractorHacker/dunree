package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/dpcore"
)

/*
	Tests for the findings of the phase 1 review (docs/plugins/reliability-plan.md,
	"Phase 1 review fixes"): capture breaker verdicts, start after a stop, and what
	an uninstall leaves behind.
*/

func breakerPlugin(threshold int, cooldown time.Duration) *Plugin {
	p := &Plugin{}
	p.pol.CaptureTimeoutMs = 200
	p.capBreaker.threshold = threshold
	p.capBreaker.cooldown = cooldown
	return p
}

func failCapture(t *testing.T, p *Plugin) {
	t.Helper()
	if !p.beginCapture() {
		t.Fatal("the request was not admitted")
	}
	p.captureResult(p.newCaptureWriter(httptest.NewRecorder()), "static capture", errors.New("dial tcp: connection refused"))
}

func TestCaptureBreakerClientAbortIsNotASuccess(t *testing.T) {
	// A visitor who gives up must not reset the failure streak of a hung plugin
	p := breakerPlugin(3, 50*time.Millisecond)
	failCapture(t, p)
	failCapture(t, p)
	if !p.beginCapture() {
		t.Fatal("the breaker opened too early")
	}
	if code := p.captureResult(p.newCaptureWriter(httptest.NewRecorder()), "static capture", context.Canceled); code != http.StatusBadGateway {
		t.Fatalf("status for an aborted request: %d", code)
	}
	if p.obs.captureFails.Load() != 2 {
		t.Fatalf("a client abort was counted as a failure of the plugin: %d", p.obs.captureFails.Load())
	}
	failCapture(t, p)
	if p.beginCapture() {
		t.Fatal("two failures, a client abort and a third failure must open the breaker: the abort reset the streak")
	}

	// Half open: the visitor of the probe request goes away. The breaker stays open,
	// and the probe slot is free for the next request.
	time.Sleep(70 * time.Millisecond)
	if !p.beginCapture() {
		t.Fatal("no probe after the cooldown")
	}
	if p.beginCapture() {
		t.Fatal("two probes at once")
	}
	p.captureResult(p.newCaptureWriter(httptest.NewRecorder()), "static capture", context.Canceled)
	p.capBreaker.mu.Lock()
	streak, probing := p.capBreaker.consecFail, p.capBreaker.probing
	p.capBreaker.mu.Unlock()
	if streak < 3 || probing {
		t.Fatalf("an aborted probe must leave the breaker open and free the probe slot: streak %d probing %v", streak, probing)
	}
	if !p.beginCapture() {
		t.Fatal("the next request must be allowed to probe")
	}
	if p.beginCapture() {
		t.Fatal("the breaker closed after an aborted probe")
	}
}

func TestCaptureBreakerProbeIsSettledWhenThePluginAnswers(t *testing.T) {
	for name, answer := range map[string]func(cw *captureWriter){
		"101 upgrade":  func(cw *captureWriter) { cw.WriteHeader(http.StatusSwitchingProtocols) },
		"final status": func(cw *captureWriter) { cw.WriteHeader(http.StatusOK) },
		"body":         func(cw *captureWriter) { cw.Write([]byte("x")) },
	} {
		t.Run(name, func(t *testing.T) {
			p := breakerPlugin(3, 30*time.Millisecond)
			for i := 0; i < 3; i++ {
				failCapture(t, p)
			}
			time.Sleep(50 * time.Millisecond)
			if !p.beginCapture() {
				t.Fatal("no probe after the cooldown")
			}
			cw := p.newCaptureWriter(httptest.NewRecorder())
			cw.WriteHeader(http.StatusContinue) //an interim answer is not an answer yet
			if p.beginCapture() {
				t.Fatal("100 Continue closed the breaker")
			}
			answer(cw)
			// The probe request is still running (WebSocket, long download): everyone else is served
			for i := 0; i < 3; i++ {
				if !p.beginCapture() {
					t.Fatal("requests are still rejected although the plugin answered the probe: the probe slot is held until the request ends")
				}
				p.captureResult(p.newCaptureWriter(httptest.NewRecorder()), "static capture", nil)
			}
			// The plugin breaks again while the long request is still open ...
			for i := 0; i < 3; i++ {
				failCapture(t, p)
			}
			// ... and the end of the long request, good or bad, changes nothing about that
			p.captureResult(cw, "static capture", nil)
			if p.beginCapture() {
				t.Fatal("the end of an old request closed a breaker that opened after its answer")
			}
			fails := p.obs.captureFails.Load()
			p.captureResult(cw, "static capture", dpcore.ErrResponseAborted)
			if p.beginCapture() {
				t.Fatal("a broken body of an old request closed the breaker")
			}
			if p.obs.captureFails.Load() != fails+1 {
				t.Fatal("a broken body must still be counted as a capture failure")
			}
		})
	}
}

func TestCaptureBreakerHijackSettlesTheProbe(t *testing.T) {
	p := breakerPlugin(2, 20*time.Millisecond)
	failCapture(t, p)
	failCapture(t, p)
	time.Sleep(40 * time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.beginCapture() {
			t.Error("no probe after the cooldown")
			return
		}
		cw := p.newCaptureWriter(w)
		conn, _, err := cw.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if !p.beginCapture() {
			t.Error("a taken-over connection (WebSocket) keeps the probe slot")
		}
		conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestFaultAbortedRequestsToAHungCaptureDoNotResetTheBreaker(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "limbo", "mode=hang\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.CaptureTimeoutMs = 300 })
	p.capBreaker.threshold = 3
	p.capBreaker.cooldown = time.Minute
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)

	timeout := func(what string) {
		t.Helper()
		if _, rec, _ := captureOnce(m, nil); rec.Code != http.StatusGatewayTimeout {
			t.Fatalf("%s: status %d, want 504", what, rec.Code)
		}
	}
	timeout("first request")
	timeout("second request")
	//A visitor that gives up before the capture timeout
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(60*time.Millisecond, cancel)
	_, _, d := captureOnce(m, ctx)
	if d > 250*time.Millisecond {
		t.Fatalf("the aborted request took %s", d)
	}
	timeout("third request")
	if _, rec, d := captureOnce(m, nil); rec.Code != http.StatusServiceUnavailable || d > 100*time.Millisecond {
		t.Fatalf("three timeouts with one aborted request in between must open the breaker: status %d after %s", rec.Code, d)
	}
	if c := p.Status().Counters; c.CaptureFailures != 3 {
		t.Fatalf("the aborted request must not count as a failure of the plugin: %+v", c)
	}
}

func TestFaultFailedStartAfterAStopIsDownNotStopped(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "sentry", "mode=ok\nfeatures=hooks,failclosed\n", "t")
	yes := true
	if err := m.SetHookAdminSettings(p.Spec.ID, nil, &yes); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.BlockWhenDown = true })
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)

	//Stopped by the administrator (or by an update / a rebuild): out of the path
	if err := m.DisablePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("a plugin stopped by the administrator must not block requests")
	}

	//The start that follows fails (what a broken update looks like)
	bin := filepath.Join(p.RootDir, "sentry")
	if err := os.Rename(bin, bin+".gone"); err != nil {
		t.Fatal(err)
	}
	if err := m.StartPlugin(p.Spec.ID); err == nil {
		t.Fatal("the start without an entry point must fail")
	}
	if st := p.Status(); st.State != StateFailedToStart {
		t.Fatalf("state %q", st.State)
	}
	res, rec, _ := runPreAuth(m)
	if !res.Handled || !res.Denied || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a fail-closed plugin that failed to start after a stop must block with block-when-down: %+v status %d", res, rec.Code)
	}
	if c := p.Status().Counters; c.BlockedWhileDown != 1 {
		t.Fatalf("counters: %+v", c)
	}

	//Stop on the failed plugin ends the blocking, a working start serves again
	m.StopPlugin(p.Spec.ID)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("Stop on a plugin that failed to start must end the blocking")
	}
	if err := os.Rename(bin+".gone", bin); err != nil {
		t.Fatal(err)
	}
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("after a working start requests must pass again")
	}
}

func TestFaultUninstallForgetsPolicyAndConsent(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaosStopped(t, m, "tenant", "mode=ok\nfeatures=hooks,failclosed,api\n", "t")
	id := p.Spec.ID
	if !m.Options.Database.KeyExists(permDBTable, id) {
		t.Fatal("the test setup did not store the approved API permissions")
	}
	yes := true
	if err := m.SetHookAdminSettings(id, &yes, &yes); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, m, p, func(pp *PluginPolicy) {
		pp.Restart = RestartAlways
		pp.BlockWhenDown = true
		pp.MaxOpenFiles = 64
	})
	db := m.Options.Database
	if !db.KeyExists(policyDBTable, id) || !db.KeyExists(hookDBTable, id) {
		t.Fatal("the test setup did not store the policy and the hook settings")
	}
	if err := m.UninstallPlugin(id); err != nil {
		t.Fatal(err)
	}
	if db.KeyExists(policyDBTable, id) {
		t.Fatal("the policy of an uninstalled plugin is still in the database")
	}
	if db.KeyExists(hookDBTable, id) {
		t.Fatal("the global attach and fail-closed consent of an uninstalled plugin are still in the database")
	}
	if db.KeyExists(permDBTable, id) {
		t.Fatal("the approved API permissions of an uninstalled plugin are still in the database")
	}

	//A plugin installed later under the same ID starts with the defaults
	again := loadChaosStopped(t, m, "tenant", "mode=ok\nfeatures=hooks,failclosed\n", "t")
	m.loadHookAdminSettings(again)
	if again.Spec.ID != id {
		t.Fatalf("id %q", again.Spec.ID)
	}
	if pol := again.policy(); pol.Restart != RestartNever || pol.BlockWhenDown || pol.hasLimits() {
		t.Fatalf("the new install inherited the policy of the old one: %+v", pol)
	}
	if admin := again.hookAdminState(); admin.FailClosedConsent || again.isGlobal() {
		t.Fatalf("the new install inherited the consent of the old one: %+v", admin)
	}
}

/*
	Second review round: the port probe belongs to the status view of the Plugin
	Manager only, and the "last problem" never quotes the text of a network error.
*/

func statusAPI(t *testing.T, m *Manager, method string, query string, form string) pluginStatusDetail {
	t.Helper()
	var req *http.Request
	if method == http.MethodPost {
		req = httptest.NewRequest(method, "/api/plugins/status", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, "/api/plugins/status"+query, nil)
	}
	rec := httptest.NewRecorder()
	m.HandlePluginStatus(rec, req)
	var one pluginStatusDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatalf("status API: %v\n%s", err, rec.Body.String())
	}
	return one
}

// The probe is a TCP connection to the plugin. It is made for the status view of
// the Plugin Manager (probe=true) and for nothing else: not for the plugin list
// (side menu, plugins with the list permission) and not for a plain status call.
func TestFaultPortProbeOnlyForTheStatusView(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "viewprobed", "mode=hang_start\n", "t")
	p.startGrace = 50 * time.Millisecond
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) //past the start grace
	id := url.QueryEscape(p.Spec.ID)

	if v := listed(t, m, p.Spec.ID); v.Status.Health != HealthOK {
		t.Fatalf("the list API must not judge the port, got %+v", v.Status)
	}
	if st := statusAPI(t, m, http.MethodGet, "?plugin_id="+id, "").Status; st.Health != HealthOK {
		t.Fatalf("a status call without probe=true must not judge the port, got %+v", st)
	}
	statusAPI(t, m, http.MethodPost, "", "plugin_id="+id)
	if p.obs.probeAt.Load() != 0 {
		t.Fatal("the port of the plugin was probed although nobody asked for it")
	}

	if st := statusAPI(t, m, http.MethodGet, "?plugin_id="+id+"&probe=true", "").Status; st.State != StateRunning || st.Health != HealthNotListening {
		t.Fatalf("the status view (probe=true) must show a closed port, got %+v", st)
	}
	if p.obs.probeAt.Load() == 0 {
		t.Fatal("probe=true did not probe")
	}
	p.obs.probeAt.Store(0)
	if st := statusAPI(t, m, http.MethodPost, "", "plugin_id="+id+"&probe=true").Status; st.Health != HealthNotListening {
		t.Fatalf("the details call (POST, probe=true) must show a closed port, got %+v", st)
	}
	p.obs.probeAt.Store(0)
	rec := httptest.NewRecorder()
	m.HandlePluginStatus(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/status?probe=true", nil))
	if !strings.Contains(rec.Body.String(), `"Health":"`+HealthNotListening+`"`) {
		t.Fatalf("the status list (probe=true) must show a closed port: %s", rec.Body.String())
	}

	// The answer of a probe is not carried over into calls that did not ask for one
	if v := listed(t, m, p.Spec.ID); v.Status.Health != HealthOK {
		t.Fatalf("after a probe the list API must still not judge the port, got %+v", v.Status)
	}
	// A parameter on the list API (which plugins can be allowed to call) does nothing
	p.obs.probeAt.Store(0)
	m.HandleListPlugins(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/plugins/list?probe=true", nil))
	if p.obs.probeAt.Load() != 0 {
		t.Fatal("the list API probed the port")
	}
}

// The text of a network error can hold bytes the plugin sent and the address
// that was called. None of it may reach the status, which is readable by
// read-only accounts and by plugins with the list permission.
func TestLastProblemNeverQuotesANetworkError(t *testing.T) {
	leak := errors.New(`malformed HTTP response "LEAK<b>from-plugin</b>"`)
	wrapped := &url.Error{Op: "Post", URL: "http://127.0.0.1:5999/secret-path?token=LEAKTOKEN", Err: leak}
	refused := &url.Error{Op: "Post", URL: "http://127.0.0.1:5999/secret-path", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
	for name, got := range map[string]string{
		"filter call":       publicCallError(wrapped),
		"capture":           publicTransportError(leak),
		"capture, wrapped":  publicTransportError(wrapped),
		"refused":           publicCallError(refused),
		"aborted":           publicTransportError(fmt.Errorf("%w: %v", dpcore.ErrResponseAborted, leak)),
		"timeout":           publicTransportError(context.DeadlineExceeded),
		"closed connection": publicTransportError(io.ErrUnexpectedEOF),
	} {
		for _, bad := range []string{"LEAK", "from-plugin", "<b>", "secret-path", "5999", "malformed"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: the public text quotes the error (%q): %q", name, bad, got)
			}
		}
		if got == "" {
			t.Errorf("%s: empty text", name)
		}
	}
	if got := publicCallError(refused); !strings.Contains(got, "connection refused") {
		t.Errorf("a refused connection should be named: %q", got)
	}
	// Errors worded by Dunree itself stay as they are
	if got := publicCallError(errors.New("plugin answered HTTP 500")); got != "plugin answered HTTP 500" {
		t.Errorf("own wording changed: %q", got)
	}

	// End to end through the capture path
	p := &Plugin{}
	p.status.state = StateRunning
	if !p.beginCapture() {
		t.Fatal("not admitted")
	}
	p.captureResult(p.newCaptureWriter(httptest.NewRecorder()), "static capture", leak)
	st := p.Status().LastError
	if !strings.HasPrefix(st, "A static capture request failed: ") || strings.Contains(st, "LEAK") || strings.Contains(st, "malformed") {
		t.Fatalf("LastError after a failed capture: %q", st)
	}
}
