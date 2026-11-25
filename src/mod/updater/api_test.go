package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func call(h http.HandlerFunc, method, target string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.RemoteAddr = "192.0.2.7:5555"
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestAPIHandlers(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v1.1.0", false, time.Hour, "NEW"))
	m := f.m

	// mutations require POST
	for name, h := range map[string]http.HandlerFunc{"start": m.HandleStart, "rollback": m.HandleRollback, "channel": m.HandleSetChannel, "backup": m.HandleSetBackup} {
		if rec := call(h, "GET", "/x", nil); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: GET gave %d", name, rec.Code)
		}
	}

	// info (no network)
	rec := call(m.HandleInfo, "GET", "/info", nil)
	if rec.Code != 200 || f.gh.hit("/repos/o/r/releases") != 0 {
		t.Fatalf("info: %d hits=%d", rec.Code, f.gh.hit("/repos/o/r/releases"))
	}
	var info struct {
		Settings  Settings
		Preflight Preflight
	}
	json.Unmarshal(rec.Body.Bytes(), &info)
	if info.Settings.Channel != "stable" || !info.Settings.BackupFirst || info.Preflight.AppBlocked != "" {
		t.Errorf("info: %s", rec.Body.String())
	}

	// check
	rec = call(m.HandleCheck, "GET", "/check?force=true", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"update_available":true`) {
		t.Fatalf("check: %d %s", rec.Code, rec.Body.String())
	}

	// settings
	if rec := call(m.HandleSetChannel, "POST", "/c", url.Values{"channel": {"nightly"}}); rec.Code != 400 {
		t.Errorf("bad channel: %d", rec.Code)
	}
	if rec := call(m.HandleSetChannel, "POST", "/c", url.Values{"channel": {"beta"}}); rec.Code != 200 || m.Settings().Channel != "beta" {
		t.Errorf("set channel: %d", rec.Code)
	}
	if rec := call(m.HandleSetBackup, "POST", "/b", url.Values{"enabled": {"maybe"}}); rec.Code != 400 {
		t.Errorf("bad bool: %d", rec.Code)
	}
	if rec := call(m.HandleSetBackup, "POST", "/b", url.Values{"enabled": {"false"}}); rec.Code != 200 || m.Settings().BackupFirst {
		t.Errorf("set backup: %d", rec.Code)
	}

	// start validation
	if rec := call(m.HandleStart, "POST", "/s", url.Values{"action": {"app"}}); rec.Code != 400 {
		t.Errorf("missing confirm: %d", rec.Code)
	}
	if rec := call(m.HandleStart, "POST", "/s", url.Values{"action": {"nope"}, "confirm": {"true"}}); rec.Code != 400 {
		t.Errorf("bad action: %d", rec.Code)
	}
	if rec := call(m.HandleStart, "POST", "/s", url.Values{"action": {"db"}, "confirm": {"true"}}); rec.Code != 409 {
		t.Errorf("db without migrate func must be refused: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(m.HandleRollback, "POST", "/r", url.Values{"confirm": {"true"}}); rec.Code != 409 {
		t.Errorf("rollback with no prev: %d", rec.Code)
	}

	// start app, then a second start is throttled
	gate := make(chan struct{})
	f.smoke = func(context.Context, string) (string, error) { <-gate; return "Dunree - Version 1.1.0", nil }
	rec = call(m.HandleStart, "POST", "/s", url.Values{"action": {"app"}, "confirm": {"true"}, "backup": {"false"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(m.HandleStart, "POST", "/s", url.Values{"action": {"app"}, "confirm": {"true"}}); rec.Code != 409 {
		t.Errorf("concurrent start: %d", rec.Code)
	}
	if rec := call(m.HandleSetChannel, "POST", "/c", url.Values{"channel": {"stable"}}); rec.Code != 409 {
		t.Errorf("channel change while running: %d", rec.Code)
	}
	var st Status
	json.Unmarshal(call(m.HandleStatus, "GET", "/st", nil).Body.Bytes(), &st)
	if st.State != "running" || st.Op != "app" {
		t.Errorf("status: %+v", st)
	}
	close(gate)
	deadline := time.Now().Add(5 * time.Second)
	for m.Status().State != "restarting" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.Status().State != "restarting" {
		t.Fatalf("did not finish: %+v", m.Status())
	}

	// history newest first
	var hist []HistoryEntry
	json.Unmarshal(call(m.HandleHistory, "GET", "/h", nil).Body.Bytes(), &hist)
	if len(hist) != 1 || hist[0].To != "v1.1.0" {
		t.Errorf("history: %+v", hist)
	}
}

func TestAPIDockerBlocksStart(t *testing.T) {
	f := newFixture(t)
	f.build(func(c *Config) { c.InDocker = true })
	rec := call(f.m.HandleStart, "POST", "/s", url.Values{"action": {"app"}, "confirm": {"true"}})
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "Docker") {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestAPICheckError(t *testing.T) {
	f := newFixture(t)
	f.gh.srv.Close()
	rec := call(f.m.HandleCheck, "GET", "/check", nil)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d", rec.Code)
	}
}

func TestAutoCheckDefaultsOffAndPersists(t *testing.T) {
	f := newFixture(t)
	m := f.m
	if m.AutoCheckEnabled() || m.Settings().AutoCheck {
		t.Fatal("the daily update check must be off by default")
	}
	if rec := call(m.HandleSetAutoCheck, "GET", "/x", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET gave %d, want 405", rec.Code)
	}
	if rec := call(m.HandleSetAutoCheck, "POST", "/x", url.Values{"enabled": {"maybe"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a bad value gave %d, want 400", rec.Code)
	}
	if rec := call(m.HandleSetAutoCheck, "POST", "/x", url.Values{"enabled": {"true"}}); rec.Code != 200 || !m.AutoCheckEnabled() {
		t.Fatalf("enabling: %d", rec.Code)
	}
	// the other settings written later must not switch it off
	if err := m.SetBackupFirst(false); err != nil {
		t.Fatal(err)
	}
	if err := m.SetChannel(ChannelBeta); err != nil {
		t.Fatal(err)
	}
	if !m.AutoCheckEnabled() {
		t.Fatal("saving another setting reset the daily check")
	}
	if rec := call(m.HandleSetAutoCheck, "POST", "/x", url.Values{"enabled": {"false"}}); rec.Code != 200 || m.AutoCheckEnabled() {
		t.Fatal("disabling did not work")
	}
}

func TestBadgeFollowsTheSettingAndNeverUsesTheNetwork(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v1.1.0", false, time.Hour, "NEW"))
	m := f.m
	badge := func() map[string]any {
		before := f.gh.hit("/repos/o/r/releases")
		rec := call(m.HandleBadge, "GET", "/api/updater/badge", nil)
		if f.gh.hit("/repos/o/r/releases") != before {
			t.Fatal("the badge endpoint made a network request")
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err, rec.Body.String())
		}
		return out
	}
	// a check was made (as the Update page does) but the daily check is off: the badge reports nothing
	if _, err := m.Check(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if out := badge(); out["auto_check"] != false || out["update_available"] != false {
		t.Fatalf("with the daily check off the badge must stay silent: %v", out)
	}
	m.SetAutoCheck(true)
	out := badge()
	if out["auto_check"] != true || out["update_available"] != true || out["latest"] != "v1.1.0" {
		t.Fatalf("with the daily check on the badge must show the cached release: %v", out)
	}
}
