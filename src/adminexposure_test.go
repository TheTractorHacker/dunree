package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/adminallow"
	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/destguard"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/loadbalance"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
)

func exposureSetup(t *testing.T) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldDB, oldLog, oldG, oldA, oldFlag := sysdb, SystemWideLogger, destGuardMgr, adminAllowMgr, *resetAdminAllowList
	sysdb = db
	sysdb.NewTable("settings")
	if SystemWideLogger == nil {
		l, _ := logger.NewFmtLogger()
		SystemWideLogger = l
	}
	*resetAdminAllowList = false
	initAdminExposure()
	t.Cleanup(func() {
		sysdb, SystemWideLogger, destGuardMgr, adminAllowMgr, *resetAdminAllowList = oldDB, oldLog, oldG, oldA, oldFlag
		destguard.SetDefault(oldG)
	})
}

func exposurePost(h http.HandlerFunc, remote, cfg string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{"config": {cfg}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestAdminAllowAPILockoutProtection(t *testing.T) {
	exposureSetup(t)
	if adminAllowMgr.Active() || destGuardMgr.Restricting() || destGuardMgr.HasAllowList() {
		t.Fatal("a fresh install must have both features off")
	}
	// a list without the caller is refused and not stored
	w := exposurePost(HandleAdminAllowSet, "203.0.113.9:5555", `{"cidrs":["192.168.10.0/24"]}`)
	if !strings.Contains(w.Body.String(), "lock you out") || adminAllowMgr.Active() {
		t.Fatalf("lock-out list accepted: %s active=%v", w.Body.String(), adminAllowMgr.Active())
	}
	// a forged X-Forwarded-For does not make the caller "inside"
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{"config": {`{"cidrs":["192.168.10.0/24"]}`}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-For", "192.168.10.5")
	r.Header.Set("X-Real-IP", "192.168.10.5")
	r.RemoteAddr = "203.0.113.9:1"
	rec := httptest.NewRecorder()
	HandleAdminAllowSet(rec, r)
	if !strings.Contains(rec.Body.String(), "lock you out") || adminAllowMgr.Active() {
		t.Fatalf("spoofed header bypassed the lock-out check: %s", rec.Body.String())
	}
	for _, bad := range []string{`{"cidrs":["0.0.0.0/0"]}`, `{"cidrs":["203.0.113.0/24"],"bogus":1}`, `nonsense`} {
		if w := exposurePost(HandleAdminAllowSet, "203.0.113.9:1", bad); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("%s accepted: %s", bad, w.Body.String())
		}
	}
	if w := exposurePost(HandleAdminAllowSet, "203.0.113.9:1", `{"cidrs":["203.0.113.0/24"]}`); strings.Contains(w.Body.String(), "error") || !adminAllowMgr.Active() {
		t.Fatalf("list containing the caller refused: %s", w.Body.String())
	}
	g := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/api/adminallow/get", nil)
	r2.RemoteAddr = "203.0.113.9:1"
	HandleAdminAllowGet(g, r2)
	var v adminAllowView
	if err := json.Unmarshal(g.Body.Bytes(), &v); err != nil || !v.Active || v.YourAddr != "203.0.113.9" || len(v.CIDRs) != 1 {
		t.Fatalf("%v %+v", err, v)
	}
	// persists across a restart (new managers over the same db)
	initAdminExposure()
	if !adminAllowMgr.Active() {
		t.Fatal("allow-list lost on restart")
	}
	// recovery flag clears it before the admin port serves
	*resetAdminAllowList = true
	initAdminExposure()
	if adminAllowMgr.Active() {
		t.Fatal("-reset_admin_allowlist did not clear the list")
	}
	*resetAdminAllowList = false
	initAdminExposure()
	if adminAllowMgr.Active() {
		t.Fatal("reset was not persisted")
	}
	// the wrapped admin handler is a pass-through again
	reached := false
	h := adminHandlerWithAllowList(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	rr := httptest.NewRequest("GET", "/", nil)
	rr.RemoteAddr = "198.51.100.1:1"
	h.ServeHTTP(httptest.NewRecorder(), rr)
	if !reached {
		t.Fatal("no allow-list but the request was refused")
	}
}

func TestDestGuardAPIAndRuleTargetValidation(t *testing.T) {
	exposureSetup(t)
	// no list: any target is accepted (today)
	for _, tgt := range []string{"127.0.0.1:8000", "169.254.169.254:80", "unix:/run/x.sock", "app.lan:80"} {
		if err := validateBackendTarget(tgt, false); err != nil {
			t.Fatalf("%s refused without a list: %v", tgt, err)
		}
	}
	if w := exposurePost(HandleDestGuardSet, "198.51.100.1:1", `{"restrictTools":true,"allowedBackends":["10.20.0.0/24","10.30.0.5 443"]}`); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	for _, bad := range []string{`{"allowedBackends":["example.com"]}`, `{"allowedBackends":["0.0.0.0/0"]}`, `{"restrictTools":true,"x":1}`} {
		if w := exposurePost(HandleDestGuardSet, "198.51.100.1:1", bad); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("%s accepted", bad)
		}
	}
	if !destguard.Restricting() {
		t.Fatal("default guard not installed")
	}
	for tgt, wantErr := range map[string]bool{"10.20.0.7:8080": false, "10.30.0.5:443": false, "10.30.0.5:80": true, "10.21.0.1:80": true, "127.0.0.1:8000": true,
		"169.254.169.254:80": true, "[fd00:ec2::254]:80": true, "https://10.20.0.9/app": false, "unix:/run/x.sock": false} {
		if err := validateBackendTarget(tgt, false); (err != nil) != wantErr {
			t.Errorf("%s: err=%v want error=%v", tgt, err, wantErr)
		}
	}
	// an upstream written without a port is judged by the port it will really use (80 / 443), never "any port"
	for _, c := range []struct {
		tgt  string
		tls  bool
		want bool
	}{{"10.30.0.5", false, true}, {"10.30.0.5", true, false}, {"https://10.30.0.5", false, false}, {"http://10.30.0.5", false, true},
		{"10.20.0.7", false, false}, {"10.20.0.7", true, false}} {
		if err := validateBackendTarget(c.tgt, c.tls); (err != nil) != c.want {
			t.Errorf("port-less %s tls=%v: err=%v want error=%v", c.tgt, c.tls, err, c.want)
		}
	}
	// and the test tool dials through the guard
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	res := testUpstream(strings.TrimPrefix(srv.URL, "http://"))
	if res.OK || res.Error == "" {
		t.Fatalf("upstream test reached loopback with the restriction on: %+v", res)
	}
	if res := testUpstream("169.254.169.254"); res.OK {
		t.Fatalf("upstream test reached the metadata address: %+v", res)
	}
	if res := testUpstream("unix:/tmp/none.sock"); res.OK || !strings.Contains(res.Error, "restriction") {
		t.Fatalf("unix socket test under restriction: %+v", res)
	}
	// listing loopback allows the test tool again
	exposurePost(HandleDestGuardSet, "198.51.100.1:1", `{"restrictTools":true,"allowedBackends":["127.0.0.1/32"]}`)
	if res := testUpstream(strings.TrimPrefix(srv.URL, "http://")); !res.OK {
		t.Fatalf("listed loopback refused: %+v", res)
	}
	// switching everything off restores today's behaviour
	exposurePost(HandleDestGuardSet, "198.51.100.1:1", `{"restrictTools":false,"allowedBackends":[]}`)
	if err := validateBackendTarget("169.254.169.254:80", false); err != nil || destguard.Restricting() {
		t.Fatalf("settings off but still restricting: %v", err)
	}
	if res := testUpstream(strings.TrimPrefix(srv.URL, "http://")); !res.OK {
		t.Fatalf("unrestricted upstream test broken: %+v", res)
	}
}

func TestRuleTargetsAdminListener(t *testing.T) {
	old := *webUIPort
	defer func() { *webUIPort = old }()
	ep := func(origins ...string) *dynamicproxy.ProxyEndpoint {
		e := &dynamicproxy.ProxyEndpoint{}
		for _, o := range origins {
			e.ActiveOrigins = append(e.ActiveOrigins, &loadbalance.Upstream{OriginIpOrDomain: o})
		}
		return e
	}
	*webUIPort = ":8000"
	for _, o := range []string{"127.0.0.1:8000", "localhost:8000", "[::1]:8000", "0.0.0.0:8000"} {
		if !ruleTargetsAdminListener(ep("10.0.0.5:80", o)) {
			t.Errorf("%s not recognised as the admin listener", o)
		}
	}
	for _, o := range []string{"127.0.0.1:8001", "10.0.0.5:8000", "example.invalid:8000", "127.0.0.1"} {
		if ruleTargetsAdminListener(ep(o)) {
			t.Errorf("%s flagged", o)
		}
	}
	// a virtual directory counts too
	e := ep("10.0.0.5:80")
	e.VirtualDirectories = []*dynamicproxy.VirtualDirectoryEndpoint{{MatchingPath: "/admin/", Domain: "127.0.0.1:8000"}}
	if !ruleTargetsAdminListener(e) {
		t.Error("virtual directory to the admin port not flagged")
	}
	// admin bound to one address: only that address reaches it
	*webUIPort = "127.0.0.1:9000"
	if !ruleTargetsAdminListener(ep("127.0.0.1:9000")) || ruleTargetsAdminListener(ep("10.0.0.5:9000")) {
		t.Error("specific bind address not honoured")
	}
}

func TestGlobalReadTimeoutAPI(t *testing.T) {
	exposureSetup(t) //temp sysdb
	router := setupEditTest(t)
	timeoutPost := func(v url.Values) string {
		r := httptest.NewRequest(http.MethodPost, "/api/proxy/timeouts", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandleGlobalProxyTimeoutSettings(w, r)
		return w.Body.String()
	}
	get := func() globalProxyTimeoutSettings {
		w := httptest.NewRecorder()
		HandleGlobalProxyTimeoutSettings(w, httptest.NewRequest(http.MethodGet, "/api/proxy/timeouts", nil))
		var s globalProxyTimeoutSettings
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatalf("%v: %s", err, w.Body.String())
		}
		return s
	}
	if s := get(); s.ReadTimeout != 0 {
		t.Fatalf("default read timeout %d, want 0 (off)", s.ReadTimeout)
	}
	base := url.Values{"readHeaderTimeout": {"30"}, "writeTimeout": {"0"}, "idleTimeout": {"60"}}
	// an older client that does not know the field leaves it alone
	if out := timeoutPost(base); strings.Contains(out, "error") {
		t.Fatal(out)
	}
	if s := get(); s.ReadTimeout != 0 || s.IdleTimeout != 60 {
		t.Fatalf("%+v", s)
	}
	with := url.Values{"readHeaderTimeout": {"30"}, "readTimeout": {"45"}, "writeTimeout": {"0"}, "idleTimeout": {"60"}}
	if out := timeoutPost(with); strings.Contains(out, "error") {
		t.Fatal(out)
	}
	if s := get(); s.ReadTimeout != 45 || router.Option.ReadTimeout != 45 {
		t.Fatalf("not applied: %+v", s)
	}
	var stored int
	if err := sysdb.Read("settings", "readTimeout", &stored); err != nil || stored != 45 {
		t.Fatalf("not persisted: %v %d", err, stored)
	}
	// a client that omits it again does not reset it
	timeoutPost(base)
	if s := get(); s.ReadTimeout != 45 {
		t.Fatalf("omitted field reset the value: %+v", s)
	}
	for _, bad := range []string{"-1", "x", "99999999"} {
		v := url.Values{"readHeaderTimeout": {"30"}, "readTimeout": {bad}, "writeTimeout": {"0"}, "idleTimeout": {"60"}}
		if out := timeoutPost(v); !strings.Contains(out, "error") {
			t.Errorf("readTimeout=%s accepted", bad)
		}
	}
	if s := get(); s.ReadTimeout != 45 {
		t.Fatalf("a refused value changed the setting: %+v", s)
	}
	timeoutPost(url.Values{"readHeaderTimeout": {"30"}, "readTimeout": {"0"}, "writeTimeout": {"0"}, "idleTimeout": {"60"}})
	if s := get(); s.ReadTimeout != 0 {
		t.Fatalf("cannot switch back off: %+v", s)
	}
}

// The admin listener dial guard is armed by initAdminExposure: with an allow-list a proxy rule cannot dial the admin port.
func TestAdminPortDialGuardArmedBySetup(t *testing.T) {
	exposureSetup(t)
	old := *webUIPort
	defer func() { *webUIPort = old; adminallow.InstallDialGuard(nil, "") }()
	*webUIPort = ":8123"
	adminallow.InstallDialGuard(adminAllowMgr, *webUIPort)
	if adminallow.DialBlocked("tcp", "127.0.0.1:8123") {
		t.Fatal("dial blocked without an allow-list (default must not change)")
	}
	if w := exposurePost(HandleAdminAllowSet, "127.0.0.1:5555", `{"cidrs":["127.0.0.1"]}`); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if !adminallow.DialBlocked("tcp", "127.0.0.1:8123") || adminallow.DialBlocked("tcp", "127.0.0.1:8124") {
		t.Fatal("dial to the admin port not refused (or an unrelated port was)")
	}
}

// An unrelated edit of an upstream that predates the allowed backend list must not be refused for its old target;
// moving it to a target outside the list still is.
func TestUpstreamUpdateValidatesOnlyChangedTarget(t *testing.T) {
	setupEditTest(t)
	exposureSetup(t)
	if err := destGuardMgr.Set(destguard.Settings{AllowedBackends: []string{"10.20.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	update := func(payload string) string {
		r := httptest.NewRequest(http.MethodPost, "/api/proxy/upstream/update", strings.NewReader(url.Values{
			"ep": {"app.example.com"}, "origin": {"127.0.0.1:1"}, "payload": {payload}, "active": {"true"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		func() {
			defer func() { _ = recover() }() //uptime monitor is not set up in this test, after the part under test
			ReverseProxyUpstreamUpdate(w, r)
		}()
		return w.Body.String()
	}
	if out := update(`{"Weight":3}`); strings.Contains(out, "allowed backend") {
		t.Errorf("unchanged target was re-validated: %s", out)
	}
	if out := update(`{"OriginIpOrDomain":"192.0.2.9:80"}`); !strings.Contains(out, "allowed backend") {
		t.Errorf("target moved outside the list was accepted: %s", out)
	}
}

// Config import and history restore bypass the save-time check: existing violators are reported (posture fact)
func TestBackendViolationsReportExistingTargets(t *testing.T) {
	setupEditTest(t) //one rule, upstream 127.0.0.1:1
	exposureSetup(t)
	if v := backendViolations(); len(v) != 0 {
		t.Fatalf("no list, yet violations: %v", v)
	}
	if err := destGuardMgr.Set(destguard.Settings{AllowedBackends: []string{"10.20.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if v := backendViolations(); len(v) != 1 || !strings.Contains(v[0], "127.0.0.1:1") {
		t.Fatalf("existing violating upstream not reported: %v", v)
	}
	if err := destGuardMgr.Set(destguard.Settings{AllowedBackends: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if v := backendViolations(); len(v) != 0 {
		t.Fatalf("listed upstream reported: %v", v)
	}
}

// The Deployment card must save the administrator's own "harden headers" choice, never the state the role forces on screen
func TestDeploymentCardRemembersOwnHardenChoice(t *testing.T) {
	b, err := os.ReadFile("web/components/security/deployment.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, `hardenHeaders: $("#drHarden").prop("checked")`) {
		t.Error("save() still reads the (possibly forced) checkbox")
	}
	for _, want := range []string{`hardenHeaders: ownHarden`, `forced ? true : ownHarden`, `ownHarden = !!d.hardenHeaders`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}
