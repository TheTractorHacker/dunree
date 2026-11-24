package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/access"
	"github.com/foleyit/dunree/mod/auth"
	"github.com/foleyit/dunree/mod/blocklog"
	"github.com/foleyit/dunree/mod/crowdsec"
	"github.com/foleyit/dunree/mod/destguard"
	"github.com/foleyit/dunree/mod/info/logger"
	"github.com/foleyit/dunree/mod/netplan"
	"github.com/foleyit/dunree/mod/secaudit"
	"github.com/gorilla/csrf"
)

// sliceHSetup prepares the globals the overview and the network plan read: router with one rule, sys.db, a fresh plan
// manager and overview cache, and a security audit log in a temp dir.
func sliceHSetup(t *testing.T) {
	t.Helper()
	postureTestSystem(t)
	oldPlan, oldAudit, oldBlock, oldCS, oldAccess, oldRole, oldGuard, oldAllow := netplanMgr, secAudit, blockLog, crowdsecMgr, accessController, deployRoleMgr, destGuardMgr, adminAllowMgr
	netplanMgr = nil
	invalidateSecurityOverview()
	t.Cleanup(func() {
		netplanMgr, secAudit, blockLog, crowdsecMgr, accessController, deployRoleMgr, destGuardMgr, adminAllowMgr = oldPlan, oldAudit, oldBlock, oldCS, oldAccess, oldRole, oldGuard, oldAllow
		destguard.SetDefault(oldGuard)
		invalidateSecurityOverview()
	})
	sysdb.NewTable("settings")
	tmp := t.TempDir()
	ac, err := access.NewAccessController(&access.Options{Logger: *SystemWideLogger, ConfigFolder: filepath.Join(tmp, "access"),
		TrustedProxiesFile: filepath.Join(tmp, "tp.json"), Database: sysdb, SkipPublicIPCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	accessController = ac
	initDeployRole()
	initAdminExposure()
	CONF_FOLDER = t.TempDir()
	l, err := secaudit.New(secaudit.Options{Path: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	secAudit = l
}

func overviewMap(t *testing.T) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(securityOverviewJSON(time.Now()), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSecurityOverviewShapeBoundsAndNoSecrets(t *testing.T) {
	sliceHSetup(t)
	// a lot of everything: the answer must stay bounded
	blockLog = blocklog.New(filepath.Join(t.TempDir(), "blocked.json.gz"), 500, blocklog.DefaultSettings())
	for i := 0; i < 400; i++ {
		blockLog.Record(blocklog.Entry{Time: time.Now().Unix(), IP: "203.0.113." + strconv.Itoa(i%250), Host: "h" + strconv.Itoa(i) + ".example.com", Path: "/secret-path?token=" + postureSentinel, Status: 403, Reason: "waf", UA: postureSentinel})
	}
	for i := 0; i < 80; i++ {
		secAudit.Record(secaudit.Event{Actor: "root", Event: "trustedproxy.add", Target: "10.0.0." + strconv.Itoa(i), Detail: map[string]string{"password": postureSentinel}})
	}
	secAudit.Flush()
	for i := 0; i < 60; i++ {
		accessController.AddTrustedProxy("198.51.100."+strconv.Itoa(i), "proxy "+strconv.Itoa(i))
	}
	m := overviewMap(t)
	for _, k := range []string{"generated", "status", "role", "backends", "routes", "certs", "crowdsec", "ratelimit", "traffic", "events", "trusted", "warnings", "errors"} {
		if _, ok := m[k]; !ok {
			t.Errorf("section %s missing", k)
		}
	}
	if errs := m["errors"].([]interface{}); len(errs) != 0 {
		t.Fatalf("sections failed: %v", errs)
	}
	js := string(securityOverviewJSON(time.Now()))
	if len(js) > 48<<10 {
		t.Errorf("answer is %d bytes, it must stay small", len(js))
	}
	for _, bad := range []string{postureSentinel, "secret-path", "PasswordHash", "SecretKey"} {
		if strings.Contains(js, bad) {
			t.Errorf("overview leaks %q", bad)
		}
	}
	ev := m["events"].(map[string]interface{})
	if n := len(ev["audit"].([]interface{})); n != ovMaxAudit {
		t.Errorf("audit events: %d, want exactly the cap %d", n, ovMaxAudit)
	}
	if n := len(ev["blocked"].([]interface{})); n != ovMaxBlocked {
		t.Errorf("blocked events: %d, want %d", n, ovMaxBlocked)
	}
	tr := m["trusted"].(map[string]interface{})
	if int(tr["count"].(float64)) < 60 || len(tr["entries"].([]interface{})) != ovMaxTrusted {
		t.Errorf("trusted proxies not summarised: %v", tr["count"])
	}
	traffic := m["traffic"].(map[string]interface{})
	if len(traffic["series"].([]interface{})) != 30 || len(traffic["blockLog"].(map[string]interface{})["hourly"].([]interface{})) != 24 {
		t.Error("chart series must be fixed length")
	}
	if n := len(traffic["blockLog"].(map[string]interface{})["reasons"].([]interface{})); n > ovMaxReasons {
		t.Errorf("%d reasons", n)
	}
	w := m["warnings"].(map[string]interface{})
	items := w["items"].([]interface{})
	if len(items) == 0 || len(items) > ovMaxWarnings {
		t.Fatalf("warnings: %d", len(items))
	}
	// severity sorted: failures before warnings before unknowns, heavier first within a status
	rank := map[string]int{"fail": 0, "warn": 1, "unknown": 2}
	prev, prevW := -1, 100
	for _, it := range items {
		x := it.(map[string]interface{})
		r := rank[x["status"].(string)]
		if r < prev {
			t.Fatalf("warnings are not sorted by status: %v", x["id"])
		}
		if r > prev {
			prev, prevW = r, 100
		}
		if wt := int(x["weight"].(float64)); wt > prevW {
			t.Fatalf("warnings are not sorted by weight within a status: %v", x["id"])
		} else {
			prevW = wt
		}
		if x["fix"].(string) == "" {
			t.Errorf("%v has no one-line fix", x["id"])
		}
		if len(x["evidence"].(string)) > ovEvidenceChars+3 {
			t.Errorf("%v evidence is not clipped", x["id"])
		}
	}
	if _, ok := m["score"]; !ok {
		t.Error("score missing")
	}
}

func TestOverviewBackendsWorstFirstAndBounded(t *testing.T) {
	var g GlanceData
	for i := 0; i < 100; i++ {
		g.Upstreams = append(g.Upstreams, glanceUp{Name: "up" + strconv.Itoa(i), URL: "http://10.0.0." + strconv.Itoa(i), Online: i%10 != 0, StatusCode: 200, LatencyMs: int64(i)})
	}
	g.UpstreamsTotal = 100
	b := ovBackends(g, true)
	items := b["items"].([]map[string]interface{})
	if len(items) != ovMaxBackends || b["down"].(int) != 10 {
		t.Fatalf("%d items, down=%v", len(items), b["down"])
	}
	for i := 0; i < 10; i++ { // all ten down ones come first
		if items[i]["online"].(bool) {
			t.Fatalf("item %d is up but a down upstream was left out", i)
		}
	}
	if items[10]["latencyMs"].(int64) < items[11]["latencyMs"].(int64) {
		t.Error("after the down ones the slowest comes first")
	}
	if b := ovBackends(GlanceData{}, false); len(b["items"].([]map[string]interface{})) != 0 || b["monitored"].(bool) {
		t.Error("empty state")
	}
}

func TestOverviewIsCachedAndInvalidated(t *testing.T) {
	sliceHSetup(t)
	t0 := time.Now()
	first := securityOverviewJSON(t0)
	accessController.AddTrustedProxy("192.0.2.77", "new")
	if string(securityOverviewJSON(t0.Add(2*time.Second))) != string(first) {
		t.Fatal("a second request inside the TTL must be served from the cache")
	}
	if string(securityOverviewJSON(t0.Add(6*time.Second))) == string(first) {
		t.Fatal("after the TTL the answer must be rebuilt")
	}
	invalidateSecurityOverview()
	var m map[string]interface{}
	json.Unmarshal(securityOverviewJSON(t0.Add(6*time.Second)), &m)
	if int(m["trusted"].(map[string]interface{})["count"].(float64)) == 0 {
		t.Fatal("invalidation must rebuild")
	}
}

func TestOverviewOneSectionFailingDoesNotBreakThePage(t *testing.T) {
	sliceHSetup(t)
	crowdsecMgr = &crowdsec.Manager{} // a zero manager panics when read
	m := overviewMap(t)
	errs := m["errors"].([]interface{})
	if len(errs) != 1 || errs[0] != "crowdsec" {
		t.Fatalf("errors: %v", errs)
	}
	if _, ok := m["status"]; !ok {
		t.Fatal("the other sections must still be served")
	}
	if _, ok := m["crowdsec"]; ok {
		t.Fatal("the failed section must be left out, not half filled")
	}
}

func TestOverviewEmptyInstanceHasEmptyStates(t *testing.T) {
	sliceHSetup(t)
	crowdsecMgr = nil
	blockLog = nil
	m := overviewMap(t)
	if m["crowdsec"].(map[string]interface{})["state"] != "off" {
		t.Error("crowdsec off state")
	}
	if len(m["events"].(map[string]interface{})["blocked"].([]interface{})) != 0 {
		t.Error("no blocked events")
	}
	if m["backends"].(map[string]interface{})["monitored"].(bool) {
		t.Error("no uptime monitor in this fixture")
	}
}

func TestOverviewMakesNoNetworkCalls(t *testing.T) {
	sliceHSetup(t)
	// every DNS lookup goes through a resolver that counts (and refuses) the attempt
	var lookups atomic.Int32
	oldRes := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("blocked by the test")
	}}
	t.Cleanup(func() { net.DefaultResolver = oldRes })
	// a backend written as a name, and an allowed backend list that would make Dunree resolve it
	ep, _ := dynamicProxyRouter.LoadProxy("app.example.com")
	ep.ActiveOrigins[0].OriginIpOrDomain = "does-not-resolve.invalid:8080"
	if err := destGuardMgr.Set(destguard.Settings{AllowedBackends: []string{"10.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	m := overviewMap(t)
	if n := lookups.Load(); n != 0 {
		t.Fatalf("the overview made %d DNS lookups", n)
	}
	if len(m["errors"].([]interface{})) != 0 {
		t.Fatalf("%v", m["errors"])
	}
	// the page that validates (and the posture page) do resolve names: the counter must see it, or this test proves nothing
	collectPostureFactsDNS(true)
	if lookups.Load() == 0 {
		t.Fatal("the resolver hook is not exercised, the test above is meaningless")
	}
	f := collectNetPlanFacts()
	if f.Unresolved != 1 || f.Backends[0].Addr.IsValid() {
		t.Fatalf("a name must be reported unchecked, not resolved: %+v", f.Backends)
	}
}

/* ---- HTTP: roles, CSRF, viewer denial ---- */

func sliceHHTTP(t *testing.T) (http.Handler, *http.Cookie, *http.Cookie) {
	t.Helper()
	sliceHSetup(t)
	lg, _ := logger.NewFmtLogger()
	old := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { auth.ProfileAdmin = old })
	authAgent = auth.NewAuthenticationAgent("t", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "401", http.StatusUnauthorized) })
	authAgent.CreateUserAccount("root", "password-1", "")
	authAgent.CreateUser("view", "password-2", auth.RoleViewer)
	mux := http.NewServeMux()
	rt := auth.NewManagedHTTPRouter(auth.RouterOption{AuthAgent: authAgent, RequireAuth: true, TargetMux: mux,
		DeniedHandler: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "401", http.StatusUnauthorized) }})
	RegisterSecurityOverviewAPIs(rt)
	RegisterNetPlanAPIs(rt)
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(csrf.Token(r))) })
	protected := csrf.Protect([]byte("0123456789abcdef0123456789abcdef"), csrf.Secure(false), csrf.Path("/"))(mux)
	login := func(user, pw string) *http.Cookie {
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader("username="+user+"&password="+pw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authAgent.HandleLogin(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == authAgent.SessionName && c.Value != "" {
				return c
			}
		}
		t.Fatal("login failed for " + user)
		return nil
	}
	return protected, login("root", "password-1"), login("view", "password-2")
}

func formCall(h http.Handler, method, path, body string, cookies []*http.Cookie, token string, csrfCookies []*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range append(append([]*http.Cookie{}, cookies...), csrfCookies...) {
		r.AddCookie(c)
	}
	if token != "" {
		r.Header.Set("X-CSRF-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOverviewAndNetPlanAuthViewerAndCSRF(t *testing.T) {
	h, adminC, viewC := sliceHHTTP(t)
	paths := []string{"/api/security/overview", "/api/netplan/get", "/api/netplan/policy", "/api/netplan/policy?download=1"}

	for _, p := range paths { // anonymous
		if w := formCall(h, "GET", p, "", nil, "", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous GET %s = %d", p, w.Code)
		}
	}
	for _, p := range paths { // viewer: everything here exposes configuration
		if w := formCall(h, "GET", p, "", []*http.Cookie{viewC}, "", nil); w.Code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", p, w.Code)
		}
	}
	tok := formCall(h, "GET", "/token", "", []*http.Cookie{adminC}, "", nil)
	token, cc := tok.Body.String(), tok.Result().Cookies()
	vt := formCall(h, "GET", "/token", "", []*http.Cookie{viewC}, "", nil)
	body := "config=" + `{"appPorts":["443"]}`
	if w := formCall(h, "POST", "/api/netplan/set", body, []*http.Cookie{viewC}, vt.Body.String(), vt.Result().Cookies()); w.Code != http.StatusForbidden {
		t.Errorf("viewer POST set = %d", w.Code)
	}
	if getNetPlan().Declared() {
		t.Fatal("a viewer request changed the plan")
	}
	// admin: reads work, writes need the token
	for _, p := range paths {
		if w := formCall(h, "GET", p, "", []*http.Cookie{adminC}, "", nil); w.Code != 200 {
			t.Errorf("admin GET %s = %d %s", p, w.Code, w.Body.String())
		}
	}
	if w := formCall(h, "POST", "/api/netplan/set", body, []*http.Cookie{adminC}, "", cc); w.Code != http.StatusForbidden {
		t.Errorf("set without CSRF token = %d", w.Code)
	}
	if w := formCall(h, "POST", "/api/netplan/set", body, []*http.Cookie{adminC}, "wrong", cc); w.Code != http.StatusForbidden {
		t.Errorf("set with a wrong CSRF token = %d", w.Code)
	}
	if getNetPlan().Declared() {
		t.Fatal("a refused request changed the plan")
	}
	// wrong methods
	if w := formCall(h, "GET", "/api/netplan/set", "", []*http.Cookie{adminC}, "", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET set = %d", w.Code)
	}
	if w := formCall(h, "POST", "/api/security/overview", "a=b", []*http.Cookie{adminC}, token, cc); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST overview = %d", w.Code)
	}
	if w := formCall(h, "POST", "/api/netplan/policy", "a=b", []*http.Cookie{adminC}, token, cc); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST policy = %d", w.Code)
	}
	// and the real write goes through
	if w := formCall(h, "POST", "/api/netplan/set", body, []*http.Cookie{adminC}, token, cc); w.Code != 200 || !strings.Contains(w.Body.String(), "OK") {
		t.Fatalf("admin set: %d %s", w.Code, w.Body.String())
	}
	if !getNetPlan().Declared() {
		t.Fatal("not saved")
	}
}

func TestViewerDeniedPrefixesCoverTheNewEndpoints(t *testing.T) {
	for _, p := range []string{"/api/security/overview", "/api/netplan/get", "/api/netplan/set", "/api/netplan/policy"} {
		for _, m := range []string{"GET", "POST", "HEAD"} {
			if auth.ViewerAllowed(m, p) {
				t.Errorf("a viewer may %s %s", m, p)
			}
		}
	}
	if !auth.ViewerAllowed("GET", "/api/stats/glance") {
		t.Error("the prefix must not widen to unrelated reads")
	}
}

func TestNetPlanAuditAndHistoryRoutes(t *testing.T) {
	ev, ok := secaudit.Classify("POST", "/api/netplan/set", map[string]string{"config": "{}"})
	if !ok || ev != "netplan.set" {
		t.Fatalf("a plan change must be audited as netplan.set, got %q %v", ev, ok)
	}
	if _, ok := secaudit.Classify("GET", "/api/netplan/get", nil); ok {
		t.Error("reads are not recorded as changes")
	}
}

var _ = netplan.DBKey

// the dashboard promises no secrets: URLs and error strings are scrubbed before they are served
func TestOverviewClipScrubsCredentialsFromUrlsAndErrors(t *testing.T) {
	for _, in := range []string{
		"https://admin:hunter2@status.example.com/ping",
		"https://TOKEN-ONLY@status.example.com/ping",
		"https://status.example.com/ping?token=abc123&x=1",
		`Get "https://api.crowdsec.example/v1/decisions?api_key=SEKRET": dial tcp: refused`,
		"upstream said: Authorization Bearer abcdef123456.zzz",
	} {
		out := clip(in, 240)
		for _, leak := range []string{"hunter2", "TOKEN-ONLY", "abc123", "SEKRET", "abcdef123456"} {
			if strings.Contains(out, leak) {
				t.Errorf("clip leaked %q from %q: %q", leak, in, out)
			}
		}
	}
	if out := clip("https://status.example.com/ping?x=1", 240); out != "https://status.example.com/ping?x=1" {
		t.Errorf("a harmless URL was altered: %q", out)
	}
}
