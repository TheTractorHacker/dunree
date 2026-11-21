package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/baseline"
	"imuslab.com/zoraxy/mod/deployrole"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/secaudit"
)

func baselineSetup(t *testing.T, fresh bool) {
	t.Helper()
	deployTestSetup(t)
	useSecAudit(t)
	oldProbe, oldMgr, oldCS := baselineProbe, baselineMgr, crowdsecMgr
	crowdsecMgr = nil
	t.Cleanup(func() { baselineProbe, baselineMgr, crowdsecMgr = oldProbe, oldMgr, oldCS })
	baselineProbe = baseline.Probe{DBExisted: !fresh}
	initBaseline()
}

func baselineTrustedProxy(t *testing.T) {
	t.Helper()
	ac, err := access.NewAccessController(&access.Options{
		Logger: *SystemWideLogger, ConfigFolder: filepath.Join(t.TempDir(), "access"), TrustedProxiesFile: filepath.Join(t.TempDir(), "tp.json"),
		Database: sysdb, SkipPublicIPCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	accessController = ac
	ac.AddTrustedProxy("10.9.0.2", "front proxy")
}

func baselinePost(h http.HandlerFunc) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/baseline/x", nil)
	r.RemoteAddr = "192.168.5.5:4000"
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func baselineGetView(t *testing.T) baselineView {
	t.Helper()
	w := httptest.NewRecorder()
	HandleBaselineGet(w, httptest.NewRequest(http.MethodGet, "/api/baseline/get", nil))
	var v baselineView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return v
}

func baselineAudit(t *testing.T) []secaudit.Entry {
	t.Helper()
	secAudit.Flush()
	p, err := secAudit.List(secaudit.Query{Event: "baseline.*", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return p.Entries
}

// the sysdb keys of everything the baseline must never touch stay absent
func assertExcludedUntouched(t *testing.T) {
	t.Helper()
	for _, k := range []string{"destguard", "adminallow", "crowdsec", "netplan", "abuse"} {
		if sysdb.KeyExists("settings", k) {
			t.Errorf("settings/%s was written by the baseline", k)
		}
	}
	s := deployRoleMgr.Settings()
	if s.Role != deployrole.RoleStandalone || s.PeerGate || len(s.DirectCIDRs) != 0 {
		t.Errorf("role, peer gate or direct networks changed: %+v", s)
	}
}

func TestBaselineFreshInstall(t *testing.T) {
	baselineSetup(t, true)
	if !deployRoleMgr.HardenActive() {
		t.Fatal("fresh install: header clean-up should be on")
	}
	hh := loadHardenedDefault()
	if hh == nil || !hh.Enabled || !hh.NoSniff || !hh.HSTS || hh.HSTSMaxAge != baselineHSTSAge || hh.ReferrerPolicy != "strict-origin-when-cross-origin" {
		t.Fatalf("default for new sites: %+v", hh)
	}
	if hh.FrameProtection != "" || hh.PermissionsPolicy || hh.HSTSIncludeSubdomains || hh.HSTSPreload || hh.OverrideExisting {
		t.Fatalf("the default is more than the conservative set: %+v", hh)
	}
	assertExcludedUntouched(t)

	//the planned headers of a TLS and a plain site
	for _, e := range hh.Plan(nil, false) {
		if e.Key == "Strict-Transport-Security" && e.Mode != "skipped" {
			t.Fatal("HSTS must not be sent on plain HTTP")
		}
	}
	keys := map[string]bool{}
	for _, e := range hh.Plan(nil, true) {
		keys[e.Key] = true
	}
	if !keys["Strict-Transport-Security"] || !keys["X-Content-Type-Options"] || !keys["Referrer-Policy"] || keys["X-Frame-Options"] || keys["Permissions-Policy"] {
		t.Fatalf("planned headers: %v", keys)
	}

	//a new site gets it, a site with its own choice keeps it
	ep := &dynamicproxy.ProxyEndpoint{}
	applyHardenedDefault(ep)
	if ep.HeaderRewriteRules == nil || ep.HeaderRewriteRules.HardenedHeaders == nil || !ep.HeaderRewriteRules.HardenedHeaders.NoSniff {
		t.Fatal("a new site should get the default")
	}
	own := &dynamicproxy.HardenedHeaders{Enabled: true, FrameProtection: "deny"}
	ep2 := &dynamicproxy.ProxyEndpoint{HeaderRewriteRules: &dynamicproxy.HeaderRewriteRules{HardenedHeaders: own}}
	applyHardenedDefault(ep2)
	if ep2.HeaderRewriteRules.HardenedHeaders != own {
		t.Fatal("a site's own choice must stay")
	}

	//visible in the audit log with the source
	es := baselineAudit(t)
	if len(es) != 1 || es[0].Event != "baseline.apply" || es[0].Detail["source"] != "fresh" || es[0].Detail["changed"] != "2" || es[0].Actor != "system" {
		t.Fatalf("audit: %+v", es)
	}

	//undo, then a restart (initBaseline again) must not re-apply
	if w := baselinePost(HandleBaselineUndo); !strings.Contains(w.Body.String(), "restored") {
		t.Fatal(w.Body.String())
	}
	if deployRoleMgr.HardenActive() || loadHardenedDefault() != nil || sysdb.KeyExists("settings", hardenedDefaultKey) {
		t.Fatal("undo must restore the previous values (clean-up off, no default stored)")
	}
	baselineMgr = nil
	initBaseline() //restart; even a probe that still says fresh changes nothing
	if deployRoleMgr.HardenActive() || loadHardenedDefault() != nil {
		t.Fatal("a restart re-applied the baseline after the admin undid it")
	}
	if n := len(baselineAudit(t)); n != 2 {
		t.Fatalf("audit entries after undo and restart: %d", n)
	}
}

func TestBaselineExistingInstallNotChangedThenButton(t *testing.T) {
	baselineSetup(t, false)
	if deployRoleMgr.HardenActive() || loadHardenedDefault() != nil {
		t.Fatal("an existing install must not be changed by the update")
	}
	if len(baselineAudit(t)) != 0 {
		t.Fatal("nothing was applied, nothing to audit")
	}
	v := baselineGetView(t)
	if !v.Available || v.CanUndo || v.State.Decision != "existing" {
		t.Fatalf("%+v", v)
	}
	status := map[string]string{}
	for _, c := range v.Preview {
		status[c.ID] = c.Status
	}
	//no trusted proxy listed: header clean-up is skipped with a reason, the default for new sites is offered
	if status["harden-headers"] != "skipped" || status["new-site-headers"] != "change" || status["audit-log"] != "info" || status["crowdsec"] != "info" || v.Pending != 1 {
		t.Fatalf("preview: %v pending %d", status, v.Pending)
	}
	for _, c := range v.Preview {
		if c.ID == "harden-headers" && !strings.Contains(c.Reason, "Trusted Proxies") {
			t.Fatalf("reason: %q", c.Reason)
		}
	}

	if w := baselinePost(HandleBaselineApply); strings.Contains(w.Body.String(), `"error"`) {
		t.Fatal(w.Body.String())
	}
	if deployRoleMgr.HardenActive() {
		t.Fatal("clean-up must stay off without a trusted proxy")
	}
	if hh := loadHardenedDefault(); hh == nil || !hh.NoSniff {
		t.Fatal("default for new sites not set")
	}
	assertExcludedUntouched(t)
	es := baselineAudit(t)
	if len(es) != 1 || es[0].Event != "baseline.apply" || es[0].Detail["source"] != "button" || es[0].Actor != "admin" || !strings.Contains(es[0].Detail["items"], "new-site-headers") {
		t.Fatalf("audit: %+v", es)
	}

	//idempotent: a second click changes and audits nothing
	baselinePost(HandleBaselineApply)
	if len(baselineAudit(t)) != 1 {
		t.Fatal("a second apply must not be audited as a change")
	}
}

func TestBaselineButtonWithTrustedProxyAndUndoKeepsOtherSettings(t *testing.T) {
	baselineSetup(t, false)
	baselineTrustedProxy(t)
	//the admin's own deployment settings must survive apply and undo untouched
	if err := deployRoleMgr.Set(deployrole.Settings{Role: deployrole.RoleStandalone, DirectCIDRs: []string{"10.20.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	//(a stored default of any kind is the administrator's choice and is never overwritten, see TestBaselineExplicitOffDefaultIsAnAdminChoice; here none is stored, so undo brings back "none")
	before, _ := baselineHeadersItem{}.Current()

	baselinePost(HandleBaselineApply)
	if !deployRoleMgr.HardenActive() || loadHardenedDefault() == nil {
		t.Fatal("both items should be applied")
	}
	if got := deployRoleMgr.Settings().DirectCIDRs; len(got) != 1 || got[0] != "10.20.0.0/16" {
		t.Fatalf("apply lost the direct networks: %v", got)
	}
	assertNoPeerGate := deployRoleMgr.Settings()
	if assertNoPeerGate.PeerGate || assertNoPeerGate.Role != deployrole.RoleStandalone {
		t.Fatal("role or gate touched")
	}

	baselinePost(HandleBaselineUndo)
	if deployRoleMgr.HardenActive() {
		t.Fatal("clean-up should be off again")
	}
	after, _ := baselineHeadersItem{}.Current()
	if string(after) != string(before) {
		t.Fatalf("previous value not restored exactly: %s vs %s", after, before)
	}
	if got := deployRoleMgr.Settings().DirectCIDRs; len(got) != 1 || got[0] != "10.20.0.0/16" {
		t.Fatalf("undo lost the direct networks: %v", got)
	}
	es := baselineAudit(t)
	if len(es) != 2 || es[0].Event != "baseline.undo" || es[1].Event != "baseline.apply" {
		t.Fatalf("audit: %+v", es)
	}
}

func TestBaselineUndoSkipsWhatTheAdminChanged(t *testing.T) {
	baselineSetup(t, false)
	baselineTrustedProxy(t)
	baselinePost(HandleBaselineApply)
	//the admin picks a stricter default for new sites afterwards
	custom := &dynamicproxy.HardenedHeaders{Enabled: true, NoSniff: true, FrameProtection: "deny"}
	custom.Validate()
	sysdb.Write("settings", hardenedDefaultKey, custom)

	w := baselinePost(HandleBaselineUndo)
	body := w.Body.String()
	if !strings.Contains(body, "changed since the baseline was applied") {
		t.Fatalf("no warning: %s", body)
	}
	if hh := loadHardenedDefault(); hh == nil || hh.FrameProtection != "deny" {
		t.Fatal("the admin's own default was overwritten")
	}
	if deployRoleMgr.HardenActive() {
		t.Fatal("the untouched item should have been restored")
	}
}

func TestBaselineAlreadyConfiguredByAdminIsLeftAlone(t *testing.T) {
	baselineSetup(t, false)
	mine := &dynamicproxy.HardenedHeaders{Enabled: true, NoSniff: true, FrameProtection: "sameorigin"}
	mine.Validate()
	sysdb.Write("settings", hardenedDefaultKey, mine)
	v := baselineGetView(t)
	for _, c := range v.Preview {
		if c.ID == "new-site-headers" && (c.Status != "skipped" || !strings.Contains(c.Reason, "your own")) {
			t.Fatalf("%+v", c)
		}
	}
	baselinePost(HandleBaselineApply)
	if hh := loadHardenedDefault(); hh == nil || hh.FrameProtection != "sameorigin" {
		t.Fatal("the admin's default was replaced")
	}
}

func TestBaselineEndpointsViewerDeniedAndMethods(t *testing.T) {
	for _, p := range []string{"/api/baseline/get", "/api/baseline/apply", "/api/baseline/undo"} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			if auth.ViewerAllowed(m, p) {
				t.Errorf("viewer may %s %s", m, p)
			}
		}
	}
	baselineSetup(t, false)
	for name, h := range map[string]http.HandlerFunc{"apply": HandleBaselineApply, "undo": HandleBaselineUndo} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/api/baseline/"+name, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s must be POST only, got %d", name, w.Code)
		}
	}
	w := httptest.NewRecorder()
	HandleBaselineGet(w, httptest.NewRequest(http.MethodPost, "/api/baseline/get", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Error("get must be GET only")
	}
	//undo with nothing recorded is an error, not a silent success
	if w := baselinePost(HandleBaselineUndo); !strings.Contains(w.Body.String(), "nothing to undo") {
		t.Fatal(w.Body.String())
	}
}

func TestBaselineOldConfigLoadsUnchanged(t *testing.T) {
	deployTestSetup(t)
	useSecAudit(t)
	oldProbe, oldMgr := baselineProbe, baselineMgr
	t.Cleanup(func() { baselineProbe, baselineMgr = oldProbe, oldMgr })
	//an install from before the baseline: deployment settings with a value, no baseline key
	if err := deployRoleMgr.Set(deployrole.Settings{Role: deployrole.RoleStandalone, DirectCIDRs: []string{"192.168.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	before := deployRoleMgr.Settings()
	baselineProbe = baseline.Probe{DBExisted: true, SchemaStamp: 1, ConfFiles: 12}
	initBaseline()
	after := deployRoleMgr.Settings()
	if before.HardenHeaders != after.HardenHeaders || len(after.DirectCIDRs) != 1 || sysdb.KeyExists("settings", hardenedDefaultKey) {
		t.Fatal("loading an old configuration changed it")
	}
	if len(baselineAudit(t)) != 0 {
		t.Fatal("nothing should be audited")
	}
	if !baselineMgr.Decided() || baselineMgr.State().Decision != "existing" {
		t.Fatal("the decision must be stored")
	}
}

func TestBaselineStatusShowsInfoItems(t *testing.T) {
	baselineSetup(t, false)
	v := baselineGetView(t)
	by := map[string]baseline.ItemStatus{}
	for _, it := range v.Items {
		by[it.ID] = it
	}
	if by["audit-log"].Current != "recording" || !by["audit-log"].Info.Info {
		t.Fatalf("audit item: %+v", by["audit-log"])
	}
	if by["crowdsec"].Current != "not configured" || !by["crowdsec"].Info.Info || by["crowdsec"].Anchor != "crowdsec" {
		t.Fatalf("crowdsec item: %+v", by["crowdsec"])
	}
	for _, it := range v.Items {
		if it.Why == "" || it.Effect == "" || it.Title == "" {
			t.Errorf("%s is not described", it.ID)
		}
	}
}

func TestBaselineFreshWithoutTrustedProxyWarnsInAuditAndCard(t *testing.T) {
	baselineSetup(t, true)
	es := baselineAudit(t)
	if len(es) != 1 || !strings.Contains(es[0].Detail["warning"], "Trusted Proxies") {
		t.Fatalf("the first-start audit entry must carry the trusted proxy warning: %+v", es)
	}
	if v := baselineGetView(t); len(v.Warnings) != 1 {
		t.Fatalf("card warnings: %v", v.Warnings)
	}
	baselineTrustedProxy(t)
	if v := baselineGetView(t); len(v.Warnings) != 0 {
		t.Fatalf("no warning once a proxy is listed: %v", v.Warnings)
	}
}

func TestBaselineExplicitOffDefaultIsAnAdminChoice(t *testing.T) {
	baselineSetup(t, false)
	off := &dynamicproxy.HardenedHeaders{Enabled: false}
	if err := sysdb.Write("settings", hardenedDefaultKey, off); err != nil {
		t.Fatal(err)
	}
	for _, c := range baselineGetView(t).Preview {
		if c.ID == "new-site-headers" && (c.Status != "skipped" || c.Reason == "") {
			t.Fatalf("a stored default of off must be left alone: %+v", c)
		}
	}
	baselinePost(HandleBaselineApply)
	if hh := loadHardenedDefault(); hh != nil && hh.Enabled {
		t.Fatal("the button overwrote the administrator's explicit choice")
	}
}

type failingBaselineItem struct{ baselineInfoItem }

func (failingBaselineItem) Info() baseline.Info               { return baseline.Info{ID: "boom", Title: "boom"} }
func (failingBaselineItem) Target() json.RawMessage           { return jsonRaw("on") }
func (failingBaselineItem) Eligible(bool) (bool, string)      { return true, "" }
func (failingBaselineItem) Current() (json.RawMessage, error) { return jsonRaw("off"), nil }
func (failingBaselineItem) Set(json.RawMessage) error         { return fmt.Errorf("disk on fire") }

func TestBaselineFailedFirstStartApplyIsAudited(t *testing.T) {
	deployTestSetup(t)
	useSecAudit(t)
	oldProbe, oldMgr, oldFn := baselineProbe, baselineMgr, baselineItemsFn
	t.Cleanup(func() { baselineProbe, baselineMgr, baselineItemsFn = oldProbe, oldMgr, oldFn })
	baselineItemsFn = func() []baseline.Item { return []baseline.Item{failingBaselineItem{}} }
	baselineProbe = baseline.Probe{}
	initBaseline()
	es := baselineAudit(t)
	if len(es) != 1 || es[0].Outcome != "error" || es[0].Actor != "system" || !strings.Contains(es[0].Detail["error"], "disk on fire") || es[0].Detail["changed"] != "0" {
		t.Fatalf("a failed first-start apply must be audited as an error: %+v", es)
	}
	if baselineMgr.State().Decision != "fresh" {
		t.Fatal("the decision stays recorded")
	}
}
