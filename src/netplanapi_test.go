package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/adminallow"
	"github.com/TheTractorHacker/dunree/mod/confhistory"
	"github.com/TheTractorHacker/dunree/mod/deployrole"
	"github.com/TheTractorHacker/dunree/mod/destguard"
	"github.com/TheTractorHacker/dunree/mod/posture"
	"github.com/TheTractorHacker/dunree/mod/secaudit"
)

func planPost(cfg string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/netplan/set", strings.NewReader(url.Values{"config": {cfg}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleNetPlanSet(w, r)
	return w
}

func planView(t *testing.T) netplanView {
	t.Helper()
	w := httptest.NewRecorder()
	HandleNetPlanGet(w, httptest.NewRequest(http.MethodGet, "/api/netplan/get", nil))
	var v netplanView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return v
}

func finding(t *testing.T, v netplanView, id string) netplanFinding {
	t.Helper()
	for _, f := range v.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %s", id)
	return netplanFinding{}
}

const planJSON = `{"proxyVlan":{"name":"Proxy VLAN","cidrs":["10.0.1.0/24"]},"managementVlan":{"name":"Mgmt","cidrs":["10.0.9.0/24"]},` +
	`"applicationVlan":{"name":"Apps","cidrs":["10.0.2.0/24"]},"trustedProxies":["10.0.1.5"],"allowedBackends":[],"appPorts":["443","8000-8100"],"adminAccess":[]}`

func TestNetPlanSavePersistsAcrossRestartAndIsAuditedAndLabelled(t *testing.T) {
	sliceHSetup(t)
	if v := planView(t); v.Declared || len(v.Findings) == 0 {
		t.Fatalf("a fresh install has no plan: %+v", v.Declared)
	}
	if w := planPost(planJSON); !strings.Contains(w.Body.String(), "OK") {
		t.Fatalf("%s", w.Body.String())
	}
	// "restart": drop the manager, it must come back from sys.db
	netplanMgr = nil
	v := planView(t)
	if !v.Declared || v.Settings.ManagementVLAN.CIDRs[0] != "10.0.9.0/24" || v.Settings.AppPorts[1] != "8000-8100" {
		t.Fatalf("plan lost on restart: %+v", v.Settings)
	}
	if !strings.Contains(v.Disclaimer, "NOT applied") && !strings.Contains(v.Disclaimer, "NOT") {
		t.Fatalf("the view must carry the disclaimer: %q", v.Disclaimer)
	}
	// history captures the settings table, and the change has a readable label
	req := httptest.NewRequest(http.MethodPost, "/api/netplan/set", nil)
	if s := confhistory.Summary(req); !strings.Contains(s, "Network plan") {
		t.Errorf("history label: %q", s)
	}
	if ev, ok := secaudit.Classify("POST", "/api/netplan/set", nil); !ok || ev != "netplan.set" {
		t.Errorf("audit: %q %v", ev, ok)
	}
}

func TestNetPlanSetRefusesHostileInput(t *testing.T) {
	sliceHSetup(t)
	if w := planPost(planJSON); !strings.Contains(w.Body.String(), "OK") {
		t.Fatal(w.Body.String())
	}
	bad := map[string]string{
		"not json":      `{{{`,
		"unknown field": `{"proxyVlan":{"name":"x","cidrs":[]},"shell":"rm -rf /"}`,
		"markdown name": `{"proxyVlan":{"name":"a|b","cidrs":["10.0.0.0/24"]}}`,
		"match all":     `{"managementVlan":{"name":"m","cidrs":["0.0.0.0/0"]}}`,
		"host name":     `{"trustedProxies":["evil.example.com"]}`,
		"bad port":      `{"appPorts":["70000"]}`,
		"empty":         ``,
	}
	for name, cfg := range bad {
		w := planPost(cfg)
		if strings.Contains(w.Body.String(), `"OK"`) {
			t.Errorf("%s was accepted: %s", name, w.Body.String())
		}
	}
	// a body past the limit is refused, not read
	huge := `{"adminAccess":["` + strings.Repeat("1", 300<<10) + `"]}`
	if w := planPost(huge); strings.Contains(w.Body.String(), `"OK"`) {
		t.Error("an oversized body was accepted")
	}
	// none of that changed the saved plan
	if v := planView(t); v.Settings.ManagementVLAN.CIDRs[0] != "10.0.9.0/24" || len(v.Settings.TrustedProxies) != 1 {
		t.Fatalf("a refused request changed the plan: %+v", v.Settings)
	}
	// clearing is allowed
	if w := planPost(`{}`); !strings.Contains(w.Body.String(), "OK") || planView(t).Declared {
		t.Fatalf("clear: %s", w.Body.String())
	}
}

// The validation reads the real configuration: each mismatch the task lists shows up as its own finding.
func TestNetPlanValidationAgainstTheRealConfiguration(t *testing.T) {
	sliceHSetup(t)
	oldPort := *webUIPort
	t.Cleanup(func() { *webUIPort = oldPort })
	*webUIPort = "127.0.0.1:8000"
	planPost(planJSON)
	ep, _ := dynamicProxyRouter.LoadProxy("app.example.com")
	setBackend := func(origin string, tls bool) {
		ep.ActiveOrigins[0].OriginIpOrDomain, ep.ActiveOrigins[0].RequireTLS = origin, tls
	}

	// a clean configuration: backend inside the application network on a permitted port
	setBackend("10.0.2.9:443", true)
	v := planView(t)
	for _, id := range []string{"netplan.backend_zone", "netplan.backend_port", "netplan.admin_bind", "netplan.plan_consistent"} {
		if f := finding(t, v, id); f.Status != posture.StatusOK {
			t.Errorf("%s = %s %v on a configuration that matches", id, f.Status, f.Evidence)
		}
	}

	// backend outside the application CIDR and on a port the plan does not permit
	setBackend("10.0.9.50:22", false)
	v = planView(t)
	if f := finding(t, v, "netplan.backend_zone"); f.Status != posture.StatusWarn || !strings.Contains(f.Evidence[0], "app.example.com -> 10.0.9.50:22") {
		t.Errorf("zone: %+v", f)
	}
	if f := finding(t, v, "netplan.backend_port"); f.Status != posture.StatusWarn {
		t.Errorf("port: %+v", f)
	}
	// a name without a port: the port really dialled (80, or 443 with TLS) is what is judged
	setBackend("10.0.2.9", false)
	if f := finding(t, planView(t), "netplan.backend_port"); f.Status != posture.StatusWarn || !strings.Contains(f.Evidence[0], ":80") {
		t.Errorf("an upstream without a port dials 80: %+v", f)
	}
	setBackend("10.0.2.9", true)
	if f := finding(t, planView(t), "netplan.backend_port"); f.Status != posture.StatusOK {
		t.Errorf("an upstream without a port on TLS dials 443: %+v", f)
	}

	// admin listener outside the management network, and open on every interface
	setBackend("10.0.2.9:443", true)
	*webUIPort = "10.0.2.2:8000"
	if f := finding(t, planView(t), "netplan.admin_bind"); f.Status != posture.StatusFail {
		t.Errorf("admin outside management: %+v", f)
	}
	*webUIPort = ":8000"
	if f := finding(t, planView(t), "netplan.admin_bind"); f.Status != posture.StatusFail || !strings.Contains(f.Evidence[0], "every interface") {
		t.Errorf("admin on every interface: %+v", f)
	}
	if err := adminAllowMgr.Set(adminAllowSettings("10.0.9.0/24", "10.0.0.0/8"), "10.0.9.5"); err != nil {
		t.Fatal(err)
	}
	if f := finding(t, planView(t), "netplan.admin_bind"); f.Status != posture.StatusWarn || !strings.Contains(f.Evidence[0], "10.0.0.0/8") {
		t.Errorf("a leaky allow-list: %+v", f)
	}
	adminAllowMgr.Set(adminAllowSettings("10.0.9.0/24"), "10.0.9.5")
	if f := finding(t, planView(t), "netplan.admin_bind"); f.Status != posture.StatusOK {
		t.Errorf("allow-list inside management: %+v", f)
	}
	*webUIPort = "203.0.113.7:8000"
	if f := finding(t, planView(t), "netplan.admin_public"); f.Status != posture.StatusWarn && f.Status != posture.StatusFail {
		t.Errorf("public admin: %+v", f)
	}
	*webUIPort = "127.0.0.1:8000"

	// trusted proxy outside the proxy network, trust-all
	accessController.AddTrustedProxy("192.168.50.0/24", "stray")
	if f := finding(t, planView(t), "netplan.trusted_zone"); f.Status != posture.StatusWarn || !strings.Contains(f.Evidence[0], "192.168.50.0/24") {
		t.Errorf("trusted zone: %+v", f)
	}
	accessController.AddTrustedProxy("0.0.0.0/0", "everyone")
	if f := finding(t, planView(t), "netplan.trust_all"); f.Status != posture.StatusFail {
		t.Errorf("trust all: %+v", f)
	}
	accessController.RemoveTrustedProxy("0.0.0.0/0")
	accessController.RemoveTrustedProxy("192.168.50.0/24")

	// external role with a backend in the management network
	if err := deployRoleMgr.Set(deployrole.Settings{Role: deployrole.RoleExternal}); err != nil {
		t.Fatal(err)
	}
	setBackend("10.0.9.60:443", true)
	if f := finding(t, planView(t), "netplan.external_mgmt"); f.Status != posture.StatusFail {
		t.Errorf("external with a management backend: %+v", f)
	}
	// SSRF capable targets
	setBackend("169.254.169.254:80", false)
	if f := finding(t, planView(t), "netplan.ssrf_targets"); f.Status != posture.StatusFail {
		t.Errorf("metadata target: %+v", f)
	}
	setBackend("10.0.2.9:443", true)
	deployRoleMgr.Set(deployrole.Settings{Role: deployrole.RoleStandalone})

	// unrestricted backend ranges: no allowed backend list, then one that is too broad
	if f := finding(t, planView(t), "netplan.backend_unrestricted"); f.Status != posture.StatusWarn {
		t.Errorf("no allowed list: %+v", f)
	}
	if err := destGuardMgr.Set(destguardSettings("10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if f := finding(t, planView(t), "netplan.backend_unrestricted"); f.Status != posture.StatusWarn || !strings.Contains(f.Evidence[0], "10.0.0.0/8") {
		t.Errorf("broad allowed list: %+v", f)
	}
	destGuardMgr.Set(destguardSettings("10.0.2.0/24"))
	if f := finding(t, planView(t), "netplan.backend_unrestricted"); f.Status != posture.StatusOK {
		t.Errorf("allowed list inside the plan: %+v", f)
	}

	// TLS verification off is reported through the existing check, not a copy of it
	ep.ActiveOrigins[0].SkipCertValidations = true
	v = planView(t)
	found := false
	for _, r := range v.Related {
		if r.ID == "upstream.tls_verify" && r.Status == posture.StatusWarn {
			found = true
		}
	}
	if !found {
		t.Errorf("the validation must surface upstream.tls_verify: %+v", v.Related)
	}
	for _, f := range v.Findings {
		if f.ID == "upstream.tls_verify" {
			t.Error("an existing check must not be duplicated as a netplan finding")
		}
	}
}

func TestNetPlanPolicyExport(t *testing.T) {
	sliceHSetup(t)
	planPost(planJSON)
	ep, _ := dynamicProxyRouter.LoadProxy("app.example.com")
	ep.ActiveOrigins[0].OriginIpOrDomain = "https://svc:" + postureSentinel + "@10.0.2.9:8443/private?token=" + postureSentinel
	ep.ActiveOrigins[0].RequireTLS = true

	w := httptest.NewRecorder()
	HandleNetPlanPolicy(w, httptest.NewRequest(http.MethodGet, "/api/netplan/policy", nil))
	var out struct{ Markdown, Filename, Disclaimer string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v %s", err, w.Body.String())
	}
	md := out.Markdown
	if strings.Count(md, "NOT APPLIED") < 2 || !strings.Contains(md, "Dunree has NOT applied") || out.Disclaimer == "" {
		t.Fatalf("the disclaimer is missing:\n%s", md)
	}
	if !strings.Contains(md, "10.0.2.9") || !strings.Contains(md, "8443") || !strings.Contains(md, "10.0.9.0/24") {
		t.Errorf("the export lacks the plan or the backends:\n%s", md)
	}
	for _, bad := range []string{postureSentinel, "svc:", "/private", "token=", "password", "BEGIN"} {
		if strings.Contains(md, bad) {
			t.Errorf("the export leaks %q", bad)
		}
	}
	// the download variant is a markdown attachment that cannot be sniffed into HTML
	w = httptest.NewRecorder()
	HandleNetPlanPolicy(w, httptest.NewRequest(http.MethodGet, "/api/netplan/policy?download=1", nil))
	h := w.Header()
	if !strings.HasPrefix(h.Get("Content-Type"), "text/markdown") || !strings.Contains(h.Get("Content-Disposition"), "attachment") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", h)
	}
	if w.Body.String() != md && !strings.Contains(w.Body.String(), "NOT APPLIED") {
		t.Error("download body")
	}
	// the export is recorded in the security audit log
	secAudit.Flush()
	page, _ := secAudit.List(secaudit.Query{Event: "netplan.export"})
	if len(page.Entries) < 2 {
		t.Fatalf("exports must be audited: %+v", page.Entries)
	}
	// an empty plan still exports, with placeholders and the disclaimer
	planPost(`{}`)
	w = httptest.NewRecorder()
	HandleNetPlanPolicy(w, httptest.NewRequest(http.MethodGet, "/api/netplan/policy", nil))
	if !strings.Contains(w.Body.String(), "Incomplete plan") || !strings.Contains(w.Body.String(), "NOT APPLIED") {
		t.Fatalf("%s", w.Body.String())
	}
}

func TestNetPlanChecksDoNotChangeTheScoreWithoutAPlan(t *testing.T) {
	sliceHSetup(t)
	var withPlanChecks, without int
	rep := getPostureEngine().Checks.Evaluate(collectPostureFacts())
	withPlanChecks = rep.Score.Value
	// the same facts with the netplan section removed (what the older code produced): same score
	f := collectPostureFacts()
	f.NetPlan = nil
	without = getPostureEngine().Checks.Evaluate(f).Score.Value
	if withPlanChecks != without {
		t.Fatalf("an install without a plan scores %d with the network plan checks and %d without", withPlanChecks, without)
	}
}

func adminAllowSettings(c ...string) adminallow.Settings { return adminallow.Settings{CIDRs: c} }

func destguardSettings(entries ...string) destguard.Settings {
	return destguard.Settings{AllowedBackends: entries}
}
