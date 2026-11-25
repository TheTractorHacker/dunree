package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
)

// Default template of new rules (upstream #877): off until chosen, only existing non-preset templates are
// accepted, and deleting the template clears the choice.

func templateDefaultSetup(t *testing.T) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	old := sysdb
	sysdb = db
	sysdb.NewTable("settings")
	t.Cleanup(func() { sysdb = old; db.Close() })
}

func templateCall(t *testing.T, h http.HandlerFunc, form url.Values) map[string]any {
	t.Helper()
	var r *http.Request
	if form == nil {
		r = httptest.NewRequest(http.MethodGet, "/x", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	h(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestRuleTemplateDefaultIsOffUntilChosen(t *testing.T) {
	templateDefaultSetup(t)
	if out := templateCall(t, HandleRuleTemplateDefault, nil); out["name"] != "" {
		t.Fatalf("a fresh installation must have no default template, got %v", out)
	}
	if defaultRuleTemplateName() != "" || sysdb.KeyExists("settings", ruleTemplateDefaultKey) {
		t.Fatal("reading the default must not store one")
	}
}

func TestRuleTemplateDefaultSetAndClear(t *testing.T) {
	templateDefaultSetup(t)
	// a built in template, matched without case, is stored under its real name
	if out := templateCall(t, HandleRuleTemplateDefault, url.Values{"name": {"secure WEB app"}}); out["name"] != "Secure web app" {
		t.Fatalf("set built in: %v", out)
	}
	if out := templateCall(t, HandleRuleTemplateDefault, nil); out["name"] != "Secure web app" {
		t.Fatalf("read back: %v", out)
	}
	// refused choices leave the stored default alone
	if out := templateCall(t, HandleRuleTemplateDefault, url.Values{"name": {"No such template"}}); out["error"] == nil {
		t.Fatalf("an unknown template must be refused: %v", out)
	}
	var preset string
	for _, p := range dynamicproxy.AppPresets() {
		preset = p.Name
		break
	}
	if preset != "" {
		if out := templateCall(t, HandleRuleTemplateDefault, url.Values{"name": {preset}}); out["error"] == nil {
			t.Fatalf("an app preset must be refused as default: %v", out)
		}
	}
	if defaultRuleTemplateName() != "Secure web app" {
		t.Fatalf("a refused choice changed the default to %q", defaultRuleTemplateName())
	}
	if out := templateCall(t, HandleRuleTemplateDefault, url.Values{"name": {""}}); out["name"] != "" || out["error"] != nil {
		t.Fatalf("clear: %v", out)
	}
	if sysdb.KeyExists("settings", ruleTemplateDefaultKey) {
		t.Fatal("clearing must remove the setting")
	}
}

func TestRuleTemplateDefaultFollowsDelete(t *testing.T) {
	templateDefaultSetup(t)
	tpl := `{"Name":"Quiet host","HSTSMaxAge":31536000,"UptimeMonitor":false}`
	if out := templateCall(t, HandleRuleTemplateSave, url.Values{"template": {tpl}}); out["error"] != nil {
		t.Fatalf("save: %v", out)
	}
	if out := templateCall(t, HandleRuleTemplateDefault, url.Values{"name": {"Quiet host"}}); out["name"] != "Quiet host" {
		t.Fatalf("set custom: %v", out)
	}
	// the default is only a name for the forms: what a rule gets is still what the request names
	ep := dynamicproxy.GetDefaultProxyEndpoint()
	if err := applyRuleTemplateByName(&ep, defaultRuleTemplateName()); err != nil {
		t.Fatal(err)
	}
	if ep.HeaderRewriteRules.HSTSMaxAge != 31536000 || !ep.DisableUptimeMonitor {
		t.Fatalf("the default template did not set HSTS / uptime monitor: %+v", ep.HeaderRewriteRules)
	}
	templateCall(t, HandleRuleTemplateDelete, url.Values{"name": {"Quiet host"}})
	if defaultRuleTemplateName() != "" || sysdb.KeyExists("settings", ruleTemplateDefaultKey) {
		t.Fatal("deleting the template must clear the default")
	}
	// a new template with the old name does not become the default by itself
	templateCall(t, HandleRuleTemplateSave, url.Values{"template": {tpl}})
	if out := templateCall(t, HandleRuleTemplateDefault, nil); out["name"] != "" {
		t.Fatalf("a re-created template became the default: %v", out)
	}
	// deleting another template leaves the default alone
	templateCall(t, HandleRuleTemplateDefault, url.Values{"name": {"Static site"}})
	templateCall(t, HandleRuleTemplateDelete, url.Values{"name": {"Quiet host"}})
	if defaultRuleTemplateName() != "Static site" {
		t.Fatalf("deleting another template changed the default to %q", defaultRuleTemplateName())
	}
}

// A default stored before its template disappeared some other way (restore, hand edit) reads as none
func TestRuleTemplateDefaultStaleNameIsNone(t *testing.T) {
	templateDefaultSetup(t)
	sysdb.Write("settings", ruleTemplateDefaultKey, "Gone template")
	if out := templateCall(t, HandleRuleTemplateDefault, nil); out["name"] != "" {
		t.Fatalf("a stale default must read as none: %v", out)
	}
}
