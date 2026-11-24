package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/foleyit/dunree/mod/access"
	"github.com/foleyit/dunree/mod/dynamicproxy/rewrite"
	"github.com/foleyit/dunree/mod/ruleset"
	"github.com/foleyit/dunree/mod/uservars"
)

func withTestUserVars(t *testing.T, e *ruleset.Engine) *uservars.Store {
	t.Helper()
	s, err := uservars.Open(filepath.Join(t.TempDir(), "variables.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := userVarStore
	userVarStore = s
	userVarOnce = sync.Once{}
	userVarOnce.Do(func() {})
	s.OnChange(func() { getRulesEngine().RefreshVars() })
	e.SetVarResolver(s.Lookup)
	t.Cleanup(func() {
		// leave nothing of this store behind: a later test that calls getUserVars() must open its
		// own store instead of getting this one (or nil), and no consumer may keep resolving
		// against a store whose temp dir is gone
		userVarStore = old
		userVarOnce = sync.Once{}
		if old != nil {
			userVarOnce.Do(func() {}) // a store was already loaded before this test: keep it
		}
		e.SetVarResolver(nil)
		rewrite.SetUserVarProvider(nil)
		access.SetVarResolver(nil)
	})
	return s
}

// The variables API (issue #89): define, list with usage, change, delete; a rule list that
// references the variable follows every step without being edited.
func TestUserVarAPILifecycle(t *testing.T) {
	e := withTestRulesEngine(t)
	s := withTestUserVars(t, e)
	ext := ""
	s.SetBuiltin("external_ip", func() string { return ext })

	matches := func(expr, host, ip string) bool {
		res := e.Test(ruleset.TestInput{Method: "GET", URL: "http://" + host + "/", ClientIP: ip, Expression: expr})
		return len(res.Rules) == 1 && res.Rules[0].Matched
	}

	if code, _, raw := rsDo(HandleUserVarSet, "GET", "/api/vars/set", ""); code != 405 {
		t.Fatalf("GET on set: %d %s", code, raw)
	}
	for _, body := range []string{
		`{"name":"external_ip","value":"1.2.3.4","create":true}`, // built-in
		`{"name":"Bad Name","value":"x","create":true}`,
		`{"name":"ok","value":"","create":true}`,
		`{"name":"ok","value":"a\nb","create":true}`,
		`{"name":"ok","value":"x","bogus":1}`,
	} {
		if code, _, raw := rsDo(HandleUserVarSet, "POST", "/api/vars/set", body); code != 400 {
			t.Fatalf("%s: %d %s", body, code, raw)
		}
	}
	code, m, raw := rsDo(HandleUserVarSet, "POST", "/api/vars/set", `{"name":"remote_office_ext_ip","value":"203.0.113.9","description":"office","create":true}`)
	if code != 200 || m["name"] != "remote_office_ext_ip" || m["value"] != "203.0.113.9" {
		t.Fatalf("create: %d %s", code, raw)
	}
	if code, _, _ := rsDo(HandleUserVarSet, "POST", "/api/vars/set", `{"name":"remote_office_ext_ip","value":"1.1.1.1","create":true}`); code != 400 {
		t.Fatalf("create over an existing name: %d", code)
	}

	// lists that use the user variable and the built-in
	if code, _, raw := rsDo(HandleRulesetListSave, "POST", "/x", `{"name":"office","type":"ip","items":["{{remote_office_ext_ip}}"]}`); code != 200 {
		t.Fatalf("list save: %d %s", code, raw)
	}
	if code, _, raw := rsDo(HandleRulesetListSave, "POST", "/x", `{"name":"me","type":"string","items":["{{external_ip}}"]}`); code != 200 {
		t.Fatalf("list save: %d %s", code, raw)
	}
	if !matches("ip.src in $office", "a.example", "203.0.113.9") || matches("ip.src in $office", "a.example", "203.0.113.10") {
		t.Fatal("the list does not resolve the variable")
	}
	if matches("http.host in $me", "198.51.100.77", "192.0.2.1") {
		t.Fatal("an unknown external IP must match nothing")
	}

	// list view: usage, built-in, limits; the rule lists report how their references resolve
	code, m, raw = rsDo(HandleUserVarList, "GET", "/api/vars/list", "")
	if code != 200 {
		t.Fatalf("list: %d %s", code, raw)
	}
	var view struct {
		Variables []struct {
			Name   string   `json:"name"`
			Value  string   `json:"value"`
			UsedBy []string `json:"used_by"`
		} `json:"variables"`
		Builtins []struct {
			Name   string   `json:"name"`
			Value  string   `json:"value"`
			UsedBy []string `json:"used_by"`
		} `json:"builtins"`
		Limits map[string]int `json:"limits"`
	}
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Variables) != 1 || len(view.Variables[0].UsedBy) != 1 || view.Variables[0].UsedBy[0] != "list $office" {
		t.Fatalf("variables: %s", raw)
	}
	if len(view.Builtins) != 1 || view.Builtins[0].Name != "external_ip" || view.Builtins[0].Value != "" || len(view.Builtins[0].UsedBy) != 1 {
		t.Fatalf("builtins: %s", raw)
	}
	if view.Limits["variables"] != uservars.MaxVariables || m["refresh_seconds"] == nil {
		t.Fatalf("limits: %s", raw)
	}
	_, _, raw = rsDo(HandleRulesetLists, "GET", "/api/ruleset/lists", "")
	var lists []struct {
		Name      string            `json:"name"`
		Items     []string          `json:"items"`
		Variables []ruleset.ListVar `json:"variables"`
	}
	json.Unmarshal([]byte(raw), &lists)
	if len(lists) != 2 || lists[0].Name != "me" || len(lists[0].Variables) != 1 || lists[0].Variables[0].OK ||
		len(lists[1].Variables) != 1 || !lists[1].Variables[0].OK || lists[1].Items[0] != "{{remote_office_ext_ip}}" {
		t.Fatalf("ruleset lists: %s", raw)
	}

	// changing the value through the API is applied to the rules at once
	if code, _, raw := rsDo(HandleUserVarSet, "POST", "/api/vars/set", `{"name":"remote_office_ext_ip","value":"198.51.100.0/24, 2001:db8::1"}`); code != 200 {
		t.Fatalf("update: %d %s", code, raw)
	}
	if matches("ip.src in $office", "a.example", "203.0.113.9") || !matches("ip.src in $office", "a.example", "198.51.100.200") || !matches("ip.src in $office", "a.example", "2001:db8::1") {
		t.Fatal("a changed value did not reach the rules")
	}
	// the public address becomes known / changes: picked up by the periodic refresh
	ext = "198.51.100.77"
	if !getRulesEngine().RefreshVars() || !matches("http.host in $me", "198.51.100.77", "192.0.2.1") {
		t.Fatal("{{external_ip}} did not reach the rules")
	}

	if code, _, _ := rsDo(HandleUserVarDelete, "POST", "/api/vars/delete", `{"name":"nope"}`); code != 404 {
		t.Fatalf("delete missing: %d", code)
	}
	if code, _, raw := rsDo(HandleUserVarDelete, "POST", "/api/vars/delete", `{"name":"remote_office_ext_ip"}`); code != 200 {
		t.Fatalf("delete: %d %s", code, raw)
	}
	if matches("ip.src in $office", "a.example", "198.51.100.200") {
		t.Fatal("a deleted variable still matches")
	}
}

// A variables file that could not be read is reported by the list API (the Variables tab shows
// it), and saving through the API keeps the unreadable file instead of overwriting it.
func TestUserVarListReportsLoadProblem(t *testing.T) {
	e := withTestRulesEngine(t)
	withTestUserVars(t, e)
	if _, m, raw := rsDo(HandleUserVarList, "GET", "/api/vars/list", ""); m["load_error"] != "" || m["load_backup"] != "" {
		t.Fatalf("a clean store reports a problem: %s", raw)
	}

	path := filepath.Join(t.TempDir(), "variables.json")
	broken := `{"version":1,"variables":[{"name":"office","value":"203.0.113.9"},{"na`
	if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := uservars.Open(path)
	if err == nil {
		t.Fatal("the truncated file must be reported")
	}
	userVarStore = s // restored by withTestUserVars
	_, m, raw := rsDo(HandleUserVarList, "GET", "/api/vars/list", "")
	if msg, _ := m["load_error"].(string); !strings.Contains(msg, "variables.json") || m["load_backup"] != "" {
		t.Fatalf("list: %s", raw)
	}
	if code, _, raw := rsDo(HandleUserVarSet, "POST", "/api/vars/set", `{"name":"fresh","value":"x","create":true}`); code != 200 {
		t.Fatalf("set: %d %s", code, raw)
	}
	_, m, raw = rsDo(HandleUserVarList, "GET", "/api/vars/list", "")
	backup, _ := m["load_backup"].(string)
	if !strings.HasPrefix(backup, "variables.json.broken-") || m["load_error"] == "" {
		t.Fatalf("list after a save: %s", raw)
	}
	if b, _ := os.ReadFile(filepath.Join(filepath.Dir(path), backup)); string(b) != broken {
		t.Fatalf("the kept copy differs: %q", b)
	}
}

// The test helper leaves no state behind: afterwards getUserVars() opens a store of its own
// instead of handing out the helper's (or nil), and no consumer still resolves against it.
func TestUserVarsHelperCleansUp(t *testing.T) {
	if userVarStore != nil {
		t.Skip("a store was loaded before this test")
	}
	t.Run("uses the helper", func(t *testing.T) {
		e := withTestRulesEngine(t)
		s := withTestUserVars(t, e)
		access.SetVarResolver(s.Lookup)
		if _, err := s.Set(uservars.Variable{Name: "office", Value: "203.0.113.9"}, true); err != nil {
			t.Fatal(err)
		}
		if _, ok := access.ResolveEntryVar("office"); !ok {
			t.Fatal("the resolver is not installed")
		}
	})
	if userVarStore != nil {
		t.Fatal("the helper's store is still installed")
	}
	if _, ok := access.ResolveEntryVar("office"); ok {
		t.Fatal("the access lists still resolve against the helper's store")
	}
	// the next first use loads a store (from an empty conf folder here) rather than returning nil
	withTestRulesEngine(t)
	oldConf := CONF_FOLDER
	CONF_FOLDER = t.TempDir()
	t.Cleanup(func() {
		CONF_FOLDER = oldConf
		userVarStore, userVarOnce = nil, sync.Once{}
		rewrite.SetUserVarProvider(nil)
		access.SetVarResolver(nil)
	})
	if s := getUserVars(); s == nil || len(s.List()) != 0 {
		t.Fatalf("getUserVars() after the helper = %v", s)
	}
}
