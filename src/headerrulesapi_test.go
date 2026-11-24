package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
)

// /api/headerrules/set and get: the rule set options of #245 (mode, exceptions) through the API handlers.
func TestHeaderRulesAPIOptions(t *testing.T) {
	router := setupEditTest(t)
	const host = "app.example.com"
	live := func() *dynamicproxy.ProxyEndpoint {
		ep, err := router.LoadProxy(host)
		if err != nil {
			t.Fatal(err)
		}
		return ep
	}
	saved := func() string {
		b, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, host+".config"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	set := func(v url.Values) string {
		v.Set("ep", host)
		return postNet(t, HandleHeaderRulesSet, v)
	}
	meta := func() (m struct {
		Mode    string
		Except  []string
		Rules   []*dynamicproxy.HeaderRule
		Invalid string
	}, raw string) {
		w := httptest.NewRecorder()
		HandleHeaderRulesGet(w, httptest.NewRequest("GET", "/api/headerrules/get?meta=true&ep="+host, nil))
		raw = w.Body.String()
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("meta read: %v %s", err, raw)
		}
		return m, raw
	}
	const one = `[{"Name":"X-Edge-Key","Values":["s3cret-api"]}]`
	const two = `[{"Name":"X-Edge-Key","Values":[""]},{"Name":"X-Debug","Match":"present","Negate":true}]`

	// a set without mode / except is the old call: nothing new is stored
	if out := set(url.Values{"rules": {one}}); !strings.Contains(out, "OK") {
		t.Fatalf("plain set: %s", out)
	}
	if e := live(); len(e.HeaderRules) != 1 || e.HeaderRulesMode != "" || e.HeaderRulesExcept != nil {
		t.Fatalf("plain set stored options: %q %v", e.HeaderRulesMode, e.HeaderRulesExcept)
	}
	if s := saved(); strings.Contains(s, "HeaderRulesMode") || strings.Contains(s, "HeaderRulesExcept") {
		t.Fatalf("plain set wrote the options to the config file: %s", s)
	}
	if m, raw := meta(); m.Mode != "all" || m.Except == nil || len(m.Except) != 0 || m.Invalid != "" || strings.Contains(raw, "s3cret-api") || strings.Contains(raw, "Invalid") {
		t.Fatalf("meta of a plain rule set: %s", raw)
	}

	// mode and exceptions are stored, entries are trimmed and empty ones dropped
	if out := set(url.Values{"rules": {two}, "mode": {"any"}, "except": {`[" 10.0.0.0/8 ","", "192.0.2.7"]`}}); !strings.Contains(out, "OK") {
		t.Fatalf("set with options: %s", out)
	}
	if e := live(); e.HeaderRulesMode != "any" || strings.Join(e.HeaderRulesExcept, ",") != "10.0.0.0/8,192.0.2.7" || e.HeaderRules[0].Values[0] != "s3cret-api" {
		t.Fatalf("options not stored (or the secret was lost): %q %v", e.HeaderRulesMode, e.HeaderRulesExcept)
	}
	if !strings.Contains(saved(), `"HeaderRulesMode": "any"`) && !strings.Contains(saved(), `"HeaderRulesMode":"any"`) {
		t.Fatalf("mode not persisted: %s", saved())
	}

	// a set without mode / except keeps what is stored
	if out := set(url.Values{"rules": {two}}); !strings.Contains(out, "OK") {
		t.Fatalf("set without options: %s", out)
	}
	if e := live(); e.HeaderRulesMode != "any" || len(e.HeaderRulesExcept) != 2 {
		t.Fatalf("a set without mode / except must keep them: %q %v", e.HeaderRulesMode, e.HeaderRulesExcept)
	}

	// refused values: an error answer, and nothing changes
	for name, v := range map[string]url.Values{
		"unknown mode":         {"rules": {two}, "mode": {"bogus"}},
		"unreadable address":   {"rules": {two}, "except": {`["10.0.0.0/8","not-an-address"]`}},
		"every address":        {"rules": {two}, "except": {`["0.0.0.0/0"]`}},
		"every address, split": {"rules": {two}, "except": {`["0.0.0.0/1","128.0.0.0/1"]`}},
		"every IPv6, split":    {"rules": {two}, "except": {`["::/1","8000::/1"]`}},
		"except not a list":    {"rules": {two}, "except": {`"10.0.0.0/8"`}},
		"bad rule, good mode":  {"rules": {`[{"Name":"Host","Match":"present"}]`}, "mode": {"all"}, "except": {`[]`}},
	} {
		if out := set(v); !strings.Contains(out, "error") {
			t.Errorf("%s must be refused: %s", name, out)
		}
		if e := live(); e.HeaderRulesMode != "any" || strings.Join(e.HeaderRulesExcept, ",") != "10.0.0.0/8,192.0.2.7" || len(e.HeaderRules) != 2 {
			t.Fatalf("%s: a refused set changed the stored rule set: %q %v %d", name, e.HeaderRulesMode, e.HeaderRulesExcept, len(e.HeaderRules))
		}
	}

	// "all" is the default and is not written, an empty exception list is stored as none
	if out := set(url.Values{"rules": {two}, "mode": {"all"}, "except": {`[]`}}); !strings.Contains(out, "OK") {
		t.Fatalf("back to the defaults: %s", out)
	}
	if e := live(); e.HeaderRulesMode != "" || e.HeaderRulesExcept != nil {
		t.Fatalf("defaults must be stored as empty: %q %#v", e.HeaderRulesMode, e.HeaderRulesExcept)
	}
	if s := saved(); strings.Contains(s, "HeaderRulesMode") || strings.Contains(s, "HeaderRulesExcept") {
		t.Fatalf("defaults written to the config file: %s", s)
	}

	// no rules left: the options go with them, whatever the request (or the store) says
	set(url.Values{"rules": {two}, "mode": {"any"}, "except": {`["10.0.0.0/8"]`}})
	if out := set(url.Values{"rules": {`[]`}, "mode": {"any"}, "except": {`["10.0.0.0/8"]`}}); !strings.Contains(out, "OK") {
		t.Fatalf("remove all rules: %s", out)
	}
	if e := live(); len(e.HeaderRules) != 0 || e.HeaderRulesMode != "" || e.HeaderRulesExcept != nil {
		t.Fatalf("a site without rules kept rule set options: %q %v", e.HeaderRulesMode, e.HeaderRulesExcept)
	}
	set(url.Values{"rules": {one}}) // a later client that does not know the options gets the default mode
	if e := live(); e.HeaderRulesMode != "" || e.HeaderRulesExcept != nil {
		t.Fatalf("options came back: %q %v", e.HeaderRulesMode, e.HeaderRulesExcept)
	}

	// a hand-edited invalid value: the read names it, so the page can say why the site answers 503
	bad := dynamicproxy.CopyEndpoint(live())
	bad.HeaderRulesMode = "bogus"
	live().Remove()
	ready, err := router.PrepareProxyRoute(bad)
	if err != nil {
		t.Fatal(err)
	}
	router.AddProxyRouteToRuntime(ready)
	if m, raw := meta(); !strings.Contains(m.Invalid, "mode must be all or any") || m.Mode != "bogus" || strings.Contains(raw, "s3cret-api") {
		t.Fatalf("an invalid stored rule set must be reported: %s", raw)
	}
	if out := set(url.Values{"rules": {one}}); !strings.Contains(out, "error") {
		t.Fatalf("a set without mode must not paper over the invalid stored mode: %s", out)
	}
	if out := set(url.Values{"rules": {`[{"Name":"X-Edge-Key","Values":[""]}]`}, "mode": {"all"}, "except": {`[]`}}); !strings.Contains(out, "OK") {
		t.Fatalf("saving from the page repairs it: %s", out)
	}
	if m, raw := meta(); m.Invalid != "" || m.Mode != "all" || live().HeaderRules[0].Values[0] != "s3cret-api" {
		t.Fatalf("after the repair: %s", raw)
	}
}
