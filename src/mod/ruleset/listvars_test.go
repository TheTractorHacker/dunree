package ruleset

import (
	"sync"
	"testing"
)

type tvars struct {
	mu sync.Mutex
	m  map[string]string
}

func (v *tvars) set(k, val string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if val == "" {
		delete(v.m, k)
		return
	}
	v.m[k] = val
}

func (v *tvars) lookup(k string) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.m[k]
	return s, ok
}

// blocked runs the engine for one request and reports whether a rule matched
func hit(e *Engine, host, ip string) bool {
	if !e.Active() {
		return false
	}
	run := e.Begin(&Env{R: mkReq("GET", "http://"+host+"/", nil), ClientIP: ip}, "")
	return run != nil && run.Next() != nil
}

// "Block requests addressed to my current external IP" (upstream #370) without hard-coding it:
// a string list holding {{external_ip}}, compared with http.host.
func TestListFollowsExternalIP(t *testing.T) {
	e := NewMemory()
	vars := &tvars{m: map[string]string{}}
	e.SetVarResolver(vars.lookup)
	if _, err := e.SaveList(List{Name: "my_addresses", Type: ListString, Items: []string{"{{external_ip}}", "legacy.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Create("", in("by ip", `http.host in $my_addresses`, Action{Type: ActBlock}), -1); err != nil {
		t.Fatal(err)
	}
	// public IP not known yet: only the literal entry matches
	if hit(e, "198.51.100.77", "192.0.2.1") || !hit(e, "legacy.example.com", "192.0.2.1") {
		t.Fatal("unresolved variable: wrong matches")
	}
	if v := e.ListVars("my_addresses"); len(v) != 1 || v[0].OK || v[0].Name != "external_ip" || v[0].Error == "" {
		t.Fatalf("ListVars = %+v", v)
	}
	if e.RefreshVars() {
		t.Fatal("RefreshVars reported a change although nothing changed")
	}
	vars.set("external_ip", "198.51.100.77")
	if hit(e, "198.51.100.77", "192.0.2.1") {
		t.Fatal("a value is only applied by RefreshVars, never per request")
	}
	if !e.RefreshVars() {
		t.Fatal("RefreshVars did not notice the new value")
	}
	if !hit(e, "198.51.100.77", "192.0.2.1") || hit(e, "app.example.com", "192.0.2.1") {
		t.Fatal("the rule does not follow {{external_ip}}")
	}
	// the dynamic address changes
	vars.set("external_ip", "203.0.113.200")
	e.RefreshVars()
	if hit(e, "198.51.100.77", "192.0.2.1") || !hit(e, "203.0.113.200", "192.0.2.1") {
		t.Fatal("the rule kept the old address")
	}
	if v := e.ListVars("my_addresses"); len(v) != 1 || !v[0].OK || v[0].Value != "203.0.113.200" {
		t.Fatalf("ListVars = %+v", v)
	}
	// the stored list keeps the reference, not the value
	if l := e.Lists(); len(l) != 1 || l[0].Items[0] != "{{external_ip}}" {
		t.Fatalf("stored items = %v", l[0].Items)
	}
	// the request tester sees the resolved value too
	res := e.Test(TestInput{Method: "GET", URL: "http://203.0.113.200/", ClientIP: "192.0.2.1"})
	if len(res.Rules) != 1 || !res.Rules[0].Matched {
		t.Fatalf("tester: %+v", res.Rules)
	}
}

// A user variable in an ip list: the "remote office" alias of the issue
func TestIPListWithVariables(t *testing.T) {
	e := NewMemory()
	vars := &tvars{m: map[string]string{"remote_office_ext_ip": "203.0.113.9"}}
	e.SetVarResolver(vars.lookup)
	if _, err := e.SaveList(List{Name: "office", Type: ListIP, Items: []string{"10.0.0.0/8", "{{ remote_office_ext_ip }}", "{{droplets}}"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Create("", in("office only", `ip.src not in $office`, Action{Type: ActBlock}), -1); err != nil {
		t.Fatal(err)
	}
	if hit(e, "a", "203.0.113.9") || hit(e, "a", "10.1.2.3") || !hit(e, "a", "203.0.113.10") {
		t.Fatal("ip list with a variable: wrong matches")
	}
	// several addresses / networks in one variable, IPv6 included
	vars.set("droplets", "198.51.100.0/28, 2001:db8::5 192.0.2.44")
	e.RefreshVars()
	for _, ip := range []string{"198.51.100.3", "2001:db8::5", "192.0.2.44", "203.0.113.9"} {
		if hit(e, "a", ip) {
			t.Errorf("%s is in $office and must not be blocked", ip)
		}
	}
	if !hit(e, "a", "198.51.100.99") {
		t.Fatal("an address outside the list was let through")
	}
	// a value that is not an address disables that entry only, and is reported
	vars.set("droplets", "not-an-address")
	e.RefreshVars()
	if !hit(e, "a", "198.51.100.3") || hit(e, "a", "203.0.113.9") || hit(e, "a", "10.1.2.3") {
		t.Fatal("an invalid value must drop only its own entry")
	}
	bad := 0
	for _, v := range e.ListVars("office") {
		if !v.OK {
			bad++
			if v.Name != "droplets" || v.Error == "" {
				t.Fatalf("unexpected state %+v", v)
			}
		}
	}
	if bad != 1 {
		t.Fatalf("expected exactly one unresolved variable, got %d", bad)
	}
	// deleting the variable: the entry matches nothing (never "everything")
	vars.set("remote_office_ext_ip", "")
	e.RefreshVars()
	if !hit(e, "a", "203.0.113.9") {
		t.Fatal("a deleted variable still matches")
	}
}

func TestListVariablesValidationAndCompat(t *testing.T) {
	e := NewMemory()
	// no resolver: nothing resolves, nothing breaks
	if _, err := e.SaveList(List{Name: "words", Type: ListString, Items: []string{"{{literal}}", "b"}}); err != nil {
		t.Fatal(err)
	}
	x, perr := Parse(`http.header["x"] in $words`)
	if perr != nil {
		t.Fatal(perr)
	}
	if perr := x.Link(e.currentLists()); perr != nil {
		t.Fatal(perr)
	}
	// a string entry that looks like a reference but is not defined keeps its literal meaning
	if !x.Eval(&Env{R: mkReq("GET", "/", map[string]string{"X": "{{literal}}"})}) {
		t.Fatal("an undefined reference in a string list must stay the literal text")
	}
	// country lists do not take variables
	if _, err := e.SaveList(List{Name: "cc", Type: ListCountry, Items: []string{"{{countries}}"}}); err == nil {
		t.Fatal("a country list accepted a variable")
	}
	// things that are not exactly one reference are still invalid in an ip list
	for _, it := range []string{"{{a}}/24", "{{A}}", "{{}}", "x{{a}}", "{{a}}{{b}}"} {
		if _, err := e.SaveList(List{Name: "nets", Type: ListIP, Items: []string{it}}); err == nil {
			t.Errorf("ip list accepted %q", it)
		}
	}
	// lists without references are the very same object in the snapshot (no copy, no new cost)
	if _, err := e.SaveList(List{Name: "plain", Type: ListIP, Items: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	var stored *List
	for _, l := range e.Lists() {
		if l.Name == "plain" {
			stored = l
		}
	}
	if e.snap.Load().lists["plain"] != stored {
		t.Fatal("a list without variables must not be copied")
	}
}

func TestListVariablesPersistAndRace(t *testing.T) {
	e, _ := newPersisted(t)
	vars := &tvars{m: map[string]string{"external_ip": "198.51.100.1"}}
	e.SetVarResolver(vars.lookup)
	if _, err := e.SaveList(List{Name: "me", Type: ListIP, Items: []string{"{{external_ip}}"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Create("", in("self", `ip.src in $me`, Action{Type: ActBlock}), -1); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	if !hit(e, "a", "198.51.100.1") {
		t.Fatal("the reference did not survive a reload")
	}
	// requests keep running while values change (run with -race)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					hit(e, "a", "198.51.100.1")
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		vars.set("external_ip", []string{"198.51.100.1", "198.51.100.2"}[i%2])
		e.RefreshVars()
	}
	close(stop)
	wg.Wait()
}

// A variable written with an IPv4 wildcard works in an access list, so it has to work in a rule
// list as well (as the network it stands for); a wildcard that is not a network is reported.
func TestIPListVariableWildcards(t *testing.T) {
	for in, want := range map[string]string{"10.0.*.*": "10.0.0.0/16", "192.168.1.*": "192.168.1.0/24", "10.*.*.*": "10.0.0.0/8", "*.*.*.*": "0.0.0.0/0"} {
		if got, problem := wildcardCIDR(in); got != want || problem != "" {
			t.Errorf("wildcardCIDR(%q) = %q %q, want %q", in, got, problem, want)
		}
	}
	for _, in := range []string{"10.*.0.1", "10.0.*", "10.0.*.*.*", "300.1.*.*", "a.b.*.*", "*", "10.0.1*.*", "2001:db8::*"} {
		if got, problem := wildcardCIDR(in); problem == "" {
			t.Errorf("wildcardCIDR(%q) = %q, want a problem", in, got)
		}
	}

	e := NewMemory()
	vars := &tvars{m: map[string]string{"lan": "10.0.*.*, 203.0.113.9"}}
	e.SetVarResolver(vars.lookup)
	if _, err := e.SaveList(List{Name: "lan", Type: ListIP, Items: []string{"{{lan}}"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Create("", in("lan", `ip.src in $lan`, Action{Type: ActBlock}), -1); err != nil {
		t.Fatal(err)
	}
	if !hit(e, "a", "10.0.7.7") || !hit(e, "a", "203.0.113.9") || hit(e, "a", "10.1.0.1") {
		t.Fatal("a trailing wildcard must match its network and nothing else")
	}
	if v := e.ListVars("lan"); len(v) != 1 || !v[0].OK {
		t.Fatalf("list vars: %+v", v)
	}
	// not a network: the entry matches nothing and says why
	vars.set("lan", "10.*.0.1")
	e.RefreshVars()
	if hit(e, "a", "10.5.0.1") || hit(e, "a", "10.0.7.7") {
		t.Fatal("a wildcard that is not a network must match nothing")
	}
	if v := e.ListVars("lan"); len(v) != 1 || v[0].OK || v[0].Error == "" {
		t.Fatalf("list vars: %+v", v)
	}
}
