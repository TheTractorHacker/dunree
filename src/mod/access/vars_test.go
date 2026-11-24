package access

import (
	"sync"
	"testing"
)

type testVars struct {
	mu sync.Mutex
	m  map[string]string
}

func (v *testVars) set(k, val string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if val == "" {
		delete(v.m, k)
		return
	}
	v.m[k] = val
}

func (v *testVars) lookup(k string) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.m[k]
	return s, ok
}

func TestEntryVar(t *testing.T) {
	for in, want := range map[string]string{"{{external_ip}}": "external_ip", "{{ office }}": "office", "{{a1_b}}": "a1_b"} {
		if got, ok := EntryVar(in); !ok || got != want {
			t.Errorf("EntryVar(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "1.2.3.4", "{{}}", "{{A}}", "{{1a}}", "{{a}}/24", "x{{a}}", "{{a b}}", "{{a}}{{b}}"} {
		if _, ok := EntryVar(in); ok {
			t.Errorf("EntryVar(%q) must not match", in)
		}
	}
}

// A {{name}} entry of the IP blacklist follows the variable without the list being edited
func TestBlacklistVariableEntries(t *testing.T) {
	vars := &testVars{m: map[string]string{}}
	rule := ruleWithList(map[string]string{"{{external_ip}}": "my own address", "{{bad_nets}}": "nets", "10.9.9.9": "static"})

	// no resolver installed: the entries match nothing, exactly as before the feature existed
	SetVarResolver(nil)
	if rule.IsIPBlacklisted("198.51.100.77") {
		t.Fatal("matched without a resolver")
	}
	SetVarResolver(vars.lookup)
	defer SetVarResolver(nil)
	if rule.IsIPBlacklisted("198.51.100.77") {
		t.Fatal("an unresolved variable must match nothing")
	}
	if !rule.IsIPBlacklisted("10.9.9.9") {
		t.Fatal("the static entry stopped working")
	}

	vars.set("external_ip", "198.51.100.77")
	if !rule.IsIPBlacklisted("198.51.100.77") || rule.IsIPBlacklisted("198.51.100.78") {
		t.Fatal("{{external_ip}} does not follow the variable")
	}
	if c, err := rule.GetBlacklistedIPComment("198.51.100.77"); err != nil || c != "my own address" {
		t.Fatalf("comment = %q %v", c, err)
	}
	// the address changes (dynamic IP): no list edit, no index rebuild needed
	vars.set("external_ip", "203.0.113.200")
	if rule.IsIPBlacklisted("198.51.100.77") || !rule.IsIPBlacklisted("203.0.113.200") {
		t.Fatal("a changed value is not picked up")
	}
	// several values, CIDR, wildcard and IPv6 in one variable
	vars.set("bad_nets", "192.0.2.0/24, 172.16.*.*;2001:db8::/32 100.64.0.1")
	for _, ip := range []string{"192.0.2.200", "172.16.5.6", "2001:db8::1", "100.64.0.1"} {
		if !rule.IsIPBlacklisted(ip) {
			t.Errorf("%s must be blacklisted through {{bad_nets}}", ip)
		}
	}
	for _, ip := range []string{"192.0.3.1", "172.17.0.1", "2001:db9::1", "100.64.0.2"} {
		if rule.IsIPBlacklisted(ip) {
			t.Errorf("%s must not be blacklisted", ip)
		}
	}
	// garbage in a variable never matches and never panics
	vars.set("bad_nets", "not-an-ip, 999.1.1.1/99, {{external_ip}}")
	if rule.IsIPBlacklisted("192.0.2.200") || rule.IsIPBlacklisted("203.0.113.201") {
		t.Fatal("an invalid value matched")
	}
}

func TestWhitelistVariableEntries(t *testing.T) {
	vars := &testVars{m: map[string]string{}}
	wl := map[string]string{"{{remote_office_ext_ip}}": "office", "192.0.2.1": ""}
	rule := &AccessRule{WhiteListIP: &wl}

	SetVarResolver(nil)
	if rule.IsIPWhitelisted("203.0.113.9") {
		t.Fatal("matched without a resolver")
	}
	SetVarResolver(vars.lookup)
	defer SetVarResolver(nil)
	if rule.IsIPWhitelisted("203.0.113.9") {
		t.Fatal("an unresolved variable must never allow-list an address")
	}
	vars.set("remote_office_ext_ip", "203.0.113.9")
	if !rule.IsIPWhitelisted("203.0.113.9") || rule.IsIPWhitelisted("203.0.113.10") || !rule.IsIPWhitelisted("192.0.2.1") {
		t.Fatal("{{remote_office_ext_ip}} does not follow the variable")
	}
	vars.set("remote_office_ext_ip", "203.0.113.0/28")
	if !rule.IsIPWhitelisted("203.0.113.10") || rule.IsIPWhitelisted("203.0.113.40") {
		t.Fatal("a network value is not honoured")
	}
	vars.set("remote_office_ext_ip", "")
	if rule.IsIPWhitelisted("203.0.113.10") {
		t.Fatal("a deleted variable still allow-lists")
	}
}
