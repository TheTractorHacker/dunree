package netplan

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type memKV struct {
	m       map[string]string
	failing bool
}

func (k *memKV) Read(table, key string, v interface{}) error {
	raw, ok := k.m[table+"/"+key]
	if !ok {
		return errors.New("not found")
	}
	return json.Unmarshal([]byte(raw), v)
}

func (k *memKV) Write(table, key string, v interface{}) error {
	if k.failing {
		return errors.New("disk full")
	}
	b, _ := json.Marshal(v)
	k.m[table+"/"+key] = string(b)
	return nil
}

func goodPlan() Settings {
	return Settings{
		ProxyVLAN:       Zone{Name: "Proxy VLAN", CIDRs: []string{"10.0.1.0/24"}},
		ManagementVLAN:  Zone{Name: "Mgmt", CIDRs: []string{"10.0.9.0/24"}},
		ApplicationVLAN: Zone{Name: "Apps", CIDRs: []string{"10.0.2.0/24", "fd00:2::/64"}},
		TrustedProxies:  []string{"10.0.1.5"},
		AllowedBackends: []string{"10.0.3.5 443"},
		AppPorts:        []string{"443", "8000-8100"},
		AdminAccess:     []string{"192.168.77.5"},
	}
}

func TestNormalizeAcceptsAGoodPlanAndCanonicalises(t *testing.T) {
	in := goodPlan()
	in.ApplicationVLAN.CIDRs = []string{" 10.0.2.77/24 ", "10.0.2.0/24", "fd00:2::1/64"}
	in.AppPorts = []string{"443", "443", " 8000 - 8100 ", "9000-9000"}
	n, err := Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(n.ApplicationVLAN.CIDRs, ","); got != "10.0.2.0/24,fd00:2::/64" {
		t.Fatalf("cidrs not masked and deduplicated: %s", got)
	}
	if got := strings.Join(n.AppPorts, ","); got != "443,8000-8100,9000" {
		t.Fatalf("ports: %s", got)
	}
	if n.TrustedProxies[0] != "10.0.1.5" {
		t.Fatalf("a single address must stay a single address: %v", n.TrustedProxies)
	}
}

func TestNormalizeRefusesHostileOrBrokenInput(t *testing.T) {
	long := strings.Repeat("a", 500)
	many := make([]string, MaxEntries+1)
	for i := range many {
		many[i] = "10.1." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10)) + "/32"
	}
	manyPrefix := []string{}
	for i := 0; i <= MaxEntries; i++ {
		manyPrefix = append(manyPrefix, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 7, byte(i), 1}), 32).String())
	}
	cases := []struct {
		name string
		mut  func(s *Settings)
		want string
	}{
		{"markdown table break in a name", func(s *Settings) { s.ProxyVLAN.Name = "A | B" }, "name may only"},
		{"code fence in a name", func(s *Settings) { s.ManagementVLAN.Name = "x```\nrm -rf /" }, "name may only"},
		{"newline in a name", func(s *Settings) { s.ApplicationVLAN.Name = "a\nb" }, "name may only"},
		{"html in a name", func(s *Settings) { s.ProxyVLAN.Name = "<script>alert(1)</script>" }, "name may only"},
		{"shell substitution in a name", func(s *Settings) { s.ProxyVLAN.Name = "$(reboot)" }, "name may only"},
		{"leading space-less symbol", func(s *Settings) { s.ProxyVLAN.Name = "-rf" }, "name may only"},
		{"name too long", func(s *Settings) { s.ProxyVLAN.Name = strings.Repeat("a", MaxNameLen+1) }, "longer than"},
		{"any v4", func(s *Settings) { s.ProxyVLAN.CIDRs = []string{"0.0.0.0/0"} }, "every address"},
		{"any v6", func(s *Settings) { s.ManagementVLAN.CIDRs = []string{"::/0"} }, "every address"},
		{"host name instead of an address", func(s *Settings) { s.TrustedProxies = []string{"proxy.example.com"} }, "not an IP"},
		{"bad cidr", func(s *Settings) { s.ProxyVLAN.CIDRs = []string{"10.0.0.0/33"} }, "not a valid network"},
		{"garbage", func(s *Settings) { s.AdminAccess = []string{"; drop table"} }, "not an IP"},
		{"mapped v4", func(s *Settings) { s.AdminAccess = []string{"::ffff:10.0.0.1"} }, "plain form"},
		{"entry too long", func(s *Settings) { s.AdminAccess = []string{long} }, "too long"},
		{"port 0", func(s *Settings) { s.AppPorts = []string{"0"} }, "not a port"},
		{"port 65536", func(s *Settings) { s.AppPorts = []string{"65536"} }, "not a port"},
		{"reversed range", func(s *Settings) { s.AppPorts = []string{"9000-8000"} }, "not a port"},
		{"port word", func(s *Settings) { s.AppPorts = []string{"https"} }, "not a port"},
		{"allowed backend host name", func(s *Settings) { s.AllowedBackends = []string{"app.lan"} }, "host names are not accepted"},
		{"allowed backend match-all", func(s *Settings) { s.AllowedBackends = []string{"0.0.0.0/0"} }, "every address"},
		{"allowed backend bad port", func(s *Settings) { s.AllowedBackends = []string{"10.0.0.1 99999"} }, "ports must be"},
		{"too many entries", func(s *Settings) { s.TrustedProxies = manyPrefix }, "at most"},
	}
	_ = many
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := goodPlan()
			c.mut(&s)
			_, err := Normalize(s)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestDeclared(t *testing.T) {
	if (Settings{}).Declared() {
		t.Fatal("the zero value is no plan")
	}
	if !(Settings{AppPorts: []string{"443"}}).Declared() || !(Settings{ProxyVLAN: Zone{Name: "x"}}).Declared() {
		t.Fatal("any field makes it a plan")
	}
}

func TestManagerPersistsAcrossRestartAndRefusesBadInput(t *testing.T) {
	kv := &memKV{m: map[string]string{}}
	m, err := New(kv)
	if err != nil || m.Declared() {
		t.Fatal("a fresh install has no plan", err)
	}
	var seen [2]Settings
	m.OnChange = func(o, n Settings) { seen = [2]Settings{o, n} }
	if err := m.Set(goodPlan()); err != nil {
		t.Fatal(err)
	}
	if seen[0].Declared() || !seen[1].Declared() {
		t.Fatalf("OnChange: %+v", seen)
	}
	// "restart": a new manager over the same store
	m2, err := New(kv)
	if err != nil || !m2.Declared() || m2.Settings().ManagementVLAN.CIDRs[0] != "10.0.9.0/24" {
		t.Fatalf("plan lost on restart: %v %+v", err, m2.Settings())
	}
	// a refused plan changes nothing and persists nothing
	bad := goodPlan()
	bad.ProxyVLAN.CIDRs = []string{"0.0.0.0/0"}
	before := kv.m[DBTable+"/"+DBKey]
	if err := m2.Set(bad); err == nil {
		t.Fatal("accepted")
	}
	if kv.m[DBTable+"/"+DBKey] != before || m2.Settings().ProxyVLAN.CIDRs[0] != "10.0.1.0/24" {
		t.Fatal("a refused plan altered the stored plan")
	}
	// a failing store leaves the active plan alone
	kv.failing = true
	other := goodPlan()
	other.AppPorts = []string{"1234"}
	if err := m2.Set(other); err == nil || m2.Settings().AppPorts[0] == "1234" {
		t.Fatal("a failed write was applied")
	}
	// clearing the plan is possible
	kv.failing = false
	if err := m2.Set(Settings{}); err != nil || m2.Declared() {
		t.Fatalf("clear: %v", err)
	}
}

func TestStoredPlanThatNoLongerValidatesIsIgnored(t *testing.T) {
	kv := &memKV{m: map[string]string{DBTable + "/" + DBKey: `{"proxyVlan":{"name":"x|y","cidrs":["10.0.0.0/8"]}}`}}
	m, err := New(kv)
	if err == nil || m.Declared() {
		t.Fatalf("a tampered stored plan must be ignored with an error: %v declared=%v", err, m.Declared())
	}
}

func TestSettingsReturnsCopiesAndNeverNilLists(t *testing.T) {
	m, _ := New(nil)
	s := m.Settings()
	if s.TrustedProxies == nil || s.ProxyVLAN.CIDRs == nil || s.AppPorts == nil {
		t.Fatal("nil list in the API shape")
	}
	m.Set(goodPlan())
	s = m.Settings()
	s.TrustedProxies[0] = "6.6.6.6"
	if m.Settings().TrustedProxies[0] == "6.6.6.6" {
		t.Fatal("Settings must return a copy")
	}
	var nilMgr *Manager
	if nilMgr.Declared() || nilMgr.Settings().Declared() {
		t.Fatal("nil manager")
	}
}

func TestParseDestsAndMatching(t *testing.T) {
	d := ParseDests([]string{"10.0.3.0/24 443,8000-8100", "10.0.4.5", "bogus"})
	if len(d) != 2 {
		t.Fatalf("%d", len(d))
	}
	a := netip.MustParseAddr
	if !d[0].Matches(a("10.0.3.9"), 8050) || d[0].Matches(a("10.0.3.9"), 22) || d[0].Matches(a("10.0.5.9"), 443) {
		t.Fatal("port or range matching")
	}
	if !d[1].Matches(a("10.0.4.5"), 22) || !d[0].Matches(a("::ffff:10.0.3.1"), 443) {
		t.Fatal("any port / mapped address")
	}
}

/* ---- policy export ---- */

func exportCtx() Context {
	return Context{Role: "internal", ProxyPorts: []int{443, 80}, AdminPort: 8000, AdminListen: "10.0.9.2:8000",
		Now:      time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC),
		Backends: []Backend{{Rule: "app.example.com", Host: "10.0.2.10", Port: 443}, {Rule: "rogue.example.com", Host: "10.0.9.77", Port: 22}, {Rule: "named", Host: "app.lan", Port: 8080}}}
}

func TestRecommendationsStateThatNothingWasApplied(t *testing.T) {
	for _, role := range []string{"standalone", "external", "internal"} {
		c := exportCtx()
		c.Role = role
		md := Recommendations(goodPlan(), c)
		if strings.Count(md, "NOT APPLIED") < 2 {
			t.Fatalf("%s: the disclaimer must open and close the document", role)
		}
		if !strings.HasPrefix(md, "# Firewall recommendations") || !strings.Contains(strings.SplitN(md, "\n", 4)[2], "NOT APPLIED") {
			t.Fatalf("%s: the disclaimer must be the first thing after the title:\n%s", role, md[:200])
		}
		if !strings.Contains(md, "Dunree has NOT applied") || !strings.Contains(md, "apply it yourself") {
			t.Fatal("disclaimer text")
		}
		low := strings.ToLower(md)
		for _, forbidden := range []string{"has been applied", "were applied", "successfully applied", "rules applied", "applied to the firewall", "configured your"} {
			if strings.Contains(low, forbidden) {
				t.Errorf("%s: the export must never claim rules were applied (%q)", role, forbidden)
			}
		}
		// both firewalls are covered, with allows and explicit denies
		for _, want := range []string{"## 3. UniFi", "## 4. Proxmox", "Deny and log", "IN ACCEPT", "policy_in: DROP", "[IPSET dunree-mgmt]", "10.0.9.0/24", "8000"} {
			if !strings.Contains(md, want) {
				t.Errorf("%s: export lacks %q", role, want)
			}
		}
	}
}

func TestRecommendationsRoleSpecificRules(t *testing.T) {
	c := exportCtx()
	c.Role = "internal"
	md := Recommendations(goodPlan(), c)
	if !strings.Contains(md, "the external proxy: 10.0.1.5") || !strings.Contains(md, "-source +dunree-upstream-proxies -p tcp -dport 443") {
		t.Fatalf("internal role must allow only the declared upstream proxy:\n%s", md)
	}
	c.Role = "external"
	md = Recommendations(goodPlan(), c)
	if !strings.Contains(md, "Internet (or your CDN ranges)") || strings.Contains(md, "+dunree-upstream-proxies -p tcp") {
		t.Fatalf("external role:\n%s", md)
	}
}

func TestRecommendationsMarksBackendsOutsideThePlan(t *testing.T) {
	md := Recommendations(goodPlan(), exportCtx())
	for _, want := range []string{"| app.example.com | 10.0.2.10 | 443 | yes |", "| rogue.example.com | 10.0.9.77 | 22 | NO: address outside the plan |", "unknown (host name"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	p := goodPlan()
	p.AppPorts = []string{"8443"}
	if md := Recommendations(p, exportCtx()); !strings.Contains(md, "NO: port not permitted") {
		t.Error("a permitted-port mismatch must be marked")
	}
}

func TestRecommendationsIncompletePlanUsesPlaceholders(t *testing.T) {
	md := Recommendations(Settings{}, Context{Role: "standalone"})
	if !strings.Contains(md, "Incomplete plan") || !strings.Contains(md, "(not set in the plan)") || !strings.Contains(md, "NOT APPLIED") {
		t.Fatalf("%s", md)
	}
	if strings.Contains(md, "<nil>") || strings.Contains(md, "%!") {
		t.Fatal("formatting leak")
	}
}

func TestRecommendationsContainOnlyPlanValuesAndCannotBeInjected(t *testing.T) {
	c := exportCtx()
	// a proxy rule name or a host is attacker influenced text: it must not break the table or open markup
	c.Backends = []Backend{{Rule: "evil|x`<img src=x onerror=1>**\n# Heading\n[a](javascript:1)", Host: "h|`", Port: 1}}
	md := Recommendations(goodPlan(), c)
	for _, bad := range []string{"<img", "```\n# Heading", "\n# Heading", "[a](", "onerror=1>"} {
		if strings.Contains(md, bad) {
			t.Errorf("injection survived: %q", bad)
		}
	}
	idx := strings.Index(md, "## 5.")
	section := md[idx:strings.Index(md, "## 6.")]
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "| evil") && strings.Count(line, "|") != 5 {
			t.Errorf("table row broken: %q", line)
		}
	}
	// no field of the instance other than the listed ones can appear: the plan and the context have no secret field
	for _, f := range []string{"password", "secret", "token", "apikey", "BEGIN PRIVATE KEY"} {
		if strings.Contains(strings.ToLower(md), strings.ToLower(f)) {
			t.Errorf("export mentions %q", f)
		}
	}
}

func TestRecommendationsBoundedWithManyBackends(t *testing.T) {
	c := exportCtx()
	c.Backends = nil
	for i := 0; i < 5000; i++ {
		c.Backends = append(c.Backends, Backend{Rule: "r", Host: "10.0.2.1", Port: 1 + i%60000})
	}
	if md := Recommendations(goodPlan(), c); len(md) > 64<<10 || !strings.Contains(md, "more |") {
		t.Fatalf("export of %d bytes is not bounded", len(md))
	}
}

func TestIpsetNameIsProxmoxSafe(t *testing.T) {
	for in, want := range map[string]string{"Mgmt VLAN (10)": "dunree-mgmt-vlan-10", "": "dunree-zone", "../etc": "dunree-etc", "A_B": "dunree-a-b"} {
		if got := ipsetName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// an IPv6 zone suffix is accepted by the address parser: the stored form must be rebuilt, never the raw text
func TestAllowedBackendZoneSuffixCannotInjectMarkup(t *testing.T) {
	in := goodPlan()
	evil := "fe80::1%<svg+onerror=alert(1)>|` 443"
	in.AllowedBackends = []string{evil}
	n, err := Normalize(in)
	if err != nil {
		t.Fatalf("a valid address with a zone must be accepted and canonicalised: %v", err)
	}
	if got := n.AllowedBackends[0]; got != "fe80::1 443" {
		t.Fatalf("not canonical: %q", got)
	}
	md := Recommendations(n, exportCtx())
	for _, bad := range []string{"<svg", "onerror", "%<"} {
		if strings.Contains(md, bad) {
			t.Errorf("zone markup survived into the export: %q", bad)
		}
	}
	// settings stored by an older build skip Normalize: the renderer must still hold
	raw := goodPlan()
	raw.AllowedBackends = []string{evil}
	md = Recommendations(raw, exportCtx())
	for _, bad := range []string{"<svg", "|`", "%<", "alert(1)>"} {
		if strings.Contains(md, bad) {
			t.Errorf("unnormalised entry reached the export unescaped: %q", bad)
		}
	}
}
