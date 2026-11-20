package posture

import (
	"net/netip"
	"strings"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func be(rule, host string, port int) BackendFact {
	b := BackendFact{Rule: rule, Host: host, Port: port}
	if a, err := netip.ParseAddr(host); err == nil {
		b.Addr = a
	}
	return b
}

// declaredPlan is a plan that the healthy snapshot satisfies
func declaredPlan(f *Facts) {
	f.NetPlan = &NetPlanFacts{
		Declared: true, Role: "internal",
		ProxyCIDRs: []netip.Prefix{pfx("10.0.1.0/24")}, MgmtCIDRs: []netip.Prefix{pfx("10.0.9.0/24")}, AppCIDRs: []netip.Prefix{pfx("10.0.2.0/24")},
		AppPorts:      []PlanPorts{{443, 443}, {8000, 8100}},
		ActualTrusted: []netip.Prefix{pfx("10.0.1.5/32")}, TrustedUpstream: []netip.Prefix{pfx("10.0.1.5/32")},
		GuardHasList: true, GuardEntries: []netip.Prefix{pfx("10.0.2.0/24")},
		Backends: []BackendFact{be("a.example.com", "10.0.2.10", 443), be("b.example.com", "10.0.2.11", 8000)},
	}
}

func withPlan(mut func(f *Facts)) func(f *Facts) {
	return func(f *Facts) {
		declaredPlan(f)
		if mut != nil {
			mut(f)
		}
	}
}

func TestNetPlanChecksAreNotApplicableWithoutAPlan(t *testing.T) {
	f := healthy()
	f.NetPlan = &NetPlanFacts{Declared: false, Role: "standalone", Backends: []BackendFact{be("a", "10.5.5.5", 8123)}}
	for _, id := range []string{"netplan.backend_zone", "netplan.backend_port", "netplan.admin_bind", "netplan.trusted_zone", "netplan.external_mgmt", "netplan.backend_unrestricted", "netplan.plan_consistent"} {
		if got := statusOf(t, f, id); got.Status != StatusNA {
			t.Errorf("%s = %s without a plan", id, got.Status)
		}
	}
	// the plan independent checks stay silent on a clean install, so the score of an existing install does not move
	for _, id := range []string{"netplan.admin_public", "netplan.trust_all", "netplan.ssrf_targets"} {
		if got := statusOf(t, f, id); got.Status != StatusNA {
			t.Errorf("%s = %s on a clean install", id, got.Status)
		}
	}
	if rep := Default.Evaluate(f); rep.Score.Value != 100 {
		t.Fatalf("a snapshot without a plan changed the score: %d", rep.Score.Value)
	}
}

func TestNetPlanHealthyPlanPassesEverything(t *testing.T) {
	f := healthy()
	declaredPlan(f)
	rep := Default.Evaluate(f)
	for _, c := range rep.Checks {
		if c.Status != StatusOK && c.Status != StatusNA {
			t.Errorf("%s = %s %v with a plan that matches", c.ID, c.Status, c.Evidence)
		}
	}
}

func TestChecks_NetPlanBackendZone(t *testing.T) {
	runCases(t, "netplan.backend_zone", []checkCase{
		{"inside", withPlan(nil), StatusOK, "inside the plan"},
		{"outside", withPlan(func(f *Facts) {
			f.NetPlan.Backends = append(f.NetPlan.Backends, be("evil.example.com", "10.0.9.7", 443))
		}), StatusWarn, "evil.example.com"},
		{"outside public", withPlan(func(f *Facts) { f.NetPlan.Backends = []BackendFact{be("x", "8.8.8.8", 443)} }), StatusWarn, "8.8.8.8"},
		{"declared dest rescues", withPlan(func(f *Facts) {
			f.NetPlan.Backends = []BackendFact{be("x", "10.0.3.5", 443)}
			f.NetPlan.AllowedDecl = []PlanDest{{Prefix: pfx("10.0.3.5/32"), Ports: []PlanPorts{{443, 443}}}}
		}), StatusOK, ""},
		{"declared dest wrong port", withPlan(func(f *Facts) {
			f.NetPlan.Backends = []BackendFact{be("x", "10.0.3.5", 22)}
			f.NetPlan.AllowedDecl = []PlanDest{{Prefix: pfx("10.0.3.5/32"), Ports: []PlanPorts{{443, 443}}}}
		}), StatusWarn, ""},
		{"names only are unchecked", withPlan(func(f *Facts) { f.NetPlan.Backends = []BackendFact{be("x", "app.lan", 443)}; f.NetPlan.Unresolved = 1 }), StatusNA, "host names"},
		{"no application net", withPlan(func(f *Facts) { f.NetPlan.AppCIDRs = nil }), StatusNA, ""},
		{"ipv4-mapped is judged as ipv4", withPlan(func(f *Facts) {
			b := be("x", "::ffff:10.0.9.7", 443)
			f.NetPlan.Backends = []BackendFact{b}
		}), StatusWarn, ""},
		{"no facts", func(f *Facts) { f.NetPlan = nil }, StatusNA, ""},
	})
}

func TestChecks_NetPlanBackendPort(t *testing.T) {
	runCases(t, "netplan.backend_port", []checkCase{
		{"permitted", withPlan(nil), StatusOK, ""},
		{"one backend on 9090", withPlan(func(f *Facts) { f.NetPlan.Backends[1].Port = 9090 }), StatusWarn, "b.example.com"},
		{"all ok", withPlan(func(f *Facts) {
			f.NetPlan.Backends = []BackendFact{be("a", "10.0.2.10", 443), be("b", "10.0.2.11", 8000), be("c", "10.0.2.12", 8100)}
		}), StatusOK, ""},
		{"just outside the range", withPlan(func(f *Facts) { f.NetPlan.Backends = []BackendFact{be("a", "10.0.2.10", 8101)} }), StatusWarn, ":8101"},
		{"port of a host name is checked too", withPlan(func(f *Facts) { f.NetPlan.Backends = []BackendFact{be("a", "app.lan", 22)} }), StatusWarn, ""},
		{"declared destination port", withPlan(func(f *Facts) {
			f.NetPlan.Backends = []BackendFact{be("a", "10.0.2.10", 9443)}
			f.NetPlan.AllowedDecl = []PlanDest{{Prefix: pfx("10.0.2.10/32"), Ports: []PlanPorts{{9443, 9443}}}}
		}), StatusOK, ""},
		{"no ports declared", withPlan(func(f *Facts) { f.NetPlan.AppPorts = nil }), StatusNA, ""},
		{"no backends", withPlan(func(f *Facts) { f.NetPlan.Backends = nil }), StatusNA, ""},
	})
}

func TestChecks_NetPlanAdminBind(t *testing.T) {
	runCases(t, "netplan.admin_bind", []checkCase{
		{"loopback", withPlan(nil), StatusOK, "loopback"},
		{"inside management", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.ListenAddr = false, "10.0.9.2:8000"
		}), StatusOK, "inside the management"},
		{"outside management", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.ListenAddr = false, "10.0.2.2:8000"
		}), StatusFail, "outside the management"},
		{"all interfaces no allow-list", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.AllInterfaces, f.Admin.ListenAddr = false, true, ":8000"
		}), StatusFail, "every interface"},
		{"all interfaces allow-list inside", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.AllInterfaces, f.Admin.ListenAddr = false, true, ":8000"
			f.NetPlan.AdminAllow = []netip.Prefix{pfx("10.0.9.0/25")}
		}), StatusOK, ""},
		{"all interfaces allow-list leaks", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.AllInterfaces, f.Admin.ListenAddr = false, true, ":8000"
			f.NetPlan.AdminAllow = []netip.Prefix{pfx("10.0.9.0/24"), pfx("10.0.0.0/8")}
		}), StatusWarn, "10.0.0.0/8"},
		{"declared extra admin access is accepted", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.AllInterfaces, f.Admin.ListenAddr = false, true, ":8000"
			f.NetPlan.AdminAllow = []netip.Prefix{pfx("192.168.77.5/32")}
			f.NetPlan.AdminAccess = []netip.Prefix{pfx("192.168.77.5/32")}
		}), StatusOK, ""},
		{"name is unknown", withPlan(func(f *Facts) {
			f.Admin.Loopback, f.Admin.ListenAddr = false, "admin.lan:8000"
		}), StatusUnknown, ""},
		{"no management network", withPlan(func(f *Facts) { f.NetPlan.MgmtCIDRs = nil }), StatusNA, ""},
		{"admin unknown", withPlan(func(f *Facts) { f.Admin = nil }), StatusUnknown, ""},
	})
}

func TestChecks_NetPlanAdminPublic(t *testing.T) {
	pub := func(f *Facts) { f.Admin.Loopback, f.Admin.ListenAddr = false, "203.0.113.5:8000" }
	runCases(t, "netplan.admin_public", []checkCase{
		{"loopback is silent", nil, StatusNA, ""},
		{"private is silent", func(f *Facts) { f.Admin.Loopback, f.Admin.ListenAddr = false, "10.0.9.2:8000" }, StatusNA, ""},
		{"all interfaces is left to admin.bind", func(f *Facts) { f.Admin.AllInterfaces, f.Admin.ListenAddr = true, ":8000" }, StatusNA, ""},
		{"public address", pub, StatusFail, "203.0.113.5"},
		{"public ipv6", func(f *Facts) { f.Admin.Loopback, f.Admin.ListenAddr = false, "[2001:db8::5]:8000" }, StatusFail, "2001:db8::5"},
		{"public with allow-list is a warning", func(f *Facts) {
			pub(f)
			f.NetPlan = &NetPlanFacts{AdminAllow: []netip.Prefix{pfx("10.0.9.0/24")}}
		}, StatusWarn, "allow-list"},
		{"link-local is silent", func(f *Facts) { f.Admin.Loopback, f.Admin.ListenAddr = false, "169.254.1.1:8000" }, StatusNA, ""},
		{"no admin facts", func(f *Facts) { f.Admin = nil }, StatusNA, ""},
	})
	f := healthy()
	pub(f)
	if got := statusOf(t, f, "netplan.admin_public"); !got.Critical || got.Severity != "critical" {
		t.Errorf("a public admin listener must be critical: %+v", got)
	}
	if Default.Evaluate(f).Score.Value > CriticalCap {
		t.Error("a public admin listener must cap the score")
	}
}

func TestChecks_NetPlanTrustedZone(t *testing.T) {
	runCases(t, "netplan.trusted_zone", []checkCase{
		{"agrees", withPlan(nil), StatusOK, ""},
		{"private outside the proxy net", withPlan(func(f *Facts) {
			f.NetPlan.ActualTrusted = append(f.NetPlan.ActualTrusted, pfx("192.168.50.0/24"))
		}), StatusWarn, "192.168.50.0/24"},
		{"public range on an external proxy is a CDN", withPlan(func(f *Facts) {
			f.NetPlan.Role = "external"
			f.NetPlan.TrustedUpstream = nil
			f.NetPlan.ActualTrusted = []netip.Prefix{pfx("104.16.0.0/13")}
		}), StatusOK, ""},
		{"public range on an internal proxy", withPlan(func(f *Facts) {
			f.NetPlan.ActualTrusted = append(f.NetPlan.ActualTrusted, pfx("104.16.0.0/13"))
		}), StatusWarn, "internal proxy"},
		{"declared upstream outside proxy net", withPlan(func(f *Facts) {
			f.NetPlan.TrustedUpstream = []netip.Prefix{pfx("10.0.2.9/32")}
			f.NetPlan.ActualTrusted = append(f.NetPlan.ActualTrusted, pfx("10.0.2.9/32"))
		}), StatusWarn, "declared upstream proxy outside"},
		{"declared upstream not trusted", withPlan(func(f *Facts) { f.NetPlan.ActualTrusted = nil }), StatusWarn, "not in the Trusted Proxies"},
		{"wider trusted entry covers declared", withPlan(func(f *Facts) { f.NetPlan.ActualTrusted = []netip.Prefix{pfx("10.0.1.0/24")} }), StatusOK, ""},
		{"a trusted range larger than the proxy net", withPlan(func(f *Facts) { f.NetPlan.ActualTrusted = []netip.Prefix{pfx("10.0.0.0/16")} }), StatusWarn, "10.0.0.0/16"},
		{"nothing declared", withPlan(func(f *Facts) { f.NetPlan.ProxyCIDRs, f.NetPlan.TrustedUpstream = nil, nil }), StatusNA, ""},
	})
}

func TestChecks_NetPlanExternalMgmt(t *testing.T) {
	ext := func(mut func(f *Facts)) func(f *Facts) {
		return withPlan(func(f *Facts) {
			f.NetPlan.Role = "external"
			if mut != nil {
				mut(f)
			}
		})
	}
	runCases(t, "netplan.external_mgmt", []checkCase{
		{"clean", ext(nil), StatusOK, ""},
		{"backend in management", ext(func(f *Facts) {
			f.NetPlan.Backends = append(f.NetPlan.Backends, be("sneaky.example.com", "10.0.9.20", 443))
		}), StatusFail, "sneaky.example.com"},
		{"internal role is not judged", withPlan(func(f *Facts) { f.NetPlan.Backends = append(f.NetPlan.Backends, be("a", "10.0.9.20", 443)) }), StatusNA, "external role"},
		{"no management net", ext(func(f *Facts) { f.NetPlan.MgmtCIDRs = nil }), StatusNA, ""},
	})
}

func TestChecks_NetPlanTrustAll(t *testing.T) {
	trusted := func(p ...string) func(f *Facts) {
		return func(f *Facts) {
			f.NetPlan = &NetPlanFacts{}
			for _, s := range p {
				f.NetPlan.ActualTrusted = append(f.NetPlan.ActualTrusted, pfx(s))
			}
		}
	}
	runCases(t, "netplan.trust_all", []checkCase{
		{"normal list", trusted("104.16.0.0/13", "10.0.1.5/32"), StatusNA, ""},
		{"trust everything v4", trusted("0.0.0.0/0"), StatusFail, "forge"},
		{"trust everything v6", trusted("::/0"), StatusFail, "::/0"},
		{"one slash 8 is fine", trusted("10.0.0.0/8"), StatusNA, ""},
		{"very broad v4", trusted("64.0.0.0/2"), StatusWarn, "very broad"},
		{"very broad v6", trusted("2000::/3"), StatusWarn, "very broad"},
		{"hidden among many", trusted("10.0.1.5/32", "104.16.0.0/13", "0.0.0.0/0"), StatusFail, "0.0.0.0/0"},
		{"empty list", trusted(), StatusNA, ""},
		{"no facts", func(f *Facts) { f.NetPlan = nil }, StatusNA, ""},
	})
}

func TestChecks_NetPlanBackendUnrestricted(t *testing.T) {
	runCases(t, "netplan.backend_unrestricted", []checkCase{
		{"limited", withPlan(nil), StatusOK, ""},
		{"no list", withPlan(func(f *Facts) { f.NetPlan.GuardHasList, f.NetPlan.GuardEntries = false, nil }), StatusWarn, "no allowed backend"},
		{"too broad", withPlan(func(f *Facts) { f.NetPlan.GuardEntries = []netip.Prefix{pfx("10.0.0.0/8")} }), StatusWarn, "10.0.0.0/8"},
		{"narrower is fine", withPlan(func(f *Facts) { f.NetPlan.GuardEntries = []netip.Prefix{pfx("10.0.2.64/26")} }), StatusOK, ""},
		{"one entry outside among good ones", withPlan(func(f *Facts) {
			f.NetPlan.GuardEntries = []netip.Prefix{pfx("10.0.2.0/24"), pfx("10.0.9.4/32")}
		}), StatusWarn, "10.0.9.4"},
		{"declared destination allowed", withPlan(func(f *Facts) {
			f.NetPlan.GuardEntries = []netip.Prefix{pfx("10.0.2.0/24"), pfx("10.0.3.5/32")}
			f.NetPlan.AllowedDecl = []PlanDest{{Prefix: pfx("10.0.3.5/32")}}
		}), StatusOK, ""},
		{"no application net", withPlan(func(f *Facts) { f.NetPlan.AppCIDRs = nil }), StatusNA, ""},
	})
}

func TestChecks_NetPlanSSRFTargets(t *testing.T) {
	backends := func(role string, b ...BackendFact) func(f *Facts) {
		return func(f *Facts) { f.NetPlan = &NetPlanFacts{Role: role, Backends: b} }
	}
	runCases(t, "netplan.ssrf_targets", []checkCase{
		{"normal", backends("standalone", be("a", "10.0.2.10", 443), be("b", "app.lan", 80)), StatusNA, ""},
		{"aws metadata", backends("standalone", be("meta.example.com", "169.254.169.254", 80)), StatusFail, "169.254.169.254"},
		{"aws ipv6 metadata", backends("standalone", be("m", "fd00:ec2::254", 80)), StatusFail, "fd00:ec2::254"},
		{"gcp name", backends("standalone", be("m", "metadata.google.internal", 80)), StatusFail, "metadata.google.internal"},
		{"unspecified", backends("standalone", be("z", "0.0.0.0", 80)), StatusFail, "0.0.0.0"},
		{"multicast", backends("standalone", be("z", "224.0.0.1", 80)), StatusFail, "224.0.0.1"},
		{"mapped metadata", backends("standalone", be("m", "::ffff:169.254.169.254", 80)), StatusFail, "169.254.169.254"},
		{"link-local is a warning", backends("standalone", be("l", "169.254.10.10", 80)), StatusWarn, "link-local"},
		{"loopback on standalone is normal", backends("standalone", be("l", "127.0.0.1", 3000)), StatusNA, ""},
		{"loopback on external", backends("external", be("l", "127.0.0.1", 3000)), StatusWarn, "loopback"},
		{"loopback on internal", backends("internal", be("l", "::1", 3000)), StatusWarn, "loopback"},
		{"no facts", func(f *Facts) { f.NetPlan = nil }, StatusNA, ""},
	})
}

func TestChecks_NetPlanConsistent(t *testing.T) {
	runCases(t, "netplan.plan_consistent", []checkCase{
		{"disjoint", withPlan(nil), StatusOK, ""},
		{"management inside application", withPlan(func(f *Facts) { f.NetPlan.AppCIDRs = []netip.Prefix{pfx("10.0.0.0/16")} }), StatusWarn, "overlaps"},
		{"proxy equals application", withPlan(func(f *Facts) { f.NetPlan.AppCIDRs = f.NetPlan.ProxyCIDRs }), StatusWarn, "proxy 10.0.1.0/24 overlaps application"},
		{"upstream proxy in management", withPlan(func(f *Facts) { f.NetPlan.TrustedUpstream = []netip.Prefix{pfx("10.0.9.5/32")} }), StatusWarn, "declared upstream proxy"},
		{"no plan", func(f *Facts) { f.NetPlan = &NetPlanFacts{} }, StatusNA, ""},
	})
}

func TestNetPlanChecksNeverTouchTheNetwork(t *testing.T) {
	// a backend written as a name must be reported as unchecked, never resolved: the facts have no resolver at all
	f := healthy()
	declaredPlan(f)
	f.NetPlan.Backends = []BackendFact{be("x", "does-not-resolve.invalid", 443)}
	f.NetPlan.Unresolved = 1
	got := statusOf(t, f, "netplan.backend_zone")
	if got.Status != StatusNA || !strings.Contains(got.Evidence[0], "host names") {
		t.Fatalf("%+v", got)
	}
}
