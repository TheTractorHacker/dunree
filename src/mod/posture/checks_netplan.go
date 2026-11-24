package posture

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/foleyit/dunree/mod/destguard"
)

/*
	Network plan checks (ids netplan.*). They compare the real configuration with the plan the administrator wrote
	in Security Center > Network plan (mod/netplan), and add a few plan independent checks for dangerous
	configuration (trust-all forwarding, public admin listener, SSRF capable backends).

	Rules that keep existing installs unchanged:
	  - a check that needs the plan is "not applicable" until a plan is saved;
	  - a plan independent check is "not applicable" while it finds nothing, so it can only lower a score when
	    it finds a real problem, never add to it;
	  - nothing here resolves a host name: a backend written as a name is counted as unchecked in the evidence.
	Checks that already exist are not repeated: certificate verification is upstream.tls_verify, a rule that points
	at the admin port is admin.rule_target, the allowed backend list is exposure.backend_allowlist.
*/

func init() {
	for _, c := range netplanChecks() {
		Default.MustRegister(c)
	}
}

var netplanFix = Remediation{Label: "Open Security Center, Network plan", Page: "seccenter", Anchor: "netplan"}

func inAny(a netip.Addr, list []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// prefixWithin: every address of p is inside one of list
func prefixWithin(p netip.Prefix, list []netip.Prefix) bool {
	for _, o := range list {
		if o.Bits() <= p.Bits() && o.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func overlaps(a, b netip.Prefix) bool { return a.Overlaps(b) }

func (d PlanDest) matches(a netip.Addr, port int) bool {
	if !d.Prefix.Contains(a.Unmap()) {
		return false
	}
	if port <= 0 || len(d.Ports) == 0 {
		return true
	}
	for _, p := range d.Ports {
		if port >= p.Lo && port <= p.Hi {
			return true
		}
	}
	return false
}

func (n *NetPlanFacts) declaredDest(a netip.Addr, port int) bool {
	for _, d := range n.AllowedDecl {
		if d.matches(a, port) {
			return true
		}
	}
	return false
}

func backendLabel(b BackendFact) string {
	return fmt.Sprintf("%s -> %s:%d", b.Rule, b.Host, b.Port)
}

func addrOf(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func prefixNames(l []netip.Prefix, max int) string {
	s := make([]string, 0, len(l))
	for _, p := range l {
		s = append(s, addrOf(p))
	}
	return listNames(s, max)
}

// planFacts returns the facts when a plan is saved, else the "not applicable" result
func planFacts(f *Facts) (*NetPlanFacts, *Result) {
	if f.NetPlan == nil {
		r := na("the network plan could not be read")
		return nil, &r
	}
	if !f.NetPlan.Declared {
		r := na("no network plan is saved (Security Center > Network plan)")
		return nil, &r
	}
	return f.NetPlan, nil
}

// adminHost extracts the literal address of the admin listener ("" and false when it is all interfaces or a name)
func adminHost(listen string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func netplanChecks() []Check {
	return []Check{
		{
			ID: "netplan.backend_zone", Title: "Proxy rule backends are inside the declared application network", Category: CatExposure, Weight: 5,
			Why:         "Your network plan says where the application servers live. A proxy rule that forwards to an address outside it either means the plan is out of date or the rule points somewhere it should not. Backends written as host names are not checked (Dunree does not look names up here).",
			Remediation: netplanFix,
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				if len(n.AppCIDRs) == 0 && len(n.AllowedDecl) == 0 {
					return na("the plan names no application network or allowed backend destination")
				}
				var bad []string
				checked := 0
				for _, b := range n.Backends {
					if !b.Addr.IsValid() {
						continue
					}
					checked++
					if !inAny(b.Addr, n.AppCIDRs) && !n.declaredDest(b.Addr, b.Port) {
						bad = append(bad, backendLabel(b))
					}
				}
				if checked == 0 {
					return na(fmt.Sprintf("no backend is written as an IP address (%d written as host names are not checked)", n.Unresolved))
				}
				if len(bad) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%d of %d backends are outside the declared application network: %s", len(bad), checked, listNames(bad, 6))}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("all %d backends written as IP addresses are inside the plan (%d host names unchecked)", checked, n.Unresolved)}}
			},
		},
		{
			ID: "netplan.backend_port", Title: "Proxy rule backends use only permitted application ports", Category: CatExposure, Weight: 4,
			Why:         "The plan lists the ports applications may be reached on, and the firewall recommendations only allow those. A backend on another port would be blocked there, or means the plan is incomplete.",
			Remediation: netplanFix,
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				if len(n.AppPorts) == 0 {
					return na("the plan names no permitted application ports")
				}
				var bad []string
				for _, b := range n.Backends {
					ok := false
					for _, p := range n.AppPorts {
						if b.Port >= p.Lo && b.Port <= p.Hi {
							ok = true
						}
					}
					if !ok && b.Addr.IsValid() && n.declaredDest(b.Addr, b.Port) {
						ok = true
					}
					if !ok {
						bad = append(bad, backendLabel(b))
					}
				}
				if len(n.Backends) == 0 {
					return na("there are no proxy rule backends")
				}
				if len(bad) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%d of %d backends use a port the plan does not permit: %s", len(bad), len(n.Backends), listNames(bad, 6))}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("all %d backends use permitted ports", len(n.Backends))}}
			},
		},
		{
			ID: "netplan.admin_bind", Title: "The admin panel is reachable only from the management network", Category: CatExposure, Weight: 6,
			Why:         "The plan says which network administers this proxy. An admin listener bound to an address outside it, or open on every interface without an allow-list, can be reached from networks that should never see the admin panel.",
			Remediation: Remediation{Label: "Bind the admin port to the management address, or set the admin allow-list", Page: "seccenter", Anchor: "exposure"},
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				if len(n.MgmtCIDRs) == 0 {
					return na("the plan names no management network")
				}
				if f.Admin == nil {
					return unknown("the admin interface settings could not be read")
				}
				allowed := append(append([]netip.Prefix{}, n.MgmtCIDRs...), n.AdminAccess...)
				a := f.Admin
				if a.Loopback {
					return Result{Status: StatusOK, Evidence: []string{"the admin panel listens on loopback (" + a.ListenAddr + ") only"}}
				}
				if a.AllInterfaces {
					if len(n.AdminAllow) == 0 {
						return Result{Status: StatusFail, Evidence: []string{"-port=" + a.ListenAddr + " listens on every interface and no admin allow-list is set: the admin panel is reachable from every network of this host, not only " + prefixNames(n.MgmtCIDRs, 4)}}
					}
					var out []string
					for _, p := range n.AdminAllow {
						if !prefixWithin(p, allowed) {
							out = append(out, addrOf(p))
						}
					}
					if len(out) > 0 {
						return Result{Status: StatusWarn, Evidence: []string{"the admin allow-list admits " + listNames(out, 6) + ", which is outside the management network and the declared administrative access"}}
					}
					return Result{Status: StatusOK, Evidence: []string{"every network of the admin allow-list is inside the management network or the declared administrative access"}}
				}
				ip, ok := adminHost(a.ListenAddr)
				if !ok {
					return unknown("the admin listen address " + a.ListenAddr + " is not an IP address, so it cannot be compared with the plan")
				}
				if inAny(ip, allowed) {
					return Result{Status: StatusOK, Evidence: []string{"the admin panel listens on " + ip.String() + ", inside the management network"}}
				}
				return Result{Status: StatusFail, Evidence: []string{"the admin panel listens on " + ip.String() + ", which is outside the management network " + prefixNames(n.MgmtCIDRs, 4)}}
			},
		},
		{
			ID: "netplan.admin_public", Title: "The admin panel is not bound to a public address", Category: CatExposure, Weight: 8, Critical: true,
			Why:         "An admin listener bound to a publicly routable address is reachable from the internet unless a firewall in front blocks it, and the admin panel is the most valuable target of the proxy. This check applies with or without a network plan, and only reports when it finds the problem.",
			Remediation: Remediation{Label: "Bind the admin port to the management address, or set the admin allow-list", Page: "seccenter", Anchor: "exposure"},
			Run: func(f *Facts) Result {
				if f.Admin == nil {
					return na("the admin interface settings could not be read")
				}
				ip, ok := adminHost(f.Admin.ListenAddr)
				if !ok || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					return na("the admin listener is not bound to a public address")
				}
				if f.NetPlan != nil && len(f.NetPlan.AdminAllow) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{"the admin panel is bound to the public address " + ip.String() + "; the admin allow-list limits who may connect, but the listener is still on a public address"}}
				}
				return Result{Status: StatusFail, Evidence: []string{"the admin panel is bound to the public address " + ip.String() + " with no admin allow-list: anyone on the internet who can reach it sees the login page"}}
			},
		},
		{
			ID: "netplan.trusted_zone", Title: "Trusted proxies match the proxy network of the plan", Category: CatExposure, Weight: 5,
			Why:         "Trusted proxies are believed when they say who the visitor is. Your plan says which network proxies live in: a private address trusted outside it, a public range trusted on an internal proxy, or a declared upstream proxy that is not in the trusted list, all make the client address wrong or spoofable.",
			Remediation: Remediation{Label: "Open Trusted Proxies", Page: "trustproxy"},
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				if len(n.ProxyCIDRs) == 0 && len(n.TrustedUpstream) == 0 {
					return na("the plan names no proxy network or upstream proxy")
				}
				var bad []string
				for _, p := range n.ActualTrusted {
					a := p.Addr()
					private := a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
					if len(n.ProxyCIDRs) > 0 && private && !prefixWithin(p, n.ProxyCIDRs) {
						bad = append(bad, addrOf(p)+" (private, outside the proxy network)")
					} else if n.Role == "internal" && !private && len(n.ProxyCIDRs) > 0 {
						bad = append(bad, addrOf(p)+" (public range trusted on an internal proxy)")
					}
				}
				for _, p := range n.TrustedUpstream {
					if len(n.ProxyCIDRs) > 0 && !prefixWithin(p, n.ProxyCIDRs) {
						bad = append(bad, addrOf(p)+" (declared upstream proxy outside the proxy network)")
					}
					covered := false
					for _, t := range n.ActualTrusted {
						if t.Bits() <= p.Bits() && t.Contains(p.Addr()) {
							covered = true
						}
					}
					if !covered {
						bad = append(bad, addrOf(p)+" (declared upstream proxy, not in the Trusted Proxies list)")
					}
				}
				if len(bad) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{"trusted proxy mismatch: " + listNames(bad, 5)}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("the %d trusted proxy entries and the declared upstream proxies agree with the plan", len(n.ActualTrusted))}}
			},
		},
		{
			ID: "netplan.external_mgmt", Title: "The external proxy does not forward to the management network", Category: CatExposure, Weight: 8,
			Why:         "An internet-facing proxy that can forward to the management network turns any flaw in a proxied request into access to the admin side of your network. Judged only for the external role.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp"},
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				if n.Role != "external" {
					return na("this instance is not set to the external role")
				}
				if len(n.MgmtCIDRs) == 0 {
					return na("the plan names no management network")
				}
				var bad []string
				for _, b := range n.Backends {
					if b.Addr.IsValid() && inAny(b.Addr, n.MgmtCIDRs) {
						bad = append(bad, backendLabel(b))
					}
				}
				if len(bad) > 0 {
					return Result{Status: StatusFail, Evidence: []string{"this is the external proxy and these backends are in the management network: " + listNames(bad, 6)}}
				}
				return Result{Status: StatusOK, Evidence: []string{"no backend of the external proxy is in the management network"}}
			},
		},
		{
			ID: "netplan.trust_all", Title: "Forwarded headers are not trusted from everyone", Category: CatExposure, Weight: 7,
			Why:         "If the trusted proxy list covers every address (or a huge part of the internet), anyone can set their own client address in X-Forwarded-For and defeat access rules, rate limits and bans. This check applies with or without a network plan, and only reports when it finds the problem.",
			Remediation: Remediation{Label: "Open Trusted Proxies", Page: "trustproxy"},
			Run: func(f *Facts) Result {
				if f.NetPlan == nil {
					return na("the trusted proxy list could not be read")
				}
				var all, broad []string
				for _, p := range f.NetPlan.ActualTrusted {
					switch {
					case p.Bits() == 0:
						all = append(all, addrOf(p))
					case p.Addr().Is4() && p.Bits() < 8, p.Addr().Is6() && p.Bits() < 16:
						broad = append(broad, addrOf(p))
					}
				}
				if len(all) > 0 {
					return Result{Status: StatusFail, Evidence: []string{"the trusted proxy list contains " + listNames(all, 3) + ": every client is treated as a trusted proxy, so any visitor can forge their address"}}
				}
				if len(broad) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{"the trusted proxy list contains very broad ranges: " + listNames(broad, 4)}}
				}
				return na("the trusted proxy list has no catch-all range")
			},
		},
		{
			ID: "netplan.backend_unrestricted", Title: "Allowed backend destinations are limited to the application network", Category: CatExposure, Weight: 4,
			Why:         "Without an allowed backend list, a proxy rule (or a stolen admin session) can point at any address, including the management network. An entry broader than the plan lets rules reach more than you declared. Compare with the check that existing upstreams are inside the list (exposure.backend_allowlist).",
			Remediation: Remediation{Label: "Open Security Center, Network exposure", Page: "seccenter", Anchor: "exposure"},
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				if len(n.AppCIDRs) == 0 && len(n.AllowedDecl) == 0 {
					return na("the plan names no application network or allowed backend destination")
				}
				if !n.GuardHasList {
					return Result{Status: StatusWarn, Evidence: []string{"no allowed backend destinations list is set (Network exposure): a proxy rule may point at any address. The plan's application network can be entered there"}}
				}
				var wide []string
				decl := make([]netip.Prefix, 0, len(n.AllowedDecl))
				for _, d := range n.AllowedDecl {
					decl = append(decl, d.Prefix)
				}
				for _, p := range n.GuardEntries {
					if !prefixWithin(p, n.AppCIDRs) && !prefixWithin(p, decl) {
						wide = append(wide, addrOf(p))
					}
				}
				if len(wide) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{"the allowed backend list admits " + listNames(wide, 6) + ", more than the plan's application network and declared destinations"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"the allowed backend list stays inside the plan"}}
			},
		},
		{
			ID: "netplan.ssrf_targets", Title: "No proxy rule targets a cloud metadata or link-local address", Category: CatExposure, Weight: 6,
			Why:         "A backend on a cloud metadata address (169.254.169.254), a link-local, multicast or unspecified address is almost never a real application server, and is how server-side request forgery reaches cloud credentials. Loopback backends are normal on a standalone proxy and are only reported on the external and internal roles. This check applies with or without a plan, and only reports when it finds a problem.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp"},
			Run: func(f *Facts) Result {
				if f.NetPlan == nil {
					return na("the backends could not be read")
				}
				var meta, other []string
				for _, b := range f.NetPlan.Backends {
					if !b.Addr.IsValid() {
						if h := strings.ToLower(strings.TrimSuffix(b.Host, ".")); h == "metadata.google.internal" || h == "instance-data" {
							meta = append(meta, backendLabel(b))
						}
						continue
					}
					cls, err := destguard.Classify(b.Addr)
					switch {
					case err != nil:
						a := b.Addr.Unmap()
						if a.IsLinkLocalUnicast() && a.String() != "169.254.169.254" && a.String() != "169.254.170.2" {
							other = append(other, backendLabel(b)+" (link-local)")
						} else {
							meta = append(meta, backendLabel(b))
						}
					case cls == destguard.ClassLoopback && f.NetPlan.Role != "" && f.NetPlan.Role != "standalone":
						other = append(other, backendLabel(b)+" (loopback)")
					}
				}
				if len(meta) > 0 {
					return Result{Status: StatusFail, Evidence: []string{"backends on cloud metadata, multicast, unspecified or reserved addresses: " + listNames(meta, 5)}}
				}
				if len(other) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{"backends that can reach the local machine or link-local network: " + listNames(other, 5)}}
				}
				return na("no proxy rule backend is a metadata, link-local or other dangerous address")
			},
		},
		{
			ID: "netplan.plan_consistent", Title: "The network plan does not contradict itself", Category: CatExposure, Weight: 3,
			Why:         "Overlapping networks (the management VLAN inside the application VLAN, say) make every recommendation and every comparison ambiguous.",
			Remediation: netplanFix,
			Run: func(f *Facts) Result {
				n, early := planFacts(f)
				if early != nil {
					return *early
				}
				zones := []struct {
					name string
					list []netip.Prefix
				}{{"proxy", n.ProxyCIDRs}, {"management", n.MgmtCIDRs}, {"application", n.AppCIDRs}}
				var bad []string
				for i := 0; i < len(zones); i++ {
					for j := i + 1; j < len(zones); j++ {
						for _, a := range zones[i].list {
							for _, b := range zones[j].list {
								if overlaps(a, b) {
									bad = append(bad, fmt.Sprintf("%s %s overlaps %s %s", zones[i].name, addrOf(a), zones[j].name, addrOf(b)))
								}
							}
						}
					}
				}
				for _, p := range n.TrustedUpstream {
					if inAny(p.Addr(), n.MgmtCIDRs) || inAny(p.Addr(), n.AppCIDRs) {
						bad = append(bad, "declared upstream proxy "+addrOf(p)+" is inside the management or application network")
					}
				}
				if len(bad) > 0 {
					return Result{Status: StatusWarn, Evidence: []string{listNames(bad, 4)}}
				}
				return Result{Status: StatusOK, Evidence: []string{"the declared networks do not overlap"}}
			},
		},
	}
}
