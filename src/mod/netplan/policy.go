package netplan

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Disclaimer is stated at the top and the bottom of every export and on the Network plan tab.
const Disclaimer = "Dunree has NOT applied, changed or checked any firewall rule. Nothing in this document is active anywhere. " +
	"It is a set of recommendations generated from the network plan written in Dunree. Review every line, adapt it to your " +
	"network and apply it yourself in the UniFi and Proxmox consoles. Dunree cannot see your firewalls and does not know whether " +
	"these rules exist."

// Backend is one backend destination currently used by a proxy rule: address and port only, never a path,
// credential or header (the caller strips them).
type Backend struct {
	Rule string // proxy rule host name
	Host string
	Port int
}

// Context is what the export needs from the running instance besides the plan
type Context struct {
	Role        string // standalone | external | internal
	ProxyPorts  []int  // ports of the reverse proxy listener (443, 80)
	AdminPort   int    // 0 = unknown
	AdminListen string // the -port value as given
	Backends    []Backend
	Now         time.Time
}

const unset = "(not set in the plan)"

func zoneLabel(z Zone, def string) string {
	if z.Name != "" {
		return z.Name
	}
	return def
}

func cidrText(z Zone) string {
	if len(z.CIDRs) == 0 {
		return unset
	}
	return strings.Join(z.CIDRs, ", ")
}

// ipsetName makes a name Proxmox accepts: starts with a letter, letters, digits, - and _
func ipsetName(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	n := strings.Trim(b.String(), "-")
	if n == "" {
		n = "zone"
	}
	return "dunree-" + n
}

func portList(ports []string) string {
	if len(ports) == 0 {
		return unset
	}
	return strings.Join(ports, ", ")
}

func ints(p []int) []string {
	out := []string{}
	for _, v := range p {
		out = append(out, strconv.Itoa(v))
	}
	return out
}

// Recommendations renders the firewall recommendations as markdown. It contains the plan values, the
// listener ports and the host:port pairs of current backends, and nothing else of the configuration.
func Recommendations(s Settings, c Context) string {
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}
	proxyZ, mgmtZ, appZ := zoneLabel(s.ProxyVLAN, "Proxy VLAN"), zoneLabel(s.ManagementVLAN, "Management VLAN"), zoneLabel(s.ApplicationVLAN, "Application VLAN")
	proxyPorts := ints(c.ProxyPorts)
	if len(proxyPorts) == 0 {
		proxyPorts = []string{"443"}
	}
	adminPort := unset
	if c.AdminPort > 0 {
		adminPort = strconv.Itoa(c.AdminPort)
	}
	role := c.Role
	if role == "" {
		role = "standalone"
	}

	var b strings.Builder
	w := func(f string, a ...interface{}) { fmt.Fprintf(&b, f+"\n", a...) }

	w("# Firewall recommendations from the Dunree network plan")
	w("")
	w("> **NOT APPLIED. %s**", Disclaimer)
	w("")
	w("Generated %s for a Dunree instance with the deployment role **%s**.", now.UTC().Format("2006-01-02 15:04 UTC"), role)
	w("")
	var missing []string
	if len(s.ProxyVLAN.CIDRs) == 0 {
		missing = append(missing, "the proxy VLAN networks")
	}
	if len(s.ManagementVLAN.CIDRs) == 0 {
		missing = append(missing, "the management VLAN networks")
	}
	if len(s.ApplicationVLAN.CIDRs) == 0 && len(s.AllowedBackends) == 0 {
		missing = append(missing, "the application VLAN networks or allowed backend destinations")
	}
	if len(missing) > 0 {
		w("**Incomplete plan.** The plan does not name %s. Rules that need them are written with the placeholder `%s` and cannot be used until you fill it in.", strings.Join(missing, ", "), unset)
		w("")
	}

	w("## 1. The plan these recommendations come from")
	w("")
	w("| Zone | Name | Networks |")
	w("|---|---|---|")
	w("| Proxy | %s | %s |", proxyZ, cidrText(s.ProxyVLAN))
	w("| Management | %s | %s |", mgmtZ, cidrText(s.ManagementVLAN))
	w("| Application | %s | %s |", appZ, cidrText(s.ApplicationVLAN))
	w("")
	w("- Trusted upstream proxies: %s", orUnset(s.TrustedProxies))
	w("- Allowed backend destinations: %s", orUnset(s.AllowedBackends))
	w("- Permitted application ports: %s", portList(s.AppPorts))
	w("- Extra administrative access (besides %s): %s", mgmtZ, orUnset(s.AdminAccess))
	w("- Reverse proxy listener ports: %s. Admin port: %s", strings.Join(proxyPorts, ", "), adminPort)
	w("")

	w("## 2. Intended traffic (stateful: replies are allowed automatically)")
	w("")
	w("| # | From | To | Protocol and ports | Action |")
	w("|---|---|---|---|---|")
	n := 1
	row := func(from, to, pp, act string) { w("| %d | %s | %s | %s | %s |", n, from, to, pp, act); n++ }
	switch role {
	case "external":
		row("Internet (or your CDN ranges)", proxyZ+" (this proxy)", "TCP "+strings.Join(proxyPorts, ", "), "Allow")
		row(proxyZ+" (this proxy)", "the internal proxy (the backend destinations of the plan): "+appDest(s), "TCP "+declaredOr(s.AppPorts, internalPort), "Allow")
	case "internal":
		if len(s.TrustedProxies) > 0 {
			row("the external proxy: "+strings.Join(s.TrustedProxies, ", "), proxyZ+" (this proxy)", "TCP "+strings.Join(proxyPorts, ", "), "Allow")
		} else {
			row("the external proxy "+unset, proxyZ+" (this proxy)", "TCP "+strings.Join(proxyPorts, ", "), "Allow")
		}
		row(proxyZ+" (this proxy)", appZ+": "+appDest(s), "TCP "+portList(s.AppPorts), "Allow")
	default:
		row("Clients (internet or LAN, as you intend)", proxyZ+" (this proxy)", "TCP "+strings.Join(proxyPorts, ", "), "Allow")
		row(proxyZ+" (this proxy)", appZ+": "+appDest(s), "TCP "+portList(s.AppPorts), "Allow")
	}
	adminSrc := mgmtZ + " (" + cidrText(s.ManagementVLAN) + ")"
	if len(s.AdminAccess) > 0 {
		adminSrc += " and " + strings.Join(s.AdminAccess, ", ")
	}
	row(adminSrc, proxyZ+" (this proxy), admin panel", "TCP "+adminPort, "Allow")
	w("")
	w("Explicit denies (put them below the allows, log them):")
	w("")
	w("| # | From | To | Action |")
	w("|---|---|---|---|")
	d := 1
	deny := func(from, to string) { w("| D%d | %s | %s | Deny and log |", d, from, to); d++ }
	deny(proxyZ, mgmtZ+" (everything, including the admin ports of other hosts)")
	deny(appZ, mgmtZ)
	deny(appZ, proxyZ+" (new connections; replies to proxy-initiated connections are covered by connection tracking)")
	deny("everything that is not in the admin source list above", proxyZ+" admin port "+adminPort)
	deny(proxyZ, "everything else on private networks and the internet, except what table 2 allows (name the update, DNS, NTP and ACME destinations you need before denying)")
	w("")

	w("## 3. UniFi (UDM Pro, zone-based firewall)")
	w("")
	w("Created by you in Network > Settings > Security > Policy Table (the menu names differ between UniFi Network versions). **Untested here: Dunree has no access to a UniFi console.**")
	w("")
	w("1. Zones: put the %s networks in one zone (for example `%s`), the %s networks in another and the %s networks in a third. The zone assignment of a network is a UniFi setting, not a rule.", proxyZ, proxyZ, mgmtZ, appZ)
	w("2. Allow policies, in this order (rows of table 2):")
	for _, line := range udmAllows(s, c, role, proxyZ, mgmtZ, appZ, proxyPorts, adminPort) {
		w("   - %s", line)
	}
	w("3. Block policies (rows D1 to D%d): create one per row, action Block, **Logging on**, and put them after the allow policies.", d-1)
	w("4. Check the policy order and the \"Return traffic\" / connection tracking default of your UniFi version. Do not rely on a default allow between zones.")
	w("5. After applying: test an allowed path, test each denied path from a test host, and look at the block log. Dunree does not verify any of this.")
	w("")

	w("## 4. Proxmox VE firewall")
	w("")
	w("For the VM or container that runs Dunree (file `/etc/pve/firewall/<vmid>.fw`, or the Firewall tab of the guest). Enable the datacenter and the guest firewall yourself. **Untested here: check the syntax against your Proxmox version.**")
	w("")
	w("```")
	w("[OPTIONS]")
	w("enable: 1")
	w("policy_in: DROP")
	w("policy_out: ACCEPT")
	w("")
	for _, z := range []struct {
		label string
		zone  Zone
		extra []string
	}{{mgmtZ, s.ManagementVLAN, s.AdminAccess}, {proxyZ, s.ProxyVLAN, nil}, {appZ, s.ApplicationVLAN, nil}} {
		w("[IPSET %s]", ipsetName(z.label))
		cidrs := append(append([]string{}, z.zone.CIDRs...), z.extra...)
		if len(cidrs) == 0 {
			w("# %s", unset)
		}
		for _, cidr := range cidrs {
			w("%s", cidr)
		}
		w("")
	}
	if len(s.TrustedProxies) > 0 {
		w("[IPSET dunree-upstream-proxies]")
		for _, p := range s.TrustedProxies {
			w("%s", p)
		}
		w("")
	}
	w("[RULES]")
	w("IN ACCEPT -source +%s -p tcp -dport %s # admin panel from the management network", ipsetName(mgmtZ), adminPortOr(adminPort))
	switch role {
	case "internal":
		src := "+dunree-upstream-proxies"
		if len(s.TrustedProxies) == 0 {
			src = "+" + ipsetName(proxyZ)
		}
		for _, p := range proxyPorts {
			w("IN ACCEPT -source %s -p tcp -dport %s # traffic from the external proxy only", src, p)
		}
	case "external":
		for _, p := range proxyPorts {
			w("IN ACCEPT -p tcp -dport %s # from the internet; narrow with -source if only your CDN may connect", p)
		}
	default:
		for _, p := range proxyPorts {
			w("IN ACCEPT -p tcp -dport %s # clients; narrow with -source if you can", p)
		}
	}
	w("OUT ACCEPT -dest +%s -p tcp -dport %s # backends", ipsetName(appZ), portListRule(s.AppPorts))
	w("```")
	w("")
	w("Add the DNS, NTP and ACME destinations Dunree needs to the output rules, and keep `policy_in: DROP` so everything not listed is refused.")
	w("")

	if len(c.Backends) > 0 {
		w("## 5. Backends the proxy rules use today")
		w("")
		w("Taken from the running configuration when this file was generated. Compare with the allowed destinations above.")
		w("")
		w("| Proxy rule | Backend host | Port | Inside the plan |")
		w("|---|---|---|---|")
		bs := append([]Backend(nil), c.Backends...)
		sort.Slice(bs, func(i, j int) bool {
			if bs[i].Host != bs[j].Host {
				return bs[i].Host < bs[j].Host
			}
			return bs[i].Port < bs[j].Port
		})
		app := ParsePrefixes(s.ApplicationVLAN.CIDRs)
		dests := ParseDests(s.AllowedBackends)
		ports := ParsePorts(s.AppPorts)
		shown := 0
		for _, be := range bs {
			if shown >= 100 {
				w("| ... | %d more | | |", len(bs)-shown)
				break
			}
			shown++
			w("| %s | %s | %d | %s |", mdCell(be.Rule), mdCell(be.Host), be.Port, inPlan(be, app, dests, ports))
		}
		w("")
	}

	w("## 6. Dunree settings that match this plan (set them yourself)")
	w("")
	w("These are Dunree's own optional settings. Dunree has not changed them.")
	w("")
	w("- Security Center > Network exposure > Admin panel allow-list: %s", orUnset(append(append([]string{}, s.ManagementVLAN.CIDRs...), s.AdminAccess...)))
	w("- Security Center > Network exposure > Allowed backend destinations: %s", orUnset(append(append([]string{}, s.ApplicationVLAN.CIDRs...), s.AllowedBackends...)))
	w("- Trusted Proxies: %s", orUnset(s.TrustedProxies))
	w("")
	w("---")
	w("")
	w("> **NOT APPLIED. %s**", Disclaimer)
	return b.String()
}

func orUnset(l []string) string {
	if len(l) == 0 {
		return unset
	}
	safe := make([]string, len(l))
	for i, e := range l {
		safe[i] = planSafe(e)
	}
	return strings.Join(safe, ", ")
}

// planSafe is the defence in depth for every plan string that reaches the exported markdown: only characters
// an address, a port list or a zone name can need survive (settings stored by an older build are not trusted either)
func planSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '.', r == ':', r == '/', r == ',', r == '(', r == ')', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// internalPort: the port the external proxy uses towards the internal proxy is not in the plan (the plan lists
// application ports); 443 is the usual listener, the administrator confirms it
func declaredOr(declared []string, def string) string {
	if len(declared) > 0 {
		return orUnset(declared)
	}
	return def
}

const internalPort = "443 (the internal proxy's listener port, confirm it)"

func appDest(s Settings) string {
	all := append(append([]string{}, s.ApplicationVLAN.CIDRs...), s.AllowedBackends...)
	return orUnset(all)
}

func adminPortOr(p string) string {
	if p == unset {
		return "<admin port>"
	}
	return p
}

func portListRule(p []string) string {
	if len(p) == 0 {
		return "<application ports>"
	}
	out := make([]string, len(p))
	for i, v := range p {
		out[i] = strings.ReplaceAll(v, "-", ":") //Proxmox writes ranges as 8000:8100
	}
	return strings.Join(out, ",")
}

func udmAllows(s Settings, c Context, role, proxyZ, mgmtZ, appZ string, proxyPorts []string, adminPort string) []string {
	var out []string
	switch role {
	case "external":
		out = append(out, fmt.Sprintf("Internet or Cloudflare ranges -> %s, TCP %s", proxyZ, strings.Join(proxyPorts, ", ")))
		out = append(out, fmt.Sprintf("%s (this proxy) -> internal proxy %s, TCP %s", proxyZ, appDest(s), declaredOr(s.AppPorts, internalPort)))
	case "internal":
		out = append(out, fmt.Sprintf("external proxy %s -> %s, TCP %s", orUnset(s.TrustedProxies), proxyZ, strings.Join(proxyPorts, ", ")))
		out = append(out, fmt.Sprintf("%s -> %s (%s), TCP %s", proxyZ, appZ, appDest(s), portList(s.AppPorts)))
	default:
		out = append(out, fmt.Sprintf("clients -> %s, TCP %s", proxyZ, strings.Join(proxyPorts, ", ")))
		out = append(out, fmt.Sprintf("%s -> %s (%s), TCP %s", proxyZ, appZ, appDest(s), portList(s.AppPorts)))
	}
	out = append(out, fmt.Sprintf("%s (%s) -> %s, admin panel TCP %s", mgmtZ, orUnset(append(append([]string{}, s.ManagementVLAN.CIDRs...), s.AdminAccess...)), proxyZ, adminPort))
	return out
}

func inPlan(be Backend, app []netip.Prefix, dests []Dest, ports []PortRange) string {
	a, err := netip.ParseAddr(strings.Trim(be.Host, "[]"))
	if err != nil {
		return "unknown (host name, not resolved by Dunree)"
	}
	a = a.Unmap()
	ok := false
	for _, p := range app {
		if p.Contains(a) {
			ok = true
		}
	}
	for _, d := range dests {
		if d.Matches(a, be.Port) {
			ok = true
		}
	}
	if !ok && len(app) == 0 && len(dests) == 0 {
		return "no application network declared"
	}
	if !ok {
		return "NO: address outside the plan"
	}
	if len(ports) > 0 {
		pok := false
		for _, p := range ports {
			if p.Contains(be.Port) {
				pok = true
			}
		}
		for _, d := range dests {
			if d.Matches(a, be.Port) {
				pok = true
			}
		}
		if !pok {
			return "NO: port not permitted"
		}
	}
	return "yes"
}

// mdCell keeps untrusted text (a proxy rule name, a host name) from breaking a markdown table or opening markup
func mdCell(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '|' || r == '`' || r == '<' || r == '>' || r == '\\' || r == '*' || r == '_' || r == '[' || r == ']':
			b.WriteByte('?')
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
		if b.Len() > 120 {
			break
		}
	}
	return b.String()
}
