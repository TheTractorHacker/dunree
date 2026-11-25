// Package netplan holds the network plan the administrator writes down: the proxy, management and application
// VLANs (names and CIDRs), the upstream proxies that are expected, the backend destinations and application
// ports that are permitted, and who may administer this instance. It is a document. Nothing in it is applied
// to a firewall, a switch, a hypervisor or Dunree's own listeners: the posture checks (mod/posture) compare the
// real configuration with it and report differences, and policy.go turns it into recommendations for the
// administrator to review and apply by hand.
//
// Opt-in: the zero value is "no plan" and nothing is judged against it.
package netplan

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/TheTractorHacker/dunree/mod/destguard"
)

const (
	// DBTable and DBKey are where the plan lives (sys.db, table "settings": captured by the change history)
	DBTable = "settings"
	DBKey   = "netplan"

	MaxEntries = 64  // entries per list
	MaxNameLen = 48  // zone names
	maxEntry   = 120 // characters of one entry
)

// Zone is one named network segment
type Zone struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// Settings is the plan. Every field's zero value means "not declared".
type Settings struct {
	ProxyVLAN       Zone `json:"proxyVlan"`       // where the proxies live
	ManagementVLAN  Zone `json:"managementVlan"`  // where administrators and the admin ports live
	ApplicationVLAN Zone `json:"applicationVlan"` // where the backend servers live

	// TrustedProxies are the upstream proxies this instance expects to receive traffic from (an internal proxy
	// lists the external proxy here). Addresses or CIDRs; they should be inside the proxy VLAN.
	TrustedProxies []string `json:"trustedProxies"`

	// AllowedBackends are explicit backend destinations outside (or narrower than) the application VLAN, in the
	// syntax of the Network exposure list: "10.0.2.5", "10.0.2.0/24 443,8000-8100", "10.0.2.5:443"
	AllowedBackends []string `json:"allowedBackends"`

	// AppPorts are the ports applications may be reached on ("443", "8000-8100"). Empty = not declared.
	AppPorts []string `json:"appPorts"`

	// AdminAccess are extra addresses or networks, besides the management VLAN, that may administer this instance
	AdminAccess []string `json:"adminAccess"`
}

// PortRange is an inclusive port range
type PortRange struct{ Lo, Hi int }

// Contains tells whether p is in the range
func (r PortRange) Contains(p int) bool { return p >= r.Lo && p <= r.Hi }

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]*$`)

// Declared reports whether the administrator wrote anything down
func (s Settings) Declared() bool {
	for _, z := range []Zone{s.ProxyVLAN, s.ManagementVLAN, s.ApplicationVLAN} {
		if z.Name != "" || len(z.CIDRs) > 0 {
			return true
		}
	}
	return len(s.TrustedProxies) > 0 || len(s.AllowedBackends) > 0 || len(s.AppPorts) > 0 || len(s.AdminAccess) > 0
}

// ParsePrefix reads an address or a CIDR. A single address becomes a host prefix. Networks that match
// everything are refused: a plan that says "any" says nothing.
func ParsePrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, errors.New("empty entry")
	}
	if len(raw) > maxEntry {
		return netip.Prefix{}, errors.New("entry too long")
	}
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		var err error
		if p, err = netip.ParsePrefix(raw); err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid network (write it like 10.0.2.0/24)", raw)
		}
		p = p.Masked()
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or network (host names are not accepted, they can change)", raw)
		}
		a = a.WithZone("")
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q: write IPv4 addresses in plain form", raw)
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%q matches every address, a plan entry must name a real network", raw)
	}
	return p, nil
}

// ParsePrefixes reads a list; entries that do not parse are skipped (a stored plan is validated on save)
func ParsePrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, e := range list {
		if p, err := ParsePrefix(e); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// ParsePort reads "443" or "8000-8100"
func ParsePort(raw string) (PortRange, error) {
	raw = strings.TrimSpace(raw)
	lo, hi := 0, 0
	var e1, e2 error
	if a, b, ok := strings.Cut(raw, "-"); ok {
		lo, e1 = strconv.Atoi(strings.TrimSpace(a))
		hi, e2 = strconv.Atoi(strings.TrimSpace(b))
	} else {
		lo, e1 = strconv.Atoi(raw)
		hi = lo
	}
	if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return PortRange{}, fmt.Errorf("%q is not a port (use 443 or a range such as 8000-8100)", raw)
	}
	return PortRange{lo, hi}, nil
}

// ParsePorts reads a list; entries that do not parse are skipped
func ParsePorts(list []string) []PortRange {
	out := make([]PortRange, 0, len(list))
	for _, e := range list {
		if p, err := ParsePort(e); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Dest is an allowed backend entry in parsed form
type Dest struct {
	Prefix netip.Prefix
	Ports  []PortRange // empty = any port
}

// Matches tells whether addr:port is covered (port 0 = any port)
func (d Dest) Matches(addr netip.Addr, port int) bool {
	if !d.Prefix.Contains(addr.Unmap()) {
		return false
	}
	if port <= 0 || len(d.Ports) == 0 {
		return true
	}
	for _, p := range d.Ports {
		if p.Contains(port) {
			return true
		}
	}
	return false
}

// ParseDests reads allowed backend entries with the same parser as the Network exposure list
func ParseDests(list []string) []Dest {
	out := make([]Dest, 0, len(list))
	for _, e := range list {
		pfx, ports, err := destguard.EntryParts(e)
		if err != nil {
			continue
		}
		d := Dest{Prefix: pfx}
		for _, p := range ports {
			d.Ports = append(d.Ports, PortRange{p[0], p[1]})
		}
		out = append(out, d)
	}
	return out
}

func cleanList(what string, in []string, parse func(string) (string, error)) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		c, err := parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) > MaxEntries {
			return nil, fmt.Errorf("%s: at most %d entries", what, MaxEntries)
		}
	}
	return out, nil
}

func prefixString(raw string) (string, error) {
	p, err := ParsePrefix(raw)
	if err != nil {
		return "", err
	}
	if p.IsSingleIP() {
		return p.Addr().String(), nil
	}
	return p.String(), nil
}

func cleanZone(label string, z Zone) (Zone, error) {
	z.Name = strings.TrimSpace(z.Name)
	if len(z.Name) > MaxNameLen {
		return z, fmt.Errorf("%s: the name is longer than %d characters", label, MaxNameLen)
	}
	//Names go into the exported recommendations and the page: letters, digits, space and . _ - ( ) only,
	//so a name can never carry markup, a table break, a code fence or a shell command
	if z.Name != "" && !nameRe.MatchString(z.Name) {
		return z, fmt.Errorf("%s: the name may only contain letters, digits, spaces and . _ - ( )", label)
	}
	c, err := cleanList(label, z.CIDRs, prefixString)
	if err != nil {
		return z, err
	}
	z.CIDRs = c
	return z, nil
}

// Normalize validates and canonicalises a plan: trimmed, deduplicated, networks masked, bounded. It never
// returns a plan with a nil list.
func Normalize(s Settings) (Settings, error) {
	var err error
	if s.ProxyVLAN, err = cleanZone("Proxy VLAN", s.ProxyVLAN); err != nil {
		return s, err
	}
	if s.ManagementVLAN, err = cleanZone("Management VLAN", s.ManagementVLAN); err != nil {
		return s, err
	}
	if s.ApplicationVLAN, err = cleanZone("Application VLAN", s.ApplicationVLAN); err != nil {
		return s, err
	}
	if s.TrustedProxies, err = cleanList("Trusted upstream proxies", s.TrustedProxies, prefixString); err != nil {
		return s, err
	}
	if s.AdminAccess, err = cleanList("Administrative access", s.AdminAccess, prefixString); err != nil {
		return s, err
	}
	if s.AllowedBackends, err = cleanList("Allowed backend destinations", s.AllowedBackends, func(raw string) (string, error) {
		if len(raw) > maxEntry {
			return "", errors.New("entry too long")
		}
		//the canonical form is rebuilt from the parsed address and ports, never the raw text: an IPv6 zone suffix
		//("fe80::1%<anything>") is accepted by the parser and must not travel into the exported plan
		pfx, ports, err := destguard.EntryParts(raw)
		if err != nil {
			return "", err
		}
		out := pfx.String()
		if pfx.IsSingleIP() {
			out = pfx.Addr().String()
		}
		if len(ports) > 0 {
			parts := make([]string, 0, len(ports))
			for _, p := range ports {
				if p[0] == p[1] {
					parts = append(parts, strconv.Itoa(p[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%d-%d", p[0], p[1]))
				}
			}
			out += " " + strings.Join(parts, ",")
		}
		return out, nil
	}); err != nil {
		return s, err
	}
	if s.AppPorts, err = cleanList("Application ports", s.AppPorts, func(raw string) (string, error) {
		p, err := ParsePort(raw)
		if err != nil {
			return "", err
		}
		if p.Lo == p.Hi {
			return strconv.Itoa(p.Lo), nil
		}
		return fmt.Sprintf("%d-%d", p.Lo, p.Hi), nil
	}); err != nil {
		return s, err
	}
	return s, nil
}

// KV is the part of the sys.db API the manager needs (database.Database satisfies it)
type KV interface {
	Read(table, key string, assignee interface{}) error
	Write(table, key string, value interface{}) error
}

// Manager keeps the plan. Reads are lock free.
type Manager struct {
	kv  KV
	cur atomic.Pointer[Settings]
	// OnChange, if set, is called after a successful Set with the old and the new plan
	OnChange func(old, next Settings)
}

// New loads the plan from kv (nil kv: in memory only). A stored plan that no longer validates is ignored
// (no plan) and the error says so.
func New(kv KV) (*Manager, error) {
	m := &Manager{kv: kv}
	empty := Settings{}
	m.cur.Store(&empty)
	if kv == nil {
		return m, nil
	}
	var stored Settings
	if err := kv.Read(DBTable, DBKey, &stored); err != nil {
		return m, nil
	}
	n, err := Normalize(stored)
	if err != nil {
		return m, fmt.Errorf("stored network plan ignored: %w", err)
	}
	m.cur.Store(&n)
	return m, nil
}

// Settings returns a copy of the plan (lists are never nil)
func (m *Manager) Settings() Settings {
	if m == nil {
		return fill(Settings{})
	}
	return fill(*m.cur.Load())
}

func fill(s Settings) Settings {
	cp := func(in []string) []string { return append([]string{}, in...) }
	s.ProxyVLAN.CIDRs, s.ManagementVLAN.CIDRs, s.ApplicationVLAN.CIDRs = cp(s.ProxyVLAN.CIDRs), cp(s.ManagementVLAN.CIDRs), cp(s.ApplicationVLAN.CIDRs)
	s.TrustedProxies, s.AllowedBackends, s.AppPorts, s.AdminAccess = cp(s.TrustedProxies), cp(s.AllowedBackends), cp(s.AppPorts), cp(s.AdminAccess)
	return s
}

// Declared reports whether a plan is saved
func (m *Manager) Declared() bool { return m != nil && m.cur.Load().Declared() }

// Set validates, persists and applies a plan. Nothing changes when it fails.
func (m *Manager) Set(next Settings) error {
	n, err := Normalize(next)
	if err != nil {
		return err
	}
	old := m.Settings()
	if m.kv != nil {
		if err := m.kv.Write(DBTable, DBKey, n); err != nil {
			return fmt.Errorf("could not save: %w", err)
		}
	}
	m.cur.Store(&n)
	if m.OnChange != nil {
		m.OnChange(old, fill(n))
	}
	return nil
}
