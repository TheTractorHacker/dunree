package destguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// DBTable and DBKey are where the settings live (sys.db, table "settings")
	DBTable = "settings"
	DBKey   = "destguard"

	maxAllowedEntries = 256
)

// Settings is the persisted configuration. The zero value is today's behaviour: nothing is restricted.
type Settings struct {
	//RestrictTools makes the diagnostic tools (upstream test, port and IP scan, uptime checks, web SSH,
	//forward proxy) refuse loopback, link-local, cloud metadata, multicast and unspecified addresses and,
	//when AllowedBackends is not empty, everything outside that list.
	RestrictTools bool `json:"restrictTools"`

	//AllowedBackends are the destinations the admin approves: "10.0.0.0/8", "10.1.2.3", "10.0.0.0/24 443,8000-8100"
	//(CIDR or address, optionally followed by a space and ports), "10.1.2.3:443" and "[fd00::5]:443" also work.
	//When not empty, a proxy rule upstream must match an entry (checked when the rule is saved, independent
	//of RestrictTools), and with RestrictTools the tools may only reach matching addresses.
	//Empty = no restriction (today).
	AllowedBackends []string `json:"allowedBackends"`
}

type portRange struct{ lo, hi int }

type rule struct {
	prefix netip.Prefix
	ports  []portRange //empty = any port
}

func (r rule) matches(ip netip.Addr, port int) bool {
	if !r.prefix.Contains(ip) {
		return false
	}
	if port <= 0 || len(r.ports) == 0 { //port 0 = "any port" (ping, address-only checks)
		return true
	}
	for _, p := range r.ports {
		if port >= p.lo && port <= p.hi {
			return true
		}
	}
	return false
}

type state struct {
	s     Settings
	rules []rule
}

// KV is the part of the sys.db API the guard needs (database.Database satisfies it)
type KV interface {
	Read(table, key string, assignee interface{}) error
	Write(table, key string, value interface{}) error
}

// Guard holds the settings and does the checks. A nil *Guard restricts nothing. Reads are lock free.
type Guard struct {
	kv  KV
	cur atomic.Pointer[state]

	// Resolver looks a host name up (replaced in tests)
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
	// OnChange, if set, is called after a successful Set with the old and new settings
	OnChange func(old, next Settings)
}

// New loads the settings from kv (nil kv: in memory only). A stored value that no longer validates
// is ignored (nothing restricted) and the error says so.
func New(kv KV) (*Guard, error) {
	g := &Guard{kv: kv}
	g.cur.Store(&state{})
	if kv == nil {
		return g, nil
	}
	var stored Settings
	if err := kv.Read(DBTable, DBKey, &stored); err != nil {
		return g, nil
	}
	st, err := build(stored)
	if err != nil {
		return g, fmt.Errorf("stored destination guard settings ignored, nothing restricted: %w", err)
	}
	g.cur.Store(st)
	return g, nil
}

func build(s Settings) (*state, error) {
	if len(s.AllowedBackends) > maxAllowedEntries {
		return nil, fmt.Errorf("at most %d allowed backend entries", maxAllowedEntries)
	}
	var rules []rule
	clean := make([]string, 0, len(s.AllowedBackends))
	seen := map[string]bool{}
	for _, raw := range s.AllowedBackends {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		r, err := parseRule(raw)
		if err != nil {
			return nil, err
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		clean = append(clean, raw)
		rules = append(rules, r)
	}
	s.AllowedBackends = clean
	return &state{s: s, rules: rules}, nil
}

// ParseEntry validates one allowed backend entry
func ParseEntry(raw string) error {
	_, err := parseRule(strings.TrimSpace(raw))
	return err
}

// EntryParts validates one allowed backend entry and returns what it means: the address range and the
// permitted port ranges ([lo, hi] pairs, empty = any port). Used by the network plan (mod/netplan) so both
// features read the same entry syntax from this one parser.
func EntryParts(raw string) (netip.Prefix, [][2]int, error) {
	r, err := parseRule(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, nil, err
	}
	ports := make([][2]int, 0, len(r.ports))
	for _, p := range r.ports {
		ports = append(ports, [2]int{p.lo, p.hi})
	}
	return r.prefix, ports, nil
}

func parseRule(raw string) (rule, error) {
	bad := func(why string) (rule, error) { return rule{}, fmt.Errorf("%q: %s", raw, why) }
	addrPart, portPart := raw, ""
	if i := strings.IndexAny(raw, " \t"); i >= 0 {
		addrPart, portPart = raw[:i], strings.TrimSpace(raw[i:])
	}
	var r rule
	switch {
	case strings.Contains(addrPart, "/"):
		p, err := netip.ParsePrefix(addrPart)
		if err != nil {
			return bad("not a valid CIDR")
		}
		r.prefix = p.Masked()
	default:
		if ip, err := netip.ParseAddr(addrPart); err == nil {
			ip = ip.WithZone("").Unmap()
			r.prefix = netip.PrefixFrom(ip, ip.BitLen())
		} else if ap, err := netip.ParseAddrPort(addrPart); err == nil && portPart == "" {
			ip := ap.Addr().WithZone("").Unmap()
			r.prefix = netip.PrefixFrom(ip, ip.BitLen())
			r.ports = []portRange{{int(ap.Port()), int(ap.Port())}}
			return r, nil
		} else {
			return bad("not an IP address or CIDR (host names are not accepted, they can change)")
		}
	}
	if r.prefix.Addr().Is4In6() {
		return bad("write IPv4 addresses in plain form")
	}
	if r.prefix.Bits() == 0 {
		return bad("matches every address, that would make the list meaningless")
	}
	if portPart != "" {
		for _, tok := range strings.Split(portPart, ",") {
			tok = strings.TrimSpace(tok)
			lo, hi := 0, 0
			var e1, e2 error
			if a, b, ok := strings.Cut(tok, "-"); ok {
				lo, e1 = strconv.Atoi(strings.TrimSpace(a))
				hi, e2 = strconv.Atoi(strings.TrimSpace(b))
			} else {
				lo, e1 = strconv.Atoi(tok)
				hi = lo
			}
			if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return bad("ports must be numbers 1-65535 or ranges like 8000-8100, separated by commas")
			}
			r.ports = append(r.ports, portRange{lo, hi})
		}
	}
	return r, nil
}

func (g *Guard) load() *state {
	if g == nil {
		return &state{}
	}
	return g.cur.Load()
}

// Settings returns a copy of the current settings
func (g *Guard) Settings() Settings {
	s := g.load().s
	s.AllowedBackends = append([]string{}, s.AllowedBackends...)
	return s
}

// Restricting reports whether the diagnostic tools are restricted
func (g *Guard) Restricting() bool { return g != nil && g.load().s.RestrictTools }

// HasAllowList reports whether an allowed backend list is configured
func (g *Guard) HasAllowList() bool { return len(g.load().rules) > 0 }

// Set validates, persists and applies new settings. Nothing changes when it fails.
func (g *Guard) Set(next Settings) error {
	old := g.Settings()
	st, err := build(next)
	if err != nil {
		return err
	}
	if g.kv != nil {
		if err := g.kv.Write(DBTable, DBKey, st.s); err != nil {
			return fmt.Errorf("could not save: %w", err)
		}
	}
	g.cur.Store(st)
	if g.OnChange != nil {
		g.OnChange(old, st.s)
	}
	return nil
}

// JSON is the API representation (never a null list)
func (s Settings) JSON() []byte {
	if s.AllowedBackends == nil {
		s.AllowedBackends = []string{}
	}
	b, _ := json.Marshal(s)
	return b
}

func (st *state) listed(ip netip.Addr, port int) bool {
	for _, r := range st.rules {
		if r.matches(ip, port) {
			return true
		}
	}
	return false
}

func norm(ip netip.Addr) netip.Addr { return ip.WithZone("").Unmap() }

// listedAny matches a transition form (NAT64, 6to4...) by the address it carries as well as by its own text
func (st *state) listedAny(ip netip.Addr, port int) bool {
	ip = ip.WithZone("")
	if st.listed(norm(ip), port) {
		return true
	}
	if ip.Is6() {
		if emb, refuse, ok := embeddedIPv4(norm(ip)); ok && !refuse {
			return st.listed(emb, port)
		}
	}
	return false
}

// CheckDest is the decision for a diagnostic tool dialing ip:port (port 0 = any port). It does nothing when
// the tools are not restricted. Always refused: metadata, link-local, multicast, unspecified, reserved, and
// transition forms carrying them. Loopback needs an explicit allowed backend entry. With an allowed backend
// list, everything else must match it too; without one, private and public addresses pass.
func (g *Guard) CheckDest(ip netip.Addr, port int) error {
	if !g.Restricting() {
		return nil
	}
	return g.check(ip, port, true)
}

// CheckBackend is the decision for a proxy rule upstream: it only applies when an allowed backend list is
// configured (empty list = no restriction = today), independent of RestrictTools.
func (g *Guard) CheckBackend(ip netip.Addr, port int) error {
	if !g.HasAllowList() {
		return nil
	}
	return g.check(ip, port, false)
}

func (g *Guard) check(ip netip.Addr, port int, tool bool) error {
	st := g.load()
	cls, err := Classify(ip)
	if err != nil {
		return err
	}
	listed := st.listedAny(ip, port)
	if tool && cls == ClassLoopback && !listed {
		return errors.New("loopback addresses are refused by the destination restriction (list the address under allowed backends to permit it)")
	}
	if len(st.rules) > 0 && !listed {
		if port > 0 {
			return fmt.Errorf("%s port %d is not in the allowed backend destinations", norm(ip), port)
		}
		return fmt.Errorf("%s is not in the allowed backend destinations", norm(ip))
	}
	return nil
}

func (g *Guard) resolver() func(context.Context, string) ([]netip.Addr, error) {
	if g != nil && g.Resolver != nil {
		return g.Resolver
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
}

// Resolve turns host (IP literal or name) into addresses by resolving once, and checks every one of them
// (a mixed answer cannot be used to slip through). tool selects CheckDest (true) or CheckBackend (false) rules.
// The returned addresses are the checked ones: dial them, do not resolve the name again.
func (g *Guard) Resolve(ctx context.Context, host string, port int, tool bool) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		var lerr error
		if ips, lerr = g.resolver()(ctx, host); lerr != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", host, lerr)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%q has no address", host)
	}
	for _, ip := range ips {
		if err := g.check(ip, port, tool); err != nil {
			return nil, err
		}
	}
	return ips, nil
}

// ValidateBackend checks a proxy rule upstream (host or host:port, optional scheme and path) against the allowed
// backend list: a no-op without a list. Names are resolved now and every address must match, so a name that
// later resolves elsewhere is not covered (see the known limits in docs/ux/changes.md).
func (g *Guard) ValidateBackend(ctx context.Context, target string) error {
	return g.ValidateBackendTLS(ctx, target, false)
}

// ValidateBackendTLS is ValidateBackend for an upstream that is written without a port: the port the proxy will
// really dial (443 with TLS, 80 without, or the one the scheme names) is matched, never "any port".
func (g *Guard) ValidateBackendTLS(ctx context.Context, target string, requireTLS bool) error {
	if !g.HasAllowList() {
		return nil
	}
	host, port, ok := SplitTarget(target)
	if !ok {
		return fmt.Errorf("cannot read the upstream address %q", target)
	}
	if host == "" { //unix socket: a local file, not a network destination
		return nil
	}
	port = EffectivePort(port, requireTLS)
	_, err := g.Resolve(ctx, host, port, false)
	return err
}

// EffectivePort is the port an upstream is really dialled on: the written one, else the default of the
// protocol (443 with TLS, 80 without). A port of 0 would match every port of an allowed address.
func EffectivePort(port int, requireTLS bool) int {
	if port > 0 {
		return port
	}
	if requireTLS {
		return 443
	}
	return 80
}

// SplitTarget extracts host and port from an upstream string such as "10.0.0.5:8080", "https://app.lan/x",
// "[fd00::1]:443". The port is 0 when it is not given and the scheme does not tell. A unix: socket gives
// host "" and ok true.
func SplitTarget(target string) (host string, port int, ok bool) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(strings.ToLower(t), "unix:") {
		return "", 0, true
	}
	defPort := 0
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "https://"):
		t, defPort = t[len("https://"):], 443
	case strings.HasPrefix(lower, "http://"):
		t, defPort = t[len("http://"):], 80
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	if t == "" {
		return "", 0, false
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 0 || n > 65535 || h == "" {
			return "", 0, false
		}
		return h, n, true
	}
	return strings.Trim(t, "[]"), defPort, true
}

// DialContext dials addr ("host:port") the way the guard allows. Not restricting: a plain dial, exactly as before.
// Restricting: the name is resolved once, every answer is checked, and a checked address is dialed, so a DNS
// answer that changes between the check and the dial (rebinding) is not used.
func (g *Guard) DialContext(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	if !g.Restricting() {
		return d.DialContext(ctx, network, addr)
	}
	if strings.HasPrefix(network, "unix") {
		return nil, errors.New("unix sockets are refused by the destination restriction")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, err
	}
	ips, err := g.Resolve(ctx, host, port, true)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		c, derr := d.DialContext(ctx, network, net.JoinHostPort(norm(ip).String(), strconv.Itoa(port)))
		if derr == nil {
			return c, nil
		}
		last = derr
	}
	return nil, last
}

/* Package level entry points used by the tools. Default is set by the main package at start up. */

var def atomic.Pointer[Guard]

// SetDefault installs the guard the package level functions use
func SetDefault(g *Guard) { def.Store(g) }

// Default returns the installed guard (nil when none)
func Default() *Guard { return def.Load() }

// Restricting reports whether the default guard restricts the diagnostic tools
func Restricting() bool { return def.Load().Restricting() }

// CheckDest checks ip:port against the default guard (nil error when not restricting)
func CheckDest(ip netip.Addr, port int) error { return def.Load().CheckDest(ip, port) }

// DialTimeout is net.DialTimeout through the default guard; without restriction it is net.DialTimeout.
func DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	g := def.Load()
	if !g.Restricting() {
		return net.DialTimeout(network, addr, timeout)
	}
	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	return g.DialContext(ctx, &net.Dialer{Timeout: timeout}, network, addr)
}

// DialContext is a plain context dial through the default guard
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return def.Load().DialContext(ctx, nil, network, addr)
}
