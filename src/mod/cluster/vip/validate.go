package vip

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	reIface    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	rePassword = regexp.MustCompile(`^[A-Za-z0-9._~+-]{1,8}$`)
	reLabel    = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,32}$`)
)

// FieldError names the field that failed, for the UI.
type FieldError struct {
	Field string `json:"field"`
	Msg   string `json:"message"`
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func fe(field, format string, a ...any) error {
	return &FieldError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// ParseShared decodes a settings document strictly: size limit, typed fields,
// unknown fields refused, trailing data refused. Fields that are absent keep
// the values of def.
func ParseShared(raw []byte, def Shared) (Shared, error) {
	if len(raw) > MaxConfigBytes {
		return Shared{}, errors.New("settings document is larger than 16 KiB")
	}
	s := def
	s.Members = nil
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Shared{}, fmt.Errorf("invalid settings document: %w", err)
	}
	if dec.More() {
		return Shared{}, errors.New("invalid settings document: trailing data")
	}
	return s, nil
}

// ParseLocal decodes the node-local overrides strictly.
func ParseLocal(raw []byte) (Local, error) {
	if len(raw) > MaxConfigBytes {
		return Local{}, errors.New("settings document is larger than 16 KiB")
	}
	var l Local
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Local{}, fmt.Errorf("invalid settings document: %w", err)
	}
	if dec.More() {
		return Local{}, errors.New("invalid settings document: trailing data")
	}
	return l, nil
}

// ParseAddr is the strict address rule of section 2.1: a plain IP, no zone,
// not unspecified, loopback, multicast, link-local or IPv4-mapped.
func ParseAddr(field, s string) (netip.Addr, error) {
	if s != strings.TrimSpace(s) || s == "" {
		return netip.Addr{}, fe(field, "enter an IP address without spaces")
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fe(field, "not a valid IP address")
	}
	switch {
	case a.Zone() != "":
		return netip.Addr{}, fe(field, "a zone (%%) is not allowed")
	case a.Is4In6():
		return netip.Addr{}, fe(field, "an IPv4-mapped IPv6 address is not allowed")
	case a.IsUnspecified():
		return netip.Addr{}, fe(field, "the unspecified address is not allowed")
	case a.IsLoopback():
		return netip.Addr{}, fe(field, "a loopback address is not allowed")
	case a.IsMulticast():
		return netip.Addr{}, fe(field, "a multicast address is not allowed")
	case a.IsLinkLocalUnicast():
		return netip.Addr{}, fe(field, "a link-local address is not allowed")
	}
	return a, nil
}

// broadcastOf returns the broadcast address of a v4 prefix.
func broadcastOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	if host > 0 {
		v |= (1 << uint(host)) - 1
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func checkInt(field string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fe(field, "must be %d to %d", lo, hi)
	}
	return nil
}

// ValidInterfaceName reports whether s is an acceptable interface name.
func ValidInterfaceName(s string) bool {
	return reIface.MatchString(s) && s != "." && s != ".."
}

// ValidatePassword checks a VRRP PASS password (never truncates).
func ValidatePassword(p string) error {
	if !rePassword.MatchString(p) {
		return fe("password", "1 to 8 characters from A-Z a-z 0-9 . _ ~ + - (keepalived only uses the first 8)")
	}
	return nil
}

// ValidateShared checks every rule of section 2.1. A disabled configuration
// may be incomplete (no VIP or members yet), but whatever is present has to
// be valid. An enabled one has to be complete.
func ValidateShared(s *Shared) error {
	if s.Transport != TransportUnicast && s.Transport != TransportMulticast {
		return fe("transport", "must be unicast or multicast")
	}
	switch s.Auth {
	case AuthCluster, AuthPassword, AuthNone:
	default:
		return fe("auth", "must be cluster, password or none")
	}
	if err := checkInt("vrid", s.VRID, 1, 255); err != nil {
		return err
	}
	if err := checkInt("advertInt", s.AdvertInt, 1, 10); err != nil {
		return err
	}
	if err := checkInt("preemptDelay", s.PreemptDelay, 0, 1000); err != nil {
		return err
	}
	if err := checkInt("garpRefresh", s.GarpRefresh, 0, 3600); err != nil {
		return err
	}
	h := s.Health
	if err := checkInt("health.interval", h.Interval, 1, 60); err != nil {
		return err
	}
	if err := checkInt("health.timeout", h.Timeout, 1, 60); err != nil {
		return err
	}
	if err := checkInt("health.fall", h.Fall, 1, 10); err != nil {
		return err
	}
	if err := checkInt("health.rise", h.Rise, 1, 10); err != nil {
		return err
	}
	if h.Timeout <= CurlMaxTime(h.Timeout) {
		return fe("health.timeout", "must be 2 to 60 (it has to be longer than the probe time limit)")
	}
	if s.Password != "" {
		if err := ValidatePassword(s.Password); err != nil {
			return err
		}
	}
	if s.ClusterPass != "" {
		if err := ValidatePassword(s.ClusterPass); err != nil {
			return fe("clusterPass", "the generated password is not valid; rotate it")
		}
	}
	if s.Enabled && s.Auth == AuthPassword && s.Password == "" {
		return fe("password", "enter a password (1 to 8 characters) or choose another authentication mode")
	}
	if len(s.Members) > 8 {
		return fe("members", "at most 8 members")
	}
	if s.Enabled {
		if s.VIP == "" {
			return fe("vip", "enter the floating IP")
		}
		if len(s.Members) < 2 {
			return fe("members", "enter at least 2 members")
		}
	}
	if s.VIP == "" && len(s.Members) == 0 {
		return nil
	}
	if s.VIP == "" {
		return fe("vip", "enter the floating IP")
	}
	vip, err := ParseAddr("vip", s.VIP)
	if err != nil {
		return err
	}
	if s.VIP != vip.String() {
		return fe("vip", "write the address in its canonical form (%s)", vip.String())
	}
	max := 32
	if vip.Is6() {
		max = 128
	}
	if s.Prefix < 1 || s.Prefix > max {
		return fe("prefix", "must be 1 to %d", max)
	}
	if vip.Is4() && s.Prefix > 30 {
		return fe("prefix", "a /31 or /32 network has no room for two nodes and a floating IP (use /30 or larger)")
	}
	pfx := netip.PrefixFrom(vip, s.Prefix)
	if vip.Is4() {
		if pfx.Masked().Addr() == vip {
			return fe("vip", "this is the network address of the subnet")
		}
		if broadcastOf(pfx) == vip {
			return fe("vip", "this is the broadcast address of the subnet")
		}
	}
	addrs := map[netip.Addr]bool{}
	prios := map[int]bool{}
	for i, m := range s.Members {
		f := fmt.Sprintf("members[%d]", i)
		if !reLabel.MatchString(m.Label) {
			return fe(f+".label", "1 to 32 characters from A-Z a-z 0-9 space . _ -")
		}
		a, err := ParseAddr(f+".address", m.Address)
		if err != nil {
			return err
		}
		if m.Address != a.String() {
			return fe(f+".address", "write the address in its canonical form (%s)", a.String())
		}
		if a.Is4() != vip.Is4() {
			return fe(f+".address", "must be the same address family as the floating IP")
		}
		if a == vip {
			return fe(f+".address", "a member cannot use the floating IP as its own address")
		}
		if !pfx.Contains(a) {
			return fe(f+".address", "is not inside %s", pfx.Masked())
		}
		if a.Is4() {
			if pfx.Masked().Addr() == a {
				return fe(f+".address", "this is the network address of the subnet")
			}
			if broadcastOf(pfx) == a {
				return fe(f+".address", "this is the broadcast address of the subnet")
			}
		}
		if addrs[a] {
			return fe(f+".address", "duplicate member address")
		}
		addrs[a] = true
		if m.Priority < 1 || m.Priority > 254 {
			return fe(f+".priority", "must be 1 to 254 (255 is reserved)")
		}
		if prios[m.Priority] {
			return fe(f+".priority", "each member needs a different priority")
		}
		prios[m.Priority] = true
		if m.InterfaceHint != "" && !ValidInterfaceName(m.InterfaceHint) {
			return fe(f+".interfaceHint", "not a valid interface name")
		}
	}
	return nil
}

// CurlMaxTime is the --max-time given to the probe: timeout-1, at least 1.
func CurlMaxTime(timeout int) int {
	if timeout-1 < 1 {
		return 1
	}
	return timeout - 1
}

// ValidateLocal checks the node-local overrides against the shared members.
func ValidateLocal(l *Local, s *Shared) error {
	if l.Interface != "" && !ValidInterfaceName(l.Interface) {
		return fe("interface", "not a valid interface name")
	}
	if l.PriorityOverride != 0 {
		if err := checkInt("priorityOverride", l.PriorityOverride, 1, 254); err != nil {
			return err
		}
	}
	if l.SourceAddress != "" {
		a, err := ParseAddr("sourceAddress", l.SourceAddress)
		if err != nil {
			return err
		}
		if l.SourceAddress != a.String() {
			return fe("sourceAddress", "write the address in its canonical form (%s)", a.String())
		}
		if s != nil && len(s.Members) > 0 {
			found := false
			for _, m := range s.Members {
				if m.Address == l.SourceAddress {
					found = true
				}
			}
			if !found {
				return fe("sourceAddress", "must be the address of one of the members")
			}
		}
	}
	if _, _, err := ParseHealthTarget(l.HealthTarget); err != nil {
		return err
	}
	return nil
}

// ParseHealthTarget validates a healthTarget override. auto is ("", false).
// Otherwise it returns the scheme and the host:port part (loopback only).
func ParseHealthTarget(t string) (base string, custom bool, err error) {
	if t == "" || t == "auto" {
		return "", false, nil
	}
	u, perr := url.Parse(t)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false, fe("healthTarget", "use auto, or http(s)://127.0.0.1:port or http(s)://[::1]:port")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", false, fe("healthTarget", "no path, user, query or fragment allowed")
	}
	h := u.Hostname()
	if h != "127.0.0.1" && h != "::1" {
		return "", false, fe("healthTarget", "the host must be 127.0.0.1 or [::1]")
	}
	ps := u.Port()
	if ps == "" || len(ps) > 5 {
		return "", false, fe("healthTarget", "a port is required")
	}
	for _, c := range ps {
		if c < '0' || c > '9' {
			return "", false, fe("healthTarget", "invalid port")
		}
	}
	p, _ := strconv.Atoi(ps)
	if p < 1 || p > 65535 {
		return "", false, fe("healthTarget", "port must be 1 to 65535")
	}
	host := "127.0.0.1"
	if h == "::1" {
		host = "[::1]"
	}
	return u.Scheme + "://" + host + ":" + strconv.Itoa(p), true, nil
}
