package vip

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Check is one pre-flight result.
type Check struct {
	ID      string `json:"id"`
	Level   string `json:"level"` // ok, warn, block, info
	Message string `json:"message"`
}

// PreflightEnv holds the side effects of the checks, injectable for tests.
// Every probe goes only to the VIP and the peers the admin typed.
type PreflightEnv struct {
	Lister InterfaceLister
	Paths  Paths
	// HTTPGet returns the HTTP status of a GET (0 with an error on a network failure).
	HTTPGet func(url string) (int, error)
	// Dial tries a TCP connection and reports whether it connected, and whether
	// the host actively refused (which also proves a host answers).
	Dial func(addr string, timeout time.Duration) (connected bool, refused bool)
	// OldFollowers names followers that may be too old for the ha root.
	OldFollowers []string
	// NetplanOutside is set by the caller when a Network plan exists and the VIP lies outside it.
	NetplanOutside bool
	// HeldBy names a member known to hold the VIP right now ("" = none).
	HeldBy string
}

// RealDial dials a TCP address.
func RealDial(addr string, timeout time.Duration) (bool, bool) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		c.Close()
		return true, false
	}
	return false, strings.Contains(err.Error(), "refused")
}

func ck(id, level, format string, a ...any) Check {
	return Check{ID: id, Level: level, Message: fmt.Sprintf(format, a...)}
}

// Preflight runs the checks of section 5. It does not change anything.
func Preflight(s *Shared, l *Local, env *Env, pe *PreflightEnv) []Check {
	var out []Check
	add := func(c Check) { out = append(out, c) }
	if l == nil {
		l = &Local{}
	}
	if err := ValidateShared(s); err != nil {
		add(ck("settings", "block", "%s", err.Error()))
		return out
	}
	if err := ValidateLocal(l, s); err != nil {
		add(ck("local", "block", "%s", err.Error()))
	}
	if s.VIP == "" || len(s.Members) < 2 {
		add(ck("settings", "block", "Enter the floating IP and at least two members."))
		return out
	}
	add(ck("settings", "ok", "The settings are valid."))
	vip := netip.MustParseAddr(s.VIP)
	ifs, err := pe.Lister.Interfaces()
	if err != nil {
		add(ck("interfaces", "warn", "Cannot list the network interfaces of this host."))
	}
	pfx := netip.PrefixFrom(vip, s.Prefix)
	self, serr := Resolve(s, l, ifs)
	held := false
	for _, in := range ifs {
		for _, a := range in.Addrs {
			if a.Addr() == vip {
				held = true
			}
		}
	}
	// VIP versus members and this host's own addresses
	for _, m := range s.Members {
		if m.Address == s.VIP {
			add(ck("vip-distinct", "block", "The floating IP is the same as the address of %s.", m.Label))
		}
	}
	if !held {
		add(ck("vip-distinct", "ok", "The floating IP differs from every member address."))
	} else {
		add(ck("vip-distinct", "ok", "This host currently holds the floating IP (expected on the active node)."))
	}
	if serr != nil {
		add(ck("member", "block", "%s", serr.Error()))
	} else {
		add(ck("member", "ok", "This node is %s (%s).", s.Members[self.Index].Label, self.Source))
		if self.Prefix != 0 && self.Prefix != s.Prefix {
			add(ck("prefix", "warn", "The prefix /%d differs from the prefix /%d configured on %s.", s.Prefix, self.Prefix, self.Interface))
		}
		var found *IfaceInfo
		for i := range ifs {
			if ifs[i].Name == self.Interface {
				found = &ifs[i]
			}
		}
		switch {
		case found == nil:
			add(ck("interface", "block", "The interface %s does not exist on this host.", self.Interface))
		case !found.Up:
			add(ck("interface", "warn", "The interface %s is down.", self.Interface))
		default:
			add(ck("interface", "ok", "The interface %s exists and is up.", self.Interface))
		}
		if !pfx.Contains(netip.MustParseAddr(self.Source)) {
			add(ck("subnet", "block", "The floating IP and the member addresses are not in the same subnet."))
		} else {
			add(ck("subnet", "ok", "The floating IP and the members share %s.", pfx.Masked()))
		}
		if s.Members[self.Index].Priority != self.Priority {
			add(ck("priority", "warn", "A node-local priority override (%d) is in effect.", self.Priority))
		}
	}
	// health target
	pr, blockers, perr := ProbeTarget(s, l, env)
	for _, b := range blockers {
		add(ck("health-config", "block", "%s", b))
	}
	if perr != nil {
		add(ck("health-config", "block", "%s", perr.Error()))
	}
	if pr.Base != "" && len(blockers) == 0 && pe.HTTPGet != nil {
		code, herr := pe.HTTPGet(pr.Base + HealthPath)
		switch {
		case herr != nil:
			add(ck("health", "block", "The health probe %s%s failed: %s", pr.Base, HealthPath, herr.Error()))
		case code == 200:
			add(ck("health", "ok", "The health probe answers 200."))
		case code == 503:
			add(ck("health", "warn", "The health probe answers 503: the proxy is stopped."))
		default:
			add(ck("health", "block", "The health probe answers HTTP %d, keepalived would treat this node as failed.", code))
		}
	}
	// VIP in use (best effort)
	switch {
	case held:
		add(ck("vip-free", "info", "Skipped: this host holds the floating IP."))
	case pe.HeldBy != "":
		add(ck("vip-free", "info", "Skipped: held by %s.", pe.HeldBy))
	default:
		if used, why := vipInUse(vip, pe); used {
			add(ck("vip-free", "warn", "Another host may already use the floating IP (%s). This check is best effort.", why))
		} else {
			add(ck("vip-free", "ok", "No other host answered on the floating IP (best effort, it cannot prove the address is free)."))
		}
	}
	// peers
	if pe.Dial != nil && pr.Base != "" {
		port := portOf(pr.Base)
		for _, m := range s.Members {
			if serr == nil && m.Address == self.Source {
				continue
			}
			if c, _ := pe.Dial(net.JoinHostPort(m.Address, port), time.Second); c {
				add(ck("peer-"+m.Label, "ok", "%s answers on port %s. VRRP itself (protocol 112) cannot be tested without raw sockets.", m.Label, port))
			} else {
				add(ck("peer-"+m.Label, "warn", "%s does not answer on port %s. VRRP itself (protocol 112) cannot be tested without raw sockets.", m.Label, port))
			}
		}
	}
	if s.Auth == AuthCluster && s.ClusterPass == "" {
		add(ck("auth", "block", "Authentication uses the cluster password, but none has been generated yet. Save the Floating IP settings on the primary."))
	}
	if s.Auth == AuthNone || s.Auth == AuthPassword {
		add(ck("auth", "info", "VRRP password authentication is not security: anyone on the VLAN can take the floating IP."))
	}
	if len(pe.OldFollowers) > 0 {
		add(ck("old-followers", "warn", "These followers may refuse a snapshot that carries the ha root until they are updated: %s.", strings.Join(pe.OldFollowers, ", ")))
	}
	if pe.NetplanOutside {
		add(ck("netplan", "warn", "The floating IP is outside the proxy network in the Network plan."))
	}
	if pe.Paths.KeepalivedBins != nil {
		st := ReadStatus(s, l, pe.Lister, pe.Paths, env)
		if st.KeepalivedFound == No {
			add(ck("keepalived", "info", "keepalived is not installed on this host. The install commands are in the next step."))
		}
	}
	return out
}

func portOf(base string) string {
	i := strings.LastIndex(base, ":")
	if i < 0 {
		return "80"
	}
	p := base[i+1:]
	if _, err := strconv.Atoi(p); err != nil {
		return "80"
	}
	return p
}

// vipInUse looks at the ARP table and tries a few TCP ports.
func vipInUse(vip netip.Addr, pe *PreflightEnv) (bool, string) {
	if pe.Paths.ARPFile != "" {
		if b, err := os.ReadFile(pe.Paths.ARPFile); err == nil {
			for _, line := range strings.Split(string(b), "\n")[min(1, len(strings.Split(string(b), "\n"))):] {
				f := strings.Fields(line)
				if len(f) >= 4 && f[0] == vip.String() && f[2] == "0x2" && f[3] != "00:00:00:00:00:00" {
					return true, "ARP entry " + f[3]
				}
			}
		}
	}
	if pe.Dial != nil {
		for _, port := range []string{"22", "80", "443"} {
			c, r := pe.Dial(net.JoinHostPort(vip.String(), port), 500*time.Millisecond)
			if c || r {
				return true, "answered on port " + port
			}
		}
	}
	return false, ""
}

// HasBlock reports whether any check blocks generation.
func HasBlock(cs []Check) bool {
	for _, c := range cs {
		if c.Level == "block" {
			return true
		}
	}
	return false
}
