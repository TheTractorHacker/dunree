// Package deployrole holds the deployment role of this Dunree instance
// (standalone, external or internal proxy of a two proxy chain) and the settings
// that depend on it. See docs/enterprise-dual-proxy-plan.md.
//
// Everything is opt-in. The zero value of Settings is the role "standalone"
// with every switch off, and in that state nothing in this package touches a
// request: standalone behaviour is unchanged byte for byte.
package deployrole

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// Role is the place of this instance in the network
type Role string

const (
	RoleStandalone Role = "standalone" // default: today's behaviour
	RoleExternal   Role = "external"   // internet facing proxy in front of an internal proxy
	RoleInternal   Role = "internal"   // proxy behind an external proxy
)

const (
	// DBTable and DBKey are where the settings live (sys.db, table "settings")
	DBTable = "settings"
	DBKey   = "deployrole"

	maxDirectCIDRs = 256
)

// Settings is the persisted configuration. Every field's zero value is the old behaviour.
type Settings struct {
	Role Role `json:"role"` //"" is read as standalone

	//HardenHeaders turns the forwarded header hardening on in the standalone role.
	//In the external and internal roles it is always on.
	HardenHeaders bool `json:"hardenHeaders"`

	//PeerGate (internal role only): only accept connections from trusted proxy
	//peers and from DirectCIDRs, everything else gets 403 before routing.
	PeerGate bool `json:"peerGate"`

	//DirectCIDRs are the networks (CIDR or single address) that may reach an
	//internal proxy directly, for example the management VLAN or the servers VLAN.
	DirectCIDRs []string `json:"directCIDRs"`
}

// KV is the part of the sys.db API the manager needs (database.Database satisfies it)
type KV interface {
	Read(table, key string, assignee interface{}) error
	Write(table, key string, value interface{}) error
}

type state struct {
	s    Settings
	nets []*net.IPNet
}

// Manager keeps the settings. Reads are lock free and safe from any goroutine.
type Manager struct {
	kv  KV
	cur atomic.Pointer[state]
	// OnChange, if set, is called after a successful Set (audit hook), with the old and new settings
	OnChange func(old, next Settings)
}

// New loads the settings from kv (nil kv: in memory only). A stored value that
// no longer validates is ignored and the defaults are used; the error says so.
func New(kv KV) (*Manager, error) {
	m := &Manager{kv: kv}
	m.cur.Store(&state{s: Settings{Role: RoleStandalone}})
	if kv == nil {
		return m, nil
	}
	var stored Settings
	if err := kv.Read(DBTable, DBKey, &stored); err != nil {
		return m, nil //nothing stored yet
	}
	st, err := build(stored)
	if err != nil {
		return m, fmt.Errorf("stored deployment settings ignored, using standalone: %w", err)
	}
	m.cur.Store(st)
	return m, nil
}

func build(s Settings) (*state, error) {
	n, err := Validate(&s)
	if err != nil {
		return nil, err
	}
	return &state{s: s, nets: n}, nil
}

// Validate normalises s in place (role default, trimmed CIDR list) and returns the parsed networks.
func Validate(s *Settings) ([]*net.IPNet, error) {
	s.Role = Role(strings.ToLower(strings.TrimSpace(string(s.Role))))
	switch s.Role {
	case "":
		s.Role = RoleStandalone
	case RoleStandalone, RoleExternal, RoleInternal:
	default:
		return nil, fmt.Errorf("unknown role %q (use standalone, external or internal)", s.Role)
	}
	if s.PeerGate && s.Role != RoleInternal {
		return nil, errors.New("the peer gate only exists in the internal role")
	}
	if len(s.DirectCIDRs) > maxDirectCIDRs {
		return nil, fmt.Errorf("at most %d direct-access networks", maxDirectCIDRs)
	}
	var nets []*net.IPNet
	clean := make([]string, 0, len(s.DirectCIDRs))
	seen := map[string]bool{}
	for _, raw := range s.DirectCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		n, err := parseNet(raw)
		if err != nil {
			return nil, err
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("%q matches every address, that would switch the peer gate off", raw)
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		clean = append(clean, raw)
		nets = append(nets, n)
	}
	s.DirectCIDRs = clean
	return nets, nil
}

func parseNet(raw string) (*net.IPNet, error) {
	if strings.Contains(raw, "/") {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR", raw)
		}
		return n, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("%q is not an IP address or CIDR", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func (m *Manager) load() *state {
	if m == nil {
		return &state{s: Settings{Role: RoleStandalone}}
	}
	return m.cur.Load()
}

// Settings returns a copy of the current settings
func (m *Manager) Settings() Settings {
	s := m.load().s
	s.DirectCIDRs = append([]string(nil), s.DirectCIDRs...)
	return s
}

// Role returns the current role (standalone for a nil manager)
func (m *Manager) Role() Role { return m.load().s.Role }

// HardenActive reports whether the forwarded header hardening runs
func (m *Manager) HardenActive() bool {
	s := &m.load().s
	return s.Role == RoleExternal || s.Role == RoleInternal || s.HardenHeaders
}

// PeerGateActive reports whether the internal role peer gate rejects unknown peers
func (m *Manager) PeerGateActive() bool {
	s := &m.load().s
	return s.Role == RoleInternal && s.PeerGate
}

// Set validates, persists and applies new settings. Nothing changes when it fails.
func (m *Manager) Set(next Settings) error {
	old := m.Settings()
	st, err := build(next)
	if err != nil {
		return err
	}
	if m.kv != nil {
		if err := m.kv.Write(DBTable, DBKey, st.s); err != nil {
			return fmt.Errorf("could not save: %w", err)
		}
	}
	m.cur.Store(st)
	if m.OnChange != nil {
		m.OnChange(old, st.s)
	}
	return nil
}

// JSON is the API representation (never a null list)
func (s Settings) JSON() []byte {
	if s.DirectCIDRs == nil {
		s.DirectCIDRs = []string{}
	}
	b, _ := json.Marshal(s)
	return b
}

// PeerAllowed is the peer gate decision for a connection from peerIP: allowed
// when the gate is off, the peer is a trusted proxy, or it lies in a direct-access network.
func (m *Manager) PeerAllowed(peerIP string, isTrusted func(string) bool) bool {
	st := m.load()
	if !(st.s.Role == RoleInternal && st.s.PeerGate) {
		return true
	}
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return false
	}
	if isTrusted != nil && (isTrusted(peerIP) || isTrusted(ip.String())) {
		return true
	}
	for _, n := range st.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
