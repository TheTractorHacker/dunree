// Package adminallow is the optional allow-list of networks that may reach the admin listener
// (dual proxy plan, Phase 2 slice C). Empty list (the default, and every existing install) means
// no restriction: the middleware is then one atomic load and the request is passed on untouched.
//
// Lock-out safety: Set refuses a non-empty list that does not contain the address of the client
// that saves it. If an admin is locked out anyway (changed network, wrong entry), start Dunree once
// with -reset_admin_allowlist, which clears the list before the admin port starts serving.
package adminallow

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DBTable and DBKey are where the settings live (sys.db, table "settings")
	DBTable = "settings"
	DBKey   = "adminallow"

	maxEntries = 64
)

// Settings is the persisted configuration. Zero value = no allow-list = today's behaviour.
type Settings struct {
	CIDRs []string `json:"cidrs"` //networks or single addresses (CIDR or IP) that may reach the admin listener
}

// KV is the part of the sys.db API the manager needs (database.Database satisfies it)
type KV interface {
	Read(table, key string, assignee interface{}) error
	Write(table, key string, value interface{}) error
}

type state struct {
	s    Settings
	nets []netip.Prefix
}

// Manager keeps the list. Reads are lock free.
type Manager struct {
	kv  KV
	cur atomic.Pointer[state]

	// OnChange, if set, is called after a successful Set or Reset
	OnChange func(old, next Settings)

	denied  atomic.Uint64
	logMu   sync.Mutex
	lastLog time.Time
	// Logf receives the (rate limited) refusal log line; nil = silent
	Logf func(string)
}

// New loads the list from kv (nil kv: in memory only). A stored list that no longer validates is
// ignored (no restriction) and the error says so, so a corrupt value can never lock the admin out.
func New(kv KV) (*Manager, error) {
	m := &Manager{kv: kv}
	m.cur.Store(&state{})
	if kv == nil {
		return m, nil
	}
	var stored Settings
	if err := kv.Read(DBTable, DBKey, &stored); err != nil {
		return m, nil
	}
	st, err := build(stored)
	if err != nil {
		return m, fmt.Errorf("stored admin allow-list ignored, no restriction: %w", err)
	}
	m.cur.Store(st)
	return m, nil
}

func build(s Settings) (*state, error) {
	if len(s.CIDRs) > maxEntries {
		return nil, fmt.Errorf("at most %d entries", maxEntries)
	}
	st := &state{}
	seen := map[string]bool{}
	for _, raw := range s.CIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, err
		}
		st.s.CIDRs = append(st.s.CIDRs, raw)
		st.nets = append(st.nets, p)
	}
	return st, nil
}

func parsePrefix(raw string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		var err error
		if p, err = netip.ParsePrefix(raw); err != nil {
			return p, fmt.Errorf("%q is not a valid CIDR", raw)
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			return p, fmt.Errorf("%q: write IPv4 networks in plain form", raw)
		}
	} else {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return p, fmt.Errorf("%q is not an IP address or CIDR", raw)
		}
		ip = ip.WithZone("").Unmap()
		p = netip.PrefixFrom(ip, ip.BitLen())
	}
	if p.Bits() == 0 {
		return p, fmt.Errorf("%q matches every address, that is no restriction: leave the list empty instead", raw)
	}
	return p, nil
}

func (m *Manager) load() *state {
	if m == nil {
		return &state{}
	}
	return m.cur.Load()
}

// Active reports whether an allow-list is configured
func (m *Manager) Active() bool { return len(m.load().nets) > 0 }

// Settings returns a copy of the current settings
func (m *Manager) Settings() Settings {
	return Settings{CIDRs: append([]string{}, m.load().s.CIDRs...)}
}

// Denied is the number of requests refused since start
func (m *Manager) Denied() uint64 {
	if m == nil {
		return 0
	}
	return m.denied.Load()
}

// Allowed reports whether ip may reach the admin listener (true when no list is configured)
func (m *Manager) Allowed(ip netip.Addr) bool {
	st := m.load()
	if len(st.nets) == 0 {
		return true
	}
	ip = ip.WithZone("").Unmap()
	for _, n := range st.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Set validates, persists and applies a new list. clientIP is the address of the client making the
// change: a non-empty list that does not contain it is refused (it would lock that admin out).
// An empty list switches the restriction off. Nothing changes when it fails.
func (m *Manager) Set(next Settings, clientIP string) error {
	st, err := build(next)
	if err != nil {
		return err
	}
	if len(st.nets) > 0 {
		ip, perr := netip.ParseAddr(strings.TrimSpace(clientIP))
		if perr != nil {
			return errors.New("cannot tell your own address, so the list was not saved (it could lock you out)")
		}
		ip = ip.WithZone("").Unmap()
		ok := false
		for _, n := range st.nets {
			if n.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("your address %s is not in the list: saving it would lock you out of the admin panel. Add your address or network first", ip)
		}
	}
	return m.store(st)
}

// Reset clears the list (the recovery path, see the package comment)
func (m *Manager) Reset() error { return m.store(&state{}) }

func (m *Manager) store(st *state) error {
	old := m.Settings()
	if m.kv != nil {
		s := st.s
		if s.CIDRs == nil {
			s.CIDRs = []string{}
		}
		if err := m.kv.Write(DBTable, DBKey, s); err != nil {
			return fmt.Errorf("could not save: %w", err)
		}
	}
	m.cur.Store(st)
	if m.OnChange != nil {
		m.OnChange(old, m.Settings())
	}
	return nil
}

// Middleware refuses admin requests from addresses outside the list. With no list it is a pass-through.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := m.load()
		if len(st.nets) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip, perr := netip.ParseAddr(host)
		switch {
		case perr != nil || !m.Allowed(ip):
			m.refuse(w, r, host, "address not in the admin allow-list")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func (m *Manager) refuse(w http.ResponseWriter, r *http.Request, host, why string) {
	m.denied.Add(1)
	if m.Logf != nil {
		m.logMu.Lock()
		if time.Since(m.lastLog) > 30*time.Second {
			m.lastLog = time.Now()
			m.logMu.Unlock()
			m.Logf("Admin request from " + host + " refused: " + why + " (logged at most every 30 s)")
		} else {
			m.logMu.Unlock()
		}
	}
	http.Error(w, "403 Forbidden", http.StatusForbidden)
}

// TargetsListener reports whether a proxy rule upstream (host, port) would reach the admin listener
// bound at listenAddr (the -port value: ":8000", "0.0.0.0:8000", "127.0.0.1:8000", "[::]:8000").
// A wildcard listener is reached through loopback and through every address of this machine (local);
// a listener bound to one address is only reached through that address. Names are resolved with
// resolve (nil: IP literals and "localhost" only). A port of 0 never matches.
func TargetsListener(listenAddr, host string, port int, local []netip.Addr, resolve func(string) []netip.Addr) bool {
	_, lp, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		lp = strings.TrimPrefix(strings.TrimSpace(listenAddr), ":")
	}
	adminPort, perr := net.LookupPort("tcp", lp)
	if perr != nil || port <= 0 || port != adminPort {
		return false
	}
	bindHost := ""
	if h, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr)); err == nil {
		bindHost = strings.Trim(h, "[]")
	}
	var bind netip.Addr
	wildcard := bindHost == ""
	if !wildcard {
		if ip, err := netip.ParseAddr(bindHost); err == nil {
			bind = ip.Unmap()
			wildcard = bind.IsUnspecified()
		} else if strings.EqualFold(bindHost, "localhost") {
			bind = netip.MustParseAddr("127.0.0.1")
		} else {
			return false //a bind host name we cannot judge
		}
	}
	reaches := func(ip netip.Addr) bool {
		ip = ip.WithZone("").Unmap()
		if ip.IsUnspecified() { //connecting to 0.0.0.0 / :: goes to this machine
			return wildcard || bind.IsLoopback()
		}
		if wildcard {
			if ip.IsLoopback() {
				return true
			}
			for _, l := range local {
				if l.Unmap() == ip {
					return true
				}
			}
			return false
		}
		return ip == bind
	}
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		return reaches(ip)
	}
	if strings.EqualFold(host, "localhost") {
		return reaches(netip.MustParseAddr("127.0.0.1")) || reaches(netip.IPv6Loopback())
	}
	if resolve != nil {
		for _, ip := range resolve(host) {
			if reaches(ip) {
				return true
			}
		}
	}
	return false
}
