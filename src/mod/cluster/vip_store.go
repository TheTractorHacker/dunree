package cluster

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TheTractorHacker/dunree/mod/cluster/vip"
)

/*
	Floating IP (keepalived / VRRP) settings. Design: docs/cluster/vip-plan.md.

	Shared settings: conf/ha/vip.json (0600), a snapshot root of its own that
	only joins the snapshot once the file exists, so a node that never used the
	feature produces byte-identical snapshots. Node-local overrides: the
	"vipLocal" object of conf/cluster.json (never synced).

	Dunree applies nothing: this file only stores settings. Generated text is
	in vip_api.go, the generator in mod/cluster/vip.
*/

const (
	haRoot      = "ha"
	vipFileName = "vip.json"
)

// VIPOptions are the injectable parts of the feature. The zero value uses
// the real host, so tests need no root.
type VIPOptions struct {
	Lister   vip.InterfaceLister
	Paths    *vip.Paths
	Listener func() vip.ListenerFacts
	HTTPGet  func(url string) (int, error)
	Dial     func(addr string, timeout time.Duration) (connected, refused bool)
	// Audit records a change in the security audit log. detail never holds a secret.
	Audit func(r *http.Request, event string, detail map[string]string)
	// NetplanOutside reports whether the VIP is outside the Network plan's proxy network.
	NetplanOutside func(vip string) bool
	// HTTPBody fetches a peer's health JSON (at most 8 KiB). Tests replace it.
	HTTPBody func(url string) ([]byte, error)
}

func (m *Manager) vipPath() string { return filepath.Join(m.opt.ConfDir, haRoot, vipFileName) }

func (m *Manager) vipLister() vip.InterfaceLister {
	if m.opt.VIP.Lister != nil {
		return m.opt.VIP.Lister
	}
	return vip.RealInterfaces{}
}

func (m *Manager) vipPaths() vip.Paths {
	if m.opt.VIP.Paths != nil {
		return *m.opt.VIP.Paths
	}
	return vip.SystemPaths()
}

// VIPExists reports whether conf/ha/vip.json exists (the ha root is in the
// snapshot only from then on).
func (m *Manager) VIPExists() bool { return vipFileExists(m.opt.ConfDir) }

func vipFileExists(confDir string) bool {
	fi, err := os.Lstat(filepath.Join(confDir, haRoot, vipFileName))
	return err == nil && fi.Mode().IsRegular()
}

// LoadVIPShared reads the shared settings. exists is false (and the defaults
// are returned) before the first save.
func (m *Manager) LoadVIPShared() (s vip.Shared, exists bool, err error) {
	def := vip.Defaults(m.secret() != "")
	b, err := os.ReadFile(m.vipPath())
	if err != nil {
		if os.IsNotExist(err) {
			return def, false, nil
		}
		return def, false, err
	}
	s, err = vip.ParseShared(b, def)
	if err != nil {
		return def, true, err
	}
	return s, true, nil
}

// saveVIPShared validates and writes the shared settings atomically.
func (m *Manager) saveVIPShared(s *vip.Shared) error {
	if err := vip.ValidateShared(s); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > vip.MaxConfigBytes {
		return errors.New("settings are too large")
	}
	dir := filepath.Dir(m.vipPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := m.vipPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.vipPath())
}

// VIPLocal returns the node-local overrides (never nil).
func (m *Manager) VIPLocal() vip.Local {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg.VIPLocal == nil {
		return vip.Local{}
	}
	return *m.cfg.VIPLocal
}

// SetVIPLocal stores the node-local overrides in conf/cluster.json.
func (m *Manager) SetVIPLocal(l vip.Local) error {
	s, _, err := m.LoadVIPShared()
	var sp *vip.Shared
	if err == nil {
		sp = &s
	}
	if err := vip.ValidateLocal(&l, sp); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.cfg.VIPLocal
	if l == (vip.Local{}) {
		m.cfg.VIPLocal = nil
	} else {
		m.cfg.VIPLocal = &l
	}
	if err := m.saveLocked(); err != nil {
		m.cfg.VIPLocal = old
		return err
	}
	return nil
}

// NewVIPPassword returns a random 8 character VRRP password (crypto/rand,
// no modulo bias). It is derived from nothing: keepalived PASS auth sends it
// in clear in every advert, so it must not reveal any key material.
func NewVIPPassword() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const limit = 256 - 256%len(alphabet) // 248: bytes at or above are rejected
	out := make([]byte, 0, 8)
	buf := make([]byte, 16)
	for len(out) < 8 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, c := range buf {
			if int(c) < limit && len(out) < 8 {
				out = append(out, alphabet[int(c)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}

// vipEnv collects what only this process knows.
func (m *Manager) vipEnv() *vip.Env {
	env := &vip.Env{Version: m.opt.Version}
	if m.opt.VIP.Listener != nil {
		env.Listener = m.opt.VIP.Listener()
	}
	cfg := m.Config()
	env.Listener.HealthDisabled = cfg.HealthDisabled
	env.Listener.HealthAllow = cfg.HealthAllow
	if ifs, err := m.vipLister().Interfaces(); err == nil {
		env.Interfaces = ifs
	}
	env.UFWEnabled = vip.ReadUFWEnabled(m.vipPaths().UFWConf)
	return env
}

func sanitizeBeat(b *vip.HeartbeatFact) *vip.HeartbeatFact {
	if b == nil {
		return nil
	}
	out := *b
	switch out.Keepalived {
	case vip.Yes, vip.No, vip.Unknown:
	default:
		out.Keepalived = vip.Unknown
	}
	return &out
}

// vipBeat is the optional heartbeat fact: nil unless the feature is in use.
func (m *Manager) vipBeat() *vip.HeartbeatFact {
	s, exists, err := m.LoadVIPShared()
	if err != nil || !exists || !s.Enabled {
		return nil
	}
	l := m.VIPLocal()
	st := vip.ReadStatus(&s, &l, m.vipLister(), m.vipPaths(), m.vipEnv())
	return &vip.HeartbeatFact{Held: st.Held, Keepalived: st.KeepalivedUp}
}
