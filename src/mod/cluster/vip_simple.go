package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheTractorHacker/dunree/mod/cluster/vip"
)

// Backend of the simple guided floating IP setup
// (docs/cluster/vip-simple-setup.md): installer script, address suggestions
// and per-server progress. Dunree still applies nothing: it generates text
// and reads status.

// vipBlocker is one reason a script cannot be made, ready for the page.
type vipBlocker struct {
	Field    string `json:"field,omitempty"`
	Node     int    `json:"node"`
	LabelKey string `json:"labelKey,omitempty"`
	Message  string `json:"message"`
}

func vipBlockers(s *vip.Shared, l *vip.Local, err error) []vipBlocker {
	var fe *vip.FieldError
	if errors.As(err, &fe) {
		key, node, _ := vip.FieldLabelKey(fe.Field)
		return []vipBlocker{{Field: fe.Field, Node: node, LabelKey: key, Message: fe.Msg}}
	}
	var be *vip.BlockedError
	if errors.As(err, &be) {
		var out []vipBlocker
		for _, b := range be.Blockers {
			out = append(out, vipBlocker{Node: -1, Message: b})
		}
		return out
	}
	return []vipBlocker{{Node: -1, Message: err.Error()}}
}

// HandleVIPScript: GET /api/cluster/vip/script?member=self|<index>&download=0|1
func (m *Manager) HandleVIPScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, "GET required")
		return
	}
	s, exists, err := m.LoadVIPShared()
	if err != nil || !exists {
		writeErr(w, "save the floating IP settings first")
		return
	}
	member := -1
	if v := r.URL.Query().Get("member"); v != "" && v != "self" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || len(v) > 2 {
			writeErr(w, "member must be self or a member number")
			return
		}
		member = n
	}
	l := m.VIPLocal()
	env := m.vipEnv()
	// Field errors first, so the page can focus the field.
	if verr := vip.ValidateShared(&s); verr != nil {
		writeJSON(w, map[string]any{"error": verr.Error(), "blockers": vipBlockers(&s, &l, verr)})
		return
	}
	if member >= len(s.Members) {
		writeErr(w, "no such member")
		return
	}
	var pf *vip.PeerFacts
	if member >= 0 {
		if self, serr := vip.Resolve(&s, &l, env.Interfaces); serr == nil && self.Index == member {
			member = -1 // that member is this server: no guessing needed
		} else {
			pf = m.vipPeerFacts(&s, &l, env, member)
		}
	}
	out, err := vip.Script(&s, &l, env, member, pf)
	if err != nil {
		var be *vip.BlockedError
		if errors.As(err, &be) {
			writeJSON(w, map[string]any{"error": be.Error(), "blockers": vipBlockers(&s, &l, err)})
			return
		}
		m.opt.Logf("[cluster] floating IP script render failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal error while generating the script"})
		return
	}
	if out.Guessed == nil {
		out.Guessed = []string{}
	}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	m.vipAudit(r, "cluster.vip.generate", map[string]string{"member": out.Label, "kind": "script"})
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="dunree-floating-ip-`+sanitizeFileName(out.Label)+`.sh"`)
		w.Write([]byte(out.Inner))
		return
	}
	writeJSON(w, map[string]any{
		"title":          map[string]string{"label": out.Label, "address": out.Address, "role": out.Role},
		"script":         out.Script,
		"keepalivedConf": out.Conf,
		"commands":       out.Commands,
		"fingerprint":    out.Fingerprint,
		"healthUrl":      out.HealthURL,
		"interface":      out.Interface,
		"guessed":        out.Guessed,
		"warnings":       out.Warnings,
		"blockers":       []vipBlocker{},
	})
}

// HandleVIPSuggest: POST /api/cluster/vip/suggest (optional near=<address>)
func (m *Manager) HandleVIPSuggest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	if !vipPreflightLimiter.Allow(clientIP(r), m.opt.Now()) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		writeErr(w, "too many checks, wait a minute")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, vipMaxForm)
	if err := r.ParseForm(); err != nil {
		writeErr(w, "the request is too large or malformed")
		return
	}
	s, _, _ := m.LoadVIPShared()
	var members []string
	for _, mm := range s.Members {
		members = append(members, mm.Address)
	}
	env := m.vipEnv()
	base, err := vip.SuggestBase(r.PostForm.Get("near"), members, env.Interfaces)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	dial := m.opt.VIP.Dial
	if dial == nil {
		dial = vip.RealDial
	}
	res, err := vip.Suggest(vip.SuggestInput{Base: base, Members: members, Lister: m.vipLister(), Paths: m.vipPaths(), Dial: dial})
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, res)
}

// ---- peer facts (health JSON "vip" block) ----

// vipHealthBlock is the optional "vip" block of the health JSON. It holds no
// secret: floating IP state, interface name and health check URL.
type vipHealthBlock struct {
	Held       bool   `json:"held"`
	Keepalived string `json:"keepalived"`
	Settings   string `json:"settings,omitempty"`
	Installed  string `json:"installed,omitempty"`
	Iface      string `json:"iface,omitempty"`
	Probe      string `json:"probe,omitempty"`
	// Prio is this server's own priority override (Expert values), 0 = none.
	Prio int `json:"prio,omitempty"`
}

// healthVIPBlock builds the block for the health endpoint. It is only added
// when the floating IP is enabled and the request comes from loopback or from
// a member address (not authentication: it only keeps the block off the
// open internet; it holds no secret). A server that holds no saved settings
// (the servers are not linked) answers from the marker its installer script
// left, so the other server's page can still see its progress.
func (m *Manager) healthVIPBlock(r *http.Request) map[string]any {
	host, _, herr := net.SplitHostPort(r.RemoteAddr)
	if herr != nil {
		host = r.RemoteAddr
	}
	ip, perr := netip.ParseAddr(host)
	if perr != nil {
		return nil
	}
	ip = ip.Unmap()
	s, exists, err := m.LoadVIPShared()
	if err != nil {
		return nil
	}
	if !exists {
		return m.healthVIPBlockFromMarker(ip)
	}
	if !s.Enabled {
		return nil
	}
	ok := ip.IsLoopback()
	for _, mm := range s.Members {
		if mm.Address == ip.String() {
			ok = true
		}
	}
	if !ok {
		return nil
	}
	l := m.VIPLocal()
	env := m.vipEnv()
	st := m.vipStatus.Get(func() vip.Status {
		return vip.ReadStatus(&s, &l, m.vipLister(), m.vipPaths(), env)
	})
	b := vipHealthBlock{Held: st.Held, Keepalived: string(st.KeepalivedUp), Settings: st.CurrentFinger, Installed: firstNonEmpty(st.MarkerFinger, st.InstalledFinger), Iface: st.Interface, Prio: l.PriorityOverride}
	if pr, _, perr := vip.ProbeTarget(&s, &l, env); perr == nil && pr.Base != "" {
		b.Probe = pr.Base + vip.HealthPath
	}
	return vipBlockMap(b)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func vipBlockMap(b vipHealthBlock) map[string]any {
	raw, _ := json.Marshal(b)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

// healthVIPBlockFromMarker answers for a server that holds no floating IP
// settings but ran the installer script. Only loopback and the other members
// the script was made with may ask.
func (m *Manager) healthVIPBlockFromMarker(ip netip.Addr) map[string]any {
	paths := m.vipPaths()
	mk, ok := vip.ReadMarker(paths.MarkerFile)
	if !ok || mk.VIP == "" {
		return nil
	}
	allowed := ip.IsLoopback()
	for _, p := range mk.Peers {
		if p == ip.String() {
			allowed = true
		}
	}
	if !allowed {
		return nil
	}
	l := vip.Local{}
	st := vip.ReadStatus(&vip.Shared{VIP: mk.VIP}, &l, m.vipLister(), paths, m.vipEnv())
	b := vipHealthBlock{Held: st.Held, Keepalived: string(st.KeepalivedUp), Installed: mk.Fingerprint}
	if mk.Member != "" {
		if ifs, err := m.vipLister().Interfaces(); err == nil {
			if a, err := netip.ParseAddr(mk.Member); err == nil {
				for _, in := range ifs {
					for _, p := range in.Addrs {
						if p.Addr() == a {
							b.Iface = in.Name
						}
					}
				}
			}
		}
	}
	return vipBlockMap(b)
}

type peerAnswer struct {
	at      time.Time
	ok      bool
	version string
	block   *vipHealthBlock
	// proxyDown: the server answered 503, its proxy is stopped.
	proxyDown bool
}

var (
	peerMu    sync.Mutex
	peerCache = map[string]peerAnswer{}
)

func vipHTTPBody(u string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		return nil, errors.New("no answer")
	}
	defer resp.Body.Close()
	// 503 carries the same JSON as 200: the proxy of that server is stopped,
	// and the page needs to tell that apart from "no answer".
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<10))
}

// vipPeerAnswer asks a member's Dunree for its health JSON. The peer is
// assumed to serve the health check on the same port as this server (the
// block says where it really is). Answers are cached for 2 s.
func (m *Manager) vipPeerAnswer(s *vip.Shared, l *vip.Local, env *vip.Env, addr string) peerAnswer {
	pr, _, err := vip.ProbeTarget(s, l, env)
	if err != nil || pr.Base == "" || pr.TLS {
		return peerAnswer{}
	}
	u, err := url.Parse(pr.Base)
	if err != nil || u.Port() == "" {
		return peerAnswer{}
	}
	target := "http://" + netJoin(addr, u.Port()) + vip.HealthPath
	peerMu.Lock()
	if c, ok := peerCache[target]; ok && m.opt.Now().Sub(c.at) < 2*time.Second {
		peerMu.Unlock()
		return c
	}
	peerMu.Unlock()
	get := m.opt.VIP.HTTPBody
	if get == nil {
		get = vipHTTPBody
	}
	ans := peerAnswer{at: m.opt.Now()}
	if body, err := get(target); err == nil {
		var doc struct {
			Version      string          `json:"version"`
			ProxyRunning *bool           `json:"proxyRunning"`
			VIP          *vipHealthBlock `json:"vip"`
		}
		if json.Unmarshal(body, &doc) == nil {
			ans.ok, ans.version, ans.block = true, doc.Version, doc.VIP
			ans.proxyDown = doc.ProxyRunning != nil && !*doc.ProxyRunning
		}
	}
	peerMu.Lock()
	peerCache[target] = ans
	peerMu.Unlock()
	return ans
}

// vipPeerFacts turns a peer's answer into script inputs, refusing values that
// are not plain interface names or probe base URLs.
func (m *Manager) vipPeerFacts(s *vip.Shared, l *vip.Local, env *vip.Env, member int) *vip.PeerFacts {
	ans := m.vipPeerAnswer(s, l, env, s.Members[member].Address)
	if !ans.ok || ans.block == nil {
		return nil
	}
	pf := &vip.PeerFacts{}
	if vip.ValidInterfaceName(ans.block.Iface) {
		pf.Iface = ans.block.Iface
	}
	// The probe only ever has to reach that server's own Dunree: accept its
	// loopback or its own member address, never another host.
	if base := strings.TrimSuffix(ans.block.Probe, vip.HealthPath); base != ans.block.Probe && vip.ValidProbeBase(base, s.Members[member].Address) {
		pf.ProbeBase = base
	}
	if p := ans.block.Prio; p >= 1 && p <= 254 {
		pf.Priority = p
	}
	return pf
}

// vipNode is one entry of status.nodes.
type vipNode struct {
	Label         string `json:"label"`
	Address       string `json:"address"`
	Self          bool   `json:"self,omitempty"`
	State         string `json:"state"`
	Held          bool   `json:"held"`
	Keepalived    string `json:"keepalived"`
	Installed     bool   `json:"installed"`
	InstalledFP   string `json:"installedFingerprint,omitempty"`
	SettingsMatch bool   `json:"settingsMatch"`
	Reachable     bool   `json:"reachable"`
	Version       string `json:"version,omitempty"`
	Iface         string `json:"iface,omitempty"`
	// Prio is the server's own priority override, 0 = none.
	Prio int `json:"prio,omitempty"`
}

// vipNodes computes the card state of every member (section 10.1).
func (m *Manager) vipNodes(s *vip.Shared, l *vip.Local, env *vip.Env, self vip.Status) []vipNode {
	selfIdx := -1
	if sf, err := vip.Resolve(s, l, env.Interfaces); err == nil {
		selfIdx = sf.Index
	}
	nodes := make([]vipNode, len(s.Members))
	facts := make([]vip.NodeFacts, len(s.Members))
	var wg sync.WaitGroup
	for i, mm := range s.Members {
		n := &nodes[i]
		n.Label, n.Address = mm.Label, mm.Address
		if i == selfIdx {
			n.Self, n.Reachable, n.Held, n.Keepalived = true, true, self.Held, string(self.KeepalivedUp)
			// A server set up with the classic commands has no marker, but its
			// keepalived.conf carries the settings fingerprint: that counts.
			inst, fp := self.Installed || self.InstalledFinger != "", firstNonEmpty(self.MarkerFinger, self.InstalledFinger)
			n.Installed, n.InstalledFP, n.Iface, n.Version, n.Prio = inst, fp, self.Interface, m.opt.Version, l.PriorityOverride
			facts[i] = vip.NodeFacts{Reachable: true, KeepalivedBin: self.KeepalivedFound == vip.Yes, Installed: inst,
				InstalledFP: fp, CurrentFP: self.CurrentFinger, KeepalivedUp: self.KeepalivedUp, Held: self.Held}
			n.SettingsMatch = inst && fp == self.CurrentFinger
			continue
		}
		wg.Add(1)
		go func(i int, mm vip.Member) {
			defer wg.Done()
			ans := m.vipPeerAnswer(s, l, env, mm.Address)
			n := &nodes[i]
			n.Reachable, n.Version = ans.ok, ans.version
			f := vip.NodeFacts{Reachable: ans.ok, CurrentFP: self.CurrentFinger, KeepalivedUp: vip.Unknown}
			if ans.ok && ans.block == nil {
				if ans.version != m.opt.Version {
					f.OldVersion = true
				} else {
					f.NoBlock = true
				}
			}
			if ans.proxyDown {
				f.ProbeOK = vip.No
			}
			if b := ans.block; b != nil {
				n.Held, n.Keepalived, n.Iface = b.Held, b.Keepalived, b.Iface
				n.Installed, n.InstalledFP, n.Prio = b.Installed != "", b.Installed, b.Prio
				n.SettingsMatch = b.Installed != "" && b.Installed == self.CurrentFinger
				f.Installed, f.InstalledFP, f.Held = b.Installed != "", b.Installed, b.Held
				f.KeepalivedUp = vip.Tri(b.Keepalived)
				f.KeepalivedBin = b.Installed != ""
			}
			facts[i] = f
		}(i, mm)
	}
	wg.Wait()
	some := false
	for _, f := range facts {
		if f.Held {
			some = true
		}
	}
	for i := range nodes {
		facts[i].SomeoneHolds = some
		nodes[i].State = vip.NodeState(facts[i])
	}
	return nodes
}
