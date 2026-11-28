package cluster

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TheTractorHacker/dunree/mod/cluster/vip"
)

// Admin routes of the floating IP section (registered next to the other
// cluster routes). All of them are admin only; /api/cluster/vip/ is also in
// the viewer deny list because the generated file holds the VRRP password.
const (
	VIPRouteConfig    = "/api/cluster/vip/config"
	VIPRouteShared    = "/api/cluster/vip/shared"
	VIPRouteLocal     = "/api/cluster/vip/local"
	VIPRoutePreflight = "/api/cluster/vip/preflight"
	VIPRouteGenerate  = "/api/cluster/vip/generate"
	VIPRouteStatus    = "/api/cluster/vip/status"
	VIPRouteScript    = "/api/cluster/vip/script"
	VIPRouteSuggest   = "/api/cluster/vip/suggest"
)

const vipMaxForm = 64 << 10

var vipPreflightLimiter = NewRateLimiter(6, time.Minute)

func (m *Manager) vipAudit(r *http.Request, event string, detail map[string]string) {
	if m.opt.VIP.Audit != nil {
		m.opt.VIP.Audit(r, event, detail)
	}
}

func vipWriteErr(w http.ResponseWriter, err error) {
	var fe *vip.FieldError
	if errors.As(err, &fe) {
		writeJSON(w, map[string]string{"error": fe.Msg, "field": fe.Field})
		return
	}
	writeErr(w, err.Error())
}

func (m *Manager) vipSharedEditable() bool {
	return m.Role() != RoleFollower || m.opt.AllowLocalEdits
}

func (m *Manager) vipSource() string {
	if m.Role() == RoleFollower {
		return "primary"
	}
	return "local"
}

// maskedShared is the shared settings as returned to the page: the password
// never leaves, only whether one is set.
type maskedShared struct {
	vip.Shared
	Password       string `json:"-"`
	ClusterPass    string `json:"-"`
	PasswordSet    bool   `json:"passwordSet"`
	ClusterPassSet bool   `json:"clusterPassSet"`
}

func maskShared(s vip.Shared) maskedShared {
	return maskedShared{Shared: s, PasswordSet: s.Password != "", ClusterPassSet: s.ClusterPass != ""}
}

// MarshalJSON writes the embedded fields without the password.
func (ms maskedShared) MarshalJSON() ([]byte, error) {
	s := ms.Shared
	s.Password, s.ClusterPass = "", ""
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	extra, _ := json.Marshal(map[string]bool{"passwordSet": ms.PasswordSet, "clusterPassSet": ms.ClusterPassSet})
	return append(b[:len(b)-1], append([]byte(","), extra[1:]...)...), nil
}

func (m *Manager) effectivePassword(s *vip.Shared) string {
	p, _ := vip.EffectivePassword(s, m.vipEnv())
	return p
}

// HandleVIPConfig: GET /api/cluster/vip/config
func (m *Manager) HandleVIPConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, "GET required")
		return
	}
	s, exists, err := m.LoadVIPShared()
	if err != nil {
		writeErr(w, "the saved floating IP settings cannot be read: "+err.Error())
		return
	}
	l := m.VIPLocal()
	env := m.vipEnv()
	out := map[string]any{
		"exists":         exists,
		"shared":         maskShared(s),
		"local":          l,
		"defaults":       maskShared(vip.Defaults(m.secret() != "")),
		"source":         m.vipSource(),
		"sharedEditable": m.vipSharedEditable(),
		"role":           m.Role(),
		"haveSecret":     m.secret() != "",
		"fingerprint":    "",
	}
	if pass, perr := vip.EffectivePassword(&s, env); perr == nil && s.VIP != "" {
		out["fingerprint"] = vip.Fingerprint(&s, pass)
	}
	eff := map[string]any{}
	if len(s.Members) > 0 {
		if self, err := vip.Resolve(&s, &l, env.Interfaces); err == nil {
			eff["member"] = s.Members[self.Index].Label
			eff["interface"] = self.Interface
			eff["interfaceSource"] = self.IfaceSource
			eff["priority"] = self.Priority
			eff["prioritySource"] = self.PrioSource
			eff["sourceAddress"] = self.Source
			eff["prefix"] = self.Prefix
		} else {
			eff["error"] = err.Error()
		}
		if s.VIP != "" {
			if pr, _, err := vip.ProbeTarget(&s, &l, env); err == nil && pr.Base != "" {
				eff["healthUrl"] = pr.Base + vip.HealthPath
			}
		}
	}
	out["effective"] = eff
	writeJSON(w, out)
}

// HandleVIPShared: POST /api/cluster/vip/shared (config=<json>, password, ackOldFollowers)
func (m *Manager) HandleVIPShared(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	if !m.vipSharedEditable() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "These settings are managed by the primary. Change them there."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, vipMaxForm)
	if err := r.ParseForm(); err != nil {
		writeErr(w, "the request is too large or malformed")
		return
	}
	raw := r.PostForm.Get("config")
	if raw == "" {
		writeErr(w, "config is required")
		return
	}
	old, exists, lerr := m.LoadVIPShared()
	if lerr != nil && exists {
		old = vip.Defaults(m.secret() != "")
	}
	s, err := vip.ParseShared([]byte(raw), vip.Defaults(m.secret() != ""))
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	// The password never travels inside config: an empty form value keeps the saved one.
	s.Password = old.Password
	if pw := r.PostForm.Get("password"); pw != "" {
		s.Password = pw
	}
	if s.Auth != vip.AuthPassword {
		s.Password = ""
	}
	if r.PostForm.Get("generatePassword") == "1" && s.Auth == vip.AuthPassword && s.Password == "" {
		// "Automatic" without linked servers: the server makes the password, once
		np, perr := NewVIPPassword()
		if perr != nil {
			writeErr(w, "cannot generate a password: "+perr.Error())
			return
		}
		s.Password = np
	}
	// The main server decides the priorities (they are derived, never typed)
	if err := vip.ApplyMain(&s); err != nil {
		vipWriteErr(w, err)
		return
	}
	// The cluster password never comes from the page: keep the saved one, make
	// one the first time auth=cluster is used, or replace it on request.
	s.ClusterPass = old.ClusterPass
	rotated := false
	if s.Auth != vip.AuthCluster {
		s.ClusterPass = ""
	} else if s.ClusterPass == "" || r.PostForm.Get("rotateAuth") == "true" {
		np, perr := NewVIPPassword()
		if perr != nil {
			writeErr(w, "cannot generate a password: "+perr.Error())
			return
		}
		s.ClusterPass, rotated = np, true
	}
	if err := vip.ValidateShared(&s); err != nil {
		vipWriteErr(w, err)
		return
	}
	if s.Enabled && s.Auth == vip.AuthCluster && m.secret() == "" {
		writeErr(w, "authentication is set to the cluster secret, but no cluster secret is set")
		return
	}
	if m.Role() == RolePrimary && (!exists || (s.Main != "" && old.Main == "")) && r.PostForm.Get("ackOldFollowers") != "true" {
		if old := m.oldFollowers(); len(old) > 0 {
			writeJSON(w, map[string]any{
				"error":        "These followers run another version and may refuse a snapshot that carries the floating IP settings until they are updated: " + strings.Join(old, ", ") + ". Update them first, or confirm with ackOldFollowers=true.",
				"oldFollowers": old,
			})
			return
		}
	}
	if err := m.saveVIPShared(&s); err != nil {
		vipWriteErr(w, err)
		return
	}
	m.vipStatus.Invalidate()
	// No fingerprint here: the audit log may be exported, and the fingerprint
	// depends on the VRRP password.
	m.vipAudit(r, "cluster.vip.shared", map[string]string{
		"enabled": strconv.FormatBool(s.Enabled), "vip": s.VIP, "members": strconv.Itoa(len(s.Members)),
		"transport": s.Transport, "auth": s.Auth, "authRotated": strconv.FormatBool(rotated),
	})
	writeJSON(w, "ok")
}

// oldFollowers names followers whose reported version differs from this one.
func (m *Manager) oldFollowers() []string {
	var out []string
	for _, n := range m.Nodes() {
		if n.Version != m.opt.Version {
			name := n.Name
			if name == "" {
				name = n.ID
			}
			out = append(out, name)
		}
	}
	return out
}

// HandleVIPLocal: POST /api/cluster/vip/local (config=<json>)
func (m *Manager) HandleVIPLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, vipMaxForm)
	if err := r.ParseForm(); err != nil {
		writeErr(w, "the request is too large or malformed")
		return
	}
	l, err := vip.ParseLocal([]byte(r.PostForm.Get("config")))
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	if err := m.SetVIPLocal(l); err != nil {
		vipWriteErr(w, err)
		return
	}
	m.vipStatus.Invalidate()
	m.vipAudit(r, "cluster.vip.local", map[string]string{
		"interface": l.Interface, "sourceAddress": l.SourceAddress,
		"priorityOverride": strconv.Itoa(l.PriorityOverride), "healthTarget": l.HealthTarget,
	})
	writeJSON(w, "ok")
}

func (m *Manager) vipPreflightEnv() *vip.PreflightEnv {
	pe := &vip.PreflightEnv{Lister: m.vipLister(), Paths: m.vipPaths(), HTTPGet: m.opt.VIP.HTTPGet, Dial: m.opt.VIP.Dial}
	if pe.HTTPGet == nil {
		pe.HTTPGet = vipHTTPGet
	}
	if pe.Dial == nil {
		pe.Dial = vip.RealDial
	}
	return pe
}

func vipHTTPGet(u string) (int, error) {
	// Like `curl -k` in the generated script: the probe goes to loopback, the
	// node's own address or the floating IP, where the certificate name never
	// matches. Only URLs built by ProbeTarget and vipReach reach this.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		return 0, errors.New("no answer")
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// HandleVIPPreflight: POST /api/cluster/vip/preflight
func (m *Manager) HandleVIPPreflight(w http.ResponseWriter, r *http.Request) {
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
	s, _, err := m.LoadVIPShared()
	if err != nil {
		writeErr(w, "the saved floating IP settings cannot be read: "+err.Error())
		return
	}
	l := m.VIPLocal()
	pe := m.vipPreflightEnv()
	if m.Role() == RolePrimary {
		pe.OldFollowers = m.oldFollowers()
	}
	if m.opt.VIP.NetplanOutside != nil && s.VIP != "" {
		pe.NetplanOutside = m.opt.VIP.NetplanOutside(s.VIP)
	}
	pe.HeldBy = m.peerHolding()
	checks := vip.Preflight(&s, &l, m.vipEnv(), pe)
	writeJSON(w, map[string]any{"checks": checks, "blocked": vip.HasBlock(checks)})
}

// HandleVIPGenerate: GET /api/cluster/vip/generate?member=self|<index>&download=1
func (m *Manager) HandleVIPGenerate(w http.ResponseWriter, r *http.Request) {
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
	out, err := vip.Generate(&s, &l, m.vipEnv(), member)
	if err != nil {
		var be *vip.BlockedError
		if errors.As(err, &be) {
			writeJSON(w, map[string]any{"error": be.Error(), "blockers": be.Blockers})
			return
		}
		m.opt.Logf("[cluster] floating IP render failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal error while generating the configuration"})
		return
	}
	if r.URL.Query().Get("download") == "1" {
		name := sanitizeFileName(out.Member)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", `attachment; filename="keepalived-`+name+`.conf"`)
		w.Write([]byte(out.KeepalivedConf))
		return
	}
	writeJSON(w, out)
}

func sanitizeFileName(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "node"
	}
	return b.String()
}

type vipReach struct {
	Code      int    `json:"code,omitempty"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latencyMs,omitempty"`
	Local     bool   `json:"local"`
}

type vipStatusResp struct {
	vip.Status
	Reach *vipReach `json:"reach,omitempty"`
}

// HandleVIPStatus: GET /api/cluster/vip/status
func (m *Manager) HandleVIPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, "GET required")
		return
	}
	s, exists, err := m.LoadVIPShared()
	if err != nil {
		writeErr(w, "the saved floating IP settings cannot be read: "+err.Error())
		return
	}
	var resp vipStatusResp
	cached := m.vipStatus.Get(func() vip.Status {
		l := m.VIPLocal()
		env := m.vipEnv()
		st := vip.ReadStatus(&s, &l, m.vipLister(), m.vipPaths(), env)
		return st
	})
	resp.Status = cached
	if exists && s.VIP != "" && s.Enabled {
		resp.Reach = m.vipReach(&s, cached)
	}
	out := map[string]any{"status": resp, "exists": exists, "enabled": s.Enabled}
	if exists && s.VIP != "" && len(s.Members) > 0 {
		l := m.VIPLocal()
		out["nodes"] = m.vipNodes(&s, &l, m.vipEnv(), cached)
	}
	if m.Role() == RolePrimary && exists {
		peers, split := m.vipPeers(cached)
		out["peers"] = peers
		out["splitBrain"] = split
	}
	writeJSON(w, out)
}

// vipReach probes http://<vip>:<port>/.dunree/health with a short timeout.
func (m *Manager) vipReach(s *vip.Shared, st vip.Status) *vipReach {
	l := m.VIPLocal()
	env := m.vipEnv()
	pr, blockers, err := vip.ProbeTarget(s, &l, env)
	if err != nil || len(blockers) > 0 || pr.Base == "" {
		return nil
	}
	u, err := url.Parse(pr.Base)
	if err != nil {
		return nil
	}
	addr, err := netip.ParseAddr(s.VIP)
	if err != nil {
		return nil
	}
	target := u.Scheme + "://" + netJoin(addr.String(), u.Port()) + vip.HealthPath
	get := m.opt.VIP.HTTPGet
	if get == nil {
		get = vipHTTPGet
	}
	start := time.Now()
	code, gerr := get(target)
	rc := &vipReach{Code: code, Local: st.Held, LatencyMs: time.Since(start).Milliseconds()}
	if gerr != nil {
		rc.Error = gerr.Error()
	}
	return rc
}

func netJoin(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + port
}

type vipPeer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Self       bool   `json:"self,omitempty"`
	Held       bool   `json:"held"`
	Keepalived string `json:"keepalived"`
	LastSeen   int64  `json:"lastSeen"`
	// Stale: the follower has not reported within three sync intervals, so
	// Held and Keepalived are old news and the page must not show them as current.
	Stale bool `json:"stale,omitempty"`
}

// vipWindow is how long a follower report counts as current.
func (m *Manager) vipWindow() int64 {
	iv := m.Config().SyncIntervalSeconds
	if iv <= 0 {
		iv = 1
	}
	return int64(3 * iv)
}

// vipPeers lists the holders known to the primary. Split brain: more than one
// node holds the VIP within three sync intervals.
func (m *Manager) vipPeers(self vip.Status) ([]vipPeer, bool) {
	now := m.opt.Now().Unix()
	window := m.vipWindow()
	peers := []vipPeer{{ID: m.opt.NodeID, Name: m.opt.NodeName, Self: true, Held: self.Held, Keepalived: string(self.KeepalivedUp), LastSeen: now}}
	holders := 0
	if self.Held {
		holders++
	}
	for _, n := range m.Nodes() {
		if n.VIP == nil {
			continue
		}
		stale := now-n.VIPSeen > window
		p := vipPeer{ID: n.ID, Name: n.Name, Held: n.VIP.Held, Keepalived: string(n.VIP.Keepalived), LastSeen: n.VIPSeen, Stale: stale}
		peers = append(peers, p)
		if n.VIP.Held && !stale {
			holders++
		}
	}
	return peers, holders > 1
}

// peerHolding names a follower currently reported as holding the VIP. A
// report older than the window is ignored.
func (m *Manager) peerHolding() string {
	now := m.opt.Now().Unix()
	window := m.vipWindow()
	for _, n := range m.Nodes() {
		if n.VIP != nil && n.VIP.Held && now-n.VIPSeen <= window {
			if n.Name != "" {
				return n.Name
			}
			return n.ID
		}
	}
	return ""
}
