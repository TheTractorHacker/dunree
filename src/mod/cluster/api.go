package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg string) {
	writeJSON(w, map[string]string{"error": msg})
}

// HandleStatus returns everything the Cluster page shows. The secret itself
// is never returned, only whether it is set and a short fingerprint.
func (m *Manager) HandleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := m.Config()
	out := map[string]any{
		"role":               cfg.Role,
		"secretSet":          m.secret() != "",
		"secretFingerprint":  m.SecretFingerprint(),
		"secretFromFlag":     m.secretFlag,
		"restartRequired":    m.RestartRequired(),
		"primaryUrl":         cfg.PrimaryURL,
		"primaryFingerprint": cfg.PrimaryFingerprint,
		"syncInterval":       cfg.SyncIntervalSeconds,
		"syncCerts":          cfg.SyncCerts,
		"syncSettings":       cfg.SyncSettings,
		"syncSettingsAvail":  m.opt.ExportSettings != nil,
		"keepLocalListener":  cfg.KeepLocalListener,
		"sharedSsoSessions":  cfg.SharedSSOSessions,
		"sharedSsoActive":    m.SharedSSOSessionsActive(),
		"sharedSsoRestart":   m.SharedSSORestartRequired(),
		"healthDisabled":     cfg.HealthDisabled,
		"healthAllow":        cfg.HealthAllow,
		"healthPath":         HealthPath,
		"allowLocalEdits":    m.opt.AllowLocalEdits,
		"nodeId":             m.opt.NodeID,
		"version":            m.opt.Version,
		"readOnly":           cfg.Role == RoleFollower && !m.opt.AllowLocalEdits,
		"legacyMode":         cfg.Role == RolePrimary || cfg.Role == RoleFollower,
		"fleet":              m.FleetInfo(),
	}
	if cfg.Role == RoleFollower {
		out["follower"] = m.Status()
	}
	if cfg.Role == RolePrimary {
		if v, err := m.CurrentSnapshotVersion(); err == nil {
			out["snapshotVersion"] = v
		}
		out["nodes"] = m.Nodes()
	}
	writeJSON(w, out)
}

// HandleConfig applies configuration changes (POST form fields).
func (m *Manager) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	r.ParseForm()
	var u ConfigUpdate
	has := func(k string) (string, bool) {
		if _, ok := r.PostForm[k]; !ok {
			return "", false
		}
		return strings.TrimSpace(r.PostForm.Get(k)), true
	}
	if v, ok := has("role"); ok {
		u.Role = &v
	}
	if v, ok := has("secret"); ok && v != "" {
		if m.secretFlag {
			writeErr(w, "the cluster secret is set by -cluster_secret and cannot be changed here")
			return
		}
		u.Secret = &v
	}
	if v, ok := has("primaryUrl"); ok {
		u.PrimaryURL = &v
	}
	if v, ok := has("primaryFingerprint"); ok {
		u.PrimaryFingerprint = &v
	}
	if v, ok := has("syncInterval"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, "syncInterval must be a number of seconds")
			return
		}
		u.SyncIntervalSeconds = &n
	}
	if v, ok := has("syncCerts"); ok {
		b := v == "true"
		if b && !m.Config().SyncCerts {
			//SyncCerts ships the TLS private keys from the primary to every follower: explicit acknowledge required
			if r.PostForm.Get("ackSyncCerts") != "true" {
				writeErr(w, "Syncing certificates sends TLS PRIVATE KEYS to the followers. Confirm that you want this by sending ackSyncCerts=true.")
				return
			}
		}
		u.SyncCerts = &b
	}
	if v, ok := has("syncSettings"); ok {
		b := v == "true"
		if b && !m.Config().SyncSettings {
			if m.opt.ExportSettings == nil {
				writeErr(w, "this build cannot sync settings")
				return
			}
			//SyncSettings ships password hashes, 2FA secrets and SSO client secrets to every follower: explicit acknowledge required
			if r.PostForm.Get("ackSyncSettings") != "true" {
				writeErr(w, "Syncing settings sends the SSO portal users (password hashes, 2FA secrets) and the SSO provider client secrets to the followers. Confirm that you want this by sending ackSyncSettings=true.")
				return
			}
		}
		u.SyncSettings = &b
	}
	if v, ok := has("keepLocalListener"); ok {
		b := v == "true"
		u.KeepLocalListener = &b
	}
	if v, ok := has("sharedSsoSessions"); ok {
		b := v == "true"
		u.SharedSSOSessions = &b
	}
	if v, ok := has("healthDisabled"); ok {
		b := v == "true"
		u.HealthDisabled = &b
	}
	if v, ok := has("healthAllow"); ok {
		list := []string{}
		for _, e := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == '\n' || c == ' ' }) {
			list = append(list, e)
		}
		u.HealthAllow = &list
	}
	if err := m.Update(u); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, "ok")
}

// HandleGenerateSecret creates a new secret, stores it and returns it once.
func (m *Manager) HandleGenerateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	if m.secretFlag {
		writeErr(w, "the cluster secret is set by -cluster_secret and cannot be changed here")
		return
	}
	s, err := GenerateSecret()
	if err != nil {
		writeErr(w, "cannot generate secret")
		return
	}
	if err := m.Update(ConfigUpdate{Secret: &s}); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, map[string]any{"secret": s, "fingerprint": Fingerprint(s), "restartRequired": m.RestartRequired()})
}

// HandleSyncNow runs a follower sync immediately.
func (m *Manager) HandleSyncNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	force := r.PostFormValue("force") == "true"
	if err := m.SyncOnce(ctx, force); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, m.Status())
}

// HandleNodes lists the followers seen by this primary.
func (m *Manager) HandleNodes(w http.ResponseWriter, r *http.Request) {
	if m.Role() != RolePrimary {
		writeJSON(w, []NodeInfo{})
		return
	}
	writeJSON(w, m.Nodes())
}

// Prefixes of admin APIs that change synced objects. A follower refuses
// non-GET requests to them (primary wins) unless -cluster_allow_local_edits.
var syncedPrefixes = []string{
	"/api/redirect/", "/api/access/", "/api/blacklist/", "/api/whitelist/",
	"/api/quickban/", "/api/pathrule/", "/api/streamprox/", "/api/trustedproxy/",
	"/api/acme/autoRenew/", "/api/conf/import",
}

// Node-local proxy settings that are stored in the database, not synced.
var nodeLocalProxyPaths = map[string]bool{
	"/api/proxy/enable": true, "/api/proxy/setIncoming": true, "/api/proxy/useHttpsRedirect": true,
	"/api/proxy/listenPort80": true, "/api/proxy/httpListenAddr": true, "/api/proxy/developmentMode": true, "/api/proxy/proxyProtocol": true,
	"/api/proxy/quic": true, "/api/proxy/timeouts": true, "/api/proxy/tlscheck": true,
	"/api/proxy/requestIsProxied": true, "/api/proxy/ops/globalerrors": true, "/api/proxy/ops/errorpreview": true,
	"/api/proxy/templates/save": true, "/api/proxy/templates/delete": true,
}

// Listener settings a follower receives with the settings sync unless it keeps
// its own (Config.KeepLocalListener).
var syncedListenerPaths = map[string]bool{
	"/api/proxy/setIncoming": true, "/api/proxy/useHttpsRedirect": true, "/api/proxy/listenPort80": true,
	"/api/cert/tls": true, "/api/cert/tlsMinVersion": true, "/api/cert/tlsCipherProfile": true,
}

// isSyncedSettingsWrite reports whether a write targets settings that came
// with the settings sync: the SSO providers, the ZorxAuth users and options
// and, unless the node keeps its own, the listener settings.
func isSyncedSettingsWrite(p string, keepLocalListener bool) bool {
	if strings.HasPrefix(p, "/api/sso/") {
		return true
	}
	return !keepLocalListener && syncedListenerPaths[p]
}

// isSyncedWrite reports whether a request would modify synced state.
func (m *Manager) isSyncedWrite(r *http.Request, syncCerts bool) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	p := r.URL.Path
	m.mu.RLock()
	settingsSynced, keepLocal := m.status.SettingsSynced, m.cfg.KeepLocalListener
	m.mu.RUnlock()
	if settingsSynced && isSyncedSettingsWrite(p, keepLocal) {
		return true
	}
	if strings.HasPrefix(p, "/api/proxy/") {
		return !nodeLocalProxyPaths[p]
	}
	for _, pre := range syncedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	if syncCerts && strings.HasPrefix(p, "/api/cert/") {
		return true
	}
	return false
}

// GuardLocalEdits wraps the admin handler: on a follower, writes to synced
// objects are refused with 403 (primary wins).
func (m *Manager) GuardLocalEdits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fleet node: objects the hub manages are read-only, node local ones stay editable.
		if m.Role() == RoleNode {
			if what := m.fleetBlocks(r); what != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Managed by hub (" + what + "). Change it on the Fleet hub; node local objects can still be edited here.",
				})
				return
			}
		}
		if m.opt.AllowLocalEdits {
			next.ServeHTTP(w, r)
			return
		}
		m.mu.RLock()
		certsSynced := m.status.CertsSynced
		m.mu.RUnlock()
		if m.Role() == RoleFollower && m.isSyncedWrite(r, certsSynced) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "This node is a cluster follower. Configuration is managed by the primary; make this change there (or start with -cluster_allow_local_edits).",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
