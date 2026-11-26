package cluster

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/cluster/vip"
)

type fakeIfs []vip.IfaceInfo

func (f fakeIfs) Interfaces() ([]vip.IfaceInfo, error) { return f, nil }

func hostWith(addr string) fakeIfs {
	return fakeIfs{{Name: "ens18", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix(addr)}}}
}

type auditRec struct{ events []string }

func vipTestOptions(addr string, rec *auditRec) VIPOptions {
	paths := vip.Paths{} // nothing exists: keepalived "not installed"
	return VIPOptions{
		Lister:   hostWith(addr),
		Paths:    &paths,
		Listener: func() vip.ListenerFacts { return vip.ListenerFacts{HealthPort: ":8081", InboundPort: 443} },
		HTTPGet:  func(string) (int, error) { return 200, nil },
		Dial:     func(string, time.Duration) (bool, bool) { return false, false },
		Audit: func(r *http.Request, event string, detail map[string]string) {
			if rec != nil {
				b, _ := json.Marshal(detail)
				rec.events = append(rec.events, event+" "+string(b))
			}
		},
	}
}

const vipDoc = `{"enabled":true,"vip":"192.0.2.10","prefix":24,"auth":"password",
"members":[{"label":"node-a","address":"192.0.2.11","priority":150},{"label":"node-b","address":"192.0.2.12","priority":100}]}`

func vipPost(h http.HandlerFunc, path string, vals url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func errOf(w *httptest.ResponseRecorder) string {
	var m map[string]any
	json.Unmarshal(w.Body.Bytes(), &m)
	if e, ok := m["error"].(string); ok {
		return e
	}
	return ""
}

func TestVIPSharedSaveAudit(t *testing.T) {
	rec := &auditRec{}
	m, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "a", Version: "1.0", VIP: vipTestOptions("192.0.2.11/24", rec)})
	if m.VIPExists() {
		t.Fatal("no file before the first save")
	}
	w := vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	if errOf(w) != "" || w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	fi, err := os.Stat(filepath.Join(m.opt.ConfDir, "ha", "vip.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("vip.json: %v %v", fi, err)
	}
	if len(rec.events) != 1 || !strings.HasPrefix(rec.events[0], "cluster.vip.shared ") {
		t.Fatalf("audit: %v", rec.events)
	}
	if strings.Contains(rec.events[0], "Xb7kQ2mT") {
		t.Fatal("the VRRP password reached the audit log")
	}
	// GET never returns the password
	gw := httptest.NewRecorder()
	m.HandleVIPConfig(gw, httptest.NewRequest("GET", VIPRouteConfig, nil))
	if strings.Contains(gw.Body.String(), "Xb7kQ2mT") || !strings.Contains(gw.Body.String(), `"passwordSet":true`) {
		t.Fatalf("config response: %s", gw.Body.String())
	}
	// empty password keeps the saved one
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {strings.Replace(vipDoc, `"prefix":24`, `"prefix":24,"vrid":60`, 1)}})
	s, _, _ := m.LoadVIPShared()
	if s.Password != "Xb7kQ2mT" || s.VRID != 60 {
		t.Fatalf("saved %+v", s)
	}
	// validation errors are HTTP 200 {error, field} like the other cluster handlers
	w = vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {strings.Replace(vipDoc, "192.0.2.10", "192.0.2.255", 1)}})
	if w.Code != 200 || errOf(w) == "" || !strings.Contains(w.Body.String(), `"field":"vip"`) {
		t.Fatalf("validation error shape: %d %s", w.Code, w.Body.String())
	}
	// the invalid save changed nothing
	if s2, _, _ := m.LoadVIPShared(); s2.VIP != "192.0.2.10" {
		t.Fatal("an invalid save changed the file")
	}
	// wrong method
	gw = httptest.NewRecorder()
	m.HandleVIPShared(gw, httptest.NewRequest("GET", VIPRouteShared, nil))
	if errOf(gw) == "" {
		t.Fatal("GET on shared must be refused")
	}
}

func TestVIPLocalOverridesStayInClusterJSON(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(Options{ConfDir: dir, NodeID: "a", VIP: vipTestOptions("192.0.2.11/24", nil)})
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"abc"}})
	w := vipPost(m.HandleVIPLocal, VIPRouteLocal, url.Values{"config": {`{"interface":"bond0","priorityOverride":90}`}})
	if errOf(w) != "" {
		t.Fatal(w.Body.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "cluster.json"))
	if !strings.Contains(string(b), "bond0") {
		t.Fatalf("cluster.json: %s", b)
	}
	if hb, _ := os.ReadFile(filepath.Join(dir, "ha", "vip.json")); strings.Contains(string(hb), "bond0") {
		t.Fatal("node-local fields leaked into the shared file")
	}
	// a reload keeps it
	m2, _ := NewManager(Options{ConfDir: dir, NodeID: "a"})
	if l := m2.VIPLocal(); l.Interface != "bond0" || l.PriorityOverride != 90 {
		t.Fatalf("%+v", l)
	}
	// invalid overrides are refused
	for _, bad := range []string{`{"interface":"eth0:1"}`, `{"sourceAddress":"192.0.2.99"}`, `{"healthTarget":"http://10.0.0.1:80"}`, `{"x":1}`, `{"priorityOverride":255}`} {
		if w := vipPost(m.HandleVIPLocal, VIPRouteLocal, url.Values{"config": {bad}}); errOf(w) == "" {
			t.Errorf("%s accepted", bad)
		}
	}
	// clearing removes the object
	vipPost(m.HandleVIPLocal, VIPRouteLocal, url.Values{"config": {`{}`}})
	if b, _ := os.ReadFile(filepath.Join(dir, "cluster.json")); strings.Contains(string(b), "vipLocal") {
		t.Fatalf("empty overrides must remove vipLocal: %s", b)
	}
}

func TestVIPGenerateAndStatusHandlers(t *testing.T) {
	m, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "a", Version: "1.0", VIP: vipTestOptions("192.0.2.11/24", nil)})
	gw := httptest.NewRecorder()
	m.HandleVIPGenerate(gw, httptest.NewRequest("GET", VIPRouteGenerate, nil))
	if errOf(gw) == "" {
		t.Fatal("generate before the first save must say so")
	}
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	gw = httptest.NewRecorder()
	m.HandleVIPGenerate(gw, httptest.NewRequest("GET", VIPRouteGenerate, nil))
	var out vip.Output
	json.Unmarshal(gw.Body.Bytes(), &out)
	if !strings.Contains(out.KeepalivedConf, "priority 150") || gw.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %v", gw.Body.String(), gw.Header())
	}
	// download
	gw = httptest.NewRecorder()
	m.HandleVIPGenerate(gw, httptest.NewRequest("GET", VIPRouteGenerate+"?download=1&member=1", nil))
	if !strings.Contains(gw.Header().Get("Content-Disposition"), `keepalived-node-b.conf`) || !strings.Contains(gw.Body.String(), "unicast_src_ip 192.0.2.12") {
		t.Fatalf("%v %s", gw.Header(), gw.Body.String())
	}
	for _, bad := range []string{"member=-1x", "member=999", "member=1%3Brm"} {
		gw = httptest.NewRecorder()
		m.HandleVIPGenerate(gw, httptest.NewRequest("GET", VIPRouteGenerate+"?"+bad, nil))
		if errOf(gw) == "" {
			t.Errorf("%s accepted", bad)
		}
	}
	// a blocker returns {error, blockers} and no config
	m.opt.VIP.Listener = func() vip.ListenerFacts { return vip.ListenerFacts{HealthPort: ":8081"} }
	m.Update(ConfigUpdate{HealthDisabled: boolPtr(true)})
	gw = httptest.NewRecorder()
	m.HandleVIPGenerate(gw, httptest.NewRequest("GET", VIPRouteGenerate, nil))
	if !strings.Contains(gw.Body.String(), `"blockers"`) || strings.Contains(gw.Body.String(), "keepalivedConf") {
		t.Fatalf("%s", gw.Body.String())
	}
	m.Update(ConfigUpdate{HealthDisabled: boolPtr(false)})
	// status: this node is a member, nothing installed, not holding
	sw := httptest.NewRecorder()
	m.HandleVIPStatus(sw, httptest.NewRequest("GET", VIPRouteStatus, nil))
	var st struct {
		Status struct {
			Held     bool   `json:"held"`
			IsMember bool   `json:"isMember"`
			Found    string `json:"keepalivedInstalled"`
		} `json:"status"`
	}
	json.Unmarshal(sw.Body.Bytes(), &st)
	if st.Status.Held || !st.Status.IsMember || st.Status.Found != "no" {
		t.Fatalf("%s", sw.Body.String())
	}
	// preflight
	pw := vipPost(m.HandleVIPPreflight, VIPRoutePreflight, url.Values{})
	if !strings.Contains(pw.Body.String(), `"checks"`) {
		t.Fatalf("%s", pw.Body.String())
	}
}

func boolPtr(b bool) *bool { return &b }

func TestVIPPreflightRateLimit(t *testing.T) {
	m, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "a", VIP: vipTestOptions("192.0.2.11/24", nil)})
	vipPreflightLimiter = NewRateLimiter(6, time.Minute)
	var last int
	for i := 0; i < 8; i++ {
		last = vipPost(m.HandleVIPPreflight, VIPRoutePreflight, url.Values{}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("7th and 8th preflight in a minute must be refused, got %d", last)
	}
	vipPreflightLimiter = NewRateLimiter(6, time.Minute)
}

func hasRoot(p *Payload, root string) bool {
	for _, r := range p.Roots {
		if r == root {
			return true
		}
	}
	return false
}

func TestVIPSyncRoundTrip(t *testing.T) {
	p := newPair(t, false)
	p.primary.opt.VIP = vipTestOptions("192.0.2.11/24", nil)
	p.follower.opt.VIP = vipTestOptions("192.0.2.12/24", nil)

	// before the first save: no ha root, snapshot as before
	pl, err := CollectFiles(p.pDir, false)
	if err != nil || hasRoot(pl, "ha") {
		t.Fatalf("ha root before the first save: %v %v", err, pl.Roots)
	}
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if p.follower.VIPExists() {
		t.Fatal("follower has ha/vip.json before the primary saved")
	}

	// the follower's own node-local override must survive
	if err := p.follower.SetVIPLocal(vip.Local{Interface: "ens19"}); err != nil {
		t.Fatal(err)
	}
	w := vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}, "ackOldFollowers": {"true"}})
	if errOf(w) != "" {
		t.Fatal(w.Body.String())
	}
	pl, _ = CollectFiles(p.pDir, false)
	if !hasRoot(pl, "ha") {
		t.Fatal("ha root missing after the save")
	}
	p.pClock.Add(time.Second)
	p.fClock.Add(time.Second)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	ps, _, _ := p.primary.LoadVIPShared()
	fs, exists, err := p.follower.LoadVIPShared()
	if err != nil || !exists || fs.VIP != "192.0.2.10" || len(fs.Members) != 2 || fs.Password != ps.Password {
		t.Fatalf("follower settings %+v %v %v", fs, exists, err)
	}
	if l := p.follower.VIPLocal(); l.Interface != "ens19" {
		t.Fatalf("node-local override lost in the sync: %+v", l)
	}
	// both nodes show the same fingerprint, each its own member
	cfgOf := func(m *Manager) map[string]any {
		gw := httptest.NewRecorder()
		m.HandleVIPConfig(gw, httptest.NewRequest("GET", VIPRouteConfig, nil))
		var out map[string]any
		json.Unmarshal(gw.Body.Bytes(), &out)
		return out
	}
	pc, fc := cfgOf(p.primary), cfgOf(p.follower)
	if pc["fingerprint"] == "" || pc["fingerprint"] != fc["fingerprint"] {
		t.Fatalf("fingerprints differ: %v %v", pc["fingerprint"], fc["fingerprint"])
	}
	if fc["sharedEditable"] != false || fc["source"] != "primary" || pc["sharedEditable"] != true {
		t.Fatalf("edit flags: %v", fc)
	}
	if fc["effective"].(map[string]any)["member"] != "node-b" || pc["effective"].(map[string]any)["member"] != "node-a" {
		t.Fatalf("each node must find itself: %v / %v", fc["effective"], pc["effective"])
	}

	// disabling on the primary reaches the follower (the root stays)
	vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {strings.Replace(vipDoc, `"enabled":true`, `"enabled":false`, 1)}, "ackOldFollowers": {"true"}})
	p.pClock.Add(time.Second)
	p.fClock.Add(time.Second)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if fs, _, _ := p.follower.LoadVIPShared(); fs.Enabled {
		t.Fatal("disable did not propagate")
	}
}

func TestVIPFollowerGuard(t *testing.T) {
	p := newPair(t, false)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	g := p.follower.GuardLocalEdits(next)
	do := func(method, path string) int {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}
	if c := do("POST", VIPRouteShared); c != 403 {
		t.Errorf("shared on a follower: %d", c)
	}
	for _, path := range []string{VIPRouteLocal, VIPRoutePreflight} {
		if c := do("POST", path); c != 204 {
			t.Errorf("POST %s on a follower: %d", path, c)
		}
	}
	if c := do("GET", VIPRouteConfig); c != 204 {
		t.Errorf("GET config: %d", c)
	}
	// defence in depth: the handler itself refuses even without the guard
	p.follower.opt.VIP = vipTestOptions("192.0.2.12/24", nil)
	w := vipPost(p.follower.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"abc"}})
	if w.Code != 403 {
		t.Errorf("handler on a follower: %d", w.Code)
	}
	if p.follower.VIPExists() {
		t.Error("a refused write created the file")
	}
	// primary and standalone are not restricted
	if c := func() int {
		w := httptest.NewRecorder()
		p.primary.GuardLocalEdits(next).ServeHTTP(w, httptest.NewRequest("POST", VIPRouteShared, nil))
		return w.Code
	}(); c != 204 {
		t.Errorf("primary: %d", c)
	}
	// -cluster_allow_local_edits lifts it
	lm, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "l", AllowLocalEdits: true, VIP: vipTestOptions("192.0.2.12/24", nil)})
	lm.Update(ConfigUpdate{Role: strPtr(RoleFollower), Secret: strPtr(testSecret), PrimaryURL: strPtr("http://127.0.0.1:1")})
	defer lm.Stop()
	if w := vipPost(lm.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"abc"}}); w.Code != 200 || errOf(w) != "" {
		t.Errorf("allow local edits: %d %s", w.Code, w.Body.String())
	}
}

func TestVIPSnapshotRejectsBadFile(t *testing.T) {
	good := FileEntry{Path: "ha/vip.json", Mode: 0o600, Data: []byte(`{"enabled":false}`)}
	for name, data := range map[string]string{
		"unknown field":   `{"enabled":true,"evil":1}`,
		"bad address":     `{"enabled":true,"vip":"192.0.2.10\n}","prefix":24,"auth":"none","members":[]}`,
		"bad label":       `{"enabled":false,"vip":"192.0.2.10","prefix":24,"members":[{"label":"a}","address":"192.0.2.11","priority":1}]}`,
		"not json object": `[]`,
	} {
		p := &Payload{Roots: []string{"ha"}, Files: []FileEntry{{Path: "ha/vip.json", Data: []byte(data)}}}
		p.ContentHash = HashFiles(p.Files)
		if err := ValidatePayload(p); err == nil {
			t.Errorf("%s: snapshot accepted", name)
		}
	}
	p := &Payload{Roots: []string{"ha"}, Files: []FileEntry{good}}
	p.ContentHash = HashFiles(p.Files)
	if err := ValidatePayload(p); err != nil {
		t.Errorf("good file: %v", err)
	}
	// only ha/vip.json is a valid entry in the root
	for _, path := range []string{"ha/other.json", "ha/sub/vip.json", "ha/../proxy/a.config", "ha"} {
		if validEntryPath(path, []string{"ha"}) {
			t.Errorf("%s accepted", path)
		}
	}
	if validEntryPath("ha/vip.json", baseRoots) {
		t.Error("ha is only valid when the snapshot declares the ha root")
	}
}

func TestVIPHeartbeatCompat(t *testing.T) {
	// an old heartbeat without the field still parses and leaves it nil
	var hb heartbeatBody
	if err := json.Unmarshal([]byte(`{"name":"n","version":"1","appliedVersion":3,"lastSyncAt":4,"lastError":""}`), &hb); err != nil || hb.VIP != nil {
		t.Fatalf("%+v %v", hb, err)
	}
	// a new body parses on a struct that does not know the field
	type oldBody struct {
		Name           string `json:"name"`
		Version        string `json:"version"`
		AppliedVersion int64  `json:"appliedVersion"`
	}
	b, _ := json.Marshal(heartbeatBody{Name: "n", VIP: &vip.HeartbeatFact{Held: true, Keepalived: vip.Yes}})
	var ob oldBody
	if err := json.Unmarshal(b, &ob); err != nil || ob.Name != "n" {
		t.Fatalf("%v", err)
	}
	// a node that does not use the feature sends no vip field at all
	if strings.Contains(string(mustJSON(heartbeatBody{Name: "n"})), "vip") {
		t.Fatal("unused feature must not change the heartbeat")
	}
	if sanitizeBeat(&vip.HeartbeatFact{Keepalived: "evil"}).Keepalived != vip.Unknown {
		t.Fatal("heartbeat values are clamped")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestVIPBeatAndSplitBrain(t *testing.T) {
	p := newPair(t, false)
	// the primary holds the VIP (the address is on its fake interface)
	h := hostWith("192.0.2.11/24")
	h[0].Addrs = append(h[0].Addrs, netip.MustParsePrefix("192.0.2.10/24"))
	p.primary.opt.VIP = vipTestOptions("192.0.2.11/24", nil)
	p.primary.opt.VIP.Lister = h
	vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"abc"}, "ackOldFollowers": {"true"}})
	if b := p.primary.vipBeat(); b == nil || !b.Held {
		t.Fatalf("beat %+v", b)
	}
	// follower also claims it: split brain
	p.primary.primary.mu.Lock()
	p.primary.primary.nodes["f1"] = &NodeInfo{ID: "f1", Name: "node-b", Version: "1.0", VIP: &vip.HeartbeatFact{Held: true, Keepalived: vip.Yes}, VIPSeen: p.pClock.Now().Unix()}
	p.primary.primary.mu.Unlock()
	w := httptest.NewRecorder()
	p.primary.HandleVIPStatus(w, httptest.NewRequest("GET", VIPRouteStatus, nil))
	var out struct {
		SplitBrain bool      `json:"splitBrain"`
		Peers      []vipPeer `json:"peers"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if !out.SplitBrain || len(out.Peers) != 2 {
		t.Fatalf("%s", w.Body.String())
	}
	// a stale report does not count
	p.primary.primary.mu.Lock()
	p.primary.primary.nodes["f1"].VIPSeen -= 100000
	p.primary.primary.mu.Unlock()
	w = httptest.NewRecorder()
	p.primary.HandleVIPStatus(w, httptest.NewRequest("GET", VIPRouteStatus, nil))
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.SplitBrain {
		t.Fatalf("stale report counted: %s", w.Body.String())
	}
}

func TestVIPOldFollowerAck(t *testing.T) {
	p := newPair(t, false)
	p.primary.opt.VIP = vipTestOptions("192.0.2.11/24", nil)
	p.primary.primary.mu.Lock()
	p.primary.primary.nodes["old"] = &NodeInfo{ID: "old", Name: "old-follower", Version: "0.9"}
	p.primary.primary.mu.Unlock()
	w := vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"abc"}})
	if !strings.Contains(errOf(w), "old-follower") || p.primary.VIPExists() {
		t.Fatalf("first save must ask for confirmation: %s", w.Body.String())
	}
	w = vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"abc"}, "ackOldFollowers": {"true"}})
	if errOf(w) != "" || !p.primary.VIPExists() {
		t.Fatalf("%s", w.Body.String())
	}
}

func TestDeriveVIPPassword(t *testing.T) {
	a, b := DeriveVIPPassword(testSecret), DeriveVIPPassword(testSecret)
	if a != b || len(a) != 8 || vip.ValidatePassword(a) != nil {
		t.Fatalf("%q", a)
	}
	if a == DeriveVIPPassword(testSecret+"x") || DeriveVIPPassword("") != "" {
		t.Fatal("derived password must depend on the secret")
	}
	// the key is separated from the other purposes
	if a == KeyMaterial(testSecret, "u", PurposeSyncSign)[:8] {
		t.Fatal("purpose separation")
	}
}

func TestVIPHealthPathInStep(t *testing.T) {
	if vip.HealthPath != HealthPath {
		t.Fatalf("vip.HealthPath %q != cluster.HealthPath %q", vip.HealthPath, HealthPath)
	}
	if !strings.Contains(LegacyHealthPath, "zoraxy") {
		t.Fatal("legacy health alias must stay")
	}
}
