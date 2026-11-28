package cluster

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func newSimpleMgr(t *testing.T, addr string, rec *auditRec) *Manager {
	t.Helper()
	m, err := NewManager(Options{ConfDir: t.TempDir(), NodeID: "a", NodeName: "node-a", Version: "1.0", VIP: vipTestOptions(addr, rec)})
	if err != nil {
		t.Fatal(err)
	}
	m.Update(ConfigUpdate{HealthDisabled: boolPtr(false)})
	peerMu.Lock()
	peerCache = map[string]peerAnswer{}
	peerMu.Unlock()
	return m
}

func getJSON(t *testing.T, h http.HandlerFunc, path string) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "198.51.100.9:4000"
	h(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return out, w
}

const vipDocNoPass = `{"enabled":true,"vip":"192.0.2.10","prefix":24,"auth":"password",
"members":[{"label":"node-a","address":"192.0.2.11","priority":150},{"label":"node-b","address":"192.0.2.12","priority":100}]}`

func authPass(conf string) string {
	m := regexp.MustCompile(`auth_pass (\S+)`).FindStringSubmatch(conf)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestVIPGeneratePasswordOnce(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	// without the flag an enabled password setup with no password is refused, as before
	if errOf(vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDocNoPass}})) == "" {
		t.Fatal("missing password accepted")
	}
	w := vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDocNoPass}, "generatePassword": {"1"}})
	if errOf(w) != "" {
		t.Fatal(w.Body.String())
	}
	s1, _, _ := m.LoadVIPShared()
	if !regexp.MustCompile(`^[A-Za-z0-9]{8}$`).MatchString(s1.Password) {
		t.Fatalf("password %q", s1.Password)
	}
	// saving again never replaces it
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDocNoPass}, "generatePassword": {"1"}})
	s2, _, _ := m.LoadVIPShared()
	if s2.Password != s1.Password {
		t.Fatal("password was replaced")
	}
	// the page's masked config never shows it
	cw := httptest.NewRecorder()
	m.HandleVIPConfig(cw, httptest.NewRequest("GET", VIPRouteConfig, nil))
	if strings.Contains(cw.Body.String(), s1.Password) {
		t.Fatal("password leaked in the config")
	}
	// both servers' scripts carry the same password
	a, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=0")
	b, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
	pa, pb := authPass(a["keepalivedConf"].(string)), authPass(b["keepalivedConf"].(string))
	if pa == "" || pa != pb || pa != s1.Password {
		t.Fatalf("passwords differ: %q %q", pa, pb)
	}
	// the flag does nothing for other auth modes
	m2 := newSimpleMgr(t, "192.0.2.11/24", nil)
	doc := strings.Replace(vipDocNoPass, `"auth":"password"`, `"auth":"none"`, 1)
	vipPost(m2.HandleVIPShared, VIPRouteShared, url.Values{"config": {doc}, "generatePassword": {"1"}})
	if s, _, _ := m2.LoadVIPShared(); s.Password != "" {
		t.Error("password made for auth=none")
	}
}

func TestVIPMainField(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	doc := strings.Replace(vipDoc, `"prefix":24`, `"prefix":24,"main":"192.0.2.12","dhcpChecked":true`, 1)
	if e := errOf(vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {doc}, "password": {"Xb7kQ2mT"}})); e != "" {
		t.Fatal(e)
	}
	s, _, _ := m.LoadVIPShared()
	if s.Main != "192.0.2.12" || !s.DHCPChecked || s.Members[0].Priority != 100 || s.Members[1].Priority != 150 {
		t.Fatalf("%+v", s)
	}
	// the generated configs follow
	a, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript)
	if a["title"].(map[string]any)["role"] != "Backup server" {
		t.Errorf("title %v", a["title"])
	}
	// main must be a member: the field name comes back
	bad := strings.Replace(vipDoc, `"prefix":24`, `"prefix":24,"main":"192.0.2.99"`, 1)
	w := vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {bad}, "password": {"Xb7kQ2mT"}})
	var out map[string]string
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["field"] != "main" {
		t.Errorf("%s", w.Body.String())
	}
	// numbers by hand: no main, priorities as typed
	if e := errOf(vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}})); e != "" {
		t.Fatal(e)
	}
	if s, _, _ := m.LoadVIPShared(); s.Main != "" || s.Members[0].Priority != 150 {
		t.Errorf("manual mode: %+v", s)
	}
}

func TestVIPOldSettingsFileUnchanged(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	b, _ := os.ReadFile(m.vipPath())
	if strings.Contains(string(b), `"main"`) || strings.Contains(string(b), "dhcpChecked") {
		t.Fatalf("new keys in an old setup: %s", b)
	}
	// the classic endpoint still answers exactly as before
	g, _ := getJSON(t, m.HandleVIPGenerate, VIPRouteGenerate)
	if g["keepalivedConf"] == nil || g["fingerprint"] == nil {
		t.Fatalf("%v", g)
	}
}

func TestVIPScriptEndpoint(t *testing.T) {
	rec := &auditRec{}
	m := newSimpleMgr(t, "192.0.2.11/24", rec)
	if _, w := getJSON(t, m.HandleVIPScript, VIPRouteScript); errOf(w) == "" {
		t.Fatal("script before the first save")
	}
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	self, w := getJSON(t, m.HandleVIPScript, VIPRouteScript)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("cache header")
	}
	title := self["title"].(map[string]any)
	if title["label"] != "node-a" || title["address"] != "192.0.2.11" || title["role"] != "Main server" {
		t.Fatalf("title %v", title)
	}
	if !strings.Contains(self["script"].(string), "D_LABEL='node-a'") || len(self["guessed"].([]any)) != 0 {
		t.Error("self script")
	}
	// member index of this server = no guessing
	idx0, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=0")
	if len(idx0["guessed"].([]any)) != 0 {
		t.Errorf("own member guessed: %v", idx0["guessed"])
	}
	// the other member: guessed, then told by the peer
	other, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
	if g := other["guessed"].([]any); len(g) != 2 {
		t.Errorf("guessed %v", g)
	}
	m.opt.VIP.HTTPBody = func(u string) ([]byte, error) {
		if u != "http://192.0.2.12:8081/.dunree/health" {
			return nil, errors.New("unexpected " + u)
		}
		return []byte(`{"version":"1.0","vip":{"held":false,"keepalived":"yes","iface":"ens19","probe":"http://127.0.0.1:9100/.dunree/health"}}`), nil
	}
	peerMu.Lock()
	peerCache = map[string]peerAnswer{}
	peerMu.Unlock()
	told, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
	sc := told["script"].(string)
	if len(told["guessed"].([]any)) != 0 || !strings.Contains(sc, "D_IFACE='ens19'") || !strings.Contains(sc, "D_PROBE='http://127.0.0.1:9100/.dunree/health'") {
		t.Errorf("peer facts ignored: %v", told["guessed"])
	}
	// hostile peer facts are dropped (the script then guesses)
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) {
		return []byte(`{"version":"1.0","vip":{"iface":"x';id","probe":"http://127.0.0.1:1/;id/.dunree/health"}}`), nil
	}
	peerMu.Lock()
	peerCache = map[string]peerAnswer{}
	peerMu.Unlock()
	h, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
	if strings.Contains(h["script"].(string), "id'") || strings.Contains(h["script"].(string), ";id") || len(h["guessed"].([]any)) != 2 {
		t.Errorf("hostile peer facts reached the script")
	}
	// download
	_, dw := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?download=1")
	if !strings.HasPrefix(dw.Body.String(), "#!/bin/sh\n") || !strings.Contains(dw.Header().Get("Content-Disposition"), `dunree-floating-ip-node-a.sh"`) || !strings.HasPrefix(dw.Header().Get("Content-Type"), "text/x-shellscript") {
		t.Errorf("download: %v", dw.Header())
	}
	// audited
	n := 0
	for _, e := range rec.events {
		if strings.HasPrefix(e, "cluster.vip.generate") {
			n++
		}
		if strings.Contains(e, "Xb7kQ2mT") {
			t.Error("password in the audit log")
		}
	}
	if n < 4 {
		t.Errorf("audit events: %v", rec.events)
	}
	// bad member numbers
	for _, bad := range []string{"member=x", "member=-1", "member=99", "member=123"} {
		if _, w := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?"+bad); errOf(w) == "" {
			t.Errorf("%s accepted", bad)
		}
	}
	// a blocker is structured: health switched off
	m.Update(ConfigUpdate{HealthDisabled: boolPtr(true)})
	blk, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript)
	bl, ok := blk["blockers"].([]any)
	if !ok || len(bl) == 0 || !strings.Contains(bl[0].(map[string]any)["message"].(string), "health endpoint is switched off") {
		t.Errorf("blockers: %v", blk)
	}
}

func TestVIPScriptFieldBlockers(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	// a file that became invalid on disk (hand edit): the field and the member come back
	b, _ := os.ReadFile(m.vipPath())
	edited := regexp.MustCompile(`"priority":\s*100`).ReplaceAllString(string(b), `"priority":150`)
	if edited == string(b) {
		t.Fatalf("edit did not apply: %s", b)
	}
	os.WriteFile(m.vipPath(), []byte(edited), 0o600)
	out, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript)
	bl, ok := out["blockers"].([]any)
	if !ok || len(bl) != 1 {
		t.Fatalf("%v", out)
	}
	first := bl[0].(map[string]any)
	if first["field"] != "members[1].priority" || first["node"].(float64) != 1 || first["labelKey"] != "vip.field.member.priority" {
		t.Errorf("%v", first)
	}
}

func TestVIPSuggestEndpoint(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	dials := 0
	m.opt.VIP.Dial = func(addr string, _ time.Duration) (bool, bool) {
		dials++
		return strings.HasPrefix(addr, "192.0.2.10:"), false
	}
	post := func(vals url.Values, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", VIPRouteSuggest, strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = ip + ":1"
		w := httptest.NewRecorder()
		m.HandleVIPSuggest(w, r)
		return w
	}
	w := post(url.Values{}, "198.51.100.20")
	var res struct {
		Network    struct{ CIDR string } `json:"network"`
		Candidates []struct{ Address, Reason string }
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res.Network.CIDR != "192.0.2.0/24" || len(res.Candidates) != 3 || res.Candidates[0].Address != "192.0.2.13" {
		// .10 answers, .11 is this host, .12 is not excluded (no members yet)
		if res.Candidates[0].Address != "192.0.2.12" {
			t.Fatalf("%s", w.Body.String())
		}
	}
	if dials > 12*3 {
		t.Errorf("%d dials", dials)
	}
	for _, bad := range []string{"x'; id", "2001:db8::1", "192.0.2.300"} {
		if e := errOf(post(url.Values{"near": {bad}}, "198.51.100.21")); e == "" {
			t.Errorf("near=%q accepted", bad)
		}
	}
	if post(url.Values{}, "198.51.100.22").Code != 200 {
		t.Fatal("first call")
	}
	if r := httptest.NewRequest("GET", VIPRouteSuggest, nil); true {
		w := httptest.NewRecorder()
		m.HandleVIPSuggest(w, r)
		if errOf(w) == "" {
			t.Error("GET accepted")
		}
	}
	// the preflight limit applies: the 7th call within a minute is refused
	var last int
	for i := 0; i < 8; i++ {
		last = post(url.Values{}, "198.51.100.30").Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("no rate limit: %d", last)
	}
}

func TestVIPHealthBlock(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	serve := func(remote string) map[string]any {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", HealthPath, nil)
		r.RemoteAddr = remote
		m.Health().Serve(w, r, true, 1)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	// not configured: the health JSON is exactly what it was
	if _, has := serve("127.0.0.1:1")["vip"]; has {
		t.Fatal("vip block without the feature")
	}
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	blk, ok := serve("127.0.0.1:1")["vip"].(map[string]any)
	if !ok || blk["probe"] != "http://127.0.0.1:8081/.dunree/health" || blk["iface"] != "ens18" || blk["keepalived"] == nil {
		t.Fatalf("block %v", blk)
	}
	if _, has := serve("192.0.2.12:5555")["vip"]; !has {
		t.Error("member source got no block")
	}
	for _, src := range []string{"203.0.113.9:1", "192.0.2.77:1", "[2001:db8::9]:1"} {
		if _, has := serve(src)["vip"]; has {
			t.Errorf("%s got the block", src)
		}
	}
	// no secret anywhere in it
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", HealthPath, nil)
	r.RemoteAddr = "127.0.0.1:1"
	m.Health().Serve(w, r, true, 1)
	if strings.Contains(w.Body.String(), "Xb7kQ2mT") {
		t.Error("password in the health JSON")
	}
}

func TestVIPStatusNodes(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	nodes := func() []map[string]any {
		peerMu.Lock()
		peerCache = map[string]peerAnswer{}
		peerMu.Unlock()
		out, _ := getJSON(t, m.HandleVIPStatus, VIPRouteStatus)
		var ns []map[string]any
		for _, n := range out["nodes"].([]any) {
			ns = append(ns, n.(map[string]any))
		}
		return ns
	}
	// peer silent
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return nil, errors.New("no answer") }
	ns := nodes()
	if len(ns) != 2 || ns[0]["self"] != true || ns[0]["state"] != "waiting" || ns[1]["state"] != "unknown" || ns[1]["reachable"] != false {
		t.Fatalf("%v", ns)
	}
	// peer answers with an older Dunree: no vip block, other version
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(`{"status":"ok","version":"0.9"}`), nil }
	if ns = nodes(); ns[1]["state"] != "old-version" {
		t.Errorf("%v", ns[1])
	}
	// peer installed and holding, with the current settings
	cur := func() string {
		out, _ := getJSON(t, m.HandleVIPConfig, VIPRouteConfig)
		return out["fingerprint"].(string)
	}()
	body := `{"version":"1.0","vip":{"held":true,"keepalived":"yes","installed":"` + cur + `","iface":"ens18"}}`
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(body), nil }
	ns = nodes()
	if ns[1]["state"] != "holding" || ns[1]["settingsMatch"] != true || ns[0]["state"] != "waiting" {
		t.Errorf("%v", ns)
	}
	// peer on older settings
	body = `{"version":"1.0","vip":{"held":false,"keepalived":"yes","installed":"deadbeef"}}`
	if ns = nodes(); ns[1]["state"] != "outdated" || ns[1]["settingsMatch"] != false {
		t.Errorf("%v", ns[1])
	}
}

func TestVIPMainOldFollowerWarning(t *testing.T) {
	p := newPair(t, false)
	p.primary.opt.VIP = vipTestOptions("192.0.2.11/24", nil)
	p.follower.opt.Version = "0.9-old"
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	// an existing setup without main
	vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}, "ackOldFollowers": {"true"}})
	withMain := strings.Replace(vipDoc, `"prefix":24`, `"prefix":24,"main":"192.0.2.11"`, 1)
	w := vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {withMain}})
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["oldFollowers"] == nil {
		t.Fatalf("no warning for a follower that cannot read main: %s", w.Body.String())
	}
	// saving again without main stays quiet
	if e := errOf(vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}})); e != "" {
		t.Errorf("unexpected: %s", e)
	}
	// confirmed
	w = vipPost(p.primary.HandleVIPShared, VIPRouteShared, url.Values{"config": {withMain}, "ackOldFollowers": {"true"}})
	if errOf(w) != "" {
		t.Errorf("%s", w.Body.String())
	}
}

// The page offers this server's host name as its default name in a first
// setup, so the config answer has to carry it.
func TestVIPConfigNodeName(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", &auditRec{})
	cfg, _ := getJSON(t, m.HandleVIPConfig, VIPRouteConfig)
	if cfg["nodeName"] != "node-a" {
		t.Fatalf("nodeName = %v", cfg["nodeName"])
	}
}
