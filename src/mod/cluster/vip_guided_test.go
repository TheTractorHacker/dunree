package cluster

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/cluster/vip"
)

// Tests of the review round "Floating IP: simple guided setup": what a peer may
// tell a script, servers that are not linked, a stopped proxy, and servers that
// were set up with the classic commands.

func resetPeers() {
	peerMu.Lock()
	peerCache = map[string]peerAnswer{}
	peerMu.Unlock()
}

func vipNodeStates(t *testing.T, m *Manager) []map[string]any {
	t.Helper()
	resetPeers()
	out, _ := getJSON(t, m.HandleVIPStatus, VIPRouteStatus)
	var ns []map[string]any
	for _, n := range out["nodes"].([]any) {
		ns = append(ns, n.(map[string]any))
	}
	return ns
}

// A peer can only point its script at its own Dunree. A host name, a foreign
// address and another member's address fall back to the guessed health check.
func TestVIPPeerProbeBaseNeverForeign(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	for _, probe := range []string{
		"http://evil.example.com:80/.dunree/health",
		"https://203.0.113.7:443/.dunree/health",
		"http://198.51.100.9:8081/.dunree/health",
		"http://192.0.2.11:8081/.dunree/health", // another member
		"http://127.0.0.1:0/.dunree/health",
		"http://127.0.0.1:99999/.dunree/health",
	} {
		body := `{"version":"1.0","vip":{"held":false,"keepalived":"yes","iface":"ens19","probe":"` + probe + `"}}`
		m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(body), nil }
		resetPeers()
		got, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
		sc, _ := got["script"].(string)
		host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(probe, "https://"), "http://"), "/.dunree/health")
		if strings.Contains(sc, host) || strings.Contains(got["keepalivedConf"].(string), host) {
			t.Errorf("%s reached the script", probe)
		}
		if !strings.Contains(sc, "D_PROBE='http://127.0.0.1:8081/.dunree/health'") {
			t.Errorf("%s: the guessed health check was not used", probe)
		}
	}
	// its own loopback and its own address are fine
	for _, probe := range []string{"http://127.0.0.1:9100/.dunree/health", "http://192.0.2.12:9100/.dunree/health", "http://[::1]:9100/.dunree/health"} {
		body := `{"version":"1.0","vip":{"iface":"ens19","probe":"` + probe + `"}}`
		m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(body), nil }
		resetPeers()
		got, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
		if !strings.Contains(got["script"].(string), "D_PROBE='"+probe+"'") {
			t.Errorf("%s was refused", probe)
		}
	}
}

// The peer's own priority override comes through, so the page makes the same
// script for it that it makes for itself.
func TestVIPPeerPriorityOverrideReported(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	doc := strings.Replace(vipDoc, `"prefix":24`, `"prefix":24,"main":"192.0.2.11"`, 1)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {doc}, "password": {"Xb7kQ2mT"}})
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) {
		return []byte(`{"version":"1.0","vip":{"iface":"ens18","probe":"http://127.0.0.1:8081/.dunree/health","prio":200}}`), nil
	}
	resetPeers()
	got, _ := getJSON(t, m.HandleVIPScript, VIPRouteScript+"?member=1")
	if !strings.Contains(got["keepalivedConf"].(string), "priority 200") || !strings.Contains(got["script"].(string), "D_ROLE='Main server'") {
		t.Errorf("the override of the peer was not used:\n%v", got["keepalivedConf"])
	}
	w := got["warnings"].([]any)
	if len(w) == 0 || !strings.Contains(w[len(w)-1].(string), "own priority") {
		t.Errorf("no warning: %v", w)
	}
	ns := vipNodeStates(t, m)
	if ns[1]["prio"] != float64(200) {
		t.Errorf("the status must carry the override of the peer: %v", ns[1])
	}
}

// A server that answers but sends no floating IP block holds no saved settings
// (the servers are not linked). Its state is "unknown", never "waiting".
func TestVIPPeerWithoutBlockIsUnknownNotWaiting(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(`{"status":"ok","version":"1.0"}`), nil }
	ns := vipNodeStates(t, m)
	if ns[1]["state"] != "unknown" || ns[1]["reachable"] != true {
		t.Errorf("%v", ns[1])
	}
	// another version is still said so
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(`{"status":"ok","version":"0.9"}`), nil }
	if ns = vipNodeStates(t, m); ns[1]["state"] != "old-version" {
		t.Errorf("%v", ns[1])
	}
}

// A peer whose proxy is stopped answers 503 with the same JSON. It is a fault
// ("its health check fails"), not an unreachable server.
func TestVIPPeerWithStoppedProxy(t *testing.T) {
	m := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	cur := func() string {
		out, _ := getJSON(t, m.HandleVIPConfig, VIPRouteConfig)
		return out["fingerprint"].(string)
	}()
	body := `{"status":"unavailable","version":"1.0","proxyRunning":false,"vip":{"held":false,"keepalived":"yes","installed":"` + cur + `"}}`
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(body), nil }
	ns := vipNodeStates(t, m)
	if ns[1]["state"] != "fault" || ns[1]["reachable"] != true {
		t.Errorf("%v", ns[1])
	}
	// the real fetcher reads a 503 body and refuses other codes
	for code, want := range map[int]bool{200: true, 503: true, 403: false, 404: false, 500: false, 302: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if code == 302 {
				http.Redirect(w, r, "http://203.0.113.9/", code)
				return
			}
			w.WriteHeader(code)
			w.Write([]byte(`{"version":"1.0"}`))
		}))
		b, err := vipHTTPBody(srv.URL)
		srv.Close()
		if (err == nil) != want || (want && !strings.Contains(string(b), "version")) {
			t.Errorf("status %d: err %v", code, err)
		}
	}
}

// A server set up with the classic commands has no marker, but its
// keepalived.conf carries the settings fingerprint. It is not "waiting".
func TestVIPOldInstallWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "keepalived")
	os.WriteFile(bin, []byte("x"), 0o755)
	os.MkdirAll(filepath.Join(dir, "proc/4242"), 0o755)
	os.WriteFile(filepath.Join(dir, "proc/4242/comm"), []byte("keepalived\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "pid"), []byte("4242\n"), 0o644)
	opts := vipTestOptions("192.0.2.11/24", nil)
	opts.Paths = &vip.Paths{KeepalivedBins: []string{bin}, PidFile: filepath.Join(dir, "pid"), ProcDir: filepath.Join(dir, "proc"),
		ConfFile: filepath.Join(dir, "keepalived.conf"), MarkerFile: filepath.Join(dir, "dunree-installed")}
	m, err := NewManager(Options{ConfDir: t.TempDir(), NodeID: "a", NodeName: "node-a", Version: "1.0", VIP: opts})
	if err != nil {
		t.Fatal(err)
	}
	m.Update(ConfigUpdate{HealthDisabled: boolPtr(false)})
	vipPost(m.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	cfg, _ := getJSON(t, m.HandleVIPConfig, VIPRouteConfig)
	fp := cfg["fingerprint"].(string)
	os.WriteFile(filepath.Join(dir, "keepalived.conf"), []byte("# Generated by Dunree 1.0 for member \"node-a\" (192.0.2.11). Settings fingerprint: "+fp+"\nvrrp_instance X {}\n"), 0o600)
	m.vipStatus.Invalidate()
	peer := `{"version":"1.0","vip":{"held":true,"keepalived":"yes","installed":"` + fp + `"}}`
	m.opt.VIP.HTTPBody = func(string) ([]byte, error) { return []byte(peer), nil }
	ns := vipNodeStates(t, m)
	if ns[0]["state"] != "standby" || ns[0]["installed"] != true || ns[0]["settingsMatch"] != true {
		t.Errorf("this server, set up by hand, must count as installed: %v", ns[0])
	}
	// the health block of this server says the same to its peer
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", HealthPath, nil)
	r.RemoteAddr = "192.0.2.12:5000"
	m.Health().Serve(w, r, true, 1)
	var doc map[string]any
	json.Unmarshal(w.Body.Bytes(), &doc)
	blk, _ := doc["vip"].(map[string]any)
	if blk == nil || blk["installed"] != fp {
		t.Errorf("block: %v", doc)
	}
}

// A server without saved settings answers from the marker its script left, so
// the other server's page can see its progress.
func TestVIPHealthBlockFromMarker(t *testing.T) {
	dir := t.TempDir()
	mk := filepath.Join(dir, "dunree-installed")
	opts := vipTestOptions("192.0.2.12/24", nil)
	opts.Paths = &vip.Paths{MarkerFile: mk, PidFile: filepath.Join(dir, "none")}
	m, err := NewManager(Options{ConfDir: t.TempDir(), NodeID: "b", NodeName: "node-b", Version: "1.0", VIP: opts})
	if err != nil {
		t.Fatal(err)
	}
	m.Update(ConfigUpdate{HealthDisabled: boolPtr(false)})
	serve := func(remote string) map[string]any {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", HealthPath, nil)
		r.RemoteAddr = remote
		m.Health().Serve(w, r, true, 1)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if _, has := serve("127.0.0.1:1")["vip"]; has {
		t.Fatal("a block without any marker")
	}
	os.WriteFile(mk, []byte("fingerprint=3f9a1c2e\nmember=192.0.2.12\nvip=192.0.2.10\npeers=192.0.2.11\n"), 0o644)
	blk, ok := serve("192.0.2.11:5000")["vip"].(map[string]any)
	if !ok || blk["installed"] != "3f9a1c2e" || blk["iface"] != "ens18" || blk["held"] != false {
		t.Fatalf("block %v", blk)
	}
	if _, has := serve("127.0.0.1:1")["vip"]; !has {
		t.Error("loopback got no block")
	}
	for _, src := range []string{"203.0.113.9:1", "192.0.2.77:1", "[2001:db8::9]:1"} {
		if _, has := serve(src)["vip"]; has {
			t.Errorf("%s got the block", src)
		}
	}
	// and the other server's page sees "installed", not "waiting"
	m2 := newSimpleMgr(t, "192.0.2.11/24", nil)
	vipPost(m2.HandleVIPShared, VIPRouteShared, url.Values{"config": {vipDoc}, "password": {"Xb7kQ2mT"}})
	cfg, _ := getJSON(t, m2.HandleVIPConfig, VIPRouteConfig)
	fp := cfg["fingerprint"].(string)
	os.WriteFile(mk, []byte("fingerprint="+fp+"\nmember=192.0.2.12\nvip=192.0.2.10\npeers=192.0.2.11\n"), 0o644)
	m2.opt.VIP.HTTPBody = func(string) ([]byte, error) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", HealthPath, nil)
		r.RemoteAddr = "192.0.2.11:5000"
		m.Health().Serve(w, r, true, 1)
		return w.Body.Bytes(), nil
	}
	ns := vipNodeStates(t, m2)
	if ns[1]["installed"] != true || ns[1]["settingsMatch"] != true || ns[1]["state"] == "waiting" || ns[1]["state"] == "unknown" {
		t.Errorf("the unlinked server must be seen through its marker: %v", ns[1])
	}
}
