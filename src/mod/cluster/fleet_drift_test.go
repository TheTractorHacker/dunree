package cluster

import (
	"encoding/json"
	"strings"
	"testing"
)

func nodeView(e *fleetEnv, id string) NodeView {
	for _, n := range e.hub.hub.Overview()["nodes"].([]NodeView) {
		if n.ID == id {
			return n
		}
	}
	e.t.Fatalf("node %s not in the overview", id)
	return NodeView{}
}

func TestFleetDriftOnTamperedNode(t *testing.T) {
	e := newFleetEnv(t)
	a := e.addNode("node-a", "edge")
	b := e.addNode("node-b", "edge")
	mustWrite(t, e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a.example.com","Upstream":"10.0.0.1:80","Password":"HUB-SECRET-PW"}`)
	e.setGroup("edge", []string{"proxy", "redirect", "access"})
	e.publish("edge", StrategyImmediate)
	for _, n := range []*fnode{a, b} {
		if err := n.sync(t); err != nil {
			t.Fatal(err)
		}
		n.heartbeat(t)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if v := nodeView(e, id); v.Drift || v.SyncState != "in-sync" || len(v.DriftScopes) != 0 {
			t.Fatalf("%s should be in sync right after applying: %+v", id, v)
		}
	}

	// only a credential field is changed on node-a: the non secret content is the same, scope stays in sync
	mustWrite(t, a.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a.example.com","Upstream":"10.0.0.1:80","Password":"LOCAL-OTHER-PW"}`)
	a.heartbeat(t)
	if v := nodeView(e, "node-a"); len(v.DriftScopes) != 0 {
		t.Fatalf("a credential only edit must not name a scope: %+v", v)
	}

	// the upstream is changed on node-b: drifted, and the scope is named
	mustWrite(t, b.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a.example.com","Upstream":"6.6.6.6:80","Password":"HUB-SECRET-PW"}`)
	b.heartbeat(t)
	v := nodeView(e, "node-b")
	if !v.Drift || v.SyncState != "drifted" || len(v.DriftScopes) != 1 || v.DriftScopes[0] != "proxy" || !strings.Contains(v.DriftReason, "proxy") {
		t.Fatalf("tampered node not reported as drifted in proxy: %+v", v)
	}
	if v := nodeView(e, "node-a"); v.DriftScopes != nil && len(v.DriftScopes) != 0 {
		t.Fatalf("untouched scopes must stay clean: %+v", v)
	}

	// a deleted managed file is drift as well
	mustWrite(t, a.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a.example.com","Upstream":"10.0.0.1:80","Password":"HUB-SECRET-PW"}`)
	mustWrite(t, a.dir, "redirect/r1.json", `[]`)
	a.heartbeat(t)
	if v := nodeView(e, "node-a"); len(v.DriftScopes) != 1 || v.DriftScopes[0] != "redirect" {
		t.Fatalf("redirect edit not detected: %+v", v)
	}

	// re-syncing repairs it
	if err := b.m.FleetSyncOnce(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	b.heartbeat(t)
	if v := nodeView(e, "node-b"); v.Drift || v.SyncState != "in-sync" {
		t.Fatalf("not repaired after a forced sync: %+v", v)
	}
}

// the heartbeat and the compared material never carry a secret
func TestFleetDriftHashesCarryNoSecrets(t *testing.T) {
	dir := t.TempDir()
	const pw, key = "SUPER-SECRET-PASSWORD", "PRIVKEYBODY123"
	mustWrite(t, dir, "proxy/a.config", `{"RootOrMatchingDomain":"a","Password":"`+pw+`","Upstream":"x"}`)
	mustWrite(t, dir, "certs/a.key", "-----BEGIN PRIVATE KEY-----\n"+key+"\n-----END PRIVATE KEY-----\n")
	mustWrite(t, dir, "certs/a.pem", "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n")
	managed := map[string][]string{"proxy": {"proxy/a.config"}, "certs": {"certs/a.key", "certs/a.pem", "certs/gone.pem"}}
	hs := localScopeHashes(dir, managed)
	raw, _ := json.Marshal(fleetHeartbeat{ScopeHashes: hs})
	for _, s := range []string{pw, key, "PRIVATE KEY", "Upstream"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("heartbeat leaks %q", s)
		}
	}
	for _, it := range []driftItem{
		{path: "proxy/a.config", data: []byte(`{"Password":"` + pw + `","Upstream":"x"}`)},
		{path: "certs/a.key", data: []byte("-----BEGIN PRIVATE KEY-----" + key)},
		{path: "certs/b.pem", data: []byte("-----BEGIN RSA PRIVATE KEY-----" + key)},
	} {
		if m := string(driftMaterial(it)); strings.Contains(m, pw) || strings.Contains(m, key) {
			t.Errorf("compared material of %s holds a secret: %s", it.path, m)
		}
	}
	// formatting and key order do not matter, a value change does
	a := hashDriftItems([]driftItem{{path: "proxy/a.config", data: []byte(`{"a":1,"b":{"c":2}}`)}})
	b := hashDriftItems([]driftItem{{path: "proxy/a.config", data: []byte("{ \"b\": {\"c\":2},\n \"a\": 1 }")}})
	c := hashDriftItems([]driftItem{{path: "proxy/a.config", data: []byte(`{"a":1,"b":{"c":3}}`)}})
	if a != b || a == c {
		t.Error("canonicalisation wrong")
	}
	// bounded and sanitised on the hub
	big := map[string]string{}
	for i := 0; i < 100; i++ {
		big[strings.Repeat("s", 40)+string(rune('a'+i%26))+strings.Repeat("x", i)] = strings.Repeat("h", 500)
	}
	for k, v := range sanitizeScopeHashes(big) {
		if len(k) > 24 || len(v) > 64 {
			t.Fatal("hash report not trimmed")
		}
	}
	if len(sanitizeScopeHashes(big)) > maxScopeHashes {
		t.Fatal("hash report not capped")
	}
}

func TestDriftedScopes(t *testing.T) {
	got := DriftedScopes(map[string]string{"a": "1", "b": "2", "z": "9"}, map[string]string{"a": "1", "b": "3", "c": "4"})
	if strings.Join(got, ",") != "b,z" {
		t.Fatalf("%v", got)
	}
	if len(DriftedScopes(nil, nil)) != 0 {
		t.Fatal("empty is in sync")
	}
}

// a scope the hub ships but the node never reported is unchecked, not drifted (upgrade window, older node)
func TestDriftedScopesTreatsAScopeAbsentOnTheNodeAsUnchecked(t *testing.T) {
	if got := DriftedScopes(map[string]string{}, map[string]string{"proxy": "1"}); len(got) != 0 {
		t.Fatalf("absent on the node must not be drift: %v", got)
	}
	if got := DriftedScopes(map[string]string{"proxy": "2"}, map[string]string{"proxy": "1"}); len(got) != 1 {
		t.Fatalf("a real mismatch must still be drift: %v", got)
	}
}

// converged hub and node, with a node local file the hub does not own: must report in-sync (no false alarm)
func TestFleetConvergedNodeWithLocalFileIsInSync(t *testing.T) {
	e := newFleetEnv(t)
	a := e.addNode("node-a", "edge")
	mustWrite(t, e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a.example.com","Upstream":"10.0.0.1:80"}`)
	mustWrite(t, a.dir, "proxy/local-only.config", `{"RootOrMatchingDomain":"local.example.com","Upstream":"10.9.9.9:80"}`)
	e.setGroup("edge", []string{"proxy", "redirect", "access"})
	e.publish("edge", StrategyImmediate)
	if err := a.sync(t); err != nil {
		t.Fatal(err)
	}
	a.heartbeat(t)
	if v := nodeView(e, "node-a"); v.Drift || v.SyncState != "in-sync" {
		t.Fatalf("a converged node with a local file must be in sync: %+v", v)
	}
}
