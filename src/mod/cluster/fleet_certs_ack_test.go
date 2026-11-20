package cluster

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postForm(h http.HandlerFunc, path string, v url.Values) (int, string) {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code, w.Body.String()
}

func TestCertsScopeRequiresAcknowledgement(t *testing.T) {
	e := newFleetEnv(t)
	n := e.addNode("node-a", "edge")
	hub := e.hub
	call := func(action string, v url.Values) string {
		_, body := postForm(hub.HandleFleetHub, FleetAPIPrefix+action, v)
		return body
	}
	refused := func(body string) bool { return strings.Contains(body, "PRIVATE KEYS") }

	// group
	g := url.Values{"name": {"edge"}, "scopes": {"proxy,certs"}}
	if b := call("groupSet", g); !refused(b) {
		t.Fatalf("certs scope enabled without acknowledgement: %s", b)
	}
	if hub.hub.groupCertsEnabled("edge") {
		t.Fatal("the refused request changed the group")
	}
	g.Set("ackCerts", "false")
	if b := call("groupSet", g); !refused(b) {
		t.Fatalf("ackCerts=false accepted: %s", b)
	}
	g.Set("ackCerts", "true")
	if b := call("groupSet", g); refused(b) || strings.Contains(b, "error") {
		t.Fatalf("acknowledged request refused: %s", b)
	}
	if !hub.hub.groupCertsEnabled("edge") {
		t.Fatal("certs scope not enabled after acknowledgement")
	}
	// the acknowledgement is audited
	found := false
	for _, a := range hub.hub.AuditLog(50) {
		if a.Action == "certs.ack" && strings.Contains(a.Target, "edge") {
			found = true
		}
	}
	if !found {
		t.Error("no audit entry for the acknowledgement")
	}
	// saving again while it is already on does not need a second confirmation (nothing new is enabled)
	g.Del("ackCerts")
	if b := call("groupSet", g); refused(b) {
		t.Fatalf("an unchanged certs scope was refused again: %s", b)
	}
	// removing certs never needs it
	if b := call("groupSet", url.Values{"name": {"edge"}, "scopes": {"proxy"}}); refused(b) {
		t.Fatalf("turning certs off was refused: %s", b)
	}

	// node override
	ns := url.Values{"id": {"node-a"}, "scopes": {"proxy,certs"}}
	if b := call("nodeScopes", ns); !refused(b) {
		t.Fatalf("node certs override without ack: %s", b)
	}
	if hub.hub.nodeCertsEnabled("node-a") {
		t.Fatal("node changed by the refused request")
	}
	ns.Set("ackCerts", "true")
	if b := call("nodeScopes", ns); refused(b) {
		t.Fatalf("acknowledged node override refused: %s", b)
	}
	if !hub.hub.nodeCertsEnabled("node-a") {
		t.Fatal("node override not applied")
	}
	_ = n

	// capturing certificates
	st := url.Values{"keepVersions": {"10"}, "heartbeatSecs": {"20"}, "healthGraceSec": {"30"}, "captureCerts": {"true"}}
	if b := call("settings", st); !refused(b) {
		t.Fatalf("captureCerts without ack: %s", b)
	}
	if hub.hub.captureCertsEnabled() {
		t.Fatal("setting changed by refused request")
	}
	st.Set("ackCerts", "true")
	if b := call("settings", st); refused(b) {
		t.Fatalf("acknowledged settings refused: %s", b)
	}
	if !hub.hub.captureCertsEnabled() {
		t.Fatal("captureCerts not set")
	}
	// other settings changes with captureCerts left on need no new ack
	st.Del("ackCerts")
	st.Set("keepVersions", "12")
	if b := call("settings", st); refused(b) {
		t.Fatalf("unrelated settings change refused: %s", b)
	}
}

func TestLegacySyncCertsRequiresAcknowledgement(t *testing.T) {
	p := newPair(t, false)
	body := func(v url.Values) string {
		_, b := postForm(p.primary.HandleConfig, "/api/cluster/config", v)
		return b
	}
	if b := body(url.Values{"syncCerts": {"true"}}); !strings.Contains(b, "PRIVATE KEYS") {
		t.Fatalf("syncCerts enabled without ack: %s", b)
	}
	if p.primary.Config().SyncCerts {
		t.Fatal("refused request changed the setting")
	}
	if b := body(url.Values{"syncCerts": {"true"}, "ackSyncCerts": {"true"}}); strings.Contains(b, "error") {
		t.Fatalf("acknowledged request refused: %s", b)
	}
	if !p.primary.Config().SyncCerts {
		t.Fatal("setting not applied")
	}
	// leaving it on while changing something else is fine, turning it off never needs the flag
	if b := body(url.Values{"syncCerts": {"true"}, "syncInterval": {"60"}}); strings.Contains(b, "error") {
		t.Fatalf("no-op re-enable refused: %s", b)
	}
	if b := body(url.Values{"syncCerts": {"false"}}); strings.Contains(b, "error") {
		t.Fatalf("turning off refused: %s", b)
	}
}

// the certs scope must not reach a node through the back door: moving it into a certs group, or clearing its override
func TestCertsAckAlsoCoversNodeGroupMoveAndOverrideClear(t *testing.T) {
	e := newFleetEnv(t)
	e.addNode("node-a", "plain")
	hub := e.hub
	call := func(action string, v url.Values) string {
		_, body := postForm(hub.HandleFleetHub, FleetAPIPrefix+action, v)
		return body
	}
	refused := func(body string) bool { return strings.Contains(body, "PRIVATE KEYS") }
	call("groupSet", url.Values{"name": {"plain"}, "scopes": {"proxy"}})
	call("groupSet", url.Values{"name": {"keys"}, "scopes": {"proxy,certs"}, "ackCerts": {"true"}})

	// move into the certs group
	if b := call("nodeGroup", url.Values{"id": {"node-a"}, "group": {"keys"}}); !refused(b) {
		t.Fatalf("a node was moved into a certs group without acknowledgement: %s", b)
	}
	if hub.hub.nodeCertsEnabled("node-a") {
		t.Fatal("the refused move changed the node")
	}
	if b := call("nodeGroup", url.Values{"id": {"node-a"}, "group": {"keys"}, "ackCerts": {"true"}}); refused(b) {
		t.Fatalf("acknowledged move refused: %s", b)
	}
	if !hub.hub.nodeCertsEnabled("node-a") {
		t.Fatal("move not applied")
	}
	found := false
	for _, a := range hub.hub.AuditLog(50) {
		if a.Action == "certs.ack" && strings.Contains(a.Target, "node-a") {
			found = true
		}
	}
	if !found {
		t.Error("the move was not recorded as a certs.ack")
	}

	// a node with a tight override, then the override is cleared while its group has certs
	call("nodeGroup", url.Values{"id": {"node-a"}, "group": {"plain"}})
	call("nodeScopes", url.Values{"id": {"node-a"}, "scopes": {"proxy"}})
	call("nodeGroup", url.Values{"id": {"node-a"}, "group": {"keys"}}) //override still says proxy only: nothing new in effect
	if hub.hub.nodeCertsEnabled("node-a") {
		t.Fatal("the override must keep the certs scope out")
	}
	if b := call("nodeScopes", url.Values{"id": {"node-a"}, "inherit": {"true"}}); !refused(b) {
		t.Fatalf("clearing the override into a certs group needs the acknowledgement: %s", b)
	}
	if hub.hub.nodeCertsEnabled("node-a") {
		t.Fatal("refused clear changed the node")
	}
	if b := call("nodeScopes", url.Values{"id": {"node-a"}, "inherit": {"true"}, "ackCerts": {"true"}}); refused(b) {
		t.Fatalf("acknowledged clear refused: %s", b)
	}
}
