package websocketproxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"imuslab.com/zoraxy/mod/adminallow"
)

type memKV struct{}

func (memKV) Read(string, string, interface{}) error  { return nil }
func (memKV) Write(string, string, interface{}) error { return nil }

// Attack: a WebSocket rule whose upstream is the admin port. WebSocket requests skip the header rewrite of
// the normal proxy path, so no marker header could ever have protected them; the dial is refused instead.
func TestWebsocketCannotDialAdminPort(t *testing.T) {
	up := websocket.Upgrader{}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		mt, msg, err := c.ReadMessage()
		if err == nil {
			c.WriteMessage(mt, append([]byte("echo:"), msg...))
		}
	}))
	defer admin.Close()
	target, _ := url.Parse("ws" + strings.TrimPrefix(admin.URL, "http"))

	if !roundTrip(t, target, Options{}) {
		t.Fatal("baseline websocket proxying broken")
	}
	m, _ := adminallow.New(memKV{})
	if err := m.Set(adminallow.Settings{CIDRs: []string{"127.0.0.1"}}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(admin.Listener.Addr().String())
	adminallow.InstallDialGuard(m, ":"+port)
	defer adminallow.InstallDialGuard(nil, "")
	if roundTrip(t, target, Options{}) {
		t.Error("websocket proxy reached the admin port")
	}
	if roundTrip(t, target, Options{SkipTLSValidation: true}) {
		t.Error("websocket proxy (custom dialer) reached the admin port")
	}
}

// Existing configs: an SNI override (the rule's Host header overwrite) must not change wss:// verification
// unless an upstream trust option is configured.
func TestWebsocketSNIOverrideOnlyWithTrustOption(t *testing.T) {
	o := Options{TLSServerName: "app.internal"}
	if o.upstreamTLSConfig() != nil {
		t.Error("SNI override alone changed the upstream TLS config of an existing rule")
	}
	o.SkipTLSValidation = true
	if cfg := o.upstreamTLSConfig(); cfg == nil || cfg.ServerName != "" || !cfg.InsecureSkipVerify {
		t.Errorf("skip-verify rule: SNI override leaked in or skip lost: %+v", cfg)
	}
}
