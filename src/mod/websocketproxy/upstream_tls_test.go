package websocketproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"imuslab.com/zoraxy/mod/dynamicproxy/upstreamtls"
	"imuslab.com/zoraxy/mod/dynamicproxy/upstreamtls/tlstest"
)

func wssBackend(t *testing.T, cert tls.Certificate, clientCAs *x509.CertPool) *url.URL {
	t.Helper()
	up := websocket.Upgrader{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if clientCAs != nil {
		s.TLS.ClientCAs = clientCAs
		s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	u, _ := url.Parse("wss://" + strings.TrimPrefix(s.URL, "https://"))
	return u
}

// roundTrip dials the proxy and sends one message through to the upstream
func roundTrip(t *testing.T, target *url.URL, o Options) bool {
	t.Helper()
	o.SkipOriginCheck = true
	proxy := httptest.NewServer(NewProxy(target, o))
	defer proxy.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http"), nil)
	if err != nil {
		return false
	}
	defer c.Close()
	if err := c.WriteMessage(websocket.TextMessage, []byte("hi")); err != nil {
		return false
	}
	_, msg, err := c.ReadMessage()
	return err == nil && string(msg) == "echo:hi"
}

func TestWebsocketUpstreamTLSPolicy(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	loop := []net.IP{net.ParseIP("127.0.0.1")}
	cert := ca.Issue(tlstest.Options{IPs: loop})
	target := wssBackend(t, cert, nil)
	pin := upstreamtls.SPKIHash(cert.Leaf)

	cases := []struct {
		name string
		o    Options
		want bool
	}{
		{"private CA accepted", Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM()}}, true},
		{"unknown CA rejected", Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: other.PEM()}}, false},
		{"no policy: private CA is not trusted", Options{}, false},
		{"skip verify unchanged", Options{SkipTLSValidation: true}, true},
		{"CA replaces skip verify", Options{SkipTLSValidation: true, UpstreamTLS: upstreamtls.Policy{CABundlePEM: other.PEM()}}, false},
		{"pin match", Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM(), PinsSHA256: []string{hex.EncodeToString(pin[:])}}}, true},
		{"pin mismatch", Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM(), PinsSHA256: []string{strings.Repeat("00", 32)}}}, false},
		{"invalid policy fails closed", Options{SkipTLSValidation: true, UpstreamTLS: upstreamtls.Policy{CABundlePEM: "junk"}}, false},
		{"SNI override that the certificate does not cover", Options{TLSServerName: "evil.internal", UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM()}}, false},
	}
	for _, tc := range cases {
		if got := roundTrip(t, target, tc.o); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// The wss path honors the SNI override (verification host name) like the HTTP path
func TestWebsocketHonorsSNIOverride(t *testing.T) {
	ca := tlstest.NewCA("good")
	cert := ca.Issue(tlstest.Options{DNS: []string{"app.internal"}}) //no IP SAN: only the override name verifies
	target := wssBackend(t, cert, nil)
	pol := upstreamtls.Policy{CABundlePEM: ca.PEM()}
	if roundTrip(t, target, Options{UpstreamTLS: pol}) {
		t.Fatal("verification against the IP must fail for a certificate without IP SAN")
	}
	if !roundTrip(t, target, Options{UpstreamTLS: pol, TLSServerName: "app.internal:8443"}) {
		t.Fatal("the SNI override (with a port, as stored in the rule) must be used for verification")
	}
}

func TestWebsocketPresentsClientCertificate(t *testing.T) {
	ca, clientCA := tlstest.NewCA("good"), tlstest.NewCA("clients")
	target := wssBackend(t, ca.Issue(tlstest.Options{IPs: []net.IP{net.ParseIP("127.0.0.1")}}), clientCA.Pool())
	clientCert := clientCA.Issue(tlstest.Options{Client: true})
	pol := upstreamtls.Policy{CABundlePEM: ca.PEM()}

	if roundTrip(t, target, Options{UpstreamTLS: pol}) {
		t.Fatal("the upstream demands a client certificate, a dial without one must fail")
	}
	cb := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil }
	if !roundTrip(t, target, Options{UpstreamTLS: pol, ClientCertificate: cb}) {
		t.Fatal("mTLS towards a wss upstream must work with a private CA")
	}
	//also with skip verify (no policy): the client certificate is presented too
	if !roundTrip(t, target, Options{SkipTLSValidation: true, ClientCertificate: cb}) {
		t.Fatal("client certificate must be presented with skip verify too")
	}
}

func TestWebsocketDefaultDialerStaysUntouchedByPolicy(t *testing.T) {
	ca := tlstest.NewCA("good")
	target := wssBackend(t, ca.Issue(tlstest.Options{IPs: []net.IP{net.ParseIP("127.0.0.1")}}), nil)
	roundTrip(t, target, Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM()}})
	if websocket.DefaultDialer.TLSClientConfig != nil || DefaultDialer.TLSClientConfig != nil {
		t.Fatal("a shared dialer was modified")
	}
}
