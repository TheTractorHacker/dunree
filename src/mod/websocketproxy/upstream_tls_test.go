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

	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls"
	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls/tlstest"
	"github.com/gorilla/websocket"
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

// roundTripHost is roundTrip with a visitor request Host header, which names the site for an IP addressed upstream
func roundTripHost(t *testing.T, target *url.URL, o Options, host string) bool {
	t.Helper()
	o.SkipOriginCheck = true
	proxy := httptest.NewServer(NewProxy(target, o))
	defer proxy.Close()
	hdr := http.Header{}
	hdr.Set("Host", host)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http"), hdr)
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

// An IP addressed wss upstream whose certificate only carries DNS names: the request host is the verification name
// (and SNI), the same as the HTTP path, with hostname verification staying on
func TestWebsocketIPUpstreamUsesRequestHostAsSNI(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	cert := ca.Issue(tlstest.Options{DNS: []string{"app.test"}}) //SAN DNS only, no IP SAN
	target := wssBackend(t, cert, nil)
	pin := upstreamtls.SPKIHash(cert.Leaf)
	pinHex := hex.EncodeToString(pin[:])
	caPol := upstreamtls.Policy{CABundlePEM: ca.PEM()}
	pinPol := upstreamtls.Policy{CABundlePEM: ca.PEM(), PinsSHA256: []string{pinHex}}

	cases := []struct {
		name string
		o    Options
		host string
		want bool
	}{
		{"CA bundle, request host covered", Options{UpstreamTLS: caPol}, "app.test", true},
		{"CA bundle, request host with port", Options{UpstreamTLS: caPol}, "app.test:8443", true},
		{"CA bundle and pin, request host covered", Options{UpstreamTLS: pinPol}, "app.test", true},
		{"wrong host name still fails", Options{UpstreamTLS: caPol}, "evil.test", false},
		{"wrong host name fails with pin too", Options{UpstreamTLS: pinPol}, "evil.test", false},
		{"IP request host: nothing to verify the DNS-only certificate against", Options{UpstreamTLS: caPol}, "127.0.0.1", false},
		{"unknown CA still fails", Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: other.PEM()}}, "app.test", false},
		{"pin mismatch still fails", Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM(), PinsSHA256: []string{strings.Repeat("00", 32)}}}, "app.test", false},
		{"explicit override wins over the request host", Options{UpstreamTLS: caPol, TLSServerName: "app.test"}, "evil.test", true},
		{"explicit override that is not covered fails even if the request host is", Options{UpstreamTLS: caPol, TLSServerName: "evil.test"}, "app.test", false},
		{"CA replaces skip verify, wrong host fails", Options{SkipTLSValidation: true, UpstreamTLS: caPol}, "evil.test", false},
		{"skip verify without a policy unchanged (accepts anything)", Options{SkipTLSValidation: true}, "evil.test", true},
		{"no policy and no skip: unchanged (system roots, rejected)", Options{}, "app.test", false},
	}
	for _, tc := range cases {
		if got := roundTripHost(t, target, tc.o, tc.host); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// Hostname upstreams keep verifying the upstream host name: the request host must not replace it
func TestWebsocketHostnameUpstreamUnchanged(t *testing.T) {
	ca := tlstest.NewCA("good")
	o := Options{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM()}}
	if cfg := o.upstreamTLSConfig("backend.internal", "front.example.com"); cfg.ServerName != "" {
		t.Fatalf("hostname upstream: ServerName must stay empty (dial host verified), got %q", cfg.ServerName)
	}
	if cfg := o.upstreamTLSConfig("127.0.0.1", "front.example.com"); cfg.ServerName != "front.example.com" || cfg.InsecureSkipVerify {
		t.Fatalf("IP upstream: want request host with verification on, got %q skip=%v", cfg.ServerName, cfg.InsecureSkipVerify)
	}
	if cfg := (Options{}).upstreamTLSConfig("127.0.0.1", "front.example.com"); cfg != nil {
		t.Fatal("no TLS option: config must stay nil")
	}
	if cfg := (Options{SkipTLSValidation: true}).upstreamTLSConfig("127.0.0.1", "front.example.com"); cfg.ServerName != "" || !cfg.InsecureSkipVerify {
		t.Fatal("skip verify without a policy must be unchanged")
	}
	// end to end, hostname upstream: the certificate covers the dial host name only, an unrelated request host must not matter
	cert := ca.Issue(tlstest.Options{DNS: []string{"localhost"}})
	target := wssBackend(t, cert, nil)
	target.Host = "localhost:" + target.Port()
	if !roundTripHost(t, target, o, "unrelated.example.com") {
		t.Fatal("hostname upstream must verify the dial host name, not the request host")
	}
	// and a hostname upstream whose certificate does not cover its name still fails
	bad := ca.Issue(tlstest.Options{DNS: []string{"unrelated.example.com"}})
	target2 := wssBackend(t, bad, nil)
	target2.Host = "localhost:" + target2.Port()
	if roundTripHost(t, target2, o, "unrelated.example.com") {
		t.Fatal("hostname upstream must not be rescued by the request host")
	}
}
