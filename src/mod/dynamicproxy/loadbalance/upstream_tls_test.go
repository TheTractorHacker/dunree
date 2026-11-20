package loadbalance

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/dynamicproxy/upstreamtls"
	"imuslab.com/zoraxy/mod/dynamicproxy/upstreamtls/tlstest"
)

func tlsBackend(t *testing.T, cert tls.Certificate, clientCAs *x509.CertPool) string {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if clientCAs != nil {
		s.TLS.ClientCAs = clientCAs
		s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "https://")
}

// proxied sends one request through the dpcore proxy of the upstream and reports whether the upstream answered
func proxied(t *testing.T, u *Upstream) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
	u.proxy.ProxyHTTP(rec, req, &dpcore.ResponseRewriteRuleSet{ProxyDomain: u.OriginIpOrDomain, OriginalHost: "front.example.com", UseTLS: true})
	return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "ok")
}

// probed runs the active health prober of the same upstream
func probed(t *testing.T, u *Upstream) bool {
	t.Helper()
	p := newProber(u, ActiveHealthCheck{}.Normalized())
	defer p.close()
	return p.probe(t.Context()) == nil
}

func spkiHex(c tls.Certificate) string {
	h := upstreamtls.SPKIHash(c.Leaf)
	return hex.EncodeToString(h[:])
}

// The proxied traffic and the health prober must reach the same verdict for every trust configuration
func TestUpstreamTLSPolicyProxyAndProberAgree(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	loop := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	//For an upstream addressed by IP the proxy verifies against the requested site name (front.example.com, see dpcore
	//useRequestHostAsSNI), the prober against the address, so the certificate carries both
	good := ca.Issue(tlstest.Options{IPs: loop, DNS: []string{"app.internal", "front.example.com"}})
	ipOnlyHost := ca.Issue(tlstest.Options{DNS: []string{"other.internal"}}) //no IP SAN, no matching name
	expired := ca.Issue(tlstest.Options{IPs: loop, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})

	goodAddr := tlsBackend(t, good, nil)
	wrongHostAddr := tlsBackend(t, ipOnlyHost, nil)
	expiredAddr := tlsBackend(t, expired, nil)
	wrongPin := hex.EncodeToString(make([]byte, 32))

	cases := []struct {
		name string
		u    *Upstream
		sni  string
		want bool
	}{
		{"no policy: private CA is not trusted", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true}, "", false},
		{"skip verify unchanged", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, SkipCertValidations: true}, "", true},
		{"private CA accepted", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}, "", true},
		{"unknown CA rejected", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, TLSCABundlePEM: other.PEM()}, "", false},
		{"CA replaces skip verify (unknown CA still rejected)", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, SkipCertValidations: true, TLSCABundlePEM: other.PEM()}, "", false},
		{"wrong host name rejected", &Upstream{OriginIpOrDomain: wrongHostAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}, "", false},
		{"SNI override verifies against the override name", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}, "app.internal", true},
		{"SNI override that the certificate does not cover is rejected", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}, "evil.internal", false},
		{"expired rejected", &Upstream{OriginIpOrDomain: expiredAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}, "", false},
		{"pin match", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM(), TLSPinsSHA256: []string{spkiHex(good)}}, "", true},
		{"pin mismatch", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, TLSCABundlePEM: ca.PEM(), TLSPinsSHA256: []string{wrongPin}}, "", false},
		{"pin mismatch is not rescued by skip verify", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, SkipCertValidations: true, TLSCABundlePEM: ca.PEM(), TLSPinsSHA256: []string{wrongPin}}, "", false},
		{"invalid bundle fails closed, even with skip verify", &Upstream{OriginIpOrDomain: goodAddr, RequireTLS: true, SkipCertValidations: true, TLSCABundlePEM: "junk"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.u
			if err := u.StartProxy(tc.sni); err != nil {
				t.Fatal(err)
			}
			if got := proxied(t, u); got != tc.want {
				t.Errorf("proxied request: got %v want %v", got, tc.want)
			}
			if got := probed(t, u); got != tc.want {
				t.Errorf("health prober: got %v want %v", got, tc.want)
			}
		})
	}
}

func TestUpstreamTLSPolicyIgnoredWithoutTLS(t *testing.T) {
	u := &Upstream{TLSCABundlePEM: "junk"}
	if u.TLSPolicy().Active() {
		t.Fatal("policy must be inactive for a plain http upstream")
	}
	if err := (&Upstream{OriginIpOrDomain: "a:1", TLSCABundlePEM: "x"}).ValidateTransportOptions(); err == nil {
		t.Fatal("a CA bundle on a non-TLS upstream must be refused when saving")
	}
}

func TestUpstreamTLSPolicyMutualTLS(t *testing.T) {
	ca, clientCA := tlstest.NewCA("good"), tlstest.NewCA("clients")
	loop := []net.IP{net.ParseIP("127.0.0.1")}
	addr := tlsBackend(t, ca.Issue(tlstest.Options{IPs: loop, DNS: []string{"front.example.com"}}), clientCA.Pool())
	clientCert := clientCA.Issue(tlstest.Options{Client: true})

	old := UpstreamClientCertLoader
	defer func() { UpstreamClientCertLoader = old }()
	UpstreamClientCertLoader = func(string) (*tls.Certificate, error) { return &clientCert, nil }

	with := Upstream{OriginIpOrDomain: addr, RequireTLS: true, TLSCABundlePEM: ca.PEM(), ClientCertName: "c"}
	if err := with.StartProxy(""); err != nil {
		t.Fatal(err)
	}
	if !proxied(t, &with) || !probed(t, &with) {
		t.Error("private CA together with a client certificate must work (proxy and prober)")
	}
	without := Upstream{OriginIpOrDomain: addr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}
	if err := without.StartProxy(""); err != nil {
		t.Fatal(err)
	}
	if proxied(t, &without) || probed(t, &without) {
		t.Error("the upstream demands a client certificate, a request without one must fail")
	}
}

func TestUpstreamTLSValidationNormalizes(t *testing.T) {
	ca := tlstest.NewCA("good")
	u := &Upstream{OriginIpOrDomain: "a:1", RequireTLS: true, TLSCABundlePEM: "  " + ca.PEM() + "\n", TLSPinsSHA256: []string{"q80="}}
	if err := u.ValidateTransportOptions(); err == nil {
		t.Fatal("a pin that is not 32 bytes must be refused")
	}
	raw := make([]byte, 32)
	raw[0] = 0xff
	u = &Upstream{OriginIpOrDomain: "a:1", RequireTLS: true, TLSCABundlePEM: ca.PEM(), TLSPinsSHA256: []string{strings.ToUpper(hex.EncodeToString(raw)), hex.EncodeToString(raw)}}
	if err := u.ValidateTransportOptions(); err != nil {
		t.Fatal(err)
	}
	if len(u.TLSPinsSHA256) != 1 || u.TLSPinsSHA256[0] != hex.EncodeToString(raw) {
		t.Fatalf("pins not normalized: %v", u.TLSPinsSHA256)
	}
}

// The health check signature includes the policy, so changing it restarts the running probes
func TestHealthSignatureIncludesTLSPolicy(t *testing.T) {
	ca := tlstest.NewCA("good")
	mk := func(u *Upstream) string {
		cfg := &Config{}
		cfg.ActiveHealthCheck = &ActiveHealthCheck{Enabled: true}
		return healthSignature(cfg, []*Upstream{u})
	}
	a := &Upstream{OriginIpOrDomain: "a:1", RequireTLS: true}
	b := a.Clone()
	b.TLSCABundlePEM = ca.PEM()
	c := a.Clone()
	c.TLSPinsSHA256 = []string{strings.Repeat("ab", 32)}
	if mk(a) == mk(b) || mk(a) == mk(c) {
		t.Fatal("signature does not change with the TLS policy")
	}
}

// An IP addressed https upstream with a custom CA / pin and a DNS-only certificate: the probe verifies against the
// rule's primary domain, like the proxied HTTP traffic does with the request host
func TestProbeIPUpstreamUsesRuleHostAsSNI(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	cert := ca.Issue(tlstest.Options{DNS: []string{"app.test"}}) //no IP SAN
	addr := tlsBackend(t, cert, nil)
	probeWith := func(u *Upstream, sni, ruleHost string) bool {
		t.Helper()
		if err := u.StartProxy(sni); err != nil {
			t.Fatal(err)
		}
		p := newProberFor(u, ActiveHealthCheck{}.Normalized(), ruleHost)
		defer p.close()
		return p.probe(t.Context()) == nil
	}
	mk := func(mod func(*Upstream)) *Upstream {
		u := &Upstream{OriginIpOrDomain: addr, RequireTLS: true, TLSCABundlePEM: ca.PEM()}
		if mod != nil {
			mod(u)
		}
		return u
	}
	cases := []struct {
		name     string
		u        *Upstream
		sni      string
		ruleHost string
		want     bool
	}{
		{"CA bundle, rule host covered", mk(nil), "", "app.test", true},
		{"CA bundle and pin, rule host covered", mk(func(u *Upstream) { u.TLSPinsSHA256 = []string{spkiHex(cert)} }), "", "app.test", true},
		{"rule host with port", mk(nil), "", "app.test:8443", true},
		{"wrong host name still fails", mk(nil), "", "evil.test", false},
		{"wrong host name fails with a pin too", mk(func(u *Upstream) { u.TLSPinsSHA256 = []string{spkiHex(cert)} }), "", "evil.test", false},
		{"no rule host: verified against the IP, DNS-only certificate fails", mk(nil), "", "", false},
		{"wildcard rule host is no usable name", mk(nil), "", "*.test", false},
		{"explicit override wins over the rule host", mk(nil), "app.test", "evil.test", true},
		{"override not covered fails even if the rule host is", mk(nil), "evil.test", "app.test", false},
		{"unknown CA still fails", mk(func(u *Upstream) { u.TLSCABundlePEM = other.PEM() }), "", "app.test", false},
		{"pin mismatch still fails", mk(func(u *Upstream) { u.TLSPinsSHA256 = []string{hex.EncodeToString(make([]byte, 32))} }), "", "app.test", false},
		{"CA replaces skip verify, wrong host fails", mk(func(u *Upstream) { u.SkipCertValidations = true }), "", "evil.test", false},
		{"skip verify without a policy unchanged", &Upstream{OriginIpOrDomain: addr, RequireTLS: true, SkipCertValidations: true}, "", "evil.test", true},
		{"no policy and no skip unchanged (private CA untrusted)", &Upstream{OriginIpOrDomain: addr, RequireTLS: true}, "", "app.test", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeWith(tc.u, tc.sni, tc.ruleHost); got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

// Hostname upstreams keep verifying their own host name, the rule host is ignored
func TestProbeHostnameUpstreamUnchanged(t *testing.T) {
	ca := tlstest.NewCA("good")
	addr := tlsBackend(t, ca.Issue(tlstest.Options{DNS: []string{"localhost"}}), nil)
	_, port, _ := net.SplitHostPort(addr)
	u := &Upstream{OriginIpOrDomain: "localhost:" + port, RequireTLS: true, TLSCABundlePEM: ca.PEM()}
	if err := u.StartProxy(""); err != nil {
		t.Fatal(err)
	}
	if n := probeServerName(u, "unrelated.example.com"); n != "" {
		t.Fatalf("hostname upstream must not take the rule host, got %q", n)
	}
	p := newProberFor(u, ActiveHealthCheck{}.Normalized(), "unrelated.example.com")
	defer p.close()
	if err := p.probe(t.Context()); err != nil {
		t.Fatalf("hostname upstream probe: %v", err)
	}
	if n := probeServerName(&Upstream{OriginIpOrDomain: "127.0.0.1:1", RequireTLS: true}, "app.test"); n != "" {
		t.Fatalf("no CA/pin: nothing changes, got %q", n)
	}
}
