package upstreamtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls/tlstest"
)

func newTLSServer(t *testing.T, cert tls.Certificate, clientCAs *x509.CertPool) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if clientCAs != nil {
		s.TLS.ClientCAs = clientCAs
		s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func dial(t *testing.T, s *httptest.Server, cfg *tls.Config) error {
	t.Helper()
	c, err := tls.Dial("tcp", strings.TrimPrefix(s.URL, "https://"), cfg)
	if err == nil {
		c.Close()
	}
	return err
}

func TestPrivateCAAcceptedUnknownCARejected(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	s := newTLSServer(t, ca.Issue(tlstest.Options{DNS: []string{"app.internal"}}), nil)

	cfg := &tls.Config{ServerName: "app.internal"}
	Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
	if err := dial(t, s, cfg); err != nil {
		t.Fatalf("private CA must be accepted: %v", err)
	}

	cfg = &tls.Config{ServerName: "app.internal"}
	Policy{CABundlePEM: other.PEM()}.Apply(cfg)
	if err := dial(t, s, cfg); err == nil {
		t.Fatal("a certificate from an unknown CA must be rejected")
	}
}

func TestBundleReplacesSystemRoots(t *testing.T) {
	ca := tlstest.NewCA("good")
	cfg := &tls.Config{}
	Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs not set")
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("policy must never leave skip-verify on")
	}
}

func TestWrongHostnameRejected(t *testing.T) {
	ca := tlstest.NewCA("good")
	s := newTLSServer(t, ca.Issue(tlstest.Options{DNS: []string{"app.internal"}}), nil)
	cfg := &tls.Config{ServerName: "evil.internal"}
	Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
	if err := dial(t, s, cfg); err == nil {
		t.Fatal("a certificate for another host name must be rejected even when the CA is trusted")
	}
}

func TestExpiredAndNotYetValidRejected(t *testing.T) {
	ca := tlstest.NewCA("good")
	for name, o := range map[string]tlstest.Options{
		"expired": {DNS: []string{"app.internal"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)},
		"notyet":  {DNS: []string{"app.internal"}, NotBefore: time.Now().Add(24 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour)},
	} {
		s := newTLSServer(t, ca.Issue(o), nil)
		cfg := &tls.Config{ServerName: "app.internal"}
		Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
		if err := dial(t, s, cfg); err == nil {
			t.Fatalf("%s certificate must be rejected", name)
		}
	}
}

func TestPins(t *testing.T) {
	ca := tlstest.NewCA("good")
	cert := ca.Issue(tlstest.Options{DNS: []string{"app.internal"}})
	s := newTLSServer(t, cert, nil)
	leafPin := SPKIHash(cert.Leaf)
	caPin := SPKIHash(ca.Cert)
	wrong := SPKIHash(tlstest.NewCA("x").Cert)

	try := func(pins ...string) error {
		cfg := &tls.Config{ServerName: "app.internal"}
		Policy{CABundlePEM: ca.PEM(), PinsSHA256: pins}.Apply(cfg)
		return dial(t, s, cfg)
	}
	if err := try(hex.EncodeToString(leafPin[:])); err != nil {
		t.Fatalf("leaf pin (hex) must match: %v", err)
	}
	if err := try("sha256//" + base64.StdEncoding.EncodeToString(leafPin[:])); err != nil {
		t.Fatalf("leaf pin (curl base64) must match: %v", err)
	}
	//the server only sends the leaf, but the verified chain includes the CA, a CA pin is the usual "pin the issuer"
	if err := try(hex.EncodeToString(caPin[:])); err != nil {
		t.Fatalf("CA pin must match through the verified chain: %v", err)
	}
	if err := try(hex.EncodeToString(wrong[:])); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a mismatching pin must be refused, got %v", err)
	}
	if err := try(hex.EncodeToString(wrong[:]), hex.EncodeToString(leafPin[:])); err != nil {
		t.Fatalf("any one of several pins may match: %v", err)
	}
}

// a pin never replaces chain verification: a matching pin on a certificate from an untrusted CA is still refused
func TestPinDoesNotBypassChainVerification(t *testing.T) {
	ca, rogue := tlstest.NewCA("good"), tlstest.NewCA("rogue")
	cert := rogue.Issue(tlstest.Options{DNS: []string{"app.internal"}})
	s := newTLSServer(t, cert, nil)
	pin := SPKIHash(cert.Leaf)
	cfg := &tls.Config{ServerName: "app.internal"}
	Policy{CABundlePEM: ca.PEM(), PinsSHA256: []string{hex.EncodeToString(pin[:])}}.Apply(cfg)
	if err := dial(t, s, cfg); err == nil {
		t.Fatal("a pinned key from an untrusted chain must still be rejected")
	}
	//pin only (system roots): the rogue certificate is not trusted either
	cfg = &tls.Config{ServerName: "app.internal"}
	Policy{PinsSHA256: []string{hex.EncodeToString(pin[:])}}.Apply(cfg)
	if err := dial(t, s, cfg); err == nil {
		t.Fatal("pin without a CA must not turn a self-issued certificate into a trusted one")
	}
}

func TestSelfSignedLeafAsTrustAnchorWithPin(t *testing.T) {
	ca := tlstest.NewCA("selfsigned-server")
	//a self-signed certificate that is its own CA and also serves
	key := ca.Key
	cert := tls.Certificate{Certificate: [][]byte{ca.DER}, PrivateKey: key, Leaf: ca.Cert}
	_ = cert
	//(CA certs without SANs do not satisfy host name checks: documented, the test asserts the refusal)
	s := newTLSServer(t, cert, nil)
	cfg := &tls.Config{ServerName: "app.internal"}
	Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
	if err := dial(t, s, cfg); err == nil {
		t.Fatal("host name verification must stay on for a self signed server certificate")
	}
}

func TestInvalidPolicyFailsClosed(t *testing.T) {
	ca := tlstest.NewCA("good")
	s := newTLSServer(t, ca.Issue(tlstest.Options{DNS: []string{"app.internal"}}), nil)
	for name, p := range map[string]Policy{
		"garbage bundle": {CABundlePEM: "not pem"},
		"bad pin":        {PinsSHA256: []string{"zzz"}},
	} {
		cfg := &tls.Config{ServerName: "app.internal", InsecureSkipVerify: true}
		p.Apply(cfg)
		if cfg.InsecureSkipVerify {
			t.Fatalf("%s: skip-verify must be cleared", name)
		}
		if err := dial(t, s, cfg); err == nil {
			t.Fatalf("%s: connection must be refused", name)
		}
	}
}

func TestMutualTLSStillWorks(t *testing.T) {
	ca := tlstest.NewCA("good")
	clientCA := tlstest.NewCA("clients")
	s := newTLSServer(t, ca.Issue(tlstest.Options{DNS: []string{"app.internal"}}), clientCA.Pool())
	clientCert := clientCA.Issue(tlstest.Options{Client: true})

	cfg := &tls.Config{ServerName: "app.internal", Certificates: []tls.Certificate{clientCert}}
	Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
	if err := dial(t, s, cfg); err != nil {
		t.Fatalf("mTLS with a private CA must work: %v", err)
	}
	cfg = &tls.Config{ServerName: "app.internal"}
	Policy{CABundlePEM: ca.PEM()}.Apply(cfg)
	c, err := tls.Dial("tcp", strings.TrimPrefix(s.URL, "https://"), cfg)
	if err == nil {
		//TLS 1.3 reports a missing client certificate on first read
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("server must refuse a client without certificate")
	}
}

func TestParseBundle(t *testing.T) {
	ca := tlstest.NewCA("good")
	_, infos, err := ParseBundle(ca.PEM()+ca.PEM(), time.Now())
	if err != nil || len(infos) != 2 {
		t.Fatalf("bundle: %v %v", infos, err)
	}
	if !infos[0].IsCA || !infos[0].SelfSigned || len(infos[0].Fingerprint) != 95 || len(infos[0].SPKIPin) != 64 {
		t.Fatalf("details wrong: %+v", infos[0])
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
	for name, in := range map[string]string{
		"empty":       "",
		"text":        "hello",
		"private key": ca.PEM() + keyPEM,
		"broken cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})),
		"huge":        strings.Repeat("A", MaxBundleBytes+1),
	} {
		if _, _, err := ParseBundle(in, time.Now()); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestNormalizePin(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 0xab
	h := hex.EncodeToString(raw)
	for _, in := range []string{h, strings.ToUpper(h), base64.StdEncoding.EncodeToString(raw), "sha256//" + base64.StdEncoding.EncodeToString(raw), base64.URLEncoding.EncodeToString(raw)} {
		got, err := NormalizePin(in)
		if err != nil || got != h {
			t.Fatalf("%q -> %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), "sha256//short"} {
		if _, err := NormalizePin(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestZeroPolicyIsInactive(t *testing.T) {
	if (Policy{}).Active() || (Policy{}).Key() != "" {
		t.Fatal("zero policy must be inactive")
	}
	_ = net.IP{}
}
