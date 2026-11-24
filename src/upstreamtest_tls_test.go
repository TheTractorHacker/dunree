package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/dynamicproxy/loadbalance"
	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls"
	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls/tlstest"
)

func TestUpstreamTestUsesTrustPolicy(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	cert := ca.Issue(tlstest.Options{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()
	addr := strings.TrimPrefix(s.URL, "https://")
	pin := upstreamtls.SPKIHash(cert.Leaf)

	res := testUpstreamWith(addr, upstreamtls.Policy{CABundlePEM: ca.PEM()}, "")
	if !res.OK || !res.TrustChecked || !res.TrustOK || res.Status != 200 {
		t.Fatalf("private CA: %+v", res)
	}
	res = testUpstreamWith(addr, upstreamtls.Policy{CABundlePEM: ca.PEM(), PinsSHA256: []string{hex.EncodeToString(pin[:])}}, "")
	if !res.OK || !res.TrustOK {
		t.Fatalf("pin match: %+v", res)
	}
	for name, pol := range map[string]upstreamtls.Policy{
		"unknown CA":   {CABundlePEM: other.PEM()},
		"pin mismatch": {CABundlePEM: ca.PEM(), PinsSHA256: []string{strings.Repeat("00", 32)}},
	} {
		res = testUpstreamWith(addr, pol, "")
		if res.OK || !res.TrustChecked || res.TrustOK || res.TrustError == "" {
			t.Fatalf("%s must fail the test: %+v", name, res)
		}
	}
	if res = testUpstreamWith(addr, upstreamtls.Policy{CABundlePEM: ca.PEM()}, "evil.example"); res.OK {
		t.Fatalf("a server name the certificate does not cover must fail: %+v", res)
	}
	//no policy: unchanged behavior (reachability test, self signed noted)
	if res = testUpstream(addr); !res.OK || !res.SelfSign || res.TrustChecked {
		t.Fatalf("no policy: %+v", res)
	}
}

func TestUpstreamTestHandlerPostPolicyAndTLSInspect(t *testing.T) {
	ca := tlstest.NewCA("good")
	cert := ca.Issue(tlstest.Options{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()
	addr := strings.TrimPrefix(s.URL, "https://")

	post := func(h http.HandlerFunc, vals url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	rec := post(HandleTestUpstream, url.Values{"url": {addr}, "cabundle": {ca.PEM()}})
	var res upstreamTestResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || !res.OK || !res.TrustOK {
		t.Fatalf("handler: %s %v", rec.Body.String(), err)
	}
	if rec = post(HandleTestUpstream, url.Values{"url": {addr}, "cabundle": {"junk"}}); !strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("an invalid bundle must be refused: %s", rec.Body.String())
	}

	rec = post(HandleUpstreamTLSInspect, url.Values{"cabundle": {ca.PEM()}, "pins": {"SHA256//" + strings.Repeat("A", 43) + "="}})
	var out struct {
		Certs []upstreamtls.CertInfo
		Pins  []string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Certs) != 1 || out.Certs[0].Fingerprint == "" || len(out.Pins) != 1 {
		t.Fatalf("inspect: %s %v", rec.Body.String(), err)
	}
	if rec = post(HandleUpstreamTLSInspect, url.Values{"cabundle": {"x"}}); !strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("inspect must refuse a bad bundle: %s", rec.Body.String())
	}
	if rec = post(HandleUpstreamTLSInspect, url.Values{"pins": {"nothex"}}); !strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("inspect must refuse a bad pin: %s", rec.Body.String())
	}
}

// Existing upstream JSON (without the new fields) loads unchanged and means "no custom trust"
func TestUpstreamJSONBackwardCompatible(t *testing.T) {
	var u loadbalance.Upstream
	if err := json.Unmarshal([]byte(`{"OriginIpOrDomain":"10.0.0.5:443","RequireTLS":true,"SkipCertValidations":true,"Weight":1}`), &u); err != nil {
		t.Fatal(err)
	}
	if u.TLSPolicy().Active() || u.TLSCABundlePEM != "" || u.TLSPinsSHA256 != nil || !u.SkipCertValidations {
		t.Fatal("old config must keep meaning skip verify only")
	}
	c := u.Clone()
	ca := tlstest.NewCA("x")
	u.TLSCABundlePEM, u.TLSPinsSHA256 = ca.PEM(), []string{strings.Repeat("ab", 32)}
	c = u.Clone()
	if c.TLSCABundlePEM != u.TLSCABundlePEM || len(c.TLSPinsSHA256) != 1 {
		t.Fatal("Clone (used by the upstream update API) must carry the new fields")
	}
}

// The posture warning appears for skip verify and disappears once a CA bundle or pin replaces it
func TestPostureTLSVerifyOffFact(t *testing.T) {
	ca := tlstest.NewCA("x")
	skip := &loadbalance.Upstream{OriginIpOrDomain: "10.0.0.5:443", RequireTLS: true, SkipCertValidations: true}
	ep := &dynamicproxy.ProxyEndpoint{ActiveOrigins: []*loadbalance.Upstream{skip}}
	if !upstreamTLSVerifyOff(ep) {
		t.Fatal("skip verify must be reported")
	}
	skip.TLSCABundlePEM = ca.PEM()
	if upstreamTLSVerifyOff(ep) {
		t.Fatal("a CA bundle replaces skip verify, no warning expected")
	}
	plain := &loadbalance.Upstream{OriginIpOrDomain: "10.0.0.5:80", SkipCertValidations: true} //TLS off: nothing to verify
	if upstreamTLSVerifyOff(&dynamicproxy.ProxyEndpoint{ActiveOrigins: []*loadbalance.Upstream{plain}}) {
		t.Fatal("skip flag on a plain http upstream is not a TLS risk")
	}
	if !upstreamTLSVerifyOff(&dynamicproxy.ProxyEndpoint{VirtualDirectories: []*dynamicproxy.VirtualDirectoryEndpoint{{RequireTLS: true, SkipCertValidations: true}}}) {
		t.Fatal("a virtual directory that skips verification must be reported")
	}
}
