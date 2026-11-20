package deployrole

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func trustSet(ips ...string) func(string) bool {
	return func(ip string) bool {
		for _, t := range ips {
			if t == ip {
				return true
			}
			if strings.HasSuffix(t, ".") && strings.HasPrefix(ip, t) { //prefix match: "10.9.0." = 10.9.0.0/24
				return true
			}
		}
		return false
	}
}

func req(peer string, h map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = peer
	for k, v := range h {
		r.Header.Add(k, v)
	}
	return r
}

var spoofHeaders = map[string]string{
	"X-Forwarded-For": "6.6.6.6", "Forwarded": "for=6.6.6.6", "X-Real-Ip": "6.6.6.6",
	"CF-Connecting-IP": "6.6.6.6", "CF-Connecting-IPv6": "2001:db8::66", "Fastly-Client-IP": "6.6.6.6",
	"True-Client-IP": "6.6.6.6", "X-Client-IP": "6.6.6.6", "X-Forwarded-Host": "evil.example",
	"X-Forwarded-Proto": "https", "X-Forwarded-Port": "443",
	"X-Client-Cert-Verified": "true", "X-Client-Cert-Subject": "CN=admin", "X-Client-Cert-Fingerprint": "aa", "X-Client-Cert-Serial": "1",
}

func TestManagerDefaults(t *testing.T) {
	var nilM *Manager
	if nilM.Role() != RoleStandalone || nilM.HardenActive() || nilM.PeerGateActive() {
		t.Fatal("nil manager must be inert standalone")
	}
	m, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role() != RoleStandalone || m.HardenActive() || m.PeerGateActive() {
		t.Fatal("default must be standalone, no hardening, no gate")
	}
	//zero value Settings (an old config without the key) is standalone
	var z Settings
	if _, err := Validate(&z); err != nil || z.Role != RoleStandalone {
		t.Fatalf("zero settings: %v %v", z, err)
	}
}

func TestRoleActivation(t *testing.T) {
	for _, c := range []struct {
		s            Settings
		harden, gate bool
	}{
		{Settings{}, false, false},
		{Settings{Role: RoleStandalone}, false, false},
		{Settings{Role: RoleStandalone, HardenHeaders: true}, true, false},
		{Settings{Role: RoleExternal}, true, false},
		{Settings{Role: RoleInternal}, true, false}, //gate stays off until enabled
		{Settings{Role: RoleInternal, PeerGate: true}, true, true},
	} {
		m, _ := New(nil)
		if err := m.Set(c.s); err != nil {
			t.Fatalf("%+v: %v", c.s, err)
		}
		if m.HardenActive() != c.harden || m.PeerGateActive() != c.gate {
			t.Errorf("%+v: harden=%v gate=%v", c.s, m.HardenActive(), m.PeerGateActive())
		}
	}
}

func TestValidation(t *testing.T) {
	m, _ := New(nil)
	bad := []Settings{
		{Role: "dmz"},
		{Role: RoleExternal, PeerGate: true},
		{Role: RoleStandalone, PeerGate: true},
		{Role: RoleInternal, DirectCIDRs: []string{"not-an-ip"}},
		{Role: RoleInternal, DirectCIDRs: []string{"10.0.0.0/33"}},
		{Role: RoleInternal, DirectCIDRs: []string{"0.0.0.0/0"}},
		{Role: RoleInternal, DirectCIDRs: []string{"::/0"}},
	}
	for _, s := range bad {
		if err := m.Set(s); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	if m.Role() != RoleStandalone {
		t.Fatal("failed Set must not change anything")
	}
	if err := m.Set(Settings{Role: " Internal ", PeerGate: true, DirectCIDRs: []string{" 10.1.0.0/16 ", "10.1.0.0/16", "192.168.1.5", "fd00::/8", ""}}); err != nil {
		t.Fatal(err)
	}
	s := m.Settings()
	if s.Role != RoleInternal || len(s.DirectCIDRs) != 3 {
		t.Fatalf("normalisation: %+v", s)
	}
	s.DirectCIDRs[0] = "tampered"
	if m.Settings().DirectCIDRs[0] == "tampered" {
		t.Fatal("Settings must return a copy")
	}
}

type fakeKV struct{ store map[string]Settings }

func (f *fakeKV) Read(table, key string, a interface{}) error {
	v, ok := f.store[table+"/"+key]
	if !ok {
		return http.ErrMissingFile
	}
	*(a.(*Settings)) = v
	return nil
}
func (f *fakeKV) Write(table, key string, v interface{}) error {
	f.store[table+"/"+key] = v.(Settings)
	return nil
}

func TestPersistence(t *testing.T) {
	kv := &fakeKV{store: map[string]Settings{}}
	m, _ := New(kv)
	var changes int
	m.OnChange = func(o, n Settings) { changes++ }
	if err := m.Set(Settings{Role: RoleInternal, PeerGate: true, DirectCIDRs: []string{"10.2.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	m2, err := New(kv)
	if err != nil || m2.Role() != RoleInternal || !m2.PeerGateActive() || changes != 1 {
		t.Fatalf("reload: %v %+v changes=%d", err, m2.Settings(), changes)
	}
	//a stored value that no longer validates falls back to standalone
	kv.store["settings/deployrole"] = Settings{Role: "bogus"}
	m3, err := New(kv)
	if err == nil || m3.Role() != RoleStandalone {
		t.Fatal("invalid stored settings must be ignored with an error")
	}
	//failed Set must not be persisted
	_ = m.Set(Settings{Role: "bogus"})
	if kv.store["settings/deployrole"].Role != "bogus" { //still what we planted, i.e. not overwritten by the failed Set
		t.Fatal("failed Set wrote to the store")
	}
}

func TestPeerGate(t *testing.T) {
	m, _ := New(nil)
	trusted := trustSet("10.9.0.2", "2001:db8:a::2")
	if !m.PeerAllowed("203.0.113.9", trusted) {
		t.Fatal("gate off must allow everything")
	}
	_ = m.Set(Settings{Role: RoleInternal, PeerGate: true, DirectCIDRs: []string{"192.168.50.0/24", "fd00:1::/64"}})
	cases := map[string]bool{
		"10.9.0.2": true, "2001:db8:a::2": true, //trusted proxies
		"192.168.50.7": true, "fd00:1::7": true, //direct networks
		"192.168.51.7": false, "203.0.113.9": false, "10.9.0.3": false,
		"": false, "not-an-ip": false, "::ffff:192.168.50.9": true, //v4-mapped form of an allowed address
		"2001:db8:a::3": false,
	}
	for ip, want := range cases {
		if got := m.PeerAllowed(ip, trusted); got != want {
			t.Errorf("PeerAllowed(%q) = %v, want %v", ip, got, want)
		}
	}
	//external role never gates even if the stored flag were set by hand
	m2, _ := New(nil)
	_ = m2.Set(Settings{Role: RoleExternal})
	if !m2.PeerAllowed("203.0.113.9", trusted) {
		t.Fatal("external role has no gate")
	}
}

/* ---- header trust matrix ---- */

func TestUntrustedPeerStripsEverything(t *testing.T) {
	trusted := trustSet("10.9.0.2")
	for _, peer := range []string{"203.0.113.9:5555", "[2001:db8::9]:5555", "10.9.0.99:1"} {
		r := req(peer, spoofHeaders)
		res := Harden(r, trusted)
		if res.PeerTrusted || !res.Stripped {
			t.Fatalf("%s: %+v", peer, res)
		}
		for h := range spoofHeaders {
			if h == "Forwarded" {
				continue //replaced below
			}
			if v := r.Header.Get(h); v != "" {
				t.Errorf("%s: %s survived: %q", peer, h, v)
			}
		}
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-client-cert") {
				t.Errorf("%s: %s survived", peer, k)
			}
		}
		f := r.Header.Get("Forwarded")
		if strings.Contains(f, "6.6.6.6") || !strings.HasPrefix(f, "for=") || !strings.Contains(f, "proto=http;host=app.example.com") {
			t.Errorf("%s: Forwarded not replaced by this hop: %q", peer, f)
		}
	}
	//IPv6 peer is quoted and bracketed in Forwarded
	r := req("[2001:db8::9]:1", nil)
	Harden(r, trusted)
	if got := r.Header.Get("Forwarded"); got != `for="[2001:db8::9]";proto=http;host=app.example.com` {
		t.Errorf("IPv6 Forwarded: %q", got)
	}
}

func TestUntrustedPeerTLSProto(t *testing.T) {
	r := req("203.0.113.9:1", nil)
	r.TLS = &tls.ConnectionState{}
	Harden(r, trustSet())
	if !strings.Contains(r.Header.Get("Forwarded"), "proto=https") {
		t.Fatal(r.Header.Get("Forwarded"))
	}
}

func TestUnparsablePeerIsUntrusted(t *testing.T) {
	r := req("bogus", spoofHeaders)
	res := Harden(r, func(string) bool { return true }) //even a trust-everything list must not trust garbage
	if res.PeerTrusted || r.Header.Get("X-Real-Ip") != "" {
		t.Fatalf("%+v %v", res, r.Header)
	}
}

func TestTrustedPeerXFF(t *testing.T) {
	trusted := trustSet("10.9.0.2", "10.9.0.3", "2001:db8:a::2", "173.245.48.1")
	cases := []struct {
		name, peer string
		h          map[string]string
		client     string
		xff        string
	}{
		{"single client", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7", "198.51.100.7"},
		{"client spoofed leftmost entry", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7"}, "198.51.100.7", "198.51.100.7"},
		{"multi hop through a second trusted proxy", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.9.0.3"}, "198.51.100.7", "198.51.100.7, 10.9.0.3"},
		{"spoofed trusted address on the left is skipped", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "10.9.0.3, 198.51.100.7"}, "198.51.100.7", "198.51.100.7"},
		{"all hops trusted: leftmost", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "10.9.0.3, 173.245.48.1"}, "10.9.0.3", "10.9.0.3, 173.245.48.1"},
		{"ipv6 client", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "2001:db8::77"}, "2001:db8::77", "2001:db8::77"},
		{"ipv6 trusted peer, ipv4 client", "[2001:db8:a::2]:1", map[string]string{"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7", "198.51.100.7"},
		{"bracketed v6 with port", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "[2001:db8::77]:5000"}, "2001:db8::77", "[2001:db8::77]:5000"},
		{"split over several header lines", "10.9.0.2:1", nil, "198.51.100.7", "198.51.100.7"},
		{"no headers: the peer", "10.9.0.2:1", nil, "10.9.0.2", ""},
		{"garbage entry next to trusted hop: not trusted, falls back", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7, unknown"}, "10.9.0.2", ""},
		{"real ip used when there is no chain", "10.9.0.2:1", map[string]string{"X-Real-Ip": "198.51.100.8"}, "198.51.100.8", "198.51.100.8"},
		{"xff beats a forged x-real-ip", "10.9.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7", "X-Real-Ip": "6.6.6.6"}, "198.51.100.7", "198.51.100.7"},
	}
	for _, c := range cases {
		r := req(c.peer, c.h)
		if c.name == "split over several header lines" {
			r.Header.Add("X-Forwarded-For", "6.6.6.6")
			r.Header.Add("X-Forwarded-For", "198.51.100.7")
		}
		res := Harden(r, trusted)
		if !res.PeerTrusted || res.ClientIP != c.client {
			t.Errorf("%s: %+v want client %s", c.name, res, c.client)
		}
		if got := r.Header.Get("X-Forwarded-For"); got != c.xff {
			t.Errorf("%s: XFF = %q, want %q", c.name, got, c.xff)
		}
		if got := r.Header.Get("X-Real-Ip"); got != c.client {
			t.Errorf("%s: X-Real-Ip = %q, want %q", c.name, got, c.client)
		}
	}
}

func TestTrustedPeerCDNHeaders(t *testing.T) {
	trusted := trustSet("173.245.48.1")
	// CF header used when there is no usable chain
	r := req("173.245.48.1:1", map[string]string{"CF-Connecting-IP": "198.51.100.7"})
	if res := Harden(r, trusted); res.ClientIP != "198.51.100.7" || r.Header.Get("X-Real-Ip") != "198.51.100.7" {
		t.Fatalf("%+v %v", res, r.Header)
	}
	// IPv6 CF header
	r = req("173.245.48.1:1", map[string]string{"CF-Connecting-IPv6": "2001:db8::5"})
	if res := Harden(r, trusted); res.ClientIP != "2001:db8::5" {
		t.Fatalf("%+v", res)
	}
	// Fastly
	r = req("173.245.48.1:1", map[string]string{"Fastly-Client-IP": "198.51.100.9"})
	if res := Harden(r, trusted); res.ClientIP != "198.51.100.9" {
		t.Fatalf("%+v", res)
	}
	// values that are not a single IP are dropped, never copied into X-Real-Ip
	for _, bad := range []string{"evil.example", "1.2.3.4, 5.6.7.8", "<script>", "1.2.3.4%eth0", "\"1.2.3.4\"", "999.1.1.1", "' OR 1=1 --"} {
		r = req("173.245.48.1:1", map[string]string{"CF-Connecting-IP": bad, "Fastly-Client-IP": bad, "True-Client-IP": bad, "X-Client-IP": bad, "X-Real-Ip": bad})
		res := Harden(r, trusted)
		if res.ClientIP != "173.245.48.1" {
			t.Errorf("%q: client %s", bad, res.ClientIP)
		}
		for _, h := range singleIPHeaders {
			if h == "X-Real-Ip" {
				continue
			}
			if v := r.Header.Get(h); v != "" {
				t.Errorf("%q: %s survived: %q", bad, h, v)
			}
		}
		if r.Header.Get("X-Real-Ip") != "173.245.48.1" {
			t.Errorf("%q: X-Real-Ip = %q", bad, r.Header.Get("X-Real-Ip"))
		}
	}
}

func TestTrustedPeerForwardedHostProto(t *testing.T) {
	trusted := trustSet("10.9.0.2")
	r := req("10.9.0.2:1", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "shop.example.com", "X-Forwarded-Port": "443"})
	Harden(r, trusted)
	if r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-Host") != "shop.example.com" || r.Header.Get("X-Forwarded-Port") != "443" {
		t.Fatalf("well formed values from a trusted peer must stay: %v", r.Header)
	}
	r = req("10.9.0.2:1", map[string]string{"X-Forwarded-Proto": "javascript", "X-Forwarded-Host": "a b", "X-Forwarded-Port": "99999"})
	Harden(r, trusted)
	for _, h := range forwardedHostProtoPort {
		if r.Header.Get(h) != "" {
			t.Errorf("%s malformed value survived", h)
		}
	}
}

func TestTrustedPeerClientCertHeadersKept(t *testing.T) {
	//a trusted proxy may carry verified identity (documented). The per-endpoint client cert code overwrites them where a policy exists.
	r := req("10.9.0.2:1", map[string]string{"X-Client-Cert-Verified": "true"})
	Harden(r, trustSet("10.9.0.2"))
	if r.Header.Get("X-Client-Cert-Verified") != "true" {
		t.Fatal("trusted peer identity header was removed")
	}
}

func TestForwardedChain(t *testing.T) {
	trusted := trustSet("10.9.0.2", "10.9.0.3")
	r := req("10.9.0.2:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.9.0.3"})
	Harden(r, trusted)
	want := `for=198.51.100.7, for=10.9.0.3, for=10.9.0.2;proto=http;host=app.example.com`
	if got := r.Header.Get("Forwarded"); got != want {
		t.Errorf("Forwarded\n got %s\nwant %s", got, want)
	}
	// no chain at all: only this hop
	r = req("10.9.0.2:1", nil)
	Harden(r, trusted)
	if got := r.Header.Get("Forwarded"); got != "for=10.9.0.2;proto=http;host=app.example.com" {
		t.Errorf("no chain: %q", got)
	}
}

// Attack: a client behind a trusted peer injects its own RFC 7239 Forwarded header (the peer does not write
// Forwarded, so it passes it on unchanged). It must not reach the upstream, whatever its shape.
func TestTrustedPeerForwardedHeaderIsNeverKept(t *testing.T) {
	trusted := trustSet("10.9.0.2", "10.9.0.3")
	for _, inj := range []string{
		`for=6.6.6.6`, `for=6.6.6.6;proto=https;host=evil.example`, `for=_hidden, for=10.9.0.3`,
		`for=198.51.100.7;by=10.0.0.1`, `for="unterminated`, `for`, `=x`, `for=a"b`, `for="a\`, `by=203.0.113.1;secret=1`,
	} {
		for _, xff := range []string{"", "198.51.100.7"} {
			h := map[string]string{"Forwarded": inj}
			if xff != "" {
				h["X-Forwarded-For"] = xff
			}
			r := req("10.9.0.2:1", h)
			Harden(r, trusted)
			got := r.Header.Get("Forwarded")
			for _, bad := range []string{"6.6.6.6", "evil.example", "_hidden", "by=", "secret", "unterminated", "10.0.0.1"} {
				if strings.Contains(got, bad) {
					t.Errorf("injected %q (xff %q) survived as %q", inj, xff, got)
				}
			}
			if !strings.Contains(got, "for=10.9.0.2") {
				t.Errorf("own hop missing: %q", got)
			}
			if xff != "" && !strings.Contains(got, "for=198.51.100.7") {
				t.Errorf("verified chain address missing: %q", got)
			}
		}
	}
}

func TestHostileHostInForwarded(t *testing.T) {
	r := req("203.0.113.9:1", nil)
	r.Host = `a"b;for=6.6.6.6`
	Harden(r, trustSet())
	if strings.Contains(r.Header.Get("Forwarded"), "6.6.6.6") {
		t.Fatalf("Host header injected into Forwarded: %s", r.Header.Get("Forwarded"))
	}
}

// Header injection through the right-most hop must not be possible: after hardening, the upstream-bound XFF contains only parsed addresses.
func TestXFFIsRebuiltFromParsedAddressesOnly(t *testing.T) {
	r := req("10.9.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	Harden(r, trustSet("10.9.0.2"))
	if strings.ContainsAny(r.Header.Get("X-Forwarded-For"), "<>\"'") {
		t.Fatal("unexpected characters")
	}
}

func BenchmarkHarden(b *testing.B) {
	trusted := trustSet("10.9.0.2")
	for i := 0; i < b.N; i++ {
		r := req("10.9.0.2:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7"})
		Harden(r, trusted)
	}
}

var spoofVariants = []string{
	"X_Forwarded_For", "X_Real_Ip", "X_REAL_IP", "x_forwarded_for", "x-forwarded-for", "X-FORWARDED-FOR", "X_Forwarded-For",
	"X_Client_Cert_Subject", "X_Client_Cert", "x-client-cert-dn", "CF_Connecting_IP", "True_Client_IP", "Fastly_Client_IP",
	"X_Forwarded_Host", "X_Forwarded_Proto", "X_Forwarded_Port", "X_Client_IP", "Forwarded", "FORWARDED",
}

// Attack: identity headers spelled with underscores or non canonical case. CGI/WSGI/PHP backends fold "_" and "-"
// together, so X_Forwarded_For would be read as the real chain.
func TestHeaderSpellingVariantsStripped(t *testing.T) {
	trusted := trustSet("10.9.0.2")
	for _, peer := range []string{"203.0.113.9:1", "10.9.0.2:1"} {
		r := req(peer, nil)
		for _, k := range spoofVariants {
			r.Header[k] = []string{"6.6.6.6"} //raw map write: keys stay exactly as spelled
		}
		Harden(r, trusted)
		for k, v := range r.Header {
			if strings.ToLower(k) == "forwarded" {
				if strings.Contains(strings.Join(v, ","), "6.6.6.6") {
					t.Errorf("%s: attacker value survived in %s: %v", peer, k, v)
				}
				continue
			}
			if (strings.Contains(k, "_") || k != http.CanonicalHeaderKey(k)) && strings.Contains(strings.Join(v, ","), "6.6.6.6") {
				t.Errorf("%s: variant %q survived: %v", peer, k, v)
			}
		}
		if peer == "203.0.113.9:1" {
			for k := range r.Header {
				if strings.Contains(strings.ToLower(strings.ReplaceAll(k, "_", "-")), "client-cert") {
					t.Errorf("untrusted peer: %s survived", k)
				}
			}
		}
	}
}
