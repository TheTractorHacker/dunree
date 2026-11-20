package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/deployrole"
)

func drRouter(t *testing.T, s deployrole.Settings, trusted ...string) *Router {
	t.Helper()
	router := newTestRateLimitRouter(t, true, trusted...)
	m, _ := deployrole.New(nil)
	if err := m.Set(s); err != nil {
		t.Fatal(err)
	}
	router.Option.DeployRole = m
	return router
}

// run sends a request through the listener wrapper and returns the headers the next handler saw (nil = never reached) and the status
func drRun(router *Router, r *http.Request) (http.Header, int) {
	var seen http.Header
	h := router.withHealth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return seen, rec.Code
}

var allSpoof = map[string]string{
	"X-Forwarded-For": "6.6.6.6", "Forwarded": "for=6.6.6.6", "X-Real-Ip": "6.6.6.6", "CF-Connecting-IP": "6.6.6.6",
	"CF-Connecting-IPv6": "2001:db8::66", "Fastly-Client-IP": "6.6.6.6", "True-Client-IP": "6.6.6.6", "X-Client-IP": "6.6.6.6",
	"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443",
	"X-Client-Cert-Verified": "true", "X-Client-Cert-Subject": "CN=root",
}

// Standalone (default, or no manager at all) must not touch a request.
func TestDeployRoleStandaloneUnchanged(t *testing.T) {
	for name, router := range map[string]*Router{
		"no manager":           newTestRateLimitRouter(t, true, "10.9.0.2"),
		"standalone default":   drRouter(t, deployrole.Settings{}, "10.9.0.2"),
		"standalone explicit":  drRouter(t, deployrole.Settings{Role: deployrole.RoleStandalone}, "10.9.0.2"),
		"gate flag w/o harden": drRouter(t, deployrole.Settings{Role: deployrole.RoleStandalone, DirectCIDRs: []string{"10.1.0.0/16"}}, "10.9.0.2"),
	} {
		for _, peer := range []string{"203.0.113.9:1", "10.9.0.2:1", "[2001:db8::9]:1"} {
			r := httptest.NewRequest("GET", "http://app.example.com/", nil)
			r.RemoteAddr = peer
			for k, v := range allSpoof {
				r.Header.Set(k, v)
			}
			before := r.Header.Clone()
			seen, code := drRun(router, r)
			if code != 200 || !reflect.DeepEqual(seen, before) {
				t.Errorf("%s peer %s: request was modified or refused (code %d)\n before %v\n after  %v", name, peer, code, before, seen)
			}
		}
	}
}

// Roles external and internal (and the standalone opt-in) harden headers on every listener entry.
func TestDeployRoleHardeningMatrix(t *testing.T) {
	roles := map[string]deployrole.Settings{
		"standalone+optin": {Role: deployrole.RoleStandalone, HardenHeaders: true},
		"external":         {Role: deployrole.RoleExternal},
		"internal":         {Role: deployrole.RoleInternal},
		"internal+gate":    {Role: deployrole.RoleInternal, PeerGate: true, DirectCIDRs: []string{"203.0.113.0/24"}},
	}
	for name, s := range roles {
		router := drRouter(t, s, "10.9.0.2", "2001:db8:a::/64")

		//untrusted peer: nothing it says about clients survives (peer 203.0.113.9 is reachable in every variant)
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.RemoteAddr = "203.0.113.9:1"
		for k, v := range allSpoof {
			r.Header.Set(k, v)
		}
		seen, code := drRun(router, r)
		if name == "internal" && code != 200 { //gate is off in plain internal role
			t.Fatalf("%s: refused with gate off", name)
		}
		if code != 200 {
			t.Fatalf("%s: direct network peer refused", name)
		}
		for k := range allSpoof {
			if k == "Forwarded" {
				continue
			}
			if seen.Get(k) != "" {
				t.Errorf("%s: untrusted peer header %s survived: %q", name, k, seen.Get(k))
			}
		}
		if strings.Contains(seen.Get("Forwarded"), "6.6.6.6") {
			t.Errorf("%s: Forwarded kept spoofed value: %q", name, seen.Get("Forwarded"))
		}
		// the identity every later consumer (ACL, rate limit) computes is the TCP peer
		if ip := router.GetClientIPForEndpoint(rWith(seen, "203.0.113.9:1"), nil); ip != "203.0.113.9" {
			t.Errorf("%s: client IP for an untrusted peer = %s", name, ip)
		}

		//trusted IPv4 and IPv6 peers: right-most untrusted hop wins, ACL / rate-limit identity agrees
		for _, peer := range []string{"10.9.0.2:1", "[2001:db8:a::5]:1"} {
			r = httptest.NewRequest("GET", "http://app.example.com/", nil)
			r.RemoteAddr = peer
			r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
			r.Header.Set("X-Real-Ip", "6.6.6.6")
			r.Header.Set("CF-Connecting-IP", "not-an-ip")
			r.Header.Set("X-Client-Cert-Verified", "true")
			seen, code = drRun(router, r)
			if name == "internal+gate" && code != 200 {
				t.Fatalf("%s: trusted peer refused by gate", name)
			}
			if seen.Get("X-Real-Ip") != "198.51.100.7" || seen.Get("X-Forwarded-For") != "198.51.100.7" || seen.Get("CF-Connecting-IP") != "" {
				t.Errorf("%s %s: headers after hardening: %v", name, peer, seen)
			}
			if ip := router.GetClientIPForEndpoint(rWith(seen, peer), nil); ip != "198.51.100.7" {
				t.Errorf("%s %s: resolved client IP = %s", name, peer, ip)
			}
		}
	}
}

func rWith(h http.Header, remote string) *http.Request {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = remote
	r.Header = h.Clone()
	return r
}

func TestDeployRolePeerGate(t *testing.T) {
	router := drRouter(t, deployrole.Settings{Role: deployrole.RoleInternal, PeerGate: true, DirectCIDRs: []string{"192.168.50.0/24", "fd00:50::/64"}}, "10.9.0.2")
	before := PeerGateRejected()
	for peer, want := range map[string]int{
		"10.9.0.2:1": 200, "192.168.50.20:1": 200, "[fd00:50::9]:1": 200,
		"203.0.113.9:1": 403, "192.168.51.1:1": 403, "[2001:db8::1]:1": 403, "10.9.0.3:1": 403,
	} {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.RemoteAddr = peer
		//spoofing a trusted address in headers must not open the gate
		r.Header.Set("X-Forwarded-For", "10.9.0.2")
		r.Header.Set("X-Real-Ip", "10.9.0.2")
		seen, code := drRun(router, r)
		if code != want {
			t.Errorf("peer %s: status %d, want %d", peer, code, want)
		}
		if want == 403 && seen != nil {
			t.Errorf("peer %s: request reached the handler", peer)
		}
	}
	if got := PeerGateRejected() - before; got != 4 {
		t.Errorf("rejected counter moved by %d, want 4", got)
	}
	//health endpoint is behind the gate too
	r := httptest.NewRequest("GET", "http://app.example.com/.zoraxy/health", nil)
	r.RemoteAddr = "203.0.113.9:1"
	if _, code := drRun(router, r); code != 403 {
		t.Errorf("health from a refused peer: %d", code)
	}
	//the port 80 handler is gated as well
	rec := httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	router.handlePort80Request(rec, r)
	if rec.Code != 403 {
		t.Errorf("port 80 handler: %d", rec.Code)
	}
}

func TestDeployRolePeerGateOffInInternalByDefault(t *testing.T) {
	router := drRouter(t, deployrole.Settings{Role: deployrole.RoleInternal}, "10.9.0.2")
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	if _, code := drRun(router, r); code != 200 {
		t.Fatalf("internal role must not gate until enabled, got %d", code)
	}
}

// Auth exception rules that opted in to proxy headers: with hardening on, only a trusted peer's headers count.
func TestAuthExceptionUseTrustedProxyChecksPeer(t *testing.T) {
	rules := []*ZorxAuthExceptionRule{{RuleType: AuthExceptionType_CIDR, CIDR: "192.168.0.0/16", UseTrustedProxy: true}}
	mk := func(peer string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Real-Ip", "192.168.5.5")
		return r
	}
	off := newTestRateLimitRouter(t, true, "10.9.0.2")
	on := drRouter(t, deployrole.Settings{Role: deployrole.RoleExternal}, "10.9.0.2")

	//hardening off: today's behaviour, the header is believed from anybody
	if !zorxAuthExceptionMatchedIP(rules, mk("203.0.113.9:1"), off.trustedRequesterIP) {
		t.Error("standalone behaviour changed")
	}
	//hardening on, untrusted peer (headers not yet stripped, e.g. called outside the listener entry): the peer is used
	if zorxAuthExceptionMatchedIP(rules, mk("203.0.113.9:1"), on.trustedRequesterIP) {
		t.Error("untrusted peer's X-Real-Ip satisfied a UseTrustedProxy exception")
	}
	//hardening on, trusted peer: forwarded address used
	if !zorxAuthExceptionMatchedIP(rules, mk("10.9.0.2:1"), on.trustedRequesterIP) {
		t.Error("trusted peer's forwarded address was not used")
	}
}

// The default root handler path: X-Client-Cert-Verified from a client must not reach any endpoint (only listener entry code runs here)
func TestClientCertHeadersStrippedBeforeRouting(t *testing.T) {
	router := drRouter(t, deployrole.Settings{Role: deployrole.RoleExternal}, "10.9.0.2")
	r := httptest.NewRequest("GET", "http://unknown-host.example/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	r.Header.Set("X-Client-Cert-Verified", "true")
	r.Header.Set("x-client-cert-subject", "CN=root")
	seen, _ := drRun(router, r)
	for k := range seen {
		if strings.HasPrefix(strings.ToLower(k), "x-client-cert") {
			t.Errorf("%s reached routing", k)
		}
	}
}
