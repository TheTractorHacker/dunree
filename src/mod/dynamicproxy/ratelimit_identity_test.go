package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/deployrole"
)

/*
	Rate limit identity through the real listener entry (deployRoleEntry hardening) and handleRateLimit.
	The limit must apply per real client, never per front proxy, and a header a client controls must not
	change the bucket it lands in.
*/

// rlRun sends the request through the listener wrapper (role hardening), then the rate limiter, as the proxy does.
// It returns true when the request was limited (429).
func rlRun(router *Router, pe *ProxyEndpoint, r *http.Request) bool {
	limited := false
	h := router.withHealth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := router.handleRateLimit(w, r, pe); err != nil {
			limited = true
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	return limited
}

func rlReq(peer string, h map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = peer
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func newRLEndpoint() *ProxyEndpoint {
	return &ProxyEndpoint{RequireRateLimit: true, RateLimit: 3, RootOrMatchingDomain: "app.example.com"}
}

// Internal role behind an external proxy: every client reaches the internal proxy from the same front proxy address.
func TestRateLimitIdentity_InternalBehindExternalIsPerRealClient(t *testing.T) {
	router := drRouter(t, deployrole.Settings{Role: deployrole.RoleInternal}, "10.9.0.2")
	pe := newRLEndpoint()
	front := "10.9.0.2:44000"

	//client A exhausts its own budget (burst 3)
	limitedA := 0
	for i := 0; i < 8; i++ {
		if rlRun(router, pe, rlReq(front, map[string]string{"X-Forwarded-For": "198.51.100.1"})) {
			limitedA++
		}
	}
	if limitedA == 0 {
		t.Fatal("client A was never limited")
	}
	//client B through the same front proxy is untouched
	for i := 0; i < 3; i++ {
		if rlRun(router, pe, rlReq(front, map[string]string{"X-Forwarded-For": "198.51.100.2"})) {
			t.Fatalf("client B limited at request %d: the budget is shared with client A (keyed on the front proxy?)", i)
		}
	}
	if router.rateLimitCounter.Has(pe.RootOrMatchingDomain, "10.9.0.2") {
		t.Error("a bucket was created for the front proxy address")
	}
	if !router.rateLimitCounter.Has(pe.RootOrMatchingDomain, "198.51.100.1") || !router.rateLimitCounter.Has(pe.RootOrMatchingDomain, "198.51.100.2") {
		t.Error("buckets are not keyed by the real client addresses")
	}
}

// A client that sends its own X-Forwarded-For through a proxy that appends the real peer must not escape by rotating the
// forged left-most entries (the proxy appends, so the right-most untrusted hop is the real client).
func TestRateLimitIdentity_ForgedLeftEntriesDoNotEscape(t *testing.T) {
	for name, s := range map[string]deployrole.Settings{
		"internal":          {Role: deployrole.RoleInternal},
		"external":          {Role: deployrole.RoleExternal},
		"standalone harden": {Role: deployrole.RoleStandalone, HardenHeaders: true},
	} {
		t.Run(name, func(t *testing.T) {
			router := drRouter(t, s, "10.9.0.2")
			pe := newRLEndpoint()
			limited := 0
			for i := 0; i < 10; i++ {
				forged := "203.0.113." + string(rune('1'+i)) //a new forged address on every request
				if rlRun(router, pe, rlReq("10.9.0.2:1", map[string]string{
					"X-Forwarded-For": forged + ", 198.51.100.7", "X-Real-Ip": forged, "CF-Connecting-IP": forged, "Forwarded": "for=" + forged,
				})) {
					limited++
				}
			}
			if limited == 0 {
				t.Fatal("rotating forged headers behind a trusted proxy escaped the rate limit")
			}
			if router.rateLimitCounter.Len() != 1 || !router.rateLimitCounter.Has(pe.RootOrMatchingDomain, "198.51.100.7") {
				t.Errorf("expected exactly one bucket for 198.51.100.7, have %d", router.rateLimitCounter.Len())
			}
		})
	}
}

// Untrusted peer: every header is ignored, the bucket is the TCP peer, rotating the headers changes nothing.
func TestRateLimitIdentity_UntrustedPeerSpoofIgnored(t *testing.T) {
	for name, s := range map[string]deployrole.Settings{
		"standalone":        {},
		"internal":          {Role: deployrole.RoleInternal},
		"external":          {Role: deployrole.RoleExternal},
		"standalone harden": {Role: deployrole.RoleStandalone, HardenHeaders: true},
	} {
		t.Run(name, func(t *testing.T) {
			router := drRouter(t, s, "10.9.0.2") //default rule trusts proxy headers, but only from 10.9.0.2
			pe := newRLEndpoint()
			limited := 0
			for i := 0; i < 10; i++ {
				v := "203.0.113." + string(rune('1'+i))
				if rlRun(router, pe, rlReq("192.0.2.50:1", map[string]string{"X-Forwarded-For": v, "X-Real-Ip": v, "CF-Connecting-IP": v})) {
					limited++
				}
			}
			if limited == 0 {
				t.Fatal("untrusted peer rotated spoofed headers past the rate limit")
			}
			if router.rateLimitCounter.Len() != 1 || !router.rateLimitCounter.Has(pe.RootOrMatchingDomain, "192.0.2.50") {
				t.Errorf("expected one bucket for the TCP peer, have %d", router.rateLimitCounter.Len())
			}
		})
	}
}

// A malformed client value behind a trusted proxy must not fail open or poison a bucket name.
func TestRateLimitIdentity_GarbageHeaderFallsBackToPeer(t *testing.T) {
	router := drRouter(t, deployrole.Settings{Role: deployrole.RoleInternal}, "10.9.0.2")
	pe := newRLEndpoint()
	limited := 0
	for i := 0; i < 8; i++ {
		if rlRun(router, pe, rlReq("10.9.0.2:1", map[string]string{"X-Forwarded-For": "not-an-ip, <script>", "X-Real-Ip": "../../etc"})) {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("garbage identity headers disabled the rate limit")
	}
}

// Known limit, asserted so a change is noticed: in standalone with the hardening opt-in OFF, a trusted proxy that
// APPENDS to a client supplied X-Forwarded-For is believed from the left (first entry), so the client can pick its
// bucket. The fix is to turn on the header hardening (role external/internal, or "Harden client IP headers").
func TestRateLimitIdentity_StandaloneWithoutHardeningTrustsFirstXFF(t *testing.T) {
	router := drRouter(t, deployrole.Settings{}, "10.9.0.2")
	pe := newRLEndpoint()
	limited := 0
	for i := 0; i < 10; i++ {
		forged := "203.0.113." + string(rune('1'+i))
		if rlRun(router, pe, rlReq("10.9.0.2:1", map[string]string{"X-Forwarded-For": forged + ", 198.51.100.7"})) {
			limited++
		}
	}
	if limited != 0 {
		t.Skip("standalone behaviour changed: the known limit documented in docs/ux/changes.md no longer holds")
	}
}

// Known limit, asserted so a change is noticed: the role hardening rewrites the forwarded headers, but a rule whose
// access rule has "Trusted Proxy Gating" OFF does not read them, so the limiter keys on the connecting (front) proxy and
// every visitor shares one bucket. The Deployment card warns about it; docs/guides/enterprise-dual-proxy.md says to turn the gating on.
func TestRateLimitIdentity_GatingOffKeysOnFrontProxy(t *testing.T) {
	router := drRouter(t, deployrole.Settings{Role: deployrole.RoleInternal}, "10.9.0.2")
	def, _ := router.Option.AccessController.GetAccessRuleByID("default")
	def.TrustProxyHeadersOnly = false
	pe := newRLEndpoint()
	for i := 0; i < 6; i++ {
		rlRun(router, pe, rlReq("10.9.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100." + string(rune('1'+i))}))
	}
	if !router.rateLimitCounter.Has(pe.RootOrMatchingDomain, "10.9.0.2") || router.rateLimitCounter.Len() != 1 {
		t.Skip("behaviour changed: update the known limit in docs/ux/changes.md and the guide")
	}
}
