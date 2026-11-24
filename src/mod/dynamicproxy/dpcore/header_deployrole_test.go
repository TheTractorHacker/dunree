package dpcore

import (
	"net/http/httptest"
	"testing"

	"github.com/foleyit/dunree/mod/deployrole"
)

// What the upstream finally sees: hardening followed by dpcore's own X-Forwarded-For / X-Real-Ip step.
func TestUpstreamViewAfterHardening(t *testing.T) {
	trusted := func(ip string) bool { return ip == "10.9.0.2" }
	cases := []struct {
		name, peer string
		h          map[string]string
		xff, real  string
	}{
		{"direct client spoofing", "203.0.113.9:4000", map[string]string{"X-Forwarded-For": "6.6.6.6", "X-Real-Ip": "6.6.6.6", "CF-Connecting-IP": "6.6.6.6", "Fastly-Client-IP": "6.6.6.6"}, "203.0.113.9", "203.0.113.9"},
		{"trusted proxy, client spoofed first entry", "10.9.0.2:4000", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7"}, "198.51.100.7, 10.9.0.2", "198.51.100.7"},
		{"trusted proxy, forged CDN header with real chain", "10.9.0.2:4000", map[string]string{"X-Forwarded-For": "198.51.100.7", "CF-Connecting-IP": "6.6.6.6"}, "198.51.100.7, 10.9.0.2", "198.51.100.7"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.RemoteAddr = c.peer
		for k, v := range c.h {
			r.Header.Set(k, v)
		}
		deployrole.Harden(r, trusted)
		addXForwardedForHeader(r)
		if got := r.Header.Get("X-Forwarded-For"); got != c.xff {
			t.Errorf("%s: X-Forwarded-For %q, want %q", c.name, got, c.xff)
		}
		if got := r.Header.Get("X-Real-Ip"); got != c.real {
			t.Errorf("%s: X-Real-Ip %q, want %q", c.name, got, c.real)
		}
	}
}

// Without hardening (standalone) dpcore keeps copying the CDN header into X-Real-Ip: documented unchanged behaviour.
func TestStandaloneDpcoreUnchanged(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = "203.0.113.9:4000"
	r.Header.Set("CF-Connecting-IP", "6.6.6.6")
	addXForwardedForHeader(r)
	if r.Header.Get("X-Real-Ip") != "6.6.6.6" || r.Header.Get("X-Forwarded-For") != "203.0.113.9" {
		t.Fatalf("standalone dpcore behaviour changed: %v", r.Header)
	}
}
