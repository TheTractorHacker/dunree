package adminallow

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

type memKV map[string]interface{}

func (m memKV) Read(table, key string, out interface{}) error {
	v, ok := m[table+"/"+key]
	if !ok {
		return errors.New("not found")
	}
	*out.(*Settings) = v.(Settings)
	return nil
}
func (m memKV) Write(table, key string, v interface{}) error { m[table+"/"+key] = v; return nil }

func serve(m *Manager, remote string, hdr map[string]string) (int, bool) {
	var reached atomic.Bool
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true); w.WriteHeader(200) }))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/x", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	h.ServeHTTP(w, r)
	return w.Code, reached.Load()
}

// Default (and every existing install): no list, everything passes untouched.
func TestNoListPassesEverything(t *testing.T) {
	m, err := New(memKV{})
	if err != nil || m.Active() {
		t.Fatalf("fresh: %v active=%v", err, m.Active())
	}
	for _, remote := range []string{"203.0.113.9:1234", "127.0.0.1:5", "[::1]:5", "garbage"} {
		if code, reached := serve(m, remote, map[string]string{"X-Forwarded-Server": "zoraxy-abc"}); code != 200 || !reached {
			t.Errorf("%s: %d reached=%v with no list", remote, code, reached)
		}
	}
	var nilMgr *Manager
	if code, _ := serve(nilMgr, "203.0.113.9:1", nil); code != 200 {
		t.Error("nil manager must pass through")
	}
}

func TestAllowListEnforced(t *testing.T) {
	m, _ := New(memKV{})
	if err := m.Set(Settings{CIDRs: []string{"192.168.10.0/24", "2001:db8:1::/48", "10.9.9.9"}}, "192.168.10.5"); err != nil {
		t.Fatal(err)
	}
	ok := []string{"192.168.10.5:1", "192.168.10.254:9", "[2001:db8:1::77]:80", "10.9.9.9:1", "[::ffff:192.168.10.7]:1"}
	bad := []string{"192.168.11.5:1", "203.0.113.9:1", "127.0.0.1:1", "[::1]:1", "10.9.9.8:1", "[2001:db8:2::1]:1", "garbage"}
	for _, r := range ok {
		if code, reached := serve(m, r, nil); code != 200 || !reached {
			t.Errorf("%s refused (%d)", r, code)
		}
	}
	for _, r := range bad {
		if code, reached := serve(m, r, nil); code != 403 || reached {
			t.Errorf("%s allowed (%d, reached=%v)", r, code, reached)
		}
	}
	if m.Denied() == 0 {
		t.Error("refusals not counted")
	}
}

// The old marker header (X-Forwarded-Server) no longer decides anything: a request is judged by its peer address only.
// Proxy rules that point at the admin port are stopped at dial time instead (dialguard_test.go).
func TestForwardingHeadersDoNotMatter(t *testing.T) {
	m, _ := New(memKV{})
	if err := m.Set(Settings{CIDRs: []string{"127.0.0.1", "192.168.10.0/24"}}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if code, _ := serve(m, "127.0.0.1:5", nil); code != 200 {
		t.Fatalf("direct loopback request refused: %d", code)
	}
	if code, _ := serve(m, "192.168.10.8:5", map[string]string{"X-Forwarded-Server": "nginx"}); code != 200 {
		t.Errorf("foreign X-Forwarded-Server refused: %d", code)
	}
	// forged forwarding headers from a non-listed peer do not help
	if code, _ := serve(m, "203.0.113.9:5", map[string]string{"X-Forwarded-For": "192.168.10.5", "X-Real-IP": "192.168.10.5", "Forwarded": "for=192.168.10.5"}); code != 403 {
		t.Errorf("spoofed forwarding headers accepted: %d", code)
	}
}

func TestLockoutProtection(t *testing.T) {
	kv := memKV{}
	m, _ := New(kv)
	// list without the caller: refused, nothing stored, nothing active
	err := m.Set(Settings{CIDRs: []string{"192.168.10.0/24"}}, "203.0.113.9")
	if err == nil || !strings.Contains(err.Error(), "lock you out") {
		t.Fatalf("lock-out accepted: %v", err)
	}
	if m.Active() || len(kv) != 0 {
		t.Fatal("a refused list changed state")
	}
	// unknown caller address: refused (cannot prove it is safe)
	for _, who := range []string{"", "garbage", "unix:"} {
		if m.Set(Settings{CIDRs: []string{"192.168.10.0/24"}}, who) == nil {
			t.Errorf("caller %q: list saved without knowing who saves it", who)
		}
	}
	// caller inside: saved; IPv4-mapped caller form too
	if err := m.Set(Settings{CIDRs: []string{"192.168.10.0/24"}}, "::ffff:192.168.10.9"); err != nil {
		t.Fatal(err)
	}
	// replacing the list with one that excludes the caller is refused as well, the old list stays
	if m.Set(Settings{CIDRs: []string{"10.0.0.0/8"}}, "192.168.10.9") == nil {
		t.Fatal("switching to a list without the caller accepted")
	}
	if got := m.Settings().CIDRs; len(got) != 1 || got[0] != "192.168.10.0/24" {
		t.Fatalf("list changed after refusal: %v", got)
	}
	// an empty list (switch off) is always allowed
	if err := m.Set(Settings{}, "203.0.113.9"); err != nil || m.Active() {
		t.Fatalf("clearing: %v active=%v", err, m.Active())
	}
}

func TestValidationAndPersistenceAndReset(t *testing.T) {
	kv := memKV{}
	m, _ := New(kv)
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"junk"}, {"10.0.0.0/33"}, {"example.com"}, {"::ffff:10.0.0.0/104"}} {
		if m.Set(Settings{CIDRs: bad}, "10.0.0.1") == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if err := m.Set(Settings{CIDRs: []string{" 10.0.0.0/8 ", "10.0.0.0/8", ""}}, "10.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if got := m.Settings().CIDRs; len(got) != 1 {
		t.Fatalf("not normalised: %v", got)
	}
	m2, err := New(kv) // restart keeps the list
	if err != nil || !m2.Active() || m2.Allowed(netip.MustParseAddr("11.0.0.1")) || !m2.Allowed(netip.MustParseAddr("10.2.3.4")) {
		t.Fatalf("not restored: %v", err)
	}
	// recovery flag path: Reset clears and persists
	if err := m2.Reset(); err != nil || m2.Active() {
		t.Fatalf("reset: %v", err)
	}
	m3, _ := New(kv)
	if m3.Active() {
		t.Fatal("reset not persisted")
	}
	// a corrupt stored list never locks the admin out
	kv["settings/adminallow"] = Settings{CIDRs: []string{"not-a-cidr"}}
	m4, err := New(kv)
	if err == nil || m4.Active() {
		t.Fatalf("corrupt list: err=%v active=%v", err, m4.Active())
	}
}

func TestTargetsListener(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.168.10.2"), netip.MustParseAddr("fd00::2")}
	resolve := func(h string) []netip.Addr {
		switch h {
		case "admin.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.10.2")}
		case "other.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.10.77")}
		}
		return nil
	}
	cases := []struct {
		listen, host string
		port         int
		want         bool
	}{
		{":8000", "127.0.0.1", 8000, true}, {":8000", "localhost", 8000, true}, {":8000", "192.168.10.2", 8000, true}, {":8000", "fd00::2", 8000, true},
		{":8000", "0.0.0.0", 8000, true}, {":8000", "admin.lan", 8000, true}, {":8000", "[::1]", 8000, true},
		{":8000", "127.0.0.1", 8001, false}, {":8000", "192.168.10.77", 8000, false}, {":8000", "other.lan", 8000, false}, {":8000", "127.0.0.1", 0, false},
		{"0.0.0.0:8000", "127.0.0.1", 8000, true}, {"[::]:8000", "192.168.10.2", 8000, true}, {"8000", "127.0.0.1", 8000, true},
		{"192.168.10.2:8000", "192.168.10.2", 8000, true}, {"192.168.10.2:8000", "127.0.0.1", 8000, false}, {"192.168.10.2:8000", "admin.lan", 8000, true},
		{"127.0.0.1:8000", "127.0.0.1", 8000, true}, {"127.0.0.1:8000", "192.168.10.2", 8000, false}, {"127.0.0.1:8000", "0.0.0.0", 8000, true},
		{"192.168.10.2:8000", "0.0.0.0", 8000, false},
	}
	for _, c := range cases {
		if got := TargetsListener(c.listen, c.host, c.port, local, resolve); got != c.want {
			t.Errorf("listen %q target %s:%d = %v, want %v", c.listen, c.host, c.port, got, c.want)
		}
	}
}
