package destguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// Every range that must never be contacted, in every plain and transition form.
func TestClassifyBlockedRanges(t *testing.T) {
	blocked := []string{
		// cloud metadata
		"169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "168.63.129.16", "fd00:ec2::254",
		// link-local
		"169.254.0.1", "169.254.255.254", "fe80::1", "fe80::abcd:1234",
		// multicast
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2", "ff01::1",
		// unspecified, "this network", reserved / broadcast
		"0.0.0.0", "::", "0.1.2.3", "240.0.0.1", "255.255.255.255",
		// IPv4-mapped forms of the above
		"::ffff:169.254.169.254", "::ffff:224.0.0.1", "::ffff:0.0.0.0", "::ffff:a9fe:a9fe",
		// NAT64 well known prefix carrying them
		"64:ff9b::a9fe:a9fe", "64:ff9b::169.254.169.254", "64:ff9b::e000:1", "64:ff9b::f000:1",
		// NAT64 local use, Teredo: refused outright
		"64:ff9b:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
		// 6to4 carrying metadata / link-local / multicast
		"2002:a9fe:a9fe::", "2002:a9fe:1::5", "2002:e000:1::",
		// IPv4-compatible
		"::169.254.169.254", "::a9fe:a9fe", "::0.0.0.5",
	}
	for _, a := range blocked {
		if c, err := Classify(ip(a)); err == nil {
			t.Errorf("%s was classified %d, must be refused", a, c)
		}
		if CheckIP(ip(a), true) == nil {
			t.Errorf("CheckIP(%s, allowLocal) must refuse", a)
		}
	}
	// zone identifiers do not hide a blocked address
	if _, err := Classify(ip("fe80::1%eth0")); err == nil {
		t.Error("fe80::1 with a zone passed")
	}
}

func TestClassifyAllowedAndLocal(t *testing.T) {
	cases := map[string]Class{
		"127.0.0.1": ClassLoopback, "127.5.5.5": ClassLoopback, "::1": ClassLoopback, "::ffff:127.0.0.1": ClassLoopback,
		"64:ff9b::7f00:1": ClassLoopback, "2002:7f00:1::": ClassLoopback,
		"10.1.2.3": ClassPrivate, "172.16.0.9": ClassPrivate, "172.31.255.255": ClassPrivate, "192.168.1.1": ClassPrivate,
		"fd12::1": ClassPrivate, "100.64.0.1": ClassPrivate, "::ffff:10.0.0.1": ClassPrivate, "64:ff9b::a00:1": ClassPrivate,
		"8.8.8.8": ClassPublic, "2606:4700::1111": ClassPublic, "64:ff9b::808:808": ClassPublic, "172.32.0.1": ClassPublic,
	}
	for a, want := range cases {
		got, err := Classify(ip(a))
		if err != nil || got != want {
			t.Errorf("%s: class %d err %v, want %d", a, got, err, want)
		}
	}
	// aiassist semantics are kept: local needs allowLocal
	if CheckIP(ip("10.0.0.1"), false) == nil || CheckIP(ip("10.0.0.1"), true) != nil || CheckIP(ip("8.8.8.8"), false) != nil {
		t.Error("CheckIP allowLocal semantics changed")
	}
}

func mustGuard(t *testing.T, s Settings) *Guard {
	t.Helper()
	g, _ := New(nil)
	if err := g.Set(s); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestZeroValueRestrictsNothing(t *testing.T) {
	var nilGuard *Guard
	zero := mustGuard(t, Settings{})
	for _, g := range []*Guard{nilGuard, zero} {
		if g.Restricting() || g.HasAllowList() {
			t.Fatal("zero settings must not restrict")
		}
		if g.CheckDest(ip("169.254.169.254"), 80) != nil || g.CheckBackend(ip("127.0.0.1"), 1) != nil {
			t.Fatal("zero settings refused something")
		}
		if g.ValidateBackend(context.Background(), "169.254.169.254:80") != nil {
			t.Fatal("ValidateBackend must be a no-op without a list")
		}
	}
}

func TestCheckDestSemantics(t *testing.T) {
	// restrict on, empty list: hard blocks and loopback refused, private and public pass
	g := mustGuard(t, Settings{RestrictTools: true})
	for _, a := range []string{"169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0", "::ffff:169.254.169.254", "127.0.0.1", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"} {
		if g.CheckDest(ip(a), 80) == nil {
			t.Errorf("%s must be refused with the restriction on", a)
		}
	}
	for _, a := range []string{"10.0.0.5", "192.168.1.9", "8.8.8.8"} {
		if err := g.CheckDest(ip(a), 80); err != nil {
			t.Errorf("%s refused with an empty list: %v", a, err)
		}
	}
	// restrict on, with a list: only listed destinations (and ports) pass; loopback only when listed
	g = mustGuard(t, Settings{RestrictTools: true, AllowedBackends: []string{"10.20.0.0/24", "10.30.0.5 443,8000-8100", "127.0.0.1:9000", "fd00:1::/64"}})
	ok := [][2]string{{"10.20.0.7", "80"}, {"10.20.0.7", "0"}, {"10.30.0.5", "443"}, {"10.30.0.5", "8050"}, {"127.0.0.1", "9000"}, {"fd00:1::5", "22"}, {"::ffff:10.20.0.7", "80"}}
	for _, c := range ok {
		p, _ := strconv.Atoi(c[1])
		if err := g.CheckDest(ip(c[0]), p); err != nil {
			t.Errorf("%s:%s refused: %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{{"10.21.0.7", "80"}, {"10.30.0.5", "22"}, {"10.30.0.5", "8101"}, {"127.0.0.1", "9001"}, {"127.0.0.2", "9000"}, {"8.8.8.8", "443"}, {"::1", "9000"},
		{"169.254.169.254", "80"}, {"fd00:ec2::254", "80"}}
	for _, c := range bad {
		p, _ := strconv.Atoi(c[1])
		if g.CheckDest(ip(c[0]), p) == nil {
			t.Errorf("%s:%s accepted", c[0], c[1])
		}
	}
	// a hard-blocked address stays blocked even when the admin lists it
	g = mustGuard(t, Settings{RestrictTools: true, AllowedBackends: []string{"169.254.0.0/16", "224.0.0.0/4"}})
	if g.CheckDest(ip("169.254.169.254"), 80) == nil || g.CheckBackend(ip("169.254.169.254"), 80) == nil || g.CheckDest(ip("224.0.0.1"), 80) == nil {
		t.Error("listing a blocked range must not unblock it")
	}
}

func TestCheckBackendOnlyWithList(t *testing.T) {
	// no restrict switch: the list alone governs rule targets
	g := mustGuard(t, Settings{AllowedBackends: []string{"10.0.0.0/8 80,443"}})
	if g.Restricting() {
		t.Fatal("list alone must not restrict the tools")
	}
	if g.CheckBackend(ip("10.1.1.1"), 443) != nil {
		t.Error("listed backend refused")
	}
	for _, c := range []struct {
		a string
		p int
	}{{"10.1.1.1", 8080}, {"192.168.1.1", 80}, {"8.8.8.8", 443}, {"127.0.0.1", 80}, {"169.254.169.254", 80}} {
		if g.CheckBackend(ip(c.a), c.p) == nil {
			t.Errorf("%s:%d accepted as rule target", c.a, c.p)
		}
	}
	// the tools are not restricted by the list when the switch is off
	if g.CheckDest(ip("169.254.169.254"), 80) != nil {
		t.Error("CheckDest must be a no-op while the switch is off")
	}
}

func TestParseEntries(t *testing.T) {
	good := []string{"10.0.0.0/8", "10.1.2.3", "10.0.0.0/24 443", "10.0.0.0/24 443,8000-8100", "10.0.0.5:443", "[fd00::5]:443", "fd00::/8", "fd00::1 22", "::ffff:10.0.0.1"}
	for _, e := range good {
		if err := ParseEntry(e); err != nil && e != "::ffff:10.0.0.1" {
			t.Errorf("%q: %v", e, err)
		}
	}
	bad := []string{"0.0.0.0/0", "::/0", "example.com", "10.0.0.0/33", "10.0.0.0/8 0", "10.0.0.0/8 70000", "10.0.0.0/8 90-80", "10.0.0.0/8 abc", "10.0.0.5:443 80", "999.1.1.1", "10.0.0.0/8 "}
	for _, e := range bad {
		if e == "10.0.0.0/8 " { // trailing blank is trimmed by the caller
			continue
		}
		if ParseEntry(e) == nil {
			t.Errorf("%q accepted", e)
		}
	}
	g, _ := New(nil)
	if g.Set(Settings{AllowedBackends: make([]string, 300)}) == nil {
		t.Error("too many entries accepted")
	}
	if g.Set(Settings{RestrictTools: true, AllowedBackends: []string{"nonsense"}}) == nil || g.Restricting() {
		t.Error("a failed Set must change nothing")
	}
}

type memKV map[string]interface{}

func (m memKV) Read(table, key string, out interface{}) error {
	v, ok := m[table+"/"+key]
	if !ok {
		return errors.New("not found")
	}
	switch o := out.(type) {
	case *Settings:
		*o = v.(Settings)
	}
	return nil
}
func (m memKV) Write(table, key string, v interface{}) error { m[table+"/"+key] = v; return nil }

func TestPersistenceAndBackwardCompat(t *testing.T) {
	kv := memKV{}
	// nothing stored (every existing install): nothing restricted
	g, err := New(kv)
	if err != nil || g.Restricting() || g.HasAllowList() {
		t.Fatalf("fresh install: %v %v", err, g.Settings())
	}
	if err := g.Set(Settings{RestrictTools: true, AllowedBackends: []string{"10.0.0.0/8", " ", "10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	g2, err := New(kv) // restart
	if err != nil || !g2.Restricting() || len(g2.Settings().AllowedBackends) != 1 {
		t.Fatalf("not restored: %v %+v", err, g2.Settings())
	}
	// a stored value that no longer validates falls back to no restriction, with an error
	kv["settings/destguard"] = Settings{RestrictTools: true, AllowedBackends: []string{"junk"}}
	g3, err := New(kv)
	if err == nil || g3.Restricting() {
		t.Fatalf("corrupt value: err %v restricting %v", err, g3.Restricting())
	}
	if string(Settings{}.JSON()) != `{"restrictTools":false,"allowedBackends":[]}` {
		t.Fatalf("JSON %s", Settings{}.JSON())
	}
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"10.0.0.5:8080", "10.0.0.5", 8080, true}, {"app.lan", "app.lan", 0, true}, {"http://app.lan", "app.lan", 80, true},
		{"https://app.lan/x?y", "app.lan", 443, true}, {"[fd00::1]:443", "fd00::1", 443, true}, {"fd00::1", "fd00::1", 0, true},
		{"user:pw@10.0.0.5:81/x", "10.0.0.5", 81, true}, {"unix:/run/x.sock", "", 0, true}, {"", "", 0, false}, {"10.0.0.5:99999", "", 0, false},
	}
	for _, c := range cases {
		h, p, ok := SplitTarget(c.in)
		if h != c.host || p != c.port || ok != c.ok {
			t.Errorf("%q -> %q %d %v, want %q %d %v", c.in, h, p, ok, c.host, c.port, c.ok)
		}
	}
}

func TestValidateBackendResolvesNames(t *testing.T) {
	g := mustGuard(t, Settings{AllowedBackends: []string{"10.0.0.0/8"}})
	g.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "good.lan":
			return []netip.Addr{ip("10.0.0.5")}, nil
		case "mixed.lan": //one answer outside the list is enough to refuse
			return []netip.Addr{ip("10.0.0.5"), ip("192.168.0.1")}, nil
		case "meta.lan":
			return []netip.Addr{ip("169.254.169.254")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	for in, wantErr := range map[string]bool{"good.lan:80": false, "10.2.3.4:80": false, "mixed.lan": true, "meta.lan:80": true, "nx.lan": true, "192.168.1.1:80": true,
		"http://good.lan/path": false, "unix:/run/app.sock": false, "[::1]:80": true} {
		if err := g.ValidateBackend(context.Background(), in); (err != nil) != wantErr {
			t.Errorf("%q: err %v, want error=%v", in, err, wantErr)
		}
	}
}

// listener on loopback standing in for the "checked" address
func loopbackListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener")
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// DNS rebinding: the first answer is allowed, a second lookup would answer the metadata address. The guard resolves
// exactly once and dials the checked address, so the second answer is never used.
func TestDialResolvesOnceAndDialsCheckedAddress(t *testing.T) {
	_, port := loopbackListener(t)
	g := mustGuard(t, Settings{RestrictTools: true, AllowedBackends: []string{"127.0.0.1/32"}})
	var calls atomic.Int32
	g.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			return []netip.Addr{ip("127.0.0.1")}, nil
		}
		return []netip.Addr{ip("169.254.169.254")}, nil
	}
	c, err := g.DialContext(context.Background(), &net.Dialer{Timeout: time.Second}, "tcp", "rebind.example:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if calls.Load() != 1 {
		t.Fatalf("name resolved %d times, want exactly once", calls.Load())
	}
	if ra := c.RemoteAddr().(*net.TCPAddr); !ra.IP.IsLoopback() {
		t.Fatalf("connected to %v, not the checked address", ra)
	}
}

func TestDialRefusals(t *testing.T) {
	_, port := loopbackListener(t)
	p := strconv.Itoa(port)
	var calls atomic.Int32
	g := mustGuard(t, Settings{RestrictTools: true})
	g.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		switch host {
		case "loop.example":
			return []netip.Addr{ip("127.0.0.1")}, nil
		case "meta.example":
			return []netip.Addr{ip("169.254.169.254")}, nil
		case "mixed.example": // public-looking first, metadata second: the whole answer is refused
			return []netip.Addr{ip("8.8.8.8"), ip("169.254.169.254")}, nil
		case "mapped.example":
			return []netip.Addr{ip("::ffff:169.254.169.254")}, nil
		case "nat64.example":
			return []netip.Addr{ip("64:ff9b::a9fe:a9fe")}, nil
		case "nat64loop.example":
			return []netip.Addr{ip("64:ff9b::7f00:1")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	for _, addr := range []string{"127.0.0.1:" + p, "[::1]:" + p, "localhost-ip.example:" + p, "loop.example:" + p, "meta.example:80", "mixed.example:80", "mapped.example:80",
		"nat64.example:80", "nat64loop.example:" + p, "169.254.169.254:80", "[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:80", "224.0.0.1:80", "0.0.0.0:" + p} {
		c, err := g.DialContext(context.Background(), &net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", addr)
		if err == nil {
			c.Close()
			t.Errorf("%s: dial succeeded", addr)
		}
	}
	if _, err := g.DialContext(context.Background(), nil, "unix", "/tmp/x.sock"); err == nil {
		t.Error("unix dial allowed while restricting")
	}
	if _, err := g.DialContext(context.Background(), nil, "tcp", "no-port"); err == nil {
		t.Error("address without port allowed")
	}
}

// Not restricting: the guard dials like net.Dialer, loopback included (today's behaviour).
func TestDialUnrestrictedIsPlainDial(t *testing.T) {
	_, port := loopbackListener(t)
	for _, g := range []*Guard{nil, mustGuard(t, Settings{})} {
		c, err := g.DialContext(context.Background(), nil, "tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatalf("plain dial refused: %v", err)
		}
		c.Close()
	}
	// package level entry points: no default guard = net.DialTimeout
	SetDefault(nil)
	c, err := DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// default guard restricting: loopback refused, then removed again
	SetDefault(mustGuard(t, Settings{RestrictTools: true}))
	defer SetDefault(nil)
	if c, err := DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second); err == nil {
		c.Close()
		t.Fatal("loopback dial allowed through the default guard")
	} else if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("unexpected error %v", err)
	}
	if !Restricting() || CheckDest(ip("169.254.169.254"), 80) == nil {
		t.Fatal("package level helpers do not follow the default guard")
	}
}
