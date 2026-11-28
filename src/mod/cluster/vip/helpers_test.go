package vip

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

type fakeLister struct {
	ifs []IfaceInfo
	err error
}

func (f fakeLister) Interfaces() ([]IfaceInfo, error) { return f.ifs, f.err }

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// fixture4 is Node A / Node B on 192.0.2.0/24 (placeholders only).
func fixture4() Shared {
	s := Defaults(false)
	s.Enabled, s.VIP, s.Prefix = true, "192.0.2.10", 24
	s.Auth, s.Password = AuthPassword, "Xb7kQ2mT"
	s.Members = []Member{
		{Label: "node-a", Address: "192.0.2.11", Priority: 150},
		{Label: "node-b", Address: "192.0.2.12", Priority: 100},
	}
	return s
}

func fixture6() Shared {
	s := Defaults(false)
	s.Enabled, s.VIP, s.Prefix = true, "2001:db8::10", 64
	s.Auth, s.Password = AuthPassword, "Xb7kQ2mT"
	s.Members = []Member{
		{Label: "node-a", Address: "2001:db8::11", Priority: 150},
		{Label: "node-b", Address: "2001:db8::12", Priority: 100},
	}
	return s
}

// envFor builds an Env for a host that owns addr on ens18.
func envFor(addr string) *Env {
	p := pfx(addr)
	return &Env{
		Version:    "1.0.0-test",
		Interfaces: []IfaceInfo{{Name: "lo", Up: true, Addrs: []netip.Prefix{pfx("127.0.0.1/8")}}, {Name: "ens18", Up: true, Addrs: []netip.Prefix{p}}},
		Listener:   ListenerFacts{HealthPort: ":8081", InboundPort: 443, TLS: true},
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file %s (run go test -update): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file.\n--- got ---\n%s\n--- want ---\n%s", name, got, string(want))
	}
}
