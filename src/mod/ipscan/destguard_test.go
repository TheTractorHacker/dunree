package ipscan

import (
	"net"
	"testing"

	"imuslab.com/zoraxy/mod/destguard"
)

func guardWith(t *testing.T, s destguard.Settings) {
	t.Helper()
	g, _ := destguard.New(nil)
	if err := g.Set(s); err != nil {
		t.Fatal(err)
	}
	destguard.SetDefault(g)
	t.Cleanup(func() { destguard.SetDefault(nil) })
}

func TestCheckTargetOffByDefault(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1"} {
		if err := CheckTarget(h); err != nil {
			t.Errorf("%s refused with no guard: %v", h, err)
		}
	}
	guardWith(t, destguard.Settings{})
	if err := CheckTarget("127.0.0.1"); err != nil {
		t.Errorf("zero settings refused loopback: %v", err)
	}
}

func TestCheckTargetRestricted(t *testing.T) {
	guardWith(t, destguard.Settings{RestrictTools: true, AllowedBackends: []string{"10.20.0.0/24"}})
	for _, h := range []string{"127.0.0.1", "169.254.169.254", "fd00:ec2::254", "224.0.0.1", "10.21.0.1", "8.8.8.8", "::ffff:169.254.169.254", "name.example"} {
		if CheckTarget(h) == nil {
			t.Errorf("%s accepted", h)
		}
	}
	if err := CheckTarget("10.20.0.9"); err != nil {
		t.Errorf("listed host refused: %v", err)
	}
}

// The scan itself must not connect to a refused destination: the dial is guarded even if a caller skips CheckTarget.
func TestPortScanDoesNotReachLoopbackWhenRestricted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			got <- struct{}{}
		}
	}()
	host := &DiscoveredHost{IP: "127.0.0.1"}
	if ports := host.ScanPorts(port, port); len(ports) != 1 {
		t.Fatalf("unrestricted scan did not find the open port: %v", ports)
	}
	<-got
	guardWith(t, destguard.Settings{RestrictTools: true})
	if ports := host.ScanPorts(port, port); len(ports) != 0 {
		t.Fatalf("restricted scan found %v on loopback", ports)
	}
	if _, err := ScanIpRange("127.0.0.1", "127.0.0.3"); err == nil {
		t.Fatal("restricted IP range scan of loopback returned results instead of a refusal")
	}
	if _, err := ScanIpRange("169.254.169.253", "169.254.169.255"); err == nil {
		t.Fatal("range containing the metadata address was scanned")
	}
}
