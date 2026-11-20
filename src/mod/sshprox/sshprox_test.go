package sshprox

import (
	"net"
	"testing"

	"imuslab.com/zoraxy/mod/destguard"
)

func TestInstance_Destroy(t *testing.T) {
	manager := NewSSHProxyManager()
	instance, err := manager.NewSSHProxy("/tmp")
	if err != nil {
		t.Fatalf("Failed to create new SSH proxy: %v", err)
	}

	instance.Destroy()

	if len(manager.Instances) != 0 {
		t.Errorf("Expected Instances to be empty, got %d", len(manager.Instances))
	}
}

func TestInstance_ValidateUsernameAndRemoteAddr(t *testing.T) {
	tests := []struct {
		username    string
		remoteAddr  string
		expectError bool
	}{
		{"validuser", "127.0.0.1", false},
		{"valid.user", "example.com", false},
		{"; bash ;", "example.com", true},
		{"valid-user", "example.com", false},
		{"invalid user", "127.0.0.1", true},
		{"validuser", "invalid address", true},
		{"invalid@user", "127.0.0.1", true},
		{"validuser", "invalid@address", true},
		{"injection; rm -rf /", "127.0.0.1", true},
		{"validuser", "127.0.0.1; rm -rf /", true},
		{"$(reboot)", "127.0.0.1", true},
		{"validuser", "$(reboot)", true},
		{"validuser", "127.0.0.1; $(reboot)", true},
		{"validuser", "127.0.0.1 | ls", true},
		{"validuser", "127.0.0.1 & ls", true},
		{"validuser", "127.0.0.1 && ls", true},
		{"validuser", "127.0.0.1 |& ls", true},
		{"validuser", "127.0.0.1 ; ls", true},
		{"validuser", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"validuser", "2001:db8::ff00:42:8329", false},
		{"validuser", "2001:db8:0:1234:0:567:8:1", false},
		{"validuser", "2001:db8::1234:0:567:8:1", false},
		{"validuser", "2001:db8:0:0:0:0:2:1", false},
		{"validuser", "2001:db8::2:1", false},
		{"validuser", "2001:db8:0:0:8:800:200c:417a", false},
		{"validuser", "2001:db8::8:800:200c:417a", false},
		{"validuser", "2001:db8:0:0:8:800:200c:417a; rm -rf /", true},
		{"validuser", "2001:db8::8:800:200c:417a; rm -rf /", true},
	}

	for _, test := range tests {
		err := ValidateUsernameAndRemoteAddr(test.username, test.remoteAddr)
		if test.expectError && err == nil {
			t.Errorf("Expected error for username %s and remoteAddr %s, but got none", test.username, test.remoteAddr)
		}
		if !test.expectError && err != nil {
			t.Errorf("Did not expect error for username %s and remoteAddr %s, but got %v", test.username, test.remoteAddr, err)
		}
	}
}

func TestIsSSHConnectableHonoursDestinationGuard(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n"))
			c.Read(make([]byte, 64))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	if !IsSSHConnectable("127.0.0.1", port) {
		t.Fatal("unrestricted probe failed")
	}
	g, _ := destguard.New(nil)
	g.Set(destguard.Settings{RestrictTools: true})
	destguard.SetDefault(g)
	defer destguard.SetDefault(nil)
	if IsSSHConnectable("127.0.0.1", port) {
		t.Fatal("loopback ssh probe allowed with the restriction on")
	}
	if IsSSHConnectable("169.254.169.254", 22) {
		t.Fatal("metadata address probed")
	}
}
