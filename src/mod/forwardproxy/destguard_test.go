package forwardproxy

import (
	"net"
	"strconv"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/destguard"
)

func TestGuardedDialer(t *testing.T) {
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
			c.Close()
		}
	}()
	addr := "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	d := guardedDialer{}

	// default: identical to the old dialer, loopback reachable
	if s := d.Dial(addr); s == nil {
		t.Fatal("unrestricted forward proxy refused loopback")
	} else {
		s.Close()
	}

	g, _ := destguard.New(nil)
	g.Set(destguard.Settings{RestrictTools: true})
	destguard.SetDefault(g)
	defer destguard.SetDefault(nil)
	for _, a := range []string{addr, "169.254.169.254:80", "[fd00:ec2::254]:80", "[::1]:80"} {
		if s := d.Dial(a); s != nil {
			s.Close()
			t.Errorf("forward proxy connected to %s with the restriction on", a)
		}
	}
}
