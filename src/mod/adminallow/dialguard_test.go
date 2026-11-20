package adminallow

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func startAdmin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("admin")) }))
	t.Cleanup(s.Close)
	_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	return s, port
}

// Attack: a proxy rule points at the admin port. The refusal must not depend on any header (a client or
// dpcore can drop X-Forwarded-Server), so it is made on the dialled address.
func TestDialToAdminListenerRefusedWhileListIsOn(t *testing.T) {
	s, port := startAdmin(t)
	m, _ := New(memKV{})
	InstallDialGuard(m, "0.0.0.0:"+port)
	t.Cleanup(func() { InstallDialGuard(nil, "") })

	dial := func(host string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			c.Close()
		}
		return err
	}
	// no allow-list: today's behaviour, the dial works
	if err := dial("127.0.0.1"); err != nil {
		t.Fatalf("dial refused with no allow-list: %v", err)
	}
	if err := m.Set(Settings{CIDRs: []string{"127.0.0.1"}}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		err := dial(h)
		if h == "::1" && err != nil && !errors.Is(err, ErrAdminPortDial) {
			continue //no IPv6 listener on this host: refused or unreachable, either way not connected
		}
		if err == nil || !errors.Is(err, ErrAdminPortDial) {
			t.Errorf("dial to admin listener via %s not refused: %v", h, err)
		}
	}
	// same host, other port: untouched
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	if c, err := DialContext(context.Background(), "tcp", other.Listener.Addr().String()); err != nil {
		t.Errorf("dial to an unrelated port refused: %v", err)
	} else {
		c.Close()
	}
	// an http.Client using the guarded dialer cannot reach the admin handler
	cl := &http.Client{Transport: &http.Transport{DialContext: DialContext}}
	if resp, err := cl.Get(s.URL); err == nil {
		resp.Body.Close()
		t.Error("HTTP request reached the admin listener through the guarded transport")
	}
	// list cleared: dial works again
	if err := m.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := dial("127.0.0.1"); err != nil {
		t.Errorf("dial refused after the list was cleared: %v", err)
	}
}

func TestDialBlockedAddressForms(t *testing.T) {
	m, _ := New(memKV{})
	_ = m.Set(Settings{CIDRs: []string{"127.0.0.1"}}, "127.0.0.1")
	InstallDialGuard(m, ":"+strconv.Itoa(8123))
	t.Cleanup(func() { InstallDialGuard(nil, "") })
	for addr, want := range map[string]bool{"127.0.0.1:8123": true, "[::1]:8123": true, "0.0.0.0:8123": true, "127.0.0.1:8124": false, "203.0.113.5:8123": false} {
		if got := DialBlocked("tcp", addr); got != want {
			t.Errorf("%s blocked=%v want %v", addr, got, want)
		}
	}
	if DialBlocked("unix", "/tmp/x") {
		t.Error("unix dial judged")
	}
}
