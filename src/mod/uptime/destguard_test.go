package uptime

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/destguard"
)

func useGuard(t *testing.T, s destguard.Settings) {
	t.Helper()
	g, _ := destguard.New(nil)
	if err := g.Set(s); err != nil {
		t.Fatal(err)
	}
	destguard.SetDefault(g)
	t.Cleanup(func() { destguard.SetDefault(nil) })
}

// Default (no guard installed): the monitor reaches loopback exactly as before.
func TestUptimeUnrestrictedReachesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	m := &Monitor{Config: &Config{}}
	if code, err := m.getWebsiteStatus(srv.URL, false, 3*time.Second); err != nil || code != 200 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	useGuard(t, destguard.Settings{}) //installed but all zero
	if code, err := m.getWebsiteStatus(srv.URL, false, 3*time.Second); err != nil || code != 200 {
		t.Fatalf("zero settings changed behaviour: code=%d err=%v", code, err)
	}
}

func TestUptimeRestrictedRefusesLoopbackUnlessListed(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer secure.Close()
	m := &Monitor{Config: &Config{}}

	useGuard(t, destguard.Settings{RestrictTools: true})
	if _, err := m.getWebsiteStatus(plain.URL, false, 3*time.Second); err == nil {
		t.Fatal("loopback http upstream reached with the restriction on")
	}
	if _, err := m.getWebsiteStatus(secure.URL, true, 3*time.Second); err == nil { //skip-verify has its own dialer
		t.Fatal("loopback https upstream reached through the skip-verify dialer")
	}

	useGuard(t, destguard.Settings{RestrictTools: true, AllowedBackends: []string{"127.0.0.1/32"}})
	if code, err := m.getWebsiteStatus(plain.URL, false, 3*time.Second); err != nil || code != 200 {
		t.Fatalf("listed backend refused: code=%d err=%v", code, err)
	}
	if code, err := m.getWebsiteStatus(secure.URL, true, 3*time.Second); err != nil || code != 200 {
		t.Fatalf("listed https backend refused: code=%d err=%v", code, err)
	}
}

// A listed backend that redirects to an address outside the list (here 127.0.0.2, standing in for the metadata service
// that cannot be bound in a test) must not be followed: the second server must never see a request.
func TestUptimeRedirectOutsideListIsNotFollowed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 not available")
	}
	var hits atomic.Int32
	other := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })}
	go other.Serve(ln)
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+ln.Addr().String()+"/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	m := &Monitor{Config: &Config{}}

	// control: unrestricted, the redirect is followed
	m.getWebsiteStatus(srv.URL, false, 2*time.Second)
	if hits.Load() == 0 {
		t.Fatal("control failed: the redirect target was not contacted without the restriction")
	}
	hits.Store(0)
	useGuard(t, destguard.Settings{RestrictTools: true, AllowedBackends: []string{"127.0.0.1/32"}})
	m.getWebsiteStatus(srv.URL, false, 2*time.Second)
	if hits.Load() != 0 {
		t.Fatalf("redirect target outside the allowed list was contacted %d times", hits.Load())
	}
}
