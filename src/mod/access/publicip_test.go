package access

import (
	"errors"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/database"
	"github.com/foleyit/dunree/mod/info/logger"
)

type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("network disabled in tests")
}

func newPublicIPTestController(t *testing.T, skip bool) *Controller {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(dir, "db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	c, err := NewAccessController(&Options{
		Logger:             *lg,
		ConfigFolder:       filepath.Join(dir, "access"),
		TrustedProxiesFile: filepath.Join(dir, "tp.json"),
		Database:           db,
		SkipPublicIPCheck:  skip,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Tests must be able to build an access controller without calling
// checkip.amazonaws.com (fork #250).
func TestSkipPublicIPCheckMakesNoNetworkCall(t *testing.T) {
	orig := http.DefaultTransport
	ct := &countingTransport{}
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = orig })

	c := newPublicIPTestController(t, true)
	time.Sleep(200 * time.Millisecond)
	if n := ct.n.Load(); n != 0 {
		t.Fatalf("public IP lookup made %d network calls despite SkipPublicIPCheck", n)
	}
	if c.PublicIP() != "127.0.0.1" {
		t.Errorf("unexpected public IP %q", c.PublicIP())
	}
}

// The public address is written by the background updater and read on the request path (loopback
// check, {{external_ip}} entries): the accessor must be safe for that (run with -race).
func TestPublicIPConcurrentAccess(t *testing.T) {
	c := newPublicIPTestController(t, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			c.setPublicIP("198.51.100.7")
			c.setPublicIP("203.0.113.9")
		}
	}()
	for i := 0; i < 2000; i++ {
		if ip := c.PublicIP(); ip != "127.0.0.1" && ip != "198.51.100.7" && ip != "203.0.113.9" {
			t.Fatalf("unexpected public IP %q", ip)
		}
		c.IsLoopbackRequest("203.0.113.9")
	}
	<-done
}
