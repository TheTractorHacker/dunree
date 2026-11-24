package dynamicproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/tlscert"
)

// The production wiring of the ECH note: the real main TLS listener (StartProxyService) and a real secondary TLS
// listener must both carry echConnContext. Without it the callback has nowhere to note the offer, a placeholder
// (GREASE) request is counted and logged as "plain" and an accepted one loses its outer name. echTestServer in
// ech_result_test.go sets ConnContext itself, so only this test fails when the line is removed from a listener.
func TestEchConnContextOnRealListeners(t *testing.T) {
	t.Chdir(t.TempDir()) //tlscert.NewManager writes ./tmp/localhost.*
	router, sep, _ := newNonTLSTestRouter(t)
	mgr, err := tlscert.NewManager(t.TempDir(), router.Option.Logger)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.TlsManager = mgr

	var mu sync.Mutex
	var seen []bool //offered flag of every observed TLS request
	router.Option.EchKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return nil, nil }
	router.Option.EchObserve = func(accepted, offered bool) {
		mu.Lock()
		seen = append(seen, offered && !accepted)
		mu.Unlock()
	}

	mainPort, secPort := freeTCPPort(t), freeTCPPort(t)
	secAddr := "127.0.0.1:" + strconv.Itoa(secPort)
	sep.ListeningPorts = []string{secAddr}
	sep.SecondaryPortsTLS = true
	sep.initNetworkOptions()
	router.ProxyEndpoints.Store("app.example.com", sep)
	router.Root = &ProxyEndpoint{}
	router.secondaryServers = map[string]*http.Server{}
	router.secondaryStopChans = map[string]chan bool{}
	router.Option.UseTls = true
	router.Option.Port = mainPort
	if err := router.StartProxyService(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.StopProxyServiceWithin(2 * time.Second) })
	if msg := router.ListenError(); msg != "" {
		t.Fatal(msg)
	}

	if router.server == nil || router.server.ConnContext == nil {
		t.Fatal("the main TLS server has no ConnContext")
	}
	router.secondaryServerMutex.RLock()
	sec := router.secondaryServers[secAddr]
	router.secondaryServerMutex.RUnlock()
	if sec == nil || sec.TLSConfig == nil || sec.ConnContext == nil {
		t.Fatal("the secondary TLS server is missing, not TLS or has no ConnContext")
	}

	// one GREASE request per listener: a TLS 1.3 client without an ECH config sends a placeholder extension
	grease := func(addr string) error {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
			DisableKeepAlives: true,
			Dial:              func(network, _ string) (net.Conn, error) { return net.DialTimeout(network, addr, 2*time.Second) },
		}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://app.example.com/")
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	for _, l := range []struct{ name, addr string }{{"main", "127.0.0.1:" + strconv.Itoa(mainPort)}, {"secondary", secAddr}} {
		mu.Lock()
		seen = nil
		mu.Unlock()
		var err error
		for i := 0; i < 100; i++ { //the listeners start in the background
			if err = grease(l.addr); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s listener: %v", l.name, err)
		}
		mu.Lock()
		got := append([]bool(nil), seen...)
		mu.Unlock()
		if len(got) != 1 || !got[0] {
			t.Fatalf("%s listener: a placeholder (GREASE) request must be observed as offered, got %v", l.name, got)
		}
	}
}
