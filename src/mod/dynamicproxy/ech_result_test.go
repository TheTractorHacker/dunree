package dynamicproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/ech"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
)

const echTestPublic = "public.ech.test"

type echSeen struct {
	outcome, outer, sni, proto string
}

// echTestServer is an HTTPS server wired like the proxy listeners: applyEch on the TLS config, echConnContext as
// ConnContext, echObserve and the request log per request.
func echTestServer(t *testing.T, router *Router, lg *logger.Logger) (*httptest.Server, func() echSeen) {
	t.Helper()
	var mu sync.Mutex
	var last echSeen
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.echObserve(r)
		o, outer, ok := EchResultOf(r)
		if !ok {
			t.Error("a TLS request must have a result")
		}
		mu.Lock()
		last = echSeen{o, outer, r.TLS.ServerName, r.Proto}
		mu.Unlock()
		if lg != nil {
			lg.LogHTTPRequest(r, "host-http", 200, r.Host, "", "192.0.2.1")
		}
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{}
	router.applyEch(srv.TLS)
	srv.Config.ConnContext = router.echConnContext
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func() echSeen { mu.Lock(); defer mu.Unlock(); return last }
}

func echTestGet(t *testing.T, srv *httptest.Server, sni string, list []byte, h2 bool, maxVersion uint16) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: sni, RootCAs: pool, EncryptedClientHelloConfigList: list, MaxVersion: maxVersion},
		ForceAttemptHTTP2: h2,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://example.com/path")
	if err != nil {
		t.Fatalf("GET with sni %q: %v", sni, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestEchResultPerRequestAndCounters(t *testing.T) {
	m, err := ech.Open(filepath.Join(t.TempDir(), "ech"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetSettings(ech.Settings{Enabled: true, PublicName: echTestPublic, LogRequests: true}); err != nil {
		t.Fatal(err)
	}
	list, _ := base64.StdEncoding.DecodeString(m.ConfigListBase64())
	if len(list) == 0 {
		t.Fatal("no ECH config list")
	}
	dir := t.TempDir()
	lg, err := logger.NewLogger("zr", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()
	lg.ECHField = func(r *http.Request) string {
		o, outer, ok := EchResultOf(r)
		if !ok {
			return ""
		}
		return o + " outer=" + outer
	}
	router := &Router{Option: &RouterOption{
		EchKeys:    func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return m.TLSKeys(), nil },
		EchObserve: m.ObserveOutcome,
	}}
	srv, seen := echTestServer(t, router, lg)

	// 1. ECH accepted, HTTP/2 and HTTP/1.1: the request is routed on the inner name, the log gets the outer one
	for _, h2 := range []bool{true, false} {
		echTestGet(t, srv, "example.com", list, h2, 0)
		got := seen()
		if got.outcome != EchAccepted || got.outer != echTestPublic || got.sni != "example.com" {
			t.Fatalf("accepted (h2=%v): %+v", h2, got)
		}
		if h2 != (got.proto == "HTTP/2.0") {
			t.Fatalf("protocol: h2=%v got %s", h2, got.proto)
		}
	}
	// 2. GREASE: a TLS 1.3 client without an ECH config (Go's client, like the browsers) sends a dummy ECH
	// extension. The server sees an offer it cannot decrypt and the name travels in clear text.
	echTestGet(t, srv, "example.com", nil, true, 0)
	if got := seen(); got.outcome != EchOffered || got.outer != "example.com" {
		t.Fatalf("grease: %+v", got)
	}
	// 3. no ECH at all (a TLS 1.2 client): the only server name is the clear text one
	echTestGet(t, srv, "example.com", nil, false, tls.VersionTLS12)
	if got := seen(); got.outcome != EchPlain || got.outer != "example.com" {
		t.Fatalf("plain: %+v", got)
	}
	if o := m.OutcomeStats(); o.Accepted != 2 || o.Offered != 1 || o.Plain != 1 {
		t.Fatalf("counters by outcome: %+v", o)
	}
	if a, p := m.Stats(); a != 2 || p != 2 {
		t.Fatalf("legacy counters: %d %d", a, p)
	}

	// the request log lines
	var text string
	for i := 0; i < 50; i++ {
		b, _ := os.ReadFile(lg.CurrentLogFile)
		text = string(b)
		if strings.Count(text, "[router:host-http]") >= 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := strings.Count(text, "] [ech: accepted outer="+echTestPublic+"] GET /path 200"); n != 2 {
		t.Fatalf("want 2 accepted lines, got %d:\n%s", n, text)
	}
	for _, want := range []string{"] [ech: offered outer=example.com] GET /path 200", "] [ech: plain outer=example.com] GET /path 200"} {
		if !strings.Contains(text, want) {
			t.Fatalf("line %q missing:\n%s", want, text)
		}
	}
}

// A client that offers ECH with a config this server has no key for (stale DNS record, another provider's config):
// the server sees the extension, cannot decrypt it and carries on with the outer name. A real client aborts such a
// connection, so no request follows; the test reads the connection state the request would have carried.
func TestEchResultOfferedNotDecrypted(t *testing.T) {
	ours, _ := ech.Open(filepath.Join(t.TempDir(), "a"))
	foreign, _ := ech.Open(filepath.Join(t.TempDir(), "b"))
	for _, m := range []*ech.Manager{ours, foreign} {
		if err := m.SetSettings(ech.Settings{Enabled: true, PublicName: echTestPublic}); err != nil {
			t.Fatal(err)
		}
	}
	foreignList, _ := base64.StdEncoding.DecodeString(foreign.ConfigListBase64())
	router := &Router{Option: &RouterOption{
		EchKeys:    func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return ours.TLSKeys(), nil },
		EchObserve: ours.ObserveOutcome,
	}}
	cert := httptest.NewTLSServer(nil)
	defer cert.Close()
	cfg := &tls.Config{Certificates: cert.TLS.Certificates}
	router.applyEch(cfg)

	cli, srvConn := net.Pipe()
	defer cli.Close()
	defer srvConn.Close()
	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: "hidden.example.com", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: foreignList})
		c.Handshake() //fails with an ECH rejection, as a browser would
		cli.Close()
	}()
	ctx := router.echConnContext(context.Background(), srvConn)
	tc := tls.Server(srvConn, cfg)
	srvConn.SetDeadline(time.Now().Add(10 * time.Second))
	tc.HandshakeContext(ctx) //the client aborts after seeing the rejection; the hello was processed either way
	st := tc.ConnectionState()
	if st.ECHAccepted {
		t.Fatal("a foreign config must not be accepted")
	}
	r := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	r.TLS = &st
	o, outer, ok := EchResultOf(r)
	if !ok || o != EchOffered || outer != echTestPublic {
		t.Fatalf("offered: %q %q %v (server name %q)", o, outer, ok, st.ServerName)
	}
	router.echObserve(r)
	if oc := ours.OutcomeStats(); oc.Offered != 1 || oc.Accepted != 0 || oc.Plain != 0 {
		t.Fatalf("counters: %+v", oc)
	}
}

func TestEchResultEdges(t *testing.T) {
	if _, _, ok := EchResultOf(httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("a plain HTTP request has no ECH result")
	}
	// no connection note (HTTP/3, or ECH support not wired): accepted without an outer name, the rest is plain
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{ECHAccepted: true, ServerName: "inner.example.com"}
	if o, outer, _ := EchResultOf(r); o != EchAccepted || outer != "" {
		t.Fatalf("accepted without note: %q %q", o, outer)
	}
	// a server name is network input: nothing that could break a log line survives
	r.TLS = &tls.ConnectionState{ServerName: "Evil] [ech: accepted\nX.example"}
	if o, outer, _ := EchResultOf(r); o != EchPlain || outer != "evil???ech??accepted?x.example" {
		t.Fatalf("sanitised: %q %q", o, outer)
	}
	// without ECH keys the listeners add nothing to the connection context
	router := &Router{Option: &RouterOption{}}
	ctx := context.Background()
	if router.echConnContext(ctx, nil) != ctx {
		t.Fatal("no ECH callback: the context must stay untouched")
	}
	cfg := &tls.Config{}
	router.applyEch(cfg)
	if cfg.GetEncryptedClientHelloKeys != nil {
		t.Fatal("no ECH callback: the TLS config must stay untouched")
	}
}
