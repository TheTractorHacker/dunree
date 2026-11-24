package dynamicproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

/*
	h2c on virtual directories (issue #201, upstream #1029)

	NetBird and similar products serve gRPC services on plain HTTP/2 under fixed paths
	(/signalexchange.SignalExchange/, /management.ManagementService/) next to ordinary
	HTTP paths on the same host name. The per-upstream h2c option only covers the host
	rule, so the gRPC paths need the option on the virtual directory.
*/

type vdirH2CSeen struct {
	mu    sync.Mutex
	proto string
	path  string
}

func (s *vdirH2CSeen) set(r *http.Request) {
	s.mu.Lock()
	s.proto, s.path = r.Proto, r.URL.Path
	s.mu.Unlock()
}

func (s *vdirH2CSeen) get() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proto, s.path
}

// vdirGRPCLikeBackend only speaks HTTP/2 (like a gRPC server), echoes each line of the
// request body as it arrives and ends with a Grpc-Status trailer
func vdirGRPCLikeBackend(t *testing.T, seen *vdirH2CSeen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.set(r)
		if r.ProtoMajor != 2 {
			http.Error(w, "http/2 only", http.StatusHTTPVersionNotSupported)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			w.Write([]byte(sc.Text() + "\n"))
			w.(http.Flusher).Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	}), &http2.Server{}))
	t.Cleanup(srv.Close)
	return srv
}

// vdirH2CFront serves the endpoint the way the listener does, reachable with prior-knowledge
// HTTP/2 so the test client can behave like a gRPC client
func vdirH2CFront(t *testing.T, router *Router, sep *ProxyEndpoint) (*httptest.Server, *http.Client) {
	t.Helper()
	front := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.handleNonTLSRequest(w, r, sep)
	}), &http2.Server{}))
	t.Cleanup(front.Close)
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return front, &http.Client{Transport: tr}
}

func TestVdirH2C_GRPCPathNextToPlainHTTPPath(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil

	grpcSeen, apiSeen := &vdirH2CSeen{}, &vdirH2CSeen{}
	grpcBackend := vdirGRPCLikeBackend(t, grpcSeen)
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiSeen.set(r)
		w.Write([]byte("api-ok"))
	}))
	defer apiBackend.Close()

	// The matched prefix is replaced by the path of the target, so a gRPC service keeps its
	// full method path when the target repeats the prefix (this is what the guide tells to enter)
	const grpcPrefix = "/signalexchange.SignalExchange/"
	sep.ProxyType = ProxyTypeHost
	sep.VirtualDirectories = []*VirtualDirectoryEndpoint{
		{MatchingPath: grpcPrefix, Domain: strings.TrimPrefix(grpcBackend.URL, "http://") + grpcPrefix, H2C: true},
		{MatchingPath: "/api/", Domain: strings.TrimPrefix(apiBackend.URL, "http://") + "/api/"},
	}
	if _, err := router.PrepareProxyRoute(sep); err != nil {
		t.Fatal(err)
	}
	front, client := vdirH2CFront(t, router, sep)

	// gRPC style bidirectional stream through the h2c virtual directory
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, front.URL+grpcPrefix+"ConnectStream", pr)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gRPC path: status %d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	for _, msg := range []string{"m1", "m2"} {
		if _, err := pw.Write([]byte(msg + "\n")); err != nil {
			t.Fatal(err)
		}
		got := make(chan string, 1)
		go func() {
			line, _ := reader.ReadString('\n')
			got <- strings.TrimSpace(line)
		}()
		select {
		case line := <-got:
			if line != msg {
				t.Fatalf("echo = %q, want %q", line, msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no echo for %q while the request is still open: the stream is buffered", msg)
		}
	}
	pw.Close()
	io.Copy(io.Discard, reader)
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("trailer Grpc-Status = %q, want 0", got)
	}
	proto, path := grpcSeen.get()
	if proto != "HTTP/2.0" {
		t.Errorf("gRPC target saw %q, want HTTP/2.0", proto)
	}
	if path != grpcPrefix+"ConnectStream" {
		t.Errorf("gRPC target saw path %q, want %q", path, grpcPrefix+"ConnectStream")
	}

	// The other virtual directory of the same host is untouched: still HTTP/1.1
	r2, err := client.Get(front.URL + "/api/peers")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 200 || string(body) != "api-ok" {
		t.Fatalf("plain path: %d %q", r2.StatusCode, body)
	}
	if proto, path := apiSeen.get(); proto != "HTTP/1.1" || path != "/api/peers" {
		t.Errorf("plain target saw %s %s, want HTTP/1.1 /api/peers", proto, path)
	}
}

// Default off: a virtual directory without the option keeps talking HTTP/1.1, which an
// HTTP/2-only target refuses (the situation the issue describes)
func TestVdirH2C_OffByDefault(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil
	seen := &vdirH2CSeen{}
	backend := vdirGRPCLikeBackend(t, seen)

	sep.ProxyType = ProxyTypeHost
	sep.VirtualDirectories = []*VirtualDirectoryEndpoint{
		{MatchingPath: "/svc/", Domain: strings.TrimPrefix(backend.URL, "http://") + "/svc/"},
	}
	if _, err := router.PrepareProxyRoute(sep); err != nil {
		t.Fatal(err)
	}
	w := serveNonTLS(router, sep, "/svc/Method", "198.51.100.1:1000")
	if w.Code == http.StatusOK {
		t.Fatalf("an HTTP/2-only target answered 200 without the h2c option")
	}
	if proto, _ := seen.get(); proto == "HTTP/2.0" {
		t.Fatalf("target was spoken to in HTTP/2 without the option")
	}
}

func TestVdirH2C_ModelAndTLS(t *testing.T) {
	// existing configuration files have no H2C key and none is written while the option is off
	plain, _ := json.Marshal(&VirtualDirectoryEndpoint{MatchingPath: "/a/", Domain: "10.0.0.1:80"})
	if strings.Contains(string(plain), "H2C") {
		t.Errorf("H2C written for a directory without the option: %s", plain)
	}
	var old VirtualDirectoryEndpoint
	if err := json.Unmarshal([]byte(`{"MatchingPath":"/a/","Domain":"10.0.0.1:80","RequireTLS":false,"SkipCertValidations":false,"Disabled":false}`), &old); err != nil || old.H2C {
		t.Errorf("old configuration: err=%v H2C=%v", err, old.H2C)
	}
	on, _ := json.Marshal(&VirtualDirectoryEndpoint{MatchingPath: "/a/", Domain: "10.0.0.1:80", H2C: true})
	var back VirtualDirectoryEndpoint
	if err := json.Unmarshal(on, &back); err != nil || !back.H2C {
		t.Errorf("H2C lost in a save and load: %s", on)
	}

	// only for plain http targets
	for _, c := range []struct {
		v    VirtualDirectoryEndpoint
		want bool
	}{
		{VirtualDirectoryEndpoint{Domain: "10.0.0.1:80", H2C: true}, true},
		{VirtualDirectoryEndpoint{Domain: "10.0.0.1:80"}, false},
		{VirtualDirectoryEndpoint{Domain: "10.0.0.1:443", H2C: true, RequireTLS: true}, false},
		{VirtualDirectoryEndpoint{Domain: "https://10.0.0.1", H2C: true}, false},
	} {
		if got := c.v.UsesH2C(); got != c.want {
			t.Errorf("UsesH2C(%+v) = %v, want %v", c.v, got, c.want)
		}
	}

	// bulk forward-auth management must not treat an h2c directory as its own
	custom := &VirtualDirectoryEndpoint{Domain: "10.0.0.1:80", H2C: true}
	if custom.HasSameTarget("10.0.0.1:80", false, false) {
		t.Error("a directory with h2c counts as identical to a bulk spec without it")
	}
	if ClassifyBulkVdir(false, custom, "10.0.0.1:80", false, false) != BulkVdirConflict {
		t.Error("bulk remove would delete a directory with h2c")
	}
}

// The status codes the NetBird guide lists under "Check it": a target name that does not
// resolve gives 404 (host error page), and a gRPC-only target that closes the connection on
// an HTTP/1.1 request (h2c not ticked) gives 521, the same as an unreachable target.
func TestVdirH2C_GuideStatusCodes(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil

	// like grpc-go: reads the client greeting and hangs up when it is not the HTTP/2 preface
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 24)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				io.ReadFull(c, buf)
				c.Close()
			}(c)
		}
	}()

	sep.ProxyType = ProxyTypeHost
	sep.VirtualDirectories = []*VirtualDirectoryEndpoint{
		{MatchingPath: "/unresolved/", Domain: "no-such-container.invalid:80/unresolved/", H2C: true},
		{MatchingPath: "/closes/", Domain: ln.Addr().String() + "/closes/"},
	}
	if _, err := router.PrepareProxyRoute(sep); err != nil {
		t.Fatal(err)
	}
	if w := serveNonTLS(router, sep, "/unresolved/Method", "198.51.100.1:1000"); w.Code != http.StatusNotFound {
		t.Errorf("target name that does not resolve: status %d, the guide says 404", w.Code)
	}
	if w := serveNonTLS(router, sep, "/closes/Method", "198.51.100.1:1000"); w.Code != 521 {
		t.Errorf("gRPC-only target closing an HTTP/1.1 request: status %d, the guide says 521", w.Code)
	}
}
