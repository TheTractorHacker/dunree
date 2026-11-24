package dynamicproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
	"github.com/foleyit/dunree/mod/dynamicproxy/loadbalance"
)

// routeLimitFixture builds a host rule in front of backend with the given limits and returns the proxy URL.
func routeLimitFixture(t *testing.T, backend *httptest.Server, mutate func(*ProxyEndpoint)) *httptest.Server {
	t.Helper()
	return routeLimitFixtureWrapped(t, backend, mutate, nil)
}

// routeLimitFixtureWrapped is routeLimitFixture with a wrapper around the response writer (nil = none)
func routeLimitFixtureWrapped(t *testing.T, backend *httptest.Server, mutate func(*ProxyEndpoint), wrap func(http.ResponseWriter) http.ResponseWriter) *httptest.Server {
	t.Helper()
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil
	router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: router.Option.Logger})
	sep.ProxyType = ProxyTypeHost
	sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(backend.URL, "http://"), Weight: 1}}
	if mutate != nil {
		mutate(sep)
	}
	prepared, err := router.PrepareProxyRoute(sep)
	if err != nil {
		t.Fatal(err)
	}
	prepared.parent = router
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wrap != nil {
			w = wrap(w)
		}
		router.handleNonTLSRequest(w, r, prepared)
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

type countingWriter struct {
	http.ResponseWriter
	headers *atomic.Int32
}

func (c countingWriter) WriteHeader(code int) {
	c.headers.Add(1)
	c.ResponseWriter.WriteHeader(code)
}
func (c countingWriter) Write(b []byte) (int, error) {
	c.headers.CompareAndSwap(0, 1) //an implicit 200
	return c.ResponseWriter.Write(b)
}
func (c countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func post(t *testing.T, url string, body io.Reader, length int64) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, body)
	req.ContentLength = length //-1 = chunked
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func sinkBackend(received *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Store(n)
		w.Write([]byte("ok"))
	}))
}

func TestRouteLimits_BodyLimit413(t *testing.T) {
	var received atomic.Int64
	backend := sinkBackend(&received)
	defer backend.Close()
	proxy := routeLimitFixture(t, backend, func(e *ProxyEndpoint) { e.MaxRequestBodyBytes = 1000 })

	// announced size over the limit: refused early, the backend never sees the request
	received.Store(-1)
	resp, _ := post(t, proxy.URL+"/", strings.NewReader(strings.Repeat("a", 5000)), 5000)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("content-length over limit: got %d, want 413", resp.StatusCode)
	}
	if received.Load() != -1 {
		t.Fatalf("backend was reached by an oversized announced body (read %d)", received.Load())
	}

	// unannounced (chunked) body that grows past the limit: stopped while reading, still a clean 413
	resp, _ = post(t, proxy.URL+"/", &zeroReader{left: 100000}, -1)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked body over limit: got %d, want 413", resp.StatusCode)
	}

	// a lie in Content-Length cannot be used to smuggle more: header says 10, body is longer is rejected by net/http itself,
	// so exercise the exact boundary instead: exactly the limit passes, one byte more does not
	resp, body := post(t, proxy.URL+"/", strings.NewReader(strings.Repeat("a", 1000)), 1000)
	if resp.StatusCode != 200 || body != "ok" || received.Load() != 1000 {
		t.Fatalf("body of exactly the limit: status %d body %q backend got %d", resp.StatusCode, body, received.Load())
	}
	resp, _ = post(t, proxy.URL+"/", strings.NewReader(strings.Repeat("a", 1001)), 1001)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit+1: got %d, want 413", resp.StatusCode)
	}
	// requests without a body are not affected
	r2, err := http.Get(proxy.URL + "/")
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("GET with limit set: %v %v", err, r2)
	}
	r2.Body.Close()
}

// Backward compatibility: no limit configured (every existing rule) streams any body size.
func TestRouteLimits_ZeroMeansUnlimited(t *testing.T) {
	var received atomic.Int64
	backend := sinkBackend(&received)
	defer backend.Close()
	proxy := routeLimitFixture(t, backend, nil)
	resp, body := post(t, proxy.URL+"/", &zeroReader{left: 3 << 20}, -1)
	if resp.StatusCode != 200 || body != "ok" || received.Load() != 3<<20 {
		t.Fatalf("unlimited rule: status %d, backend got %d", resp.StatusCode, received.Load())
	}
}

func TestRouteLimits_BodyLimitVirtualDirectory(t *testing.T) {
	var received atomic.Int64
	backend := sinkBackend(&received)
	defer backend.Close()
	proxy := routeLimitFixture(t, backend, func(e *ProxyEndpoint) {
		e.MaxRequestBodyBytes = 500
		e.VirtualDirectories = []*VirtualDirectoryEndpoint{{MatchingPath: "/up/", Domain: strings.TrimPrefix(backend.URL, "http://") + "/up/"}}
	})
	resp, _ := post(t, proxy.URL+"/up/x", strings.NewReader(strings.Repeat("a", 900)), 900)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("vdir: got %d, want 413", resp.StatusCode)
	}
	resp, _ = post(t, proxy.URL+"/up/x", &zeroReader{left: 9000}, -1)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("vdir chunked: got %d, want 413", resp.StatusCode)
	}
}

func TestRouteLimits_RequestTimeout504(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		w.Write([]byte("late"))
	}))
	defer slow.Close()
	proxy := routeLimitFixture(t, slow, func(e *ProxyEndpoint) { e.RequestTimeout = 1 })
	start := time.Now()
	resp, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("got %d, want 504", resp.StatusCode)
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 2500*time.Millisecond {
		t.Fatalf("timeout fired after %v, want about 1s", d)
	}

	// no timeout configured: the same slow upstream is waited for
	proxy2 := routeLimitFixture(t, slow, nil)
	c := http.Client{Timeout: 6 * time.Second}
	resp, err = c.Get(proxy2.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "late" {
		t.Fatalf("no request timeout: status %d body %q", resp.StatusCode, b)
	}
}

// A blackholed upstream address (SYN never answered) fails after the route's connect timeout, not the built-in 30 s.
func TestRouteLimits_UpstreamDialTimeout(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: nothing answers. Skip where the network refuses outright (no route).
	if c, err := net.DialTimeout("tcp", "192.0.2.1:81", 300*time.Millisecond); err == nil {
		c.Close()
		t.Skip("test address answered")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Skipf("no black hole available here (%v)", err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	proxy := routeLimitFixture(t, dead, func(e *ProxyEndpoint) {
		e.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: "192.0.2.1:81", Weight: 1}}
		e.UpstreamDialTimeout = 1
	})
	start := time.Now()
	c := http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("connect attempt took %v, the 1 s route timeout was not applied", d)
	}
}

func TestRouteLimits_Validate(t *testing.T) {
	for i, bad := range []*ProxyEndpoint{{MaxRequestBodyBytes: -1}, {RequestTimeout: -1}, {RequestTimeout: 90000}, {UpstreamDialTimeout: -5}, {UpstreamDialTimeout: 90000}} {
		if ValidateRouteLimits(bad) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := ValidateRouteLimits(&ProxyEndpoint{MaxRequestBodyBytes: 1 << 40, RequestTimeout: 86400, UpstreamDialTimeout: 1}); err != nil {
		t.Error(err)
	}
}

// Old configs (no limit fields) load with all limits 0, and 0 is not written back out.
func TestRouteLimits_JSONBackwardCompatible(t *testing.T) {
	ep := CopyEndpoint(&ProxyEndpoint{RootOrMatchingDomain: "a.example.com"})
	if ep.MaxRequestBodyBytes != 0 || ep.RequestTimeout != 0 || ep.UpstreamDialTimeout != 0 {
		t.Fatalf("zero value not preserved: %+v", ep)
	}
	ep.MaxRequestBodyBytes, ep.RequestTimeout, ep.UpstreamDialTimeout = 10, 20, 30
	cp := CopyEndpoint(ep)
	if cp.MaxRequestBodyBytes != 10 || cp.RequestTimeout != 20 || cp.UpstreamDialTimeout != 30 {
		t.Fatalf("limits lost in copy: %+v", cp)
	}
}

// The TLS listener path serves host rules through ProxyHandler.hostRequest (the plain HTTP path is covered above).
func TestRouteLimits_HostRequestPath(t *testing.T) {
	var received atomic.Int64
	backend := sinkBackend(&received)
	defer backend.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		w.Write([]byte("late"))
	}))
	defer slow.Close()

	serve := func(upstream *httptest.Server, mutate func(*ProxyEndpoint)) *httptest.Server {
		router, sep, _ := newNonTLSTestRouter(t)
		router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: router.Option.Logger})
		sep.ProxyType = ProxyTypeHost
		sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(upstream.URL, "http://"), Weight: 1}}
		mutate(sep)
		prepared, err := router.PrepareProxyRoute(sep)
		if err != nil {
			t.Fatal(err)
		}
		prepared.parent = router
		h := &ProxyHandler{Parent: router}
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.hostRequest(w, r, prepared) }))
		t.Cleanup(s.Close)
		return s
	}

	p := serve(backend, func(e *ProxyEndpoint) { e.MaxRequestBodyBytes = 1000 })
	if resp, _ := post(t, p.URL+"/", strings.NewReader(strings.Repeat("a", 4000)), 4000); resp.StatusCode != 413 {
		t.Fatalf("announced: got %d, want 413", resp.StatusCode)
	}
	if resp, _ := post(t, p.URL+"/", &zeroReader{left: 50000}, -1); resp.StatusCode != 413 {
		t.Fatalf("chunked: got %d, want 413", resp.StatusCode)
	}
	if resp, body := post(t, p.URL+"/", strings.NewReader("small"), 5); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("under the limit: %d %q", resp.StatusCode, body)
	}

	p = serve(slow, func(e *ProxyEndpoint) { e.RequestTimeout = 1 })
	start := time.Now()
	resp, _ := post(t, p.URL+"/", strings.NewReader("x"), 1)
	if resp.StatusCode != 504 || time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("got %d after %v, want 504 after about 1s", resp.StatusCode, time.Since(start))
	}
}

// Global ReadTimeout (whole request incl. body): a client that stalls its upload is cut off, 0 (default) leaves it alone.
func TestGlobalReadTimeout(t *testing.T) {
	backend := sinkBackend(new(atomic.Int64))
	defer backend.Close()
	stalled := func(readTimeout int64) (closedAfter time.Duration) {
		router, sep, _ := newNonTLSTestRouter(t)
		router.pluginRouteHook = nil
		router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: router.Option.Logger})
		sep.ProxyType = ProxyTypeHost
		sep.BypassGlobalTLS = true
		sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(backend.URL, "http://"), Weight: 1}}
		prepared, err := router.PrepareProxyRoute(sep)
		if err != nil {
			t.Fatal(err)
		}
		prepared.parent = router
		router.ProxyEndpoints.Store("app.example.com", prepared)
		router.Option.ListenOnPort80 = true
		router.Option.HttpListenAddr = "127.0.0.1:0"
		router.Option.ReadTimeout = readTimeout
		router.startHttpListener()
		if router.tlsRedirectStop == nil {
			t.Fatal("listener did not start")
		}
		defer func() { router.tlsRedirectStop <- true; time.Sleep(50 * time.Millisecond) }()

		c, err := net.Dial("tcp", router.BoundHttpAddr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("POST / HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 1000\r\n\r\nabc"))
		start := time.Now()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, rerr := io.ReadAll(c) //returns when the server closes the connection (after any error response)
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			return -1 //still open after 3 s
		}
		return time.Since(start)
	}
	if d := stalled(1); d < 0 || d > 2500*time.Millisecond {
		t.Fatalf("ReadTimeout=1: stalled upload closed after %v, want about 1s", d)
	}
	if d := stalled(0); d >= 0 {
		t.Fatalf("ReadTimeout=0 (default): stalled upload was closed after %v, want it left open", d)
	}
}

// Attack/bug: the request timeout fires while the response body is streaming. The status line is already
// with the client, so the proxy must not write a second response (superfluous WriteHeader / 504 text in the body).
func TestRouteLimits_TimeoutMidBodyWritesNoSecondResponse(t *testing.T) {
	slowBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-time.After(4 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slowBody.Close()
	var headers atomic.Int32
	proxy := routeLimitFixtureWrapped(t, slowBody, func(e *ProxyEndpoint) { e.RequestTimeout = 1 },
		func(w http.ResponseWriter) http.ResponseWriter { return countingWriter{w, &headers} })
	c := http.Client{Timeout: 8 * time.Second}
	resp, err := c.Get(proxy.URL + "/")
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), "Gateway Timeout") {
			t.Errorf("a 504 text was appended to the streamed body: %q", b)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := headers.Load(); n > 1 {
		t.Errorf("response written %d times, want once", n)
	}
}

func TestRouteLimitStatusIgnoresAbortedResponses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	ep := &ProxyEndpoint{RequestTimeout: 1}
	if st, ok := routeLimitStatus(context.DeadlineExceeded, r, ep); !ok || st != http.StatusGatewayTimeout {
		t.Fatalf("plain timeout: %d %v", st, ok)
	}
	if st, ok := routeLimitStatus(fmt.Errorf("%w: %v", dpcore.ErrResponseAborted, context.DeadlineExceeded), r, ep); ok {
		t.Fatalf("aborted response mapped to a second status %d", st)
	}
}

// A non-WebSocket Upgrade header must not switch the per-route timeout off; a genuine WebSocket upgrade still does.
func TestRouteLimits_TimeoutAppliesToNonWebSocketUpgrade(t *testing.T) {
	ep := &ProxyEndpoint{RequestTimeout: 5}
	deadline := func(upgrade string) bool {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if upgrade != "" {
			r.Header.Set("Upgrade", upgrade)
			r.Header.Set("Connection", "Upgrade")
		}
		r2, cancel, ok := applyRouteLimits(httptest.NewRecorder(), r, ep)
		defer cancel()
		_, has := r2.Context().Deadline()
		return ok && has
	}
	if !deadline("") {
		t.Error("plain request has no timeout")
	}
	for _, up := range []string{"h2c", "foo", "WebSockets", "tls/1.0"} {
		if !deadline(up) {
			t.Errorf("Upgrade: %s skipped the request timeout", up)
		}
	}
	if deadline("websocket") || deadline("WebSocket") {
		t.Error("a genuine WebSocket upgrade must not get the request timeout")
	}
	if _, cancel, _ := applyRouteLimits(httptest.NewRecorder(), httptest.NewRequest(http.MethodConnect, "/", nil), ep); cancel == nil {
		t.Error("nil cancel")
	}
}
