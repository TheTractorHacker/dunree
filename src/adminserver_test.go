package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/webuitls"
)

func TestAdminHTTPServerHasTimeouts(t *testing.T) {
	srv := newAdminHTTPServer(http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadHeaderTimeout > 30*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want a short positive timeout", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout = %v, want a positive timeout", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes = %d, want an explicit cap", srv.MaxHeaderBytes)
	}
	//Streaming endpoints and large uploads must keep working
	if srv.WriteTimeout != 0 || srv.ReadTimeout != 0 {
		t.Fatalf("ReadTimeout/WriteTimeout must stay unset, got %v/%v", srv.ReadTimeout, srv.WriteTimeout)
	}
}

// No management listener may fall back to the timeout-less package level http.Serve
func TestMainDoesNotUseBareHTTPServe(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "http.Serve(") {
		t.Fatal("main.go uses http.Serve, which has no timeouts; use newAdminHTTPServer(...).Serve")
	}
	if n := strings.Count(string(src), "newAdminHTTPServer("); n != 3 {
		t.Fatalf("expected the 3 management listeners to use newAdminHTTPServer, found %d", n)
	}
}

// expectClosedByServer fails unless the server closes the stalled connection in time
func expectClosedByServer(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within))
	_, err := io.Copy(io.Discard, c)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server kept the stalled connection open for more than %v", within)
	}
}

func startTestAdminServer(t *testing.T, wrap func(net.Listener) net.Listener) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newAdminHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.ReadHeaderTimeout = 300 * time.Millisecond //same code path as production, shortened for the test
	go srv.Serve(wrap(ln))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestAdminHTTPServerDropsSlowHeaders(t *testing.T) {
	addr := startTestAdminServer(t, func(ln net.Listener) net.Listener { return ln })

	//A normal request still works
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	//Partial request line and headers, then stall
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
	expectClosedByServer(t, c, 5*time.Second)
}

func TestAdminHTTPSServerDropsStalledHandshake(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()
	cfg := webuitls.ServerTLSConfig(&webuitls.CertInfo{Certificate: cert})
	addr := startTestAdminServer(t, func(ln net.Listener) net.Listener { return webuitls.NewSniffListener(ln, cfg) })

	//A normal TLS request still works
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	client.CloseIdleConnections()

	//First byte of a TLS record, then stall: the sniff listener clears its own deadline here
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x16})
	expectClosedByServer(t, c, 5*time.Second)
}
