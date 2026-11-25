package forwardproxy

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUpdatePortRefusesInvalidAndOccupiedPorts(t *testing.T) {
	h := &Handler{Port: 1}
	for _, p := range []int{0, -1, 99999} {
		if err := h.UpdatePort(p); err == nil {
			t.Fatalf("port %d must be refused", p)
		}
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	if err := h.UpdatePort(busy); err == nil {
		t.Fatalf("occupied port %d must be refused", busy)
	}
	if h.Port != 1 {
		t.Fatalf("a refused port change must keep the old port, got %d", h.Port)
	}
}

// A GET (open to viewer accounts and to cross-site links, no CSRF check) must not start, stop or
// move the unauthenticated proxy: it only reads the state
func TestGetCannotToggleOrMoveProxy(t *testing.T) {
	h := NewForwardProxy(nil, 1, nil)
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		w := httptest.NewRecorder()
		h.HandleToogle(w, httptest.NewRequest(method, "/api/tools/fwdproxy/enable?enable=true", nil))
		if h.running || h.server != nil {
			t.Fatalf("%s started the forward proxy", method)
		}
		if method == "GET" && strings.TrimSpace(w.Body.String()) != "false" {
			t.Fatalf("GET must report the state, got %q", w.Body.String())
		}
		h.HandlePort(httptest.NewRecorder(), httptest.NewRequest(method, "/api/tools/fwdproxy/port?port=2", nil))
		if h.Port != 1 || h.running {
			t.Fatalf("%s moved the forward proxy to port %d", method, h.Port)
		}
		h.HandlePublicClients(httptest.NewRecorder(), httptest.NewRequest(method, "/api/tools/fwdproxy/publicclients?allow=true", nil))
		if h.allowPublicClients.Load() {
			t.Fatalf("%s opened the forward proxy to public clients", method)
		}
		h.SetCredentials("u", "p")
		h.HandleCredentials(httptest.NewRecorder(), httptest.NewRequest(method, "/api/tools/fwdproxy/credentials?clear=true&username=x&password=y", nil))
		if l := h.credentials.Load(); l == nil || l.Username != "u" {
			t.Fatalf("%s changed the forward proxy login", method)
		}
		h.SetCredentials("", "")
	}
}

// The proxy has no authentication: by default it only serves clients on this machine or a private network
func TestOnlyPrivateClientsByDefault(t *testing.T) {
	h := NewForwardProxy(nil, 1, nil)
	f := ZrFilter{h: h}
	try := func(remote string) (bool, int) {
		r := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		return f.IsAuthorized(w, r), w.Code
	}
	for _, remote := range []string{"127.0.0.1:1", "[::1]:1", "10.1.2.3:1", "172.17.0.1:1", "192.168.1.9:1", "[::ffff:192.168.1.9]:1", "[fd00::1]:1", "[fe80::1%eth0]:1", "169.254.3.4:1", "100.64.0.1:1", "100.127.255.254:1"} {
		if ok, _ := try(remote); !ok {
			t.Fatalf("private client %s refused", remote)
		}
	}
	for _, remote := range []string{"198.51.100.1:1", "8.8.8.8:1", "[2001:db8::1]:1", "[::ffff:8.8.8.8]:1", "100.128.0.1:1", "100.63.255.255:1", "garbage", ""} {
		if ok, code := try(remote); ok || code != http.StatusForbidden {
			t.Fatalf("public client %q: authorized=%v code=%d", remote, ok, code)
		}
	}
	//Old behaviour behind the explicit setting
	h.SetAllowPublicClients(true)
	if ok, _ := try("198.51.100.1:1"); !ok {
		t.Fatal("public client refused although public clients are allowed")
	}
}

// With a login set, every client (also a private one) must send it as Proxy-Authorization basic auth
func TestLoginRequiredWhenSet(t *testing.T) {
	h := NewForwardProxy(nil, 1, nil)
	f := ZrFilter{h: h}
	try := func(header string) (bool, *httptest.ResponseRecorder) {
		r := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
		r.RemoteAddr = "127.0.0.1:1"
		if header != "" {
			r.Header.Set("Proxy-Authorization", header)
		}
		w := httptest.NewRecorder()
		return f.IsAuthorized(w, r), w
	}
	basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }

	//Default: no login, unchanged behaviour
	if ok, _ := try(""); !ok {
		t.Fatal("client refused although no login is set")
	}

	//Set through the API
	post := func(form url.Values) string {
		r := httptest.NewRequest("POST", "/api/tools/fwdproxy/credentials", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.HandleCredentials(w, r)
		return w.Body.String()
	}
	if out := post(url.Values{"username": {"a:b"}, "password": {"x"}}); !strings.Contains(out, "error") || h.credentials.Load() != nil {
		t.Fatalf("username with a colon accepted: %s", out)
	}
	if out := post(url.Values{"username": {"alice"}}); !strings.Contains(out, "error") || h.credentials.Load() != nil {
		t.Fatalf("empty password accepted: %s", out)
	}
	post(url.Values{"username": {"alice"}, "password": {"s3cret:pw"}})
	//A blank username is an error, not a silent removal of the login
	if out := post(url.Values{"username": {"   "}, "password": {"x"}}); !strings.Contains(out, "error") || h.credentials.Load() == nil {
		t.Fatalf("blank username removed the login: %s", out)
	}
	//Toggling public clients works without a logger or database (no nil dereference)
	{
		r := httptest.NewRequest("POST", "/api/tools/fwdproxy/publicclients", strings.NewReader("allow=false"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandlePublicClients(httptest.NewRecorder(), r)
	}

	for _, header := range []string{"", "Basic", "Basic !!!", basic("alice"), basic("alice:wrong"), basic("bob:s3cret:pw"), basic("alice:"), "Bearer " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret:pw"))} {
		ok, w := try(header)
		if ok || w.Code != http.StatusProxyAuthRequired || !strings.HasPrefix(w.Header().Get("Proxy-Authenticate"), "Basic") {
			t.Fatalf("header %q: authorized=%v code=%d", header, ok, w.Code)
		}
	}
	if ok, _ := try(basic("alice:s3cret:pw")); !ok {
		t.Fatal("correct login refused")
	}
	if ok, _ := try("basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret:pw"))); !ok {
		t.Fatal("scheme must be case insensitive")
	}

	//The state never reveals the password or its hash
	w := httptest.NewRecorder()
	h.HandleCredentials(w, httptest.NewRequest("GET", "/api/tools/fwdproxy/credentials", nil))
	if body := w.Body.String(); !strings.Contains(body, `"Required":true`) || !strings.Contains(body, "alice") || strings.Contains(body, "s3cret") || strings.Contains(body, h.credentials.Load().Hash) {
		t.Fatalf("unexpected state: %s", body)
	}

	//A public client is still refused before the login is looked at
	r := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
	r.RemoteAddr = "8.8.8.8:1"
	r.Header.Set("Proxy-Authorization", basic("alice:s3cret:pw"))
	if rec := httptest.NewRecorder(); f.IsAuthorized(rec, r) || rec.Code != http.StatusForbidden {
		t.Fatal("public client served because it knows the login")
	}

	//Removing the login restores the old behaviour
	post(url.Values{"clear": {"true"}})
	if ok, _ := try(""); !ok {
		t.Fatal("client refused after the login was removed")
	}
}

// The listener must have timeouts (slowloris), and they must not cut an established tunnel
func TestServerTimeoutsAndLoginOverTheWire(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); buf := make([]byte, 4); n, _ := c.Read(buf); c.Write(buf[:n]) }()
		}
	}()
	probe, _ := net.Listen("tcp", ":0")
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	h := NewForwardProxy(nil, port, nil)
	h.SetCredentials("alice", "pw")
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	if h.server.ReadHeaderTimeout <= 0 || h.server.IdleTimeout <= 0 {
		t.Fatalf("listener without timeouts: header=%v idle=%v", h.server.ReadHeaderTimeout, h.server.IdleTimeout)
	}

	connect := func(auth string) (net.Conn, *http.Response) {
		var c net.Conn
		for i := 0; i < 50; i++ {
			if c, err = net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := "CONNECT " + target.Addr().String() + " HTTP/1.1\r\nHost: " + target.Addr().String() + "\r\n"
		if auth != "" {
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(auth)) + "\r\n"
		}
		c.Write([]byte(req + "\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
		if err != nil {
			t.Fatal(err)
		}
		return c, resp
	}
	c, resp := connect("")
	c.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("no login: got %d", resp.StatusCode)
	}
	c, resp = connect("alice:pw")
	defer c.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", resp.StatusCode)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if n, _ := c.Read(buf); string(buf[:n]) != "ping" {
		t.Fatalf("tunnel broken, got %q", buf[:n])
	}
}
