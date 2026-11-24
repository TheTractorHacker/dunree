package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func regReq(remote string, form url.Values) *http.Request {
	r := reqWith(nil, "POST", "/api/auth/register", form)
	r.RemoteAddr = remote
	return r
}

func regDo(g *FirstAdminGuard, r *http.Request) string {
	w := httptest.NewRecorder()
	g.HandleRegister(w, r)
	return w.Body.String()
}

// The first admin can only be created from the machine itself or with the setup token
func TestFirstAdminNeedsLoopbackOrToken(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	g := a.NewFirstAdminGuard(false)
	g.Announce()
	if g.token == "" {
		t.Fatal("no setup token announced on an empty install")
	}
	form := url.Values{"username": {"evil"}, "password": {"password-1"}}

	//Remote, no token / wrong token
	if !g.TokenRequired(regReq("198.51.100.1:1234", nil)) {
		t.Fatal("a remote client must be told the token is required")
	}
	if body := regDo(g, regReq("198.51.100.1:1234", form)); !strings.Contains(body, "error") {
		t.Fatalf("remote registration without token accepted: %s", body)
	}
	bad := url.Values{"username": {"evil"}, "password": {"password-1"}, "setup_token": {"00000-00000-00000-00000"}}
	if body := regDo(g, regReq("198.51.100.1:1234", bad)); !strings.Contains(body, "error") {
		t.Fatalf("remote registration with a wrong token accepted: %s", body)
	}
	//Loopback reached through a reverse proxy is not local
	r := regReq("127.0.0.1:1234", form)
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if body := regDo(g, r); !strings.Contains(body, "error") {
		t.Fatalf("proxied registration without token accepted: %s", body)
	}
	//The token in the query string of a GET is not a registration
	w := httptest.NewRecorder()
	g.HandleRegister(w, httptest.NewRequest("GET", "/api/auth/register?username=evil&password=password-1&setup_token="+g.token, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET registration: got %d", w.Code)
	}
	if n := a.GetUserCounts(); n != 0 {
		t.Fatalf("%d account(s) created by refused requests", n)
	}

	//Remote with the token works
	good := url.Values{"username": {"root"}, "password": {"password-1"}, "setup_token": {" " + strings.ToUpper(g.token) + " "}}
	if body := regDo(g, regReq("198.51.100.1:1234", good)); strings.Contains(body, "error") {
		t.Fatalf("remote registration with the token refused: %s", body)
	}
	if !a.UserExists("root") {
		t.Fatal("root not created")
	}
	//Once an account exists nothing is accepted, token or not
	good.Set("username", "second")
	if body := regDo(g, regReq("127.0.0.1:1", good)); !strings.Contains(body, "already exists") {
		t.Fatalf("second registration: %s", body)
	}
	if g.TokenRequired(regReq("198.51.100.1:1234", nil)) {
		t.Fatal("token must not be asked for once an account exists")
	}
}

func TestFirstAdminFromLoopbackAndHeaderToken(t *testing.T) {
	fastPW(t)
	form := url.Values{"username": {"root"}, "password": {"password-1"}}
	for _, remote := range []string{"127.0.0.1:5555", "[::1]:5555"} {
		a := newTestAgent(t)
		g := a.NewFirstAdminGuard(false)
		if g.TokenRequired(regReq(remote, nil)) {
			t.Fatalf("%s must not need a token", remote)
		}
		if body := regDo(g, regReq(remote, form)); strings.Contains(body, "error") {
			t.Fatalf("local registration from %s refused: %s", remote, body)
		}
	}

	a := newTestAgent(t)
	g := a.NewFirstAdminGuard(false)
	g.Announce()
	r := regReq("10.0.0.9:5555", form)
	r.Header.Set(SetupTokenHeader, g.token)
	if body := regDo(g, r); strings.Contains(body, "error") {
		t.Fatalf("header token refused: %s", body)
	}
}

// -open_setup: the old behaviour stays reachable
func TestFirstAdminAllowRemoteKeepsOldBehaviour(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	g := a.NewFirstAdminGuard(true)
	g.Announce()
	if g.token != "" || g.TokenRequired(regReq("198.51.100.1:1234", nil)) {
		t.Fatal("no token expected in open setup mode")
	}
	form := url.Values{"username": {"root"}, "password": {"password-1"}}
	if body := regDo(g, regReq("198.51.100.1:1234", form)); strings.Contains(body, "error") {
		t.Fatalf("open setup refused: %s", body)
	}
}

// Concurrent registrations create exactly one admin
func TestFirstAdminRegistrationIsAtomic(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	g := a.NewFirstAdminGuard(false)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			regDo(g, regReq("127.0.0.1:1", url.Values{"username": {"root" + string(rune('a'+i))}, "password": {"password-1"}}))
		}(i)
	}
	wg.Wait()
	if n := a.GetUserCounts(); n != 1 {
		t.Fatalf("%d admins created by concurrent registrations, want 1", n)
	}
}
