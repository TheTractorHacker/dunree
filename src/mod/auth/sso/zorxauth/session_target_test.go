package zorxauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A signed in user (no allowed-host list, the default) who opens a crafted
// portal link must not have a session code sent to a host this SSO does not protect.
func TestHandleAuthPageRefusesForeignRedirectHost(t *testing.T) {
	for _, target := range []string{
		"https://evil.tld/x",
		"http://evil.tld/x",
		"//evil.tld/x",
		"https://app.example.com@evil.tld/x",
		"https://evil.tld\\@app.example.com/x",
		"http://app.example.com/x", //https only host: the code must not travel in cleartext
		"javascript://app.example.com/%0aalert(1)",
	} {
		ar, gs := newTestGateway(t)
		ar.gatewaySessionStore.Store("tok", &GatewaySession{Username: "alice", Expiry: time.Now().Add(time.Hour)})
		rec := httptest.NewRecorder()
		gs.handleAuthPage(rec, withCookie(ar, "GET", "/?redirect="+url.QueryEscape(target), "tok"))
		if loc := rec.Header().Get("Location"); loc != "" || strings.Contains(rec.Body.String(), "session_id") {
			t.Errorf("%q: portal redirected to %q", target, loc)
		}
		if rec.Code >= 300 && rec.Code < 400 {
			t.Errorf("%q: unexpected redirect status %d", target, rec.Code)
		}
		minted := 0
		ar.sessionIdStore.Range(func(_, _ any) bool { minted++; return true })
		if minted != 0 {
			t.Errorf("%q: a validation code was minted", target)
		}
	}
}

func TestHandleAuthPageRefusesEveryTargetWithoutPolicy(t *testing.T) {
	ar, gs := newTestGateway(t)
	ar.SessionTargetPolicy = nil
	ar.gatewaySessionStore.Store("tok", &GatewaySession{Username: "alice", Expiry: time.Now().Add(time.Hour)})
	rec := httptest.NewRecorder()
	gs.handleAuthPage(rec, withCookie(ar, "GET", "/?redirect="+url.QueryEscape("https://app.example.com/"), "tok"))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("without a policy no target may receive a code: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHandleAuthPageAllowsPlainHTTPOnlyHost(t *testing.T) {
	ar, gs := newTestGateway(t)
	ar.gatewaySessionStore.Store("tok", &GatewaySession{Username: "alice", Expiry: time.Now().Add(time.Hour)})
	rec := httptest.NewRecorder()
	gs.handleAuthPage(rec, withCookie(ar, "GET", "/?redirect="+url.QueryEscape("http://Plain.Example.com:8080/x"), "tok"))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || loc.Scheme != "http" || loc.Host != "plain.example.com:8080" {
		t.Fatalf("unexpected answer %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func loginRequest(t *testing.T, ar *AuthRouter, redirect string) *http.Request {
	t.Helper()
	if err := ar.Database.Write(DB_USERS_TABLE, ar.userDbKey("alice"), &User{ID: "alice-id", Username: "alice", PasswordHash: hashPassword("pw")}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"username": {"alice"}, "password": {"pw"}, "redirect": {redirect}}
	req := httptest.NewRequest(http.MethodPost, "http://sso.example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleLoginRefusesForeignRedirectHost(t *testing.T) {
	ar, gs := newTestGateway(t)
	rec := httptest.NewRecorder()
	gs.handleLogin(rec, loginRequest(t, ar, "https://evil.tld/x"))
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "sessionId") {
		t.Fatalf("login with a foreign redirect answered %d %s", rec.Code, rec.Body.String())
	}

	// control: a protected host gets a code bound to it, the direct login none
	rec = httptest.NewRecorder()
	gs.handleLogin(rec, loginRequest(t, ar, "https://app.example.com/x"))
	var out struct {
		Success       bool   `json:"success"`
		SessionID     string `json:"sessionId"`
		SessionSetURL string `json:"sessionSetURL"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Success || out.SessionID == "" ||
		out.SessionSetURL != "https://app.example.com"+ar.Options.SSOSessionSetURL {
		t.Fatalf("login for a protected host answered %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := ar.consumeValidationCode(out.SessionID, "other.example.com"); ok {
		t.Fatal("login code accepted on another host")
	}

	rec = httptest.NewRecorder()
	gs.handleLogin(rec, loginRequest(t, ar, "/"))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "sessionId") {
		t.Fatalf("direct login answered %d %s", rec.Code, rec.Body.String())
	}
}

// The code is bound to the host it was minted for, with and without signed tokens.
func TestValidationCodeIsBoundToItsHost(t *testing.T) {
	for _, key := range []string{"", "k1-shared-key-material"} {
		a, _, b, _ := newSharedPair(t, key, key)
		setURL := a.Options.SSOSessionSetURL

		// replayed on another protected host: refused, and used up
		code := a.generateValidationCodeForSession("alice", "app.example.com")
		rec := httptest.NewRecorder()
		a.handleSessionSetCallback(rec, httptest.NewRequest("GET", "https://other.example.com"+setURL+"?session_id="+code+"&remember_me=true", nil))
		if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("key %q: code accepted on another host: %d", key, rec.Code)
		}
		rec = httptest.NewRecorder()
		a.handleSessionSetCallback(rec, httptest.NewRequest("GET", "https://app.example.com"+setURL+"?session_id="+code, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("key %q: a code tried on the wrong host must be used up: %d", key, rec.Code)
		}

		// on its own host (any case, any port) it works once
		code = a.generateValidationCodeForSession("alice", "App.Example.com")
		rec = httptest.NewRecorder()
		a.handleSessionSetCallback(rec, httptest.NewRequest("GET", "https://APP.example.com:8443"+setURL+"?session_id="+code, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("key %q: code refused on its own host: %d", key, rec.Code)
		}
		cookieFrom(t, a, rec)

		if key != "" {
			// a signed code is host bound on the other nodes too
			code = a.generateValidationCodeForSession("alice", "app.example.com")
			if _, ok := b.consumeValidationCode(code, "other.example.com"); ok {
				t.Fatal("another node accepted a signed code on the wrong host")
			}
			code = a.generateValidationCodeForSession("alice", "app.example.com")
			if u, ok := b.consumeValidationCode(code, "app.example.com"); !ok || u != "alice" {
				t.Fatal("another node refused a signed code on its host")
			}
			// a signed code without a host (older build, or a token of another kind) is refused
			hostless := a.mintTokenClaims(tokenClaims{Kind: tokenKindCode, Username: "alice", Expiry: time.Now().Add(time.Minute).Unix()})
			if _, ok := b.consumeValidationCode(hostless, ""); ok {
				t.Fatal("a code without a host was accepted")
			}
		}
	}
}

func TestSessionSetCallbackRedirectsToSameHostOnly(t *testing.T) {
	for redirect, want := range map[string]string{
		"":                                   "/",
		"/dash?x=1":                          "/dash?x=1",
		"https://app.example.com/dash?x=1":   "https://app.example.com/dash?x=1",
		"https://APP.example.com:8443/dash":  "https://APP.example.com:8443/dash",
		"https://evil.tld/x":                 "/",
		"//evil.tld/x":                       "/",
		"/\\evil.tld/x":                      "/",
		"https://app.example.com@evil.tld/":  "/",
		"https://evil.tld\\@app.example.com": "/",
		"javascript:alert(1)":                "/",
		"dash":                               "/",
	} {
		ar, _ := newTestGateway(t)
		code := ar.generateValidationCodeForSession("alice", "app.example.com")
		rec := httptest.NewRecorder()
		ar.handleSessionSetCallback(rec, httptest.NewRequest("GET",
			"https://app.example.com"+ar.Options.SSOSessionSetURL+"?session_id="+code+"&redirect="+url.QueryEscape(redirect), nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("redirect %q: got %d %q, want %q", redirect, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}
