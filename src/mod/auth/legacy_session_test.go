package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	db "github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
	"github.com/gorilla/securecookie"
)

const (
	testOldCookie = "Zoraxy" // legacy-compat: the session cookie name of an install made before the rename
	testNewCookie = "dunree_session"
)

// upgradedAgents returns the agent of the old build (cookie testOldCookie) and the agent of the new build on
// the SAME database and key (cookie testNewCookie, old name accepted), as after an in-place upgrade.
func upgradedAgents(t *testing.T) (before *AuthAgent, after *AuthAgent) {
	t.Helper()
	fastPW(t)
	sysdb, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sysdb.Close() })
	lg, _ := logger.NewFmtLogger()
	key := []byte("0123456789abcdef0123456789abcdef")
	before = NewAuthenticationAgent(testOldCookie, key, sysdb, false, lg, nil)
	if err := before.CreateUserAccount("admin", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	after = NewAuthenticationAgent(testNewCookie, key, sysdb, false, lg, nil)
	after.LegacySessionNames = []string{testOldCookie}
	return before, after
}

// serve runs h behind the legacy middleware and returns the recorder.
func serveLegacy(a *AuthAgent, r *http.Request, h http.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.LegacySessionMiddleware(h).ServeHTTP(w, r)
	return w
}

func setCookies(w *httptest.ResponseRecorder) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		out[c.Name] = c
	}
	return out
}

// An admin who was logged in before the upgrade stays logged in: the old cookie is accepted once, the
// session is re-issued under the new name with the time it had left, and the old cookie is removed.
func TestLegacySessionCookieSurvivesRename(t *testing.T) {
	before, after := upgradedAgents(t)
	old := login(t, before, "admin", "correct-horse-battery")
	if old == nil || old.Name != testOldCookie {
		t.Fatalf("setup: old build did not issue %q: %+v", testOldCookie, old)
	}
	//control: without the middleware the renamed agent does not know the cookie
	if after.CheckAuth(reqWith(old, "GET", "/", nil)) {
		t.Fatal("setup: the new agent must not read the old cookie name by itself")
	}

	var authed bool
	var user string
	w := serveLegacy(after, reqWith(old, "GET", "/api/x", nil), func(w http.ResponseWriter, r *http.Request) {
		authed = after.CheckAuth(r)
		user, _ = after.GetUserName(w, r)
	})
	if !authed || user != "admin" {
		t.Fatalf("old session cookie not accepted after the rename: authed=%v user=%q", authed, user)
	}
	set := setCookies(w)
	nc := set[testNewCookie]
	if nc == nil || nc.Value == "" {
		t.Fatalf("no %s cookie issued: %v", testNewCookie, w.Result().Header["Set-Cookie"])
	}
	if nc.MaxAge <= 0 || nc.MaxAge > old.MaxAge {
		t.Fatalf("re-issued Max-Age %d must be the time left (at most %d)", nc.MaxAge, old.MaxAge)
	}
	if !nc.HttpOnly || nc.SameSite != http.SameSiteLaxMode || nc.Path != "/" {
		t.Fatalf("re-issued cookie lost its attributes: %+v", nc)
	}
	if oc := set[testOldCookie]; oc == nil || oc.MaxAge >= 0 {
		t.Fatalf("old cookie must be removed from the browser, got %+v", oc)
	}
	//the browser now sends only the new cookie: valid without any translation, and nothing is set again
	var again bool
	w2 := serveLegacy(after, reqWith(nc, "GET", "/api/x", nil), func(w http.ResponseWriter, r *http.Request) { again = after.CheckAuth(r) })
	if !again {
		t.Fatal("the re-issued cookie does not authenticate")
	}
	if len(w2.Result().Cookies()) != 0 {
		t.Fatalf("a request with the current cookie must not set cookies: %v", w2.Result().Header["Set-Cookie"])
	}
}

// The expiry of the session is carried over, not renewed: an old cookie whose session has run out is refused.
func TestLegacySessionCookieKeepsExpiry(t *testing.T) {
	before, after := upgradedAgents(t)
	old := login(t, before, "admin", "correct-horse-battery")
	future := time.Now().Add(2 * time.Hour) //default lifetime is one hour
	after.nowFn = func() time.Time { return future }
	var authed bool
	w := serveLegacy(after, reqWith(old, "GET", "/", nil), func(w http.ResponseWriter, r *http.Request) { authed = after.CheckAuth(r) })
	if authed {
		t.Fatal("an expired session must not be revived by the cookie rename")
	}
	if c := setCookies(w)[testNewCookie]; c != nil && c.MaxAge > 0 {
		t.Fatalf("an expired session was re-issued: %+v", c)
	}
}

// A forged cookie, a cookie signed with another key and a cookie of a session that was revoked are refused.
func TestLegacySessionCookieRefusals(t *testing.T) {
	before, after := upgradedAgents(t)
	old := login(t, before, "admin", "correct-horse-battery")
	check := func(c *http.Cookie) (bool, *httptest.ResponseRecorder) {
		var ok bool
		w := serveLegacy(after, reqWith(c, "GET", "/", nil), func(w http.ResponseWriter, r *http.Request) { ok = after.CheckAuth(r) })
		return ok, w
	}
	if ok, w := check(&http.Cookie{Name: testOldCookie, Value: old.Value[:len(old.Value)-4] + "AAAA"}); ok || setCookies(w)[testNewCookie] != nil {
		t.Fatal("tampered cookie accepted")
	}
	other := securecookie.New([]byte("ffffffffffffffffffffffffffffffff"), nil)
	forged, _ := other.Encode(testOldCookie, map[interface{}]interface{}{"authenticated": true, "username": "admin", "exp": time.Now().Add(time.Hour).Unix()})
	if ok, w := check(&http.Cookie{Name: testOldCookie, Value: forged}); ok || setCookies(w)[testNewCookie] != nil {
		t.Fatal("cookie signed with another key accepted")
	}
	//a value signed for the NEW name must not be accepted when presented under the old name, and the reverse
	if ok, _ := check(&http.Cookie{Name: testNewCookie, Value: old.Value}); ok {
		t.Fatal("the old cookie value must not validate under the new name without translation")
	}
	//password change revokes sessions (session generation): the translated session is checked like any other
	if err := after.SetPassword("admin", "another-correct-horse"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := check(old); ok {
		t.Fatal("a session revoked by a password change was accepted through the old cookie name")
	}
}

// A session from before server side expiry existed ("exp" missing) is translated per request and never
// written again, so its 30 day limit still counts from the day it was issued.
func TestLegacySessionWithoutExpiryNotReissued(t *testing.T) {
	before, after := upgradedAgents(t)
	vals := map[interface{}]interface{}{"authenticated": true, "username": "admin", "rememberMe": false, "sessver": before.loadState("admin").ver}
	sc := before.SessionStore.Codecs[0].(*securecookie.SecureCookie)
	mk := func(days int) *http.Cookie {
		issued := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
		setCodecClock(t, sc, func() int64 { return issued })
		v, err := sc.Encode(testOldCookie, vals)
		setCodecClock(t, sc, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: testOldCookie, Value: v}
	}
	var ok bool
	w := serveLegacy(after, reqWith(mk(10), "GET", "/", nil), func(w http.ResponseWriter, r *http.Request) { ok = after.CheckAuth(r) })
	if !ok {
		t.Fatal("a 10 day old session without exp must be accepted under the old name")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("a session without exp must not be re-issued (that would restart its 30 days): %v", w.Result().Header["Set-Cookie"])
	}
	w = serveLegacy(after, reqWith(mk(40), "GET", "/", nil), func(w http.ResponseWriter, r *http.Request) { ok = after.CheckAuth(r) })
	if ok {
		t.Fatal("a 40 day old session without exp must be refused as before")
	}
}

// Logout removes the cookie under the old name as well: otherwise it would log the browser straight back in.
func TestLogoutRemovesLegacySessionCookie(t *testing.T) {
	before, after := upgradedAgents(t)
	old := login(t, before, "admin", "correct-horse-battery")
	//a browser that holds both (old one still there, new one issued by a later login)
	cur := login(t, after, "admin", "correct-horse-battery")
	r := reqWith(cur, "POST", "/api/auth/logout", nil)
	r.AddCookie(old)
	w := httptest.NewRecorder()
	if err := after.Logout(w, r); err != nil {
		t.Fatal(err)
	}
	set := setCookies(w)
	if c := set[testOldCookie]; c == nil || c.MaxAge >= 0 {
		t.Fatalf("logout must expire the old cookie: %v", w.Result().Header["Set-Cookie"])
	}
	if c := set[testNewCookie]; c == nil || c.MaxAge >= 0 {
		t.Fatalf("logout must expire the current cookie: %v", w.Result().Header["Set-Cookie"])
	}
	//with both cookies present the current one wins and the stale old one is dropped
	r2 := reqWith(cur, "GET", "/", nil)
	r2.AddCookie(old)
	w2 := serveLegacy(after, r2, func(w http.ResponseWriter, r *http.Request) {})
	if c := setCookies(w2)[testOldCookie]; c == nil || c.MaxAge >= 0 {
		t.Fatal("a stale old cookie next to a current one must be removed")
	}
	if setCookies(w2)[testNewCookie] != nil {
		t.Fatal("the current cookie must not be replaced from the old one")
	}
}

// Without legacy names (every install that never had another name) the middleware changes nothing.
func TestLegacySessionMiddlewareInertByDefault(t *testing.T) {
	before, after := upgradedAgents(t)
	after.LegacySessionNames = nil
	old := login(t, before, "admin", "correct-horse-battery")
	var ok bool
	w := serveLegacy(after, reqWith(old, "GET", "/", nil), func(w http.ResponseWriter, r *http.Request) { ok = after.CheckAuth(r) })
	if ok || len(w.Result().Cookies()) != 0 {
		t.Fatal("no legacy names configured: nothing may be accepted or set")
	}
}
