package legacycompat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
)

const (
	oldCSRFName = "zoraxy_csrf" // legacy-compat: CSRF cookie name of an install made before the rename
	newCSRFName = "dunree_csrf"
)

var csrfKey = []byte("3f0c9a1e-node-uuid-used-as-key-0001")

func protect(name string) func(http.Handler) http.Handler {
	return csrf.Protect(csrfKey, csrf.CookieName(name), csrf.Secure(false), csrf.Path("/"), csrf.SameSite(csrf.SameSiteLaxMode))
}

// app answers GET with the token (what the admin page puts into its meta tag) and POST with "saved".
var app = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Write([]byte(csrf.Token(r)))
		return
	}
	w.Write([]byte("saved"))
})

func compatCookie() CSRFCookie {
	return CSRFCookie{Key: csrfKey, Name: newCSRFName, LegacyName: oldCSRFName, Path: "/", SameSite: http.SameSiteLaxMode}
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// pageOpenBeforeUpgrade loads a page on the old build and returns its CSRF cookie and the token in the page.
func pageOpenBeforeUpgrade(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	protect(oldCSRFName)(app).ServeHTTP(w, httptest.NewRequest("GET", "http://admin.test/", nil))
	c := cookieNamed(w, oldCSRFName)
	if c == nil || w.Body.Len() == 0 {
		t.Fatalf("setup: old build issued no CSRF cookie/token: %v", w.Result().Header)
	}
	return c, w.Body.String()
}

func post(h http.Handler, token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://admin.test/api/save", strings.NewReader("a=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-CSRF-Token", token)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	// the admin interface of these tests is plain HTTP: gorilla/csrf v1.7.3 has to be told, or it asks for
	// an https Referer (in the program mod/csrfguard does this per request)
	h.ServeHTTP(w, csrf.PlaintextHTTPRequest(r))
	return w
}

// An admin page that was open during the upgrade can still save: its token is checked against the old
// cookie, and the browser gets the cookie under the new name.
func TestLegacyCSRFCookieAccepted(t *testing.T) {
	old, token := pageOpenBeforeUpgrade(t)

	//control: the renamed middleware alone refuses the request
	if w := post(protect(newCSRFName)(app), token, old); w.Code != http.StatusForbidden {
		t.Fatalf("setup: without the compat layer the old cookie should not validate, got %d", w.Code)
	}

	h := compatCookie().Wrap(protect(newCSRFName)(app))
	w := post(h, token, old)
	if w.Code != http.StatusOK || w.Body.String() != "saved" {
		t.Fatalf("POST with the old CSRF cookie refused: %d %s", w.Code, w.Body.String())
	}
	nc := cookieNamed(w, newCSRFName)
	if nc == nil || nc.Value == "" {
		t.Fatalf("the new cookie was not set: %v", w.Result().Header["Set-Cookie"])
	}
	if !nc.HttpOnly || nc.Path != "/" || nc.SameSite != http.SameSiteLaxMode || nc.MaxAge != csrfDefaultMaxAge {
		t.Fatalf("new cookie attributes differ from what gorilla/csrf writes: %+v", nc)
	}
	if c := cookieNamed(w, oldCSRFName); c != nil {
		t.Fatalf("the old cookie must not be written again: %+v", c)
	}
	//next request: the browser sends both; the token of the open page still matches and nothing is set
	w2 := post(h, token, old, nc)
	if w2.Code != http.StatusOK {
		t.Fatalf("POST with both cookies refused: %d", w2.Code)
	}
	if len(w2.Result().Cookies()) != 0 {
		t.Fatalf("no cookie expected once the new one exists: %v", w2.Result().Header["Set-Cookie"])
	}
	//and with only the new one (old expired)
	if w3 := post(h, token, nc); w3.Code != http.StatusOK {
		t.Fatalf("POST with the new cookie refused: %d", w3.Code)
	}
}

// The compat layer is not a bypass: a wrong token, a forged cookie and a cookie made with another key fail.
func TestLegacyCSRFCookieRefusals(t *testing.T) {
	old, token := pageOpenBeforeUpgrade(t)
	h := compatCookie().Wrap(protect(newCSRFName)(app))

	if w := post(h, "not-the-token", old); w.Code != http.StatusForbidden {
		t.Fatalf("wrong token accepted: %d", w.Code)
	}
	if w := post(h, token); w.Code != http.StatusForbidden {
		t.Fatalf("token without any cookie accepted: %d", w.Code)
	}
	forged := &http.Cookie{Name: oldCSRFName, Value: old.Value[:len(old.Value)-4] + "AAAA"}
	w := post(h, token, forged)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tampered cookie accepted: %d", w.Code)
	}
	//another install (other key): its cookie and token are worth nothing here
	wo := httptest.NewRecorder()
	csrf.Protect([]byte("another-install-key-000000000002"), csrf.CookieName(oldCSRFName), csrf.Secure(false))(app).
		ServeHTTP(wo, httptest.NewRequest("GET", "http://admin.test/", nil))
	if w := post(h, wo.Body.String(), cookieNamed(wo, oldCSRFName)); w.Code != http.StatusForbidden {
		t.Fatalf("cookie of another key accepted: %d", w.Code)
	}
	//a value signed for the old name must not pass when sent under the new name
	if w := post(h, token, &http.Cookie{Name: newCSRFName, Value: old.Value}); w.Code != http.StatusForbidden {
		t.Fatalf("old value under the new name accepted: %d", w.Code)
	}
}

// A browser without any cookie gets only the new name.
func TestCSRFNewInstallOnlyNewName(t *testing.T) {
	h := compatCookie().Wrap(protect(newCSRFName)(app))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://admin.test/", nil))
	if cookieNamed(w, newCSRFName) == nil || cookieNamed(w, oldCSRFName) != nil {
		t.Fatalf("want only %s: %v", newCSRFName, w.Result().Header["Set-Cookie"])
	}
	if (CSRFCookie{Key: csrfKey, Name: newCSRFName}).Adopt(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("no legacy name configured: nothing to adopt")
	}
}
