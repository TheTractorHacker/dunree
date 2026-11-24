package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foleyit/dunree/mod/cluster"
	"github.com/foleyit/dunree/mod/dynamicproxy/captcha"
	"github.com/foleyit/dunree/mod/wirecompat"
)

/*
	Dunree rebrand: names on the wire of the proxy listeners.

	  - /.dunree/... is the public path, /.zoraxy/... is answered the same way
	  - response headers are X-Dunree-*, and X-Zoraxy-* as well while the legacy names are on
*/

func TestHealthAnswersOnBothPrefixes(t *testing.T) {
	if cluster.HealthPath != "/.dunree/health" || cluster.LegacyHealthPath != "/.zoraxy/health" { // legacy-compat
		t.Fatalf("health paths changed: %q %q", cluster.HealthPath, cluster.LegacyHealthPath)
	}
	router := newHealthTestRouter(cluster.NewHealthEndpoint("1"))
	router.ProxyEndpoints.Store("a.example.com", &ProxyEndpoint{RootOrMatchingDomain: "a.example.com"})
	router.Running = true
	downstream := 0
	h := router.withHealth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { downstream++ }))
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "192.0.2.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	strip := func(body string) string { //uptime moves between two calls
		i := strings.Index(body, `"uptimeSeconds"`)
		if i < 0 {
			t.Fatalf("no uptime in %s", body)
		}
		j := strings.IndexAny(body[i:], ",}")
		return body[:i] + body[i+j:]
	}
	a, b := get(cluster.HealthPath), get(cluster.LegacyHealthPath)
	if a.Code != 200 || b.Code != 200 || strip(a.Body.String()) != strip(b.Body.String()) || a.Header().Get("Content-Type") != b.Header().Get("Content-Type") {
		t.Fatalf("the two prefixes answer differently: %d %s / %d %s", a.Code, a.Body.String(), b.Code, b.Body.String())
	}
	if downstream != 0 {
		t.Fatal("a health request reached host routing")
	}
	for _, p := range []string{"/.dunree/healthz", "/.dunree/health/", "/.dunree", "/.dunree/", "/.DUNREE/health", "/x/.dunree/health", "/.dunree/captcha/verify"} {
		get(p)
	}
	if downstream != 7 {
		t.Fatalf("the health handler shadowed other routes: %d of 7 reached host routing", downstream)
	}
}

func TestCaptchaVerifyAnswersOnBothPrefixes(t *testing.T) {
	if captcha.VerifyPath != "/.dunree/captcha/verify" || captcha.LegacyVerifyPath != "/.zoraxy/captcha/verify" || // legacy-compat
		captcha.AltchaChallengePath != "/.dunree/captcha/altcha" || captcha.LegacyAltchaChallengePath != "/.zoraxy/captcha/altcha" { // legacy-compat
		t.Fatal("captcha paths changed")
	}
	// A custom challenge template saved before the rebrand posts to the old path
	for _, path := range []string{captcha.VerifyPath, captcha.LegacyVerifyPath} {
		t.Run(path, func(t *testing.T) {
			sent := stubCaptchaProvider(t)
			router := newTestCaptchaRouter(t, false)
			r := newTestCaptchaVerifyRequest("203.0.113.5:44321", nil)
			r.URL.Path = path
			w := httptest.NewRecorder()
			handled, _ := router.handleCaptchaGating(w, r, newTestCaptchaEndpoint(""))
			if !handled || sent.Get("response") != "test-token" {
				t.Fatalf("POST %s was not treated as the verification (handled=%v, provider got %v)", path, handled, *sent)
			}
			var session *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == captcha.CookieName && c.Value != "" {
					session = c
				}
			}
			if session == nil {
				t.Fatalf("POST %s: no session cookie, status %d", path, w.Code)
			}
		})
	}
	// Anything else under either prefix is an ordinary request: challenged, not verified
	for _, path := range []string{"/.dunree/captcha/verify/", "/.zoraxy/captcha/verifyx", "/.dunree/captcha", "/.Dunree/captcha/verify"} { // legacy-compat
		sent := stubCaptchaProvider(t)
		router := newTestCaptchaRouter(t, false)
		r := newTestCaptchaVerifyRequest("203.0.113.5:44321", nil)
		r.URL.Path = path
		if _, challenged := router.handleCaptchaGating(httptest.NewRecorder(), r, newTestCaptchaEndpoint("")); !challenged || len(*sent) != 0 {
			t.Errorf("%s: challenged=%v, provider called with %v", path, challenged, *sent)
		}
	}
}

// The challenge page posts to the Dunree path
func TestChallengePagePostsToTheDunreePath(t *testing.T) {
	router := newTestCaptchaRouter(t, false)
	w := httptest.NewRecorder()
	if _, challenged := router.handleCaptchaGating(w, newTestRequest("203.0.113.5:44321", nil), newTestCaptchaEndpoint("")); !challenged {
		t.Fatal("not challenged")
	}
	body := w.Body.String()
	if !strings.Contains(body, captcha.VerifyPath) || strings.Contains(body, captcha.LegacyVerifyPath) {
		t.Fatalf("the built-in challenge page must use %s only", captcha.VerifyPath)
	}
}

func TestCaptchaReasonHeaderFollowsTheLegacySwitch(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	challenge := func() http.Header {
		router := newTestCaptchaRouter(t, false)
		w := httptest.NewRecorder()
		if _, challenged := router.handleCaptchaGating(w, newTestRequest("203.0.113.5:44321", nil), newTestCaptchaEndpoint("")); !challenged {
			t.Fatal("not challenged")
		}
		return w.Header()
	}
	h := challenge()
	if h.Get("X-Dunree-Captcha-Reason") != captcha.ReasonMissing || h.Get("X-Zoraxy-Captcha-Reason") != captcha.ReasonMissing { // legacy-compat
		t.Fatalf("legacy names on: %v", h)
	}
	wirecompat.SetEmitLegacy(false)
	h = challenge()
	if h.Get("X-Dunree-Captcha-Reason") != captcha.ReasonMissing || len(h.Values("X-Zoraxy-Captcha-Reason")) != 0 { // legacy-compat
		t.Fatalf("legacy names off: %v", h)
	}
}

func TestBlockReferenceHeaderFollowsTheLegacySwitch(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	if RefHeader != "X-Dunree-Ref" || LegacyRefHeader != "X-Zoraxy-Ref" { // legacy-compat
		t.Fatalf("header names changed: %q %q", RefHeader, LegacyRefHeader)
	}
	router, sep, _ := refRouter(t, nil)
	w := serveUA(router, sep, "sqlmap/1.5")
	ref := w.Header().Get(RefHeader)
	if w.Code != 403 || !zxRef.MatchString(ref) || w.Header().Get(LegacyRefHeader) != ref {
		t.Fatalf("legacy names on: %d %v", w.Code, w.Header())
	}
	wirecompat.SetEmitLegacy(false)
	w = serveUA(router, sep, "sqlmap/1.5")
	if !zxRef.MatchString(w.Header().Get(RefHeader)) || len(w.Header().Values(LegacyRefHeader)) != 0 {
		t.Fatalf("legacy names off: %v", w.Header())
	}
	//The page itself does not depend on the switch
	if !strings.Contains(w.Body.String(), w.Header().Get(RefHeader)) {
		t.Fatal("the reference of the header is not on the page")
	}
}
