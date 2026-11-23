package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/errorpages"
)

// useErrorPages installs a manager for one test and removes it afterwards (the hook is package wide)
func useErrorPages(t *testing.T, mut func(c *errorpages.Config)) (*errorpages.Manager, *[]string) {
	t.Helper()
	logs := &[]string{}
	m := errorpages.NewManager(filepath.Join(t.TempDir(), errorpages.FileName), func(s string) { *logs = append(*logs, s) })
	if mut != nil {
		cfg := errorpages.DefaultConfig()
		mut(cfg)
		if err := m.Set(cfg); err != nil {
			t.Fatal(err)
		}
	}
	SetCustomErrorPages(m)
	t.Cleanup(func() { SetCustomErrorPages(nil) })
	return m, logs
}

type epAnswer struct {
	Code   int
	Header http.Header
	Body   string
}

// builtinAnswers collects the answer of every hooked code path
func builtinAnswers(t *testing.T) map[string]epAnswer {
	t.Helper()
	out := map[string]epAnswer{}
	rec := func(name string, f func(w http.ResponseWriter, r *http.Request)) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://app.example.com/some/path?x=1", nil)
		r.RemoteAddr = "198.51.100.1:1000"
		r.Header.Set("Accept-Language", "en")
		f(w, r)
		out[name] = epAnswer{w.Code, w.Header().Clone(), w.Body.String()}
	}
	router, sep, _ := newNonTLSTestRouter(t)
	h := &ProxyHandler{Parent: router}
	rec("403 serveProxyRequestError", func(w http.ResponseWriter, r *http.Request) {
		serveProxyRequestError(w, r, 403, router, ErrorTemplateForbidden)
	})
	rec("404 serveProxyRequestError", func(w http.ResponseWriter, r *http.Request) {
		serveProxyRequestError(w, r, 404, router, ErrorTemplateHostError)
	})
	rec("521 serveProxyRequestError", func(w http.ResponseWriter, r *http.Request) {
		serveProxyRequestError(w, r, 521, router, ErrorTemplateRPError)
	})
	rec("403 nil router", func(w http.ResponseWriter, r *http.Request) {
		serveProxyRequestError(w, r, 403, nil, ErrorTemplateForbidden)
	})
	rec("403 writeForbiddenPage", func(w http.ResponseWriter, r *http.Request) {
		router.writeForbiddenPage(w, r, 403, localizedPage(r, page_forbidden), true)
	})
	rec("404 default site", func(w http.ResponseWriter, r *http.Request) { h.serve404PageWithTemplate(w, r) })
	rec("429 site rate limit", func(w http.ResponseWriter, r *http.Request) {
		limited := &ProxyEndpoint{RootOrMatchingDomain: "limited-" + t.Name(), RequireRateLimit: true, RateLimit: 1, parent: router}
		for i := 0; i < 50; i++ {
			if router.handleRateLimit(httptest.NewRecorder(), r, limited) != nil {
				break
			}
		}
		if router.handleRateLimit(w, r, limited) == nil {
			t.Fatal("the rate limit never triggered")
		}
	})
	rec("504 gateway status", func(w http.ResponseWriter, r *http.Request) { router.serveGatewayStatus(w, r, 504) })
	rec("413 gateway status", func(w http.ResponseWriter, r *http.Request) { router.serveGatewayStatus(w, r, 413) })
	_ = sep
	return out
}

// DEFAULT = disabled: without a manager, with a manager that has nothing saved, with a saved but
// disabled customisation and with an enabled one that customises no class, every answer is the
// same, byte for byte and header for header, and it is the built-in page of today.
func TestErrorPages_DisabledIsByteIdentical(t *testing.T) {
	SetCustomErrorPages(nil)
	want := builtinAnswers(t)
	if a := want["403 serveProxyRequestError"]; a.Code != 403 || a.Body != string(renderErrorPage(page_forbidden, "", false)) {
		t.Fatalf("the reference answer is not the built-in 403 page: %d", a.Code)
	}
	if a := want["521 serveProxyRequestError"]; a.Code != 521 || a.Body != string(page_rperror) {
		t.Fatal("the reference answer is not the built-in 521 page")
	}
	if a := want["404 default site"]; a.Code != 404 || a.Body != string(page_hosterror) {
		t.Fatal("the reference answer is not the built-in default site page")
	}
	if a := want["429 site rate limit"]; a.Code != 429 || a.Body != "" || len(a.Header) != 0 {
		t.Fatalf("the reference 429 changed: %+v", a)
	}
	cases := map[string]func(c *errorpages.Config){
		"nothing saved": nil,
		"saved, not enabled": func(c *errorpages.Config) {
			c.Theme.ApplyToBuiltin = true
			c.Theme.LogoText = "Acme"
			for _, ci := range errorpages.Classes() {
				c.Pages[ci.ID] = &errorpages.Page{Title: "custom", Template: "<p>custom {{.Status}}</p>"}
			}
			c.Hosts["app.example.com"] = map[errorpages.Class]*errorpages.Page{errorpages.ClassForbidden: {Template: "host"}}
		},
		"enabled, nothing customised": func(c *errorpages.Config) { c.Enabled = true; c.Theme.LogoText = "Acme" },
		"enabled, another host only": func(c *errorpages.Config) {
			c.Enabled = true
			c.Hosts["other.example.org"] = map[errorpages.Class]*errorpages.Page{errorpages.ClassForbidden: {Template: "host"}}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			useErrorPages(t, mut)
			got := builtinAnswers(t)
			for k, w := range want {
				if g := got[k]; g.Code != w.Code || g.Body != w.Body || !reflect.DeepEqual(g.Header, w.Header) {
					t.Errorf("%s changed:\n got %d %v (%d bytes)\nwant %d %v (%d bytes)", k, g.Code, g.Header, len(g.Body), w.Code, w.Header, len(w.Body))
				}
			}
		})
	}
}

func allCustom(c *errorpages.Config) {
	c.Enabled = true
	c.Theme.LogoText = "Acme"
	for _, ci := range errorpages.Classes() {
		c.Pages[ci.ID] = &errorpages.Page{Template: `<p data-class="` + string(ci.ID) + `">{{.Status}}|{{.Title}}|{{.Host}}|{{.RequestID}}|{{.ClientIP}}|{{.Theme.LogoText}}</p>`}
	}
}

func checkCustomHeaders(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	h := w.Header()
	if h.Get("Cache-Control") != "no-store" || h.Get("Content-Security-Policy") != errorpages.ContentSecurityPolicy ||
		h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: headers of a customised page: %v", name, h)
	}
}

// Every hooked path serves the owner's page with the status it always had
func TestErrorPages_CustomPagesKeepStatusAndGetHeaders(t *testing.T) {
	useErrorPages(t, allCustom)
	got := builtinAnswers(t)
	for name, want := range map[string]struct {
		code  int
		class string
	}{
		"403 serveProxyRequestError": {403, "403"}, "404 serveProxyRequestError": {404, "404"}, "521 serveProxyRequestError": {521, "5xx"},
		"403 nil router": {403, "403"}, "403 writeForbiddenPage": {403, "403"}, "404 default site": {404, "nohost"},
		"429 site rate limit": {429, "429"}, "504 gateway status": {504, "5xx"},
	} {
		a := got[name]
		if a.Code != want.code || !strings.HasPrefix(a.Body, `<p data-class="`+want.class+`">`) || !strings.Contains(a.Body, "|app.example.com|") || !strings.HasSuffix(a.Body, "|Acme</p>") {
			t.Errorf("%s: %d %q", name, a.Code, a.Body)
		}
		if a.Header.Get("Cache-Control") != "no-store" || a.Header.Get("Content-Security-Policy") != errorpages.ContentSecurityPolicy {
			t.Errorf("%s: headers %v", name, a.Header)
		}
	}
	// 4xx statuses of the route limits are not a page class: plain text as before
	if a := got["413 gateway status"]; a.Code != 413 || strings.Contains(a.Body, "<p") || a.Header.Get("Content-Security-Policy") != "" {
		t.Errorf("413 must stay the plain answer: %+v", a)
	}
}

// Markup in the Host header (attacker controlled) never becomes markup of the page
func TestErrorPages_HostileHostIsEscaped(t *testing.T) {
	useErrorPages(t, func(c *errorpages.Config) {
		c.Enabled = true
		c.Theme.ApplyToBuiltin = true
		c.Pages[errorpages.ClassNotFound] = &errorpages.Page{Template: `<a href="https://{{.Host}}/" title="{{.Host}}">{{.Host}}</a>`}
	})
	router, _, _ := newNonTLSTestRouter(t)
	for _, tt := range []ErrorTemplateType{ErrorTemplateForbidden, ErrorTemplateHostError} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = `"><script>alert(document.domain)</script><img src=x onerror="1`
		serveProxyRequestError(w, r, 403, router, tt)
		body := w.Body.String()
		if w.Code != 403 || strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") || strings.Contains(body, `title=""><`) {
			t.Fatalf("hostile Host became markup:\n%s", body)
		}
		if !strings.Contains(body, "&lt;script&gt;") && !strings.Contains(body, "%3cscript%3e") {
			t.Fatalf("the escaped host is missing:\n%s", body)
		}
	}
}

// A template that fails for a request: the built-in page answers (same bytes as without the feature), one log line
func TestErrorPages_BrokenTemplateFallsBack(t *testing.T) {
	SetCustomErrorPages(nil)
	router, _, _ := newNonTLSTestRouter(t)
	serve := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://boom.example.com/", nil)
		serveProxyRequestError(w, r, 521, router, ErrorTemplateRPError)
		return w
	}
	want := serve()
	_, logs := useErrorPages(t, func(c *errorpages.Config) {
		c.Enabled = true
		// passes the test render at save time, fails for the host of this test
		c.Pages[errorpages.ClassServerError] = &errorpages.Page{Template: `{{if eq .Host "boom.example.com"}}{{eq .Status "x"}}{{end}}ok`}
	})
	for i := 0; i < 3; i++ {
		got := serve()
		if got.Code != want.Code || got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Header(), want.Header()) {
			t.Fatalf("fallback differs from the built-in answer: %d %v", got.Code, got.Header())
		}
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "built-in page is served instead") {
		t.Fatalf("expected exactly one log line, got %v", *logs)
	}
}

// Through the whole proxy chain (ProxyHandler.ServeHTTP): a dead upstream, a block of the access list
// with its reference, the Default Site, and a HEAD request.
func TestErrorPages_ThroughTheProxyChain(t *testing.T) {
	useErrorPages(t, func(c *errorpages.Config) {
		allCustom(c)
		c.Theme.ShowRequestID = true
		c.Hosts["app.example.com"] = map[errorpages.Class]*errorpages.Page{errorpages.ClassServerError: {Template: "site page {{.Status}} {{.Host}}"}}
	})
	router, sep := newOpsTestRouter(t, "127.0.0.1:1") //nothing listens: connection refused -> 521
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl

	// the upstream is down: per host page, with the Host the visitor sent (not the upstream's)
	w := serveOps(router, "GET", "/a", nil)
	if w.Code != 521 || w.Body.String() != "site page 521 app.example.com" {
		t.Fatalf("dead upstream: %d %q", w.Code, w.Body.String())
	}
	checkCustomHeaders(t, "dead upstream", w)
	if w := serveOps(router, "HEAD", "/a", nil); w.Code != 521 || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "0" {
		t.Errorf("HEAD: %d body %d bytes, Content-Length %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}

	// the site's own "error pages" option for that status still wins
	sep.Ops = errPagesOn(521)
	if w := serveOps(router, "GET", "/a", nil); w.Code != 521 || !strings.Contains(w.Body.String(), "<h1>521</h1>") {
		t.Errorf("the per site error page option must win: %d %q", w.Code, w.Body.String())
	}
	sep.Ops = nil

	// blocked by the access list: the reference of the block is in the header, in the page and in the log
	rule, err := router.Option.AccessController.GetAccessRuleByID("default")
	if err != nil {
		t.Fatal(err)
	}
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.1", "test")
	w = serveOps(router, "GET", "/a", nil)
	ref := w.Header().Get(RefHeader)
	if w.Code != 403 || ref == "" || !strings.Contains(w.Body.String(), `<p data-class="403">403|Access denied|app.example.com|`+ref+`||Acme</p>`) {
		t.Fatalf("blacklist: %d ref %q body %q", w.Code, ref, w.Body.String())
	}
	checkCustomHeaders(t, "blacklist", w)
	if e := waitBlocked(t, bl, 1)[0]; blocklog.FormatRef(e.Ref) != ref {
		t.Errorf("the reference on the page is not the one in the blocked log: %+v", e)
	}
	rule.BlacklistEnabled = false

	// unknown host -> Default Site "not found" page
	router.Root = &ProxyEndpoint{ProxyType: ProxyTypeRoot, DefaultSiteOption: DefaultSite_NotFoundPage, parent: router}
	w = rootRequest(router)
	if w.Code != 404 || !strings.HasPrefix(w.Body.String(), `<p data-class="nohost">404|Nothing here|unknown.example.org|`) {
		t.Fatalf("default site: %d %q", w.Code, w.Body.String())
	}
}

// "Block common exploits" and "Block AI crawlers": plain text while nothing is customised (byte for
// byte what it was), the owner's 403 / 404 page once that class is customised. 400 stays plain text.
func TestErrorPages_ExploitDetector(t *testing.T) {
	serve := func(action int, ua string, target string) *httptest.ResponseRecorder {
		router, sep, _ := newNonTLSTestRouter(t)
		sep.BlockCommonExploits = true
		sep.BlockAICrawlers = true
		sep.MitigationAction = action
		sep.InitializeExploitDetector()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = "198.51.100.1:1000"
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		router.handleNonTLSRequest(w, r, sep)
		return w
	}
	const exploit, plain = "http://app.example.com/?q=union+all+select+1", "http://app.example.com/"
	type tc struct {
		name   string
		action int
		ua     string
		target string
		code   int
		body   string
	}
	cases := []tc{
		{"exploit 404", 0, "", exploit, 404, "404 page not found\n"},
		{"exploit 403", 1, "", exploit, 403, "Forbidden\n"},
		{"exploit 400", 2, "", exploit, 400, "Bad Request\n"},
		{"AI crawler 404", 0, "Mozilla/5.0 (compatible; GPTBot/1.2)", plain, 404, "404 page not found\n"},
		{"AI crawler 403", 1, "Mozilla/5.0 (compatible; GPTBot/1.2)", plain, 403, "Forbidden\n"},
	}
	check := func(label string) {
		for _, c := range cases {
			w := serve(c.action, c.ua, c.target)
			if w.Code != c.code || w.Body.String() != c.body || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
				w.Header().Get("Content-Security-Policy") != "" {
				t.Errorf("%s, %s: got %d %q %v", label, c.name, w.Code, w.Body.String(), w.Header())
			}
		}
	}
	SetCustomErrorPages(nil)
	check("no manager")
	useErrorPages(t, func(c *errorpages.Config) {
		c.Pages[errorpages.ClassForbidden] = &errorpages.Page{Template: "custom"}
		c.Pages[errorpages.ClassNotFound] = &errorpages.Page{Template: "custom"}
	})
	check("saved, not enabled")
	useErrorPages(t, func(c *errorpages.Config) {
		c.Enabled = true
		c.Pages[errorpages.ClassRateLimit] = &errorpages.Page{Template: "custom"}
	})
	check("enabled, other class only")

	useErrorPages(t, allCustom)
	for _, c := range cases {
		w := serve(c.action, c.ua, c.target)
		if c.code == 400 {
			if w.Code != 400 || w.Body.String() != c.body {
				t.Errorf("%s must stay plain text, got %d %q", c.name, w.Code, w.Body.String())
			}
			continue
		}
		class := "403"
		if c.code == 404 {
			class = "404"
		}
		if w.Code != c.code || !strings.HasPrefix(w.Body.String(), `<p data-class="`+class+`">`+class+`|`) || !strings.Contains(w.Body.String(), "|app.example.com|") {
			t.Errorf("%s: got %d %q", c.name, w.Code, w.Body.String())
		}
		checkCustomHeaders(t, c.name, w)
	}
	// a clean request is not touched
	if w := serve(1, "Mozilla/5.0 Firefox/130.0", plain); w.Code != 299 {
		t.Fatalf("clean request got %d", w.Code)
	}
}
