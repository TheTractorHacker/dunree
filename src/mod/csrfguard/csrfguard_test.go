// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package csrfguard

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/csrf"
)

var testKey = []byte("0b0c9a1e-2222-4333-8444-555566667777")

// site is the admin interface as main() wires it (csrf.Protect behind Policy.Wrap) on a real listener,
// so that r.TLS, r.Host and r.URL are what a real request has.
type site struct {
	t      *testing.T
	srv    *httptest.Server
	host   string // host:port of the listener
	client *http.Client
	cookie *http.Cookie
	token  string
	mu     sync.Mutex
	seen   []*http.Request // what the handler behind the check received
	logs   []string
}

func newSite(t *testing.T, useTLS bool, p *Policy) *site {
	t.Helper()
	s := &site{t: t}
	p.Logf = func(format string, a ...any) {
		s.mu.Lock()
		s.logs = append(s.logs, fmt.Sprintf(format, a...))
		s.mu.Unlock()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, csrf.Token(r))
			return
		}
		s.mu.Lock()
		s.seen = append(s.seen, r)
		s.mu.Unlock()
		io.WriteString(w, "saved")
	})
	protect := csrf.Protect(testKey, append([]csrf.Option{csrf.CookieName("dunree_csrf"), csrf.Secure(useTLS), csrf.Path("/"),
		csrf.SameSite(csrf.SameSiteLaxMode)}, p.Options()...)...)
	h := p.Wrap(protect, mux)
	if useTLS {
		s.srv = httptest.NewTLSServer(h)
	} else {
		s.srv = httptest.NewServer(h)
	}
	t.Cleanup(s.srv.Close)
	u, _ := url.Parse(s.srv.URL)
	s.host = u.Host
	s.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
	resp, err := s.client.Get(s.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.token = string(body)
	for _, c := range resp.Cookies() {
		if c.Name == "dunree_csrf" {
			s.cookie = c
		}
	}
	if s.cookie == nil || s.token == "" {
		t.Fatalf("setup: no CSRF cookie or token (%d %q)", resp.StatusCode, body)
	}
	return s
}

type send struct {
	method  string            // default POST
	host    string            // Host header, default the listener address
	headers map[string]string // Origin, Referer, X-Forwarded-Host, ...
	noToken bool
	badTok  bool
}

func (s *site) do(x send) (int, string) {
	s.t.Helper()
	method := x.method
	if method == "" {
		method = http.MethodPost
	}
	req, _ := http.NewRequest(method, s.srv.URL+"/api/save?x=1", strings.NewReader("a=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if x.host != "" {
		req.Host = x.host
	}
	for k, v := range x.headers {
		req.Header.Set(k, strings.ReplaceAll(v, "{self}", s.host))
	}
	switch {
	case x.badTok:
		req.Header.Set("X-CSRF-Token", "AAAA"+s.token[4:])
	case !x.noToken:
		req.Header.Set("X-CSRF-Token", s.token)
	}
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: s.cookie.Value})
	resp, err := s.client.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

type originCase struct {
	name string
	send send
	want int
}

func runCases(t *testing.T, s *site, cases []originCase) {
	t.Helper()
	for _, c := range cases {
		got, body := s.do(c.send)
		if got != c.want {
			t.Errorf("%s: got %d, want %d (%q)", c.name, got, c.want, strings.TrimSpace(body))
		}
	}
}

func h(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// Plain HTTP admin interface (-webui_tls off, the default): without csrf.PlaintextHTTPRequest every POST
// of a browser would be refused by v1.7.3, because the library assumes https.
func TestPlainHTTPAdminInterface(t *testing.T) {
	s := newSite(t, false, &Policy{})
	runCases(t, s, []originCase{
		{"script: cookie and token, no Origin, no Referer", send{}, 200},
		{"browser: Origin is the own http address", send{headers: h("Origin", "http://{self}", "Referer", "http://{self}/", "Sec-Fetch-Site", "same-origin")}, 200},
		{"page of another site", send{headers: h("Origin", "http://evil.example", "Sec-Fetch-Site", "cross-site")}, 403},
		{"page of another site, same port", send{headers: h("Origin", "http://evil.example:80")}, 403},
		{"opaque origin (sandboxed frame, stripped referrer)", send{headers: h("Origin", "null")}, 403},
		{"broken Origin", send{headers: h("Origin", "http://%zz")}, 403},
		{"own address, token missing", send{headers: h("Origin", "http://{self}"), noToken: true}, 403},
		{"own address, token wrong", send{headers: h("Origin", "http://{self}"), badTok: true}, 403},
		{"no headers, token missing", send{noToken: true}, 403},
		{"PUT from another site", send{method: "PUT", headers: h("Origin", "http://evil.example")}, 403},
		{"DELETE from the own address", send{method: "DELETE", headers: h("Origin", "http://{self}")}, 200},
		{"GET from another site is not a change", send{method: "GET", headers: h("Origin", "http://evil.example")}, 200},
		// documented limit, same as the library: without Origin the Referer is not looked at on plain HTTP
		{"no Origin, http Referer of another site", send{headers: h("Referer", "http://evil.example/x")}, 200},
	})
}

// HTTPS admin interface (-webui_tls auto / custom): the library checks as designed. This is the case of
// the advisory: v1.7.2 accepted every one of the refused requests below when cookie and token matched.
func TestHTTPSAdminInterface(t *testing.T) {
	s := newSite(t, true, &Policy{})
	runCases(t, s, []originCase{
		{"browser: Origin is the own https address", send{headers: h("Origin", "https://{self}", "Sec-Fetch-Site", "same-origin")}, 200},
		{"script: no Origin, no Referer, no Sec-Fetch-Site", send{}, 200},
		{"old browser: no Origin, own https Referer", send{headers: h("Referer", "https://{self}/index.html")}, 200},
		{"page of another site", send{headers: h("Origin", "https://evil.example")}, 403},
		{"downgrade: http page of the own host", send{headers: h("Origin", "http://{self}")}, 403},
		{"opaque origin", send{headers: h("Origin", "null")}, 403},
		{"no Origin, Referer of another site (GO-2025-3607)", send{headers: h("Referer", "https://evil.example/form.html")}, 403},
		{"no Origin, http Referer of the own host (GO-2025-3607)", send{headers: h("Referer", "http://{self}/")}, 403},
		{"browser that hides Origin and Referer", send{headers: h("Sec-Fetch-Site", "cross-site")}, 403},
		{"browser that hides them, same-origin claim", send{headers: h("Sec-Fetch-Site", "same-origin")}, 403},
		{"script, token missing", send{noToken: true}, 403},
		{"script, token wrong", send{badTok: true}, 403},
		{"X-Forwarded-Host does not help another site", send{headers: h("Origin", "https://evil.example", "X-Forwarded-Host", "{self}")}, 403},
		{"GET from another site is not a change", send{method: "GET", headers: h("Origin", "https://evil.example")}, 200},
	})
}

func TestStrictRequiresRefererFromScripts(t *testing.T) {
	s := newSite(t, true, &Policy{Strict: true})
	runCases(t, s, []originCase{
		{"script without Origin and Referer", send{}, 403},
		{"script that sends the own Referer", send{headers: h("Referer", "https://{self}/")}, 200},
		{"browser", send{headers: h("Origin", "https://{self}")}, 200},
	})
	if _, body := s.do(send{}); !strings.Contains(body, "Forbidden - referer not supplied") || !strings.Contains(body, "neither an Origin nor a Referer") {
		t.Errorf("refusal text: %q", body)
	}
	// plain HTTP is not affected by Strict for scripts (the library has no Referer rule there)
	p := newSite(t, false, &Policy{Strict: true})
	runCases(t, p, []originCase{{"plain HTTP script, strict", send{}, 200}})
}

// A reverse proxy in front of the plain HTTP admin interface ends TLS and passes the Host header on
// (what Dunree itself, Caddy, Traefik and nginx with "proxy_set_header Host $host" do).
func TestBehindTLSProxyThatKeepsTheHost(t *testing.T) {
	s := newSite(t, false, &Policy{})
	runCases(t, s, []originCase{
		{"https page of the public name", send{host: "admin.example.com", headers: h("Origin", "https://admin.example.com")}, 200},
		{"with port", send{host: "admin.example.com:8443", headers: h("Origin", "https://admin.example.com:8443")}, 200},
		{"other port is another origin", send{host: "admin.example.com", headers: h("Origin", "https://admin.example.com:8443")}, 403},
		{"other site, https", send{host: "admin.example.com", headers: h("Origin", "https://evil.example")}, 403},
		{"sibling name", send{host: "admin.example.com", headers: h("Origin", "https://www.example.com")}, 403},
		{"no Origin, own https Referer", send{host: "admin.example.com", headers: h("Referer", "https://admin.example.com/")}, 200},
		{"no Origin, https Referer of another site", send{host: "admin.example.com", headers: h("Referer", "https://evil.example/")}, 403},
		{"script through the proxy", send{host: "admin.example.com"}, 200},
	})
}

// A reverse proxy that replaces the Host header (Apache ProxyPass, nginx without proxy_set_header).
func TestBehindProxyThatReplacesTheHost(t *testing.T) {
	s := newSite(t, false, &Policy{})
	runCases(t, s, []originCase{
		{"X-Forwarded-Host names the page's host", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com")}, 200},
		{"http page, X-Forwarded-Host", send{headers: h("Origin", "http://admin.example.com", "X-Forwarded-Host", "admin.example.com")}, 200},
		{"chain of proxies: the first value counts", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com, inner.lan:3000")}, 200},
		{"upper case in the forwarded host", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "Admin.Example.com")}, 200},
		{"no X-Forwarded-Host", send{headers: h("Origin", "https://admin.example.com")}, 403},
		{"other site, X-Forwarded-Host of the admin", send{headers: h("Origin", "https://evil.example", "X-Forwarded-Host", "admin.example.com")}, 403},
		{"other site named second in the chain", send{headers: h("Origin", "https://evil.example", "X-Forwarded-Host", "admin.example.com, evil.example")}, 403},
		{"forwarded host with another port", send{headers: h("Origin", "https://admin.example.com:8443", "X-Forwarded-Host", "admin.example.com")}, 403},
		{"token still required", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com"), noToken: true}, 403},
	})

	// the refusal says what to do, and it is logged once per origin
	s.mu.Lock()
	s.logs = nil
	s.mu.Unlock()
	for i := 0; i < 3; i++ {
		code, body := s.do(send{headers: h("Origin", "https://panel.example.net")})
		if code != 403 || !strings.HasPrefix(body, "Forbidden - origin invalid") || !strings.Contains(body, "-csrf_trusted_origins=panel.example.net") {
			t.Fatalf("refusal text: %d %q", code, body)
		}
	}
	s.mu.Lock()
	logs := append([]string(nil), s.logs...)
	s.mu.Unlock()
	if len(logs) != 1 || !strings.Contains(logs[0], `"panel.example.net"`) || !strings.Contains(logs[0], "-csrf_trusted_origins") {
		t.Errorf("want one log line naming the origin and the switch, got %q", logs)
	}

	// the handler behind the check gets the request as it came in
	s.seen = nil
	if code, _ := s.do(send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com")}); code != 200 {
		t.Fatal("setup")
	}
	r := s.seen[0]
	if r.URL.Host != "" || r.URL.Path != "/api/save" || r.URL.RawQuery != "x=1" || r.Host != s.host ||
		r.Header.Get("Origin") != "https://admin.example.com" || r.Header.Get("X-Forwarded-Host") != "admin.example.com" {
		t.Errorf("request changed on the way to the handler: URL %#v Host %q headers %v", r.URL, r.Host, r.Header)
	}

	// Strict: X-Forwarded-Host is not used
	strict := newSite(t, false, &Policy{Strict: true})
	runCases(t, strict, []originCase{
		{"strict ignores X-Forwarded-Host", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com")}, 403},
		{"strict, own address", send{headers: h("Origin", "http://{self}")}, 200},
	})
}

func TestTrustedOrigins(t *testing.T) {
	trusted, err := ParseTrustedOrigins("admin.example.com, https://panel.lan:8443")
	if err != nil {
		t.Fatal(err)
	}
	for _, useTLS := range []bool{false, true} {
		for _, strict := range []bool{false, true} {
			s := newSite(t, useTLS, &Policy{TrustedOrigins: trusted, Strict: strict})
			name := fmt.Sprintf("tls=%v strict=%v: ", useTLS, strict)
			runCases(t, s, []originCase{
				{name + "listed host", send{headers: h("Origin", "https://admin.example.com")}, 200},
				{name + "listed origin with scheme and port", send{headers: h("Origin", "https://panel.lan:8443")}, 200},
				{name + "listed https origin, http page", send{headers: h("Origin", "http://panel.lan:8443")}, 403},
				{name + "listed host, other port", send{headers: h("Origin", "https://panel.lan")}, 403},
				{name + "listed host, upper case", send{headers: h("Origin", "https://ADMIN.example.com")}, 200},
				{name + "host that only starts like a listed one", send{headers: h("Origin", "https://admin.example.com.evil.example")}, 403},
				{name + "subdomain of a listed host", send{headers: h("Origin", "https://x.admin.example.com")}, 403},
				{name + "not listed", send{headers: h("Origin", "https://evil.example")}, 403},
				{name + "listed host, token missing", send{headers: h("Origin", "https://admin.example.com"), noToken: true}, 403},
			})
		}
	}
	// GO-2025-3884 (the library's own TrustedOrigins compares the host only): an http page of a listed
	// host is refused when the admin interface is HTTPS, or when the proxy in front says the browser used https
	sec := newSite(t, true, &Policy{TrustedOrigins: trusted})
	runCases(t, sec, []originCase{
		{"HTTPS, http page of a listed host", send{headers: h("Origin", "http://admin.example.com")}, 403},
		// documented limit: without Origin only the Host header itself counts for the Referer
		{"HTTPS, Referer of a listed host, no Origin", send{headers: h("Referer", "https://admin.example.com/index.html")}, 403},
	})
	plain := newSite(t, false, &Policy{TrustedOrigins: trusted})
	runCases(t, plain, []originCase{
		{"plain HTTP, http page of a listed host", send{headers: h("Origin", "http://admin.example.com")}, 200},
		{"plain HTTP behind a TLS proxy (X-Forwarded-Proto), http page of a listed host", send{headers: h("Origin", "http://admin.example.com", "X-Forwarded-Proto", "https")}, 403},
		{"plain HTTP behind a TLS proxy, https page of a listed host", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Proto", "https")}, 200},
	})
	// the library's option is not used, so its host-only comparison never runs
	if n := len((&Policy{TrustedOrigins: trusted}).Options()); n != 1 {
		t.Errorf("Options must only set the error handler, got %d options", n)
	}
	// the empty default lists nothing
	if got, err := ParseTrustedOrigins(""); err != nil || len(got) != 0 {
		t.Errorf("empty list: %v %v", got, err)
	}
}

// X-Forwarded-Proto: https from the proxy in front: an http page is refused also for the own host.
func TestForwardedProtoHTTPS(t *testing.T) {
	s := newSite(t, false, &Policy{})
	runCases(t, s, []originCase{
		{"https page", send{host: "admin.example.com", headers: h("Origin", "https://admin.example.com", "X-Forwarded-Proto", "https")}, 200},
		{"http page of the same host (downgrade)", send{host: "admin.example.com", headers: h("Origin", "http://admin.example.com", "X-Forwarded-Proto", "https")}, 403},
		{"chain: the first value counts", send{host: "admin.example.com", headers: h("Origin", "http://admin.example.com", "X-Forwarded-Proto", "https, http")}, 403},
		{"proxy says http", send{host: "admin.example.com", headers: h("Origin", "http://admin.example.com", "X-Forwarded-Proto", "http")}, 200},
		{"script through the TLS proxy, no Origin and no Referer", send{host: "admin.example.com", headers: h("X-Forwarded-Proto", "https")}, 200},
		{"script through the TLS proxy with its Referer", send{host: "admin.example.com", headers: h("X-Forwarded-Proto", "https", "Referer", "https://admin.example.com/")}, 200},
		{"no Origin, Referer of another site", send{host: "admin.example.com", headers: h("X-Forwarded-Proto", "https", "Referer", "https://evil.example/")}, 403},
		{"no Origin, http Referer of the own host", send{host: "admin.example.com", headers: h("X-Forwarded-Proto", "https", "Referer", "http://admin.example.com/")}, 403},
		{"browser that hides Origin and Referer", send{host: "admin.example.com", headers: h("X-Forwarded-Proto", "https", "Sec-Fetch-Site", "cross-site")}, 403},
	})
	if _, body := s.do(send{host: "admin.example.com", headers: h("Origin", "http://admin.example.com", "X-Forwarded-Proto", "https")}); !strings.Contains(body, "http page") || strings.Contains(body, "csrf_trusted_origins") {
		t.Errorf("a downgrade must be named as such, not as a missing trusted origin: %q", body)
	}
	strict := newSite(t, false, &Policy{Strict: true})
	runCases(t, strict, []originCase{
		{"strict: script through the TLS proxy without Referer", send{host: "admin.example.com", headers: h("X-Forwarded-Proto", "https")}, 403},
	})
}

func TestParseTrustedOrigins(t *testing.T) {
	good := map[string][]string{
		"":                                    nil,
		" , ":                                 nil,
		"admin.example.com":                   {"admin.example.com"},
		"Admin.Example.COM":                   {"admin.example.com"},
		"https://admin.example.com/":          {"https://admin.example.com"},
		"https://admin.example.com:443":       {"https://admin.example.com"},
		"http://admin.example.com:80":         {"http://admin.example.com"},
		"https://admin.example.com:80":        {"https://admin.example.com:80"},
		"admin.example.com:443":               {"admin.example.com:443"}, // no scheme: taken as written
		"10.0.0.5:8443, [::1]:8443":           {"10.0.0.5:8443", "[::1]:8443"},
		"a.lan,b.lan , a.lan":                 {"a.lan", "b.lan"},
		"https://xn--bcher-kva.example:8443/": {"https://xn--bcher-kva.example:8443"},
	}
	for in, want := range good {
		got, err := ParseTrustedOrigins(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"*.example.com", "*", "https://admin.example.com/panel", "admin.example.com/x", "ftp://admin.example.com",
		"user@admin.example.com", "admin example.com", "admin.example.com:", "admin.example.com:port", "admin.example.com:99999",
		"https://", "a.lan;b.lan?x", "::1"} {
		if got, err := ParseTrustedOrigins(in); err == nil {
			t.Errorf("%q must be refused, got %v", in, got)
		}
	}
}

// Describe never changes the request the caller holds, and leaves safe methods alone.
func TestDescribeLeavesTheRequestAlone(t *testing.T) {
	p := &Policy{}
	r := httptest.NewRequest("POST", "/api/save", nil)
	r.Host = "127.0.0.1:3000"
	r.Header.Set("Origin", "https://admin.example.com")
	r.Header.Set("X-Forwarded-Host", "admin.example.com")
	before := *r.URL
	d := p.Describe(r)
	if d == r || d.URL.Host != "admin.example.com" {
		t.Fatalf("the forwarded host was not passed to the library: %#v", d.URL)
	}
	if *r.URL != before || r.URL.Host != "" {
		t.Errorf("the caller's request was changed: %#v", r.URL)
	}
	g := httptest.NewRequest("GET", "/x", nil)
	g.Header.Set("Origin", "https://evil.example")
	if p.Describe(g) != g {
		t.Error("a GET must be passed on as it is")
	}
}

// A proxy that writes the Host header differently from the browser (upper case, or with the default port
// of the scheme, as nginx does with "proxy_set_header Host $host:$server_port") is the same address. Before
// v1.7.3 these saves worked; the library compares exactly, so the policy hands the browser's spelling over.
func TestSameHostWrittenDifferently(t *testing.T) {
	s := newSite(t, false, &Policy{})
	runCases(t, s, []originCase{
		{"Host with :443, https page", send{host: "admin.example.com:443", headers: h("Origin", "https://admin.example.com", "X-Forwarded-Proto", "https")}, 200},
		{"Host with :80, http page", send{host: "admin.example.com:80", headers: h("Origin", "http://admin.example.com")}, 200},
		{"Host in upper case", send{host: "Admin.Example.COM", headers: h("Origin", "https://admin.example.com")}, 200},
		{"X-Forwarded-Host with :443", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com:443")}, 200},
		{"no Origin, own Referer, Host with :443", send{host: "admin.example.com:443", headers: h("Referer", "https://admin.example.com/", "X-Forwarded-Proto", "https")}, 200},
		{"no Origin, own Referer, Host in upper case", send{host: "ADMIN.example.com", headers: h("Referer", "https://admin.example.com/", "X-Forwarded-Proto", "https")}, 200},
		// the default port belongs to the page's scheme only, and the scheme is still compared
		{"Host with :443, http page", send{host: "admin.example.com:443", headers: h("Origin", "http://admin.example.com")}, 403},
		{"Host with :80, https page", send{host: "admin.example.com:80", headers: h("Origin", "https://admin.example.com")}, 403},
		{"Host with :443, http page, X-Forwarded-Proto https", send{host: "admin.example.com:443", headers: h("Origin", "http://admin.example.com", "X-Forwarded-Proto", "https")}, 403},
		{"X-Forwarded-Host with :80, https page", send{headers: h("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com:80")}, 403},
		{"no Origin, http Referer, Host with :443, X-Forwarded-Proto https", send{host: "admin.example.com:443", headers: h("Referer", "http://admin.example.com/", "X-Forwarded-Proto", "https")}, 403},
		{"no Origin, Referer of another site, Host with :443", send{host: "admin.example.com:443", headers: h("Referer", "https://evil.example/", "X-Forwarded-Proto", "https")}, 403},
		{"other site, Host with :443", send{host: "admin.example.com:443", headers: h("Origin", "https://evil.example")}, 403},
		{"other port is still another origin", send{host: "admin.example.com:8443", headers: h("Origin", "https://admin.example.com")}, 403},
		{"token still required", send{host: "admin.example.com:443", headers: h("Origin", "https://admin.example.com"), noToken: true}, 403},
	})

	// the handler gets the Host header and URL as they came in
	s.mu.Lock()
	s.seen = nil
	s.mu.Unlock()
	if code, _ := s.do(send{host: "admin.example.com:443", headers: h("Referer", "https://admin.example.com/", "X-Forwarded-Proto", "https")}); code != 200 {
		t.Fatal("setup")
	}
	if code, _ := s.do(send{host: "Admin.Example.COM", headers: h("Origin", "https://admin.example.com")}); code != 200 {
		t.Fatal("setup")
	}
	s.mu.Lock()
	seen := append([]*http.Request(nil), s.seen...)
	s.mu.Unlock()
	if len(seen) != 2 || seen[0].Host != "admin.example.com:443" || seen[0].URL.Host != "" ||
		seen[1].Host != "Admin.Example.COM" || seen[1].URL.Host != "" {
		t.Errorf("request changed on the way to the handler: %d requests", len(seen))
		for _, r := range seen {
			t.Errorf("  Host %q URL %#v", r.Host, r.URL)
		}
	}

	// same over the HTTPS listener (r.TLS set)
	tlsSite := newSite(t, true, &Policy{})
	runCases(t, tlsSite, []originCase{
		{"TLS, Host with :443", send{host: "admin.example.com:443", headers: h("Origin", "https://admin.example.com")}, 200},
		{"TLS, Host with :443, http page", send{host: "admin.example.com:443", headers: h("Origin", "http://admin.example.com")}, 403},
	})
}

// A path with a line break must not start a new line in the log.
func TestRefusalLogIsOneLine(t *testing.T) {
	s := newSite(t, false, &Policy{})
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/a%0Afake%20entry", strings.NewReader(""))
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("X-CSRF-Token", s.token)
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: s.cookie.Value})
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if resp.StatusCode != 403 || len(s.logs) != 1 || strings.Contains(s.logs[0], "\n") {
		t.Errorf("want one single-line log entry, got %d %q", resp.StatusCode, s.logs)
	}
}
