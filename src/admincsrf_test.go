// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package main

import (
	"crypto/tls"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
)

// The advisory GO-2025-3607 (Referer and Origin never checked) is fixed in gorilla/csrf v1.7.3.
func TestGorillaCSRFVersionHasTheOriginCheck(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*github\.com/gorilla/csrf v(\d+)\.(\d+)\.(\d+)\b`).FindStringSubmatch(string(mod))
	if m == nil {
		t.Fatal("gorilla/csrf is not in go.mod")
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	if v := n(m[1])*1000000 + n(m[2])*1000 + n(m[3]); v < 1007003 {
		t.Fatalf("gorilla/csrf %s.%s.%s is older than v1.7.3 (GO-2025-3607)", m[1], m[2], m[3])
	}
	sum, _ := os.ReadFile("go.sum")
	if strings.Contains(string(sum), "github.com/gorilla/csrf v1.7.2") {
		t.Error("go.sum still lists gorilla/csrf v1.7.2")
	}
}

// Both switches are off by default: an install that is started as before gets no new setting.
func TestAdminCSRFSwitchDefaults(t *testing.T) {
	for name, want := range map[string]string{"csrf_trusted_origins": "", "csrf_strict": "false"} {
		f := flag.Lookup(name)
		if f == nil {
			t.Fatalf("switch -%s is missing", name)
		}
		if f.DefValue != want {
			t.Errorf("-%s default is %q, want %q", name, f.DefValue, want)
		}
	}
	if p := adminCSRFPolicy(); len(p.TrustedOrigins) != 0 || p.Strict {
		t.Errorf("default policy: %+v", p)
	}
}

// plainHTTPAdmin is for tests that put csrf.Protect in front of a handler themselves and send requests
// without Origin or Referer: it marks every request as plain HTTP, as mod/csrfguard does in the program
// for an admin interface without TLS. Without it gorilla/csrf v1.7.3 asks for an https Referer.
func plainHTTPAdmin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, csrf.PlaintextHTTPRequest(r)) })
}

type adminCSRFSite struct {
	srv    *httptest.Server
	host   string
	client *http.Client
	cookie *http.Cookie
	token  string
}

// newAdminCSRFSite serves newAdminCSRF (the middleware of main()) on a real listener.
func newAdminCSRFSite(t *testing.T, useTLS bool) *adminCSRFSite {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, csrf.Token(r))
			return
		}
		io.WriteString(w, "saved")
	})
	h := newAdminCSRF([]byte("0b0c9a1e-2222-4333-8444-555566667777"), useTLS)(mux)
	s := &adminCSRFSite{}
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
		if c.Name == CSRF_COOKIENAME {
			s.cookie = c
		}
	}
	if s.cookie == nil || s.token == "" {
		t.Fatalf("setup: no CSRF cookie or token")
	}
	if s.cookie.Secure != useTLS {
		t.Errorf("Secure flag of the CSRF cookie: %v, want %v", s.cookie.Secure, useTLS)
	}
	return s
}

func (s *adminCSRFSite) post(headers ...string) int {
	req, _ := http.NewRequest("POST", s.srv.URL+"/api/save", strings.NewReader("a=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", s.token)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], strings.ReplaceAll(headers[i+1], "{self}", s.host))
	}
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: s.cookie.Value})
	resp, err := s.client.Do(req)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}

// The admin middleware of main() with the default switches: what worked with gorilla/csrf v1.7.2 for an
// administrator still works, and a request from another site is refused although cookie and token match.
func TestAdminCSRFOriginCheckDefault(t *testing.T) {
	plain := newAdminCSRFSite(t, false)
	for _, c := range []struct {
		name    string
		headers []string
		want    int
	}{
		{"plain HTTP, browser", []string{"Origin", "http://{self}"}, 200},
		{"plain HTTP, script", nil, 200},
		{"plain HTTP, behind a TLS proxy that keeps the Host", []string{"Origin", "https://{self}"}, 200},
		{"plain HTTP, behind a proxy with X-Forwarded-Host", []string{"Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com"}, 200},
		{"plain HTTP, another site", []string{"Origin", "http://evil.example"}, 403},
		{"plain HTTP, another host without X-Forwarded-Host", []string{"Origin", "https://admin.example.com"}, 403},
	} {
		if got := plain.post(c.headers...); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	secure := newAdminCSRFSite(t, true)
	for _, c := range []struct {
		name    string
		headers []string
		want    int
	}{
		{"HTTPS, browser", []string{"Origin", "https://{self}"}, 200},
		{"HTTPS, script", nil, 200},
		{"HTTPS, another site", []string{"Origin", "https://evil.example"}, 403},
		{"HTTPS, Referer of another site and no Origin", []string{"Referer", "https://evil.example/"}, 403},
		{"HTTPS, http page of the own host", []string{"Origin", "http://{self}"}, 403},
	} {
		if got := secure.post(c.headers...); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

func TestAdminCSRFSwitches(t *testing.T) {
	oldTrusted, oldStrict := *csrfTrustedOrigins, *csrfStrict
	defer func() { *csrfTrustedOrigins, *csrfStrict = oldTrusted, oldStrict }()

	*csrfTrustedOrigins = "https://admin.example.com, panel.lan:8443"
	s := newAdminCSRFSite(t, false)
	if got := s.post("Origin", "https://admin.example.com"); got != 200 {
		t.Errorf("listed origin: %d", got)
	}
	if got := s.post("Origin", "https://panel.lan:8443"); got != 200 {
		t.Errorf("listed origin with port: %d", got)
	}
	if got := s.post("Origin", "https://evil.example"); got != 403 {
		t.Errorf("origin that is not listed: %d", got)
	}

	*csrfTrustedOrigins, *csrfStrict = "", true
	st := newAdminCSRFSite(t, true)
	if got := st.post(); got != 403 {
		t.Errorf("-csrf_strict, script without Referer over HTTPS: %d", got)
	}
	if got := st.post("Origin", "https://{self}"); got != 200 {
		t.Errorf("-csrf_strict, browser: %d", got)
	}
	sp := newAdminCSRFSite(t, false)
	if got := sp.post("Origin", "https://admin.example.com", "X-Forwarded-Host", "admin.example.com"); got != 403 {
		t.Errorf("-csrf_strict must ignore X-Forwarded-Host: %d", got)
	}
}
