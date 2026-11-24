package logger

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readLogSoon(t *testing.T, path, want string) string {
	t.Helper()
	var s string
	for i := 0; i < 60; i++ {
		b, _ := os.ReadFile(path)
		if s = string(b); strings.Contains(s, want) {
			return s
		}
		time.Sleep(25 * time.Millisecond)
	}
	return s
}

// The ECH field is opt-in: without the hook (or with an empty answer) the request log line is the old one.
func TestRequestLogECHField(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("zr", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := DefaultSiteLogConfig()
	cfg.Rules["site.example"] = SiteLogAlso
	cfg.Format = "json"
	sites, _ := NewSiteLogs(dir, cfg)
	defer sites.Close()
	l.Sites = sites

	r := httptest.NewRequest("GET", "/old", nil)
	r.Header.Set("User-Agent", "ua/1")
	r.TLS = &tls.ConnectionState{ServerName: "site.example"}
	l.LogHTTPRequestSite("site.example", r, "host-http", 200, "site.example", "up", "192.0.2.7")
	g := readLogSoon(t, l.CurrentLogFile, "/old")
	if !strings.Contains(g, "[router:host-http] [origin:site.example] [client: 192.0.2.7] [useragent: ua/1] GET /old 200\n") || strings.Contains(g, "ech") {
		t.Fatalf("default line format changed:\n%s", g)
	}

	answer := "accepted outer=public.example"
	l.ECHField = func(*http.Request) string { return answer }
	r2 := httptest.NewRequest("GET", "/new", nil)
	r2.Header.Set("User-Agent", "ua/1")
	l.LogHTTPRequestSite("site.example", r2, "host-http", 200, "site.example", "up", "192.0.2.7")
	g = readLogSoon(t, l.CurrentLogFile, "/new")
	if !strings.Contains(g, "[useragent: ua/1] [ech: accepted outer=public.example] GET /new 200\n") {
		t.Fatalf("line with the ECH field:\n%s", g)
	}
	siteFile := filepath.Join(dir, "sites", "site.example", "site.example.log")
	s := readLogSoon(t, siteFile, "/new")
	if !strings.Contains(s, `"ech":"accepted outer=public.example"`) {
		t.Fatalf("site log (json) lacks the field:\n%s", s)
	}
	if first := strings.SplitN(s, "\n", 2)[0]; strings.Contains(first, `"ech"`) {
		t.Fatalf("the line written before the option must not carry the field: %s", first)
	}

	// an empty answer (plain HTTP request, option off) adds nothing; brackets and line breaks never get through
	answer = ""
	l.LogHTTPRequest(httptest.NewRequest("GET", "/empty", nil), "host-http", 200, "h", "", "192.0.2.7")
	if g = readLogSoon(t, l.CurrentLogFile, "/empty"); !strings.Contains(g, "[useragent: ] GET /empty 200\n") {
		t.Fatalf("empty answer:\n%s", g)
	}
	answer = "plain outer=a] [x\nb"
	l.LogHTTPRequest(httptest.NewRequest("GET", "/dirty", nil), "host-http", 200, "h", "", "192.0.2.7")
	if g = readLogSoon(t, l.CurrentLogFile, "/dirty"); !strings.Contains(g, "[ech: plain outer=a? ?x?b] GET /dirty 200\n") {
		t.Fatalf("sanitised answer:\n%s", g)
	}
	if (SiteLine{Method: "GET", URI: "/", Status: 200, ECH: "plain outer=-"}).FormatText() == (SiteLine{Method: "GET", URI: "/", Status: 200}).FormatText() {
		t.Fatal("text site lines must carry the field too")
	}
}
