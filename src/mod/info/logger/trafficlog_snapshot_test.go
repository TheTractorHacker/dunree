package logger

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The request log line is written by a goroutine while the proxy keeps working on the request (it rewrites and
// removes headers before forwarding). Everything the line needs must be read before LogHTTPRequest returns:
// reading r.Header later is a concurrent map read ("fatal error: concurrent map read and map write").
func TestLogHTTPRequestReadsRequestBeforeReturning(t *testing.T) {
	l, err := NewLogger("zr", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("GET", "/first", nil)
		r.Header.Set("User-Agent", "ua/first")
		l.LogHTTPRequest(r, "host-http", 200, "site.example", "up", "192.0.2.7")
		//what the proxy does next, on the same request
		r.Header.Set("User-Agent", "ua/later")
		r.Header.Del("X-Edge-Key")
		r.Method, r.RequestURI = "POST", "/later"
	}
	g := readLogSoon(t, l.CurrentLogFile, "never-there")
	if n := strings.Count(g, "[useragent: ua/first] GET /first 200\n"); n != 50 || strings.Contains(g, "later") {
		t.Fatalf("%d of 50 lines carry the request as it was when it was logged:\n%s", n, g)
	}
}
