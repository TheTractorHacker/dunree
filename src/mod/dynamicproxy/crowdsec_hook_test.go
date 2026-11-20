package dynamicproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/crowdsec"
)

const csTestKey = "hook-test-key-123456"

type csKV struct {
	mu sync.Mutex
	v  crowdsec.Settings
	ok bool
}

func (k *csKV) Read(t, key string, a interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.ok {
		return http.ErrMissingFile
	}
	*(a.(*crowdsec.Settings)) = k.v
	return nil
}
func (k *csKV) Write(t, key string, v interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.v, k.ok = v.(crowdsec.Settings), true
	return nil
}

func newCrowdSecRouter(t *testing.T, mode string, mod func(*crowdsec.Settings)) (*Router, *ProxyEndpoint, *crowdsec.Manager, *blocklog.Log) {
	t.Helper()
	router, sep, rule := newNonTLSTestRouter(t)
	rule.TrustProxyHeadersOnly = true
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != csTestKey {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte(`{"deleted":null,"new":[` +
			`{"id":1,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.9","duration":"1h","scenario":"crowdsecurity/ssh-bf"},` +
			`{"id":2,"origin":"CAPI","type":"ban","scope":"Range","value":"198.18.0.0/16","duration":"1h","scenario":"crowdsecurity/http-probing"},` +
			`{"id":3,"origin":"cscli","type":"ban","scope":"Ip","value":"2001:db8::bad","duration":"1h","scenario":"x"}]}`))
	}))
	t.Cleanup(lapi.Close)
	m, err := crowdsec.New(&csKV{}, crowdsec.NewVault(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := crowdsec.Settings{Enabled: true, LAPIURL: lapi.URL, Mode: mode}
	if mod != nil {
		mod(&s)
	}
	if err := m.Set(crowdsec.SetInput{Settings: s, APIKey: csTestKey, ConfirmFailClosed: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	router.Option.CrowdSec = m
	return router, sep, m, bl
}

func csSend(router *Router, sep *ProxyEndpoint, remote, xff string) int {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/x", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-IP", xff)
		r.Header.Set("CF-Connecting-IP", xff)
	}
	router.handleNonTLSRequest(w, r, sep)
	return w.Code
}

func TestCrowdSecEnforceBlocksAndLogs(t *testing.T) {
	router, sep, _, bl := newCrowdSecRouter(t, crowdsec.ModeEnforce, nil)
	if code := csSend(router, sep, "203.0.113.9:1000", ""); code != 403 {
		t.Fatalf("banned IP got %d", code)
	}
	if code := csSend(router, sep, "198.18.4.4:1000", ""); code != 403 {
		t.Fatalf("banned range member got %d", code)
	}
	if code := csSend(router, sep, "[2001:db8::bad]:1000", ""); code != 403 {
		t.Fatalf("banned IPv6 got %d", code)
	}
	if code := csSend(router, sep, "203.0.113.10:1000", ""); code != 299 {
		t.Fatalf("clean IP got %d", code)
	}
	items := waitBlocked(t, bl, 3)
	e := findBlocked(items, "203.0.113.9")
	if e == nil || e.Reason != blocklog.ReasonCrowdSec || !strings.Contains(e.Detail, "crowdsecurity/ssh-bf") {
		t.Fatalf("block log entry: %+v", e)
	}
	if !blocklog.IsBlocked("crowdsec") || !blocklog.IsBlocked("crowdsec-dropped") || !blocklog.IsBlocked("crowdsec-challenge") {
		t.Fatal("not classified as blocked")
	}
}

func TestCrowdSecLogOnlyNeverBlocks(t *testing.T) {
	router, sep, m, bl := newCrowdSecRouter(t, "", nil)
	for i := 0; i < 5; i++ {
		if code := csSend(router, sep, "203.0.113.9:1000", ""); code != 299 {
			t.Fatalf("log only mode blocked: %d", code)
		}
	}
	if st := m.Status(); st.LogOnly != 5 || st.Enforced != 0 {
		t.Fatalf("%+v", st)
	}
	if n := len(bl.List(blocklog.Filter{}, 0, 10).Items); n != 0 {
		t.Fatalf("log only wrote %d blocked entries", n)
	}
}

// Forwarded headers from a peer that is not a trusted proxy must neither frame a clean client nor hide a banned one.
func TestCrowdSecSpoofedHeaders(t *testing.T) {
	router, sep, _, _ := newCrowdSecRouter(t, crowdsec.ModeEnforce, nil)
	if code := csSend(router, sep, "192.0.2.50:1000", "203.0.113.9"); code != 299 {
		t.Fatalf("a clean client was refused because it sent a banned address in X-Forwarded-For: %d", code)
	}
	if code := csSend(router, sep, "203.0.113.9:1000", "192.0.2.50"); code != 403 {
		t.Fatalf("a banned client evaded the ban with a spoofed header: %d", code)
	}
	if code := csSend(router, sep, "203.0.113.9:1000", "203.0.113.10, 8.8.8.8"); code != 403 {
		t.Fatalf("chain spoof evaded the ban: %d", code)
	}
}

func TestCrowdSecExemptSiteAndOff(t *testing.T) {
	router, sep, m, _ := newCrowdSecRouter(t, crowdsec.ModeEnforce, func(s *crowdsec.Settings) { s.ExemptSites = []string{"app.example.com"} })
	if code := csSend(router, sep, "203.0.113.9:1000", ""); code != 299 {
		t.Fatalf("exempt site blocked: %d", code)
	}
	router, sep, m, _ = newCrowdSecRouter(t, crowdsec.ModeEnforce, nil)
	router.Option.CrowdSec = nil
	if code := csSend(router, sep, "203.0.113.9:1000", ""); code != 299 {
		t.Fatalf("nil manager changed behaviour: %d", code)
	}
	router.Option.CrowdSec = m
	s := m.Settings()
	s.Enabled = false
	if err := m.Set(crowdsec.SetInput{Settings: s}); err != nil {
		t.Fatal(err)
	}
	if code := csSend(router, sep, "203.0.113.9:1000", ""); code != 299 {
		t.Fatalf("disabled integration blocked: %d", code)
	}
}

func TestCrowdSecDropAndCaptchaWithoutSite(t *testing.T) {
	router, sep, _, _ := newCrowdSecRouter(t, crowdsec.ModeEnforce, func(s *crowdsec.Settings) { s.BanResponse = crowdsec.BanDrop })
	func() {
		defer func() {
			if rec := recover(); rec != http.ErrAbortHandler {
				t.Fatalf("drop mode did not abort the connection: %v", rec)
			}
		}()
		csSend(router, sep, "203.0.113.9:1000", "")
	}()
}

func TestCrowdSecFailClosedThroughRouter(t *testing.T) {
	router, sep, m, bl := newCrowdSecRouter(t, crowdsec.ModeEnforce, func(s *crowdsec.Settings) { s.FailClosed, s.GraceSeconds = true, 10 })
	if code := csSend(router, sep, "192.0.2.50:1000", ""); code != 299 {
		t.Fatalf("healthy LAPI: %d", code)
	}
	later := time.Now().Add(time.Hour) //no successful sync since: beyond the grace period
	m.SetClockForTest(func() time.Time { return later })
	if code := csSend(router, sep, "192.0.2.50:1000", ""); code != 403 {
		t.Fatalf("fail-closed did not refuse: %d", code)
	}
	if code := csSend(router, sep, "127.0.0.1:1000", ""); code != 299 {
		t.Fatalf("loopback refused: %d", code)
	}
	items := waitBlocked(t, bl, 1)
	if items[0].Reason != blocklog.ReasonCrowdSec || !strings.Contains(items[0].Detail, "fail-closed") {
		t.Fatalf("%+v", items[0])
	}
	s := m.Settings()
	s.FailClosed = false
	m.Set(crowdsec.SetInput{Settings: s})
	if code := csSend(router, sep, "192.0.2.50:1000", ""); code != 299 {
		t.Fatalf("fail-open refused: %d", code)
	}
}

func csSendHeaders(router *Router, sep *ProxyEndpoint, remote string, h map[string]string) int {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/x", nil)
	r.RemoteAddr = remote
	for k, v := range h {
		r.Header.Set(k, v)
	}
	router.handleNonTLSRequest(w, r, sep)
	return w.Code
}

// Behind a trusted proxy (Cloudflare does not strip a client-sent X-Real-Ip) a banned client must not hide
// behind a clean, loopback or protected address in a header.
func TestCrowdSecTrustedProxyHeaderSpoof(t *testing.T) {
	router, sep, m, _ := newCrowdSecRouter(t, crowdsec.ModeEnforce, nil)
	router.Option.AccessController.AddTrustedProxy("192.0.2.0/24", "cdn")
	m.Protect = func(a netip.Addr) bool { return a.String() == "198.51.100.1" }
	peer := "192.0.2.77:4000"
	cases := []struct {
		name string
		h    map[string]string
		want int
	}{
		{"real ban via CF header", map[string]string{"CF-Connecting-IP": "203.0.113.9"}, 403},
		{"ban hidden behind X-Real-Ip loopback", map[string]string{"X-Real-Ip": "127.0.0.1", "CF-Connecting-IP": "203.0.113.9"}, 403},
		{"ban hidden behind X-Real-Ip clean", map[string]string{"X-Real-Ip": "203.0.113.50", "CF-Connecting-IP": "203.0.113.9"}, 403},
		{"ban hidden behind protected address", map[string]string{"X-Real-Ip": "198.51.100.1", "CF-Connecting-IP": "203.0.113.9"}, 403},
		{"ban hidden behind ::1", map[string]string{"X-Real-Ip": "::1", "X-Forwarded-For": "203.0.113.9"}, 403},
		{"ban deeper in X-Forwarded-For", map[string]string{"X-Real-Ip": "203.0.113.50", "X-Forwarded-For": "10.0.0.1, 203.0.113.9"}, 403},
		{"banned range member", map[string]string{"X-Real-Ip": "127.0.0.1", "CF-Connecting-IP": "198.18.9.9"}, 403},
		{"clean client", map[string]string{"X-Real-Ip": "203.0.113.50", "CF-Connecting-IP": "203.0.113.50"}, 299},
		{"clean client claiming loopback", map[string]string{"X-Real-Ip": "127.0.0.1"}, 299},
		{"no headers, trusted peer itself", nil, 299},
	}
	for _, c := range cases {
		if got := csSendHeaders(router, sep, peer, c.h); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
	// an untrusted peer cannot use headers at all
	if got := csSendHeaders(router, sep, "203.0.113.9:1", map[string]string{"X-Real-Ip": "127.0.0.1"}); got != 403 {
		t.Errorf("untrusted banned peer with loopback header: %d", got)
	}
}
