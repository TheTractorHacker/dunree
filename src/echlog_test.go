package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/ech"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/tlscert"
)

func echPostForm(path string, v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// The request log option is off by default, is saved by the settings API and decides what echLogField answers.
func TestEchLogFieldOptIn(t *testing.T) {
	withEchMgr(t, true)
	oldLog := SystemWideLogger
	if SystemWideLogger == nil {
		SystemWideLogger, _ = logger.NewFmtLogger()
	}
	t.Cleanup(func() { SystemWideLogger = oldLog })

	plain := httptest.NewRequest("GET", "https://www.example.com/", nil)
	plain.TLS = &tls.ConnectionState{ServerName: "www.example.com"}
	if echMgr.Settings().LogRequests || echLogField(plain) != "" {
		t.Fatal("the request log option must be off by default and add nothing")
	}
	rec := httptest.NewRecorder()
	HandleEchSettings(rec, echPostForm("/api/ech/settings", url.Values{"logrequests": {"true"}}))
	if !strings.Contains(rec.Body.String(), "OK") {
		t.Fatalf("settings: %s", rec.Body.String())
	}
	s := echMgr.Settings()
	if !s.LogRequests || !s.Enabled || s.PublicName != "ech.example.test" {
		t.Fatalf("only the posted field may change: %+v", s)
	}
	if got := echLogField(plain); got != "plain outer=www.example.com" {
		t.Fatalf("plain: %q", got)
	}
	noSNI := httptest.NewRequest("GET", "https://192.0.2.1/", nil)
	noSNI.TLS = &tls.ConnectionState{}
	if got := echLogField(noSNI); got != "plain outer=-" {
		t.Fatalf("no SNI: %q", got)
	}
	acc := httptest.NewRequest("GET", "https://www.example.com/", nil)
	acc.TLS = &tls.ConnectionState{ServerName: "www.example.com", ECHAccepted: true}
	if got := echLogField(acc); got != "accepted" {
		t.Fatalf("accepted without a visible outer hello: %q", got)
	}
	if got := echLogField(httptest.NewRequest("GET", "http://www.example.com/", nil)); got != "" {
		t.Fatalf("plain HTTP requests get no field: %q", got)
	}

	// counters by outcome are part of the status
	echMgr.ObserveOutcome(true, false)
	echMgr.ObserveOutcome(false, true)
	echMgr.ObserveOutcome(false, false)
	echMgr.ObserveOutcome(false, false)
	rec = httptest.NewRecorder()
	HandleEchStatus(rec, httptest.NewRequest(http.MethodGet, "/api/ech/status", nil))
	var out struct {
		Settings    ech.Settings
		Outcomes    ech.Outcomes
		Accepted    uint64
		NotAccepted uint64
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Settings.LogRequests || out.Outcomes != (ech.Outcomes{Accepted: 1, Offered: 1, Plain: 2}) || out.Accepted != 1 || out.NotAccepted != 3 {
		t.Fatalf("status: %+v", out)
	}

	// with ECH and the log option both off nothing is counted
	withEchMgr(t, false)
	echMgr.ObserveOutcome(false, true)
	if o := echMgr.OutcomeStats(); o != (ech.Outcomes{}) {
		t.Fatalf("counted while off: %+v", o)
	}
	// the log option alone is enough (a foreign ECH config shows up even while ECH is off here)
	if err := echMgr.SetSettings(ech.Settings{LogRequests: true}); err != nil {
		t.Fatal(err)
	}
	echMgr.ObserveOutcome(false, true)
	if o := echMgr.OutcomeStats(); o.Offered != 1 {
		t.Fatalf("log option on: %+v", o)
	}
	// ... but the older Accepted / NotAccepted pair keeps its meaning: it counts only while ECH is enabled
	if a, p := echMgr.Stats(); a != 0 || p != 0 {
		t.Fatalf("legacy counters counted while ECH is off: %d %d", a, p)
	}
}

// The reject option: default off, admin only, stored in the settings table, never applied to a proxy rule's name.
func TestEchUnknownSNIOption(t *testing.T) {
	oldDB, oldLog, oldMgr, oldR, oldTab := sysdb, SystemWideLogger, tlsCertManager, dynamicProxyRouter, echFallbacks
	t.Cleanup(func() {
		sysdb, SystemWideLogger, tlsCertManager, dynamicProxyRouter, echFallbacks = oldDB, oldLog, oldMgr, oldR, oldTab
	})
	lg, _ := logger.NewFmtLogger()
	SystemWideLogger = lg
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.NewTable("settings")
	sysdb = db
	m, err := tlscert.NewManagerWithTmp(t.TempDir(), t.TempDir(), lg)
	if err != nil {
		t.Fatal(err)
	}
	tlsCertManager = m
	echFallbacks = ech.NewFallbackTable()
	dynamicProxyRouter = &dynamicproxy.Router{ProxyEndpoints: &sync.Map{}}
	dynamicProxyRouter.ProxyEndpoints.Store("app.example.com", &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "app.example.com"})
	m.IsKnownHost = tlsKnownHost
	m.OnUnknownRejected = echFallbackHook

	if auth.ViewerAllowed(http.MethodPost, "/api/ech/unknownsni") {
		t.Fatal("viewers must not change the option")
	}
	get := func() (out struct {
		Reject   bool
		Rejected uint64
	}) {
		rec := httptest.NewRecorder()
		HandleEchUnknownSNI(rec, httptest.NewRequest(http.MethodGet, "/api/ech/unknownsni", nil))
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err, rec.Body.String())
		}
		return
	}
	served := func(name string) bool {
		c, err := m.GetCert(&tls.ClientHelloInfo{ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		return c != nil
	}
	if get().Reject || !served("scanner.test") || !served("") {
		t.Fatal("default: off, unknown names get the fallback certificate")
	}
	rec := httptest.NewRecorder()
	HandleEchUnknownSNI(rec, echPostForm("/api/ech/unknownsni", url.Values{"reject": {"maybe"}}))
	if !strings.Contains(rec.Body.String(), "error") || get().Reject {
		t.Fatalf("a bad value must be refused: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	HandleEchUnknownSNI(rec, echPostForm("/api/ech/unknownsni", url.Values{"reject": {"true"}}))
	if !strings.Contains(rec.Body.String(), "OK") {
		t.Fatalf("enable: %s", rec.Body.String())
	}
	var stored bool
	if err := sysdb.Read("settings", rejectUnknownSNIKey, &stored); err != nil || !stored {
		t.Fatalf("not stored: %v %v", stored, err)
	}
	if served("scanner.test") || served("") {
		t.Fatal("unknown names must be refused")
	}
	if !served("app.example.com") {
		t.Fatal("the name of a proxy rule keeps its (fallback) certificate")
	}
	if g := get(); !g.Reject || g.Rejected != 2 {
		t.Fatalf("state: %+v", g)
	}
	// refused names stay visible in the diagnostics list, together with the state of the option
	rec = httptest.NewRecorder()
	HandleEchFallbacks(rec, httptest.NewRequest(http.MethodGet, "/api/ech/fallbacks", nil))
	var fb struct {
		Entries       []struct{ Name string }
		RejectUnknown bool
		Rejected      uint64
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &fb); err != nil {
		t.Fatal(err)
	}
	if !fb.RejectUnknown || fb.Rejected != 2 || len(fb.Entries) != 2 {
		t.Fatalf("fallbacks: %+v", fb)
	}
	// a rule keyed on an IP address: clients send no SNI for it, the local address of the connection decides
	dynamicProxyRouter.ProxyEndpoints.Store("192.0.2.7", &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "192.0.2.7"})
	dynamicProxyRouter.ProxyEndpoints.Store("[2001:db8::7]", &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "[2001:db8::7]"})
	servedOn := func(local string) bool {
		c, err := m.GetCert(&tls.ClientHelloInfo{Conn: localAddrConn{local: &net.TCPAddr{IP: net.ParseIP(local), Port: 443}}})
		if err != nil {
			t.Fatal(err)
		}
		return c != nil
	}
	if !servedOn("192.0.2.7") || !servedOn("2001:db8::7") {
		t.Fatal("a proxy rule for the IP address of the listener must keep working without SNI")
	}
	if servedOn("192.0.2.8") {
		t.Fatal("an IP address without a rule must still be refused")
	}
	rec = httptest.NewRecorder()
	HandleEchUnknownSNI(rec, echPostForm("/api/ech/unknownsni", url.Values{"reject": {"false"}}))
	if get().Reject || !served("scanner.test") {
		t.Fatal("switching off must restore the fallback certificate at once")
	}
}

type localAddrConn struct {
	net.Conn
	local net.Addr
}

func (c localAddrConn) LocalAddr() net.Addr { return c.local }
