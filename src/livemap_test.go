package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	db "imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func lsample(at time.Time, total int64, down, up int64) liveSample {
	return liveSample{at: at, total: total, errors: total / 10, down: map[string]int64{"a.test": down}, up: map[string]int64{"10.0.0.1:80": up}}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestLiveRatesFirstPollIsWarmup(t *testing.T) {
	var r liveRates
	t0 := time.Unix(1000, 0)
	rs := r.push(lsample(t0, 500, 500, 500))
	if !rs.Warmup || rs.Total != 0 || rs.Down["a.test"] != 0 {
		t.Fatalf("first poll must be warmup with zero rates: %+v", rs)
	}
	// a second sample 0.1 s later is still too close to give a rate
	if rs := r.push(lsample(t0.Add(100*time.Millisecond), 600, 600, 600)); !rs.Warmup {
		t.Fatalf("a sample closer than %v must stay warmup", liveMinElapsed)
	}
}

func TestLiveRatesSteadyAndIdle(t *testing.T) {
	var r liveRates
	t0 := time.Unix(1000, 0)
	r.push(lsample(t0, 0, 0, 0))
	// 20 req/s for 4 s
	rs := r.push(lsample(t0.Add(4*time.Second), 80, 80, 40))
	if rs.Warmup || !near(rs.Total, 20) || !near(rs.Down["a.test"], 20) || !near(rs.Up["10.0.0.1:80"], 10) {
		t.Fatalf("expected 20 / 20 / 10 req/s, got %+v", rs)
	}
	if !near(rs.Errors, 2) {
		t.Fatalf("errors per second: %v", rs.Errors)
	}
	// no traffic for 12 s: the old burst must have left the window, the rate falls to 0
	r.push(lsample(t0.Add(8*time.Second), 80, 80, 40))
	rs = r.push(lsample(t0.Add(20*time.Second), 80, 80, 40))
	if rs.Total != 0 || rs.Down["a.test"] != 0 {
		t.Fatalf("an idle window must give 0 req/s: %+v", rs)
	}
}

func TestLiveRatesWindowUsesRecentBase(t *testing.T) {
	var r liveRates
	t0 := time.Unix(1000, 0)
	for i := 0; i <= 20; i++ { // 10 req/s for 20 s, then reading at +21 s with no new traffic
		r.push(lsample(t0.Add(time.Duration(i)*time.Second), int64(i*10), int64(i*10), int64(i*10)))
	}
	rs := r.push(lsample(t0.Add(30*time.Second), 200, 200, 200))
	// the window is the last ~10 s: base is the sample at +20 s (no traffic since)
	if rs.Total != 0 {
		t.Fatalf("the rate must be over the recent window, got %v", rs.Total)
	}
	if rs.Window > 10.5 {
		t.Fatalf("window %v s is longer than the ~10 s target", rs.Window)
	}
}

func TestLiveRatesCounterReset(t *testing.T) {
	var r liveRates
	t0 := time.Unix(1000, 0)
	r.push(lsample(t0, 1000, 1000, 1000))
	// midnight: the counters start again from a small number
	rs := r.push(lsample(t0.Add(2*time.Second), 6, 6, 6))
	if rs.Total < 0 || rs.Down["a.test"] < 0 || rs.Up["10.0.0.1:80"] < 0 || rs.Errors < 0 {
		t.Fatalf("negative rate after a reset: %+v", rs)
	}
	if rs.Total != 0 {
		t.Fatalf("a reset reads as no traffic: %+v", rs)
	}
	// the next reading works against the post-reset sample, not the pre-reset one
	rs = r.push(lsample(t0.Add(4*time.Second), 26, 26, 26))
	if !near(rs.Total, 10) {
		t.Fatalf("after the reset the rate must recover (want 10, got %v)", rs.Total)
	}
	// a single key that went down (a rule that was renamed and re-added) is 0 too
	s := lsample(t0.Add(6*time.Second), 46, 46, 46)
	s.down["a.test"] = 0
	if rs = r.push(s); rs.Down["a.test"] != 0 || rs.Total <= 0 {
		t.Fatalf("per key reset: %+v", rs)
	}
}

func TestLiveRatesStaleBaseIgnored(t *testing.T) {
	var r liveRates
	t0 := time.Unix(1000, 0)
	r.push(lsample(t0, 0, 0, 0))
	// the viewer came back after 5 minutes: the old sample must not be used (would average a burst away)
	rs := r.push(lsample(t0.Add(5*time.Minute), 9000, 9000, 9000))
	if !rs.Warmup || rs.Total != 0 {
		t.Fatalf("a stale base must give warmup, got %+v", rs)
	}
	// clock going backwards is also ignored
	rs = r.push(lsample(t0.Add(4*time.Minute), 9100, 9100, 9100))
	if !rs.Warmup {
		t.Fatalf("a sample from the past must not be a base: %+v", rs)
	}
}

func TestLiveMapCache(t *testing.T) {
	var r liveRates
	reads := 0
	total := int64(0)
	read := func(now time.Time) (liveSample, []*LiveMapProxy) {
		reads++
		total += 10
		s := liveSample{at: now, total: total, down: map[string]int64{"a.test": total}, up: map[string]int64{"o:1": total}}
		return s, []*LiveMapProxy{{Domain: "a.test", Upstreams: []*LiveMapUpstream{{Origin: "o:1", InFlight: 3}}}}
	}
	t0 := time.Unix(2000, 0)
	b1 := r.get(t0, read)
	b2 := r.get(t0.Add(300*time.Millisecond), read)
	b3 := r.get(t0.Add(900*time.Millisecond), read)
	if reads != 1 || string(b1) != string(b2) || string(b1) != string(b3) {
		t.Fatalf("polls inside the cache time must share one sample: reads=%d", reads)
	}
	var first LiveMapData
	json.Unmarshal(b1, &first)
	if !first.Warmup || first.TotalInFlight != 3 || first.Proxies[0].InFlight != 3 {
		t.Fatalf("first answer: %+v", first)
	}
	b4 := r.get(t0.Add(2*time.Second), read)
	if reads != 2 {
		t.Fatalf("an expired cache must sample again: reads=%d", reads)
	}
	var second LiveMapData
	json.Unmarshal(b4, &second)
	if second.Warmup || !near(second.TotalRps, 5) || !near(second.Proxies[0].Rps, 5) || !near(second.Proxies[0].Upstreams[0].Rps, 5) {
		t.Fatalf("second answer should be 5 req/s: %+v", second)
	}
}

// The endpoint needs a session: an anonymous request gets no data, a viewer and an admin get the JSON.
func TestLiveMapEndpointPermission(t *testing.T) {
	CONF_FOLDER = t.TempDir()
	sysdb, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sysdb.Close()
	lg, _ := logger.NewFmtLogger()
	old := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	defer func() { auth.ProfileAdmin = old }()
	authAgent = auth.NewAuthenticationAgent("t", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "login required", http.StatusUnauthorized) })
	authAgent.CreateUserAccount("root", "password-1", "")
	authAgent.CreateUser("view", "password-2", auth.RoleViewer)

	mux := http.NewServeMux()
	rt := auth.NewManagedHTTPRouter(auth.RouterOption{AuthAgent: authAgent, RequireAuth: true, TargetMux: mux})
	RegisterStatisticalAPIs(rt)
	found := false
	for _, ep := range rt.Endpoints() {
		found = found || ep == "/api/stats/livemap"
	}
	if !found {
		t.Fatal("/api/stats/livemap is not registered on the authenticated router")
	}

	anon := httptest.NewRecorder()
	mux.ServeHTTP(anon, httptest.NewRequest("GET", "/api/stats/livemap", nil))
	if anon.Code == http.StatusOK && strings.Contains(anon.Body.String(), "totalRps") {
		t.Fatalf("an anonymous request got the live data (status %d)", anon.Code)
	}

	login := func(user, pw string) *http.Cookie {
		form := url.Values{"username": {user}, "password": {pw}}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authAgent.HandleLogin(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == authAgent.SessionName && c.Value != "" {
				return c
			}
		}
		t.Fatal("login failed for " + user)
		return nil
	}
	for _, user := range []struct{ n, p string }{{"root", "password-1"}, {"view", "password-2"}} {
		liveMapRates = liveRates{}
		r := httptest.NewRequest("GET", "/api/stats/livemap", nil)
		r.AddCookie(login(user.n, user.p))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var d LiveMapData
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &d) != nil || !d.Warmup || d.Proxies == nil {
			t.Fatalf("%s GET: status %d body %s", user.n, w.Code, w.Body.String())
		}
	}
	// the endpoint is read-only: a viewer may not POST to it (the role guard)
	r := httptest.NewRequest("POST", "/api/stats/livemap", strings.NewReader("a=b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(login("view", "password-2"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST must be refused, got %d", w.Code)
	}
}

func TestLiveRatesPerRuleErrors(t *testing.T) {
	var r liveRates
	t0 := time.Unix(1000, 0)
	mk := func(at time.Time, total, down, errs int64) liveSample {
		return liveSample{at: at, total: total, down: map[string]int64{"a.test": down}, downErr: map[string]int64{"a.test": errs}, up: map[string]int64{}}
	}
	r.push(mk(t0, 100, 100, 5))
	rs := r.push(mk(t0.Add(5*time.Second), 200, 200, 25)) // 100 requests, 20 of them errors in 5 s
	if !near(rs.Down["a.test"], 20) || !near(rs.DownErr["a.test"], 4) {
		t.Fatalf("rule rate %v errors %v, want 20 and 4 per second", rs.Down["a.test"], rs.DownErr["a.test"])
	}
	// a rule without errors yet has no entry: its error rate is 0, never negative or missing a key lookup
	rs = r.push(mk(t0.Add(10*time.Second), 300, 300, 25))
	if rs.DownErr["a.test"] < 0 {
		t.Fatalf("negative error rate %v", rs.DownErr["a.test"])
	}
}
