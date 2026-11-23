package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/ruleset"
	"imuslab.com/zoraxy/mod/statistic"
)

const statTestChrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

func newStatSourceCollector(t *testing.T) *statistic.Collector {
	t.Helper()
	db, err := database.NewDatabase(t.TempDir()+"/db", dbinc.BackendLevelDB)
	if err != nil {
		t.Fatal(err)
	}
	c, err := statistic.NewStatisticCollector(statistic.CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitStatTotal(t *testing.T, c *statistic.Collector, want int64) *statistic.DailySummaryExport {
	t.Helper()
	for i := 0; i < 400; i++ {
		if c.GetExportSummary().TotalRequest >= want {
			time.Sleep(40 * time.Millisecond) //let the record goroutines finish their maps
			return c.GetExportSummary()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d of %d requests were recorded", c.GetExportSummary().TotalRequest, want)
	return nil
}

// Every request that reaches the statistics has a referrer key: the header when sent, the reason when not.
// Blocked requests and WebSocket upgrades are recorded like any other.
func TestStatisticsReferrerKeyForEveryRequest(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	c := newStatSourceCollector(t)
	router.Option.StatisticCollector = c

	do := func(hdr map[string]string, code int, forwardType string) {
		r := httptest.NewRequest("GET", "http://app.example.com/page", nil)
		r.RemoteAddr = "198.51.100.9:4000"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		router.logRequest(r, code < 400, code, forwardType, "app.example.com", "up", sep)
	}
	do(map[string]string{"Referer": "https://news.example/story", "User-Agent": statTestChrome, "Sec-Fetch-Site": "cross-site"}, 200, "host-http")
	do(map[string]string{"User-Agent": statTestChrome, "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"}, 200, "host-http")
	do(map[string]string{"User-Agent": statTestChrome, "Sec-Fetch-Site": "cross-site"}, 403, "blacklist")       //blocked
	do(map[string]string{"User-Agent": statTestChrome, "Sec-Fetch-Site": "same-origin"}, 101, "host-websocket") //WebSocket
	do(map[string]string{"User-Agent": "curl/8.5.0"}, 200, "static-response")
	do(map[string]string{"User-Agent": statTestChrome, "Origin": "https://shop.example"}, 200, "host-http")
	do(map[string]string{"User-Agent": statTestChrome, "Origin": "https://app.example.com"}, 200, "host-http")
	do(map[string]string{"User-Agent": statTestChrome, "Origin": `https://x.example"><script>`}, 200, "host-http")

	got := waitStatTotal(t, c, 8).Referer
	want := map[string]int{
		"https://news.example/story":   1,
		statistic.RefererDirect:        1,
		statistic.RefererHiddenPolicy:  1,
		statistic.RefererSameSite:      2,
		statistic.RefererNonBrowser:    1,
		"~origin:https://shop.example": 1,
		statistic.RefererUnknown:       1,
	}
	if _, has := got[""]; has {
		t.Errorf("requests are still counted under the empty key: %v", got)
	}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%q = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if site := c.GetSiteExport("app.example.com"); site == nil || site.Referer[statistic.RefererDirect] != 1 || site.Referer["https://news.example/story"] != 1 {
		t.Errorf("per-site referrers: %+v", site)
	}
}

// A rule that removes or replaces the Referer (or the headers used to explain a missing one) on the way to the
// upstream must not change what the statistics record: they show what the client sent.
func TestRuleHeaderActionsDoNotHideTheReferrer(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	c := newStatSourceCollector(t)
	router.Option.StatisticCollector = c
	var upstream http.Header
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, s *ProxyEndpoint) bool {
		upstream = r.Header.Clone()
		w.WriteHeader(okCode)
		router.logRequest(r, true, okCode, "host-http", "app.example.com", "up", s)
		return true
	}
	addRule(t, eng, "", "strip referer", `http.path == "/strip"`, ruleset.Action{Type: ruleset.ActDelReqH, Name: "referer"})
	addRule(t, eng, "", "strip ua", `http.path == "/strip"`, ruleset.Action{Type: ruleset.ActSetReqH, Name: "User-Agent", Value: "rewritten"})
	addRule(t, eng, "", "strip fetch site", `http.path == "/direct"`, ruleset.Action{Type: ruleset.ActDelReqH, Name: "Sec-Fetch-Site"})
	addRule(t, eng, "", "fake referer", `http.path == "/direct"`, ruleset.Action{Type: ruleset.ActSetReqH, Name: "Referer", Value: "https://made-up.example/"})

	rsGet(router, sep, "http://app.example.com/strip", rsIPA, map[string]string{"Referer": "https://news.example/story", "User-Agent": statTestChrome})
	if upstream.Get("Referer") != "" || upstream.Get("User-Agent") != "rewritten" {
		t.Fatalf("the rule must still act on what the upstream receives: %v", upstream)
	}
	rsGet(router, sep, "http://app.example.com/direct", rsIPA, map[string]string{"Sec-Fetch-Site": "none", "User-Agent": statTestChrome})
	if upstream.Get("Referer") != "https://made-up.example/" {
		t.Fatalf("the rule must still act on what the upstream receives: %v", upstream)
	}

	s := waitStatTotal(t, c, 2)
	if s.Referer["https://news.example/story"] != 1 || s.Referer[statistic.RefererDirect] != 1 || len(s.Referer) != 2 {
		t.Errorf("referrers changed by a header rule: %v", s.Referer)
	}
	if s.UserAgent[statTestChrome] != 2 || len(s.UserAgent) != 1 {
		t.Errorf("user agents changed by a header rule: %v", s.UserAgent)
	}
}

func TestKeepStatSourceOnlyForStatisticsHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.Header.Set("Referer", "https://a.example/")
	keepStatSource(r, "X-Other")
	if r.Context().Value(statSourceKey{}) != nil {
		t.Fatal("a copy was taken for a header the statistics do not read")
	}
	keepStatSource(r, "sec-fetch-site")
	r.Header.Del("Referer")
	keepStatSource(r, "Referer") //second call must not overwrite the first copy
	if got := statSourceOf(r).Referer; got != "https://a.example/" {
		t.Fatalf("got %q", got)
	}
	keepStatSource(nil, "Referer")
}

// Through the real proxy path: hostRequest rewrites r.Host before the request is logged, which must not change the
// classification, and a request whose upstream is down is counted once (it used to be counted twice: as the error
// and again as a success).
func TestStatisticsThroughProxyCountOnceWithReferrer(t *testing.T) {
	serve := func(h *ProxyHandler, hdr map[string]string) int {
		r := httptest.NewRequest("GET", "http://waf.test/page", nil)
		r.RemoteAddr = "198.51.100.9:4000"
		r.Header.Set("User-Agent", statTestChrome)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	h, hits, _ := newCentralWAFTestProxy(t, nil, nil)
	c := newStatSourceCollector(t)
	h.Parent.Option.StatisticCollector = c
	if code := serve(h, map[string]string{"Origin": "http://waf.test"}); code != 200 || *hits != 1 {
		t.Fatalf("live upstream: %d, %d hits", code, *hits)
	}
	serve(h, map[string]string{"Referer": "https://news.example/story"})
	s := waitStatTotal(t, c, 2)
	if s.TotalRequest != 2 || s.Referer[statistic.RefererSameSite] != 1 || s.Referer["https://news.example/story"] != 1 || len(s.Referer) != 2 {
		t.Errorf("live upstream: total %d, referrers %v", s.TotalRequest, s.Referer)
	}

	down, _, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) {
		ep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: "127.0.0.1:1"}}
	})
	c2 := newStatSourceCollector(t)
	down.Parent.Option.StatisticCollector = c2
	if code := serve(down, map[string]string{"Sec-Fetch-Site": "none"}); code < 500 {
		t.Fatalf("dead upstream answered %d", code)
	}
	time.Sleep(150 * time.Millisecond) //a second record of the same request would arrive now
	s = waitStatTotal(t, c2, 1)
	if s.TotalRequest != 1 || s.ErrorRequest != 1 || s.ValidRequest != 0 || s.Referer[statistic.RefererDirect] != 1 || len(s.Referer) != 1 {
		t.Errorf("dead upstream: total %d, errors %d, valid %d, referrers %v", s.TotalRequest, s.ErrorRequest, s.ValidRequest, s.Referer)
	}
}
