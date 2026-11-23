package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// decO is dec with an origin and a scenario
func decO(id int, typ, scope, value, origin, scenario string) string {
	return fmt.Sprintf(`{"id":%d,"origin":%q,"type":%q,"scope":%q,"value":%q,"duration":"4h","scenario":%q}`, id, origin, typ, scope, value, scenario)
}

func mixed() string {
	return stream([]string{
		decO(1, "ban", "Ip", "203.0.113.1", "crowdsec", "crowdsecurity/http-probing"),
		decO(2, "ban", "Ip", "203.0.113.2", "cscli", "manual ban"),
		decO(3, "ban", "Ip", "203.0.113.3", "CAPI", "crowdsecurity/ssh-bf"),
		decO(4, "ban", "Range", "198.18.0.0/16", "lists:firehol", "firehol_level1"),
		decO(5, "captcha", "Ip", "203.0.113.5", "crowdsec", "crowdsecurity/http-crawl-non_statics"),
		decO(6, "ban", "Ip", "203.0.113.6", "console", "from the console"),
	}, nil)
}

func setupMixed(t *testing.T, mutate func(*Settings)) *tm {
	t.Helper()
	x := setup(t, mutate)
	x.f.startup = mixed()
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *tm) set(t *testing.T, f func(*Settings)) {
	t.Helper()
	s := x.m.Settings()
	f(&s)
	if err := x.m.Set(SetInput{Settings: s, ConfirmFailClosed: true}); err != nil {
		t.Fatal(err)
	}
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
}

// Check alone must not count or list anything: only what the request path reports is shown.
func TestCheckHasNoSideEffectsReportCountsRealOutcome(t *testing.T) {
	x := setupMixed(t, func(s *Settings) { s.CaptchaAction = CaptchaChallenge })
	v := x.m.Check(netip.MustParseAddr("203.0.113.5"), "site")
	if !v.Matched || v.Action != ActionCaptcha || !v.Enforce {
		t.Fatalf("%+v", v)
	}
	st := x.m.Status()
	if st.Enforced != 0 || st.LogOnly != 0 || st.Checked != 1 || x.m.Feed(FeedQuery{}).Total != 0 {
		t.Fatalf("Check counted an outcome before the request path knew it: %+v", st)
	}
	// every outcome, once
	for i, o := range Outcomes {
		vv := v
		vv.IP = netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", 100+i)) //a different visitor each: no merging
		if o == OutAllowlisted || o == OutExempt {
			vv.Matched, vv.Skip = false, map[Outcome]string{OutAllowlisted: SkipAllowlist, OutExempt: SkipSiteExempt}[o]
		}
		x.m.Report(vv, o, Event{Host: "app.example.com", Method: "GET", Path: "/x", Country: "de"})
	}
	st = x.m.Status()
	// stopped: blocked, dropped, challenged. fail-closed has its own counter. Everything else was served.
	if st.Enforced != 3 || st.FailClosedBlocks != 1 || st.LogOnly != 1 {
		t.Fatalf("enforced %d fail-closed %d log only %d", st.Enforced, st.FailClosedBlocks, st.LogOnly)
	}
	want := Counts{Checked: 1, Blocked: 2, WouldBlock: 1, Challenged: 1, Passed: 1, NotChallenged: 2, Allowlisted: 1, Exempt: 1, FailClosed: 1}
	if st.Today != want {
		t.Fatalf("today %+v, want %+v", st.Today, want)
	}
	// the bug this replaces: a captcha decision on a site without CAPTCHA is served, so it must never count as blocked
	before := x.m.Status().Enforced
	x.m.Report(v, OutNoCaptcha, Event{})
	x.m.Report(v, OutPassed, Event{})
	x.m.Report(v, OutSkipped, Event{})
	if x.m.Status().Enforced != before {
		t.Fatal("a served captcha decision counted as blocked")
	}
	// nothing and no outcome: ignored
	x.m.Report(Verdict{}, OutBlocked, Event{})
	x.m.Report(v, "", Event{})
	if got := x.m.Feed(FeedQuery{Limit: 200}).Total; got != len(Outcomes)+3 {
		t.Fatalf("feed has %d entries", got)
	}
	// the older matches list holds only what was acted on or would have been
	_, matches := x.m.Decisions(100)
	for _, mt := range matches {
		if !mt.Enforced && mt.Action == "" {
			t.Fatalf("%+v", mt)
		}
	}
	if len(matches) != 5 {
		t.Fatalf("matches %d: %+v", len(matches), matches)
	}
}

func TestFeedFieldsDedupFilterPaging(t *testing.T) {
	x := setupMixed(t, func(s *Settings) { s.Mode = ModeLog })
	for i := 0; i < 3; i++ {
		v := x.m.Check(netip.MustParseAddr("203.0.113.1"), "App.Example.com")
		x.m.Report(v, v.DefaultOutcome(), Event{Host: "app.example.com:443", Method: "GET", Path: fmt.Sprintf("/wp-login.php?try=%d&password=hunter2", i), Country: "de"})
		x.advance(time.Second)
	}
	p := x.m.Feed(FeedQuery{})
	if len(p.Entries) != 1 {
		t.Fatalf("repeats of one visitor must be one entry: %+v", p.Entries)
	}
	e := p.Entries[0]
	if e.Count != 3 || e.Outcome != OutLogOnly || e.Enforced || e.Why != WhyMode || e.IP != "203.0.113.1" || e.Country != "DE" || e.Rule != "app.example.com" ||
		e.Method != "GET" || e.Path != "/wp-login.php" || e.Origin != "crowdsec" || e.Scenario != "crowdsecurity/http-probing" || e.Type != "ban" ||
		e.Value != "203.0.113.1" || e.Expires == nil || !e.First.Before(e.Time) {
		t.Fatalf("%+v", e)
	}
	js, _ := json.Marshal(p)
	if strings.Contains(string(js), "hunter2") || strings.Contains(string(js), "try=") {
		t.Fatalf("the query string of a request is in the feed: %s", js)
	}
	// more visitors, to page and filter
	for i := 0; i < 30; i++ {
		v := x.m.Check(netip.MustParseAddr(fmt.Sprintf("198.18.0.%d", i+1)), "shop.example.com")
		x.m.Report(v, v.DefaultOutcome(), Event{Host: "shop.example.com", Method: "POST", Path: "/cart", Country: "FR"})
		x.advance(time.Second)
	}
	p = x.m.Feed(FeedQuery{})
	if len(p.Entries) != 25 || !p.More || p.Total != 31 || p.Entries[0].IP != "198.18.0.30" {
		t.Fatalf("first page: %d more=%v total=%d first=%s", len(p.Entries), p.More, p.Total, p.Entries[0].IP)
	}
	p2 := x.m.Feed(FeedQuery{Before: p.Entries[24].Time})
	if len(p2.Entries) != 6 || p2.More || p2.Entries[5].IP != "203.0.113.1" {
		t.Fatalf("second page: %d %+v", len(p2.Entries), p2.More)
	}
	for q, n := range map[FeedQuery]int{{IP: "203.0.113.1"}: 1, {Q: "FIREHOL"}: 25, {Q: "wp-login"}: 1, {Outcome: "log-only", Limit: 200}: 31,
		{Outcome: "enforced"}: 0, {Outcome: "served", Limit: 200}: 31, {Outcome: "blocked"}: 0, {Q: "nothing-like-this"}: 0, {Limit: 5}: 5} {
		if got := len(x.m.Feed(q).Entries); got != n {
			t.Errorf("%+v: %d entries, want %d", q, got, n)
		}
	}
	// bounded
	for i := 0; i < feedSize+50; i++ {
		v := Verdict{Matched: true, Action: ActionBan, IP: netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), Site: "s", Decision: Decision{Type: "ban", Value: "v"}}
		x.m.Report(v, OutLogOnly, Event{})
	}
	if got := x.m.Feed(FeedQuery{Limit: 200}).Total; got != feedSize {
		t.Fatalf("feed holds %d entries, bound is %d", got, feedSize)
	}
}

func TestHourlyRingRolloverAndExpiry(t *testing.T) {
	x := setupMixed(t, nil) //the clock starts 2026-01-01 12:00 UTC
	hit := func(n int) {
		for i := 0; i < n; i++ {
			x.check("203.0.113.1")
		}
	}
	clean := func(n int) {
		for i := 0; i < n; i++ {
			x.check("192.0.2.200")
		}
	}
	reload := func() { //the test decisions last 4 hours: load them again after the clock moved further
		t.Helper()
		x.m.resync.Store(true)
		if err := x.pull(t); err != nil {
			t.Fatal(err)
		}
	}
	hit(2)
	clean(5)
	x.advance(time.Hour) //13:00
	hit(1)
	clean(1)
	a := x.m.Activity("24h")
	if len(a.Series) != 24 || a.Series[23].T != x.clock.Unix()/3600*3600 || a.Series[23].Hours != 1 {
		t.Fatalf("series: %d points, last %+v", len(a.Series), a.Series[23])
	}
	if got := a.Series[22].Counts; got.Checked != 7 || got.Blocked != 2 {
		t.Fatalf("previous hour %+v", got)
	}
	if got := a.Series[23].Counts; got.Checked != 2 || got.Blocked != 1 {
		t.Fatalf("this hour %+v", got)
	}
	if a.Total.Checked != 9 || a.Total.Blocked != 3 || a.Today.Blocked != 3 {
		t.Fatalf("totals %+v today %+v", a.Total, a.Today)
	}
	// a new day: "today" starts again, the 7 day window still has everything
	x.advance(24 * time.Hour)
	reload()
	hit(1)
	if got := x.m.Today(); got.Blocked != 1 || got.Checked != 1 {
		t.Fatalf("today after midnight %+v", got)
	}
	if got := x.m.Activity("24h").Total; got.Blocked != 1 { //24 hourly bars, this hour included: 13:00 yesterday has just left the window
		t.Fatalf("24 h window %+v", got)
	}
	w := x.m.Activity("7d")
	if len(w.Series) != 28 || w.Series[0].Hours != 6 || w.Total.Blocked != 4 || w.Total.Checked != 10 {
		t.Fatalf("7 d: %d points, %+v", len(w.Series), w.Total)
	}
	// after 7 days the old hours are gone, also when nothing happened in between (no request rolled the ring)
	x.advance(8 * 24 * time.Hour)
	if got := x.m.Activity("7d").Total; got != (Counts{}) {
		t.Fatalf("counters older than 7 days are still shown: %+v", got)
	}
	reload()
	hit(1)
	if got := x.m.Activity("7d").Total; got.Blocked != 1 || got.Checked != 1 {
		t.Fatalf("%+v", got)
	}
	// switching CrowdSec off forgets it all
	x.set(t, func(s *Settings) { s.Enabled = false })
	if got := x.m.Activity("7d"); got.Total != (Counts{}) || got.FeedSize != 0 || len(got.Pulls) != 0 {
		t.Fatalf("not reset: %+v", got.Total)
	}
}

func TestTopListsBoundedWithOther(t *testing.T) {
	x := setupMixed(t, nil)
	for i := 0; i < topKeys+20; i++ {
		v := Verdict{Matched: true, Action: ActionBan, Enforce: i%2 == 0, IP: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), Site: "s",
			Decision: Decision{Type: "ban", Origin: "CAPI", Scenario: fmt.Sprintf("scenario-%03d", i), Value: "v"}}
		x.m.Report(v, v.DefaultOutcome(), Event{Country: "US"})
	}
	for i := 0; i < 5; i++ {
		x.check("203.0.113.1")
	}
	a := x.m.Activity("24h")
	sc := a.Tops["scenarios"]
	if len(sc) != topN {
		t.Fatalf("%d scenarios listed", len(sc))
	}
	// 32 distinct keys are kept per hour, the 25 others are summed
	if sc[0].Key != "other" || sc[0].Enforced+sc[0].LogOnly != 25 {
		t.Fatalf("first %+v", sc[0])
	}
	var hb *hourBucket
	x.m.mu.Lock()
	hb = x.m.st.bucket(x.clock.Unix() / 3600)
	n := len(hb.tops[dimScenario])
	x.m.mu.Unlock()
	if n > topKeys+1 {
		t.Fatalf("%d keys kept, bound is %d plus other", n, topKeys)
	}
	if o := a.Tops["origins"]; len(o) != 2 || o[0].Key != "capi" || o[0].Enforced != 26 || o[0].LogOnly != 26 || o[1].Key != "crowdsec" || o[1].Enforced != 5 {
		t.Fatalf("origins %+v", o)
	}
	if c := a.Tops["countries"]; len(c) != 2 || c[0].Key != "US" {
		t.Fatalf("countries %+v", c)
	}
	if s := a.Tops["sites"]; len(s) != 2 {
		t.Fatalf("sites %+v", s)
	}
	if len(a.Tops["addresses"]) != topN {
		t.Fatalf("addresses %+v", a.Tops["addresses"])
	}
}

func TestLookupAllOverlappingRanges(t *testing.T) {
	c := NewCache(100)
	now := time.Now()
	exp := now.Add(time.Hour)
	for i, d := range []Decision{
		{Type: "ban", Scope: "ip", Value: "198.18.5.5"},
		{Type: "captcha", Scope: "range", Value: "198.18.0.0/16"},
		{Type: "ban", Scope: "range", Value: "198.18.5.0/24"},
		{Type: "ban", Scope: "range", Value: "198.19.0.0/16"},
		{Type: "ban", Scope: "ip", Value: "198.18.5.6"},
	} {
		d.ID, d.Expires = int64(i+1), exp
		if c.Add(d) != addOK {
			t.Fatal(d)
		}
	}
	c.Add(Decision{ID: 9, Type: "ban", Scope: "range", Value: "198.18.5.0/25", Expires: now.Add(-time.Second)}) //expired
	got := c.LookupAll(netip.MustParseAddr("198.18.5.5"), now)
	ids := ""
	for _, d := range got {
		ids += fmt.Sprint(d.ID)
	}
	if ids != "123" {
		t.Fatalf("exact match, then the ranges from wide to narrow, expired ones skipped: got %s", ids)
	}
	if len(c.LookupAll(netip.MustParseAddr("192.0.2.1"), now)) != 0 {
		t.Fatal("unrelated address matched")
	}
	if len(c.LookupAll(netip.MustParseAddr("::ffff:198.18.5.6"), now)) != 3 {
		t.Fatal("IPv4-mapped address")
	}
}

func TestPolicyMatrix(t *testing.T) {
	const (
		own, manual, capi, list, cap, console = "203.0.113.1", "203.0.113.2", "203.0.113.3", "198.18.7.7", "203.0.113.5", "203.0.113.6"
	)
	type want struct {
		matched, enforce bool
		why, skip        string
	}
	for _, tc := range []struct {
		name string
		set  func(*Settings)
		ip   string
		site string
		want want
	}{
		{"defaults, enforce: everything is enforced", nil, capi, "site", want{true, true, "", ""}},
		{"defaults, enforce: list range", nil, list, "site", want{true, true, "", ""}},
		{"defaults, log: nothing is enforced", func(s *Settings) { s.Mode = ModeLog }, own, "site", want{true, false, WhyMode, ""}},
		{"capi kept log only", func(s *Settings) { s.OriginPolicy = map[string]string{"capi": "log"} }, capi, "site", want{true, false, WhyOriginLog, ""}},
		{"capi kept log only: own scenarios still enforced", func(s *Settings) { s.OriginPolicy = map[string]string{"capi": "log"} }, own, "site", want{true, true, "", ""}},
		{"lists ignored", func(s *Settings) { s.OriginPolicy = map[string]string{"lists": "ignore"} }, list, "site", want{false, false, "", ""}},
		{"other origin (console) log only", func(s *Settings) { s.OriginPolicy = map[string]string{"other": "log"} }, console, "site", want{true, false, WhyOriginLog, ""}},
		{"cscli ignored: manual ban not applied", func(s *Settings) { s.OriginPolicy = map[string]string{"cscli": "ignore"} }, manual, "site", want{false, false, "", ""}},
		{"policy never raises: log mode stays log", func(s *Settings) {
			s.Mode = ModeLog
			s.OriginPolicy = map[string]string{"capi": "log", "crowdsec": "follow"}
		}, own, "site", want{true, false, WhyMode, ""}},
		{"scenario kept log only (substring, any case)", func(s *Settings) { s.ScenarioLogOnly = []string{"HTTP-Probing"} }, own, "site", want{true, false, WhyScenarioLog, ""}},
		{"scenario list does not touch other scenarios", func(s *Settings) { s.ScenarioLogOnly = []string{"http-probing"} }, capi, "site", want{true, true, "", ""}},
		{"allowlisted address", func(s *Settings) { s.Allowlist = []string{"203.0.113.0/29"} }, own, "site", want{false, false, "", SkipAllowlist}},
		{"allowlist does not cover others", func(s *Settings) { s.Allowlist = []string{"203.0.113.0/29"} }, list, "site", want{true, true, "", ""}},
		{"site exempt", func(s *Settings) { s.SiteOverrides = map[string]string{"site": "exempt"} }, own, "Site", want{false, false, "", SkipSiteExempt}},
		{"site exempt, older setting", func(s *Settings) { s.ExemptSites = []string{"site"} }, own, "site", want{false, false, "", SkipSiteExempt}},
		{"site log only while enforcing", func(s *Settings) { s.SiteOverrides = map[string]string{"site": "log"} }, own, "site", want{true, false, WhySiteLog, ""}},
		{"site log only: other sites enforce", func(s *Settings) { s.SiteOverrides = map[string]string{"site": "log"} }, own, "other", want{true, true, "", ""}},
		{"site enforce while the mode is log", func(s *Settings) { s.Mode = ModeLog; s.SiteOverrides = map[string]string{"site": "enforce"} }, own, "site", want{true, true, "", ""}},
		{"site enforce: other sites stay log", func(s *Settings) { s.Mode = ModeLog; s.SiteOverrides = map[string]string{"site": "enforce"} }, own, "other", want{true, false, WhyMode, ""}},
		{"site enforce does not lift an origin policy", func(s *Settings) {
			s.Mode = ModeLog
			s.SiteOverrides = map[string]string{"site": "enforce"}
			s.OriginPolicy = map[string]string{"capi": "log"}
		}, capi, "site", want{true, false, WhyOriginLog, ""}},
		{"captcha decision, default: logged", nil, cap, "site", want{true, false, WhyCaptchaLog, ""}},
		{"captcha decision, challenge", func(s *Settings) { s.CaptchaAction = CaptchaChallenge }, cap, "site", want{true, true, "", ""}},
		{"captcha decision, challenge, log mode", func(s *Settings) { s.CaptchaAction = CaptchaChallenge; s.Mode = ModeLog }, cap, "site", want{true, false, WhyMode, ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setupMixed(t, tc.set)
			v := x.m.Check(netip.MustParseAddr(tc.ip), tc.site)
			got := want{v.Matched, v.Enforce, v.Why, v.Skip}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v (%+v)", got, tc.want, v)
			}
		})
	}
}

// With several decisions for one visitor the one that will be enforced decides, not the strongest on paper.
func TestStrongestApplicableDecisionWins(t *testing.T) {
	x := setup(t, func(s *Settings) {
		s.CaptchaAction = CaptchaChallenge
		s.OriginPolicy = map[string]string{"capi": "log", "lists": "ignore"}
	})
	x.f.startup = stream([]string{
		decO(1, "ban", "Range", "198.18.0.0/16", "CAPI", "community"),
		decO(2, "captcha", "Ip", "198.18.1.1", "crowdsec", "own"),
		decO(3, "ban", "Ip", "198.18.1.2", "lists:x", "list"),
		decO(4, "ban", "Ip", "198.18.1.3", "cscli", "manual"),
	}, nil)
	x.pull(t)
	if v := x.m.Check(netip.MustParseAddr("198.18.1.1"), "site"); v.Action != ActionCaptcha || !v.Enforce || v.Decision.ID != 2 {
		t.Fatalf("the enforced captcha decision must win over the log-only community ban: %+v", v)
	}
	if v := x.m.Check(netip.MustParseAddr("198.18.1.2"), "site"); !v.Matched || v.Enforce || v.Decision.ID != 1 || v.Why != WhyOriginLog {
		t.Fatalf("ignored list decision: the log-only range must still be listed: %+v", v)
	}
	if v := x.m.Check(netip.MustParseAddr("198.18.1.3"), "site"); !v.Enforce || v.Decision.ID != 4 {
		t.Fatalf("%+v", v)
	}
	// through a trusted proxy: an allowlisted address in the headers triggers nothing, the banned one still does
	x.set(t, func(s *Settings) { s.Allowlist = []string{"198.18.1.3"} })
	v := x.m.CheckForwarded([]netip.Addr{netip.MustParseAddr("198.18.1.3"), netip.MustParseAddr("192.0.2.1")}, "site")
	if v.Matched || v.Skip != SkipAllowlist {
		t.Fatalf("%+v", v)
	}
	x.set(t, func(s *Settings) { s.OriginPolicy = nil; s.Allowlist = []string{"192.0.2.1"} })
	v = x.m.CheckForwarded([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.18.1.3")}, "site")
	if !v.Enforce || v.IP.String() != "198.18.1.3" {
		t.Fatalf("an allowlisted address in a header must not hide the banned one: %+v", v)
	}
	// ignored-by-policy is counted
	x.set(t, func(s *Settings) { s.OriginPolicy = map[string]string{"cscli": "ignore"}; s.Allowlist = nil })
	x.check("198.18.1.3")
	if got := x.m.Today().Ignored; got != 0 { //the community range still applies to it: not "ignored"
		t.Fatalf("ignored %d", got)
	}
	x.set(t, func(s *Settings) { s.OriginPolicy = map[string]string{"cscli": "ignore", "capi": "ignore"} })
	if v := x.check("198.18.1.3"); v.Matched || v.Skip != "" {
		t.Fatalf("%+v", v)
	}
	if got := x.m.Today().Ignored; got != 1 {
		t.Fatalf("ignored %d", got)
	}
}

func TestCaptchaFallback(t *testing.T) {
	x := setupMixed(t, func(s *Settings) { s.CaptchaAction = CaptchaChallenge })
	if v := x.m.Check(netip.MustParseAddr("203.0.113.5"), "site"); !v.Enforce || v.Fallback {
		t.Fatalf("default fallback is log: %+v", v)
	}
	x.set(t, func(s *Settings) { s.CaptchaFallback = CaptchaFallbackBan })
	if v := x.m.Check(netip.MustParseAddr("203.0.113.5"), "site"); !v.Enforce || !v.Fallback {
		t.Fatalf("%+v", v)
	}
	// only when captcha decisions are challenged at all, and never for a ban
	x.set(t, func(s *Settings) { s.CaptchaAction = CaptchaLog })
	if v := x.m.Check(netip.MustParseAddr("203.0.113.5"), "site"); v.Enforce || v.Fallback {
		t.Fatalf("%+v", v)
	}
	if v := x.m.Check(netip.MustParseAddr("203.0.113.1"), "site"); v.Fallback {
		t.Fatalf("%+v", v)
	}
}

func TestFailClosedRespectsSiteAndAllowlist(t *testing.T) {
	x := setupMixed(t, func(s *Settings) {
		s.FailClosed, s.GraceSeconds = true, 60
		s.Allowlist = []string{"192.0.2.10"}
		s.SiteOverrides = map[string]string{"quiet": "log", "skip": "exempt"}
		s.OriginPolicy = map[string]string{"capi": "log"}
	})
	x.f.srv.Close()
	x.advance(10 * time.Minute)
	x.pull(t)
	if v := x.m.Check(netip.MustParseAddr("192.0.2.99"), "site"); v.Action != ActionClosed || !v.Enforce {
		t.Fatalf("%+v", v)
	}
	if v := x.m.Check(netip.MustParseAddr("203.0.113.3"), "site"); v.Action != ActionClosed { //a log-only match is refused like everyone else
		t.Fatalf("%+v", v)
	}
	for _, c := range [][2]string{{"192.0.2.10", "site"}, {"192.0.2.99", "quiet"}, {"192.0.2.99", "skip"}} {
		if v := x.m.Check(netip.MustParseAddr(c[0]), c[1]); v.Matched && v.Enforce {
			t.Fatalf("%v refused by fail-closed: %+v", c, v)
		}
	}
	// a header cannot buy the exemption: only the resolved client address (the first one) counts
	v := x.m.CheckForwarded([]netip.Addr{netip.MustParseAddr("192.0.2.99"), netip.MustParseAddr("192.0.2.10")}, "site")
	if v.Action != ActionClosed {
		t.Fatalf("%+v", v)
	}
}

func TestExplain(t *testing.T) {
	ctx := context.Background()
	x := setupMixed(t, func(s *Settings) {
		s.OriginPolicy = map[string]string{"capi": "log", "lists": "ignore"}
		s.Allowlist = []string{"203.0.113.6"}
		s.SiteOverrides = map[string]string{"skip": "exempt", "quiet": "log"}
		s.CaptchaAction = CaptchaChallenge
	})
	x.m.Protect = func(a netip.Addr) bool { return a.String() == "192.0.2.77" }
	for _, tc := range []struct{ ip, site, result, why string }{
		{"192.0.2.1", "", "none", ""},
		{"203.0.113.1", "", "block", ""},
		{"203.0.113.1", "skip", "exempt", ""},
		{"203.0.113.1", "quiet", "would-block", WhySiteLog},
		{"203.0.113.3", "", "would-block", WhyOriginLog},
		{"198.18.1.1", "", "ignored", ""},
		{"203.0.113.5", "", "challenge", ""},
		{"203.0.113.6", "", "allowlisted", ""},
		{"127.0.0.1", "", "protected", ""},
		{"192.0.2.77", "", "protected", ""},
	} {
		ex, err := x.m.Explain(ctx, netip.MustParseAddr(tc.ip), tc.site, false)
		if err != nil || ex.Result != tc.result || ex.Why != tc.why {
			t.Errorf("%s on %q: result %q why %q, want %q %q (%v)", tc.ip, tc.site, ex.Result, ex.Why, tc.result, tc.why, err)
		}
		if ex.Live != nil {
			t.Errorf("asked the server without being told to")
		}
	}
	ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.3"), "", false)
	if len(ex.Decisions) != 1 || ex.Decisions[0].Policy != "log" || ex.Decisions[0].Class != "capi" || !ex.Decisions[0].Wins || ex.Mode != ModeEnforce {
		t.Fatalf("%+v", ex)
	}
	ex, _ = x.m.Explain(ctx, netip.MustParseAddr("203.0.113.6"), "", false)
	if ex.AllowedBy != "203.0.113.6" || len(ex.Decisions) != 1 || !ex.Decisions[0].Allowlisted {
		t.Fatalf("%+v", ex)
	}
	// explaining counts nothing and lists nothing
	if st := x.m.Status(); st.Checked != 0 || st.Enforced != 0 || x.m.Feed(FeedQuery{}).Total != 0 {
		t.Fatalf("Explain had side effects: %+v", st)
	}
	if _, err := x.m.Explain(ctx, netip.Addr{}, "", false); err == nil {
		t.Fatal("invalid address accepted")
	}
	// the recent requests of the address are part of the answer
	x.check("203.0.113.1")
	if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", false); len(ex.Recent) != 1 || ex.Recent[0].Outcome != OutBlocked {
		t.Fatalf("%+v", ex.Recent)
	}
	// mode log
	x.set(t, func(s *Settings) { s.Mode = ModeLog; s.BanResponse = BanDrop })
	if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", false); ex.Result != "would-block" || ex.Why != WhyMode || ex.Mode != ModeLog {
		t.Fatalf("%+v", ex)
	}
	if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.5"), "", false); ex.Result != "would-challenge" {
		t.Fatalf("%+v", ex)
	}
	x.set(t, func(s *Settings) { s.Mode = ModeEnforce })
	if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", false); ex.Result != "drop" {
		t.Fatalf("%+v", ex)
	}
	// live: one call to the LAPI with the bouncer key; the key is in no answer; limited to 30 a minute
	x.f.mu.Lock()
	x.f.lookup = `[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.1","duration":"3h59m","scenario":"crowdsecurity/http-probing"},{"id":77,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.1","duration":"1h","scenario":"new"}]`
	before := len(x.f.calls)
	x.f.mu.Unlock()
	ex, err := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", true)
	if err != nil || ex.Live == nil || ex.Live.Error != "" || len(ex.Live.Decisions) != 2 || !ex.Live.Differs {
		t.Fatalf("%+v %v", ex.Live, err)
	}
	x.f.mu.Lock()
	calls := x.f.calls[before:]
	x.f.mu.Unlock()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "/v1/decisions?ip=203.0.113.1") {
		t.Fatalf("calls %v", calls)
	}
	js, _ := json.Marshal(ex)
	if strings.Contains(string(js), testKey) {
		t.Fatal("API key in the answer")
	}
	x.f.mu.Lock()
	x.f.lookup = `[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.1","duration":"3h59m","scenario":"s"}]`
	x.f.mu.Unlock()
	if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", true); ex.Live.Differs {
		t.Fatalf("same decision on both sides reported as different: %+v", ex.Live)
	}
	limited := 0
	for i := 0; i < liveLookups+5; i++ {
		if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", true); ex.Live.Error != "" {
			limited++
			if ex.Result != "drop" {
				t.Fatal("a limited live lookup must still return the local answer")
			}
		}
	}
	if limited != 7 {
		t.Fatalf("%d lookups limited, want 7 (30 a minute, 2 were used)", limited)
	}
	x.advance(time.Minute)
	if ex, _ := x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", true); ex.Live.Error != "" {
		t.Fatalf("not refilled: %s", ex.Live.Error)
	}
	// a LAPI error is shown as text without the key
	x.f.mu.Lock()
	x.f.status = 500
	x.f.mu.Unlock()
	ex, _ = x.m.Explain(ctx, netip.MustParseAddr("203.0.113.1"), "", true)
	if ex.Live.Error == "" || strings.Contains(ex.Live.Error, testKey) {
		t.Fatalf("%q", ex.Live.Error)
	}
}

func TestCompositionAndSyncHistory(t *testing.T) {
	x := setupMixed(t, nil)
	a := x.m.Activity("24h")
	l := a.Loaded
	if l.Total != 6 || l.IPs != 5 || l.Ranges != 1 || l.ByClass["crowdsec"] != 2 || l.ByClass["cscli"] != 1 || l.ByClass["capi"] != 1 ||
		l.ByClass["lists"] != 1 || l.ByClass["other"] != 1 || l.ByType["ban"] != 5 || l.ByType["captcha"] != 1 {
		t.Fatalf("after the full synchronisation: %+v", l)
	}
	names := map[string]int{}
	for _, o := range l.ByOrigin {
		names[o.Name] = o.Count
	}
	if names["lists:firehol"] != 1 || names["capi"] != 1 || names["console"] != 1 || len(l.Scenarios) != 6 {
		t.Fatalf("%+v %+v", l.ByOrigin, l.Scenarios)
	}
	if len(a.Pulls) != 1 || !a.Pulls[0].Full || a.Pulls[0].New != 6 || a.Pulls[0].Error != "" || a.LastFull == nil {
		t.Fatalf("%+v", a.Pulls)
	}
	// a delta: two more from the community list, one removed
	x.f.delta = stream([]string{decO(10, "ban", "Ip", "203.0.113.10", "CAPI", "crowdsecurity/ssh-bf"), decO(11, "ban", "Ip", "203.0.113.11", "CAPI", "crowdsecurity/ssh-bf")},
		[]string{decO(2, "ban", "Ip", "203.0.113.2", "cscli", "manual ban")})
	x.advance(10 * time.Second)
	x.pull(t)
	a = x.m.Activity("24h")
	if l := a.Loaded; l.Total != 7 || l.ByClass["capi"] != 3 || l.ByClass["cscli"] != 0 || l.Scenarios[0].Name != "crowdsecurity/ssh-bf" || l.Scenarios[0].Count != 3 {
		t.Fatalf("after the delta: %+v", l)
	}
	if len(a.Pulls) != 2 || a.Pulls[0].Full || a.Pulls[0].New != 2 || a.Pulls[0].Deleted != 1 {
		t.Fatalf("%+v", a.Pulls)
	}
	// expiry shows up without any change from the server (recomputed at most once a minute)
	x.f.delta = stream(nil, nil)
	x.advance(5 * time.Hour)
	x.pull(t)
	if l := x.m.Activity("24h").Loaded; l.Total != 0 {
		t.Fatalf("expired decisions still counted: %+v", l)
	}
	// a failure is in the history with its error, and the history is bounded
	x.f.mu.Lock()
	x.f.status = 500
	x.f.mu.Unlock()
	for i := 0; i < pullRing+10; i++ {
		x.pull(t)
	}
	a = x.m.Activity("24h")
	if len(a.Pulls) != pullRing || a.Pulls[0].Error == "" || strings.Contains(a.Pulls[0].Error, testKey) {
		t.Fatalf("%d pulls, newest %+v", len(a.Pulls), a.Pulls[0])
	}
}

func TestTransitionsAndNotifications(t *testing.T) {
	x := setup(t, func(s *Settings) { s.GraceSeconds = 60 })
	var sent []string
	x.m.Notify = func(ev, subject string, extra map[string]string) {
		if !strings.HasPrefix(subject, "http://127.0.0.1") {
			t.Errorf("subject %q", subject)
		}
		sent = append(sent, ev)
	}
	x.pull(t)
	x.f.mu.Lock()
	x.f.status = 500
	x.f.mu.Unlock()
	fail := func(after time.Duration) { x.advance(after); x.pull(t) }
	ok := func() {
		x.f.mu.Lock()
		x.f.status = 0
		x.f.mu.Unlock()
		x.advance(time.Second)
		if err := x.pull(t); err != nil {
			t.Fatal(err)
		}
		x.f.mu.Lock()
		x.f.status = 500
		x.f.mu.Unlock()
	}
	fail(10 * time.Second) //degraded
	if len(sent) != 0 {
		t.Fatalf("a short failure notified: %v", sent)
	}
	fail(2 * time.Minute) //down
	fail(time.Second)     //still down: no second notification
	ok()                  //back
	if fmt.Sprint(sent) != "[crowdsec.lapi_down crowdsec.lapi_up]" {
		t.Fatalf("%v", sent)
	}
	// flapping: down again within five minutes is not sent again, and neither is the recovery that follows it
	fail(90 * time.Second)
	ok()
	if len(sent) != 2 {
		t.Fatalf("flap notified: %v", sent)
	}
	// later it is
	x.advance(10 * time.Minute)
	x.pull(t) //the long gap itself is "down"
	fail(90 * time.Second)
	ok()
	if fmt.Sprint(sent[2:]) != "[crowdsec.lapi_down crowdsec.lapi_up]" {
		t.Fatalf("%v", sent)
	}
	tr := x.m.Activity("24h").Transitions
	if len(tr) < 6 || tr[len(tr)-1].From != "off" || tr[len(tr)-1].To != "starting" || tr[0].To != "ok" {
		t.Fatalf("%+v", tr)
	}
	sawDown := false
	for _, e := range tr {
		if e.To == "down" && e.Error != "" && !strings.Contains(e.Error, testKey) {
			sawDown = true
		}
	}
	if !sawDown {
		t.Fatalf("no down transition with its error: %+v", tr)
	}
	// bounded
	for i := 0; i < transRing; i++ {
		fail(90 * time.Second)
		ok()
	}
	if got := len(x.m.Activity("24h").Transitions); got != transRing {
		t.Fatalf("%d transitions kept", got)
	}
}

func TestPolicySettingsValidationAndMigration(t *testing.T) {
	norm := func(s Settings) (Settings, error) { err := s.Normalize(); return s, err }
	// empty means the behaviour before the settings existed
	s, err := norm(Settings{})
	if err != nil || len(s.OriginPolicy) != 0 || len(s.Allowlist) != 0 || len(s.SiteOverrides) != 0 || len(s.ScenarioLogOnly) != 0 || s.CaptchaFallback != CaptchaFallbackLog {
		t.Fatalf("%+v %v", s, err)
	}
	// a stored value from before (no policy fields in the JSON) loads unchanged
	var old Settings
	if err := json.Unmarshal([]byte(`{"enabled":true,"lapiUrl":"http://127.0.0.1:8080","mode":"enforce","exemptSites":["Status.Example.com"]}`), &old); err != nil {
		t.Fatal(err)
	}
	if err := old.Normalize(); err != nil || old.SiteMode("status.example.com") != SiteExempt || old.SiteMode("x") != "" || old.Mode != ModeEnforce {
		t.Fatalf("%+v %v", old, err)
	}
	// an override replaces the older exempt entry of the same site
	s, err = norm(Settings{ExemptSites: []string{"a.example.com", "b.example.com"}, SiteOverrides: map[string]string{"A.example.com": "Enforce", "c.example.com": ""}})
	if err != nil || len(s.ExemptSites) != 1 || s.SiteMode("a.example.com") != SiteEnforce || s.SiteMode("b.example.com") != SiteExempt || len(s.SiteOverrides) != 1 ||
		fmt.Sprint(s.EnforcedSites()) != "[a.example.com]" {
		t.Fatalf("%+v %v", s, err)
	}
	// normalised forms
	s, err = norm(Settings{OriginPolicy: map[string]string{"CAPI": "Log", "lists": "follow", "cscli": ""}, ScenarioLogOnly: []string{" HTTP-Crawl ", "http-crawl", ""},
		Allowlist: []string{"203.0.113.7", "203.0.113.7/32", "198.51.100.77/24", "2001:DB8::1", "::ffff:192.0.2.1", ""}})
	if err != nil || fmt.Sprint(s.OriginPolicy) != "map[capi:log]" || fmt.Sprint(s.ScenarioLogOnly) != "[http-crawl]" ||
		fmt.Sprint(s.Allowlist) != "[203.0.113.7 198.51.100.0/24 2001:db8::1 192.0.2.1]" {
		t.Fatalf("%+v %v", s, err)
	}
	many := func(n int, f func(i int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	big := map[string]string{}
	for i := 0; i < maxSiteOverrides+1; i++ {
		big[fmt.Sprintf("s%d.example.com", i)] = "log"
	}
	for name, bad := range map[string]Settings{
		"unknown origin":      {OriginPolicy: map[string]string{"community": "log"}},
		"unknown policy":      {OriginPolicy: map[string]string{"capi": "enforce"}},
		"allowlist /0":        {Allowlist: []string{"0.0.0.0/0"}},
		"allowlist ::/0":      {Allowlist: []string{"::/0"}},
		"allowlist mapped /0": {Allowlist: []string{"::ffff:0.0.0.0/96"}},
		"allowlist text":      {Allowlist: []string{"example.com"}},
		"allowlist too long":  {Allowlist: many(maxAllowlist+1, func(i int) string { return fmt.Sprintf("10.0.%d.%d", i/256, i%256) })},
		"scenario too short":  {ScenarioLogOnly: []string{"ab"}},
		"scenario control":    {ScenarioLogOnly: []string{"abc\ndef"}},
		"too many scenarios":  {ScenarioLogOnly: many(maxScenarioLog+1, func(i int) string { return fmt.Sprintf("scenario-%d", i) })},
		"override value":      {SiteOverrides: map[string]string{"a.example.com": "block"}},
		"override host":       {SiteOverrides: map[string]string{"a b": "log"}},
		"too many overrides":  {SiteOverrides: big},
		"captcha fallback":    {CaptchaFallback: "drop"},
	} {
		if _, err := norm(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// persisted and read back by a new manager; Settings() hands out copies
	x := setup(t, func(s *Settings) {
		s.OriginPolicy = map[string]string{"capi": "log"}
		s.Allowlist = []string{"192.0.2.0/24"}
		s.SiteOverrides = map[string]string{"a.example.com": "log"}
		s.ScenarioLogOnly = []string{"http-crawl"}
		s.CaptchaFallback = CaptchaFallbackBan
	})
	got := x.m.Settings()
	got.OriginPolicy["capi"], got.SiteOverrides["a.example.com"], got.Allowlist[0] = "ignore", "enforce", "x"
	if c := x.m.Settings(); c.OriginPolicy["capi"] != "log" || c.SiteOverrides["a.example.com"] != "log" || c.Allowlist[0] != "192.0.2.0/24" {
		t.Fatalf("Settings() shares its maps: %+v", c)
	}
	m2, err := New(x.kv, NewVault(x.dir))
	if err != nil {
		t.Fatal(err)
	}
	if c := m2.Settings(); c.OriginPolicy["capi"] != "log" || c.CaptchaFallback != CaptchaFallbackBan || c.ScenarioLogOnly[0] != "http-crawl" || c.SiteMode("a.example.com") != SiteLog {
		t.Fatalf("%+v", c)
	}
	// the status says when a site enforces although the mode is log only
	x.set(t, func(s *Settings) { s.Mode = ModeLog; s.SiteOverrides = map[string]string{"a.example.com": "enforce"} })
	st := x.m.Status()
	if fmt.Sprint(st.EnforcedSites) != "[a.example.com]" || !st.PolicyActive || !strings.Contains(strings.Join(st.Warnings, " "), "except on the sites set to Enforce") {
		t.Fatalf("%+v", st)
	}
}

func TestOriginClass(t *testing.T) {
	for in, want := range map[string]string{"crowdsec": "crowdsec", "cscli": "cscli", "cscli-import": "cscli", "CAPI": "capi", "capi": "capi",
		"lists:firehol_level1": "lists", "lists": "lists", "console": "other", "": "other", " Crowdsec ": "crowdsec"} {
		if got := OriginClass(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}
