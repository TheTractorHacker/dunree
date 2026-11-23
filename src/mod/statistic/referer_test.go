package statistic

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	uaChrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	uaCurl   = "curl/8.5.0"
)

func TestClassifyReferer(t *testing.T) {
	long := "https://" + strings.Repeat("a", 300) + ".example"
	cases := []struct {
		name string
		src  RefererSource
		want string
	}{
		{"referer is kept as sent", RefererSource{Referer: "https://news.example/story?id=1", SecFetchSite: "cross-site", HasFetchMeta: true, UserAgent: uaChrome}, "https://news.example/story?id=1"},
		{"referer wins over origin", RefererSource{Referer: "https://a.example/", Origin: "https://b.example"}, "https://a.example/"},
		{"referer that imitates a sentinel is escaped", RefererSource{Referer: "~direct"}, "%7Edirect"},
		{"referer that imitates an origin key is escaped", RefererSource{Referer: "~origin:https://evil.example"}, "%7Eorigin:https://evil.example"},
		{"referer that is only markup is not counted as missing", RefererSource{Referer: "<script>x</script>", SecFetchSite: "none", HasFetchMeta: true, UserAgent: uaChrome}, RefererInvalid},
		{"whitespace referer counts as missing", RefererSource{Referer: "   ", SecFetchSite: "none", HasFetchMeta: true, UserAgent: uaChrome}, RefererDirect},

		{"typed address or bookmark", RefererSource{SecFetchSite: "none", HasFetchMeta: true, UserAgent: uaChrome}, RefererDirect},
		{"sec-fetch-site is case insensitive", RefererSource{SecFetchSite: " None ", HasFetchMeta: true, UserAgent: uaChrome}, RefererDirect},
		{"cross-site without referer", RefererSource{SecFetchSite: "cross-site", HasFetchMeta: true, UserAgent: uaChrome}, RefererHiddenPolicy},
		{"same-origin without referer", RefererSource{SecFetchSite: "same-origin", HasFetchMeta: true, UserAgent: uaChrome}, RefererSameSite},
		{"same-site without referer", RefererSource{SecFetchSite: "same-site", HasFetchMeta: true, UserAgent: uaChrome}, RefererSameSite},
		{"unknown sec-fetch-site value", RefererSource{SecFetchSite: "sideways", HasFetchMeta: true, UserAgent: uaChrome}, RefererUnknown},
		{"fetch metadata without a site value", RefererSource{HasFetchMeta: true, UserAgent: uaChrome}, RefererUnknown},
		{"a bot that sends fetch metadata is still classified by it", RefererSource{SecFetchSite: "none", HasFetchMeta: true, UserAgent: uaCurl}, RefererDirect},

		{"origin of another site", RefererSource{Origin: "https://Shop.Example", SecFetchSite: "cross-site", HasFetchMeta: true, UserAgent: uaChrome, Host: "app.example.com"}, "~origin:https://shop.example"},
		{"origin with port", RefererSource{Origin: "http://192.0.2.7:8080", Host: "app.example.com", UserAgent: uaChrome}, "~origin:http://192.0.2.7:8080"},
		{"ipv6 origin", RefererSource{Origin: "https://[2001:db8::1]:8443", Host: "app.example.com"}, "~origin:https://[2001:db8::1]:8443"},
		{"origin equal to the requested host", RefererSource{Origin: "https://app.example.com", Host: "app.example.com:443", UserAgent: uaChrome}, RefererSameSite},
		{"same-origin fetch behind a host rewrite", RefererSource{Origin: "https://public.example", SecFetchSite: "same-origin", HasFetchMeta: true, Host: "internal"}, RefererSameSite},
		{"origin null falls back to fetch metadata", RefererSource{Origin: "null", SecFetchSite: "cross-site", HasFetchMeta: true, UserAgent: uaChrome}, RefererHiddenPolicy},

		// hostile Origin values: never stored
		{"origin with markup", RefererSource{Origin: `https://x.example"><script>alert(1)</script>`, UserAgent: uaChrome}, RefererUnknown},
		{"origin with a path", RefererSource{Origin: "https://x.example/secret/path", UserAgent: uaChrome}, RefererUnknown},
		{"origin with a query", RefererSource{Origin: "https://x.example?token=abc", UserAgent: uaChrome}, RefererUnknown},
		{"origin with credentials", RefererSource{Origin: "https://user:pw@x.example", UserAgent: uaChrome}, RefererUnknown},
		{"origin with another scheme", RefererSource{Origin: "javascript://x.example", UserAgent: uaChrome}, RefererUnknown},
		{"origin with a file scheme", RefererSource{Origin: "file://host", UserAgent: uaChrome}, RefererUnknown},
		{"origin with a control character", RefererSource{Origin: "https://x.example\r\nX: 1", UserAgent: uaChrome}, RefererUnknown},
		{"origin with a space", RefererSource{Origin: "https://x .example", UserAgent: uaChrome}, RefererUnknown},
		{"origin with unicode", RefererSource{Origin: "https://exаmple.com", UserAgent: uaChrome}, RefererUnknown},
		{"origin that imitates a sentinel", RefererSource{Origin: "~direct", UserAgent: uaChrome}, RefererUnknown},
		{"oversized origin", RefererSource{Origin: long, UserAgent: uaChrome}, RefererUnknown},
		{"hostile origin from a script", RefererSource{Origin: "<img src=x>", UserAgent: uaCurl}, RefererNonBrowser},

		{"curl", RefererSource{UserAgent: uaCurl}, RefererNonBrowser},
		{"empty user agent", RefererSource{}, RefererNonBrowser},
		{"search engine crawler", RefererSource{UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}, RefererNonBrowser},
		{"python library", RefererSource{UserAgent: "python-requests/2.32.0"}, RefererNonBrowser},
		{"health check", RefererSource{UserAgent: "Zoraxy-HealthCheck"}, RefererNonBrowser},
		{"bot named at the end of a word", RefererSource{UserAgent: "Mozilla/5.0 (compatible; AhrefsBot; +http://ahrefs.com/robot/)"}, RefererNonBrowser},
		{"bot followed by a dash", RefererSource{UserAgent: "Mozilla/5.0 (compatible; Slackbot-LinkExpanding 1.0)"}, RefererNonBrowser},
		{"bot as the last word", RefererSource{UserAgent: "Mozilla/5.0 (compatible; my bot"}, RefererNonBrowser},
		{"CUBOT phone with an underscore", RefererSource{UserAgent: "Mozilla/5.0 (Linux; Android 10; CUBOT_X30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"}, RefererUnknown},
		{"CUBOT phone with a space", RefererSource{UserAgent: "Mozilla/5.0 (Linux; Android 9; CUBOT X19) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"}, RefererUnknown},
		{"bot inside another word", RefererSource{UserAgent: "Mozilla/5.0 (Linux; Android 12; Bottle 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"}, RefererUnknown},
		{"app with its own user agent", RefererSource{UserAgent: "MyApp/3.1 (iPhone; iOS 18.0)"}, RefererNonBrowser},
		{"browser without fetch metadata (plain http, old browser)", RefererSource{UserAgent: uaChrome}, RefererUnknown},
	}
	for _, c := range cases {
		got := ClassifyReferer(c.src)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
		if got == "" {
			t.Errorf("%s: the empty key must never be produced", c.name)
		}
		if len(got) > MaxStatKeyLength && c.src.Referer == "" {
			t.Errorf("%s: key of %d bytes", c.name, len(got))
		}
		if strings.TrimSpace(c.src.Referer) != "" && IsRefererSentinel(got) && got != RefererInvalid {
			t.Errorf("%s: a client supplied Referer became the sentinel %q", c.name, got)
		}
	}
}

func TestRefererSourceFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/x", nil)
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Origin", "https://other.example")
	r.Header.Set("User-Agent", uaChrome)
	s := RefererSourceFromRequest(r)
	if !s.HasFetchMeta || s.SecFetchSite != "" || s.Origin != "https://other.example" || s.Host != "app.example.com" || s.UserAgent != uaChrome {
		t.Fatalf("bad source: %+v", s)
	}
	if got := ClassifyReferer(s); got != "~origin:https://other.example" {
		t.Fatalf("got %q", got)
	}
	if got := ClassifyReferer(RefererSourceFromRequest(nil)); got != RefererNonBrowser {
		t.Fatalf("nil request: %q", got)
	}
}

func TestRefererLabel(t *testing.T) {
	for key, want := range map[string]string{
		"":                             "Unknown (recorded before this version)",
		RefererDirect:                  "Direct visit (typed / bookmark / app)",
		RefererHiddenPolicy:            "Hidden by the referring site's policy",
		RefererSameSite:                "Same site",
		RefererNonBrowser:              "Non-browser client (bot / API / script)",
		RefererUnknown:                 "Not sent (reason unknown)",
		RefererInvalid:                 "Unreadable referrer (markup only)",
		"~origin:https://shop.example": "https://shop.example (from the Origin header)",
		"https://news.example/a":       "https://news.example/a",
	} {
		got := RefererLabel(key)
		if got != want {
			t.Errorf("%q: got %q, want %q", key, got, want)
		}
		if strings.Contains(got, ",") {
			t.Errorf("%q: the name %q holds a comma, which splits the Referer cell of the CSV export", key, got)
		}
	}
}

// What RecordRequest stores, globally and per site, and that it survives a save and load
func TestRefererRecordRoundTrip(t *testing.T) {
	c := newTestCollector(t, 1000)
	rec := func(ref string) {
		c.RecordRequest(RequestInfo{IpAddr: "1.1.1.1", Succ: true, StatusCode: 200, Site: "a.example.com", Referer: ref, UserAgent: uaChrome})
	}
	rec("https://news.example/story")
	rec(RefererDirect)
	rec(RefererDirect)
	rec(RefererHiddenPolicy)
	rec(RefererNonBrowser)
	rec("~origin:https://shop.example")
	rec("")                                                 //a caller that knows nothing about the request
	rec("<b></b>")                                          //nothing left after the markup is removed
	rec("https://long.example/" + strings.Repeat("p", 400)) //truncated, host kept
	waitTotal(t, c, 9)

	want := map[string]int{
		"https://news.example/story": 1, RefererDirect: 2, RefererHiddenPolicy: 1, RefererNonBrowser: 1,
		"~origin:https://shop.example": 1, RefererUnknown: 1, RefererInvalid: 1,
		("https://long.example/" + strings.Repeat("p", 400))[:MaxStatKeyLength]: 1,
	}
	check := func(where string, got map[string]int) {
		t.Helper()
		if _, has := got[""]; has {
			t.Errorf("%s: the empty Referer key is still written: %v", where, got)
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", where, got, want)
		}
		sum := 0
		for k, n := range want {
			if got[k] != n {
				t.Errorf("%s: %q = %d, want %d", where, k, got[k], n)
			}
			sum += got[k]
		}
		if sum != 9 {
			t.Errorf("%s: %d requests have a referrer key, want every one of the 9", where, sum)
		}
	}
	check("global", c.GetExportSummary().Referer)
	check("site", c.GetSiteExport("a.example.com").Referer)

	c.SaveSummaryOfDay()
	y, m, d := time.Now().Date()
	e := dailySummaryToExport(c.LoadSummaryOfDay(y, m, d))
	check("global after reload", e.Referer)
	check("site after reload", e.Sites["a.example.com"].Referer)
}

// Markup is removed from a Referer before it is stored. What is left must not be
// able to pose as a classification key, whatever the header looked like before.
func TestStoredRefererKey(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"no value", "", RefererUnknown},
		{"blank value", "   ", RefererUnknown},
		{"a referrer", "https://news.example/story", "https://news.example/story"},
		{"keys of the classifier", RefererDirect, RefererDirect},
		{"hidden", RefererHiddenPolicy, RefererHiddenPolicy},
		{"same site", RefererSameSite, RefererSameSite},
		{"non-browser", RefererNonBrowser, RefererNonBrowser},
		{"unknown", RefererUnknown, RefererUnknown},
		{"invalid", RefererInvalid, RefererInvalid},
		{"origin key", "~origin:https://shop.example", "~origin:https://shop.example"},
		{"origin key with port", "~origin:http://192.0.2.7:8080", "~origin:http://192.0.2.7:8080"},

		{"markup only", "<b></b>", RefererInvalid},
		{"script only", "<script>x</script>", RefererInvalid},
		{"markup in front of a sentinel", "<b></b>~direct", "%7Edirect"},
		{"markup in front of a sentinel, with a space", "<b></b> ~direct", "%7Edirect"},
		{"markup inside a sentinel", "~dir<i></i>ect", "%7Edirect"},
		{"markup in front of an origin key", "<i></i>~origin:javascript:alert(document.domain)", "%7Eorigin:javascript:alert(document.domain)"},
		{"markup in front of a well formed origin key", "<i></i>~origin:https://shop.example", "%7Eorigin:https://shop.example"},
		{"origin key that is not an origin", "~origin:javascript:alert(1)", "%7Eorigin:javascript:alert(1)"},
		{"origin key with a path", "~origin:https://shop.example/a", "%7Eorigin:https://shop.example/a"},
		{"origin key in upper case", "~origin:https://Shop.Example", "%7Eorigin:https://Shop.Example"},
		{"a key no classifier produces", "~made-up", "%7Emade-up"},
		{"sentinel with a trailing space", "~direct ", "%7Edirect"},
	} {
		got := StoredRefererKey(c.in)
		if got != c.want {
			t.Errorf("%s: StoredRefererKey(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		if got == "" {
			t.Errorf("%s: the empty key must never be produced", c.name)
		}
	}
}

// End to end, as the proxy does it: a hostile Referer goes through ClassifyReferer and RecordRequest
func TestHostileRefererIsNeverCountedAsAReason(t *testing.T) {
	c := newTestCollector(t, 1000)
	sent := []string{
		"<b></b>~direct",
		"<i></i>~origin:javascript:alert(document.domain)",
		"~direct",
		"~origin:https://evil.example",
		"<script>x</script>",
		" <b></b>~non-browser",
	}
	for _, ref := range sent {
		key := ClassifyReferer(RefererSource{Referer: ref, UserAgent: uaChrome, SecFetchSite: "none", HasFetchMeta: true})
		c.RecordRequest(RequestInfo{IpAddr: "1.1.1.1", Succ: true, StatusCode: 200, Site: "a.example.com", Referer: key, UserAgent: uaChrome})
	}
	waitTotal(t, c, int64(len(sent)))
	want := map[string]int{
		"%7Edirect": 2,
		"%7Eorigin:javascript:alert(document.domain)": 1,
		"%7Eorigin:https://evil.example":              1,
		RefererInvalid:                                1,
		"%7Enon-browser":                              1,
	}
	for where, got := range map[string]map[string]int{"global": c.GetExportSummary().Referer, "site": c.GetSiteExport("a.example.com").Referer} {
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", where, got, want)
		}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("%s: %q = %d, want %d (all: %v)", where, k, got[k], n, got)
			}
		}
		for k := range got {
			if IsRefererSentinel(k) && k != RefererInvalid {
				t.Errorf("%s: a Referer header was stored under the classification key %q", where, k)
			}
		}
	}
}
