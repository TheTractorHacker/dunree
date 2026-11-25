package metrics

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

/*
	Dunree rebrand: every family is exported as dunree_*. While the legacy names are on (the
	default) the same family is exported a second time as zoraxy_*, with the same samples.
*/

func legacyRegistry(t *testing.T) *Registry {
	t.Helper()
	r := New()
	r.SetEnabled(true)
	serve(r, "app.example.com", func(w http.ResponseWriter, rq *http.Request) { w.Write([]byte("ok")) }, httptest.NewRequest("GET", "/", nil))
	serve(r, "app.example.com", func(w http.ResponseWriter, rq *http.Request) { w.WriteHeader(500) }, httptest.NewRequest("POST", "/", nil))
	r.Event(EventRateLimited, "app.example.com", "limit")
	r.AddCollector(func(e *Emitter) {
		e.Gauge("dunree_build_info", "Build information; value is always 1.", 1, "version", "t")
		e.Gauge("other_vendor_metric", "not ours", 7)
	})
	return r
}

// linesOf returns the exposition lines that belong to families with the prefix, with the prefix cut off
// (uptime is left out: it moves between two scrapes, not inside one)
func linesOf(text string, prefix string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		rest := strings.TrimPrefix(strings.TrimPrefix(l, "# HELP "), "# TYPE ")
		if strings.HasPrefix(rest, prefix) && !strings.HasPrefix(rest, prefix+"uptime_seconds") {
			out = append(out, strings.Replace(l, prefix, "", 1))
		}
	}
	sort.Strings(out)
	return out
}

func TestLegacyNamesAreExportedNextToTheDunreeNames(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	r := legacyRegistry(t)
	if !r.LegacyNames() {
		t.Fatal("the legacy metric names must be on by default")
	}
	text := scrape(t, r)
	ss, types := parseExposition(t, text)                                //also checks that the whole exposition is well formed
	dunree, legacy := linesOf(text, "dunree_"), linesOf(text, "zoraxy_") // legacy-compat
	if len(dunree) < 20 {
		t.Fatalf("too few dunree_ lines: %d\n%s", len(dunree), text)
	}
	if strings.Join(dunree, "\n") != strings.Join(legacy, "\n") {
		t.Fatalf("the zoraxy_* families are not the same as the dunree_* families\ndunree:\n%s\nlegacy:\n%s", strings.Join(dunree, "\n"), strings.Join(legacy, "\n"))
	}
	for _, name := range []string{"http_requests_total", "http_request_duration_seconds", "ratelimit_rejected_total", "build_info", "uptime_seconds"} {
		if types["dunree_"+name] == "" || types["dunree_"+name] != types["zoraxy_"+name] { // legacy-compat
			t.Errorf("family %s: TYPE dunree=%q legacy=%q", name, types["dunree_"+name], types["zoraxy_"+name])
		}
	}
	for _, prefix := range []string{"dunree_", "zoraxy_"} { // legacy-compat
		if s, ok := find(ss, prefix+"http_requests_total", "endpoint", "app.example.com", "status_class", "5xx", "method", "POST"); !ok || s.value != 1 {
			t.Errorf("%shttp_requests_total 5xx: %+v %v", prefix, s, ok)
		}
		if s, ok := find(ss, prefix+"http_request_duration_seconds_count", "endpoint", "app.example.com"); !ok || s.value != 2 {
			t.Errorf("%shttp_request_duration_seconds_count: %+v %v", prefix, s, ok)
		}
		if _, ok := find(ss, prefix+"http_request_duration_seconds_bucket", "endpoint", "app.example.com", "le", "+Inf"); !ok {
			t.Errorf("%shttp_request_duration_seconds_bucket +Inf missing", prefix)
		}
	}
	//A family that is not ours is written once, under its own name
	if n := strings.Count(text, "other_vendor_metric 7"); n != 1 || strings.Contains(text, "zoraxy_vendor") {
		t.Fatalf("foreign family written %d times", n)
	}

	//Switch off: only the Dunree names, and nothing else changes
	wirecompat.SetEmitLegacy(false)
	off := scrape(t, r)
	parseExposition(t, off)
	if strings.Contains(off, "zoraxy_") { // legacy-compat
		t.Fatalf("legacy names are still exported with the switch off:\n%s", off)
	}
	if got := linesOf(off, "dunree_"); strings.Join(got, "\n") != strings.Join(dunree, "\n") {
		t.Fatalf("the dunree_* families changed with the switch:\n%s", strings.Join(got, "\n"))
	}
}

// A collector that already writes a zoraxy_* family itself is not overwritten or doubled
func TestLegacyNameAlreadyTakenIsNotWrittenTwice(t *testing.T) {
	r := New()
	r.SetEnabled(true)
	r.AddCollector(func(e *Emitter) {
		e.Gauge("dunree_thing", "new", 1)
		e.Gauge("zoraxy_thing", "old, written by the collector itself", 2) // legacy-compat
	})
	text := scrape(t, r)
	parseExposition(t, text)
	if strings.Count(text, "# TYPE zoraxy_thing ") != 1 || !strings.Contains(text, "zoraxy_thing 2\n") || strings.Contains(text, "zoraxy_thing 1\n") { // legacy-compat
		t.Fatalf("unexpected exposition:\n%s", text)
	}
}

func TestBearerRealmIsDunree(t *testing.T) {
	w := httptest.NewRecorder()
	RequireBearer("tok", http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Bearer realm="dunree-metrics"` {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}
