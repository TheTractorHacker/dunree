package wirecompat

import (
	"net/http"
	"sync/atomic"
	"testing"
)

func TestDefaultIsOn(t *testing.T) {
	if !EmitLegacy() {
		t.Fatal("the legacy names must be sent by default: an existing install must not change silently")
	}
}

func TestSetHeaderFollowsTheSwitch(t *testing.T) {
	defer SetEmitLegacy(true)
	h := http.Header{}
	SetHeader(h, "Ref", "a")
	if h.Get("X-Dunree-Ref") != "a" || h.Get("X-Zoraxy-Ref") != "a" { // legacy-compat
		t.Fatalf("switch on: %v", h)
	}
	SetEmitLegacy(false)
	SetHeader(h, "Ref", "b")
	if h.Get("X-Dunree-Ref") != "b" || len(h.Values("X-Zoraxy-Ref")) != 0 { // legacy-compat
		t.Fatalf("switch off must leave no stale legacy header: %v", h)
	}
	//The plugin and cluster channel does not follow the switch
	SetHeaderAlways(h, "Plugin-Token", "t")
	if h.Get("X-Dunree-Plugin-Token") != "t" || h.Get("X-Zoraxy-Plugin-Token") != "t" { // legacy-compat
		t.Fatalf("SetHeaderAlways: %v", h)
	}
	if p := HeaderPairs("Capture", "/x"); len(p) != 2 || p[0][0] != "X-Dunree-Capture" || p[1][0] != "X-Zoraxy-Capture" || p[0][1] != "/x" || p[1][1] != "/x" { // legacy-compat
		t.Fatalf("HeaderPairs: %v", p)
	}
}

func TestGetHeaderPrefersDunreeAndAcceptsLegacy(t *testing.T) {
	h := http.Header{}
	if GetHeader(h, "Csrf") != "" {
		t.Fatal("empty")
	}
	h.Set("x-zoraxy-csrf", "old") // legacy-compat
	if GetHeader(h, "Csrf") != "old" {
		t.Fatal("the legacy header is not accepted on input")
	}
	h.Set("X-Dunree-Csrf", "new")
	if GetHeader(h, "Csrf") != "new" {
		t.Fatal("the Dunree header must win")
	}
	DelHeader(h, "Csrf")
	if len(h) != 0 {
		t.Fatalf("DelHeader: %v", h)
	}
	for name, want := range map[string]bool{"X-Dunree-Ref": true, "x-zoraxy-ref": true, "X-ZORAXY-": true, "X-Dunre": false, "X-Other": false, "": false} { // legacy-compat
		if IsReservedHeader(name) != want {
			t.Errorf("IsReservedHeader(%q) != %v", name, want)
		}
	}
}

func TestPaths(t *testing.T) {
	if LegacyPath("/.dunree/captcha/verify") != "/.zoraxy/captcha/verify" || LegacyPath("/other") != "/other" || LegacyPath("/.dunreex/a") != "/.dunreex/a" { // legacy-compat
		t.Fatal("LegacyPath")
	}
	var calls atomic.Int64
	SetLegacyPathLogger(func(path string, hits uint64) {
		if path != "/.zoraxy/health" || hits != 1 { // legacy-compat
			t.Errorf("logger got %q %d", path, hits)
		}
		calls.Add(1)
	})
	defer SetLegacyPathLogger(nil)
	const canonical = "/.dunree/health"
	for path, want := range map[string]bool{
		"/.dunree/health":   true,
		"/.zoraxy/health":   true, // legacy-compat
		"/.zoraxy/health/":  false,
		"/.dunree/healthz":  false,
		"/.ZORAXY/health":   false, // legacy-compat
		"/x/.zoraxy/health": false,
		"/.zoraxy/other":    false,
		"":                  false,
	} {
		if IsPath(path, canonical) != want {
			t.Errorf("IsPath(%q) != %v", path, want)
		}
	}
	IsPath("/.zoraxy/health", canonical) // legacy-compat: second hit the same day is counted, not logged
	if calls.Load() != 1 {
		t.Fatalf("the use of a legacy path must be logged once a day, got %d calls", calls.Load())
	}
	if hits := LegacyPathHits(); hits["/.zoraxy/health"] != 2 || len(hits) != 1 { // legacy-compat
		t.Fatalf("hits: %v", hits)
	}
}
