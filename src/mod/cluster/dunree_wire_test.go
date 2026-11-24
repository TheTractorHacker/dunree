package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/foleyit/dunree/mod/wirecompat"
)

/*
	Dunree rebrand: the health path has a Dunree name and keeps answering on the Zoraxy name, // legacy-compat
	and a primary sends the snapshot version under both header names whatever the legacy
	switch says (a cluster is upgraded node by node).
*/

func TestHealthPathNames(t *testing.T) {
	if HealthPath != "/.dunree/health" || LegacyHealthPath != "/.zoraxy/health" { // legacy-compat
		t.Fatalf("health paths changed: %q %q", HealthPath, LegacyHealthPath)
	}
	for path, want := range map[string]bool{
		HealthPath:                true,
		LegacyHealthPath:          true,
		LegacyHealthPath + "/":    false,
		LegacyHealthPath + "z":    false,
		"/.dunree/captcha/x":      false,
		"/.zoraxy":                false, // legacy-compat
		"/.Zoraxy/health":         false, // legacy-compat
		"/prefix" + HealthPath:    false,
		"/.dunree/.zoraxy/health": false, // legacy-compat
	} {
		r := &http.Request{URL: httptest.NewRequest("GET", "http://h"+path, nil).URL}
		if IsHealthRequest(r) != want {
			t.Errorf("%s: want %v", path, want)
		}
	}
	h := NewHealthEndpoint("1")
	r := httptest.NewRequest("GET", "http://any.host"+LegacyHealthPath, nil)
	r.RemoteAddr = "203.0.113.9:1"
	w := httptest.NewRecorder()
	if !h.Serve(w, r, true, 1) || w.Code != 200 {
		t.Fatalf("legacy health path: %d", w.Code)
	}
}

func TestSnapshotVersionHeaderHasBothNamesAlways(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	for _, legacy := range []bool{true, false} {
		wirecompat.SetEmitLegacy(legacy)
		p := newPair(t, false)
		r := httptest.NewRequest("GET", SnapshotPath, nil)
		r.RemoteAddr = "198.51.100.8:1"
		r.Header.Set("Authorization", "Bearer "+MakeToken(testSecret, "GET", SnapshotPath, "node-x", p.pClock.Now()))
		w := httptest.NewRecorder()
		p.primary.SyncHandler().ServeHTTP(w, r)
		v := w.Header().Get("X-Dunree-Snapshot-Version")
		if w.Code != 200 || v == "" || w.Header().Get("X-Zoraxy-Snapshot-Version") != v { // legacy-compat
			t.Fatalf("legacy switch %v: %d %v", legacy, w.Code, w.Header())
		}
	}
}
