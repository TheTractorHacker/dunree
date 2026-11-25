package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
)

func hhSetup(t *testing.T) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	old := sysdb
	sysdb = db
	sysdb.NewTable("settings")
	t.Cleanup(func() { sysdb = old })
}

func hhPost(settings string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{"settings": {settings}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleHardenedHeadersDefault(w, r)
	return w
}

func TestHardenedDefaultOffUntilChosen(t *testing.T) {
	hhSetup(t)
	if loadHardenedDefault() != nil {
		t.Fatal("global default is on without anyone choosing it")
	}
	ep := &dynamicproxy.ProxyEndpoint{HeaderRewriteRules: dynamicproxy.GetDefaultHeaderRewriteRules()}
	applyHardenedDefault(ep)
	if ep.HeaderRewriteRules.HardenedHeaders != nil {
		t.Fatal("new site got the preset with the default off")
	}

	// turning it on affects NEW sites only, and never one that already has its own choice
	on, _ := json.Marshal(dynamicproxy.DefaultHardenedHeaders())
	if w := hhPost(string(on)); strings.Contains(w.Body.String(), "error") {
		t.Fatalf("save refused: %s", w.Body.String())
	}
	existing := &dynamicproxy.ProxyEndpoint{HeaderRewriteRules: &dynamicproxy.HeaderRewriteRules{HardenedHeaders: &dynamicproxy.HardenedHeaders{Enabled: false}}}
	applyHardenedDefault(existing)
	if existing.HeaderRewriteRules.HardenedHeaders.Enabled {
		t.Error("the default overwrote a site's own choice")
	}
	fresh := &dynamicproxy.ProxyEndpoint{} //no header rules at all
	applyHardenedDefault(fresh)
	if fresh.HeaderRewriteRules == nil || fresh.HeaderRewriteRules.HardenedHeaders == nil || !fresh.HeaderRewriteRules.HardenedHeaders.Enabled {
		t.Error("default not applied to a new site")
	}
	// persistence: read it back through the GET handler
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	HandleHardenedHeadersDefault(w, r)
	if !strings.Contains(w.Body.String(), `"Enabled":true`) {
		t.Errorf("setting not persisted: %s", w.Body.String())
	}
	// off again
	if w := hhPost(`{"Enabled":false}`); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if loadHardenedDefault() != nil {
		t.Error("default still on after turning it off")
	}
}

func TestHardenedSettingsRejectBadInput(t *testing.T) {
	hhSetup(t)
	for name, in := range map[string]string{
		"not json":         `nope`,
		"unknown field":    `{"Enabled":true,"Evil":"x"}`,
		"header injection": `{"Enabled":true,"ReferrerPolicy":"no-referrer\r\nSet-Cookie: a=b"}`,
		"preload alone":    `{"Enabled":true,"HSTS":true,"HSTSPreload":true}`,
		"frame allow-from": `{"Enabled":true,"FrameProtection":"allow-from x"}`,
		"huge age":         `{"Enabled":true,"HSTS":true,"HSTSMaxAge":9999999999}`,
		"wrong type":       `{"Enabled":"yes"}`,
	} {
		if w := hhPost(in); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("%s accepted: %s", name, w.Body.String())
		}
	}
	if loadHardenedDefault() != nil {
		t.Error("a rejected save changed the stored default")
	}
	// a damaged stored value never turns anything on
	sysdb.Write("settings", hardenedDefaultKey, map[string]any{"Enabled": true, "ReferrerPolicy": "bogus"})
	if loadHardenedDefault() != nil {
		t.Error("damaged stored default was applied")
	}
	// method other than GET/POST
	r := httptest.NewRequest(http.MethodDelete, "/x", nil)
	w := httptest.NewRecorder()
	HandleHardenedHeadersDefault(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE -> %d", w.Code)
	}
}

func TestHardenedPreviewDoesNotSave(t *testing.T) {
	hhSetup(t)
	r := httptest.NewRequest(http.MethodGet, "/x?settings="+url.QueryEscape(`{"Enabled":true,"HSTS":true,"HSTSIncludeSubdomains":true,"NoSniff":true}`), nil)
	w := httptest.NewRecorder()
	HandleHardenedHeadersDefault(w, r)
	var v hardenedView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err, w.Body.String())
	}
	found := false
	for _, e := range v.HTTPS {
		if e.Key == "Strict-Transport-Security" && e.Value == "max-age=31536000; includeSubDomains" {
			found = true
		}
	}
	if !found {
		t.Errorf("preview missing HSTS: %+v", v.HTTPS)
	}
	if loadHardenedDefault() != nil {
		t.Error("a preview saved the settings")
	}
}

// A read or preview of a site with no header rules must not change the live endpoint
func TestHardenedHeadersGetDoesNotMutateEndpoint(t *testing.T) {
	ep := &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "ro.example.com"}
	rt := &dynamicproxy.Router{ProxyEndpoints: &sync.Map{}}
	rt.ProxyEndpoints.Store("ro.example.com", ep)
	old := dynamicProxyRouter
	dynamicProxyRouter = rt
	t.Cleanup(func() { dynamicProxyRouter = old })
	for _, q := range []string{"domain=ro.example.com", "domain=ro.example.com&settings=" + url.QueryEscape(`{"enabled":true}`)} {
		w := httptest.NewRecorder()
		HandleHardenedHeaders(w, httptest.NewRequest(http.MethodGet, "/x?"+q, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body.String())
		}
	}
	if ep.HeaderRewriteRules != nil {
		t.Fatal("a GET changed the live endpoint")
	}
	w := httptest.NewRecorder()
	HandleHardenedHeaders(w, httptest.NewRequest(http.MethodGet, "/x?domain=nope.example.com", nil))
	if !strings.Contains(w.Body.String(), "not exists") {
		t.Fatalf("unknown site: %s", w.Body.String())
	}
}
