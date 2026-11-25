package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

/*
	Dunree rebrand: the setting "Also send legacy X-Zoraxy-* headers".
	Default on, stored in the database, applied immediately, changed by POST only.
*/

func wireCompatSetup(t *testing.T) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	oldDB, oldLog := sysdb, SystemWideLogger
	sysdb = db
	sysdb.NewTable("settings")
	if SystemWideLogger == nil {
		l, _ := logger.NewFmtLogger()
		SystemWideLogger = l
	}
	t.Cleanup(func() {
		db.Close()
		sysdb, SystemWideLogger = oldDB, oldLog
		wirecompat.SetEmitLegacy(true)
		wirecompat.SetLegacyPathLogger(nil)
	})
}

func legacyCall(method string, target string, form url.Values) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	w := httptest.NewRecorder()
	HandleLegacyNames(w, r)
	return w
}

func legacyState(t *testing.T) bool {
	t.Helper()
	w := legacyCall(http.MethodGet, "/api/compat/legacy", nil)
	var v struct {
		Enabled bool `json:"enabled"`
		Default bool `json:"default"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || !v.Default {
		t.Fatalf("GET /api/compat/legacy: %d %s", w.Code, w.Body.String())
	}
	return v.Enabled
}

func TestLegacyNamesSettingDefaultsOnAndPersists(t *testing.T) {
	wireCompatSetup(t)

	//An install that never saw the setting (no key): on
	wirecompat.SetEmitLegacy(false)
	initWireCompat()
	if !wirecompat.EmitLegacy() || !legacyState(t) {
		t.Fatal("without a stored value the legacy names must be on")
	}
	if sysdb.KeyExists("settings", legacyEmitKey) {
		t.Fatal("reading the setting must not store it")
	}

	//A GET never changes it, whatever the query string says
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if w := legacyCall(method, "/api/compat/legacy?enable=false", nil); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s ?enable=false = %d, want 405", method, w.Code)
		}
	}
	if !wirecompat.EmitLegacy() {
		t.Fatal("a GET changed the setting")
	}

	//Bad input is refused and changes nothing
	for _, bad := range []url.Values{{}, {"enable": {"maybe"}}, {"enable": {""}}} {
		if w := legacyCall(http.MethodPost, "/api/compat/legacy", bad); !strings.Contains(w.Body.String(), "error") || !wirecompat.EmitLegacy() {
			t.Fatalf("POST %v: %s", bad, w.Body.String())
		}
	}

	//Off: applies at once and survives a restart
	if w := legacyCall(http.MethodPost, "/api/compat/legacy", url.Values{"enable": {"false"}}); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if wirecompat.EmitLegacy() || legacyState(t) {
		t.Fatal("switching off did not apply")
	}
	wirecompat.SetEmitLegacy(true) //"restart"
	initWireCompat()
	if wirecompat.EmitLegacy() {
		t.Fatal("the stored value (off) was not loaded at startup")
	}

	//And on again
	legacyCall(http.MethodPost, "/api/compat/legacy", url.Values{"enable": {"true"}})
	wirecompat.SetEmitLegacy(false)
	initWireCompat()
	if !wirecompat.EmitLegacy() {
		t.Fatal("the stored value (on) was not loaded at startup")
	}
}

// A stored value that is not a boolean (hand-edited or corrupted database, a restore from another
// build) must not switch the legacy names off: monitors of an existing install rely on them
func TestLegacyNamesUnreadableStoredValueKeepsThemOn(t *testing.T) {
	wireCompatSetup(t)
	for _, bad := range []interface{}{"false", "garbage", 0, map[string]bool{"enabled": false}, nil} {
		if err := sysdb.Write("settings", legacyEmitKey, bad); err != nil {
			t.Fatal(err)
		}
		wirecompat.SetEmitLegacy(false)
		initWireCompat()
		if !wirecompat.EmitLegacy() {
			t.Fatalf("stored value %#v switched the legacy names off", bad)
		}
	}
}

// The header of the error page test link, with the setting on and off
func TestErrorPageHeaderFollowsLegacySetting(t *testing.T) {
	wireCompatSetup(t)
	oldConf, oldMgr := CONF_FOLDER, errorPageMgr
	CONF_FOLDER = t.TempDir()
	t.Cleanup(func() { CONF_FOLDER, errorPageMgr = oldConf, oldMgr })
	initErrorPages()

	w := epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=403", nil)
	if w.Header().Get("X-Dunree-Error-Page") != "built-in" || w.Header().Get("X-Zoraxy-Error-Page") != "built-in" { // legacy-compat
		t.Fatalf("setting on: %v", w.Header())
	}
	legacyCall(http.MethodPost, "/api/compat/legacy", url.Values{"enable": {"false"}})
	w = epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=403", nil)
	if w.Header().Get("X-Dunree-Error-Page") != "built-in" || len(w.Header().Values("X-Zoraxy-Error-Page")) != 0 { // legacy-compat
		t.Fatalf("setting off: %v", w.Header())
	}
}

// The metrics token: the Dunree variable wins, the Zoraxy variable of an existing unit file still works // legacy-compat
func TestMetricsTokenEnvNames(t *testing.T) {
	oldConf, oldFlag := CONF_FOLDER, *metricsToken
	CONF_FOLDER, *metricsToken = t.TempDir(), ""
	t.Cleanup(func() { CONF_FOLDER, *metricsToken = oldConf, oldFlag })
	t.Setenv("DUNREE_METRICS_TOKEN", "")
	t.Setenv("ZORAXY_METRICS_TOKEN", "") // legacy-compat
	if metricsTokenValue() != "" {
		t.Fatal("no token expected")
	}
	os.WriteFile(filepath.Join(CONF_FOLDER, "metrics.json"), []byte(`{"token":"from-file"}`), 0o600)
	if metricsTokenValue() != "from-file" {
		t.Fatal("conf file")
	}
	t.Setenv("ZORAXY_METRICS_TOKEN", "old-name") // legacy-compat
	if metricsTokenValue() != "old-name" {
		t.Fatal("the legacy variable must still be read")
	}
	t.Setenv("DUNREE_METRICS_TOKEN", "new-name")
	if metricsTokenValue() != "new-name" {
		t.Fatal("the Dunree variable must win")
	}
	*metricsToken = "flag"
	if metricsTokenValue() != "flag" {
		t.Fatal("the flag must win")
	}
}

// What plugins are told about the host: the legacy field keeps a Zoraxy version number // legacy-compat
func TestPluginRuntimeConstKeepsTheZoraxyBaseVersion(t *testing.T) { // legacy-compat
	oldUUID := nodeUUID
	nodeUUID = "11111111-2222-3333-4444-555555555555"
	t.Cleanup(func() { nodeUUID = oldUUID })
	rc := pluginRuntimeConst()
	if rc.ZoraxyVersion != "3.3.6" { // legacy-compat: the Zoraxy release Dunree 1.0 is based on
		t.Fatalf("zoraxy_version must stay the Zoraxy base version, got %q", rc.ZoraxyVersion) // legacy-compat
	}
	if rc.DunreeVersion != PRODUCT_VERSION || rc.DunreeUUID != nodeUUID || rc.ZoraxyUUID != nodeUUID { // legacy-compat
		t.Fatalf("%+v", rc)
	}
	raw, _ := json.Marshal(rc)
	for _, field := range []string{`"zoraxy_version":"3.3.6"`, `"zoraxy_uuid":"` + nodeUUID + `"`, `"dunree_uuid":"` + nodeUUID + `"`, `"dunree_version":"` + PRODUCT_VERSION + `"`} { // legacy-compat
		if !strings.Contains(string(raw), field) {
			t.Errorf("runtime_const lacks %s: %s", field, raw)
		}
	}
}
