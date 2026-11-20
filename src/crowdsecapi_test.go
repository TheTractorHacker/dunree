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

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/crowdsec"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/secaudit"
)

const csAPIKey = "api-test-KEY-98765432100"

func crowdsecTestSetup(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldDB, oldMgr, oldLog, oldAC, oldConf := sysdb, crowdsecMgr, SystemWideLogger, accessController, CONF_FOLDER
	sysdb = db
	sysdb.NewTable("settings")
	accessController = nil
	CONF_FOLDER = t.TempDir()
	crowdsecMgr = nil
	if SystemWideLogger == nil {
		l, _ := logger.NewFmtLogger()
		SystemWideLogger = l
	}
	initCrowdSec()
	t.Cleanup(func() {
		stopCrowdSec()
		sysdb, crowdsecMgr, SystemWideLogger, accessController, CONF_FOLDER = oldDB, oldMgr, oldLog, oldAC, oldConf
	})
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != csAPIKey {
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/v1/decisions/stream" {
			w.Write([]byte(`{"new":[{"id":1,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.9","duration":"1h","scenario":"x"}],"deleted":null}`))
			return
		}
		w.Write([]byte("null"))
	}))
	t.Cleanup(lapi.Close)
	return lapi
}

func csPost(h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func csGet(h http.HandlerFunc) string {
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	return w.Body.String()
}

func TestCrowdSecAPIFlow(t *testing.T) {
	lapi := crowdsecTestSetup(t)
	var v crowdsecView
	if err := json.Unmarshal([]byte(csGet(HandleCrowdSecGet)), &v); err != nil || v.Enabled || v.KeySet || v.Mode != crowdsec.ModeLog || v.FailClosed {
		t.Fatalf("default must be off, log mode, no key, fail-open: %+v %v", v, err)
	}
	if w := httptest.NewRecorder(); true {
		HandleCrowdSecSet(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("set must be POST only: %d", w.Code)
		}
	}
	cfg := `{"enabled":true,"lapiUrl":"` + lapi.URL + `"}`
	for _, bad := range []url.Values{
		{"config": {cfg}}, //no key
		{"config": {`{"enabled":true,"lapiUrl":"http://169.254.169.254"}`}, "apikey": {csAPIKey}},
		{"config": {`{"enabled":true,"lapiUrl":"` + lapi.URL + `","bogus":1}`}, "apikey": {csAPIKey}},
		{"config": {`nonsense`}},
		{"config": {`{"enabled":true,"lapiUrl":"` + lapi.URL + `","failClosed":true}`}, "apikey": {csAPIKey}}, //no confirm
		{"config": {cfg}, "apikey": {"bad key"}},
	} {
		if w := csPost(HandleCrowdSecSet, bad); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("accepted %v: %s", bad, w.Body.String())
		}
	}
	if crowdsecMgr.Active() || crowdsecMgr.KeySet() {
		t.Fatal("a refused request changed state")
	}
	if w := csPost(HandleCrowdSecSet, url.Values{"config": {cfg}, "apikey": {csAPIKey}}); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if err := crowdsecMgr.PullOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	outs := []string{csGet(HandleCrowdSecGet), csGet(HandleCrowdSecStatus), csGet(HandleCrowdSecDecisions)}
	tw := csPost(HandleCrowdSecTest, url.Values{})
	outs = append(outs, tw.Body.String())
	if !strings.Contains(tw.Body.String(), `"ok":true`) {
		t.Fatalf("test with the saved key: %s", tw.Body.String())
	}
	if !strings.Contains(csGet(HandleCrowdSecDecisions), "203.0.113.9") {
		t.Fatal("decision missing from the list")
	}
	for _, o := range outs {
		if strings.Contains(o, csAPIKey) || strings.Contains(o, "api-test-KEY") {
			t.Fatalf("API key in output: %s", o)
		}
	}
	if err := json.Unmarshal([]byte(outs[0]), &v); err != nil || !v.KeySet || !v.Enabled || v.Mode != crowdsec.ModeLog {
		t.Fatalf("%+v", v)
	}
	// wrong key / metadata destination through the test endpoint
	if w := csPost(HandleCrowdSecTest, url.Values{"apikey": {"wrong-key-000"}}); !strings.Contains(w.Body.String(), "403") || strings.Contains(w.Body.String(), "wrong-key") {
		t.Fatalf("%s", w.Body.String())
	}
	if w := csPost(HandleCrowdSecTest, url.Values{"config": {`{"lapiUrl":"http://169.254.169.254/"}`}, "apikey": {"k-123456"}}); !strings.Contains(w.Body.String(), `"ok":false`) {
		t.Fatalf("metadata address tested: %s", w.Body.String())
	}
	// persisted across a restart: a fresh manager reads the same store and key
	m2, err := crowdsec.New(sysdb, crowdsec.NewVault(CONF_FOLDER+"/"+crowdsec.DirName))
	if err != nil || !m2.Active() || !m2.KeySet() {
		t.Fatalf("not persisted: %v", err)
	}
	// the sys.db entry holds no key (it is part of includeDB exports)
	var stored crowdsec.Settings
	sysdb.Read(crowdsec.DBTable, crowdsec.DBKey, &stored)
	js, _ := json.Marshal(stored)
	if strings.Contains(string(js), "api-test-KEY") {
		t.Fatal("key in sys.db")
	}
	// the sealed key file is under the conf folder and excluded from exports
	if _, err := os.Stat(filepath.Join(CONF_FOLDER, "crowdsec", "apikey.sealed")); err != nil {
		t.Fatal(err)
	}
	// fail-closed needs the confirm flag; with it, it is saved
	fc := `{"enabled":true,"lapiUrl":"` + lapi.URL + `","mode":"enforce","failClosed":true}`
	if w := csPost(HandleCrowdSecSet, url.Values{"config": {fc}}); !strings.Contains(w.Body.String(), "confirm") {
		t.Fatalf("%s", w.Body.String())
	}
	if w := csPost(HandleCrowdSecSet, url.Values{"config": {fc}, "confirmfailclosed": {"true"}}); strings.Contains(w.Body.String(), "error") {
		t.Fatalf("%s", w.Body.String())
	}
}

func TestCrowdSecViewerDeniedAndAudited(t *testing.T) {
	for _, p := range []string{"/api/crowdsec/get", "/api/crowdsec/status", "/api/crowdsec/decisions"} {
		if auth.ViewerAllowed(http.MethodGet, p) {
			t.Errorf("viewer may read %s", p)
		}
	}
	if auth.ViewerAllowed(http.MethodPost, "/api/crowdsec/set") || auth.ViewerAllowed(http.MethodPost, "/api/crowdsec/test") {
		t.Error("viewer may change CrowdSec")
	}
	l, _ := useSecAudit(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) })
	h := secAuditWrap(ok)
	formPost(h, "/api/crowdsec/set", url.Values{"config": {`{"enabled":true,"lapiUrl":"http://127.0.0.1:8080","mode":"enforce"}`}, "apikey": {csAPIKey}, "confirmfailclosed": {"true"}})
	formPost(h, "/api/crowdsec/test", url.Values{"apikey": {csAPIKey}})
	pg, _ := l.List(secaudit.Query{Limit: 50})
	got := map[string]bool{}
	for _, e := range pg.Entries {
		got[e.Event] = true
		js, _ := json.Marshal(e)
		if strings.Contains(string(js), "api-test-KEY") {
			t.Fatalf("API key in the audit log: %s", js)
		}
		if e.Event == "crowdsec.set" && !strings.Contains(e.Detail["config"], "enforce") {
			t.Errorf("audit detail lacks the setting: %v", e.Detail)
		}
	}
	if !got["crowdsec.set"] || !got["crowdsec.test"] {
		t.Fatalf("audit events: %v", got)
	}
}
