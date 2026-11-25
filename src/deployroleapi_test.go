package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/access"
	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/deployrole"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
)

func deployTestSetup(t *testing.T) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldDB, oldMgr, oldLog, oldAC := sysdb, deployRoleMgr, SystemWideLogger, accessController
	sysdb = db
	sysdb.NewTable("settings")
	accessController = nil
	if SystemWideLogger == nil {
		l, err := logger.NewFmtLogger()
		if err != nil {
			t.Fatal(err)
		}
		SystemWideLogger = l
	}
	initDeployRole()
	t.Cleanup(func() { sysdb, deployRoleMgr, SystemWideLogger, accessController = oldDB, oldMgr, oldLog, oldAC })
}

func deploySet(cfg string, method string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/deployrole/set", strings.NewReader(url.Values{"config": {cfg}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleDeployRoleSet(w, r)
	return w
}

func deployGet(t *testing.T) deployRoleView {
	t.Helper()
	w := httptest.NewRecorder()
	HandleDeployRoleGet(w, httptest.NewRequest(http.MethodGet, "/api/deployrole/get", nil))
	var v deployRoleView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return v
}

func TestDeployRoleAPI(t *testing.T) {
	deployTestSetup(t)
	v := deployGet(t)
	if v.Role != deployrole.RoleStandalone || v.HardenActive || v.PeerGateActive || v.DirectCIDRs == nil {
		t.Fatalf("default must be standalone and inactive: %+v", v)
	}
	if w := deploySet(`{"role":"internal"}`, http.MethodGet); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("set must be POST only, got %d", w.Code)
	}
	for _, bad := range []string{`{"role":"dmz"}`, `{"role":"internal","peerGate":true}`, `{"role":"external","peerGate":true}`, `{"role":"internal","bogus":1}`, `nonsense`, `{"role":"internal","directCIDRs":["0.0.0.0/0"]}`} {
		if w := deploySet(bad, http.MethodPost); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("%s accepted: %s", bad, w.Body.String())
		}
	}
	if deployGet(t).Role != deployrole.RoleStandalone {
		t.Fatal("a rejected change must not apply")
	}
	if w := deploySet(`{"role":"internal"}`, http.MethodPost); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	v = deployGet(t)
	if v.Role != deployrole.RoleInternal || !v.HardenActive || v.PeerGateActive || len(v.Warnings) == 0 {
		t.Fatalf("internal without gate must warn: %+v", v)
	}
	if w := deploySet(`{"role":"internal","peerGate":true,"directCIDRs":["10.1.0.0/16"]}`, http.MethodPost); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if v = deployGet(t); !v.PeerGateActive || len(v.DirectCIDRs) != 1 {
		t.Fatalf("%+v", v)
	}
	//persisted: a fresh manager on the same database sees it
	initDeployRole()
	if v = deployGet(t); v.Role != deployrole.RoleInternal || !v.PeerGateActive {
		t.Fatalf("not persisted: %+v", v)
	}
}

// With no trusted proxy and no direct network the gate would refuse everyone, so the API refuses to enable it.
func TestDeployRoleAPIRefusesLockoutGate(t *testing.T) {
	deployTestSetup(t)
	w := deploySet(`{"role":"internal","peerGate":true}`, http.MethodPost)
	if !strings.Contains(w.Body.String(), "refuse every connection") {
		t.Fatalf("expected lockout refusal: %s", w.Body.String())
	}
	if deployGet(t).PeerGateActive {
		t.Fatal("gate became active")
	}
}

// A hardened role with an access rule that does not trust proxy headers makes rate limits and bans see the front proxy.
func TestDeployRoleWarnsAboutUngatedAccessRules(t *testing.T) {
	deployTestSetup(t)
	ac, err := access.NewAccessController(&access.Options{
		Logger: *SystemWideLogger, ConfigFolder: filepath.Join(t.TempDir(), "access"), TrustedProxiesFile: filepath.Join(t.TempDir(), "tp.json"),
		Database: sysdb, SkipPublicIPCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	accessController = ac
	ac.AddTrustedProxy("10.9.0.2", "external proxy")
	def, _ := ac.GetAccessRuleByID("default")

	hasUngated := func(v deployRoleView) bool {
		for _, w := range v.Warnings {
			if strings.Contains(w, "Trusted Proxy Gating") {
				return true
			}
		}
		return false
	}
	// standalone, nothing hardened: unchanged, no warning
	if v := deployGet(t); hasUngated(v) || len(v.UngatedRules) != 0 {
		t.Fatalf("standalone must not warn: %+v", v)
	}
	if w := deploySet(`{"role":"internal"}`, http.MethodPost); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	def.TrustProxyHeadersOnly = false
	if v := deployGet(t); !hasUngated(v) || len(v.UngatedRules) == 0 {
		t.Fatalf("internal role with a rule without gating must warn: %+v", v)
	}
	def.TrustProxyHeadersOnly = true
	if v := deployGet(t); hasUngated(v) || len(v.UngatedRules) != 0 {
		t.Fatalf("gated rule still warns: %+v", v)
	}
}
