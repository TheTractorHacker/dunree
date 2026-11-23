package plugins

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	Phase 2 of docs/plugins/reliability-plan.md, item 2.6: permission approval.

	Default (log-only): every endpoint a manifest asks for is granted, as always;
	endpoints that are not approved are reported once (log, audit entry, status).
	Opt-in "require approval": only approved endpoints are granted.
*/

const (
	epList   = "/plugin/api/access/list"
	epAdd    = "/plugin/api/blacklist/ip/add"
	epRemove = "/plugin/api/blacklist/ip/remove"
)

func keyOpens(m *Manager, apiKey string, method string, endpoint string) bool {
	_, err := m.Options.APIKeyManager.ValidateAPIKeyForEndpoint(endpoint, method, apiKey)
	return err == nil
}

// storeUpdate plays a store update of an installed chaos plugin: the store offers
// a newer version of the same binary, and newConf is what its manifest says after
// the update (the chaos plugin reads chaos.conf at every introspect).
func storeUpdate(t *testing.T, m *Manager, p *Plugin, newConf string) {
	t.Helper()
	srv := storeFixture(t)
	m.Options.DownloadablePluginCache = []*DownloadablePlugin{{
		PluginIntroSpect: zp.IntroSpect{ID: p.Spec.ID, Name: p.Spec.Name, VersionMajor: p.Spec.VersionMajor, VersionMinor: p.Spec.VersionMinor + 1},
		DownloadURLs:     map[string]string{runtime.GOOS + "_" + runtime.GOARCH: srv.URL + "/chaos"},
	}}
	m.storeCfg.HealthSettle = 200 * time.Millisecond //the health check after an update, see phase2_store_test.go
	rewriteChaosConf(t, p, newConf)
	os.Remove(filepath.Join(p.RootDir, "last-configure.json")) //startedWith then waits for the start after the update
	if err := m.UpdatePlugin(p.Spec.ID); err != nil {
		t.Fatalf("UpdatePlugin: %v", err)
	}
}

// The plugins that are installed when permission tracking runs for the first time
// keep what they have (the baseline); a plugin that shows up later is new.
func TestPermissionBaselineThenNewPluginsArePending(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	installChaos(t, m.Options.PluginDir, "veteran", "mode=ok\nfeatures=hooks,api\n")
	m.Options.Database.Write("plugins", "test.chaos.veteran", false) //do not start it at "boot"
	if err := m.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	veteran, err := m.GetPluginByID("test.chaos.veteran")
	if err != nil {
		t.Fatal(err)
	}
	st := m.permissionStateOf(veteran)
	if st.Pending != 0 || st.Withheld != 0 || st.Origin != permOriginBaseline || len(st.Requested) != 1 || !st.Requested[0].Approved || !st.Requested[0].Granted {
		t.Fatalf("a plugin that was installed before permissions were tracked must be recorded as approved: %+v", st)
	}
	if got := audit.of(veteran.Spec.ID); len(got) != 0 {
		t.Fatalf("the baseline must not be reported as new permissions: %+v", got)
	}
	if sum := veteran.Status().Permissions; sum.Requested != 1 || sum.Pending != 0 || sum.RequireApproval {
		t.Fatalf("summary in the status: %+v", sum)
	}

	//A plugin that is copied into the plugin folder afterwards
	installChaos(t, m.Options.PluginDir, "newcomer", "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epAdd+"\n")
	m.ReloadPluginFromDisk()
	newcomer, err := m.GetPluginByID("test.chaos.newcomer")
	if err != nil {
		t.Fatal(err)
	}
	st = m.permissionStateOf(newcomer)
	if st.Pending != 2 || st.Withheld != 0 || !st.Requested[0].Granted || st.Requested[0].Approved {
		t.Fatalf("a new plugin: not approved, but granted while approval is not required: %+v", st)
	}
	got := audit.of(newcomer.Spec.ID)
	if len(got) != 1 || got[0].Event != "plugins.permissions.new" || got[0].Detail["count"] != "2" ||
		!strings.Contains(got[0].Detail["endpoints"], "POST "+epAdd) || !strings.HasPrefix(got[0].Detail["granted"], "yes") {
		t.Fatalf("audit entries for the new plugin: %+v", got)
	}

	//Loading the same manifest again (reload, next boot) does not report it again
	m.ReloadPluginFromDisk()
	next := newFaultManager(t)
	next.Options.PluginDir = m.Options.PluginDir
	next.Options.Database = m.Options.Database
	nextAudit := trapAudit(next)
	m.Options.Database.Write("plugins", "test.chaos.newcomer", false)
	if err := next.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if len(audit.of(newcomer.Spec.ID)) != 1 || len(nextAudit.of(newcomer.Spec.ID)) != 0 {
		t.Fatalf("the same new permissions were reported more than once: %+v / %+v", audit.of(newcomer.Spec.ID), nextAudit.of(newcomer.Spec.ID))
	}
	again, _ := next.GetPluginByID("test.chaos.newcomer")
	if st := next.permissionStateOf(again); st.Pending != 2 {
		t.Fatalf("after a restart of Zoraxy the new plugin must still wait for a review: %+v", st)
	}
	if st := next.permissionStateOf(mustPlugin(t, next, "test.chaos.veteran")); st.Pending != 0 {
		t.Fatalf("after a restart of Zoraxy the baseline must hold: %+v", st)
	}
}

func mustPlugin(t *testing.T, m *Manager, id string) *Plugin {
	t.Helper()
	p, err := m.GetPluginByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Default: an update that asks for one more endpoint gets it, and it is reported
func TestFaultPermissionAddedByAnUpdateIsGrantedAndReportedByDefault(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	p := startChaos(t, m, "syncer", "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+"\n", "t")
	m.markPermissionBaseline()
	waitHealth(t, p, HealthOK)
	if sum := p.Status().Permissions; sum.Pending != 0 || sum.Requested != 1 {
		t.Fatalf("before the update: %+v", sum)
	}

	storeUpdate(t, m, p, "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epAdd+"\n")
	waitHealth(t, p, HealthOK)
	key := jsonString(startedWith(t, p.RootDir)["api_key"])
	if !keyOpens(m, key, http.MethodGet, epList) || !keyOpens(m, key, http.MethodPost, epAdd) {
		t.Fatal("without the approval option an update must get what its manifest asks for, as before")
	}
	sum := p.Status().Permissions
	if sum.Requested != 2 || sum.Pending != 1 || sum.Withheld != 0 || sum.RequireApproval {
		t.Fatalf("after the update: %+v", sum)
	}
	got := audit.of(p.Spec.ID)
	if len(got) != 1 || got[0].Detail["endpoints"] != "POST "+epAdd || !strings.HasPrefix(got[0].Detail["granted"], "yes") {
		t.Fatalf("audit entry for the added permission: %+v", got)
	}

	//Approving it clears the badge and changes nothing else
	if body := postForm(m.HandlePluginPermissions, url.Values{"plugin_id": {p.Spec.ID}, "action": {"approve"}}); strings.Contains(body, "error") {
		t.Fatal(body)
	}
	if sum := p.Status().Permissions; sum.Pending != 0 {
		t.Fatalf("after the approval: %+v", sum)
	}
	if !keyOpens(m, key, http.MethodPost, epAdd) {
		t.Fatal("the approval took a permission away")
	}
}

// Opt-in: an update that adds blacklist/ip/add does not get it until an administrator approves it
func TestFaultPermissionAddedByAnUpdateIsNotGrantedUntilApproved(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	p := startChaos(t, m, "syncer", "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+"\n", "t")
	m.markPermissionBaseline()
	waitHealth(t, p, HealthOK)
	if body := postForm(m.HandlePluginSettings, url.Values{"require_permission_approval": {"true"}}); strings.Contains(body, "error") {
		t.Fatal(body)
	}
	//Turning the option on does not cut off what the plugin already had
	before := jsonString(startedWith(t, p.RootDir)["api_key"])
	if !keyOpens(m, before, http.MethodGet, epList) {
		t.Fatal("turning approval on took the baseline permission away")
	}

	storeUpdate(t, m, p, "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epAdd+";POST "+epRemove+"\n")
	waitHealth(t, p, HealthOK)
	var key string
	eventually(t, 3*time.Second, "the updated plugin to record its new API key", func() bool {
		key = jsonString(startedWith(t, p.RootDir)["api_key"])
		return key != "" && key != before
	})
	if !keyOpens(m, key, http.MethodGet, epList) {
		t.Fatal("the approved endpoint must keep working after the update")
	}
	if keyOpens(m, key, http.MethodPost, epAdd) || keyOpens(m, key, http.MethodPost, epRemove) {
		t.Fatal("an endpoint added by an update was granted without approval")
	}
	sum := p.Status().Permissions
	if sum.Requested != 3 || sum.Pending != 2 || sum.Withheld != 2 || !sum.RequireApproval {
		t.Fatalf("status after the update: %+v", sum)
	}
	got := audit.of(p.Spec.ID)
	if len(got) != 1 || got[0].Detail["count"] != "2" || !strings.HasPrefix(got[0].Detail["granted"], "no") {
		t.Fatalf("audit entry: %+v", got)
	}

	//The permission view of the admin API
	var view PermissionState
	getJSON(t, m.HandlePluginPermissions, "plugin_id="+url.QueryEscape(p.Spec.ID), &view)
	if len(view.Requested) != 3 || !view.Requested[0].Granted || view.Requested[1].Granted || view.Requested[1].Approved || view.Requested[1].Endpoint != epAdd || view.Requested[1].Reason == "" {
		t.Fatalf("permission view: %+v", view)
	}

	//Approve one of the two: it works at once, with the same key and the same process
	pid := p.Status().PID
	one, _ := json.Marshal([]PermissionKey{{Method: http.MethodPost, Endpoint: epAdd}})
	if body := postForm(m.HandlePluginPermissions, url.Values{"plugin_id": {p.Spec.ID}, "action": {"approve"}, "endpoints": {string(one)}}); strings.Contains(body, "error") {
		t.Fatal(body)
	}
	if !keyOpens(m, key, http.MethodPost, epAdd) || keyOpens(m, key, http.MethodPost, epRemove) {
		t.Fatal("approving one endpoint must grant exactly that one")
	}
	if st := p.Status(); st.PID != pid || st.Permissions.Pending != 1 || st.Permissions.Withheld != 1 {
		t.Fatalf("after approving one endpoint: %+v", st)
	}

	//Requests that make no sense are refused and change nothing
	bogus, _ := json.Marshal([]PermissionKey{{Method: http.MethodPost, Endpoint: "/plugin/api/upstream/add"}})
	for _, form := range []url.Values{
		{"plugin_id": {p.Spec.ID}, "action": {"approve"}, "endpoints": {string(bogus)}},
		{"plugin_id": {p.Spec.ID}, "action": {"grant-everything"}},
		{"plugin_id": {p.Spec.ID}, "action": {"approve"}, "endpoints": {"not json"}},
		{"plugin_id": {"nobody"}, "action": {"approve"}},
	} {
		if body := postForm(m.HandlePluginPermissions, form); !strings.Contains(body, "error") {
			t.Fatalf("%v was accepted: %s", form, body)
		}
	}
	if keyOpens(m, key, http.MethodPost, "/plugin/api/upstream/add") || keyOpens(m, key, http.MethodPost, epRemove) {
		t.Fatal("a refused request changed what the key opens")
	}

	//Withdraw the approval again: refused at once
	if body := postForm(m.HandlePluginPermissions, url.Values{"plugin_id": {p.Spec.ID}, "action": {"revoke"}, "endpoints": {string(one)}}); strings.Contains(body, "error") {
		t.Fatal(body)
	}
	if keyOpens(m, key, http.MethodPost, epAdd) || !keyOpens(m, key, http.MethodGet, epList) {
		t.Fatal("withdrawing one approval must take away exactly that endpoint")
	}

	//Approve everything, restart: the new process gets all three
	if body := postForm(m.HandlePluginPermissions, url.Values{"plugin_id": {p.Spec.ID}, "action": {"approve"}}); strings.Contains(body, "error") {
		t.Fatal(body)
	}
	if err := m.StopPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(p.RootDir, "last-configure.json"))
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	key2 := jsonString(startedWith(t, p.RootDir)["api_key"])
	for _, ep := range []string{epAdd, epRemove} {
		if !keyOpens(m, key2, http.MethodPost, ep) {
			t.Fatalf("%s is approved but not granted after a restart", ep)
		}
	}
	if sum := p.Status().Permissions; sum.Pending != 0 || sum.Withheld != 0 {
		t.Fatalf("after approving everything: %+v", sum)
	}

	//An update that drops an endpoint and a later one that brings it back: it is new again
	storeUpdate(t, m, p, "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+"\n")
	storeUpdate(t, m, p, "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epAdd+"\n")
	waitHealth(t, p, HealthOK)
	if sum := p.Status().Permissions; sum.Requested != 2 || sum.Pending != 1 || sum.Withheld != 1 {
		t.Fatalf("an endpoint that was dropped and came back must need a new approval: %+v", sum)
	}

	//Turning the option off again grants everything the manifest asks for, at once
	key3 := jsonString(startedWith(t, p.RootDir)["api_key"])
	if keyOpens(m, key3, http.MethodPost, epAdd) {
		t.Fatal("the endpoint that came back was granted without approval")
	}
	if body := postForm(m.HandlePluginSettings, url.Values{"require_permission_approval": {"false"}}); strings.Contains(body, "error") {
		t.Fatal(body)
	}
	if !keyOpens(m, key3, http.MethodPost, epAdd) {
		t.Fatal("with the option off every endpoint of the manifest is granted")
	}
	if sum := p.Status().Permissions; sum.Pending != 1 || sum.Withheld != 0 || sum.RequireApproval {
		t.Fatalf("with the option off: %+v", sum)
	}
}

// Opt-in: a plugin installed after the baseline starts with a key that opens nothing
func TestFaultNewPluginGetsNothingUntilApprovedWhenApprovalIsRequired(t *testing.T) {
	m := newFaultManager(t)
	m.markPermissionBaseline()
	if err := m.SetSettings(func(s *ManagerSettings) { s.RequirePermissionApproval = true }); err != nil {
		t.Fatal(err)
	}
	p := startChaos(t, m, "stranger", "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epAdd+"\n", "t")
	waitHealth(t, p, HealthOK)
	key := jsonString(startedWith(t, p.RootDir)["api_key"])
	if key == "" {
		t.Fatal("the plugin must still get an API key, so its calls are answered \"not permitted\"")
	}
	if _, err := m.Options.APIKeyManager.ValidateAPIKey(key); err != nil {
		t.Fatalf("the key itself must be valid: %v", err)
	}
	if keyOpens(m, key, http.MethodGet, epList) || keyOpens(m, key, http.MethodPost, epAdd) {
		t.Fatal("a plugin nobody approved was granted API access")
	}
	if err := m.SetPluginPermissionApproval(p.Spec.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if !keyOpens(m, key, http.MethodGet, epList) || !keyOpens(m, key, http.MethodPost, epAdd) {
		t.Fatal("approved endpoints must work at once")
	}
	if st := m.permissionStateOf(p); st.Origin != permOriginAdmin || st.Pending != 0 {
		t.Fatalf("%+v", st)
	}

	//The approval is stored: the next Zoraxy start grants it without asking again
	next := newFaultManager(t)
	next.Options.Database = m.Options.Database
	if !next.Settings().RequirePermissionApproval {
		t.Fatal("the setting was not stored")
	}
	next.perm.mu.Lock()
	rec, found := next.recordLocked(p.Spec.ID)
	next.perm.mu.Unlock()
	if !found || len(rec.Approved) != 2 {
		t.Fatalf("the approval was not stored: %+v", rec)
	}
}

// A plugin without permitted endpoints is not touched by any of this
func TestFaultPluginWithoutPermissionsHasNoRecordAndNoKey(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	m.markPermissionBaseline()
	if err := m.SetSettings(func(s *ManagerSettings) { s.RequirePermissionApproval = true }); err != nil {
		t.Fatal(err)
	}
	p := startChaos(t, m, "plain", "mode=ok\n", "t")
	waitHealth(t, p, HealthOK)
	if key := jsonString(startedWith(t, p.RootDir)["api_key"]); key != "" {
		t.Fatalf("a plugin that asks for nothing got an API key: %q", key)
	}
	if m.Options.Database.KeyExists(permDBTable, p.Spec.ID) || len(audit.of(p.Spec.ID)) != 0 {
		t.Fatal("a plugin that asks for nothing must leave no record and no audit entry")
	}
	if sum := p.Status().Permissions; sum.Requested != 0 || sum.Pending != 0 || sum.Withheld != 0 {
		t.Fatalf("%+v", sum)
	}
}
