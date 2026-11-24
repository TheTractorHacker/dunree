package cluster

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDB stands in for the database of a node: file name -> content.
type fakeDB struct {
	mu       sync.Mutex
	data     map[string]string
	imports  int
	keep     []bool
	restores []bool
	fail     bool
}

func (d *fakeDB) export() (map[string][]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range d.data {
		out[k] = []byte(v)
	}
	return out, nil
}

func (d *fakeDB) imp(files map[string][]byte, keepLocalListener bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return errors.New("database is read-only")
	}
	d.imports++
	d.keep = append(d.keep, keepLocalListener)
	own, hasOwn := d.data[listenerFile]
	d.data = map[string]string{}
	for k, v := range files {
		d.data[k] = string(v)
	}
	if keepLocalListener {
		delete(d.data, listenerFile)
		if hasOwn {
			d.data[listenerFile] = own
		}
	}
	return nil
}

const listenerFile = "listener.json"

func (d *fakeDB) restore(saved map[string][]byte, listenerOnly bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return errors.New("database is read-only")
	}
	d.restores = append(d.restores, listenerOnly)
	if !listenerOnly {
		d.data = map[string]string{}
	}
	delete(d.data, listenerFile)
	for k, v := range saved {
		if !listenerOnly || k == listenerFile {
			d.data[k] = string(v)
		}
	}
	return nil
}

func (d *fakeDB) store() SettingsStore {
	return SettingsStore{Export: d.export, Import: d.imp, Restore: d.restore}
}

func (d *fakeDB) set(k, v string) { d.mu.Lock(); d.data[k] = v; d.mu.Unlock() }
func (d *fakeDB) get(k string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.data[k]
}

const primaryUsers = `{"zorxauth_users":{"user_alice":{"username":"alice","passwordHash":"HASH-ALICE"}}}`

// settingsPair is newPair with a database on each side and SSO files on the primary.
func settingsPair(t *testing.T, on bool) (*pair, *fakeDB, *fakeDB) {
	t.Helper()
	p := newPair(t, false)
	pdb := &fakeDB{data: map[string]string{"sso.json": `{"oauth2":{"oauth2ClientSecret":"CLIENT-SECRET"}}`, "zorxauth_users.json": primaryUsers}}
	fdb := &fakeDB{data: map[string]string{"sso.json": `{"oauth2":{}}`, "zorxauth_users.json": `{"zorxauth_users":{"user_local":{"username":"local"}}}`}}
	p.primary.opt.ExportSettings = pdb.export
	p.follower.opt.ExportSettings = fdb.export
	os.MkdirAll(filepath.Join(p.pDir, "sso", "zorxauth", "grouppolicy"), 0o755)
	os.WriteFile(filepath.Join(p.pDir, "sso", "zorxauth", "grouppolicy", "g1.json"), []byte(`{"id":"g1"}`), 0o600)
	os.MkdirAll(filepath.Join(p.fDir, "sso", "zorxauth", "grouppolicy"), 0o755)
	os.WriteFile(filepath.Join(p.fDir, "sso", "zorxauth", "grouppolicy", "local.json"), []byte(`{"id":"local"}`), 0o600)
	if on {
		yes := true
		if err := p.primary.Update(ConfigUpdate{SyncSettings: &yes}); err != nil {
			t.Fatal(err)
		}
	}
	return p, pdb, fdb
}

func (p *pair) tick() { p.fClock.Add(time.Second); p.pClock.Add(time.Second) }

func importOn(t *testing.T, m *Manager, db *fakeDB) bool {
	t.Helper()
	changed, err := m.ImportSyncedSettings(db.store())
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestSettingsSyncIsOffByDefault(t *testing.T) {
	p, _, fdb := settingsPair(t, false)
	// a leftover folder (node used to be a follower) must never be offered either
	os.MkdirAll(filepath.Join(p.pDir, SettingsRoot), 0o755)
	os.WriteFile(filepath.Join(p.pDir, SettingsRoot, "stale.json"), []byte(`{"stale":true}`), 0o600)

	raw, _, payload, err := p.primary.primary.current(false)
	if err != nil {
		t.Fatal(err)
	}
	if payload.IncludesSettings {
		t.Fatal("settings in the snapshot although sync settings is off")
	}
	for _, f := range payload.Files {
		if strings.HasPrefix(f.Path, SettingsRoot+"/") || strings.HasPrefix(f.Path, ssoRoot+"/") {
			t.Fatalf("%s is in the snapshot although sync settings is off", f.Path)
		}
	}
	for _, r := range payload.Roots {
		if r == SettingsRoot || r == ssoRoot {
			t.Fatalf("root %s declared although sync settings is off", r)
		}
	}
	if strings.Contains(string(raw), "CLIENT-SECRET") {
		t.Fatal("secret in the envelope")
	}
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "sso/zorxauth/grouppolicy/local.json") == "<missing>" || readFile(t, p.fDir, "dbsync/sso.json") != "<missing>" {
		t.Fatal("follower SSO files touched although sync settings is off")
	}
	if importOn(t, p.follower, fdb) || fdb.imports != 0 || p.follower.Status().SettingsSynced {
		t.Fatal("import ran although sync settings is off")
	}
	if _, err := os.Stat(filepath.Join(p.fDir, StateDirName, settingsBaselineFile)); err == nil {
		t.Fatal("state file created although sync settings is off")
	}
}

func TestSettingsSyncEndToEnd(t *testing.T) {
	p, pdb, fdb := settingsPair(t, true)

	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if !p.follower.Status().SettingsSynced || p.reloads.Load() != 1 {
		t.Fatalf("settings snapshot not applied: %+v", p.follower.Status())
	}
	if readFile(t, p.fDir, "dbsync/zorxauth_users.json") != primaryUsers {
		t.Fatal("settings file did not reach the follower")
	}
	if fi, err := os.Stat(filepath.Join(p.fDir, "dbsync", "zorxauth_users.json")); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("settings file must not be readable by others: %v", fi.Mode())
	}
	// group policies the users refer to travel along; primary wins
	if readFile(t, p.fDir, "sso/zorxauth/grouppolicy/g1.json") != `{"id":"g1"}` || readFile(t, p.fDir, "sso/zorxauth/grouppolicy/local.json") != "<missing>" {
		t.Fatal("SSO files not replaced by the primary's")
	}
	// nothing is written to the primary's own conf folder
	if readFile(t, p.pDir, "dbsync/zorxauth_users.json") != "<missing>" {
		t.Fatal("primary wrote its export to disk")
	}
	// the files alone change nothing: the import happens at the restart
	if fdb.get("zorxauth_users.json") == primaryUsers {
		t.Fatal("database changed before the restart")
	}
	if !importOn(t, p.follower, fdb) || fdb.get("zorxauth_users.json") != primaryUsers || fdb.get("sso.json") != pdb.get("sso.json") {
		t.Fatal("import did not bring the primary's settings into the database")
	}
	// the node's own values were saved first
	base := readFile(t, p.fDir, ".cluster/"+settingsBaselineFile)
	if !strings.Contains(base, "user_local") {
		t.Fatalf("own settings not saved before the import: %s", base)
	}
	// every later start: nothing to do
	if importOn(t, p.follower, fdb) || fdb.imports != 1 {
		t.Fatal("unchanged settings imported again")
	}

	// unchanged settings keep the version (no restart loop)
	v1 := p.follower.Status().AppliedVersion
	p.tick()
	if err := p.sync(t); err != nil || p.reloads.Load() != 1 || p.follower.Status().AppliedVersion != v1 {
		t.Fatalf("unchanged settings caused a new apply: %v", err)
	}

	// a change on the primary: new version, restart, import
	pdb.set("zorxauth_users.json", `{"zorxauth_users":{"user_bob":{"username":"bob"}}}`)
	p.tick()
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if p.reloads.Load() != 2 || p.follower.Status().AppliedVersion <= v1 {
		t.Fatal("settings change did not produce a new snapshot version")
	}
	if !importOn(t, p.follower, fdb) || !strings.Contains(fdb.get("zorxauth_users.json"), "user_bob") {
		t.Fatal("changed settings not imported")
	}
	// the baseline is the state before the FIRST import, it is not overwritten
	if readFile(t, p.fDir, ".cluster/"+settingsBaselineFile) != base {
		t.Fatal("baseline overwritten by a later import")
	}

	// only followers import
	if changed, _ := p.primary.ImportSyncedSettings(pdb.store()); changed || pdb.imports != 0 {
		t.Fatal("primary imported settings")
	}
}

func TestSettingsSyncRollback(t *testing.T) {
	p, _, fdb := settingsPair(t, true)

	// reload fails: files rolled back, database never touched
	p.failReload.Store(true)
	if err := p.sync(t); err == nil {
		t.Fatal("want reload error")
	}
	if readFile(t, p.fDir, "dbsync/sso.json") != "<missing>" || readFile(t, p.fDir, "sso/zorxauth/grouppolicy/local.json") == "<missing>" {
		t.Fatal("settings files not rolled back")
	}
	if importOn(t, p.follower, fdb) || fdb.imports != 0 || !strings.Contains(fdb.get("zorxauth_users.json"), "user_local") {
		t.Fatal("database changed although the snapshot was rolled back")
	}

	// applied and imported, then the boot guard undoes the snapshot (start never became healthy)
	p.failReload.Store(false)
	p.tick()
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	importOn(t, p.follower, fdb)
	if fdb.get("zorxauth_users.json") != primaryUsers {
		t.Fatal("not imported")
	}
	var pend pendingApply
	json.Unmarshal([]byte(readFile(t, p.fDir, ".cluster/pending.json")), &pend)
	if err := restoreBackup(p.fDir, pend.BackupDir, pend.Roots); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "dbsync/sso.json") != "<missing>" {
		t.Fatal("boot guard left the settings files")
	}
	if !importOn(t, p.follower, fdb) || !strings.Contains(fdb.get("zorxauth_users.json"), "user_local") {
		t.Fatalf("own settings not restored after the rollback: %s", fdb.get("zorxauth_users.json"))
	}
	if importOn(t, p.follower, fdb) {
		t.Fatal("restore ran twice")
	}

	// a failing import is reported and retried on the next start
	p.tick()
	p.follower.mu.Lock()
	p.follower.status.RejectedHash, p.follower.status.AppliedHash = "", ""
	p.follower.mu.Unlock()
	if err := p.follower.SyncOnce(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	fdb.fail = true
	if _, err := p.follower.ImportSyncedSettings(fdb.store()); err == nil {
		t.Fatal("import error swallowed")
	}
	fdb.fail = false
	if !importOn(t, p.follower, fdb) {
		t.Fatal("failed import not retried")
	}
}

func TestSettingsSyncKeepLocalListenerAndGuard(t *testing.T) {
	p, _, fdb := settingsPair(t, true)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	g := p.follower.GuardLocalEdits(next)
	do := func(method, path string) int {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}
	// before any settings arrived the SSO pages stay editable (as before this feature)
	for _, path := range []string{"/api/sso/zorxauth/users/create", "/api/sso/OAuth2", "/api/proxy/setIncoming", "/api/cert/tls"} {
		if c := do("POST", path); c != 204 {
			t.Errorf("POST %s without synced settings: want 204 got %d", path, c)
		}
	}
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	importOn(t, p.follower, fdb)
	for _, path := range []string{"/api/sso/zorxauth/users/create", "/api/sso/OAuth2", "/api/sso/forward-auth", "/api/sso/zorxauth/grouppolicy/delete", "/api/proxy/setIncoming", "/api/cert/tls"} {
		if c := do("POST", path); c != 403 {
			t.Errorf("POST %s with synced settings: want 403 got %d", path, c)
		}
	}
	if do("GET", "/api/sso/zorxauth/users/list") != 204 || do("POST", "/api/proxy/timeouts") != 204 {
		t.Error("reads and node local settings must stay allowed")
	}

	// keep this node's own listener: passed to the import, port editable again, re-imported at the next start
	yes := true
	if err := p.follower.Update(ConfigUpdate{KeepLocalListener: &yes}); err != nil {
		t.Fatal(err)
	}
	if do("POST", "/api/proxy/setIncoming") != 204 || do("POST", "/api/sso/OAuth2") != 403 {
		t.Error("keep local listener must free the listener settings and nothing else")
	}
	if !importOn(t, p.follower, fdb) || len(fdb.keep) != 2 || fdb.keep[0] || !fdb.keep[1] {
		t.Fatalf("keep local listener not passed to the import: %v", fdb.keep)
	}

	// the primary stops syncing settings: the follower keeps the last values and may edit them again
	no := false
	if err := p.primary.Update(ConfigUpdate{SyncSettings: &no}); err != nil {
		t.Fatal(err)
	}
	p.tick()
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if p.follower.Status().SettingsSynced || do("POST", "/api/sso/OAuth2") != 204 {
		t.Error("follower still read-only after the primary stopped syncing settings")
	}
	if readFile(t, p.fDir, "dbsync/zorxauth_users.json") != primaryUsers || importOn(t, p.follower, fdb) {
		t.Error("stopping the settings sync must leave the last synced values alone")
	}
}

func TestSettingsSyncAPIAndValidation(t *testing.T) {
	p, _, _ := settingsPair(t, false)
	post := func(m *Manager, form url.Values) string {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/cluster/config", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		m.HandleConfig(w, r)
		return w.Body.String()
	}
	if out := post(p.primary, url.Values{"syncSettings": {"true"}}); !strings.Contains(out, "ackSyncSettings") || p.primary.Config().SyncSettings {
		t.Fatalf("sync settings switched on without the acknowledgement: %s", out)
	}
	if out := post(p.primary, url.Values{"syncSettings": {"true"}, "ackSyncSettings": {"true"}}); strings.Contains(out, "error") || !p.primary.Config().SyncSettings {
		t.Fatalf("acknowledged request refused: %s", out)
	}
	w := httptest.NewRecorder()
	p.primary.HandleStatus(w, httptest.NewRequest("GET", "/api/cluster/status", nil))
	if !strings.Contains(w.Body.String(), `"syncSettings":true`) || strings.Contains(w.Body.String(), "CLIENT-SECRET") || strings.Contains(w.Body.String(), "HASH-ALICE") {
		t.Fatalf("status wrong or leaks settings: %s", w.Body.String())
	}
	// persisted, and a build without the export hook refuses
	if !strings.Contains(readFile(t, p.pDir, "cluster.json"), `"syncSettings": true`) {
		t.Fatal("not persisted")
	}
	p.follower.opt.ExportSettings = nil
	if out := post(p.follower, url.Values{"syncSettings": {"true"}, "ackSyncSettings": {"true"}}); !strings.Contains(out, "error") {
		t.Fatal("build without export hook accepted sync settings")
	}

	// a failing or invalid export fails the snapshot instead of sending half of it
	p.primary.opt.ExportSettings = func() (map[string][]byte, error) { return nil, errors.New("db closed") }
	if _, _, _, err := p.primary.primary.current(false); err == nil {
		t.Fatal("export error swallowed")
	}
	for _, name := range []string{"../cluster.json", "a/b.json", "users.txt", ""} {
		p.primary.opt.ExportSettings = func() (map[string][]byte, error) { return map[string][]byte{name: []byte(`{}`)}, nil }
		if _, _, _, err := p.primary.primary.current(false); err == nil {
			t.Fatalf("export file name %q accepted", name)
		}
	}
	p.primary.opt.ExportSettings = func() (map[string][]byte, error) { return map[string][]byte{"sso.json": []byte(`{broken`)}, nil }
	if _, _, _, err := p.primary.primary.current(false); err == nil {
		t.Fatal("invalid JSON accepted")
	}

	// the follower re-validates paths under the settings root
	for _, bad := range []string{"dbsync/../cluster.json", "dbsync/a/b.json", "dbsync/x.sh", "dbsync"} {
		if validEntryPath(bad, managedRoots(true, true)) {
			t.Errorf("path %q accepted", bad)
		}
	}
	if !validEntryPath("dbsync/sso.json", managedRoots(false, true)) || validEntryPath("dbsync/sso.json", ManagedRoots(true)) {
		t.Error("settings root must be valid only when the snapshot declares it")
	}
}

// "Keep this node's own listening ports" switched on AFTER an import must bring
// the node's own listener settings back, also the ones it changed while the
// switch was on earlier, and a rollback must not lose them.
func TestSettingsSyncKeepListenerSwitchedOnLater(t *testing.T) {
	p, pdb, fdb := settingsPair(t, true)
	pdb.set(listenerFile, `{"settings":{"inbound":443}}`)
	fdb.set(listenerFile, `{"settings":{"inbound":null}}`) //a node on defaults: the key does not exist
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	importOn(t, p.follower, fdb)
	if fdb.get(listenerFile) != `{"settings":{"inbound":443}}` {
		t.Fatalf("listener not imported: %s", fdb.get(listenerFile))
	}
	keep := func(on bool) {
		t.Helper()
		if err := p.follower.Update(ConfigUpdate{KeepLocalListener: &on}); err != nil {
			t.Fatal(err)
		}
	}

	keep(true)
	if !importOn(t, p.follower, fdb) || fdb.get(listenerFile) != `{"settings":{"inbound":null}}` {
		t.Fatalf("own listener not restored from the baseline: %s", fdb.get(listenerFile))
	}
	if len(fdb.restores) != 1 || !fdb.restores[0] || fdb.get("zorxauth_users.json") != primaryUsers {
		t.Fatalf("only the listener part may be restored: %v %s", fdb.restores, fdb.get("zorxauth_users.json"))
	}
	if importOn(t, p.follower, fdb) {
		t.Fatal("restore repeated at the next start")
	}

	// changed locally while the switch is on, then off and on again: the latest own value comes back
	fdb.set(listenerFile, `{"settings":{"inbound":9090}}`)
	keep(false)
	if !importOn(t, p.follower, fdb) || fdb.get(listenerFile) != `{"settings":{"inbound":443}}` {
		t.Fatalf("switch off: the primary's listener must apply: %s", fdb.get(listenerFile))
	}
	keep(true)
	if !importOn(t, p.follower, fdb) || fdb.get(listenerFile) != `{"settings":{"inbound":9090}}` {
		t.Fatalf("latest own listener not restored: %s", fdb.get(listenerFile))
	}

	// off again, a failing import in between must not make the retry save the primary's values as "own"
	keep(false)
	fdb.fail = true
	if _, err := p.follower.ImportSyncedSettings(fdb.store()); err == nil {
		t.Fatal("want import error")
	}
	fdb.fail = false
	fdb.set(listenerFile, `{"settings":{"inbound":443}}`) //what a half finished import leaves behind
	importOn(t, p.follower, fdb)

	// rollback of the settings snapshot: own users from the baseline, own listener as last saved
	if err := os.RemoveAll(filepath.Join(p.fDir, SettingsRoot)); err != nil {
		t.Fatal(err)
	}
	if !importOn(t, p.follower, fdb) || !strings.Contains(fdb.get("zorxauth_users.json"), "user_local") {
		t.Fatalf("own settings not restored: %s", fdb.get("zorxauth_users.json"))
	}
	if fdb.get(listenerFile) != `{"settings":{"inbound":9090}}` {
		t.Fatalf("rollback lost the node's latest own listener: %s", fdb.get(listenerFile))
	}
	for _, f := range []string{settingsAppliedFile, settingsBaselineFile, settingsOwnListenerFile} {
		if readFile(t, p.fDir, ".cluster/"+f) != "<missing>" {
			t.Errorf("%s left behind after the rollback", f)
		}
	}
}

// Once the primary stopped syncing settings, the files in conf/dbsync are old:
// nothing may be imported from them again (the follower's settings are
// editable by then), whatever is toggled. A resumed sync imports again.
func TestSettingsSyncStaleFilesAreNotImportedAgain(t *testing.T) {
	p, pdb, fdb := settingsPair(t, true)
	pdb.set(listenerFile, `{"settings":{"inbound":443}}`)
	fdb.set(listenerFile, `{"settings":{"inbound":8080}}`)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	importOn(t, p.follower, fdb)
	off, on := false, true
	if err := p.primary.Update(ConfigUpdate{SyncSettings: &off}); err != nil {
		t.Fatal(err)
	}
	p.tick()
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	fdb.set("zorxauth_users.json", "EDITED-ON-THE-FOLLOWER")
	imports := fdb.imports
	if err := p.follower.Update(ConfigUpdate{KeepLocalListener: &on}); err != nil {
		t.Fatal(err)
	}
	if !importOn(t, p.follower, fdb) || fdb.get(listenerFile) != `{"settings":{"inbound":8080}}` {
		t.Fatalf("own listener not restored: %s", fdb.get(listenerFile))
	}
	if fdb.imports != imports || fdb.get("zorxauth_users.json") != "EDITED-ON-THE-FOLLOWER" {
		t.Fatalf("old settings files imported again: %d imports, users %s", fdb.imports-imports, fdb.get("zorxauth_users.json"))
	}
	if importOn(t, p.follower, fdb) || fdb.imports != imports {
		t.Fatal("something ran again at the next start")
	}

	// the primary syncs settings again, unchanged: the follower must import them (its local edits end)
	if err := p.primary.Update(ConfigUpdate{SyncSettings: &on}); err != nil {
		t.Fatal(err)
	}
	p.tick()
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if !importOn(t, p.follower, fdb) || fdb.get("zorxauth_users.json") != primaryUsers {
		t.Fatalf("resumed settings sync not imported: %s", fdb.get("zorxauth_users.json"))
	}
	if fdb.get(listenerFile) != `{"settings":{"inbound":8080}}` {
		t.Fatalf("keep own listener ignored after the resume: %s", fdb.get(listenerFile))
	}
}

// Signed SSO portal sessions are opt-in: a cluster secret alone must not
// switch them on (it would change what a logout reaches), and the switch
// counts as of process start.
func TestSharedSSOSessionsAreOptIn(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Options{ConfDir: dir, NodeID: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	on := true
	if err := m.Update(ConfigUpdate{SharedSSOSessions: &on}); err == nil {
		t.Fatal("switching it on without a cluster secret must be refused")
	}
	if err := m.Update(ConfigUpdate{Secret: strPtr(testSecret)}); err != nil {
		t.Fatal(err)
	}
	reopen := func() *Manager {
		t.Helper()
		m, err := NewManager(Options{ConfDir: dir, NodeID: "n1"})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m = reopen()
	if _, ok := m.SharedSSOSessionKey("uuid"); ok || m.SharedSSOSessionsActive() || m.Config().SharedSSOSessions {
		t.Fatal("a cluster secret alone must not enable shared SSO sessions")
	}
	if m.KeyMaterial("uuid", PurposeCaptchaSession) == "uuid" {
		t.Fatal("the other session keys must still follow the secret")
	}
	if err := m.Update(ConfigUpdate{SharedSSOSessions: &on}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.SharedSSOSessionKey("uuid"); ok || !m.SharedSSORestartRequired() {
		t.Fatal("the switch must only count from the next start")
	}
	m = reopen()
	key, ok := m.SharedSSOSessionKey("uuid")
	if !ok || string(key) != KeyMaterial(testSecret, "uuid", PurposeZorxAuth) || m.SharedSSORestartRequired() {
		t.Fatalf("switched on and restarted: want the derived key, got ok=%v", ok)
	}
	other := reopen()
	if k2, _ := other.SharedSSOSessionKey("another-uuid"); string(k2) != string(key) {
		t.Fatal("two nodes with the same secret must derive the same key")
	}

	// API: status fields and the form field
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/cluster/config", strings.NewReader("sharedSsoSessions=false"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m.HandleConfig(w, req)
	w = httptest.NewRecorder()
	m.HandleStatus(w, httptest.NewRequest("GET", "/api/cluster/status", nil))
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["sharedSsoSessions"] != false || st["sharedSsoActive"] != true || st["sharedSsoRestart"] != true {
		t.Fatalf("status after switching off: %v %v %v", st["sharedSsoSessions"], st["sharedSsoActive"], st["sharedSsoRestart"])
	}
}
