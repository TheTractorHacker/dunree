package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/auth/sso/forward"
	"github.com/TheTractorHacker/dunree/mod/auth/sso/zorxauth"
	"github.com/TheTractorHacker/dunree/mod/cluster"
	"github.com/TheTractorHacker/dunree/mod/confpack"
	"github.com/TheTractorHacker/dunree/mod/database"
)

func settingsTestDB(t *testing.T) *database.Database {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, table := range []string{"settings", "auth", zorxauth.DB_NAME, zorxauth.DB_USERS_TABLE, zorxauth.DB_BROWSER_SESSIONS_TABLE, forward.DatabaseTable, "oauth2", "oauth2_providers", "oauth2_sessions"} {
		db.NewTable(table)
	}
	return db
}

func useDB(t *testing.T, db *database.Database) {
	t.Helper()
	old := sysdb
	sysdb = db
	t.Cleanup(func() { sysdb = old })
}

func dbString(db *database.Database, table, key string) string {
	if !db.KeyExists(table, key) {
		return "<missing>"
	}
	var raw json.RawMessage
	db.Read(table, key, &raw)
	return string(raw)
}

// The export of a primary, imported on a follower with its own data, through
// the real database: what must arrive, what must stay, what must never travel.
func TestClusterSettingsExportImport(t *testing.T) {
	primary, follower := settingsTestDB(t), settingsTestDB(t)

	// ---- primary ----
	primary.Write("settings", "inbound", 8443)
	primary.Write("settings", "usetls", true)
	primary.Write("settings", "uiLanguage", "de")         //node local setting: never exported
	primary.Write("auth", "admin", "ADMIN-PASSWORD-HASH") //admin account: never exported
	primary.Write(forward.DatabaseTable, forward.DatabaseKeyAddress, "https://auth.example.com/api/verify")
	primary.Write("oauth2", "oauth2ClientSecret", "OIDC-CLIENT-SECRET")
	primary.Write("oauth2_providers", "corp", map[string]string{"id": "corp", "clientSecret": "CORP-SECRET"})
	primary.Write("oauth2_sessions", "s1", "OAUTH-SESSION") //sessions: never exported
	primary.Write(zorxauth.DB_NAME, zorxauth.OptionsKey, &zorxauth.AuthRouterOptions{EnableAuthGateway: true, GatewayPort: 5489, CookieName: "sso", ConfigFolderPath: "/primary/conf/sso/zorxauth"})
	primary.Write(zorxauth.DB_NAME, "sessions_not_before", int64(1700000000000))
	primary.Write(zorxauth.DB_NAME, "session_revocations", map[string]int64{"n:abc": 1}) //node local
	primary.Write(zorxauth.DB_BROWSER_SESSIONS_TABLE, "session_x", "BROWSER-SESSION")
	primary.Write(zorxauth.DB_USERS_TABLE, "user_alice", &zorxauth.User{ID: "a1", Username: "alice", PasswordHash: "HASH-A", TOTPSecret: "TOTP-A",
		PasskeyCredentials: []zorxauth.PasskeyCredential{{ID: []byte("cred1"), PublicKey: []byte("pk"), SignCount: 41, LastUsedAt: 1700000000}}})

	useDB(t, primary)
	files, err := exportClusterSettings()
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for name, data := range files {
		if err := validateSettingsFile(data); err != nil {
			t.Fatalf("%s does not pass the follower's validation: %v", name, err)
		}
		all += string(data)
	}
	for _, never := range []string{"ADMIN-PASSWORD-HASH", "OAUTH-SESSION", "BROWSER-SESSION", "uiLanguage", "/primary/conf", "session_revocations"} {
		if strings.Contains(all, never) {
			t.Errorf("%s must never be exported", never)
		}
	}
	for _, must := range []string{"HASH-A", "TOTP-A", "OIDC-CLIENT-SECRET", "CORP-SECRET", "auth.example.com", "8443", "sessions_not_before"} {
		if !strings.Contains(all, must) {
			t.Errorf("%s missing from the export", must)
		}
	}
	// deterministic, and a passkey login on the primary (counter, last used) does not change it
	primary.Write(zorxauth.DB_USERS_TABLE, "user_alice", &zorxauth.User{ID: "a1", Username: "alice", PasswordHash: "HASH-A", TOTPSecret: "TOTP-A",
		PasskeyCredentials: []zorxauth.PasskeyCredential{{ID: []byte("cred1"), PublicKey: []byte("pk"), SignCount: 42, LastUsedAt: 1700000999}}})
	again, _ := exportClusterSettings()
	for name := range files {
		if string(files[name]) != string(again[name]) {
			t.Errorf("%s changed although no setting changed (every follower would restart)", name)
		}
	}

	// ---- follower: own data that must survive, and data the primary replaces ----
	follower.Write("settings", "inbound", 443)
	follower.Write("settings", "uiLanguage", "fr")
	follower.Write("auth", "admin", "FOLLOWER-ADMIN")
	follower.Write("oauth2", "oauth2ClientSecret", "OLD-SECRET")
	follower.Write("oauth2", "oauth2Issuer", "https://old.example.com") //not set on the primary: removed
	follower.Write(zorxauth.DB_NAME, zorxauth.OptionsKey, &zorxauth.AuthRouterOptions{GatewayPort: 15489, ConfigFolderPath: "/follower/conf/sso/zorxauth"})
	follower.Write(zorxauth.DB_NAME, "session_revocations", map[string]int64{"n:mine": 2})
	follower.Write(zorxauth.DB_USERS_TABLE, "user_alice", &zorxauth.User{ID: "a1", Username: "alice", PasswordHash: "OLD",
		PasskeyCredentials: []zorxauth.PasskeyCredential{{ID: []byte("cred1"), PublicKey: []byte("pk"), SignCount: 7, LastUsedAt: 5}}})
	follower.Write(zorxauth.DB_USERS_TABLE, "user_gone", &zorxauth.User{ID: "g", Username: "gone"})

	useDB(t, follower)
	// a hostile or newer primary cannot reach other tables
	files["evil.json"] = []byte(`{"auth":{"admin":"TAKEOVER"}}`)
	files["sso.json"] = []byte(strings.Replace(string(files["sso.json"]), `{`, `{"auth":{"admin":"TAKEOVER"},`, 1))
	if err := importClusterSettings(files, false); err != nil {
		t.Fatal(err)
	}
	if got := dbString(follower, "auth", "admin"); got != `"FOLLOWER-ADMIN"` {
		t.Fatalf("admin account changed by the sync: %s", got)
	}
	if dbString(follower, "settings", "inbound") != "8443" || dbString(follower, "settings", "uiLanguage") != `"fr"` {
		t.Error("listener setting not imported or a node local setting touched")
	}
	if dbString(follower, "oauth2", "oauth2ClientSecret") != `"OIDC-CLIENT-SECRET"` || dbString(follower, "oauth2", "oauth2Issuer") != "<missing>" {
		t.Error("OAuth2 settings not replaced by the primary's")
	}
	if !strings.Contains(dbString(follower, "oauth2_providers", "corp"), "CORP-SECRET") || !strings.Contains(dbString(follower, forward.DatabaseTable, forward.DatabaseKeyAddress), "auth.example.com") {
		t.Error("provider registry or forward auth not imported")
	}
	var opt zorxauth.AuthRouterOptions
	follower.Read(zorxauth.DB_NAME, zorxauth.OptionsKey, &opt)
	if !opt.EnableAuthGateway || opt.CookieName != "sso" || opt.GatewayPort != 5489 || opt.ConfigFolderPath != "/follower/conf/sso/zorxauth" {
		t.Errorf("portal options wrong after import: %+v", opt)
	}
	if dbString(follower, zorxauth.DB_NAME, "sessions_not_before") != "1700000000000" || !strings.Contains(dbString(follower, zorxauth.DB_NAME, "session_revocations"), "n:mine") {
		t.Error("log-out-all cut-off not imported or the node's own revocations touched")
	}
	var alice zorxauth.User
	follower.Read(zorxauth.DB_USERS_TABLE, "user_alice", &alice)
	if alice.PasswordHash != "HASH-A" || alice.TOTPSecret != "TOTP-A" || len(alice.PasskeyCredentials) != 1 || alice.PasskeyCredentials[0].SignCount != 7 || alice.PasskeyCredentials[0].LastUsedAt != 5 {
		t.Errorf("user not imported or the node's own passkey counter lost: %+v", alice)
	}
	if follower.KeyExists(zorxauth.DB_USERS_TABLE, "user_gone") {
		t.Error("a user deleted on the primary survived on the follower")
	}

	// keep this node's own listener: port and gateway port stay
	follower.Write("settings", "inbound", 443)
	follower.Write(zorxauth.DB_NAME, zorxauth.OptionsKey, &zorxauth.AuthRouterOptions{GatewayPort: 15489})
	if err := importClusterSettings(files, true); err != nil {
		t.Fatal(err)
	}
	follower.Read(zorxauth.DB_NAME, zorxauth.OptionsKey, &opt)
	if dbString(follower, "settings", "inbound") != "443" || opt.GatewayPort != 15489 || !opt.EnableAuthGateway {
		t.Errorf("keep local listener ignored: inbound %s, options %+v", dbString(follower, "settings", "inbound"), opt)
	}

	// what the follower exports now equals what the primary offered (no restart loop when a follower is promoted)
	useDB(t, primary)
	want, _ := exportClusterSettings()
	useDB(t, follower)
	follower.Write(zorxauth.DB_NAME, zorxauth.OptionsKey, &zorxauth.AuthRouterOptions{})
	importClusterSettings(files, false)
	got, _ := exportClusterSettings()
	if string(got["zorxauth_users.json"]) != string(want["zorxauth_users.json"]) || string(got["sso.json"]) != string(want["sso.json"]) {
		t.Errorf("round trip differs:\n%s\n%s", got["sso.json"], want["sso.json"])
	}

	// the files a follower keeps in conf/dbsync never go into a shareable config export
	if never, _ := confpack.NeverExported(cluster.SettingsRoot + "/zorxauth_users.json"); !never {
		t.Error("conf/dbsync must be on the never-export list")
	}

	// broken file: error, nothing half written is reported as success
	if err := importClusterSettings(map[string][]byte{"sso.json": []byte(`[1,2]`)}, false); err == nil {
		t.Error("malformed settings file imported")
	}
}

func TestValidateClusterPayloadSettings(t *testing.T) {
	ok := &cluster.Payload{Roots: append(cluster.ManagedRoots(false), cluster.SettingsRoot), Files: []cluster.FileEntry{{Path: cluster.SettingsRoot + "/sso.json", Data: []byte(`{"oauth2":{"a":1}}`)}}}
	if err := validateClusterPayload(ok); err != nil {
		t.Fatal(err)
	}
	bad := &cluster.Payload{Roots: ok.Roots, Files: []cluster.FileEntry{{Path: cluster.SettingsRoot + "/sso.json", Data: []byte(`{"oauth2":"not a table"}`)}}}
	if validateClusterPayload(bad) == nil {
		t.Fatal("settings file with the wrong shape accepted")
	}
}

// A follower on defaults has none of the listener keys in its database (they
// are written when an admin changes them). Its saved "own" values must say so,
// and the restore must remove what the primary's import added: otherwise the
// rolled back node keeps the primary's port and TLS mode.
func TestClusterSettingsRestoreRemovesWhatTheNodeDidNotHave(t *testing.T) {
	follower := settingsTestDB(t)
	useDB(t, follower)
	follower.Write("settings", "uiLanguage", "fr")
	follower.Write(zorxauth.DB_USERS_TABLE, "user_local", &zorxauth.User{ID: "l", Username: "local"})

	own, err := exportOwnClusterSettings()
	if err != nil {
		t.Fatal(err)
	}
	var listener settingsFile
	json.Unmarshal(own["listener.json"], &listener)
	for _, k := range []string{"inbound", "usetls", "minTLSVersion", "tlsCipherProfile", "listenP80", "redirect"} {
		if v, ok := listener["settings"][k]; !ok || string(v) != "null" {
			t.Errorf("own settings do not record that %q is not set: %s", k, own["listener.json"])
		}
	}
	// the export a primary offers stays free of such markers (older followers, content hash)
	offered, _ := exportClusterSettings()
	if strings.Contains(string(offered["listener.json"])+string(offered["sso.json"]), "null") {
		t.Errorf("a primary must not offer missing keys: %s %s", offered["listener.json"], offered["sso.json"])
	}

	primaryFiles := map[string][]byte{
		"listener.json":       []byte(`{"settings":{"inbound":21409,"usetls":true,"redirect":true}}`),
		"sso.json":            []byte(`{"zorxauth":{"options":{"gateway_port":6001,"cookie_name":"sso"},"sessions_not_before":1700000000000}}`),
		"zorxauth_users.json": []byte(`{"zorxauth_users":{"user_alice":{"Username":"alice"}}}`),
	}
	if err := importClusterSettings(primaryFiles, false); err != nil {
		t.Fatal(err)
	}
	if dbString(follower, "settings", "inbound") != "21409" || dbString(follower, zorxauth.DB_NAME, "sessions_not_before") == "<missing>" {
		t.Fatal("import did not happen")
	}

	// a marker in a normal import (a primary cannot delete keys here) is not a delete order
	if err := importClusterSettings(map[string][]byte{"listener.json": []byte(`{"settings":{"usetls":null}}`)}, false); err != nil {
		t.Fatal(err)
	}
	if !follower.KeyExists("settings", "usetls") {
		t.Error("an import must not delete keys")
	}
	follower.Write("settings", "usetls", true)

	if err := restoreClusterSettings(own, false); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"inbound", "usetls", "redirect"} {
		if got := dbString(follower, "settings", k); got != "<missing>" {
			t.Errorf("settings/%s is still the primary's after the restore: %s", k, got)
		}
	}
	for _, k := range []string{zorxauth.OptionsKey, "sessions_not_before"} {
		if got := dbString(follower, zorxauth.DB_NAME, k); got != "<missing>" {
			t.Errorf("zorxauth/%s is still the primary's after the restore: %s", k, got)
		}
	}
	if dbString(follower, "settings", "uiLanguage") != `"fr"` || !follower.KeyExists(zorxauth.DB_USERS_TABLE, "user_local") || follower.KeyExists(zorxauth.DB_USERS_TABLE, "user_alice") {
		t.Error("restore touched a node local setting or did not bring the node's own users back")
	}
}

// "Keep this node's own listening ports" switched on after an import: only the
// listener part of the saved values comes back (port, TLS mode, SSO portal
// port), the rest stays the primary's.
func TestClusterSettingsRestoreListenerOnly(t *testing.T) {
	follower := settingsTestDB(t)
	useDB(t, follower)
	follower.Write("settings", "inbound", 8080)
	follower.Write(zorxauth.DB_NAME, zorxauth.OptionsKey, &zorxauth.AuthRouterOptions{GatewayPort: 15489, CookieName: "mine"})
	own, _ := exportOwnClusterSettings()

	primaryFiles := map[string][]byte{
		"listener.json":       []byte(`{"settings":{"inbound":443,"usetls":true}}`),
		"sso.json":            []byte(`{"zorxauth":{"options":{"gateway_port":6001,"cookie_name":"sso","enable_auth_gateway":true},"sessions_not_before":1700000000000}}`),
		"zorxauth_users.json": []byte(`{"zorxauth_users":{"user_alice":{"Username":"alice"}}}`),
	}
	if err := importClusterSettings(primaryFiles, false); err != nil {
		t.Fatal(err)
	}
	if err := restoreClusterSettings(own, true); err != nil {
		t.Fatal(err)
	}
	var opt zorxauth.AuthRouterOptions
	follower.Read(zorxauth.DB_NAME, zorxauth.OptionsKey, &opt)
	if dbString(follower, "settings", "inbound") != "8080" || dbString(follower, "settings", "usetls") != "<missing>" || opt.GatewayPort != 15489 {
		t.Errorf("own listener not restored: inbound %s usetls %s gateway port %d", dbString(follower, "settings", "inbound"), dbString(follower, "settings", "usetls"), opt.GatewayPort)
	}
	if opt.CookieName != "sso" || !opt.EnableAuthGateway || !follower.KeyExists(zorxauth.DB_USERS_TABLE, "user_alice") || dbString(follower, zorxauth.DB_NAME, "sessions_not_before") != "1700000000000" {
		t.Errorf("the listener restore touched other synced settings: %+v", opt)
	}

	// a node that had no portal options of its own returns to the default port
	fresh := settingsTestDB(t)
	useDB(t, fresh)
	ownFresh, _ := exportOwnClusterSettings()
	importClusterSettings(primaryFiles, false)
	if err := restoreClusterSettings(ownFresh, true); err != nil {
		t.Fatal(err)
	}
	fresh.Read(zorxauth.DB_NAME, zorxauth.OptionsKey, &opt)
	if opt.GatewayPort != 5489 || opt.CookieName != "sso" || dbString(fresh, "settings", "inbound") != "<missing>" {
		t.Errorf("node on defaults: gateway port %d cookie %q inbound %s", opt.GatewayPort, opt.CookieName, dbString(fresh, "settings", "inbound"))
	}
}

// The whole path a start takes on a follower (clusterImportSettings with the
// real manager and database): import, then the snapshot is rolled back and the
// node on defaults must not keep the primary's port.
func TestClusterImportSettingsRollbackOnAFollowerOnDefaults(t *testing.T) {
	db := settingsTestDB(t)
	useDB(t, db)
	conf := t.TempDir()
	secret := strings.Repeat("s", 40)
	os.WriteFile(filepath.Join(conf, "cluster.json"), []byte(`{"role":"follower","secret":"`+secret+`","primaryUrl":"https://127.0.0.1:1"}`), 0o600)
	os.MkdirAll(filepath.Join(conf, cluster.StateDirName), 0o700)
	os.WriteFile(filepath.Join(conf, cluster.StateDirName, "follower.json"), []byte(`{"appliedVersion":1,"settingsSynced":true}`), 0o600)
	os.MkdirAll(filepath.Join(conf, cluster.SettingsRoot), 0o700)
	os.WriteFile(filepath.Join(conf, cluster.SettingsRoot, "listener.json"), []byte(`{"settings":{"inbound":21409,"usetls":true}}`), 0o600)
	mgr, err := cluster.NewManager(cluster.Options{ConfDir: conf, NodeID: "f1", ExportSettings: exportClusterSettings})
	if err != nil {
		t.Fatal(err)
	}
	old := clusterMgr
	clusterMgr = mgr
	t.Cleanup(func() { clusterMgr = old })

	clusterImportSettings()
	if dbString(db, "settings", "inbound") != "21409" {
		t.Fatalf("not imported: %s", dbString(db, "settings", "inbound"))
	}
	baseline, _ := os.ReadFile(filepath.Join(conf, cluster.StateDirName, "dbsync-baseline.json"))
	if !strings.Contains(string(baseline), `"inbound":null`) {
		t.Fatalf("baseline does not record the missing keys: %s", baseline)
	}
	os.RemoveAll(filepath.Join(conf, cluster.SettingsRoot)) //what the rollback of the snapshot does
	clusterImportSettings()
	if got := dbString(db, "settings", "inbound"); got != "<missing>" {
		t.Errorf("rolled back, but the node still listens on the primary's port: %s", got)
	}
	if got := dbString(db, "settings", "usetls"); got != "<missing>" {
		t.Errorf("rolled back, but the node still has the primary's TLS mode: %s", got)
	}
}
