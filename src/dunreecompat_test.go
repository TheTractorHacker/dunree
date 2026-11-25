package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/auth"
	"github.com/TheTractorHacker/dunree/mod/baseline"
	db "github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
	"github.com/TheTractorHacker/dunree/mod/legacycompat"
	"github.com/gorilla/csrf"
)

// The cookie names are a contract with the browsers of existing installs. The old names are pinned here:
// changing one of them logs every administrator of an upgraded install out.
func TestAdminCookieNamesPinned(t *testing.T) {
	if ADMIN_SESSION_COOKIE != "dunree_session" || CSRF_COOKIENAME != "dunree_csrf" {
		t.Fatalf("current cookie names changed: %q %q", ADMIN_SESSION_COOKIE, CSRF_COOKIENAME)
	}
	if LEGACY_ADMIN_SESSION_COOKIE != "Zoraxy" || LEGACY_CSRF_COOKIENAME != "zoraxy_csrf" { // legacy-compat
		t.Fatalf("legacy cookie names changed: %q %q", LEGACY_ADMIN_SESSION_COOKIE, LEGACY_CSRF_COOKIENAME)
	}
}

// End to end on the admin handler chain of main(): an administrator who logged in and opened a page on the
// build before the rename can keep using that page afterwards (session and CSRF token both still valid),
// and the browser ends up with the Dunree cookie names.
func TestUpgradedAdminBrowserKeepsWorking(t *testing.T) {
	sysdb, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sysdb.Close()
	lg, _ := logger.NewFmtLogger()
	oldProfile := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	defer func() { auth.ProfileAdmin = oldProfile }()
	sessionKey := []byte("0123456789abcdef0123456789abcdef")
	nodeKey := []byte("0b0c9a1e-2222-4333-8444-555566667777") //sys.uuid, the CSRF key

	//--- the build before the rename
	oldAgent := auth.NewAuthenticationAgent(LEGACY_ADMIN_SESSION_COOKIE, sessionKey, sysdb, false, lg, nil)
	oldAgent.CreateUserAccount("root", "password-1", "")
	form := url.Values{"username": {"root"}, "password": {"password-1"}}
	lr := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(form.Encode()))
	lr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lr.RemoteAddr = "198.51.100.1:1234"
	lw := httptest.NewRecorder()
	oldAgent.HandleLogin(lw, lr)
	var oldSession *http.Cookie
	for _, c := range lw.Result().Cookies() {
		if c.Name == LEGACY_ADMIN_SESSION_COOKIE && c.Value != "" {
			oldSession = c
		}
	}
	if oldSession == nil {
		t.Fatalf("setup: no session from the old build: %s", lw.Body.String())
	}
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(csrf.Token(r))) })
	pw := httptest.NewRecorder()
	csrf.Protect(nodeKey, csrf.CookieName(LEGACY_CSRF_COOKIENAME), csrf.Secure(false), csrf.Path("/"), csrf.SameSite(csrf.SameSiteLaxMode))(page).
		ServeHTTP(pw, httptest.NewRequest("GET", "http://admin.test/", nil))
	var oldCSRF *http.Cookie
	for _, c := range pw.Result().Cookies() {
		if c.Name == LEGACY_CSRF_COOKIENAME {
			oldCSRF = c
		}
	}
	token := pw.Body.String()
	if oldCSRF == nil || token == "" {
		t.Fatal("setup: no CSRF cookie from the old build")
	}

	//--- Dunree on the same database and sys.uuid, wired as in main()
	agent := auth.NewAuthenticationAgent(ADMIN_SESSION_COOKIE, sessionKey, sysdb, false, lg, nil)
	agent.LegacySessionNames = []string{LEGACY_ADMIN_SESSION_COOKIE}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/save", func(w http.ResponseWriter, r *http.Request) {
		name, err := agent.GetUserName(w, r)
		if !agent.CheckAuth(r) || err != nil {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("saved by " + name))
	})
	chain := agent.LegacySessionMiddleware(newAdminCSRF(nodeKey, false)(mux))

	r := httptest.NewRequest("POST", "http://admin.test/api/save", strings.NewReader("x=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-CSRF-Token", token)
	r.AddCookie(oldSession)
	r.AddCookie(oldCSRF)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "saved by root" {
		t.Fatalf("a page opened before the upgrade can no longer save: %d %q", w.Code, w.Body.String())
	}
	got := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		got[c.Name] = c
	}
	if got[ADMIN_SESSION_COOKIE] == nil || got[CSRF_COOKIENAME] == nil {
		t.Fatalf("the Dunree cookies were not issued: %v", w.Result().Header["Set-Cookie"])
	}
	if c := got[LEGACY_ADMIN_SESSION_COOKIE]; c == nil || c.MaxAge >= 0 {
		t.Fatalf("the old session cookie must be removed: %v", w.Result().Header["Set-Cookie"])
	}

	//the next request carries only the new names
	r2 := httptest.NewRequest("POST", "http://admin.test/api/save", strings.NewReader("x=1"))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.Header.Set("X-CSRF-Token", token)
	r2.AddCookie(got[ADMIN_SESSION_COOKIE])
	r2.AddCookie(got[CSRF_COOKIENAME])
	w2 := httptest.NewRecorder()
	chain.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("request with the Dunree cookies refused: %d %q", w2.Code, w2.Body.String())
	}

	//no cookies at all: still refused (the compat layer is not a way in)
	r3 := httptest.NewRequest("POST", "http://admin.test/api/save", strings.NewReader("x=1"))
	r3.Header.Set("X-CSRF-Token", token)
	w3 := httptest.NewRecorder()
	chain.ServeHTTP(w3, r3)
	if w3.Code != http.StatusForbidden {
		t.Fatalf("request without cookies: %d", w3.Code)
	}
}

// main() glue of the first start: an existing folder is copied once, a new folder never.
func TestRunDunreeFirstStart(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	dbPath := filepath.Join(root, "sys.db")
	os.MkdirAll(filepath.Join(conf, "proxy"), 0o775)
	os.WriteFile(filepath.Join(conf, "version"), []byte("336"), 0o775)
	os.WriteFile(filepath.Join(conf, "proxy", "a.example.com.config"), []byte(`{"RootOrMatchingDomain":"a.example.com"}`), 0o775)
	os.WriteFile(dbPath, []byte("bolt"), 0o600)

	res := runDunreeFirstStart(conf, dbPath, baseline.CaptureProbe(dbPath, conf))
	if res == nil || res.Action != legacycompat.ActionMigrated {
		t.Fatalf("existing install: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(res.Marker.ConfBackup, "proxy", "a.example.com.config")); !strings.Contains(string(b), "a.example.com") {
		t.Fatalf("no copy of the configuration in %q", res.Marker.ConfBackup)
	}
	if b, _ := os.ReadFile(filepath.Join(conf, "version")); string(b) != "336" {
		t.Fatalf("conf/version was rewritten: %q", b)
	}
	if res2 := runDunreeFirstStart(conf, dbPath, baseline.CaptureProbe(dbPath, conf)); res2.Action != legacycompat.ActionNone {
		t.Fatalf("second start: %q", res2.Action)
	}
	if m, _ := filepath.Glob(conf + legacycompat.BackupInfix + "*"); len(m) != 1 {
		t.Fatalf("copies: %v", m)
	}

	//a new install
	root2 := t.TempDir()
	conf2, db2 := filepath.Join(root2, "conf"), filepath.Join(root2, "sys.db")
	probe := baseline.CaptureProbe(db2, conf2)
	if res := runDunreeFirstStart(conf2, db2, probe); res.Action != legacycompat.ActionFresh {
		t.Fatalf("new install: %q", res.Action)
	}
	//the marker must not make a new install look like an existing one to the baseline (it reads the probe taken before)
	if fresh, why := baseline.IsFresh(probe); !fresh {
		t.Fatalf("probe no longer fresh: %s", why)
	}
	if m, _ := filepath.Glob(conf2 + legacycompat.BackupInfix + "*"); len(m) != 0 {
		t.Fatalf("a new install got a copy: %v", m)
	}
}
