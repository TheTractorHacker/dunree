// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/foleyit/dunree/mod/brand"
	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
	"github.com/foleyit/dunree/mod/update"
	"github.com/foleyit/dunree/mod/updater"
	"github.com/foleyit/dunree/mod/wirecompat"
)

// The two version numbers, and where each one comes from.
func TestProductAndCompatVersion(t *testing.T) {
	if SYSTEM_NAME != "Dunree" || brand.Name != "Dunree" {
		t.Errorf("SYSTEM_NAME = %q", SYSTEM_NAME)
	}
	if PRODUCT_VERSION != "1.0.0-beta.1" || brand.Version != "1.0.0-beta.1" {
		t.Errorf("PRODUCT_VERSION = %q, mod/brand Version = %q", PRODUCT_VERSION, brand.Version)
	}
	if COMPAT_VERSION != "3.3.6" || brand.BasedOnVersion != "3.3.6" {
		t.Errorf("COMPAT_VERSION = %q, mod/brand BasedOnVersion = %q", COMPAT_VERSION, brand.BasedOnVersion)
	}
	// the rebrand policy names the same two values
	raw, err := os.ReadFile(filepath.Join("..", "tools", "rebrand", "policy.json"))
	if err != nil {
		t.Skip("tools/rebrand/policy.json not found: ", err)
	}
	var policy struct {
		Variables map[string]string `json:"variables"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if v, ok := policy.Variables["PRODUCT_VERSION"]; ok && v != PRODUCT_VERSION {
		t.Errorf("policy.json PRODUCT_VERSION = %q, the program says %q", v, PRODUCT_VERSION)
	}
	if v, ok := policy.Variables["COMPAT_VERSION"]; ok && v != COMPAT_VERSION {
		t.Errorf("policy.json COMPAT_VERSION = %q, the program says %q", v, COMPAT_VERSION)
	}
}

// -version and the first line of the log name Dunree and its version; the base is named as the base.
func TestVersionFlagOutputAndStartupLine(t *testing.T) {
	const want = "Dunree - Version 1.0.0-beta.1 (based on Zoraxy 3.3.6)" // legacy-compat: names the base
	if got := versionLine(); got != want {
		t.Errorf("versionLine() = %q, want %q", got, want)
	}
	if strings.ContainsAny(versionLine(), "\r\n") {
		t.Error("-version must print one line")
	}
	// what the updater does with that line when it tries a downloaded program
	if !updater.VersionInOutput(versionLine(), PRODUCT_VERSION) {
		t.Error("the updater would not find the version in the -version output")
	}
	if updater.VersionInOutput(versionLine(), "1.0.0") || updater.VersionInOutput(versionLine(), "1.0.0-beta.2") {
		t.Error("another version passes for the version of this build")
	}
	if strings.Contains(versionLine(), "Version "+COMPAT_VERSION) {
		t.Error("-version shows the base version as the version")
	}
	const wantStart = "Dunree 1.0.0-beta.1 starting (Published by Foley IT; based on Zoraxy 3.3.6 by tobychui and imuslab, AGPL-3.0)"
	if got := startupLine(); got != wantStart {
		t.Errorf("startupLine() = %q, want %q", got, wantStart)
	}

	// main() prints versionLine() for -version, and startupSequence logs startupLine()
	for file, call := range map[string]string{"main.go": "fmt.Println(versionLine())", "start.go": "SystemWideLogger.Println(startupLine())"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), call) {
			t.Errorf("%s no longer calls %s", file, call)
		}
	}
}

// No Go file of the program uses a version constant other than the two. A new use of a
// single "system version" would again have to decide which of the two it means.
func TestNoUndecidedVersionConstant(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	uses := map[string]map[string]bool{}
	for _, f := range files {
		parsed, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "SYSTEM_VERSION":
				t.Errorf("%s uses SYSTEM_VERSION; use PRODUCT_VERSION (shown, compared with releases) or COMPAT_VERSION (config migrations, earlier plugins)", fset.Position(id.Pos()))
			case "PRODUCT_VERSION", "COMPAT_VERSION", "configVersionInt":
				if !strings.HasSuffix(f, "_test.go") && f != "def.go" && f != "productversion.go" {
					if uses[id.Name] == nil {
						uses[id.Name] = map[string]bool{}
					}
					uses[id.Name][f] = true
				}
			}
			return true
		})
	}
	// where each one is expected, so that a swap of the two is caught
	want := map[string][]string{
		"PRODUCT_VERSION":  {"main.go", "apiv1.go", "wrappers.go", "metrics.go", "cluster.go", "start.go", "secdashboard.go", "configschema.go", "dunreecompat.go", "wirecompatapi.go"},
		"COMPAT_VERSION":   {"confbackup.go", "reverseproxy.go", "wirecompatapi.go", "apiv1.go", "wrappers.go", "metrics.go", "dunreecompat.go"},
		"configVersionInt": {"main.go"},
	}
	for name, list := range want {
		for _, f := range list {
			if !uses[name][f] {
				t.Errorf("%s is no longer used in %s", name, f)
			}
			delete(uses[name], f)
		}
		for f := range uses[name] {
			t.Errorf("%s is used in %s, which this test does not know: add it to the list after deciding that it is the right one of the two", name, f)
		}
	}
	// the updater and the config migrations get one each, in main.go
	src, _ := os.ReadFile("main.go")
	if !strings.Contains(string(src), "CurrentVersion: PRODUCT_VERSION") {
		t.Error("the updater must be given PRODUCT_VERSION")
	}
	if n := strings.Count(string(src), "update.RunConfigUpdateInDir(CONF_FOLDER, 0, configVersionInt())"); n != 2 {
		t.Errorf("the config migrations must be given configVersionInt() in both places, found %d", n)
	}
	for _, f := range []string{"confbackup.go"} {
		src, _ := os.ReadFile(f)
		if strings.Contains(string(src), "PRODUCT_VERSION") {
			t.Errorf("%s: the version field of a backup manifest is the base version", f)
		}
	}
}

// conf/version stays on the number line of the base: 336, never 100.
func TestConfVersionStays336(t *testing.T) {
	if configVersionInt() != 336 {
		t.Fatalf("configVersionInt() = %d, want 336", configVersionInt())
	}
	if n := update.GetVersionIntFromVersionNumber(PRODUCT_VERSION); n == 336 || n >= 307 {
		t.Fatalf("the product version reads as %d on the config number line; it must not be usable there", n)
	}

	// an existing install: nothing is rewritten
	conf := filepath.Join(t.TempDir(), "conf")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(conf, "proxy"), 0o755))
	rule := []byte(`{"ProxyType":1,"RootOrMatchingDomain":"a.example.com","ActiveOrigins":[{"OriginIpOrDomain":"127.0.0.1:8080"}]}`)
	must(os.WriteFile(filepath.Join(conf, "proxy", "a.example.com.config"), rule, 0o644))
	must(os.WriteFile(filepath.Join(conf, "version"), []byte("336"), 0o644))
	before, err := os.Stat(filepath.Join(conf, "version"))
	must(err)
	update.RunConfigUpdateInDir(conf, 0, configVersionInt())
	if b, _ := os.ReadFile(filepath.Join(conf, "version")); string(b) != "336" {
		t.Fatalf("conf/version of an existing install became %q", b)
	}
	after, err := os.Stat(filepath.Join(conf, "version"))
	must(err)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("conf/version was written again although nothing changed")
	}
	if b, _ := os.ReadFile(filepath.Join(conf, "proxy", "a.example.com.config")); string(b) != string(rule) {
		t.Errorf("the rule of an install at 336 was rewritten: %s", b)
	}

	// an install one step behind is still brought to 336
	must(os.WriteFile(filepath.Join(conf, "version"), []byte("335"), 0o644))
	update.RunConfigUpdateInDir(conf, 0, configVersionInt())
	if b, _ := os.ReadFile(filepath.Join(conf, "version")); string(b) != "336" {
		t.Fatalf("conf/version after the step from 335: %q", b)
	}

	// a new install is stamped 336 too
	fresh := filepath.Join(t.TempDir(), "conf")
	update.RunConfigUpdateInDir(fresh, 0, configVersionInt())
	if b, _ := os.ReadFile(filepath.Join(fresh, "version")); string(b) != "336" {
		t.Fatalf("conf/version of a new install: %q", b)
	}
}

// The admin session cookie is not the product name any more, and the name browsers of an
// upgraded install hold is still the fallback (the login itself: TestUpgradedAdminBrowserKeepsWorking).
func TestSystemNameIsNotTheSessionCookie(t *testing.T) {
	if ADMIN_SESSION_COOKIE == SYSTEM_NAME || ADMIN_SESSION_COOKIE != "dunree_session" {
		t.Errorf("ADMIN_SESSION_COOKIE = %q", ADMIN_SESSION_COOKIE)
	}
	if LEGACY_ADMIN_SESSION_COOKIE != "Zoraxy" { // legacy-compat
		t.Errorf("LEGACY_ADMIN_SESSION_COOKIE = %q: administrators of an upgraded install would be logged out", LEGACY_ADMIN_SESSION_COOKIE)
	}
	src, err := os.ReadFile("start.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "auth.NewAuthenticationAgent(ADMIN_SESSION_COOKIE,") || !strings.Contains(string(src), "authAgent.LegacySessionNames = []string{LEGACY_ADMIN_SESSION_COOKIE}") {
		t.Error("start.go: the session store must use ADMIN_SESSION_COOKIE and fall back to LEGACY_ADMIN_SESSION_COOKIE")
	}
	if strings.Contains(string(src), "NewAuthenticationAgent(SYSTEM_NAME") {
		t.Error("the session cookie follows the product name again")
	}
}

// What clients are told: the REST health answer, the plugin payload and the default User-Agent.
func TestVersionsOnTheWire(t *testing.T) {
	var health http.HandlerFunc
	for _, rt := range v1Routes(v1Backend{}, func(h http.Handler) http.Handler { return h }) {
		if rt.Pattern == "GET /api/v1/health" {
			health = rt.Handler
		}
	}
	if health == nil {
		t.Fatal("no GET /api/v1/health route")
	}
	rec := httptest.NewRecorder()
	health(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"] != "ok" || got["version"] != "1.0.0-beta.1" || got["compat_version"] != "3.3.6" {
		t.Errorf("/api/v1/health: %v", got)
	}

	rc := pluginRuntimeConst()
	if rc.DunreeVersion != "1.0.0-beta.1" || rc.ZoraxyVersion != "3.3.6" { // legacy-compat
		t.Errorf("plugin runtime constants: dunree %q, base %q", rc.DunreeVersion, rc.ZoraxyVersion) // legacy-compat
	}

	was := wirecompat.EmitLegacy()
	defer wirecompat.SetEmitLegacy(was)
	wirecompat.SetEmitLegacy(true)
	if ua := dpcore.IdentityUserAgent(COMPAT_VERSION); ua != "Dunree/1.0.0-beta.1 Zoraxy/3.3.6" { // legacy-compat
		t.Errorf("default User-Agent with the legacy names on: %q", ua)
	}
	wirecompat.SetEmitLegacy(false)
	if ua := dpcore.IdentityUserAgent(COMPAT_VERSION); ua != "Dunree/1.0.0-beta.1" {
		t.Errorf("default User-Agent with the legacy names off: %q", ua)
	}
}
