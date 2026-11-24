package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Browser storage keys of the admin UI (see web/script/safestorage.js): pages use the Dunree names only, and
// the helper copies the keys an existing browser has under the earlier names, once.

var legacyStorageKey = regexp.MustCompile(`["']zoraxy[._](menu_groups|recent_tabs|pinned_tabs|trafficflow_[a-z]+|status_diagram|site_editor_[a-z]+|palette_recent|utm\.range|topbar\.update|stats\.refwhy|lang)["']`) // legacy-compat

func TestWebUIUsesOnlyNewStorageKeys(t *testing.T) {
	helper, err := os.ReadFile(filepath.Join("web", "script", "safestorage.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`MIGRATED_KEY = "dunree.storage.migrated"`, `migrate("local")`, `migrate("session")`, `OLD_PREFIX = "zoraxy"`} { // legacy-compat
		if !strings.Contains(string(helper), want) {
			t.Errorf("safestorage.js no longer contains %q: the one-time copy of the old storage keys is gone", want)
		}
	}
	checked := 0
	err = filepath.WalkDir("web", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(p); ext != ".js" && ext != ".html" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		checked++
		for i, line := range strings.Split(string(b), "\n") {
			if len(line) < 20000 && legacyStorageKey.MatchString(line) && !strings.Contains(line, "rebrand:keep") { //the helper's own comment names both
				t.Errorf("%s:%d stores under an old key name; use the dunree name (safestorage.js copies the old value once): %s", p, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 50 {
		t.Fatalf("only %d UI files checked: wrong folder?", checked)
	}
}

// The behaviour itself needs a browser: tools/ui-smoke/storage_migration_smoke.py runs the real safestorage.js in
// Chromium without a server. Set PY to a python that has playwright (the one used for tools/ui-smoke/run.sh).
func TestStorageKeyMigrationInBrowser(t *testing.T) {
	py := os.Getenv("PY")
	if py == "" {
		t.Skip("PY is not set (python with playwright); run: PY=... go test -run TestStorageKeyMigrationInBrowser . or tools/ui-smoke/storage_migration_smoke.py")
	}
	out, err := exec.Command(py, filepath.Join("..", "tools", "ui-smoke", "storage_migration_smoke.py")).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK storage migration") {
		t.Fatalf("storage migration check failed: %v\n%s", err, out)
	}
}
