package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/secaudit"
)

const ruleA = `{"RootOrMatchingDomain":"rule-a"}`

func setupBackupTest(t *testing.T) (confDir string, dbFile string) {
	t.Helper()
	oldConf, oldDB, oldLog := CONF_FOLDER, *path_database, SystemWideLogger
	t.Cleanup(func() { CONF_FOLDER, *path_database, SystemWideLogger = oldConf, oldDB, oldLog })
	SystemWideLogger, _ = logger.NewFmtLogger()
	root := t.TempDir()
	// deliberately NOT ./conf: installs started with -conf must back up and restore too
	confDir = filepath.Join(root, "custom-config")
	dbFile = filepath.Join(root, "my.db")
	CONF_FOLDER = confDir
	*path_database = dbFile
	os.MkdirAll(filepath.Join(confDir, "proxy"), 0o775)
	os.WriteFile(filepath.Join(confDir, "proxy", "a.config"), []byte(ruleA), 0o644)
	os.WriteFile(filepath.Join(confDir, "version"), []byte("335"), 0o644)
	return
}

func uploadZip(t *testing.T, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "backup.zip")
	fw.Write(data)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/conf/import", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	ImportConfigFromZip(w, r)
	return w
}

func TestConfigExportImportRoundTripWithCustomConfFolder(t *testing.T) {
	confDir, _ := setupBackupTest(t)

	w := httptest.NewRecorder()
	ExportConfigAsZip(w, httptest.NewRequest(http.MethodGet, "/api/conf/export", nil))
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("export is not a valid zip: %v", err)
	}
	names := []string{}
	for _, f := range zr.File {
		names = append(names, f.Name)
		if !strings.HasPrefix(f.Name, "conf/") && f.Name != "manifest.json" {
			t.Fatalf("entry %q must be stored under conf/", f.Name)
		}
	}

	os.RemoveAll(confDir)
	res := uploadZip(t, w.Body.Bytes())
	if res.Code != http.StatusOK {
		t.Fatalf("import failed: %d %s (entries %v)", res.Code, res.Body.String(), names)
	}
	got, err := os.ReadFile(filepath.Join(confDir, "proxy", "a.config"))
	if err != nil || string(got) != ruleA {
		t.Fatalf("config not restored into the -conf folder: %v %q", err, got)
	}
}

func TestInvalidConfigZipKeepsExistingConfig(t *testing.T) {
	confDir, _ := setupBackupTest(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("not-a-backup/readme.txt")
	f.Write([]byte("x"))
	zw.Close()

	res := uploadZip(t, buf.Bytes())
	if res.Code == http.StatusOK {
		t.Fatal("an invalid archive must be rejected")
	}
	got, err := os.ReadFile(filepath.Join(confDir, "proxy", "a.config"))
	if err != nil || string(got) != ruleA {
		t.Fatalf("existing config was destroyed by a rejected import: %v %q", err, got)
	}
}

func TestConfigZipRejectsTraversal(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	for _, name := range []string{"conf/../../evil.txt", "conf/../evil.txt", "/etc/passwd", "conf/"} {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create(name)
		f.Write([]byte("x"))
		zw.Close()
		if res := uploadZip(t, buf.Bytes()); res.Code == http.StatusOK && name != "conf/" {
			t.Errorf("%q accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(confDir), "evil.txt")); err == nil {
		t.Fatal("zip slip wrote outside of the config folder")
	}
	if _, err := os.Stat(filepath.Join(confDir, "proxy", "a.config")); err != nil {
		t.Fatalf("config removed by rejected archives: %v", err)
	}
}

func uploadTo(t *testing.T, h func(http.ResponseWriter, *http.Request), path string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "backup.zip")
	fw.Write(data)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, path, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func exportMode(t *testing.T, query string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	ExportConfigAsZip(w, httptest.NewRequest(http.MethodGet, "/api/conf/export"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("export %s: %d %s", query, w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

func zipText(t *testing.T, data []byte) (names []string, all string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		all += string(b)
	}
	return
}

func TestExportDefaultIsFullBackupAndSharedModeIsRedacted(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	os.WriteFile(filepath.Join(confDir, "cluster.json"), []byte(`{"secret":"CLUSTER-SECRET-123"}`), 0o600)
	os.MkdirAll(filepath.Join(confDir, "certs"), 0o775)
	os.WriteFile(filepath.Join(confDir, "certs", "a.key"), []byte("-----BEGIN PRIVATE KEY-----\nKEYBODY\n-----END PRIVATE KEY-----\n"), 0o600)
	os.WriteFile(filepath.Join(confDir, "proxy", "b.config"), []byte(`{"RootOrMatchingDomain":"b","Password":"PLAINPW"}`), 0o644)

	names, all := zipText(t, exportMode(t, ""))
	if !strings.Contains(all, "CLUSTER-SECRET-123") || !strings.Contains(all, "KEYBODY") || !strings.Contains(all, "PLAINPW") {
		t.Fatal("the default export must stay the full backup (secrets included)")
	}
	if strings.Contains(strings.Join(names, ","), "manifest.json") {
		t.Fatal("the default full export keeps its historic layout: an older Zoraxy refuses an archive with manifest.json")
	}
	names, _ = zipText(t, exportMode(t, "?manifest=true"))
	if !strings.Contains(strings.Join(names, ","), "manifest.json") {
		t.Fatal("manifest=true must add the manifest")
	}
	_, shared := zipText(t, exportMode(t, "?mode=shareable&includeDB=true"))
	for _, s := range []string{"CLUSTER-SECRET-123", "KEYBODY", "PLAINPW", "PRIVATE KEY"} {
		if strings.Contains(shared, s) {
			t.Errorf("shareable export leaks %q", s)
		}
	}
	w := httptest.NewRecorder()
	ExportConfigAsZip(w, httptest.NewRequest(http.MethodGet, "/api/conf/export?mode=bogus", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown mode: %d", w.Code)
	}
}

func treeSnapshot(t *testing.T, root string) string {
	t.Helper()
	var sb strings.Builder
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			sb.WriteString(p + "=" + string(b) + ";")
		}
		return nil
	})
	return sb.String()
}

func TestImportCheckIsADryRun(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	data := exportMode(t, "?manifest=true")
	os.WriteFile(filepath.Join(confDir, "proxy", "a.config"), []byte(`{"RootOrMatchingDomain":"changed"}`), 0o644)
	os.WriteFile(filepath.Join(confDir, "proxy", "extra.config"), []byte(`{"RootOrMatchingDomain":"extra"}`), 0o644)
	before := treeSnapshot(t, filepath.Dir(confDir))
	res := uploadTo(t, ImportCheckConfigZip, "/api/conf/importcheck", data)
	if res.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", res.Code, res.Body.String())
	}
	var rep struct {
		Verified bool
		Replaced []string
		Removed  []string
	}
	if err := json.Unmarshal(res.Body.Bytes(), &rep); err != nil || !rep.Verified {
		t.Fatalf("bad report %v %s", err, res.Body.String())
	}
	if len(rep.Replaced) == 0 || len(rep.Removed) == 0 {
		t.Errorf("report lacks replaced/removed: %s", res.Body.String())
	}
	if treeSnapshot(t, filepath.Dir(confDir)) != before {
		t.Fatal("the dry run changed files")
	}
}

func TestImportRefusesHostileAndOversizedArchives(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	before := treeSnapshot(t, filepath.Dir(confDir))
	mk := func(files map[string]string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for n, c := range files {
			f, _ := zw.Create(n)
			f.Write([]byte(c))
		}
		zw.Close()
		return buf.Bytes()
	}
	cases := map[string][]byte{
		"traversal":      mk(map[string]string{"conf/../../escape.txt": "x"}),
		"absolute":       mk(map[string]string{"/tmp/escape": "x"}),
		"backslash":      mk(map[string]string{"conf\\..\\escape": "x"}),
		"bad json rule":  mk(map[string]string{"conf/proxy/x.config": "{oops"}),
		"newer manifest": mk(map[string]string{"conf/a.json": "{}", "manifest.json": `{"format":"zoraxy-config-export","schemaVersion":7,"mode":"full","files":[]}`}),
		"bad checksum":   mk(map[string]string{"conf/a.json": "{}", "manifest.json": `{"format":"zoraxy-config-export","schemaVersion":1,"configSchema":1,"mode":"full","files":[{"path":"conf/a.json","size":2,"sha256":"00"}]}`}),
		"empty":          mk(map[string]string{}),
	}
	for name, data := range cases {
		for _, h := range []struct {
			fn   func(http.ResponseWriter, *http.Request)
			path string
		}{{ImportConfigFromZip, "/api/conf/import"}, {ImportCheckConfigZip, "/api/conf/importcheck"}} {
			if res := uploadTo(t, h.fn, h.path, data); res.Code == http.StatusOK {
				t.Errorf("%s accepted by %s", name, h.path)
			}
		}
	}
	if treeSnapshot(t, filepath.Dir(confDir)) != before {
		t.Fatal("a refused import changed something")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(confDir), "escape.txt")); err == nil {
		t.Fatal("zip slip")
	}
	// not a zip / wrong method
	if res := uploadTo(t, ImportConfigFromZip, "/api/conf/import", []byte("not a zip")); res.Code == http.StatusOK {
		t.Error("garbage accepted")
	}
	w := httptest.NewRecorder()
	ImportConfigFromZip(w, httptest.NewRequest(http.MethodGet, "/api/conf/import", nil))
	if w.Code == http.StatusOK {
		t.Error("GET accepted")
	}
}

func TestOldExportWithoutManifestStillImports(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("conf/proxy/old.config")
	f.Write([]byte(`{"RootOrMatchingDomain":"old.example"}`))
	zw.Close()
	res := uploadTo(t, ImportCheckConfigZip, "/api/conf/importcheck", buf.Bytes())
	var rep struct {
		Verified bool
		Warnings []string
	}
	json.Unmarshal(res.Body.Bytes(), &rep)
	if res.Code != http.StatusOK || rep.Verified || len(rep.Warnings) == 0 || !strings.Contains(rep.Warnings[0], "unverified") {
		t.Fatalf("an old export must report unverified: %d %s", res.Code, res.Body.String())
	}
	if res := uploadTo(t, ImportConfigFromZip, "/api/conf/import", buf.Bytes()); res.Code != http.StatusOK {
		t.Fatalf("old export refused: %s", res.Body.String())
	}
	if _, err := os.Stat(filepath.Join(confDir, "proxy", "old.config")); err != nil {
		t.Fatal("not imported")
	}
	if m, _ := filepath.Glob(confDir + ".old_*"); len(m) != 1 {
		t.Errorf("the previous config must be kept as <conf>.old_<ts>: %v", m)
	}
}

func TestImportKeepsAuditLogAndSecretsOfShareable(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	os.WriteFile(filepath.Join(confDir, "security_audit.log"), []byte("AUDIT-ENTRY\n"), 0o600)
	os.WriteFile(filepath.Join(confDir, "cluster.json"), []byte(`{"secret":"KEEP-ME"}`), 0o600)
	shared := exportMode(t, "?mode=shareable")
	if res := uploadTo(t, ImportConfigFromZip, "/api/conf/import", shared); res.Code != http.StatusOK {
		t.Fatalf("shareable import: %s", res.Body.String())
	}
	for rel, want := range map[string]string{"security_audit.log": "AUDIT-ENTRY", "cluster.json": "KEEP-ME"} {
		if b, _ := os.ReadFile(filepath.Join(confDir, rel)); !strings.Contains(string(b), want) {
			t.Errorf("%s lost by a shareable import", rel)
		}
	}
	// a full import also never replaces the audit log
	full := exportMode(t, "")
	os.WriteFile(filepath.Join(confDir, "security_audit.log"), []byte("AUDIT-2\n"), 0o600)
	if res := uploadTo(t, ImportConfigFromZip, "/api/conf/import", full); res.Code != http.StatusOK {
		t.Fatalf("full import: %s", res.Body.String())
	}
	if b, _ := os.ReadFile(filepath.Join(confDir, "security_audit.log")); !strings.Contains(string(b), "AUDIT-2") {
		t.Error("full import replaced the audit log")
	}
}

func TestViewerCannotExportOrImport(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		for _, p := range []string{"/api/conf/export", "/api/conf/import", "/api/conf/importcheck"} {
			if auth.ViewerAllowed(m, p) {
				t.Errorf("a viewer may %s %s", m, p)
			}
		}
	}
}

func TestImportResultIsAudited(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	old := secAudit
	defer func() { secAudit = old }()
	l, err := secaudit.New(secaudit.Options{Path: filepath.Join(confDir, securityAuditFile)})
	if err != nil {
		t.Fatal(err)
	}
	secAudit = l
	good := exportMode(t, "?manifest=true")
	if res := uploadTo(t, ImportConfigFromZip, "/api/conf/import", good); res.Code != http.StatusOK {
		t.Fatal(res.Body.String())
	}
	var bad bytes.Buffer
	zw := zip.NewWriter(&bad)
	f, _ := zw.Create("conf/../x")
	f.Write([]byte("x"))
	zw.Close()
	uploadTo(t, ImportConfigFromZip, "/api/conf/import", bad.Bytes())
	l.Flush()
	pg, _ := l.List(secaudit.Query{Event: "config.import.result"})
	outcomes := map[string]bool{}
	for _, e := range pg.Entries {
		outcomes[e.Outcome] = true
		if e.Outcome == "ok" && (e.Detail["mode"] != "full" || e.Detail["verified"] != "true" || e.Detail["backup"] == "") {
			t.Errorf("ok entry lacks the result: %+v", e.Detail)
		}
	}
	if !outcomes["ok"] || !outcomes["denied"] {
		t.Errorf("expected an ok and a denied audit entry, got %+v", pg.Entries)
	}
}

// the login audit is per install too: no export copies it out, no import plants or erases it
func TestAuthAuditNeverExportedAndNeverReplacedByImport(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	os.WriteFile(filepath.Join(confDir, authAuditFile), []byte("LOGIN-ENTRY alice 10.1.2.3\n"), 0o600)
	os.WriteFile(filepath.Join(confDir, authAuditFile+".1"), []byte("ROTATED\n"), 0o600)
	names, all := zipText(t, exportMode(t, "?manifest=true"))
	if strings.Contains(strings.Join(names, ","), authAuditFile) || strings.Contains(all, "alice") {
		t.Fatalf("the full export copied the login audit out: %v", names)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for name, body := range map[string]string{"conf/proxy/a.config": ruleA, "conf/" + authAuditFile: "FORGED-CLEAN-TRAIL\n"} {
		f, _ := zw.Create(name)
		f.Write([]byte(body))
	}
	zw.Close()
	if res := uploadZip(t, zb.Bytes()); res.Code != http.StatusOK {
		t.Fatalf("import: %s", res.Body.String())
	}
	if b, _ := os.ReadFile(filepath.Join(confDir, authAuditFile)); !strings.Contains(string(b), "LOGIN-ENTRY") {
		t.Errorf("an archive replaced the login audit: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(confDir, authAuditFile+".1")); !strings.Contains(string(b), "ROTATED") {
		t.Error("the rotated login audit was erased")
	}
}

// a conf import says it needs a restart and a failed upload names the problem as a client error
func TestImportCheckAnnouncesRestartForConfOnlyArchives(t *testing.T) {
	setupBackupTest(t)
	res := uploadTo(t, ImportCheckConfigZip, "/api/conf/importcheck", exportMode(t, ""))
	var rep struct{ RestartRequired bool }
	json.Unmarshal(res.Body.Bytes(), &rep)
	if !rep.RestartRequired {
		t.Fatalf("restart not announced: %s", res.Body.String())
	}
}
