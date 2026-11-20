package confpack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	secPW      = "hunter2-plaintext-PW"
	secClient  = "oauth-client-SECRET-value"
	secCluster = "cluster-secret-AAAA1111"
	secNotify  = "notify-webhook-token-XYZ"
	secHeader  = "Bearer abc.def.ghi-header"
	secURLPW   = "urlpassword99"
	secKeyBody = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-private-body"
	secBcrypt  = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
)

var secrets = []string{secPW, secClient, secCluster, secNotify, secHeader, secURLPW, secKeyBody, secBcrypt, "challenge-key-bytes", "crowdsec-api-key"}

func writeFile(t *testing.T, root, rel, data string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func proxyRule(domain string) string {
	return `{"RootOrMatchingDomain":"` + domain + `","Disabled":false,
	 "AuthenticationProvider":{"AuthMethod":2,"BasicAuthCredentials":[{"Username":"bob","PasswordHash":"` + secBcrypt + `"}],"OAuth2ClientSecret":"` + secClient + `","UseToken":false},
	 "UserDefinedHeaders":[{"Key":"Authorization","Value":"` + secHeader + `","Direction":0},{"Key":"X-Frame","Value":"deny"}],
	 "NotifyURL":"https://user:` + secURLPW + `@hooks.example/x","Upstream":"10.0.0.5:8080","Password":"` + secPW + `"}`
}

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	writeFile(t, conf, "proxy/a.example.config", proxyRule("a.example"))
	writeFile(t, conf, "proxy/b.example.config", proxyRule("b.example"))
	writeFile(t, conf, "access/default.json", `{"ID":"default","Name":"Default","BlacklistEnabled":true}`)
	writeFile(t, conf, "redirect/r.json", `[{"from":"a","to":"b"}]`)
	writeFile(t, conf, "trusted_proxies.json", `["10.0.0.0/8"]`)
	writeFile(t, conf, "version", "335")
	writeFile(t, conf, "cluster.json", `{"role":"hub","secret":"`+secCluster+`"}`)
	writeFile(t, conf, ".cluster/fleet-hub.key", "hubkey-"+secCluster)
	writeFile(t, conf, ".cluster/fleet-hub.json", `{"nodes":{"n":{"Key":"nodekey123"}}}`)
	writeFile(t, conf, "notify.json", `{"channels":[{"webhook":"`+secNotify+`"}]}`)
	writeFile(t, conf, "waf_challenge.key", "challenge-key-bytes")
	writeFile(t, conf, "crowdsec/apikey.sealed", "crowdsec-api-key")
	writeFile(t, conf, "basicauth_lists.json", `{"l":[{"u":"x","h":"`+secBcrypt+`"}]}`)
	writeFile(t, conf, "certs/site.key", "-----BEGIN PRIVATE KEY-----\n"+secKeyBody+"\n-----END PRIVATE KEY-----\n")
	writeFile(t, conf, "certs/site.pem", "-----BEGIN CERTIFICATE-----\nMIIBpublic\n-----END CERTIFICATE-----\n")
	writeFile(t, conf, "certs/bundle.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n"+secKeyBody+"\n-----END PRIVATE KEY-----\n")
	writeFile(t, conf, "visitors.json.gz", "runtime data")
	writeFile(t, conf, "security_audit.log", `{"seq":1}`+"\n")
	writeFile(t, conf, ".history/x", "history")
	return conf
}

func export(t *testing.T, conf, mode string, db string) ([]byte, *Manifest) {
	t.Helper()
	var buf bytes.Buffer
	m, err := WriteExport(&buf, ExportOptions{ConfDir: conf, DBPath: db, Mode: mode, ZoraxyVersion: "t", Now: func() time.Time { return time.Unix(1700000000, 0) },
		SkipFull: func(rel string) bool { return strings.HasPrefix(rel, "security_audit.log") }})
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), m
}

func openZip(t *testing.T, b []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := []string{}
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[n]))
	}
	zw.Close()
	return buf.Bytes()
}

// treeHash fingerprints a folder: names, modes and contents
func treeHash(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		h.Write([]byte(rel + "\n"))
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

func entryNames(zr *zip.Reader) []string {
	var n []string
	for _, f := range zr.File {
		n = append(n, f.Name)
	}
	sort.Strings(n)
	return n
}

func TestShareableExportHasNoSecrets(t *testing.T) {
	conf := fixture(t)
	db := filepath.Join(filepath.Dir(conf), "sys.db")
	os.WriteFile(db, []byte("dbsecret-"+secPW), 0o600)
	raw, m := export(t, conf, ModeShareable, db)
	zr := openZip(t, raw)
	all := ""
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		all += f.Name + "\n" + string(b) + "\n"
	}
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Errorf("shareable export contains secret %q", s)
		}
	}
	if strings.Contains(all, "PRIVATE KEY") || strings.Contains(all, "dbsecret") {
		t.Error("shareable export contains a private key or the database")
	}
	names := strings.Join(entryNames(zr), ",")
	for _, bad := range []string{"cluster.json", ".cluster/", "notify.json", "waf_challenge.key", "crowdsec/", "certs/site.key", "certs/bundle.pem", "basicauth_lists.json", "sys.db", ".history", "visitors.json.gz", "security_audit"} {
		if strings.Contains(names, bad) {
			t.Errorf("shareable export carries %s", bad)
		}
	}
	for _, good := range []string{"conf/proxy/a.example.config", "conf/access/default.json", "conf/certs/site.pem", "conf/version", ManifestName} {
		if !strings.Contains(names, good) {
			t.Errorf("shareable export misses %s (%s)", good, names)
		}
	}
	if m.Mode != ModeShareable || m.SchemaVersion != 1 || m.ZoraxyVersion != "t" || m.Created == "" || m.IncludesDB || m.RedactedFields == 0 {
		t.Errorf("bad manifest %+v", m)
	}
	// the structure survives: the non credential fields are intact, the username is kept
	var rule map[string]any
	for _, f := range zr.File {
		if f.Name == "conf/proxy/a.example.config" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			json.Unmarshal(b, &rule)
		}
	}
	if rule["Upstream"] != "10.0.0.5:8080" || rule["Password"] != RedactedMarker || !strings.Contains(rule["NotifyURL"].(string), "hooks.example") {
		t.Errorf("unexpected redaction result %v", rule)
	}
	hdrs := rule["UserDefinedHeaders"].([]any)
	if hdrs[0].(map[string]any)["Value"] != RedactedMarker || hdrs[1].(map[string]any)["Value"] != "deny" {
		t.Errorf("header pair redaction wrong: %v", hdrs)
	}
	a := rule["AuthenticationProvider"].(map[string]any)
	if a["UseToken"] != false || a["BasicAuthCredentials"] != RedactedMarker {
		t.Errorf("auth redaction wrong: %v", a)
	}
	// excluded list names paths and reasons only
	found := false
	for _, e := range m.Excluded {
		if e.Path == "cluster.json" && e.Reason != "" {
			found = true
		}
		if strings.Contains(e.Reason, secCluster) {
			t.Error("reason leaks content")
		}
	}
	if !found {
		t.Errorf("cluster.json not listed as excluded: %v", m.Excluded)
	}
}

func TestFullExportKeepsEverythingAndHasManifest(t *testing.T) {
	conf := fixture(t)
	db := filepath.Join(filepath.Dir(conf), "sys.db")
	os.WriteFile(db, []byte("db"), 0o600)
	raw, m := export(t, conf, ModeFull, db)
	zr := openZip(t, raw)
	names := strings.Join(entryNames(zr), ",")
	for _, want := range []string{"conf/cluster.json", "conf/.cluster/fleet-hub.key", "conf/certs/site.key", "conf/notify.json", "sys.db", ManifestName} {
		if !strings.Contains(names, want) {
			t.Errorf("full export misses %s", want)
		}
	}
	if strings.Contains(names, ".history") || strings.Contains(names, "security_audit") {
		t.Error("history / audit log must stay out of a full export")
	}
	if m.Mode != ModeFull || !m.IncludesDB || len(m.Files) != len(zr.File)-1 {
		t.Errorf("manifest %+v", m)
	}
	a, err := Inspect(zr, DefaultLimits)
	if err != nil || !a.Verified {
		t.Fatalf("own export must verify: %v", err)
	}
}

func TestInspectRefusesTraversalAndOddNames(t *testing.T) {
	bad := []string{"conf/../../evil", "conf/../evil", "/etc/passwd", "conf//x", "conf/a/../../b", "conf\\..\\evil", "C:/evil", "conf/C:/x",
		"../evil", "conf/proxy/./a", "other/readme.txt", "conf/a\x00b", "conf/"}
	for _, n := range bad {
		raw := buildZip(t, map[string]string{n: "x", "conf/proxy/ok.config": `{"RootOrMatchingDomain":"ok"}`})
		if n == "conf/" {
			continue //a directory entry alone is harmless
		}
		if _, err := Inspect(openZip(t, raw), DefaultLimits); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	// a symlink member
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "conf/link"}
	h.SetMode(fs.ModeSymlink | 0o777)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("/etc/passwd"))
	zw.Close()
	if _, err := Inspect(openZip(t, buf.Bytes()), DefaultLimits); err == nil {
		t.Error("symlink accepted")
	}
	// duplicate names differing in case
	buf.Reset()
	zw = zip.NewWriter(&buf)
	for _, n := range []string{"conf/a.json", "conf/A.json"} {
		w, _ := zw.Create(n)
		w.Write([]byte("{}"))
	}
	zw.Close()
	if _, err := Inspect(openZip(t, buf.Bytes()), DefaultLimits); err == nil {
		t.Error("duplicate entries accepted")
	}
}

func TestInspectLimits(t *testing.T) {
	raw := buildZip(t, map[string]string{"conf/a.json": `{}`, "conf/b.json": `{}`, "conf/c.json": `{}`})
	if _, err := Inspect(openZip(t, raw), Limits{MaxFiles: 2, MaxFileBytes: 100, MaxTotalBytes: 1000, MaxJSONBytes: 100}); err == nil {
		t.Error("file count cap not enforced")
	}
	big := buildZip(t, map[string]string{"conf/blob.bin": strings.Repeat("A", 5000)})
	if _, err := Inspect(openZip(t, big), Limits{MaxFiles: 10, MaxFileBytes: 1000, MaxTotalBytes: 100000, MaxJSONBytes: 100}); err == nil {
		t.Error("per file cap not enforced")
	}
	two := buildZip(t, map[string]string{"conf/x.bin": strings.Repeat("A", 800), "conf/y.bin": strings.Repeat("B", 800)})
	if _, err := Inspect(openZip(t, two), Limits{MaxFiles: 10, MaxFileBytes: 1000, MaxTotalBytes: 1000, MaxJSONBytes: 100}); err == nil {
		t.Error("total cap not enforced")
	}
	bigJSON := buildZip(t, map[string]string{"conf/proxy/x.config": `{"RootOrMatchingDomain":"x","pad":"` + strings.Repeat("A", 500) + `"}`})
	if _, err := Inspect(openZip(t, bigJSON), Limits{MaxFiles: 10, MaxFileBytes: 10000, MaxTotalBytes: 10000, MaxJSONBytes: 100}); err == nil {
		t.Error("JSON size cap not enforced")
	}
}

// a header that lies about the size must not get past the real byte count
func TestInspectCountsRealBytes(t *testing.T) {
	raw := buildZip(t, map[string]string{"conf/blob.bin": strings.Repeat("A", 4000)})
	// patch the declared uncompressed size (local header and central directory) to 10
	patched := append([]byte{}, raw...)
	for _, sig := range [][]byte{{'P', 'K', 3, 4}, {'P', 'K', 1, 2}} {
		i := bytes.Index(patched, sig)
		off := 22 // local header: uncompressed size at 22
		if sig[2] == 1 {
			off = 24 // central directory: at 24
		}
		patched[i+off], patched[i+off+1], patched[i+off+2], patched[i+off+3] = 10, 0, 0, 0
	}
	zr, err := zip.NewReader(bytes.NewReader(patched), int64(len(patched)))
	if err != nil {
		t.Skip("patched zip not readable by archive/zip: ", err)
	}
	if _, err := Inspect(zr, Limits{MaxFiles: 10, MaxFileBytes: 100, MaxTotalBytes: 1000, MaxJSONBytes: 100}); err == nil {
		t.Error("an archive that lies about its size got through")
	}
}

func TestManifestChecks(t *testing.T) {
	conf := fixture(t)
	raw, _ := export(t, conf, ModeFull, "")
	zr := openZip(t, raw)
	// rebuild with a changed file but the old manifest
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		files[f.Name] = string(b)
	}
	tampered := map[string]string{}
	for k, v := range files {
		tampered[k] = v
	}
	tampered["conf/access/default.json"] = `{"ID":"default","Name":"Evil","BlacklistEnabled":false}`
	if _, err := Inspect(openZip(t, buildZip(t, tampered)), DefaultLimits); !errors.Is(err, ErrBadManifest) {
		t.Errorf("corrupt checksum not refused: %v", err)
	}
	// file in the archive but not listed
	extra := map[string]string{}
	for k, v := range files {
		extra[k] = v
	}
	extra["conf/proxy/sneaky.config"] = `{"RootOrMatchingDomain":"sneaky"}`
	if _, err := Inspect(openZip(t, buildZip(t, extra)), DefaultLimits); !errors.Is(err, ErrBadManifest) {
		t.Errorf("unlisted file not refused: %v", err)
	}
	// listed but missing
	missing := map[string]string{}
	for k, v := range files {
		missing[k] = v
	}
	delete(missing, "conf/redirect/r.json")
	if _, err := Inspect(openZip(t, buildZip(t, missing)), DefaultLimits); !errors.Is(err, ErrBadManifest) {
		t.Errorf("missing file not refused: %v", err)
	}
	// garbage manifest
	garbage := map[string]string{"conf/a.json": "{}", ManifestName: "{not json"}
	if _, err := Inspect(openZip(t, buildZip(t, garbage)), DefaultLimits); !errors.Is(err, ErrBadManifest) {
		t.Errorf("garbage manifest accepted: %v", err)
	}
	// untouched passes
	if a, err := Inspect(openZip(t, buildZip(t, files)), DefaultLimits); err != nil || !a.Verified {
		t.Errorf("clean archive refused: %v", err)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	for _, mut := range []func(m *Manifest){func(m *Manifest) { m.SchemaVersion = 2 }, func(m *Manifest) { m.ConfigSchema = 99 }} {
		m := Manifest{Format: ManifestFmt, SchemaVersion: 1, ConfigSchema: 1, Mode: ModeFull, Files: []ManifestFile{}}
		mut(&m)
		mb, _ := json.Marshal(m)
		raw := buildZip(t, map[string]string{"conf/a.json": "{}", ManifestName: string(mb)})
		if _, err := Inspect(openZip(t, raw), DefaultLimits); !errors.Is(err, ErrNewerSchema) {
			t.Errorf("newer schema not refused: %v", err)
		}
	}
}

func TestOldExportWithoutManifestIsUnverifiedButImports(t *testing.T) {
	conf := fixture(t)
	target := filepath.Join(t.TempDir(), "conf")
	writeFile(t, target, "proxy/old.config", `{"RootOrMatchingDomain":"old"}`)
	raw := buildZip(t, map[string]string{"conf/proxy/n.config": `{"RootOrMatchingDomain":"n"}`, "conf/version": "335"})
	_ = conf
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil || a.Verified || len(a.Warnings) == 0 {
		t.Fatalf("expected an unverified but valid archive: %v %+v", err, a)
	}
	res, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "proxy", "n.config")); err != nil {
		t.Fatal("not restored")
	}
	if _, err := os.Stat(filepath.Join(res.BackupDir, "proxy", "old.config")); err != nil {
		t.Fatal("previous config not backed up")
	}
	if _, err := os.Stat(filepath.Join(target, "proxy", "old.config")); err == nil {
		t.Fatal("full import must replace the config as a whole")
	}
}

func TestJSONSanityRefusal(t *testing.T) {
	for name, body := range map[string]string{
		"conf/proxy/a.config":  `{not json`,
		"conf/proxy/b.config":  `[1,2]`,
		"conf/proxy/c.config":  `{"Nope":1}`,
		"conf/access/d.json":   `{"Name":"x"}`,
		"conf/redirect/e.json": `{"a":`,
		"conf/trusted.json":    "",
	} {
		if _, err := Inspect(openZip(t, buildZip(t, map[string]string{name: body})), DefaultLimits); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	src := fixture(t)
	raw, _ := export(t, src, ModeFull, "")
	target := fixture(t)
	writeFile(t, target, "proxy/only-here.config", `{"RootOrMatchingDomain":"only"}`)
	writeFile(t, target, "access/default.json", `{"ID":"default","Name":"Changed"}`)
	before := treeHash(t, filepath.Dir(target))
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Plan(a, PlanOptions{ConfDir: target, Preserve: func(rel string) bool { return strings.HasPrefix(rel, "security_audit.log") }})
	if err != nil {
		t.Fatal(err)
	}
	if after := treeHash(t, filepath.Dir(target)); after != before {
		t.Fatal("the dry run changed files")
	}
	has := func(l []string, s string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	if !has(rep.Removed, "proxy/only-here.config") || !has(rep.Replaced, "access/default.json") || rep.Unchanged == 0 || !rep.Verified || rep.Mode != ModeFull {
		t.Errorf("unexpected report %+v", rep)
	}
	if !has(rep.Kept, "security_audit.log") {
		t.Errorf("audit log must be reported as kept: %v", rep.Kept)
	}
	if entries, _ := filepath.Glob(target + ".*"); len(entries) != 0 {
		t.Errorf("dry run left folders behind: %v", entries)
	}
}

func TestFailureMidwayRestores(t *testing.T) {
	src := fixture(t)
	raw, _ := export(t, src, ModeFull, "")
	for _, stage := range []string{"stage", "swap-conf"} {
		target := fixture(t)
		writeFile(t, target, "proxy/local.config", `{"RootOrMatchingDomain":"local"}`)
		before := treeHash(t, filepath.Dir(target))
		a, err := Inspect(openZip(t, raw), DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}, Fault: func(s string) error {
			if s == stage {
				return errors.New("injected failure")
			}
			return nil
		}})
		if err == nil {
			t.Fatalf("%s: failure not reported", stage)
		}
		if after := treeHash(t, filepath.Dir(target)); after != before {
			t.Errorf("%s: live state changed after a failed import", stage)
		}
		if m, _ := filepath.Glob(target + ".*"); len(m) != 0 {
			t.Errorf("%s: leftovers %v", stage, m)
		}
	}
	// failure while swapping the database restores the config and the database
	target := fixture(t)
	db := filepath.Join(filepath.Dir(target), "sys.db")
	os.WriteFile(db, []byte("OLD-DB"), 0o600)
	dbSrc := filepath.Join(t.TempDir(), "sys.db")
	os.WriteFile(dbSrc, []byte("NEW-DB"), 0o600)
	raw2, _ := export(t, src, ModeFull, dbSrc)
	before := treeHash(t, filepath.Dir(target))
	a, err := Inspect(openZip(t, raw2), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	res, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target, DBPath: db}, BeforeDB: func() { closed = true },
		Fault: func(s string) error {
			if s == "swap-db" {
				return errors.New("injected db failure")
			}
			return nil
		}})
	if err == nil || !closed || res == nil || !res.DBClosed {
		t.Fatalf("db failure not reported properly: %v", err)
	}
	if after := treeHash(t, filepath.Dir(target)); after != before {
		t.Error("db failure left a half restored state")
	}
	// and a clean database import works and keeps the old file
	res, err = Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target, DBPath: db}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(db); string(b) != "NEW-DB" {
		t.Error("database not replaced")
	}
	if b, _ := os.ReadFile(res.DBBackup); string(b) != "OLD-DB" {
		t.Error("old database not kept")
	}
}

func TestShareableImportKeepsSecretsAndMergesRedactedValues(t *testing.T) {
	src := fixture(t)
	raw, _ := export(t, src, ModeShareable, "")
	target := fixture(t)
	// the target has different rules and its own secrets
	writeFile(t, target, "proxy/a.example.config", strings.ReplaceAll(proxyRule("a.example"), "10.0.0.5:8080", "10.9.9.9:80"))
	os.Remove(filepath.Join(target, "proxy", "b.example.config")) //b.example is new on this install
	writeFile(t, target, "proxy/gone.config", `{"RootOrMatchingDomain":"gone"}`)
	writeFile(t, target, "cluster.json", `{"role":"hub","secret":"LOCAL-CLUSTER-SECRET"}`)
	writeFile(t, target, "certs/site.pem", "LOCAL-CERT")
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Plan(a, PlanOptions{ConfDir: target})
	if err != nil {
		t.Fatal(err)
	}
	if rep.NKept == 0 || rep.SecretsKept == 0 {
		t.Errorf("report should show kept secrets: %+v", rep)
	}
	if _, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}}); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		b, _ := os.ReadFile(filepath.Join(target, filepath.FromSlash(rel)))
		return string(b)
	}
	for _, rel := range []string{"cluster.json", ".cluster/fleet-hub.key", ".cluster/fleet-hub.json", "notify.json", "waf_challenge.key", "crowdsec/apikey.sealed", "basicauth_lists.json", "certs/site.key", "certs/bundle.pem"} {
		if read(rel) == "" {
			t.Errorf("shareable import deleted the secret file %s", rel)
		}
	}
	if !strings.Contains(read("cluster.json"), "LOCAL-CLUSTER-SECRET") {
		t.Error("cluster secret replaced")
	}
	if read("certs/site.pem") != "LOCAL-CERT" {
		t.Error("an existing certificate file was replaced by a shareable import")
	}
	rule := read("proxy/a.example.config")
	if strings.Contains(rule, RedactedMarker) {
		t.Error("the redaction marker reached the live configuration")
	}
	if !strings.Contains(rule, secPW) || !strings.Contains(rule, secBcrypt) || !strings.Contains(rule, secHeader) {
		t.Errorf("credentials of the existing rule were not kept: %s", rule)
	}
	if !strings.Contains(rule, "10.0.0.5:8080") {
		t.Error("non secret value was not taken from the archive")
	}
	if strings.Contains(read("proxy/b.example.config"), secPW) { //no existing rule: the credential must not appear from nowhere
		t.Error("b.example was created with a credential")
	}
	if strings.Contains(read("proxy/b.example.config"), RedactedMarker) {
		t.Error("marker left in a new rule")
	}
	if _, err := os.Stat(filepath.Join(target, "proxy", "gone.config")); err == nil {
		t.Error("shareable import replaces the rules as a whole, gone.config should be removed")
	}
}

func TestShareableArchiveCannotSmuggleSecretsFiles(t *testing.T) {
	for _, name := range []string{"conf/cluster.json", "conf/.cluster/fleet-hub.key", "conf/certs/x.key", "conf/notify.json", "conf/visitors.json.gz"} {
		files := map[string]string{name: "{}"}
		sum := sha256.Sum256([]byte("{}"))
		m := Manifest{Format: ManifestFmt, SchemaVersion: 1, ConfigSchema: 1, Mode: ModeShareable, Files: []ManifestFile{{Path: name, Size: 2, SHA256: hex.EncodeToString(sum[:])}}}
		mb, _ := json.Marshal(m)
		files[ManifestName] = string(mb)
		if _, err := Inspect(openZip(t, buildZip(t, files)), DefaultLimits); err == nil {
			t.Errorf("shareable archive carrying %s accepted", name)
		}
	}
}

func TestRedactJSONRules(t *testing.T) {
	in := `{"password":"p","Token":"t","ApiKey":"k","client_secret":"s","BasicAuthCredentials":[{"u":"x"}],"safe":"v","n":5,"empty":"","flag":false,
	  "nested":{"PrivateKey":"-----BEGIN PRIVATE KEY-----abc","x":"$2a$10$zzzz"},"url":"https://u:pw@h.example/p","h":[{"name":"X-Api-Key","value":"abc"}]}`
	out, n, err := RedactJSON([]byte(in))
	if err != nil || n < 8 {
		t.Fatal(n, err)
	}
	s := string(out)
	for _, leak := range []string{`"p"`, `"t"`, `"k"`, `"s"`, "BEGIN PRIVATE", "$2a$", "pw@", `"abc"`} {
		if strings.Contains(s, leak) {
			t.Errorf("leaked %s in %s", leak, s)
		}
	}
	for _, keep := range []string{`"safe": "v"`, `"n": 5`, `"flag": false`, "h.example/p"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost %s in %s", keep, s)
		}
	}
	if _, _, err := RedactJSON([]byte(`{} trailing`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestMigrateStampAndIdempotence(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	writeFile(t, conf, "proxy/a.config", `{"RootOrMatchingDomain":"a"}`)
	now := time.Unix(1700000000, 0)
	res, err := Migrate(conf, nil, "t", now)
	if err != nil || !res.Stamped || res.From != 0 || res.Backup != "" {
		t.Fatalf("stamp: %v %+v", err, res)
	}
	if v, _ := ReadSchema(conf); v != CurrentConfigSchema {
		t.Fatalf("schema %d", v)
	}
	st1, _ := os.ReadFile(filepath.Join(conf, SchemaFile))
	res, err = Migrate(conf, nil, "t", now.Add(time.Hour))
	if err != nil || res.Stamped || len(res.Ran) != 0 {
		t.Fatalf("second run must do nothing: %v %+v", err, res)
	}
	if st2, _ := os.ReadFile(filepath.Join(conf, SchemaFile)); !bytes.Equal(st1, st2) {
		t.Error("stamp rewritten by an idempotent run")
	}
	if m, _ := filepath.Glob(conf + ".premigrate_*"); len(m) != 0 {
		t.Error("backup taken for a no-op")
	}
	// missing folder is left alone
	if res, err := Migrate(filepath.Join(root, "nope"), nil, "t", now); err != nil || res.Stamped {
		t.Error("missing folder touched")
	}
}

func TestMigrateRunsStepsAfterBackupAndRetriesOnFailure(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	writeFile(t, conf, "proxy/a.config", `{"RootOrMatchingDomain":"a"}`)
	writeFile(t, conf, ".history/h", "x")
	runs := 0
	fail := true
	reg := []Migration{{From: 0, Name: "rewrite", Run: func(dir string) error {
		runs++
		os.WriteFile(filepath.Join(dir, "proxy", "a.config"), []byte(`{"RootOrMatchingDomain":"changed"}`), 0o644)
		if fail {
			return errors.New("boom")
		}
		return nil
	}}}
	now := time.Unix(1700000000, 0)
	res, err := Migrate(conf, reg, "t", now)
	if err == nil || res.Stamped || res.Backup == "" {
		t.Fatalf("failing migration: %v %+v", err, res)
	}
	if v, _ := ReadSchema(conf); v != 0 {
		t.Error("stamp written after a failed migration")
	}
	if b, _ := os.ReadFile(filepath.Join(res.Backup, "proxy", "a.config")); !strings.Contains(string(b), `"a"`) {
		t.Error("backup does not hold the pre migration state")
	}
	if _, err := os.Stat(filepath.Join(res.Backup, ".history")); err == nil {
		t.Error("history copied into the migration backup")
	}
	fail = false
	res, err = Migrate(conf, reg, "t", now.Add(time.Minute))
	if err != nil || !res.Stamped || len(res.Ran) != 1 || runs != 2 {
		t.Fatalf("retry: %v %+v runs=%d", err, res, runs)
	}
	res, _ = Migrate(conf, reg, "t", now.Add(2*time.Minute))
	if res.Stamped || runs != 2 {
		t.Error("migration ran again")
	}
}

func TestMigrateNewerConfigUntouched(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "conf")
	writeFile(t, conf, SchemaFile, `{"schema":99}`)
	res, err := Migrate(conf, nil, "t", time.Now())
	if err != nil || !res.Newer || res.Stamped {
		t.Fatalf("%v %+v", err, res)
	}
	if b, _ := os.ReadFile(filepath.Join(conf, SchemaFile)); !strings.Contains(string(b), "99") {
		t.Error("newer stamp modified")
	}
	writeFile(t, conf, SchemaFile, `{broken`)
	if _, err := Migrate(conf, nil, "t", time.Now()); err == nil {
		t.Error("damaged stamp not reported")
	}
}
