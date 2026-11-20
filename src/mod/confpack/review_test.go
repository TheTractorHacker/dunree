package confpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// forgedShareable builds a shareable archive whose manifest is perfectly self consistent: the checksums prove
// integrity, not who made the file
func forgedShareable(t *testing.T, files map[string]string) []byte {
	t.Helper()
	m := Manifest{Format: ManifestFmt, SchemaVersion: 1, ConfigSchema: 1, Mode: ModeShareable, ZoraxyVersion: "t"}
	out := map[string]string{}
	for n, c := range files {
		out[n] = c
		sum := sha256.Sum256([]byte(c))
		m.Files = append(m.Files, ManifestFile{Path: n, Size: int64(len(c)), SHA256: hex.EncodeToString(sum[:])})
	}
	mb, _ := json.Marshal(m)
	out[ManifestName] = string(mb)
	return buildZip(t, out)
}

func readF(t *testing.T, root, rel string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	return string(b)
}

func TestShareableImportRefusesRealCredentialsInTheArchive(t *testing.T) {
	target := t.TempDir()
	writeFile(t, target, "proxy/a.example.config", `{"RootOrMatchingDomain":"a.example","Upstream":"10.0.0.5:80","AuthenticationProvider":{"BasicAuthCredentials":[{"Username":"bob","PasswordHash":"LIVEHASH"}]}}`)
	writeFile(t, target, "abuse/abuse.json", `{"RemoteTokenHash":"LIVE-TOKEN-HASH","Enabled":true}`)
	attackerHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	raw := forgedShareable(t, map[string]string{
		"conf/proxy/a.example.config": `{"RootOrMatchingDomain":"a.example","Upstream":"10.1.1.1:80","AuthenticationProvider":{"BasicAuthCredentials":[{"Username":"mallory","PasswordHash":"BACKDOOR"}]},"PasswordHash":"BACKDOOR2","apiToken":"ATTACKER","NotifyURL":"https://TOKEN123@hooks.example/x?token=abc"}`,
		"conf/abuse/abuse.json":       `{"RemoteTokenHash":"` + attackerHash + `","Enabled":true}`,
	})
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Plan(a, PlanOptions{ConfDir: target})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SecretsIgnored < 4 {
		t.Errorf("the report must count the refused credentials, got %d", rep.SecretsIgnored)
	}
	warned := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "ignored") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning about the ignored credentials: %v", rep.Warnings)
	}
	if _, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}}); err != nil {
		t.Fatal(err)
	}
	rule := readF(t, target, "proxy/a.example.config")
	for _, bad := range []string{"mallory", "BACKDOOR", "ATTACKER", "TOKEN123", "token=abc"} {
		if strings.Contains(rule, bad) {
			t.Errorf("attacker value %q reached the live rule: %s", bad, rule)
		}
	}
	if !strings.Contains(rule, "LIVEHASH") || !strings.Contains(rule, "10.1.1.1:80") {
		t.Errorf("live credential lost or the non secret change not applied: %s", rule)
	}
	if got := readF(t, target, "abuse/abuse.json"); strings.Contains(got, attackerHash) || !strings.Contains(got, "LIVE-TOKEN-HASH") {
		t.Errorf("the remote ban token verifier was replaced: %s", got)
	}
}

func TestMergeShareableMatchesArrayElementsByIdentityNotPosition(t *testing.T) {
	existing := `{"Hosts":[{"Name":"a","ApiSecret":"SA"},{"Name":"b","ApiSecret":"SB"}]}`
	incoming := `{"Hosts":[{"Name":"b","ApiSecret":"[REDACTED]"},{"Name":"a","ApiSecret":"[REDACTED]"},{"Name":"new","ApiSecret":"[REDACTED]"}]}`
	out, kept, dropped, _, err := MergeShareable([]byte(incoming), []byte(existing))
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Hosts []map[string]string }
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Hosts) != 3 || v.Hosts[0]["ApiSecret"] != "SB" || v.Hosts[1]["ApiSecret"] != "SA" {
		t.Fatalf("a reordered array swapped the secrets: %s", out)
	}
	if _, has := v.Hosts[2]["ApiSecret"]; has || kept != 2 || dropped != 1 {
		t.Fatalf("a new element must not inherit any secret: kept=%d dropped=%d %s", kept, dropped, out)
	}
}

func TestRedactionCoversTokenNamesNumbersAndUrlForms(t *testing.T) {
	in := `{"apiToken":"A1","botToken":"B1","webhookToken":"W1","EABConfig":{"HmacKey":"H1"},"RemoteTokenHash":"R1","WebhookURL":"https://hooks.slack.com/services/T0/B0/XYZ",
	 "secretCode":123456,"TokenTTL":3600,"u1":"https://TOKEN9@host.example/x","u2":"https://user:p@ss@host.example/x","u3":"https://h.example/x?api_key=Q9&ok=1","dsn":"postgres://x","safe":"hello"}`
	out, _, err := RedactJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"A1", "B1", "W1", "H1", "R1", "XYZ", "123456", "TOKEN9", "p@ss", "ss@host", "Q9", "postgres"} {
		if strings.Contains(s, `"`+leak+`"`) || strings.Contains(s, leak+"@") || (len(leak) > 3 && strings.Contains(s, leak)) {
			t.Errorf("leaked %q: %s", leak, s)
		}
	}
	for _, keep := range []string{`"TokenTTL": 3600`, `"safe": "hello"`, "host.example/x", "ok=1"} {
		if !strings.Contains(s, keep) {
			t.Errorf("over redacted, lost %q: %s", keep, s)
		}
	}
	// the redacted form must round trip: markers resolve from the live file, never reach it
	live := `{"u3":"https://h.example/x?api_key=LIVEQ&ok=1","apiToken":"LIVE"}`
	merged, _, _, _, _ := MergeShareable(out, []byte(live))
	if strings.Contains(string(merged), RedactedMarker) {
		t.Errorf("marker reached the merged document: %s", merged)
	}
	if !strings.Contains(string(merged), "LIVEQ") || !strings.Contains(string(merged), `"apiToken": "LIVE"`) {
		t.Errorf("live secrets not restored: %s", merged)
	}
}

func TestStagedFilesKeepOrTightenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	src := fixture(t)
	raw, _ := export(t, src, ModeFull, "")
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "sys.db")
	os.WriteFile(dbPath, []byte("live"), 0o640)
	// archive with a database
	dbSrc := filepath.Join(dbDir, "src.db")
	os.WriteFile(dbSrc, []byte("imported db with password hashes"), 0o644)
	raw, _ = export(t, src, ModeFull, dbSrc)
	target := fixture(t)
	os.Chmod(filepath.Join(target, "proxy", "a.example.config"), 0o640)
	os.Remove(filepath.Join(target, "proxy", "b.example.config"))
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target, DBPath: dbPath}}); err != nil {
		t.Fatal(err)
	}
	mode := func(p string) os.FileMode {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}
	if m := mode(dbPath); m != 0o640 {
		t.Errorf("sys.db mode %o, the live mode (640) must be kept", m)
	}
	if m := mode(filepath.Join(target, "proxy", "a.example.config")); m != 0o640 {
		t.Errorf("an existing rule file was loosened or changed to %o", m)
	}
	if m := mode(filepath.Join(target, "proxy", "b.example.config")); m&0o077 != 0 {
		t.Errorf("a new rule file (basic auth hashes) is group or world accessible: %o", m)
	}
	// no live database at all: a new one is private
	os.Remove(dbPath)
	b2 := t.TempDir()
	newDB := filepath.Join(b2, "sys.db")
	if _, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target, DBPath: newDB}}); err != nil {
		t.Fatal(err)
	}
	if m := mode(newDB); m != 0o600 {
		t.Errorf("a new sys.db must be 0600, got %o", m)
	}
}

func TestShareableImportNeverTakesVersionOrSchemaFromTheArchive(t *testing.T) {
	target := t.TempDir()
	writeFile(t, target, "version", "336")
	writeFile(t, target, SchemaFile, `{"schema":1}`)
	writeFile(t, target, "trusted_proxies.json", `["10.0.0.0/8"]`)
	raw := forgedShareable(t, map[string]string{"conf/version": "1", "conf/" + SchemaFile: `{"schema":0}`, "conf/trusted_proxies.json": `["10.1.0.0/16"]`})
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}}); err != nil {
		t.Fatal(err)
	}
	if readF(t, target, "version") != "336" || !strings.Contains(readF(t, target, SchemaFile), `"schema":1`) {
		t.Errorf("version or schema stamp rewound by an archive: %q %q", readF(t, target, "version"), readF(t, target, SchemaFile))
	}
	if !strings.Contains(readF(t, target, "trusted_proxies.json"), "10.1.0.0/16") {
		t.Error("the regular files of the archive must still be applied")
	}
}

func TestEntryNamesWithControlCharactersAndWindowsHazards(t *testing.T) {
	for _, n := range []string{"conf/proxy/a\nFORGED log line.config", "conf/proxy/a\rb.config", "conf/a b", "conf/a\x7fb", "conf/a\x1bb"} {
		_, _, err := ValidEntryName(n)
		if err == nil {
			t.Errorf("%q accepted", n)
			continue
		}
		if strings.ContainsAny(err.Error(), "\n\r ") {
			t.Errorf("the error text carries the raw control character: %q", err.Error())
		}
	}
	for _, seg := range []string{"CON.config", "nul", "COM1.txt", "lpt9", "x.config:stream", "x.config.", "x.config "} {
		if !windowsUnsafeName(seg) {
			t.Errorf("%q should be unsafe on Windows", seg)
		}
	}
	if windowsUnsafeName("console.config") || windowsUnsafeName("a.example.config") {
		t.Error("ordinary names flagged")
	}
	if runtime.GOOS != "windows" {
		if _, _, err := ValidEntryName("conf/proxy/old.example:8080.config"); err != nil {
			t.Errorf("an old backup with ':' in a rule name must still import on this platform: %v", err)
		}
	}
}

func TestRollbackWhenAModuleRecreatesTheConfFolderBetweenTheRenames(t *testing.T) {
	src := fixture(t)
	raw, _ := export(t, src, ModeFull, "")
	target := fixture(t)
	writeFile(t, target, "marker.txt", "OLD CONFIG")
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}, Fault: func(stage string) error {
		if stage == "swap-conf" { //a statistics writer calls MkdirAll and writes a file after the first rename
			writeFile(t, target, "stats/today.json", "{}")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("the swap cannot succeed over a folder that now has content")
	}
	if readF(t, target, "marker.txt") != "OLD CONFIG" {
		t.Fatalf("the previous configuration was not put back: %v", err)
	}
	if m, _ := filepath.Glob(target + ".failed_*"); len(m) != 0 {
		t.Logf("leftover folders: %v", m) // the interloper folder is removed after a clean rollback
	}
	if strings.Contains(err.Error(), "still in") {
		t.Errorf("rollback should have succeeded: %v", err)
	}
}

func TestChangeHistoryIsCarriedAndSymlinksAreReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	src := fixture(t)
	raw, _ := export(t, src, ModeFull, "")
	target := fixture(t)
	writeFile(t, target, ".history/chain.jsonl", "SEALED CHAIN")
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(target, "certs-link"))
	a, err := Inspect(openZip(t, raw), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Plan(a, PlanOptions{ConfDir: target})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.RestartRequired {
		t.Error("any configuration import needs a restart, the report must say so")
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "symbolic link") && strings.Contains(w, "certs-link") {
			found = true
		}
	}
	if !found {
		t.Errorf("a skipped symlink must be reported: %v", rep.Warnings)
	}
	if _, err := Apply(a, ApplyOptions{PlanOptions: PlanOptions{ConfDir: target}, Now: func() time.Time { return time.Unix(1700000000, 0) }}); err != nil {
		t.Fatal(err)
	}
	if readF(t, target, ".history/chain.jsonl") != "SEALED CHAIN" {
		t.Error("the change history did not survive the import")
	}
}

func TestRuleFilesWithSecretLookingNamesAreShareable(t *testing.T) {
	conf := t.TempDir()
	writeFile(t, conf, "proxy/token.example.com.config", `{"RootOrMatchingDomain":"token.example.com","Password":"PW123"}`)
	writeFile(t, conf, "proxy/private.corp.config", `{"RootOrMatchingDomain":"private.corp"}`)
	writeFile(t, conf, "certs/private-ca.pem", "-----BEGIN CERTIFICATE-----\nPUB\n-----END CERTIFICATE-----\n")
	writeFile(t, conf, "certs/leaf.key", "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n")
	writeFile(t, conf, "session.json", `{}`)
	raw, _ := export(t, conf, ModeShareable, "")
	names := strings.Join(entryNames(openZip(t, raw)), ",")
	for _, want := range []string{"conf/proxy/token.example.com.config", "conf/proxy/private.corp.config", "conf/certs/private-ca.pem"} {
		if !strings.Contains(names, want) {
			t.Errorf("%s was left out of the shareable export: %s", want, names)
		}
	}
	if strings.Contains(names, "leaf.key") {
		t.Error("a private key was exported")
	}
	_, all := func() ([]string, string) {
		var s string
		for _, f := range openZip(t, raw).File {
			rc, _ := f.Open()
			b := make([]byte, 4096)
			n, _ := rc.Read(b)
			rc.Close()
			s += string(b[:n])
		}
		return nil, s
	}()
	if strings.Contains(all, "PW123") {
		t.Error("the password of the rule that has a secret looking name leaked")
	}
}

func TestFullExportCanOmitTheManifestAndKeepsTheHistoricLayout(t *testing.T) {
	conf := t.TempDir()
	writeFile(t, conf, "proxy/a.config", proxyRule("a"))
	writeFile(t, conf, SchemaFile+".tmp", "half")
	var buf strings.Builder
	_ = buf
	raw := func(omit bool) []byte {
		var b bytesBuffer
		if _, err := WriteExport(&b, ExportOptions{ConfDir: conf, Mode: ModeFull, ZoraxyVersion: "t", OmitManifest: omit}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	plain := raw(true)
	for _, n := range entryNames(openZip(t, plain)) {
		if !strings.HasPrefix(n, "conf/") && n != DBEntry {
			t.Errorf("entry %q would be rejected by a Zoraxy that predates the manifest", n)
		}
		if strings.HasSuffix(n, ".tmp") {
			t.Errorf("half written stamp exported: %s", n)
		}
	}
	a, err := Inspect(openZip(t, plain), DefaultLimits)
	if err != nil || a.Verified {
		t.Fatalf("a manifest-less archive imports as unverified: %v %v", err, a)
	}
	if !strings.Contains(strings.Join(entryNames(openZip(t, raw(false))), ","), ManifestName) {
		t.Error("the manifest must still be there when asked for")
	}
	if _, err := WriteExport(&bytesBuffer{}, ExportOptions{ConfDir: conf, Mode: ModeShareable, OmitManifest: true}); err == nil {
		t.Error("a shareable export without a manifest must be refused")
	}
}

type bytesBuffer struct{ b []byte }

func (w *bytesBuffer) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *bytesBuffer) Bytes() []byte               { return w.b }
