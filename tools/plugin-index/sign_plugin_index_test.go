package main

// Run with:  cd tools/plugin-index && go test sign_plugin_index.go sign_plugin_index_test.go
// Uses throwaway keys only.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDraft(t *testing.T, path string, url string) {
	t.Helper()
	draft := map[string]any{
		"format": indexFormat, "version": indexVersion,
		"plugins": []any{map[string]any{
			"IconPath":         "",
			"PluginIntroSpect": map[string]any{"id": "com.example.demo", "name": "Demo", "version_major": 1},
			"Downloads":        map[string]any{"linux_amd64": map[string]any{"url": url}},
		}},
	}
	raw, _ := json.Marshal(draft)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "plugin-index.pem"), filepath.Join(dir, "plugin-index.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := generateKey(priv, pub); err == nil {
		t.Fatal("genkey must not overwrite")
	}
	if st, _ := os.Stat(priv); st.Mode().Perm() != 0o600 {
		t.Fatalf("the private key must be readable by its owner only, got %v", st.Mode().Perm())
	}
	files := filepath.Join(dir, "files")
	os.MkdirAll(filepath.Join(files, "com.example.demo"), 0o755)
	os.WriteFile(filepath.Join(files, "com.example.demo", "demo_linux_amd64"), []byte("binary-v1"), 0o755)
	draft, out := filepath.Join(dir, "draft.json"), filepath.Join(dir, "index.json")
	writeDraft(t, draft, "https://example.com/v1.0.0/demo_linux_amd64")

	opts := signOptions{indexPath: draft, outPath: out, keyPath: priv, pubPath: pub, serial: 3, filesDir: files}
	if err := signIndex(opts); err != nil {
		t.Fatal(err)
	}
	if err := verifyIndex(out, pub, files); err != nil {
		t.Fatal(err)
	}
	idx, _, err := readIndex(out)
	if err != nil {
		t.Fatal(err)
	}
	d := idx.Plugins[0].Downloads["linux_amd64"]
	if idx.Serial != 3 || d.Size != int64(len("binary-v1")) || len(d.SHA256) != 64 {
		t.Fatalf("serial, size and checksum must be filled in: %+v serial %d", d, idx.Serial)
	}
	if sig, _ := os.ReadFile(out + ".sig"); len(sig) != 64 {
		t.Fatalf("the signature must be the raw 64 bytes, got %d", len(sig))
	}

	//The serial only goes up
	if err := signIndex(opts); err == nil || !strings.Contains(err.Error(), "must be higher") {
		t.Fatalf("signing with the same serial again must be refused, got %v", err)
	}
	opts.serial = 2
	if err := signIndex(opts); err == nil {
		t.Fatal("signing with a lower serial must be refused")
	}
	opts.serial = 0
	if err := signIndex(opts); err == nil {
		t.Fatal("a serial is required")
	}

	//A changed index, a changed binary and another key are all noticed
	raw, _ := os.ReadFile(out)
	os.WriteFile(out, []byte(strings.Replace(string(raw), "v1.0.0", "v6.6.6", 1)), 0o644)
	if err := verifyIndex(out, pub, ""); err == nil {
		t.Fatal("an index changed after signing must not verify")
	}
	os.WriteFile(out, raw, 0o644)
	os.WriteFile(filepath.Join(files, "com.example.demo", "demo_linux_amd64"), []byte("binary-v2"), 0o755)
	if err := verifyIndex(out, pub, files); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("a changed binary must be noticed, got %v", err)
	}
	priv2, pub2 := filepath.Join(dir, "other.pem"), filepath.Join(dir, "other.pub")
	if err := generateKey(priv2, pub2); err != nil {
		t.Fatal(err)
	}
	if err := verifyIndex(out, pub2, ""); err == nil {
		t.Fatal("another key must not verify the index")
	}
	opts.serial, opts.keyPath = 9, priv2
	if err := signIndex(opts); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("signing with a key that does not match -pub must be refused, got %v", err)
	}
}

func TestSignRefusesWhatWouldNotVerifyLater(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	draft, out := filepath.Join(dir, "draft.json"), filepath.Join(dir, "index.json")
	base := signOptions{indexPath: draft, outPath: out, keyPath: priv, serial: 1}

	writeDraft(t, draft, "https://github.com/x/y/releases/latest/download/demo_linux_amd64")
	if err := signIndex(base); err == nil || !strings.Contains(err.Error(), "latest") {
		t.Fatalf("a download that points at latest must be refused, got %v", err)
	}
	writeDraft(t, draft, "http://example.com/v1/demo")
	if err := signIndex(base); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("a plain http download must be refused, got %v", err)
	}
	writeDraft(t, draft, "https://example.com/v1/demo")
	if err := signIndex(base); err == nil || !strings.Contains(err.Error(), "no sha256") {
		t.Fatalf("a download without a checksum, a local file or -fetch must be refused, got %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused signing must not write an index")
	}
}

// The plugin index key and the release key are two keys
func TestReleaseKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := generateKey(filepath.Join(dir, ".zoraxy-release-key"), filepath.Join(dir, "k.pub")); err == nil {
		t.Fatal("a key file named like the release key must be refused")
	}
	priv, pub := filepath.Join(dir, "plugin.pem"), filepath.Join(dir, "plugin.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZORAXY_RELEASE_KEY", priv)
	if _, err := loadPrivate(priv); err == nil || !strings.Contains(err.Error(), "release key") {
		t.Fatalf("the key $ZORAXY_RELEASE_KEY points at must be refused, got %v", err)
	}
}

func TestSignRawAddonIndex(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "addon-index.pem"), filepath.Join(dir, "addon-index.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	sum := strings.Repeat("ab", 32)
	doc := `{"format":"dunree-addon-index","version":1,"serial":3,"addons":[{"id":"ie.example.a","artifacts":{"linux_amd64":{"url":"a/x","sha256":"` + sum + `","size":5}}}]}` + "\n"
	index := filepath.Join(dir, "index.json")
	if err := os.WriteFile(index, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signRawIndex(index, priv, pub); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(index); string(got) != doc {
		t.Fatal("-sign-raw must not change a byte of the index")
	}
	if err := verifyIndex(index, pub, ""); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// One changed byte: the signature no longer matches
	if err := os.WriteFile(index, []byte(strings.Replace(doc, `"size":5`, `"size":6`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyIndex(index, pub, ""); err == nil {
		t.Fatal("a changed index must not verify")
	}
	// Refused: no serial, no checksum, a plugin index, another key than -pub
	for name, bad := range map[string]string{
		"no serial":    `{"format":"dunree-addon-index","version":1,"serial":0,"addons":[]}`,
		"no checksum":  `{"format":"dunree-addon-index","version":1,"serial":1,"addons":[{"id":"a","artifacts":{"linux_amd64":{"url":"x","sha256":"","size":5}}}]}`,
		"plugin index": `{"format":"zoraxy-plugin-index","version":1,"serial":1,"plugins":[]}`,
	} {
		p := filepath.Join(dir, "bad.json")
		os.WriteFile(p, []byte(bad), 0o644)
		if err := signRawIndex(p, priv, pub); err == nil {
			t.Errorf("%s: must be refused", name)
		}
		if _, err := os.Stat(p + ".sig"); err == nil {
			t.Errorf("%s: no signature may be written", name)
		}
	}
	otherPriv, otherPub := filepath.Join(dir, "other.pem"), filepath.Join(dir, "other.pub")
	if err := generateKey(otherPriv, otherPub); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(index, []byte(doc), 0o644)
	if err := signRawIndex(index, otherPriv, pub); err == nil {
		t.Fatal("a private key that does not match -pub must be refused")
	}
}
