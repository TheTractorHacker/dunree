package main

// Run with:  cd tools && go test sign_release.go sign_release_test.go
// Uses throwaway keys only.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := generateKey(priv, pub); err == nil {
		t.Fatal("genkey must not overwrite")
	}
	dist := filepath.Join(dir, "dist")
	os.MkdirAll(dist, 0o755)
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_amd64"), []byte("bin-a"), 0o755)
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_arm64"), []byte("bin-b"), 0o755)
	os.WriteFile(filepath.Join(dist, "README"), []byte("ignored"), 0o644)

	if err := signDist(dist, priv, pub, "v3.3.6-x.1", 7); err != nil {
		t.Fatal(err)
	}
	if err := verifyDist(dist, pub); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dist, "SHA256SUMS"))
	if !strings.HasPrefix(string(sums), "# zoraxy-release tag=v3.3.6-x.1 build=7 upstream=3.3.6\n") {
		t.Fatalf("missing header: %q", sums)
	}
	if signDist(dist, priv, pub, "", 7) == nil || signDist(dist, priv, pub, "v3.3.6", 0) == nil {
		t.Fatal("tag and build must be required")
	}
	// tamper with a binary
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_arm64"), []byte("evil"), 0o755)
	if verifyDist(dist, pub) == nil {
		t.Fatal("tampered binary verified")
	}
	// wrong public key
	priv2, pub2 := filepath.Join(dir, "k2.pem"), filepath.Join(dir, "k2.pub")
	generateKey(priv2, pub2)
	os.WriteFile(filepath.Join(dist, "zoraxy_linux_arm64"), []byte("bin-b"), 0o755)
	if verifyDist(dist, pub2) == nil {
		t.Fatal("wrong key verified")
	}
	if signDist(dist, priv, pub2, "v3.3.6-x.1", 7) == nil {
		t.Fatal("sign must flag a key/pub mismatch")
	}
}

// Dunree asset names (binaries, .exe, packages) are signed next to the legacy
// zoraxy_* names; other files are still left out.
func TestSignCoversDunreeAndLegacyNames(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(dir, "dist")
	os.MkdirAll(dist, 0o755)
	signed := []string{
		"dunree_linux_amd64", "dunree_windows_amd64.exe", "dunree_darwin_arm64",
		"dunree_1.0.0_linux_amd64.tar.gz", "dunree_1.0.0_windows_amd64.zip",
		"zoraxy_linux_amd64", "crowdsec-setup.sh",
	}
	for _, n := range signed {
		os.WriteFile(filepath.Join(dist, n), []byte("content of "+n), 0o644)
	}
	os.WriteFile(filepath.Join(dist, "notes.txt"), []byte("not an asset"), 0o644)
	os.MkdirAll(filepath.Join(dist, "dunree_folder"), 0o755)

	if err := signDist(dist, priv, pub, "v3.3.6-x.2", 8); err != nil {
		t.Fatal(err)
	}
	if err := verifyDist(dist, pub); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dist, "SHA256SUMS"))
	for _, n := range signed {
		if !strings.Contains(string(sums), "  "+n+"\n") {
			t.Errorf("%s is not in SHA256SUMS", n)
		}
	}
	for _, n := range []string{"notes.txt", "dunree_folder"} {
		if strings.Contains(string(sums), n) {
			t.Errorf("%s must not be in SHA256SUMS", n)
		}
	}
	// the header an installed updater checks is unchanged
	if !strings.HasPrefix(string(sums), "# zoraxy-release tag=v3.3.6-x.2 build=8 upstream=3.3.6\n") {
		t.Fatalf("header changed: %q", strings.SplitN(string(sums), "\n", 2)[0])
	}
	// a legacy copy that is not byte-identical any more is caught
	os.WriteFile(filepath.Join(dist, "dunree_windows_amd64.exe"), []byte("evil"), 0o644)
	if verifyDist(dist, pub) == nil {
		t.Fatal("tampered dunree_ file verified")
	}
	// a folder with only Dunree names is enough to sign
	only := filepath.Join(dir, "only")
	os.MkdirAll(only, 0o755)
	os.WriteFile(filepath.Join(only, "dunree_linux_amd64"), []byte("x"), 0o755)
	if err := signDist(only, priv, pub, "v3.3.6-x.2", 9); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	os.MkdirAll(empty, 0o755)
	os.WriteFile(filepath.Join(empty, "other_linux_amd64"), []byte("x"), 0o755)
	if signDist(empty, priv, pub, "v3.3.6-x.2", 9) == nil {
		t.Fatal("a folder without release files must not be signed")
	}
}

func TestKeyFromEnvPrefersDunreeName(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if keyFromEnv(get) != "" {
		t.Fatal("no variable set must give no path")
	}
	env["ZORAXY_RELEASE_KEY"] = "/old.pem"
	if keyFromEnv(get) != "/old.pem" {
		t.Fatal("the older variable must still be read")
	}
	env["DUNREE_RELEASE_KEY"] = "/new.pem"
	if keyFromEnv(get) != "/new.pem" {
		t.Fatal("the Dunree variable must win")
	}
}
