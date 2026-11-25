package main

// Run with:  cd tools && go test sign_release.go sign_release_test.go
// Uses throwaway keys only.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHeader = "# dunree-release product=dunree tag=v1.0.0-beta.1 build=7 upstream=3.3.6\n"

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
	os.WriteFile(filepath.Join(dist, "dunree_linux_amd64"), []byte("bin-a"), 0o755)
	os.WriteFile(filepath.Join(dist, "dunree_linux_arm64"), []byte("bin-b"), 0o755)
	os.WriteFile(filepath.Join(dist, "README"), []byte("ignored"), 0o644)

	if err := signDist(dist, priv, pub, "v1.0.0-beta.1", "3.3.6", 7); err != nil {
		t.Fatal(err)
	}
	if err := verifyDist(dist, pub); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dist, "SHA256SUMS"))
	if !strings.HasPrefix(string(sums), testHeader) {
		t.Fatalf("missing header: %q", sums)
	}
	if signDist(dist, priv, pub, "", "3.3.6", 7) == nil || signDist(dist, priv, pub, "v1.0.0", "3.3.6", 0) == nil {
		t.Fatal("tag and build must be required")
	}
	// tamper with a binary
	os.WriteFile(filepath.Join(dist, "dunree_linux_arm64"), []byte("evil"), 0o755)
	if verifyDist(dist, pub) == nil {
		t.Fatal("tampered binary verified")
	}
	// wrong public key
	priv2, pub2 := filepath.Join(dir, "k2.pem"), filepath.Join(dir, "k2.pub")
	generateKey(priv2, pub2)
	os.WriteFile(filepath.Join(dist, "dunree_linux_arm64"), []byte("bin-b"), 0o755)
	if verifyDist(dist, pub2) == nil {
		t.Fatal("wrong key verified")
	}
	if signDist(dist, priv, pub2, "v1.0.0-beta.1", "3.3.6", 7) == nil {
		t.Fatal("sign must flag a key/pub mismatch")
	}
}

func TestTagAndUpstreamForms(t *testing.T) {
	for _, good := range []string{"v1.0.0", "v1.0.0-beta.1", "v1.0.0-rc.2", "v2.10.3", "v0.9.0-alpha", "v1.0.0-beta.0", "v1.0.0-0a"} {
		if !tagRe.MatchString(good) {
			t.Errorf("%s must be a valid tag", good)
		}
	}
	// the tag forms of the earlier fork with a fourth number, a tag without v, build metadata
	for _, bad := range []string{"", "1.0.0", "v1.0", "v1.0.0.1", "v1.0.0-", "v1.0.0+5", "v01.0.0", "v1.0.0-beta..1", "v1.0.0 ", "v1.0.0-b_1", "latest", "v1.0.0-beta.01", "v1.0.0-007"} {
		if tagRe.MatchString(bad) {
			t.Errorf("%q must not be a valid tag", bad)
		}
	}
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "dunree_linux_amd64"), []byte("x"), 0o755)
	for _, bad := range []string{"3.3", "v3.3.6", "3.3.6 x=1", "3.3.6\nfoo"} {
		if signDist(dir, priv, pub, "v1.0.0", bad, 1) == nil {
			t.Errorf("-upstream %q accepted", bad)
		}
	}
	// upstream is optional: the header then has no such field and still verifies
	if err := signDist(dir, priv, pub, "v1.0.0", "", 1); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if !strings.HasPrefix(string(sums), "# dunree-release product=dunree tag=v1.0.0 build=1\n") {
		t.Fatalf("header without upstream: %q", sums)
	}
	if err := verifyDist(dir, pub); err != nil {
		t.Fatal(err)
	}
}

func TestValidHeader(t *testing.T) {
	good := strings.TrimSuffix(testHeader, "\n")
	if !validHeader(good) || !validHeader(good+"\r") || !validHeader("# dunree-release tag=v1.0.0 build=3 product=dunree") {
		t.Fatal("a Dunree header must be valid")
	}
	for _, bad := range []string{
		"# zoraxy-release tag=v3.3.6-x.1 build=7 upstream=3.3.6",                   // legacy-compat: the header of the earlier fork
		"# zoraxy-release product=dunree tag=v1.0.0-beta.1 build=7 upstream=3.3.6", // legacy-compat
		"# dunree-release tag=v1.0.0-beta.1 build=7 upstream=3.3.6",
		"# dunree-release product=other tag=v1.0.0-beta.1 build=7",
		"# dunree-release product=dunree tag=v1.0.0-beta.1",
		"# dunree-release product=dunree tag=v1.0.0-beta.1 build=x",
		"# dunree-release product=dunree tag=nightly build=7",
		"# dunree-release product=dunree tag=v9.0.0 tag=v1.0.0 build=7",
		"#dunree-release product=dunree tag=v1.0.0 build=7",
		"",
	} {
		if validHeader(bad) {
			t.Errorf("%q must not be a valid header", bad)
		}
	}
}

// A release whose SHA256SUMS carries the header of the earlier fork (or none) does not verify,
// although the signature and every checksum are right.
func TestVerifyRefusesOtherHeaders(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	if err := generateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(dir, "dist")
	os.MkdirAll(dist, 0o755)
	os.WriteFile(filepath.Join(dist, "dunree_linux_amd64"), []byte("bin-a"), 0o755)
	if err := signDist(dist, priv, pub, "v1.0.0-beta.1", "3.3.6", 7); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dist, "SHA256SUMS"))
	body := strings.SplitN(string(sums), "\n", 2)[1]
	key, err := loadPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, hdr := range []string{"# zoraxy-release tag=v1.0.0-beta.1 build=7 upstream=3.3.6\n", "# dunree-release tag=v1.0.0-beta.1 build=7\n", ""} { // legacy-compat
		forged := hdr + body
		os.WriteFile(filepath.Join(dist, "SHA256SUMS"), []byte(forged), 0o644)
		os.WriteFile(filepath.Join(dist, "SHA256SUMS.sig"), signBytes(key, []byte(forged)), 0o644)
		if verifyDist(dist, pub) == nil {
			t.Errorf("header %q verified", hdr)
		}
	}
}

// Program files, .exe, archives and packages are signed; other files are left out; a file
// with the name of the earlier fork stops the signing.
func TestSignCoversDunreeNamesOnly(t *testing.T) {
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
		"crowdsec-setup.sh",
	}
	for _, n := range signed {
		os.WriteFile(filepath.Join(dist, n), []byte("content of "+n), 0o644)
	}
	os.WriteFile(filepath.Join(dist, "notes.txt"), []byte("not an asset"), 0o644)
	os.MkdirAll(filepath.Join(dist, "dunree_folder"), 0o755)

	if err := signDist(dist, priv, pub, "v1.0.0-beta.1", "3.3.6", 7); err != nil {
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
	if !strings.HasPrefix(string(sums), testHeader) {
		t.Fatalf("header: %q", strings.SplitN(string(sums), "\n", 2)[0])
	}
	os.WriteFile(filepath.Join(dist, "dunree_windows_amd64.exe"), []byte("evil"), 0o644)
	if verifyDist(dist, pub) == nil {
		t.Fatal("tampered dunree_ file verified")
	}
	// a file named like the earlier fork's is not signed silently and not left out silently
	legacy := filepath.Join(dir, "legacy")
	os.MkdirAll(legacy, 0o755)
	os.WriteFile(filepath.Join(legacy, "dunree_linux_amd64"), []byte("x"), 0o755)
	os.WriteFile(filepath.Join(legacy, "zoraxy_linux_amd64"), []byte("x"), 0o755) // legacy-compat
	if err := signDist(legacy, priv, pub, "v1.0.0-beta.1", "3.3.6", 9); err == nil || !strings.Contains(err.Error(), "earlier fork") {
		t.Fatalf("a file with the earlier name must stop the signing, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacy, "SHA256SUMS")); err == nil {
		t.Fatal("SHA256SUMS written although the signing was refused")
	}
	empty := filepath.Join(dir, "empty")
	os.MkdirAll(empty, 0o755)
	os.WriteFile(filepath.Join(empty, "other_linux_amd64"), []byte("x"), 0o755)
	if signDist(empty, priv, pub, "v1.0.0-beta.1", "3.3.6", 9) == nil {
		t.Fatal("a folder without release files must not be signed")
	}
}

func TestKeyFromEnvPrefersDunreeName(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if keyFromEnv(get) != "" || pubFromEnv(get) != "" {
		t.Fatal("no variable set must give no path")
	}
	env["ZORAXY_RELEASE_KEY"] = "/old.pem"
	env["ZORAXY_RELEASE_PUB"] = "/old.pub"
	if keyFromEnv(get) != "/old.pem" || pubFromEnv(get) != "/old.pub" {
		t.Fatal("the older variables must still be read")
	}
	env["DUNREE_RELEASE_KEY"] = "/new.pem"
	if keyFromEnv(get) != "/new.pem" || pubFromEnv(get) != "/old.pub" {
		t.Fatal("the Dunree variable must win, each variable by itself")
	}
	env["DUNREE_RELEASE_PUB"] = "/new.pub"
	if pubFromEnv(get) != "/new.pub" {
		t.Fatal("the Dunree public key variable must win")
	}
	env["DUNREE_RELEASE_KEY"] = ""
	if keyFromEnv(get) != "/old.pem" {
		t.Fatal("an empty Dunree variable falls back to the older one")
	}
}
