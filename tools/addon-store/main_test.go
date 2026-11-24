package main

// Run with:  cd tools/addon-store && go test main.go main_test.go
// Uses throwaway keys only. The signer is the real tools/plugin-index program.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Minimal program file headers: enough for checkExecutable, not runnable
func fakeELF(machine uint16, tail string) []byte {
	b := make([]byte, 64)
	copy(b, "\x7fELF")
	b[4], b[5] = 2, 1 //64 bit, little endian
	binary.LittleEndian.PutUint16(b[18:], machine)
	return append(b, tail...)
}

func fakePE(machine uint16, tail string) []byte {
	b := make([]byte, 0x80+24)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], machine)
	return append(b, tail...)
}

func fakeMachO(cpu uint32, tail string) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], cpu)
	return append(b, tail...)
}

var png = []byte("\x89PNG\r\n\x1a\nnot really a picture")

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// sampleAddon writes ADDONS/demo with builds for three platforms
func sampleAddon(t *testing.T, in string, version string) {
	t.Helper()
	dir := filepath.Join(in, "demo")
	manifest := map[string]any{
		"id": "ie.example.demo", "name": "Demo <b>add-on</b>", "publisher": "Example Ltd", "description": "Shows the format. <script>alert(1)</script>",
		"homepage": "https://example.org/demo", "licence": "AGPL-3.0-only", "version": version, "api_version": 1, "min_host_version": "1.0.0",
		"type": "router", "categories": []string{"Security"},
		"permissions": []map[string]string{{"method": "GET", "endpoint": "/plugin/api/access/list", "reason": "read the list"}},
		"changelog":   []map[string]string{{"version": version, "date": "2026-11-20", "notes": "First release"}},
		"icon":        "icon.png", "screenshots": []string{"screenshots/one.png"},
	}
	raw, _ := json.Marshal(manifest)
	write(t, filepath.Join(dir, "addon.json"), raw)
	write(t, filepath.Join(dir, "icon.png"), png)
	write(t, filepath.Join(dir, "screenshots", "one.png"), png)
	write(t, filepath.Join(dir, "artifacts", "demo_linux_amd64"), fakeELF(62, version))
	write(t, filepath.Join(dir, "artifacts", "demo_linux_arm64"), fakeELF(183, version))
	write(t, filepath.Join(dir, "artifacts", "demo_windows_amd64.exe"), fakePE(0x8664, version))
	write(t, filepath.Join(dir, "artifacts", "demo_darwin_arm64"), fakeMachO(0x0100000c, version))
	write(t, filepath.Join(dir, "artifacts", "README.txt"), []byte("not an artifact"))
}

var signerBuild struct {
	bin string
	err error
}

// signer builds tools/plugin-index/sign_plugin_index.go once
func signer(t *testing.T) string {
	t.Helper()
	if signerBuild.bin == "" && signerBuild.err == nil {
		dir, err := os.MkdirTemp("", "addon-store-signer")
		if err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(dir, "signer")
		cmd := exec.Command("go", "build", "-o", bin, "sign_plugin_index.go")
		cmd.Dir = filepath.Join("..", "plugin-index")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			signerBuild.err = err
			t.Fatalf("building the signer failed: %v\n%s", err, out)
		}
		signerBuild.bin = bin
	}
	if signerBuild.err != nil {
		t.Fatal(signerBuild.err)
	}
	return signerBuild.bin
}

func TestMain(m *testing.M) {
	code := m.Run()
	if signerBuild.bin != "" {
		os.RemoveAll(filepath.Dir(signerBuild.bin))
	}
	os.Exit(code)
}

func keys(t *testing.T, dir string, name string) (priv string, pub string) {
	t.Helper()
	priv, pub = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".pub")
	if out, err := exec.Command(signer(t), "-genkey", priv, pub).CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}
	return priv, pub
}

func opts(t *testing.T, in, out string) options {
	return options{in: in, out: out, storeName: "Test store", publisher: "Example Ltd", signer: signer(t),
		now: func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }, stdout: io.Discard, stderr: io.Discard, hostGOOS: "linux", hostArch: "amd64"}
}

func readIndex(t *testing.T, out string) (*index, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	return &idx, raw
}

func TestGenerateSignedStore(t *testing.T) {
	work := t.TempDir()
	in, out := filepath.Join(work, "addons"), filepath.Join(work, "site")
	sampleAddon(t, in, "1.2.0")
	priv, pub := keys(t, work, "addon-index")
	o := opts(t, in, out)
	o.keyPath, o.pubPath = priv, pub
	if err := run(o); err != nil {
		t.Fatal(err)
	}

	idx, raw := readIndex(t, out)
	if idx.Format != "dunree-addon-index" || idx.Version != 1 || idx.Serial != 1 || len(idx.Addons) != 1 {
		t.Fatalf("unexpected index: %+v", idx)
	}
	a := idx.Addons[0]
	if a.ID != "ie.example.demo" || a.Publisher != "Example Ltd" || a.Licence != "AGPL-3.0-only" || a.MinHostVersion != "1.0.0" || a.APIVersion != 1 || len(a.Permissions) != 1 || len(a.Changelog) != 1 || len(a.Screenshots) != 1 || a.Icon == "" {
		t.Fatalf("metadata lost: %+v", a)
	}
	// One artifact per platform, with the checksum and size of the file, at a versioned relative address
	want := map[string]string{"linux_amd64": "demo_linux_amd64", "linux_arm64": "demo_linux_arm64", "windows_amd64": "demo_windows_amd64.exe", "darwin_arm64": "demo_darwin_arm64"}
	if len(a.Artifacts) != len(want) {
		t.Fatalf("want %d artifacts, got %v", len(want), a.Artifacts)
	}
	for platform, name := range want {
		art := a.Artifacts[platform]
		if art.URL != "addons/ie.example.demo/1.2.0/"+name {
			t.Errorf("%s: address %q", platform, art.URL)
		}
		data, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(art.URL)))
		if err != nil {
			t.Fatalf("%s: the artifact was not published: %v", platform, err)
		}
		sum := sha256.Sum256(data)
		if art.SHA256 != hex.EncodeToString(sum[:]) || art.Size != int64(len(data)) {
			t.Errorf("%s: checksum or size do not match the published file", platform)
		}
	}
	if !strings.HasSuffix(a.Artifacts["windows_amd64"].URL, ".exe") {
		t.Error("the Windows artifact must keep .exe")
	}

	// The signature is over the exact bytes of index.json, by the key of the test
	sig, err := os.ReadFile(filepath.Join(out, "index.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(pub)
	blk, _ := pem.Decode(pubPEM)
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(k.(ed25519.PublicKey), raw, sig) {
		t.Fatal("index.json.sig does not verify")
	}
	if published, _ := os.ReadFile(filepath.Join(out, "index.pub")); !bytes.Equal(published, pubPEM) {
		t.Error("index.pub must be the public key")
	}
	// The real tool verifies it too
	if msg, err := exec.Command(signer(t), "-verify", "-index", filepath.Join(out, "index.json"), "-pub", pub).CombinedOutput(); err != nil {
		t.Fatalf("sign_plugin_index -verify: %v\n%s", err, msg)
	}

	// The catalogue lists the add-on, and text of a manifest is never markup
	page, err := os.ReadFile(filepath.Join(out, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, must := range []string{"Test store", "Demo &lt;b&gt;add-on&lt;/b&gt;", "Signed index", "linux_amd64", a.Artifacts["linux_amd64"].SHA256, "AGPL-3.0-only", "index.pub"} {
		if !strings.Contains(html, must) {
			t.Errorf("the catalogue lacks %q", must)
		}
	}
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<b>add-on</b>") {
		t.Error("manifest text ended up as markup in the catalogue")
	}
	if strings.Contains(html, "http://") || strings.Count(html, "https://") != strings.Count(html, "https://example.org/demo") {
		t.Error("the catalogue must not load anything from another host")
	}
	// Nothing of the staging step is left
	if _, err := os.Stat(filepath.Join(out, "index.json.new")); err == nil {
		t.Error("index.json.new left behind")
	}
}

func TestSerialOnlyGoesUpAndPublishedFilesNeverChange(t *testing.T) {
	work := t.TempDir()
	in, out := filepath.Join(work, "addons"), filepath.Join(work, "site")
	sampleAddon(t, in, "1.0.0")
	o := opts(t, in, out)
	o.unsigned = true
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	if err := run(o); err != nil { //same content again: fine, serial 2
		t.Fatal(err)
	}
	if idx, _ := readIndex(t, out); idx.Serial != 2 {
		t.Fatalf("the serial must go up by itself, got %d", idx.Serial)
	}
	o.serial = 2
	if err := run(o); err == nil {
		t.Fatal("a serial that is not higher must be refused")
	}
	o.serial = 0

	// Another program file under the same version: refused, the published one stays
	linux := filepath.Join(in, "demo", "artifacts", "demo_linux_amd64")
	before, _ := os.ReadFile(filepath.Join(out, "addons", "ie.example.demo", "1.0.0", "demo_linux_amd64"))
	write(t, linux, fakeELF(62, "rebuilt"))
	if err := run(o); err == nil || !strings.Contains(err.Error(), "raise \"version\"") {
		t.Fatalf("replacing a published version must be refused, got %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(out, "addons", "ie.example.demo", "1.0.0", "demo_linux_amd64"))
	if !bytes.Equal(before, after) {
		t.Fatal("a published program file was replaced")
	}
	if idx, _ := readIndex(t, out); idx.Serial != 2 {
		t.Fatal("a refused run must not publish an index")
	}

	// A new version: both stay available, the index names the new one
	sampleAddon(t, in, "1.1.0")
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	idx, _ := readIndex(t, out)
	if idx.Serial != 3 || idx.Addons[0].Version != "1.1.0" || !strings.Contains(idx.Addons[0].Artifacts["linux_amd64"].URL, "/1.1.0/") {
		t.Fatalf("unexpected index after the new version: %+v", idx.Addons[0])
	}
	if _, err := os.Stat(filepath.Join(out, "addons", "ie.example.demo", "1.0.0", "demo_linux_amd64")); err != nil {
		t.Error("the older version must stay available")
	}
}

func TestUnsignedAndBaseURL(t *testing.T) {
	work := t.TempDir()
	in, out := filepath.Join(work, "addons"), filepath.Join(work, "site")
	sampleAddon(t, in, "1.0.0")
	o := opts(t, in, out)
	if err := run(o); err == nil {
		t.Fatal("without a key and without -unsigned nothing may be written")
	}
	if _, err := os.Stat(filepath.Join(out, "index.json")); err == nil {
		t.Fatal("an index was written without a key")
	}
	write(t, filepath.Join(out, "index.json.sig"), []byte("stale"))
	o.unsigned, o.baseURL = true, "https://addons.example.org/store"
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "index.json.sig")); err == nil {
		t.Error("the signature of an older index must not stay next to an unsigned one")
	}
	idx, _ := readIndex(t, out)
	if got := idx.Addons[0].Artifacts["windows_amd64"].URL; got != "https://addons.example.org/store/addons/ie.example.demo/1.0.0/demo_windows_amd64.exe" {
		t.Errorf("address with -base-url: %q", got)
	}
	page, _ := os.ReadFile(filepath.Join(out, "index.html"))
	if !strings.Contains(string(page), "Index not signed") {
		t.Error("the catalogue must say that the index is not signed")
	}
}

func TestArtifactVerification(t *testing.T) {
	type change func(t *testing.T, dir string)
	manifestWith := func(extra map[string]any) change {
		return func(t *testing.T, dir string) {
			m := map[string]any{"id": "ie.example.demo", "name": "Demo", "publisher": "Example Ltd", "licence": "MIT", "version": "1.0.0"}
			for k, v := range extra {
				if v == nil {
					delete(m, k)
				} else {
					m[k] = v
				}
			}
			raw, _ := json.Marshal(m)
			write(t, filepath.Join(dir, "addon.json"), raw)
		}
	}
	cases := map[string]struct {
		change change
		want   string
	}{
		"wrong cpu": {func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "artifacts", "demo_linux_amd64"), fakeELF(183, "x"))
		}, "another CPU"},
		"not a program": {func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "artifacts", "demo_linux_amd64"), []byte("#!/bin/sh\n"))
		}, "not an ELF"},
		"windows without exe": {manifestWith(map[string]any{"artifacts": map[string]string{"windows_amd64": "artifacts/demo_linux_amd64"}}), ".exe"},
		"exe for linux":       {manifestWith(map[string]any{"artifacts": map[string]string{"linux_amd64": "artifacts/demo_windows_amd64.exe"}}), "only a Windows"},
		"elf as windows": {func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "artifacts", "demo_windows_amd64.exe"), fakeELF(62, "x"))
		}, "not a Windows"},
		"wrong checksum":     {manifestWith(map[string]any{"artifacts": map[string]any{"linux_amd64": map[string]string{"file": "artifacts/demo_linux_amd64", "sha256": strings.Repeat("0", 64)}}}), "the manifest says sha256"},
		"outside the folder": {manifestWith(map[string]any{"artifacts": map[string]string{"linux_amd64": "../../secret"}}), "leaves the add-on folder"},
		"absolute path":      {manifestWith(map[string]any{"artifacts": map[string]string{"linux_amd64": "/etc/passwd"}}), "inside the add-on folder"},
		"missing file":       {manifestWith(map[string]any{"artifacts": map[string]string{"linux_amd64": "artifacts/nope"}}), "file not found"},
		"bad platform":       {manifestWith(map[string]any{"artifacts": map[string]string{"linux": "artifacts/demo_linux_amd64"}}), "os_arch"},
		"no licence":         {manifestWith(map[string]any{"licence": nil}), "licence"},
		"bad version":        {manifestWith(map[string]any{"version": "1.0"}), "major.minor.patch"},
		"bad id":             {manifestWith(map[string]any{"id": "../x"}), "\"id\""},
		"unknown field":      {manifestWith(map[string]any{"licnce": "MIT"}), "unknown field"},
		"svg icon":           {manifestWith(map[string]any{"icon": "icon.svg"}), "pictures must be"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			in := filepath.Join(work, "addons")
			sampleAddon(t, in, "1.0.0")
			c.change(t, filepath.Join(in, "demo"))
			o := opts(t, in, filepath.Join(work, "site"))
			o.unsigned = true
			err := run(o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error with %q, got %v", c.want, err)
			}
			if _, statErr := os.Stat(filepath.Join(work, "site", "index.json")); statErr == nil {
				t.Fatal("nothing may be published when an add-on fails its checks")
			}
		})
	}
}

func TestCheckWritesNothing(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "addons")
	sampleAddon(t, in, "1.0.0")
	o := opts(t, in, "")
	o.check = true
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 1 {
		t.Fatalf("-check must write nothing, found %d entries", len(entries))
	}
}

func TestSigningFailureLeavesThePublishedIndexAlone(t *testing.T) {
	work := t.TempDir()
	in, out := filepath.Join(work, "addons"), filepath.Join(work, "site")
	sampleAddon(t, in, "1.0.0")
	priv, pub := keys(t, work, "addon-index")
	o := opts(t, in, out)
	o.keyPath, o.pubPath = priv, pub
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	_, before := readIndex(t, out)
	sigBefore, _ := os.ReadFile(filepath.Join(out, "index.json.sig"))

	_, otherPub := keys(t, work, "other")
	o.pubPath = otherPub
	if err := run(o); err == nil {
		t.Fatal("a key that does not match -pub must stop the run")
	}
	_, after := readIndex(t, out)
	sigAfter, _ := os.ReadFile(filepath.Join(out, "index.json.sig"))
	if !bytes.Equal(before, after) || !bytes.Equal(sigBefore, sigAfter) {
		t.Fatal("a failed signing changed the published index or its signature")
	}
}

func TestCheckExecutable(t *testing.T) {
	ok := []struct {
		head         []byte
		goos, goarch string
	}{
		{fakeELF(62, ""), "linux", "amd64"}, {fakeELF(183, ""), "linux", "arm64"}, {fakeELF(62, ""), "freebsd", "amd64"},
		{fakePE(0x8664, ""), "windows", "amd64"}, {fakePE(0xaa64, ""), "windows", "arm64"},
		{fakeMachO(0x01000007, ""), "darwin", "amd64"}, {fakeMachO(0x0100000c, ""), "darwin", "arm64"},
		{[]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}, "darwin", "arm64"}, //universal
		{[]byte("anything"), "plan9", "amd64"},                          //no rule for this system
	}
	for _, c := range ok {
		if err := checkExecutable(c.head, c.goos, c.goarch); err != nil {
			t.Errorf("%s/%s: %v", c.goos, c.goarch, err)
		}
	}
	bad := []struct {
		head         []byte
		goos, goarch string
	}{
		{fakeELF(62, ""), "linux", "arm64"}, {fakePE(0x8664, ""), "linux", "amd64"}, {fakeELF(62, ""), "windows", "amd64"},
		{fakePE(0x8664, ""), "windows", "arm64"}, {fakeMachO(0x01000007, ""), "darwin", "arm64"}, {fakeELF(62, ""), "darwin", "amd64"},
		{nil, "linux", "amd64"}, {[]byte("MZ"), "windows", "amd64"},
	}
	for _, c := range bad {
		if err := checkExecutable(c.head, c.goos, c.goarch); err == nil {
			t.Errorf("%s/%s: a wrong file was accepted", c.goos, c.goarch)
		}
	}
}
