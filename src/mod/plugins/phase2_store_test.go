package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
	Phase 2 of docs/plugins/reliability-plan.md, items 2.4 (signed index), 2.5 (safe
	install, update and rollback) and 2.7 (isolated plugin UI).

	Everything here is local: the "store" is an httptest server, the plugin is the
	chaos plugin, and the index is signed by the real tool (tools/plugin-index)
	with a key pair the tool creates for the test. No key of the owner is read.
*/

var indexToolBuild struct {
	once sync.Once
	bin  string
	err  error
}

// indexTool builds tools/plugin-index/sign_plugin_index.go once per test run
func indexTool(t testing.TB) string {
	t.Helper()
	chaosBinary(t) //creates the build folder that TestMain removes, and skips on Windows
	indexToolBuild.once.Do(func() {
		bin := filepath.Join(chaosBuild.dir, "plugin-index-tool")
		cmd := exec.Command("go", "build", "-o", bin, "sign_plugin_index.go")
		cmd.Dir = filepath.Join("..", "..", "..", "tools", "plugin-index")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-p=2", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			indexToolBuild.err = errors.New("building the plugin index tool failed: " + err.Error() + "\n" + string(out))
			return
		}
		indexToolBuild.bin = bin
	})
	if indexToolBuild.err != nil {
		t.Fatal(indexToolBuild.err)
	}
	return indexToolBuild.bin
}

// chaosVariant is the chaos binary with settings of its own appended: "another
// version" of a plugin, with another checksum
func chaosVariant(t testing.TB, trailer string) []byte {
	t.Helper()
	bin, err := os.ReadFile(chaosBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	return append(bin, []byte("\n##CHAOS-TRAILER##\n"+trailer+"\n")...)
}

// storeFix is a local plugin store: an index, its signature and downloads
type storeFix struct {
	t     testing.TB
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	slow  map[string]http.HandlerFunc
	hits  map[string]int
	work  string
	priv  string
	pub   string
}

func newStoreFix(t testing.TB) *storeFix {
	t.Helper()
	f := &storeFix{t: t, files: map[string][]byte{}, slow: map[string]http.HandlerFunc{}, hits: map[string]int{}, work: t.TempDir()}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		body, ok := f.files[r.URL.Path]
		special := f.slow[r.URL.Path]
		f.mu.Unlock()
		if special != nil {
			special(w, r)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", itoa(len(body)))
		w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *storeFix) url(path string) string { return f.srv.URL + path }

func (f *storeFix) put(path string, body []byte) {
	f.mu.Lock()
	f.files[path] = body
	f.mu.Unlock()
}

func (f *storeFix) get(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[path]
}

func (f *storeFix) handle(path string, h http.HandlerFunc) {
	f.mu.Lock()
	f.slow[path] = h
	f.mu.Unlock()
}

func (f *storeFix) hitCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *storeFix) tool(args ...string) (string, error) {
	out, err := exec.Command(indexTool(f.t), args...).CombinedOutput()
	return string(out), err
}

// keys creates a throw-away key pair with the tool and returns the public key file content
func (f *storeFix) keys(name string) (priv string, pubText string) {
	f.t.Helper()
	priv, pub := filepath.Join(f.work, name+".pem"), filepath.Join(f.work, name+".pub")
	if out, err := f.tool("-genkey", priv, pub); err != nil {
		f.t.Fatalf("genkey: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(pub)
	if err != nil {
		f.t.Fatal(err)
	}
	return priv, string(raw)
}

// idxPlugin is one plugin of a test index: name is also the install folder and
// the last part of the chaos plugin ID
type idxPlugin struct {
	name    string
	version [3]int
	bin     []byte
}

func (p idxPlugin) id() string { return "test.chaos." + strings.ToLower(p.name) }
func (p idxPlugin) path() string {
	return "/bin/" + p.name + "-" + versionToString(p.version[0], p.version[1], p.version[2])
}

func (p idxPlugin) spec() map[string]any {
	return map[string]any{
		"id": p.id(), "name": p.name, "author": "test", "description": "test", "ui_path": "/ui",
		"version_major": p.version[0], "version_minor": p.version[1], "version_patch": p.version[2],
	}
}

// publishSigned serves the binaries and an index over them that the tool signed
// with privKey, at /<indexName> and /<indexName>.sig
func (f *storeFix) publishSigned(indexName string, privKey string, serial int, plugins ...idxPlugin) {
	f.t.Helper()
	filesDir := filepath.Join(f.work, "files-"+indexName)
	os.MkdirAll(filesDir, 0o755)
	entries := []any{}
	for _, p := range plugins {
		f.put(p.path(), p.bin)
		if err := os.WriteFile(filepath.Join(filesDir, filepath.Base(p.path())), p.bin, 0o644); err != nil {
			f.t.Fatal(err)
		}
		entries = append(entries, map[string]any{
			"IconPath": "", "PluginIntroSpect": p.spec(),
			"Downloads": map[string]any{platformKey(): map[string]any{"url": f.url(p.path())}},
		})
	}
	draft := filepath.Join(f.work, "draft-"+indexName)
	raw, _ := json.Marshal(map[string]any{"format": signedIndexFormat, "version": signedIndexVersion, "plugins": entries})
	if err := os.WriteFile(draft, raw, 0o644); err != nil {
		f.t.Fatal(err)
	}
	out := filepath.Join(f.work, "signed-"+itoa(serial)+"-"+indexName)
	os.Remove(out) //the tool refuses to sign over an index with the same or a higher serial
	os.Remove(out + ".sig")
	if msg, err := f.tool("-index", draft, "-out", out, "-key", privKey, "-serial", itoa(serial), "-files", filesDir, "-allow-http"); err != nil {
		f.t.Fatalf("signing the index: %v\n%s", err, msg)
	}
	doc, _ := os.ReadFile(out)
	sig, _ := os.ReadFile(out + ".sig")
	f.put("/"+indexName, doc)
	f.put("/"+indexName+".sig", sig)
}

// publishLegacy serves an index in the upstream format (a list, no checksums)
func (f *storeFix) publishLegacy(indexName string, extra map[string]any, plugins ...idxPlugin) {
	entries := []any{}
	for _, p := range plugins {
		f.put(p.path(), p.bin)
		e := map[string]any{"IconPath": "", "PluginIntroSpect": p.spec(), "DownloadURLs": map[string]string{platformKey(): f.url(p.path())}}
		for k, v := range extra {
			e[k] = v
		}
		entries = append(entries, e)
	}
	raw, _ := json.Marshal(entries)
	f.put("/"+indexName, raw)
}

// storeManager is a fault manager whose only plugin index is the fixture
func storeManager(t *testing.T, f *storeFix, indexNames ...string) *Manager {
	t.Helper()
	m := newFaultManager(t)
	if err := os.MkdirAll(m.Options.PluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range indexNames {
		m.Options.PluginStoreURLs = append(m.Options.PluginStoreURLs, f.url("/"+n))
	}
	m.Options.ProbePluginPorts = true
	m.storeCfg = storeTunables{HealthTimeout: 4 * time.Second, HealthSettle: 300 * time.Millisecond}
	t.Cleanup(func() { m.Close() })
	return m
}

func setVerify(t testing.TB, m *Manager, mode string, pubText string) {
	t.Helper()
	if err := m.SetSettings(func(s *ManagerSettings) { s.VerifyMode, s.IndexPublicKey = mode, pubText }); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
}

func sync1(t testing.TB, m *Manager) {
	t.Helper()
	if err := m.UpdateDownloadablePluginList(); err != nil {
		t.Fatalf("sync of the plugin indexes: %v", err)
	}
}

func installByID(m *Manager, id string) error {
	p := m.installCandidate(id, "")
	if p == nil {
		return errors.New("not offered")
	}
	return m.InstallPlugin(p)
}

func noStagingLeft(t testing.TB, m *Manager) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(m.Options.PluginDir, stagingDirName))
	if len(entries) != 0 {
		t.Fatalf("the staging folder still holds %d entries (%s)", len(entries), entries[0].Name())
	}
}

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

var (
	v1 = [3]int{1, 0, 0}
	v2 = [3]int{1, 1, 0}
)

func goodV1(t testing.TB, name string) idxPlugin {
	return idxPlugin{name: name, version: v1, bin: chaosVariant(t, "version=1.0.0")}
}
func goodV2(t testing.TB, name string) idxPlugin {
	return idxPlugin{name: name, version: v2, bin: chaosVariant(t, "version=1.1.0")}
}

/* 2.4 Signed index */

func TestStoreDefaultsChangeNothing(t *testing.T) {
	m := newFaultManager(t)
	s := m.Settings()
	if s.VerifyMode != VerifyWarn || s.AutoRollback || s.IsolatePluginUI || s.IndexPublicKey != "" {
		t.Fatalf("defaults: signature checking warn, no key, no automatic rollback, plugin pages not isolated; got %+v", s)
	}
	if st := m.uiIsolationState(); st.Enabled || st.Listening {
		t.Fatalf("no listener for isolated plugin pages by default: %+v", st)
	}
	if err := m.SetSettings(func(s *ManagerSettings) { s.VerifyMode = "strict" }); err == nil {
		t.Fatal("an unknown verification mode must be refused")
	}
	if err := m.SetSettings(func(s *ManagerSettings) { s.IndexPublicKey = "not a key" }); err == nil {
		t.Fatal("a public key that cannot be read must be refused")
	}
}

func TestSignedIndexKeyFormats(t *testing.T) {
	f := newStoreFix(t)
	priv, pubText := f.keys("fmt")
	pk, err := parseIndexPublicKey(pubText)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{hex.EncodeToString(pk), "  " + pubText + "\n"} {
		got, err := parseIndexPublicKey(text)
		if err != nil || !got.Equal(pk) {
			t.Fatalf("key text %q: %v", text[:12], err)
		}
	}
	privText, _ := os.ReadFile(priv)
	if _, err := parseIndexPublicKey(string(privText)); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("a private key pasted as the public key must be refused with a clear error, got %v", err)
	}
	// The start flag wins over the setting
	m := newFaultManager(t)
	_, otherPub := f.keys("other")
	setVerify(t, m, VerifyWarn, otherPub)
	m.Options.IndexPublicKeyFile = filepath.Join(f.work, "fmt.pub")
	got, from, err := m.indexPublicKey()
	if err != nil || from != "flag" || !got.Equal(pk) {
		t.Fatalf("the key file of the start flag must win: from %q, %v", from, err)
	}
}

// The index is signed by the real tool; Zoraxy verifies it, installs from it with
// signature checking set to enforce, and records where the plugin came from.
func TestSignedIndexInstallUnderEnforce(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "signedp")
	f.publishSigned("index.json", priv, 5, p1)
	m := storeManager(t, f, "index.json")
	audit := trapAudit(m)
	setVerify(t, m, VerifyEnforce, pub)
	sync1(t, m)

	src := m.ListStoreSources()
	if len(src) != 1 || src[0].Signature != SigSigned || src[0].Serial != 5 || src[0].Format != "signed" || src[0].Plugins != 1 {
		t.Fatalf("status of the index: %+v", src)
	}
	if err := installByID(m, p1.id()); err != nil {
		t.Fatalf("install from a validly signed index under enforce: %v", err)
	}
	p, err := m.GetPluginByID(p1.id())
	if err != nil {
		t.Fatal(err)
	}
	info := p.Status().Install
	if !info.Known || info.Source != f.url("/index.json") || info.Signature != SigSigned || info.Verified != VerifiedHashOK ||
		info.SHA256 != sumOf(p1.bin) || info.Version != "1.0.0" || info.CanRollback || info.Note != "" {
		t.Fatalf("install record in the status: %+v", info)
	}
	noStagingLeft(t, m)
	if m.GetPluginPreviousEnableState(p1.id()) {
		t.Fatal("a freshly installed plugin must be stored as not enabled")
	}
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	if st := p.Status().Install; st.BinaryState != "ok" {
		t.Fatalf("the binary is the installed one, state %q", st.BinaryState)
	}
	if len(audit.of(p1.id())) != 0 {
		t.Fatalf("a clean install must not write audit entries of the plugin manager: %+v", audit.of(p1.id()))
	}
}

// A binary that is not the one the index describes: warn installs it and says
// so, enforce refuses it and leaves nothing behind.
func TestSignedIndexTamperedBinaryPerMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(orig []byte) []byte
	}{
		{"same size, other content", func(orig []byte) []byte {
			b := append([]byte{}, orig...)
			b[len(b)-2] ^= 0x01 //inside the trailer: the program still runs
			return b
		}},
		{"larger than the index says", func(orig []byte) []byte { return append(append([]byte{}, orig...), []byte("#extra\n")...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreFix(t)
			priv, pub := f.keys("k")
			p1 := goodV1(t, "tampered")
			f.publishSigned("index.json", priv, 1, p1)
			f.put(p1.path(), tc.tamper(p1.bin)) //the download is swapped after the index was signed

			//enforce: refused
			m := storeManager(t, f, "index.json")
			audit := trapAudit(m)
			setVerify(t, m, VerifyEnforce, pub)
			sync1(t, m)
			err := installByID(m, p1.id())
			if err == nil || !(strings.Contains(err.Error(), "does not match its index") || strings.Contains(err.Error(), "than the limit")) {
				t.Fatalf("enforce must refuse a download that does not match the index, got %v", err)
			}
			if _, err := m.GetPluginByID(p1.id()); err == nil {
				t.Fatal("the refused plugin was loaded")
			}
			if _, err := os.Stat(filepath.Join(m.Options.PluginDir, "tampered")); !os.IsNotExist(err) {
				t.Fatalf("the refused install left a plugin folder (%v)", err)
			}
			noStagingLeft(t, m)
			if m.installRecord(p1.id()) != nil {
				t.Fatal("a refused install must not leave an install record")
			}

			//warn (default): installed, and reported
			m2 := storeManager(t, f, "index.json")
			audit2 := trapAudit(m2)
			setVerify(t, m2, VerifyWarn, pub)
			sync1(t, m2)
			if err := installByID(m2, p1.id()); err != nil {
				t.Fatalf("warn must install anyway: %v", err)
			}
			p, _ := m2.GetPluginByID(p1.id())
			info := p.Status().Install
			if info.Verified != VerifiedMismatch || info.Note == "" || info.Signature != SigSigned {
				t.Fatalf("the mismatch must be on record and shown: %+v", info)
			}
			got := audit2.of(p1.id())
			if len(got) != 1 || got[0].Event != "plugins.download.mismatch" || got[0].Detail["mode"] != VerifyWarn {
				t.Fatalf("one audit entry for the mismatch: %+v", got)
			}
			_ = audit
		})
	}
}

// An index that was changed after it was signed, signed with another key, without
// a signature file, or checked without a key: warn lists and installs, enforce refuses.
func TestSignedIndexBadSignaturePerMode(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	otherPriv, otherPub := f.keys("other")
	_ = otherPriv
	p1 := goodV1(t, "badsig")
	f.publishSigned("index.json", priv, 1, p1)
	goodDoc, goodSig := f.get("/index.json"), f.get("/index.json.sig")

	// The attacker points the download at a binary of his own and fixes the checksum in the index
	evil := chaosVariant(t, "version=1.0.0\nname=evil")
	f.put("/bin/evil", evil)
	var doc map[string]any
	json.Unmarshal(goodDoc, &doc)
	dl := doc["plugins"].([]any)[0].(map[string]any)["Downloads"].(map[string]any)[platformKey()].(map[string]any)
	dl["url"], dl["sha256"], dl["size"] = f.url("/bin/evil"), sumOf(evil), len(evil)
	forged, _ := json.Marshal(doc)

	cases := []struct {
		name  string
		setup func()
		key   string
		want  string
	}{
		{"index changed after signing", func() { f.put("/index.json", forged); f.put("/index.json.sig", goodSig) }, pub, SigBad},
		{"signed with another key", func() { f.put("/index.json", goodDoc); f.put("/index.json.sig", goodSig) }, otherPub, SigBad},
		{"signature file is not a signature", func() { f.put("/index.json", goodDoc); f.put("/index.json.sig", []byte("nope")) }, pub, SigBad},
		{"no signature file", func() {
			f.put("/index.json", goodDoc)
			f.mu.Lock()
			delete(f.files, "/index.json.sig")
			f.mu.Unlock()
		}, pub, SigMissing},
		{"no public key configured", func() { f.put("/index.json", goodDoc); f.put("/index.json.sig", goodSig) }, "", SigNoKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			for _, mode := range []string{VerifyEnforce, VerifyWarn} {
				m := storeManager(t, f, "index.json")
				audit := trapAudit(m)
				setVerify(t, m, mode, tc.key)
				sync1(t, m)
				st := m.sourceStatusOf(f.url("/index.json"))
				if st.Signature != tc.want || st.Note == "" {
					t.Fatalf("%s: status %+v, want %s with a note", mode, st, tc.want)
				}
				if got := audit.of(f.url("/index.json")); len(got) != 1 || got[0].Event != "plugins.index.signature" {
					t.Fatalf("%s: one audit entry about the index: %+v", mode, got)
				}
				sync1(t, m)
				if got := audit.of(f.url("/index.json")); len(got) != 1 {
					t.Fatalf("%s: the same finding must not be reported at every sync: %d entries", mode, len(got))
				}
				err := installByID(m, p1.id())
				if mode == VerifyEnforce {
					if err == nil || !strings.Contains(err.Error(), "enforce") {
						t.Fatalf("enforce must refuse to install from this index, got %v", err)
					}
					if _, statErr := os.Stat(filepath.Join(m.Options.PluginDir, "badsig")); !os.IsNotExist(statErr) {
						t.Fatal("the refused install left a plugin folder")
					}
					continue
				}
				if err != nil {
					t.Fatalf("warn must install anyway: %v", err)
				}
				p, _ := m.GetPluginByID(p1.id())
				if info := p.Status().Install; info.Signature != tc.want {
					t.Fatalf("the state of the index at install time must be on record: %+v", info)
				}
			}
		})
	}
}

// A validly signed but older index that is served again
func TestSignedIndexReplayPerMode(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	old, cur := goodV1(t, "replay"), goodV2(t, "replay")
	f.publishSigned("index.json", priv, 3, old)
	oldDoc, oldSig := f.get("/index.json"), f.get("/index.json.sig")
	f.publishSigned("index.json", priv, 7, cur)
	curDoc, curSig := f.get("/index.json"), f.get("/index.json.sig")

	for _, mode := range []string{VerifyEnforce, VerifyWarn} {
		t.Run(mode, func(t *testing.T) {
			f.put("/index.json", curDoc)
			f.put("/index.json.sig", curSig)
			m := storeManager(t, f, "index.json")
			setVerify(t, m, mode, pub)
			sync1(t, m)
			if st := m.sourceStatusOf(f.url("/index.json")); st.Signature != SigSigned || st.Serial != 7 {
				t.Fatalf("first sync: %+v", st)
			}
			//The store (or someone in the middle) serves the older index again
			f.put("/index.json", oldDoc)
			f.put("/index.json.sig", oldSig)
			sync1(t, m)
			st := m.sourceStatusOf(f.url("/index.json"))
			if st.Signature != SigReplayed || !strings.Contains(st.Note, "serial 3") || !strings.Contains(st.Note, "serial 7") {
				t.Fatalf("an older index must be recognised: %+v", st)
			}
			offered := m.installCandidate(old.id(), "")
			if mode == VerifyEnforce {
				if offered == nil || offered.Signature != SigSigned || versionToString(offered.PluginIntroSpect.VersionMajor, offered.PluginIntroSpect.VersionMinor, 0) != "1.1.0" {
					t.Fatalf("enforce must keep offering what the last valid index offered, got %+v", offered)
				}
			} else {
				if offered == nil || offered.Signature != SigReplayed {
					t.Fatalf("warn lists what is served, marked: %+v", offered)
				}
				if err := m.InstallPlugin(offered); err != nil {
					t.Fatalf("warn must install anyway: %v", err)
				}
			}

			//The memory of serial numbers is stored: after a restart the old index is still old
			m2 := storeManager(t, f, "index.json")
			m2.Options.Database = m.Options.Database
			sync1(t, m2)
			st = m2.sourceStatusOf(f.url("/index.json"))
			if st.Signature != SigReplayed {
				t.Fatalf("after a restart: %+v", st)
			}
			if mode == VerifyEnforce {
				if err := installByID(m2, old.id()); err == nil || !strings.Contains(err.Error(), "old one") {
					t.Fatalf("enforce must refuse to install from a replayed index, got %v", err)
				}
			}
		})
	}

	// The same serial with other content is not accepted either
	t.Run("same serial, other content", func(t *testing.T) {
		g := newStoreFix(t)
		priv, pub := g.keys("k")
		g.publishSigned("index.json", priv, 4, goodV1(t, "same"))
		m := storeManager(t, g, "index.json")
		setVerify(t, m, VerifyEnforce, pub)
		sync1(t, m)
		g.publishSigned("index.json", priv, 4, goodV2(t, "same")) //the tool refuses this for one output file; a careless signer can still do it
		sync1(t, m)
		if st := m.sourceStatusOf(g.url("/index.json")); st.Signature != SigReplayed {
			t.Fatalf("status %+v", st)
		}
		sync1(t, m)
	})
}

// The upstream index format has no checksums and no signature
func TestUnsignedIndexPerMode(t *testing.T) {
	f := newStoreFix(t)
	_, pub := f.keys("k")
	p1 := goodV1(t, "plain")
	// An unsigned index cannot make itself look signed
	f.publishLegacy("legacy.json", map[string]any{
		"Signature": SigSigned, "IndexSerial": 99,
		"Downloads": map[string]any{platformKey(): map[string]any{"url": f.url(p1.path()), "sha256": sumOf(p1.bin), "size": len(p1.bin)}},
	}, p1)

	m := storeManager(t, f, "legacy.json")
	audit := trapAudit(m)
	setVerify(t, m, VerifyWarn, pub)
	sync1(t, m)
	if st := m.sourceStatusOf(f.url("/legacy.json")); st.Signature != SigUnsigned || st.Format != "legacy" || st.Note != "" {
		t.Fatalf("status of an upstream index: %+v", st)
	}
	if f.hitCount("/legacy.json.sig") != 0 {
		t.Fatal("no signature file is asked for with an upstream index")
	}
	offered := m.installCandidate(p1.id(), "")
	if offered.Signature != SigUnsigned || offered.Downloads != nil || offered.IndexSerial != 0 {
		t.Fatalf("fields of an unsigned index entry must not be believed: %+v", offered)
	}
	if err := m.InstallPlugin(offered); err != nil {
		t.Fatalf("warn (default): an unsigned plugin installs as before: %v", err)
	}
	p, _ := m.GetPluginByID(p1.id())
	if info := p.Status().Install; info.Signature != SigUnsigned || info.Verified != VerifiedNotPinned || info.Note != "" || info.Source != f.url("/legacy.json") {
		t.Fatalf("record of an unsigned install: %+v", info)
	}
	if len(audit.entries) != 0 {
		t.Fatalf("an unsigned upstream index is not an event: %+v", audit.entries)
	}

	m2 := storeManager(t, f, "legacy.json")
	setVerify(t, m2, VerifyEnforce, pub)
	sync1(t, m2)
	if err := installByID(m2, p1.id()); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("enforce must refuse a plugin of an unsigned index, got %v", err)
	}
	if f.hitCount(p1.path()) != 1 {
		t.Fatalf("enforce must not even download it (downloads: %d)", f.hitCount(p1.path()))
	}
}

func TestVerificationOffChecksNothing(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "offmode")
	f.publishSigned("index.json", priv, 1, p1)
	f.put("/index.json.sig", []byte("broken"))
	f.put(p1.path(), append(append([]byte{}, p1.bin...), '\n'))
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyOff, pub)
	sync1(t, m)
	if f.hitCount("/index.json.sig") != 0 {
		t.Fatal("with verification off the signature file is not fetched")
	}
	if st := m.sourceStatusOf(f.url("/index.json")); st.Signature != SigUnchecked {
		t.Fatalf("status %+v", st)
	}
	if err := installByID(m, p1.id()); err != nil {
		t.Fatal(err)
	}
	p, _ := m.GetPluginByID(p1.id())
	if info := p.Status().Install; info.Verified != VerifiedUnchecked || info.Note != "" {
		t.Fatalf("record: %+v", info)
	}
}

// F15: a plugin is only updated from the index it was installed from
func TestUpdatesOnlyFromTheSourceOfInstall(t *testing.T) {
	f := newStoreFix(t)
	home := goodV1(t, "bound")
	f.publishLegacy("home.json", nil, home)
	hijack := idxPlugin{name: "bound", version: [3]int{9, 0, 0}, bin: chaosVariant(t, "version=9.0.0\nname=hijacked")}
	f.put("/other.json", []byte("[]"))

	m := storeManager(t, f, "home.json", "other.json")
	sync1(t, m)
	if err := installByID(m, home.id()); err != nil {
		t.Fatal(err)
	}
	p, _ := m.GetPluginByID(home.id())

	//Another index starts to offer the same ID with a higher version
	hijackPath := "/bin/hijack"
	f.put(hijackPath, hijack.bin)
	raw, _ := json.Marshal([]any{map[string]any{"PluginIntroSpect": hijack.spec(), "DownloadURLs": map[string]string{platformKey(): f.url(hijackPath)}}})
	f.put("/other.json", raw)
	sync1(t, m)

	infos := m.GetPluginUpdateInfos()
	if len(infos) != 1 || infos[0].UpdateAvailable || infos[0].Source != f.url("/home.json") || !infos[0].BoundToSource || infos[0].LatestVersion != "1.0.0" {
		t.Fatalf("the other index must not show up as an update: %+v", infos[0])
	}
	if err := m.UpdatePlugin(home.id()); err == nil || !strings.Contains(err.Error(), "up to date") {
		t.Fatalf("no update from the other index, got %v", err)
	}
	if f.hitCount(hijackPath) != 0 {
		t.Fatal("the binary of the other index was downloaded")
	}

	//The home index drops the plugin: still no update from elsewhere, and the error says why
	f.put("/home.json", []byte("[]"))
	sync1(t, m)
	if err := m.UpdatePlugin(home.id()); err == nil || !strings.Contains(err.Error(), "only updated from the index it was installed from") {
		t.Fatalf("got %v", err)
	}
	if len(m.GetPluginUpdateInfos()) != 0 {
		t.Fatal("no update information from an index the plugin was not installed from")
	}

	//The home index publishes version 1.1.0: that is an update
	f.publishLegacy("home.json", nil, goodV2(t, "bound"))
	sync1(t, m)
	if err := m.UpdatePlugin(home.id()); err != nil {
		t.Fatalf("update from the index of install: %v", err)
	}
	if got := versionOfSpec(p.spec()); got != "1.1.0" {
		t.Fatalf("version after the update: %s", got)
	}

	//The administrator may lift the binding; then the highest version of any index wins, as before installs were recorded
	if body := postForm(m.HandleReleaseInstallSource, url.Values{"pluginID": {home.id()}}); !strings.Contains(body, "OK") {
		t.Fatalf("release: %s", body)
	}
	if infos := m.GetPluginUpdateInfos(); len(infos) != 1 || !infos[0].UpdateAvailable || infos[0].LatestVersion != "9.0.0" || infos[0].BoundToSource {
		t.Fatalf("after the release: %+v", infos)
	}
}

// A plugin that was installed before installs were recorded (or copied in by
// hand) has no source: it is updated as before, and from then on from that index.
func TestPluginWithoutRecordUpdatesAsBeforeAndIsThenBound(t *testing.T) {
	f := newStoreFix(t)
	m := storeManager(t, f, "a.json", "b.json")
	p := loadChaos(t, m, "veteran", "mode=ok\n") //version 0.1.0, no install record
	if info := p.Status().Install; info.Known || info.Source != "" || info.CanRollback {
		t.Fatalf("a plugin without a record: %+v", info)
	}
	f.publishLegacy("a.json", nil, idxPlugin{name: "veteran", version: v1, bin: chaosVariant(t, "version=1.0.0")})
	f.publishLegacy("b.json", nil, idxPlugin{name: "veteran", version: v2, bin: chaosVariant(t, "version=1.1.0")})
	sync1(t, m)
	if err := m.UpdatePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	info := p.Status().Install
	if versionOfSpec(p.spec()) != "1.1.0" || info.Source != f.url("/b.json") || !info.CanRollback || info.PreviousVersion != "0.1.0" {
		t.Fatalf("the highest version of any index, then bound to it: %+v (version %s)", info, versionOfSpec(p.spec()))
	}
}

// The binary in the plugin folder is replaced by hand after the install
func TestBinaryChangedOnDiskPerMode(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "swapped")
	f.publishSigned("index.json", priv, 1, p1)
	m := storeManager(t, f, "index.json")
	audit := trapAudit(m)
	setVerify(t, m, VerifyWarn, pub)
	sync1(t, m)
	if err := installByID(m, p1.id()); err != nil {
		t.Fatal(err)
	}
	p, _ := m.GetPluginByID(p1.id())
	bin := filepath.Join(p.RootDir, "swapped")
	if err := os.WriteFile(bin, chaosVariant(t, "version=1.0.0\nname=replaced by hand"), 0o755); err != nil {
		t.Fatal(err)
	}

	//warn: started, shown, one audit entry
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	if info := p.Status().Install; info.BinaryState != "changed" || !strings.Contains(info.Note, "not the one that was installed") {
		t.Fatalf("warn must show the changed binary: %+v", info)
	}
	if got := audit.of(p1.id()); len(got) != 1 || got[0].Event != "plugins.binary.changed" {
		t.Fatalf("audit: %+v", got)
	}
	if err := m.StopPlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	mustStart(t, m, p)
	if got := audit.of(p1.id()); len(got) != 1 {
		t.Fatalf("the same finding must not be reported at every start: %d entries", len(got))
	}
	m.StopPlugin(p1.id())

	//enforce: not started
	setVerify(t, m, VerifyEnforce, pub)
	err := m.StartPlugin(p1.id())
	if err == nil || !strings.Contains(err.Error(), "not the one that was installed") {
		t.Fatalf("enforce must not start a changed binary, got %v", err)
	}
	if st := p.Status(); st.State != StateFailedToStart {
		t.Fatalf("state %s", st.State)
	}
	//off: not looked at
	setVerify(t, m, VerifyOff, pub)
	mustStart(t, m, p)
	if info := p.Status().Install; info.BinaryState != "" {
		t.Fatalf("off must not look at the binary: %+v", info)
	}
}

/* 2.5 Safe install, update and rollback */

// installAndRun installs version 1 of a plugin from a signed index and starts it
func installAndRun(t *testing.T, f *storeFix, m *Manager, priv string, name string) (*Plugin, idxPlugin) {
	t.Helper()
	p1 := goodV1(t, name)
	f.publishSigned("index.json", priv, 1, p1)
	sync1(t, m)
	if err := installByID(m, p1.id()); err != nil {
		t.Fatal(err)
	}
	p, err := m.GetPluginByID(p1.id())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.EnablePlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, p, HealthOK)
	return p, p1
}

func TestSafeUpdateKeepsThePreviousVersion(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	p, p1 := installAndRun(t, f, m, priv, "updater")
	os.WriteFile(filepath.Join(p.RootDir, "data.txt"), []byte("kept"), 0o644) //what the plugin stored

	p2 := goodV2(t, "updater")
	f.publishSigned("index.json", priv, 2, p2)
	sync1(t, m)
	if infos := m.GetPluginUpdateInfos(); len(infos) != 1 || !infos[0].UpdateAvailable || infos[0].Signature != SigSigned || infos[0].Blocked != "" {
		t.Fatalf("update information: %+v", infos)
	}
	if err := m.UpdatePlugin(p1.id()); err != nil {
		t.Fatalf("UpdatePlugin: %v", err)
	}
	if !p.IsRunning() || versionOfSpec(p.spec()) != "1.1.0" {
		t.Fatalf("version 1.1.0 must be running, got %s running=%v", versionOfSpec(p.spec()), p.IsRunning())
	}
	kept, err := os.ReadFile(filepath.Join(p.RootDir, previousDirName, "updater"))
	if err != nil || sumOf(kept) != sumOf(p1.bin) {
		t.Fatalf("previous/ must hold the binary of version 1.0.0 (%v)", err)
	}
	cur, _ := os.ReadFile(filepath.Join(p.RootDir, "updater"))
	if sumOf(cur) != sumOf(p2.bin) {
		t.Fatal("the plugin folder must hold the binary of version 1.1.0")
	}
	info := p.Status().Install
	if info.Version != "1.1.0" || info.PreviousVersion != "1.0.0" || !info.CanRollback || info.LastChange != "update" || info.LastChangeIssue || info.SHA256 != sumOf(p2.bin) {
		t.Fatalf("record after the update: %+v", info)
	}
	noStagingLeft(t, m)

	//Manual rollback through the API handler
	if body := postForm(m.HandleRollbackPlugin, url.Values{"pluginID": {p1.id()}}); !strings.Contains(body, "OK") {
		t.Fatalf("rollback: %s", body)
	}
	if !p.IsRunning() || versionOfSpec(p.spec()) != "1.0.0" {
		t.Fatalf("version 1.0.0 must be running after the rollback, got %s running=%v", versionOfSpec(p.spec()), p.IsRunning())
	}
	waitHealth(t, p, HealthOK)
	info = p.Status().Install
	if info.Version != "1.0.0" || info.CanRollback || info.LastChange != "rollback" || info.SHA256 != sumOf(p1.bin) || info.BinaryState != "ok" {
		t.Fatalf("record after the rollback: %+v", info)
	}
	if _, err := os.Stat(filepath.Join(p.RootDir, previousDirName)); !os.IsNotExist(err) {
		t.Fatal("a rollback uses the previous version up")
	}
	if data, _ := os.ReadFile(filepath.Join(p.RootDir, "data.txt")); string(data) != "kept" {
		t.Fatal("the files of the plugin must not be touched by update and rollback")
	}
	if body := postForm(m.HandleRollbackPlugin, url.Values{"pluginID": {p1.id()}}); !strings.Contains(body, "no previous version") {
		t.Fatalf("a second rollback has nothing to go back to: %s", body)
	}
	noStagingLeft(t, m)

	// The staging folder is not a plugin: a restart of Zoraxy does not try to load it
	os.MkdirAll(filepath.Join(m.Options.PluginDir, stagingDirName, "leftover"), 0o755)
	m.StopPlugin(p1.id())
	m2 := newFaultManager(t)
	m2.Options.PluginDir, m2.Options.Database = m.Options.PluginDir, m.Options.Database
	m2.Options.Database.Write("plugins", p1.id(), false)
	if err := m2.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if fails := m2.ListLoadFailures(); len(fails) != 0 {
		t.Fatalf("the staging folder was taken for a plugin: %+v", fails)
	}
	if _, err := m2.GetPluginByID(p1.id()); err != nil {
		t.Fatal("the plugin itself must still load")
	}
}

// A download that fails in any way leaves the installed version running
func TestFailedDownloadKeepsTheOldVersionRunning(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	p, p1 := installAndRun(t, f, m, priv, "steady")
	pid := p.Status().PID
	p2 := goodV2(t, "steady")
	f.publishSigned("index.json", priv, 2, p2)
	sync1(t, m)

	stillRunning := func(what string) {
		t.Helper()
		st := p.Status()
		if st.State != StateRunning || st.PID != pid || versionOfSpec(p.spec()) != "1.0.0" {
			t.Fatalf("%s: the installed version must keep running untouched (state %s, pid %d was %d, version %s)", what, st.State, st.PID, pid, versionOfSpec(p.spec()))
		}
		if info := st.Install; info.Version != "1.0.0" || info.CanRollback {
			t.Fatalf("%s: record %+v", what, info)
		}
		cur, _ := os.ReadFile(filepath.Join(p.RootDir, "steady"))
		if sumOf(cur) != sumOf(p1.bin) {
			t.Fatalf("%s: the installed binary was changed", what)
		}
		noStagingLeft(t, m)
	}
	fails := func(what string, wantInError string) {
		t.Helper()
		err := m.UpdatePlugin(p1.id())
		if err == nil || !strings.Contains(err.Error(), wantInError) || !strings.Contains(err.Error(), "installed version was not touched") {
			t.Fatalf("%s: got %v, want an error with %q", what, err, wantInError)
		}
		stillRunning(what)
	}

	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) { http.Error(w, "gone", http.StatusInternalServerError) })
	fails("server error", "500")

	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) {
		w.Write(p2.bin[:len(p2.bin)/2]) //the transfer breaks off half way
		panic(http.ErrAbortHandler)
	})
	fails("transfer cut off", "failed to download")

	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) { w.Write(chaosVariant(t, "version=1.1.0\nname=tampered")) })
	fails("tampered download", "than the limit")

	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) {
		b := append([]byte{}, p2.bin...)
		b[len(b)-2] ^= 1
		w.Write(b)
	})
	fails("wrong checksum", "does not match its index")

	//Timeout: the store stops answering in the middle
	m.storeCfg.DownloadTimeout = 400 * time.Millisecond
	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) {
		w.Write(p2.bin[:1024])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	began := time.Now()
	fails("stalled download", "failed to download")
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("the download timeout did not end the stalled download (%s)", d)
	}
	m.storeCfg.DownloadTimeout = 0

	//Size cap (warn mode, so the size of the index is not the limit)
	setVerify(t, m, VerifyWarn, pub)
	m.storeCfg.MaxBytes = 64 << 10
	f.handle(p2.path(), nil)
	fails("larger than the size cap, length announced", "more than the limit")
	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 20; i++ { //no Content-Length
			w.Write(make([]byte, 8<<10))
			w.(http.Flusher).Flush()
		}
	})
	fails("larger than the size cap, length not announced", "larger than the limit")
	m.storeCfg.MaxBytes = 0
	setVerify(t, m, VerifyEnforce, pub)

	//A download that is not a plugin at all (signed index, so the checksum matches: the introspect in staging refuses it)
	junk := idxPlugin{name: "steady", version: v2, bin: []byte("#!/bin/sh\necho not a manifest\n")}
	f.handle(p2.path(), nil)
	f.publishSigned("index.json", priv, 3, junk)
	sync1(t, m)
	fails("download is not a plugin", "could not be introspected")
}

// The staged binary is run for the first time as the plugin user
func TestStagedBinaryIsIntrospectedAsThePluginUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a Zoraxy that is not root: the refusal to switch users is what shows that the plugin user is applied")
	}
	f := newStoreFix(t)
	p1 := goodV1(t, "asuser")
	f.publishLegacy("index.json", nil, p1)
	m := storeManager(t, f, "index.json")
	m.Options.RunAsUser = "nobody"
	sync1(t, m)
	err := installByID(m, p1.id())
	if err == nil || !strings.Contains(err.Error(), "not running as root") {
		t.Fatalf("the introspect in staging must go through the plugin user setting, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.Options.PluginDir, "asuser")); !os.IsNotExist(statErr) {
		t.Fatal("nothing must be installed")
	}
	noStagingLeft(t, m)
}

// Chaos: the new version crashes at start
func TestFaultNewVersionCrashesAtStart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trailer string
	}{
		{"crashes at start", "version=1.1.0\nmode=crash"},
		{"exits cleanly at start", "version=1.1.0\nmode=exit0"},
		{"never opens its port", "version=1.1.0\nmode=hang_start"},
	} {
		t.Run(tc.name+", default: reported, manual rollback", func(t *testing.T) {
			f := newStoreFix(t)
			priv, pub := f.keys("k")
			m := storeManager(t, f, "index.json")
			m.storeCfg.HealthTimeout = 1500 * time.Millisecond
			audit := trapAudit(m)
			setVerify(t, m, VerifyEnforce, pub)
			p, p1 := installAndRun(t, f, m, priv, "crashy")
			f.publishSigned("index.json", priv, 2, idxPlugin{name: "crashy", version: v2, bin: chaosVariant(t, tc.trailer)})
			sync1(t, m)

			err := m.UpdatePlugin(p1.id())
			if err == nil || !strings.Contains(err.Error(), "did not start properly") || !strings.Contains(err.Error(), "Roll back") {
				t.Fatalf("the failed health check must be reported with the way out, got %v", err)
			}
			if got := versionOfSpec(p.spec()); got != "1.1.0" {
				t.Fatalf("without the opt-in the new version stays in place, got %s", got)
			}
			info := p.Status().Install
			if !info.CanRollback || !info.LastChangeIssue || !strings.Contains(info.Note, "did not start properly") || info.PreviousVersion != "1.0.0" {
				t.Fatalf("status after the failed update: %+v", info)
			}
			if got := audit.of(p1.id()); len(got) == 0 || got[len(got)-1].Event != "plugins.update.unhealthy" {
				t.Fatalf("audit: %+v", got)
			}

			//One click
			if body := postForm(m.HandleRollbackPlugin, url.Values{"pluginID": {p1.id()}}); !strings.Contains(body, "OK") {
				t.Fatalf("rollback: %s", body)
			}
			waitState(t, p, StateRunning)
			waitHealth(t, p, HealthOK)
			if got := versionOfSpec(p.spec()); got != "1.0.0" {
				t.Fatalf("the old version must run again, got %s", got)
			}
			if info := p.Status().Install; info.LastChangeIssue || info.Note != "" || info.CanRollback {
				t.Fatalf("status after the rollback: %+v", info)
			}
		})

		t.Run(tc.name+", opt-in: automatic rollback", func(t *testing.T) {
			f := newStoreFix(t)
			priv, pub := f.keys("k")
			m := storeManager(t, f, "index.json")
			m.storeCfg.HealthTimeout = 1500 * time.Millisecond
			setVerify(t, m, VerifyEnforce, pub)
			if err := m.SetSettings(func(s *ManagerSettings) { s.AutoRollback = true }); err != nil {
				t.Fatal(err)
			}
			p, p1 := installAndRun(t, f, m, priv, "crashy")
			f.publishSigned("index.json", priv, 2, idxPlugin{name: "crashy", version: v2, bin: chaosVariant(t, tc.trailer)})
			sync1(t, m)

			err := m.UpdatePlugin(p1.id())
			if err == nil || !strings.Contains(err.Error(), "Version 1.0.0 was put back and started") {
				t.Fatalf("the automatic rollback must be reported, got %v", err)
			}
			waitState(t, p, StateRunning)
			waitHealth(t, p, HealthOK)
			if got := versionOfSpec(p.spec()); got != "1.0.0" {
				t.Fatalf("the old version must be restored, got %s", got)
			}
			cur, _ := os.ReadFile(filepath.Join(p.RootDir, "crashy"))
			if sumOf(cur) != sumOf(p1.bin) {
				t.Fatal("the binary of version 1.0.0 must be back in place")
			}
			info := p.Status().Install
			if info.Version != "1.0.0" || info.CanRollback || info.LastChange != "auto_rollback" || !info.LastChangeIssue || !strings.Contains(info.Note, "did not start properly") {
				t.Fatalf("status after the automatic rollback: %+v", info)
			}
			noStagingLeft(t, m)
			//The store still offers 1.1.0: nothing retries it by itself
			time.Sleep(300 * time.Millisecond)
			if got := versionOfSpec(p.spec()); got != "1.0.0" || !p.IsRunning() {
				t.Fatalf("the restored version must stay: %s running=%v", got, p.IsRunning())
			}
		})
	}
}

// With a restart policy the supervisor would restart the crashing new version;
// the update still ends with the old version when automatic rollback is on.
func TestFaultNewVersionCrashesUnderARestartPolicy(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	m := storeManager(t, f, "index.json")
	m.supCfg = supTunables{BackoffBase: 50 * time.Millisecond, BackoffMax: 200 * time.Millisecond}
	setVerify(t, m, VerifyEnforce, pub)
	m.SetSettings(func(s *ManagerSettings) { s.AutoRollback = true })
	p, p1 := installAndRun(t, f, m, priv, "looper")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	f.publishSigned("index.json", priv, 2, idxPlugin{name: "looper", version: v2, bin: chaosVariant(t, "version=1.1.0\nmode=crash")})
	sync1(t, m)
	if err := m.UpdatePlugin(p1.id()); err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("got %v", err)
	}
	waitState(t, p, StateRunning)
	waitHealth(t, p, HealthOK)
	time.Sleep(500 * time.Millisecond) //a restart of the crashed version that was still waiting would show up now
	if got := versionOfSpec(p.spec()); got != "1.0.0" || p.Status().State != StateRunning {
		t.Fatalf("version %s state %s", got, p.Status().State)
	}
}

// A plugin the administrator stopped is updated but not started, and a rollback does not start it either
func TestUpdateAndRollbackOfAStoppedPlugin(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	p, p1 := installAndRun(t, f, m, priv, "resting")
	if err := m.DisablePlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	f.publishSigned("index.json", priv, 2, idxPlugin{name: "resting", version: v2, bin: chaosVariant(t, "version=1.1.0\nmode=crash")})
	sync1(t, m)
	if err := m.UpdatePlugin(p1.id()); err != nil {
		t.Fatalf("an update of a stopped plugin has no health check to fail: %v", err)
	}
	if p.IsRunning() || versionOfSpec(p.spec()) != "1.1.0" {
		t.Fatalf("updated, not started: version %s running=%v", versionOfSpec(p.spec()), p.IsRunning())
	}
	if err := m.RollbackPlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	if p.IsRunning() || versionOfSpec(p.spec()) != "1.0.0" {
		t.Fatalf("rolled back, not started: version %s running=%v", versionOfSpec(p.spec()), p.IsRunning())
	}
}

/* 2.7 Isolated plugin UI */

// adminAPI stands for an admin API of Zoraxy: it needs the session cookie and the CSRF token of the administrator
func adminAPI(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("zoraxy-session")
		if err != nil || c.Value != "admin" || r.Header.Get("X-CSRF-Token") != "test-csrf" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Write([]byte("done"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// adminOrigin serves the two admin routes that matter here, as router.go and api.go do
func adminOrigin(t *testing.T, m *Manager) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/plugin.ui/"):
			m.HandlePluginUI(strings.Split(r.URL.Path, "/")[2], w, r)
		case r.URL.Path == "/api/plugins/ui/ticket":
			m.HandlePluginUITicket(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// asAdmin makes a request the way the browser of a logged-in administrator would: with the session cookie
func asAdmin(t *testing.T, method string, target string, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.AddCookie(&http.Cookie{Name: "zoraxy-session", Value: "admin"})
	req.Header.Set("Authorization", "Bearer admin-token")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func ticketURL(t *testing.T, admin *httptest.Server, pluginID string) (string, bool) {
	t.Helper()
	_, body := asAdmin(t, http.MethodPost, admin.URL+"/api/plugins/ui/ticket", url.Values{"plugin_id": {pluginID}})
	var ans struct {
		Isolated bool   `json:"isolated"`
		URL      string `json:"url"`
		Sandbox  string `json:"sandbox"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &ans); err != nil || ans.URL == "" {
		t.Fatalf("ticket answer: %s", body)
	}
	if ans.Isolated == strings.Contains(ans.Sandbox, "allow-same-origin") {
		t.Fatalf("an isolated page must not get allow-same-origin, a page under the admin origin keeps it: %+v", ans)
	}
	return ans.URL, ans.Isolated
}

// An admin API call from the plugin UI works when the UI is not isolated (the
// default, as before) and fails when it is.
func TestIsolatedPluginUICannotUseTheAdminSession(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	t.Cleanup(func() { m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI = false }) })
	p := loadChaosStopped(t, m, "uiprobe", "mode=ok\nfeatures=adminprobe\n")
	other := loadChaosStopped(t, m, "bystander", "mode=ok\n")
	mustStart(t, m, p)
	mustStart(t, m, other)
	waitHealth(t, p, HealthOK)
	waitHealth(t, other, HealthOK)
	api := adminAPI(t)
	admin := adminOrigin(t, m)
	probe := "adminprobe?url=" + url.QueryEscape(api.URL+"/api/plugins/policy")
	seen := func(body string) map[string]string {
		out := map[string]string{}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("headers answer: %s", body)
		}
		return out
	}

	//Not isolated (default): the plugin is handed the session of the administrator and can use it
	page, isolated := ticketURL(t, admin, p.Spec.ID)
	if isolated || page != "/plugin.ui/"+p.Spec.ID+"/" {
		t.Fatalf("default: the page is under the admin origin, got %s", page)
	}
	resp, body := asAdmin(t, http.MethodGet, admin.URL+page+"headers", nil)
	if got := seen(body); !strings.Contains(got["cookie"], "zoraxy-session=admin") || got["csrf"] != "test-csrf" || got["isolated"] != "" {
		t.Fatalf("default: the plugin sees the admin cookie and CSRF token, as before; got %+v", got)
	}
	if len(resp.Header.Values("Set-Cookie")) == 0 || resp.Header.Get("Content-Security-Policy") != "" {
		t.Fatalf("default: answers of the plugin are passed on unchanged: %+v", resp.Header)
	}
	if _, body := asAdmin(t, http.MethodGet, admin.URL+page+probe, nil); body != "200" {
		t.Fatalf("default: the admin API call of the plugin UI works, got %q", body)
	}

	//Isolated
	if err := m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI, s.PluginUIListen = true, "127.0.0.1:0" }); err != nil {
		t.Fatal(err)
	}
	if got := audit.of("plugin pages"); len(got) != 1 || got[0].Detail["isolated"] != "true" {
		t.Fatalf("turning the isolation on is audited: %+v", got)
	}
	if resp, _ := asAdmin(t, http.MethodGet, admin.URL+"/plugin.ui/"+p.Spec.ID+"/headers", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("isolated: the page must not be served under the admin origin any more, status %d", resp.StatusCode)
	}
	page, isolated = ticketURL(t, admin, p.Spec.ID)
	if !isolated || !strings.HasPrefix(page, "http://127.0.0.1:") || strings.HasPrefix(page, admin.URL) {
		t.Fatalf("isolated: the page must be on another origin, got %s (admin %s)", page, admin.URL)
	}
	resp, body = asAdmin(t, http.MethodGet, page+"headers", nil)
	if got := seen(body); got["cookie"] != "" || got["csrf"] != "" || got["auth"] != "" || got["isolated"] != "true" {
		t.Fatalf("isolated: the plugin must see nothing of the admin session, got %+v", got)
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("isolated: a cookie of the plugin must not reach the browser (cookies are per host, not per port): %v", resp.Header.Values("Set-Cookie"))
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "sandbox ") || strings.Contains(csp, "allow-same-origin") {
		t.Fatalf("isolated: every answer is sandboxed without allow-same-origin, got %q", csp)
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("isolated: the ticket in the address must not leak in a Referer header")
	}
	if _, body := asAdmin(t, http.MethodGet, page+probe, nil); body != "403" {
		t.Fatalf("isolated: the admin API call of the plugin UI must fail, got %q", body)
	}
	if resp, body := asAdmin(t, http.MethodGet, page, nil); resp.StatusCode != 200 || !strings.Contains(body, "Chaos plugin") {
		t.Fatalf("isolated: the page itself still works, status %d", resp.StatusCode)
	}

	//The ticket is the only way in, and it is for one plugin
	base, _ := url.Parse(page)
	origin := base.Scheme + "://" + base.Host
	for _, bad := range []string{"/t/" + strings.Repeat("0", 48) + "/", "/t//", "/", "/plugin.ui/" + p.Spec.ID + "/", "/api/plugins/list"} {
		if resp, _ := asAdmin(t, http.MethodGet, origin+bad, nil); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s on the isolated listener: status %d", bad, resp.StatusCode)
		}
	}
	otherPage, _ := ticketURL(t, admin, other.Spec.ID)
	if _, body := asAdmin(t, http.MethodGet, otherPage, nil); !strings.Contains(body, "Chaos plugin") {
		t.Fatalf("the ticket of another plugin opens that plugin: %s", body)
	}
	if otherPage == page {
		t.Fatal("every ticket is its own")
	}

	//A script of the sandboxed page calls its own backend: to the browser that is a cross-origin request from "null"
	req, _ := http.NewRequest(http.MethodOptions, page+"headers", nil)
	req.Header.Set("Origin", "null")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	pre, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pre.Body.Close()
	if pre.StatusCode != http.StatusNoContent || pre.Header.Get("Access-Control-Allow-Origin") != "null" || pre.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("preflight of the page to its own backend: %d %+v", pre.StatusCode, pre.Header)
	}

	//The settings API says what is going on
	var view struct {
		IsolatePluginUI bool
		UIIsolation     UIIsolationState
	}
	getJSON(t, m.HandlePluginSettings, "", &view)
	if !view.IsolatePluginUI || !view.UIIsolation.Listening || view.UIIsolation.ListenAddr == "" || view.UIIsolation.Error != "" {
		t.Fatalf("settings view: %+v", view)
	}

	//Off again: the listener is gone, old tickets are dead, the admin origin serves the page as before
	if err := m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI = false }); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", base.Host, time.Second); err == nil {
		conn.Close()
		t.Fatal("the isolated listener must be closed when the isolation is turned off")
	}
	if _, body := asAdmin(t, http.MethodGet, admin.URL+"/plugin.ui/"+p.Spec.ID+"/"+probe, nil); body != "200" {
		t.Fatalf("off again: as before, got %q", body)
	}
}

func TestIsolatedPluginUIListenerAndStaticFiles(t *testing.T) {
	m := newFaultManager(t)
	t.Cleanup(func() { m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI = false }) })

	//A port that is taken: the setting is refused and stays off
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	err = m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI, s.PluginUIListen = true, taken.Addr().String() })
	if err == nil || m.Settings().IsolatePluginUI {
		t.Fatalf("isolation that cannot be served must be refused, not half on: %v", err)
	}
	if err := m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI = true }); err == nil {
		t.Fatal("without a listen address (and no default of the instance) the setting must be refused")
	}
	for _, bad := range []string{"plugins.example.com", "https://plugins.example.com/path", "javascript:alert(1)", "https://user@host"} {
		if err := m.SetSettings(func(s *ManagerSettings) { s.PluginUIOrigin = bad }); err == nil {
			t.Fatalf("origin %q must be refused", bad)
		}
	}

	//The default of the instance, and the public files plugin pages load by absolute path
	var seenMu sync.Mutex
	var asked []string
	m.Options.UIStaticAssets = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMu.Lock()
		asked = append(asked, r.URL.Path)
		seenMu.Unlock()
		if r.Header.Get("Cookie") != "" {
			t.Error("the cookie must not reach the file handler either")
		}
		w.Write([]byte("asset"))
	})
	wrapped := 0
	m.Options.UIHandlerWrap = func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenMu.Lock()
			wrapped++
			seenMu.Unlock()
			h.ServeHTTP(w, r)
		})
	}
	m.Options.IsolatedUIDefaultListen = "127.0.0.1:0"
	if err := m.SetSettings(func(s *ManagerSettings) { s.IsolatePluginUI, s.PluginUIOrigin = true, "https://plugins.example.com/" }); err != nil {
		t.Fatal(err)
	}
	origin := "http://" + m.uiIsolationState().ListenAddr
	for path, want := range map[string]int{
		"/script/jquery-3.6.0.min.js": 200, "/main.css": 200, "/darktheme.css": 200, "/img/public/x.png": 200,
		"/index.html": 404, "/components/plugins.html": 404, "/api/auth/login": 404, "/script/../index.html": 404, "/img/secret.png": 404,
	} {
		resp, _ := asAdmin(t, http.MethodGet, origin+path, nil)
		if resp.StatusCode != want {
			t.Fatalf("%s on the isolated listener: status %d, want %d", path, resp.StatusCode, want)
		}
	}
	seenMu.Lock()
	askedNow, wrappedNow := append([]string{}, asked...), wrapped
	seenMu.Unlock()
	for _, p := range askedNow {
		if !isolatedStaticPath(p) {
			t.Fatalf("the file handler was asked for %s", p)
		}
	}
	if len(askedNow) != 4 {
		t.Fatalf("the four public files must be served by the file handler, got %v", askedNow)
	}
	if wrappedNow == 0 {
		t.Fatal("the allow-list of the admin listener must be in front of the isolated listener")
	}

	//The configured public address is what the admin UI is told
	p := loadChaosStopped(t, m, "addr", "mode=ok\n")
	admin := adminOrigin(t, m)
	page, isolated := ticketURL(t, admin, p.Spec.ID)
	if !isolated || !strings.HasPrefix(page, "https://plugins.example.com/t/") {
		t.Fatalf("ticket address with a configured origin: %s", page)
	}
	// A plugin that is not running: its ticket answers with the page that says so, sandboxed like every answer
	local := origin + strings.TrimPrefix(page, "https://plugins.example.com")
	resp, body := asAdmin(t, http.MethodGet, local, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "not running") || !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "sandbox ") {
		t.Fatalf("stopped plugin on the isolated listener: %d %s", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}

	//The setting survives a restart: StartIsolatedUI opens the listener again
	m2 := newFaultManager(t)
	m2.Options.Database = m.Options.Database
	m2.Options.IsolatedUIDefaultListen = "127.0.0.1:0"
	m2.StartIsolatedUI()
	t.Cleanup(func() { m2.applyUIIsolation(ManagerSettings{}) })
	if st := m2.uiIsolationState(); !st.Enabled || !st.Listening {
		t.Fatalf("after a restart: %+v", st)
	}
}
