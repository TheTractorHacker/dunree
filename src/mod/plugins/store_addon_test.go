package plugins

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/offline"
	"github.com/TheTractorHacker/dunree/mod/offline/offlinetest"
	"github.com/TheTractorHacker/dunree/mod/plugins/addonindex"
)

/*
	The add-on store (docs/plugins/addon-store.md): no store and no connection by
	default, the migration of an existing installation, the Dunree add-on index
	under the three verification modes, the choice of the artifact by platform,
	the minimum host version, a local folder as a source, and the whole way from
	tools/addon-store to an installed, updated and rolled back add-on.

	Everything is local: an httptest server or a folder, the chaos plugin, keys the
	signing tool creates for the test.
*/

/* No network by default */

func TestNoStoreAndNoConnectionByDefault(t *testing.T) {
	dials := offlinetest.Install(t)
	m := newFaultManager(t) //a new installation: ExistingInstall is false
	if state := m.migrateStoreSources(); state != "fresh" {
		t.Fatalf("a new installation must be recorded as fresh, got %q", state)
	}
	if urls := m.GetAllStoreURLs(); len(urls) != 0 || m.StoreConfigured() {
		t.Fatalf("a new installation must have no store source, got %v", urls)
	}
	if err := m.UpdateDownloadablePluginList(); err != nil {
		t.Fatalf("a sync without sources is not an error: %v", err)
	}
	if got := m.ListDownloadablePlugins(); len(got) != 0 {
		t.Fatalf("nothing can be offered without a source, got %d", len(got))
	}
	m.GetPluginUpdateInfos()
	setup := m.StoreSetupInfo()
	if setup.Configured || setup.Sources != 0 || setup.Platform != runtime.GOOS+"_"+runtime.GOARCH {
		t.Fatalf("setup of a new installation: %+v", setup)
	}
	// The one-click choice of a build that only carries the placeholder address:
	// refused in words, without a connection
	if !DunreeStoreReady() {
		if setup.DunreeStore.Ready {
			t.Fatal("the placeholder address must not be reported as ready")
		}
		body := postForm(m.HandleAddStoreSource, url.Values{"kind": {SourceKindDunree}})
		if !strings.Contains(body, "not open yet") {
			t.Fatalf("choosing the Dunree add-on store of a placeholder build: %s", body)
		}
		if m.StoreConfigured() {
			t.Fatal("the placeholder address must never become a source")
		}
	}
	if n := dials.Count(); n != 0 {
		t.Fatalf("a Dunree without a store source opened %d connections", n)
	}

	// Control: with a source the same calls do dial, so the count above means something
	m.Options.PluginStoreURLs = []string{"http://plugins.invalid/index.json"}
	m.UpdateDownloadablePluginList()
	if dials.Count() == 0 {
		t.Fatal("control run should dial")
	}
}

func TestStoreAddressPlaceholderIsNeverReady(t *testing.T) {
	for _, placeholder := range []string{"", "https://addons.dunree.example/index.json", "https://example.com/index.json", "https://store.invalid/i.json", "https://x.test/i.json", "http://addons.dunree.ie/index.json", "addons.dunree.ie/index.json", "https://localhost/index.json"} {
		if storeURLReady(placeholder) {
			t.Errorf("%q must not count as a real store address", placeholder)
		}
	}
	if !storeURLReady("https://addons.dunree.ie/index.json") {
		t.Error("a real https address must count")
	}
}

/* Existing installations keep the source they had */

func TestExistingInstallKeepsItsStoreSourceOnce(t *testing.T) {
	dials := offlinetest.Install(t)
	if LegacyZoraxyStoreIndexURL == "" { // legacy-compat
		t.Skip("the migration is switched off in this build")
	}
	m := newFaultManager(t)
	m.Options.ExistingInstall = true
	if err := m.saveCustomStoreURLs([]string{"https://community.invalid/index.json"}); err != nil {
		t.Fatal(err)
	}
	if state := m.migrateStoreSources(); state != "existing-migrated" {
		t.Fatalf("want existing-migrated, got %q", state)
	}
	src := m.ListStoreSources()
	if len(src) != 2 || src[0].URL != LegacyZoraxyStoreIndexURL || src[0].Kind != SourceKindZoraxy || src[0].Official || // legacy-compat
		!strings.Contains(src[0].Label, "third party") || src[1].URL != "https://community.invalid/index.json" || src[1].Kind != SourceKindCustom {
		t.Fatalf("sources after the migration: %+v %+v", src[0], src[1])
	}
	// It is a source like any other: it can be removed, and it does not come back
	if err := m.RemoveStoreSource(LegacyZoraxyStoreIndexURL); err != nil { // legacy-compat
		t.Fatalf("the migrated source must be removable: %v", err)
	}
	if state := m.migrateStoreSources(); state != "" {
		t.Fatalf("the migration runs once, got %q", state)
	}
	if urls := m.GetAllStoreURLs(); len(urls) != 1 || urls[0] != "https://community.invalid/index.json" {
		t.Fatalf("the removed source came back: %v", urls)
	}
	if dials.Count() != 0 {
		t.Fatal("the migration itself must not open a connection")
	}

	// A new installation never gets it
	fresh := newFaultManager(t)
	fresh.migrateStoreSources()
	fresh.Options.ExistingInstall = true //a later start of the same installation
	fresh.migrateStoreSources()
	if fresh.StoreConfigured() {
		t.Fatalf("a new installation got a source at its second start: %v", fresh.GetAllStoreURLs())
	}
}

func TestInstalledPluginsOfARemovedSourceAreReported(t *testing.T) {
	m := newFaultManager(t)
	loadChaos(t, m, "orphan", "")
	m.saveInstallRecord("test.chaos.orphan", &InstallRecord{Source: "https://gone.invalid/index.json", Folder: "orphan"})
	setup := m.StoreSetupInfo()
	if len(setup.Orphaned) != 1 || setup.Orphaned[0].Source != "https://gone.invalid/index.json" || len(setup.Orphaned[0].Plugins) != 1 || setup.Orphaned[0].Plugins[0] != "test.chaos.orphan" {
		t.Fatalf("a plugin whose source is gone must be reported: %+v", setup.Orphaned)
	}
	m.Options.PluginStoreURLs = []string{"https://gone.invalid/index.json"}
	if setup := m.StoreSetupInfo(); len(setup.Orphaned) != 0 {
		t.Fatalf("with the source configured nothing is orphaned: %+v", setup.Orphaned)
	}
}

/* The add-on index on a web server */

type addonFixEntry struct {
	p            idxPlugin
	minHost      string
	artifacts    map[string]map[string]any //overrides the artifact list
	extraFields  map[string]any
	artifactPath string //relative address of the artifact, default "bin/<name>-<version>"
}

// publishAddonIndex serves an add-on index over the given plugins at /<indexName>,
// signed with privKey by the real tool ("" = no signature file)
func (f *storeFix) publishAddonIndex(indexName string, privKey string, serial int, entries ...addonFixEntry) {
	f.t.Helper()
	addons := []any{}
	for _, e := range entries {
		rel := e.artifactPath
		if rel == "" {
			rel = strings.TrimPrefix(e.p.path(), "/")
		}
		f.put("/"+rel, e.p.bin)
		f.put("/icons/"+e.p.name+".png", []byte("\x89PNG test icon"))
		arts := map[string]map[string]any{platformKey(): {"url": rel, "sha256": sumOf(e.p.bin), "size": len(e.p.bin)}}
		if e.artifacts != nil {
			arts = e.artifacts
		}
		a := map[string]any{
			"id": e.p.id(), "name": e.p.name, "publisher": "Test publisher", "description": "An add-on of the test store", "licence": "AGPL-3.0-only",
			"version": versionToString(e.p.version[0], e.p.version[1], e.p.version[2]), "api_version": 1, "type": "utility",
			"categories": []string{"Testing"}, "changelog": []map[string]string{{"version": "1.0.0", "notes": "First"}},
			"permissions": []map[string]string{{"method": "GET", "endpoint": "/plugin/api/access/list", "reason": "test"}},
			"icon":        "icons/" + e.p.name + ".png", "screenshots": []string{"shots/1.png", "file:///etc/passwd"},
			"artifacts": arts,
		}
		if e.minHost != "" {
			a["min_host_version"] = e.minHost
		}
		for k, v := range e.extraFields {
			a[k] = v
		}
		addons = append(addons, a)
	}
	raw, _ := json.MarshalIndent(map[string]any{"format": addonindex.Format, "version": addonindex.Version, "serial": serial, "addons": addons}, "", " ")
	f.put("/"+indexName, raw)
	f.mu.Lock()
	delete(f.files, "/"+indexName+".sig")
	f.mu.Unlock()
	if privKey == "" {
		return
	}
	local := filepath.Join(f.work, "addon-"+itoa(serial)+"-"+indexName)
	if err := os.WriteFile(local, raw, 0o644); err != nil {
		f.t.Fatal(err)
	}
	if msg, err := f.tool("-sign-raw", "-index", local, "-key", privKey); err != nil {
		f.t.Fatalf("signing the add-on index: %v\n%s", err, msg)
	}
	sig, _ := os.ReadFile(local + ".sig")
	f.put("/"+indexName+".sig", sig)
}

func TestAddonIndexInstallUnderEnforce(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "addonp")
	f.publishAddonIndex("index.json", priv, 3, addonFixEntry{p: p1})
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	sync1(t, m)

	src := m.ListStoreSources()
	if len(src) != 1 || src[0].Signature != SigSigned || src[0].Serial != 3 || src[0].Schema != SchemaAddonV1 || src[0].Plugins != 1 || src[0].Note != "" {
		t.Fatalf("status of the add-on index: %+v", src[0])
	}
	list := m.ListDownloadablePlugins()
	if len(list) != 1 {
		t.Fatalf("want one add-on, got %d", len(list))
	}
	e := list[0]
	if e.Addon == nil || e.Addon.Publisher != "Test publisher" || e.Addon.Licence != "AGPL-3.0-only" || e.Addon.Version != "1.0.0" || len(e.Addon.Categories) != 1 ||
		len(e.Addon.Changelog) != 1 || e.Addon.Incompatible != "" || e.PluginIntroSpect.Author != "Test publisher" || len(e.PluginIntroSpect.PermittedAPIEndpoints) != 1 {
		t.Fatalf("metadata of the add-on: %+v / %+v", e.Addon, e.PluginIntroSpect)
	}
	// Relative addresses are resolved against the index; a file address in an index of the web is dropped
	if e.DownloadURLs[platformKey()] != f.url(p1.path()) || e.IconPath != f.url("/icons/addonp.png") {
		t.Fatalf("addresses were not resolved against the index: %q %q", e.DownloadURLs[platformKey()], e.IconPath)
	}
	if len(e.Addon.Screenshots) != 1 || e.Addon.Screenshots[0] != f.url("/shots/1.png") {
		t.Fatalf("screenshots: %v", e.Addon.Screenshots)
	}
	if err := installByID(m, p1.id()); err != nil {
		t.Fatalf("install from a validly signed add-on index under enforce: %v", err)
	}
	p, err := m.GetPluginByID(p1.id())
	if err != nil {
		t.Fatal(err)
	}
	info := p.Status().Install
	if !info.Known || info.Source != f.url("/index.json") || info.Signature != SigSigned || info.Verified != VerifiedHashOK || info.SHA256 != sumOf(p1.bin) || info.Version != "1.0.0" {
		t.Fatalf("install record: %+v", info)
	}
	if m.GetPluginPreviousEnableState(p1.id()) {
		t.Fatal("a freshly installed add-on must be stored as not enabled")
	}
	noStagingLeft(t, m)
}

func TestAddonIndexSignatureModes(t *testing.T) {
	type outcome struct {
		signature string
		installs  bool
	}
	cases := []struct {
		name    string
		publish func(f *storeFix, priv, otherPriv string, p idxPlugin)
		want    map[string]outcome //verification mode -> what happens
	}{
		{"signed", func(f *storeFix, priv, _ string, p idxPlugin) {
			f.publishAddonIndex("index.json", priv, 1, addonFixEntry{p: p})
		},
			map[string]outcome{VerifyOff: {SigUnchecked, true}, VerifyWarn: {SigSigned, true}, VerifyEnforce: {SigSigned, true}}},
		{"no signature file", func(f *storeFix, _, _ string, p idxPlugin) {
			f.publishAddonIndex("index.json", "", 1, addonFixEntry{p: p})
		},
			map[string]outcome{VerifyOff: {SigUnchecked, true}, VerifyWarn: {SigMissing, true}, VerifyEnforce: {SigMissing, false}}},
		{"signed with another key", func(f *storeFix, _, other string, p idxPlugin) {
			f.publishAddonIndex("index.json", other, 1, addonFixEntry{p: p})
		},
			map[string]outcome{VerifyOff: {SigUnchecked, true}, VerifyWarn: {SigBad, true}, VerifyEnforce: {SigBad, false}}},
		{"changed after signing", func(f *storeFix, priv, _ string, p idxPlugin) {
			f.publishAddonIndex("index.json", priv, 1, addonFixEntry{p: p})
			f.put("/index.json", append(f.get("/index.json"), ' '))
		}, map[string]outcome{VerifyOff: {SigUnchecked, true}, VerifyWarn: {SigBad, true}, VerifyEnforce: {SigBad, false}}},
		{"program file is not the signed one", func(f *storeFix, priv, _ string, p idxPlugin) {
			f.publishAddonIndex("index.json", priv, 1, addonFixEntry{p: p})
			f.put(p.path(), chaosVariant(f.t, "version=1.0.0\nswapped=yes"))
		}, map[string]outcome{VerifyOff: {SigUnchecked, true}, VerifyWarn: {SigSigned, true}, VerifyEnforce: {SigSigned, false}}},
	}
	for _, c := range cases {
		for _, mode := range []string{VerifyOff, VerifyWarn, VerifyEnforce} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				f := newStoreFix(t)
				priv, pub := f.keys("k")
				otherPriv, _ := f.keys("other")
				p := goodV1(t, "modep")
				c.publish(f, priv, otherPriv, p)
				m := storeManager(t, f, "index.json")
				setVerify(t, m, mode, pub)
				sync1(t, m)
				want := c.want[mode]
				if src := m.ListStoreSources(); src[0].Signature != want.signature {
					t.Fatalf("signature state %q, want %q (%s)", src[0].Signature, want.signature, src[0].Note)
				}
				err := installByID(m, p.id())
				if want.installs && err != nil {
					t.Fatalf("must install in mode %s: %v", mode, err)
				}
				if !want.installs {
					if err == nil {
						t.Fatalf("must be refused in mode %s", mode)
					}
					if _, getErr := m.GetPluginByID(p.id()); getErr == nil {
						t.Fatal("a refused add-on must not be installed")
					}
					if entries, _ := os.ReadDir(m.Options.PluginDir); len(entries) > 1 {
						t.Fatalf("a refused install left files in the plugin directory: %v", entries)
					}
				}
				noStagingLeft(t, m)
			})
		}
	}
}

func TestAddonIndexReplayIsRefusedUnderEnforce(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1, p2 := goodV1(t, "replayp"), goodV2(t, "replayp")
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	f.publishAddonIndex("index.json", priv, 5, addonFixEntry{p: p2})
	sync1(t, m)
	f.publishAddonIndex("old.json", priv, 4, addonFixEntry{p: p1})
	oldDoc, oldSig := f.get("/old.json"), f.get("/old.json.sig")
	f.put("/index.json", oldDoc) //the older, validly signed index is served again
	f.put("/index.json.sig", oldSig)
	sync1(t, m)
	if src := m.ListStoreSources(); src[0].Signature != SigReplayed {
		t.Fatalf("an older signed add-on index must be reported as replayed, got %q", src[0].Signature)
	}
	// What the last good index offered is still what is installed
	if err := installByID(m, p1.id()); err != nil {
		t.Fatalf("the add-on of the last valid index stays installable: %v", err)
	}
	p, _ := m.GetPluginByID(p1.id())
	if got := p.Status().Install.Version; got != "1.1.0" {
		t.Fatalf("the version of the replayed index was installed: %s", got)
	}
}

/* Platform selection */

func TestAddonIndexInstallsOnlyTheBuildForThisPlatform(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "platp")
	other := "plan9_mips"
	if platformKey() == other {
		other = "linux_s390x"
	}
	sum, size := sumOf(p1.bin), len(p1.bin)
	here := strings.ToUpper(runtime.GOOS) + "/" + runtime.GOARCH //a spelling the index is allowed to use
	f.publishAddonIndex("index.json", priv, 1,
		addonFixEntry{p: p1, artifacts: map[string]map[string]any{
			here:            {"url": strings.TrimPrefix(p1.path(), "/"), "sha256": sum, "size": size},
			other:           {"url": "bin/other-platform", "sha256": sum, "size": size},
			"windows_amd64": {"url": "bin/platp.exe", "sha256": sum, "size": size},
		}},
		addonFixEntry{p: goodV1(t, "elsewhere"), artifacts: map[string]map[string]any{
			other: {"url": "bin/elsewhere-other", "sha256": sum, "size": size},
		}},
	)
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	sync1(t, m)
	if err := installByID(m, p1.id()); err != nil {
		t.Fatalf("install of the build for %s: %v", platformKey(), err)
	}
	if f.hitCount("/bin/other-platform") != 0 || f.hitCount("/bin/platp.exe") != 0 {
		t.Fatal("the build of another platform was downloaded")
	}
	if f.hitCount(p1.path()) != 1 {
		t.Fatalf("the build for this platform must be downloaded once, got %d", f.hitCount(p1.path()))
	}
	// An add-on without a build for this server: listed with a note, never installed
	var elsewhere *DownloadablePlugin
	for _, e := range m.ListDownloadablePlugins() {
		if e.PluginIntroSpect.ID == "test.chaos.elsewhere" {
			elsewhere = e
		}
	}
	if elsewhere == nil || !strings.Contains(elsewhere.Addon.Note, "no build for this server") {
		t.Fatalf("an add-on without a build for this platform must say so: %+v", elsewhere)
	}
	if err := installByID(m, "test.chaos.elsewhere"); err == nil || !strings.Contains(err.Error(), "current platform") {
		t.Fatalf("want a refusal for the missing platform, got %v", err)
	}
	if f.hitCount("/bin/elsewhere-other") != 0 {
		t.Fatal("the build of another platform was downloaded")
	}
}

/* Minimum host version */

func TestAddonIndexMinimumHostVersion(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	fits, tooNew := goodV1(t, "fits"), goodV1(t, "toonew")
	f.publishAddonIndex("index.json", priv, 1, addonFixEntry{p: fits, minHost: "1.0.0"}, addonFixEntry{p: tooNew, minHost: "1.1.0"})
	for _, mode := range []string{VerifyOff, VerifyWarn, VerifyEnforce} {
		m := storeManager(t, f, "index.json")
		m.Options.SystemConst.DunreeVersion = "1.0.0-beta.1"
		setVerify(t, m, mode, pub)
		sync1(t, m)
		if err := installByID(m, fits.id()); err != nil {
			t.Fatalf("%s: an add-on for 1.0.0 must install on 1.0.0-beta.1: %v", mode, err)
		}
		err := installByID(m, tooNew.id())
		if err == nil || !strings.Contains(err.Error(), "needs Dunree 1.1.0 or newer") {
			t.Fatalf("%s: an add-on for a newer Dunree must be refused in every mode, got %v", mode, err)
		}
		if f.hitCount(tooNew.path()) != 0 {
			t.Fatalf("%s: the program file of an incompatible add-on was downloaded", mode)
		}
	}
	// A host whose version cannot be read: nothing is refused, the entry says why
	m := storeManager(t, f, "index.json")
	m.Options.SystemConst.DunreeVersion = "development"
	setVerify(t, m, VerifyWarn, pub)
	sync1(t, m)
	for _, e := range m.ListDownloadablePlugins() {
		if e.Addon.Incompatible != "" || !strings.Contains(e.Addon.Note, "could not be read") {
			t.Fatalf("unknown host version: %+v", e.Addon)
		}
	}
}

/* An index on the web can never make Dunree read a file of the server */

func TestRemoteIndexCannotPointAtLocalFiles(t *testing.T) {
	f := newStoreFix(t)
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("not for the plugin folder"), 0o600)
	fileURL := fileURLFromPath(secret)
	p1 := goodV1(t, "localref")
	sum, size := sumOf(p1.bin), len(p1.bin)

	// Add-on index: the artifact is left out, and with it the add-on
	f.publishAddonIndex("index.json", "", 1, addonFixEntry{p: p1, artifacts: map[string]map[string]any{platformKey(): {"url": fileURL, "sha256": sum, "size": size}}})
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyWarn, "")
	sync1(t, m)
	if got := m.ListDownloadablePlugins(); len(got) != 0 {
		t.Fatalf("an add-on whose only artifact is a file of the server must be left out, got %d", len(got))
	}
	if src := m.ListStoreSources(); !strings.Contains(src[0].Note, "may not point at a file of this server") {
		t.Fatalf("the source must say what was left out: %q", src[0].Note)
	}

	// The list format carries addresses as they are: the read itself is refused
	f.publishLegacy("legacy.json", nil, p1)
	var list []map[string]any
	json.Unmarshal(f.get("/legacy.json"), &list)
	list[0]["DownloadURLs"] = map[string]string{platformKey(): fileURL}
	raw, _ := json.Marshal(list)
	f.put("/legacy.json", raw)
	m2 := storeManager(t, f, "legacy.json")
	sync1(t, m2)
	err := installByID(m2, p1.id())
	if err == nil || !strings.Contains(err.Error(), "not inside the folder of a configured local add-on store") {
		t.Fatalf("a file address in an index of the web must be refused, got %v", err)
	}
	noStagingLeft(t, m2)
}

/* File addresses */

func TestFileAddressesOfLocalSources(t *testing.T) {
	for _, c := range []struct{ raw, goos, want string }{
		{"file:///srv/store/index.json", "linux", "/srv/store/index.json"},
		{"file:///srv/my%20store/index.json", "linux", "/srv/my store/index.json"},
		{"file:///C:/Dunree/store/index.json", "windows", `C:\Dunree\store\index.json`},
		{"file://localhost/srv/store/index.json", "linux", "/srv/store/index.json"},
	} {
		if got, ok := pathFromFileURLOn(c.raw, c.goos); !ok || got != c.want {
			t.Errorf("%s on %s: got %q (%v), want %q", c.raw, c.goos, got, ok, c.want)
		}
	}
	for _, bad := range []string{"file://fileserver/share/index.json", "https://example.org/index.json", "file:", "/srv/store/index.json"} {
		if got, ok := pathFromFileURLOn(bad, "linux"); ok {
			t.Errorf("%q must not be a local file, got %q", bad, got)
		}
	}
	dir := t.TempDir()
	index := filepath.Join(dir, "a store", "index.json")
	if back, ok := pathFromFileURL(fileURLFromPath(index)); !ok || back != index {
		t.Errorf("round trip of %q gave %q", index, back)
	}
	if !pathWithin(dir, filepath.Join(dir, "a", "b")) || pathWithin(dir, filepath.Join(dir, "..", "x")) || pathWithin(dir, dir+"-other") || !pathWithin(dir, dir) {
		t.Error("pathWithin is wrong")
	}
	base, _ := url.Parse(fileURLFromPath(index))
	if _, err := resolveStoreRef(base, "../../outside", true); err == nil {
		t.Error("an artifact outside the index folder must be refused")
	}
	if got, err := resolveStoreRef(base, "addons/x/1.0.0/x", true); err != nil || !strings.HasPrefix(got, "file://") {
		t.Errorf("an artifact inside the index folder: %q %v", got, err)
	}
	web, _ := url.Parse("https://store.invalid/a/index.json")
	if got, err := resolveStoreRef(web, "addons/x", true); err != nil || got != "https://store.invalid/a/addons/x" {
		t.Errorf("relative address of a web index: %q %v", got, err)
	}
	for _, bad := range []string{"file:///etc/passwd", "javascript:alert(1)", "ftp://x/y", ""} {
		if got, err := resolveStoreRef(web, bad, true); err == nil {
			t.Errorf("%q in a web index must be refused, got %q", bad, got)
		}
	}
}

/* From tools/addon-store to an installed add-on, in a local folder, offline */

var addonStoreToolBuild struct {
	once sync.Once
	bin  string
	err  error
}

// addonStoreTool builds tools/addon-store/main.go once per test run
func addonStoreTool(t testing.TB) string {
	t.Helper()
	chaosBinary(t) //creates the build folder that TestMain removes, and skips on Windows
	addonStoreToolBuild.once.Do(func() {
		bin := filepath.Join(chaosBuild.dir, "addon-store-tool")
		cmd := exec.Command("go", "build", "-o", bin, "main.go")
		cmd.Dir = filepath.Join("..", "..", "..", "tools", "addon-store")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-p=2", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			addonStoreToolBuild.err = errors.New("building tools/addon-store failed: " + err.Error() + "\n" + string(out))
			return
		}
		addonStoreToolBuild.bin = bin
	})
	if addonStoreToolBuild.err != nil {
		t.Fatal(addonStoreToolBuild.err)
	}
	return addonStoreToolBuild.bin
}

// writeAddonSource writes the publisher's folder of one add-on
func writeAddonSource(t testing.TB, in string, p idxPlugin) {
	t.Helper()
	dir := filepath.Join(in, p.name)
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(map[string]any{
		"id": p.id(), "name": p.name, "publisher": "Test publisher", "description": "Published by the generator", "licence": "AGPL-3.0-only",
		"version": versionToString(p.version[0], p.version[1], p.version[2]), "api_version": 1, "min_host_version": "1.0.0", "type": "utility",
		"categories": []string{"Testing"},
	})
	if err := os.WriteFile(filepath.Join(dir, "addon.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifacts", p.name+"_"+platformKey()), p.bin, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestLocalFolderStoreFromTheGeneratorOffline(t *testing.T) {
	f := newStoreFix(t) //only for the keys and the signing tool; its web server is not used
	priv, pub := f.keys("k")
	pubFile := filepath.Join(f.work, "k.pub")
	in, site := filepath.Join(f.work, "addons"), filepath.Join(f.work, "site")
	p1 := goodV1(t, "localp")
	writeAddonSource(t, in, p1)
	generate := func() {
		t.Helper()
		out, err := exec.Command(addonStoreTool(t), "-in", in, "-out", site, "-key", priv, "-pub", pubFile, "-signer", indexTool(t), "-store-name", "Test store").CombinedOutput()
		if err != nil {
			t.Fatalf("tools/addon-store: %v\n%s", err, out)
		}
	}
	generate()

	// What the tool wrote is what the host package reads
	raw, err := os.ReadFile(filepath.Join(site, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	idx, skipped, err := addonindex.Parse(raw)
	if err != nil || len(skipped) != 0 || len(idx.Addons) != 1 || idx.Serial != 1 {
		t.Fatalf("the index of the generator must parse cleanly: %v %+v", err, skipped)
	}
	if _, _, ok := addonindex.SelectArtifact(idx.Addons[0].Artifacts, runtime.GOOS, runtime.GOARCH); !ok {
		t.Fatal("the index of the generator has no artifact for this platform")
	}

	// From here on: offline mode, and a transport that fails and counts
	dials := offlinetest.Install(t)
	offline.Set(true)
	m := storeManager(t, f)
	m.Options.SystemConst.DunreeVersion = "1.0.0-beta.1"
	setVerify(t, m, VerifyEnforce, pub)
	if body := postForm(m.HandleAddStoreSource, url.Values{"kind": {SourceKindLocal}, "folder": {filepath.Join(f.work, "nowhere")}}); !strings.Contains(body, "does not exist") {
		t.Fatalf("a folder that is not there: %s", body)
	}
	if body := postForm(m.HandleAddStoreSource, url.Values{"kind": {SourceKindLocal}, "folder": {site}}); !strings.Contains(body, "OK") {
		t.Fatalf("adding the local folder: %s", body)
	}
	src := m.ListStoreSources()
	if len(src) != 1 || src[0].Kind != SourceKindLocal || src[0].Folder != site || src[0].Signature != SigSigned || src[0].Schema != SchemaAddonV1 || src[0].Official {
		t.Fatalf("the local source: %+v", src[0])
	}
	if err := installByID(m, p1.id()); err != nil {
		t.Fatalf("install from the local folder under enforce, offline: %v", err)
	}
	p, err := m.GetPluginByID(p1.id())
	if err != nil {
		t.Fatal(err)
	}
	if info := p.Status().Install; info.Verified != VerifiedHashOK || info.Signature != SigSigned || info.SHA256 != sumOf(p1.bin) || info.Version != "1.0.0" {
		t.Fatalf("install record: %+v", info)
	}
	if n := dials.Count(); n != 0 {
		t.Fatalf("adding, syncing and installing from a local folder opened %d connections", n)
	}
	// (From here on the plugin runs and Dunree talks to it on the loopback, so
	// connections are no longer counted. Offline mode stays on: a fetch from the
	// web would fail the update below.)
	if err := m.EnablePlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	waitHealth(t, p, HealthOK)

	// A new version is published: safe update, the previous version is kept, rollback works
	p2 := goodV2(t, "localp")
	writeAddonSource(t, in, p2)
	generate()
	sync1(t, m)
	if infos := m.GetPluginUpdateInfos(); len(infos) != 1 || !infos[0].UpdateAvailable || infos[0].Blocked != "" {
		t.Fatalf("update information: %+v", infos)
	}
	if err := m.UpdatePlugin(p1.id()); err != nil {
		t.Fatalf("UpdatePlugin: %v", err)
	}
	if info := p.Status().Install; info.Version != "1.1.0" || info.PreviousVersion != "1.0.0" || !info.CanRollback || info.SHA256 != sumOf(p2.bin) {
		t.Fatalf("record after the update: %+v", info)
	}
	if body := postForm(m.HandleRollbackPlugin, url.Values{"pluginID": {p1.id()}}); !strings.Contains(body, "OK") {
		t.Fatalf("rollback: %s", body)
	}
	if got := versionOfSpec(p.spec()); got != "1.0.0" || !p.IsRunning() {
		t.Fatalf("version 1.0.0 must run again after the rollback, got %s running=%v", got, p.IsRunning())
	}

	// A program file that was changed in the folder after signing is refused
	artifact := filepath.Join(site, "addons", p1.id(), "1.1.0", "localp_"+platformKey())
	swapped := append([]byte(nil), p2.bin...)
	swapped[len(swapped)-2] ^= 0x01 //same size, another checksum
	if err := os.WriteFile(artifact, swapped, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdatePlugin(p1.id()); err == nil || !strings.Contains(err.Error(), "does not match its index") {
		t.Fatalf("a changed program file must be refused under enforce, got %v", err)
	}
	if got := versionOfSpec(p.spec()); got != "1.0.0" || !p.IsRunning() {
		t.Fatalf("the refused update must leave 1.0.0 running, got %s running=%v", got, p.IsRunning())
	}
	noStagingLeft(t, m)

	// Once the folder is no longer a source, nothing is read from it
	if err := m.RemoveStoreSource(src[0].URL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.downloadTo(fileURLFromPath(artifact), filepath.Join(t.TempDir(), "x"), 1<<30); err == nil {
		t.Fatal("a file of a folder that is not a source must not be read")
	}
}

// A file of this server is read only for an entry of the local source whose
// folder holds it: not for an index of the web, and not for another local
// source (the list format carries addresses as they are). And the path that is
// checked is the path that is opened, also through a link inside the folder.
func TestLocalArtifactOnlyFromItsOwnSourceFolder(t *testing.T) {
	root := t.TempDir()
	dirA, dirB, outside := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "outside", "deep")
	for _, d := range []string{dirA, dirB, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	indexA, indexB := filepath.Join(dirA, "index.json"), filepath.Join(dirB, "index.json")
	inA := filepath.Join(dirA, "bin")
	os.WriteFile(inA, []byte("artifact of a"), 0o755)

	for _, c := range []struct {
		source, artifact string
		ok               bool
	}{
		{fileURLFromPath(indexA), fileURLFromPath(inA), true},
		{fileURLFromPath(indexA), "https://example.org/bin", true}, //web addresses are not this check's business
		{fileURLFromPath(indexB), fileURLFromPath(inA), false},     //another local source
		{"https://store.invalid/index.json", fileURLFromPath(inA), false},
		{"", fileURLFromPath(inA), false},
		{fileURLFromPath(indexA), fileURLFromPath(filepath.Join(dirA, "..", "b", "x")), false},
		{fileURLFromPath(indexA), "file://fileserver/share/bin", false},
	} {
		if got := localArtifactRefused(c.source, c.artifact); (got == "") != c.ok {
			t.Errorf("source %s, artifact %s: refused=%q, want allowed=%v", c.source, c.artifact, got, c.ok)
		}
	}

	// Through the install: source B lists an artifact of folder A, both are configured
	m := newFaultManager(t)
	os.MkdirAll(m.Options.PluginDir, 0o755)
	p := goodV1(t, "crosslocal")
	os.WriteFile(filepath.Join(dirA, "crosslocal"), p.bin, 0o755)
	os.WriteFile(indexA, []byte("[]"), 0o644)
	entry := map[string]any{"IconPath": "", "PluginIntroSpect": p.spec(), "DownloadURLs": map[string]string{platformKey(): fileURLFromPath(filepath.Join(dirA, "crosslocal"))}}
	raw, _ := json.Marshal([]any{entry})
	os.WriteFile(indexB, raw, 0o644)
	m.Options.PluginStoreURLs = []string{fileURLFromPath(indexA), fileURLFromPath(indexB)}
	setVerify(t, m, VerifyOff, "")
	sync1(t, m)
	err := installByID(m, p.id())
	if err == nil || !strings.Contains(err.Error(), "not inside the folder of a configured local add-on store") {
		t.Fatalf("an artifact of another local source must be refused, got %v", err)
	}
	noStagingLeft(t, m)

	// "a/link/../x": checked lexically as a/x, opened by the OS through the link
	if runtime.GOOS == "windows" {
		return //symbolic links need a privilege there
	}
	if err := os.Symlink(outside, filepath.Join(dirA, "link")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	os.WriteFile(filepath.Join(dirA, "x"), []byte("inside"), 0o644)
	os.WriteFile(filepath.Join(root, "outside", "x"), []byte("outside the source folder"), 0o644)
	m.Options.PluginStoreURLs = []string{fileURLFromPath(indexA)}
	tricky := (&url.URL{Scheme: "file", Path: filepath.ToSlash(dirA) + "/link/../x"}).String()
	sum, _, err := m.copyLocalArtifact(tricky, filepath.Join(t.TempDir(), "copy"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if sum != sumOf([]byte("inside")) {
		t.Fatal("the file that was read is not the one inside the source folder that was checked")
	}
}
