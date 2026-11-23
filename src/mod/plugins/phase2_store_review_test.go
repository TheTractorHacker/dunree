//go:build !windows

package plugins

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

/*
	Review fixes of items 2.4 and 2.5 (docs/plugins/reliability-plan.md, "Review
	fixes" of the section on 2.4, 2.5 and 2.7)
*/

// nextBoot is a second Zoraxy on the same plugin directory and database
func nextBoot(t *testing.T, m *Manager, mode string, pub string) (*Manager, *auditTrap) {
	t.Helper()
	next := newFaultManager(t)
	next.Options.PluginDir = m.Options.PluginDir
	next.Options.Database = m.Options.Database
	next.Options.PluginStoreURLs = m.Options.PluginStoreURLs
	next.storeCfg = m.storeCfg
	t.Cleanup(func() { next.Close() })
	trap := trapAudit(next)
	setVerify(t, next, mode, pub)
	if err := next.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	return next, trap
}

// A program file that changed on disk is compared with the install record of its
// FOLDER before it is run for its manifest. Under enforce it is not run at all,
// also when it declares another plugin ID than the one that was installed.
func TestChangedBinaryIsNotRunBeforeItIsCompared(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "swapped")
	f.publishSigned("index.json", priv, 1, p1)
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	sync1(t, m)
	if err := installByID(m, p1.id()); err != nil {
		t.Fatal(err)
	}
	p := mustPlugin(t, m, p1.id())
	bin := filepath.Join(p.RootDir, "swapped")
	if id, rec := m.recordOfFolder("swapped"); id != p1.id() || rec == nil || rec.Folder != "swapped" {
		t.Fatalf("the install record must be found by the plugin folder: %q %+v", id, rec)
	}

	// The replacement leaves a marker whenever it is run, and says it is another plugin
	manifest, err := exec.Command(bin, "-introspect").Output()
	if err != nil {
		t.Fatal(err)
	}
	other := strings.ReplaceAll(string(manifest), p1.id(), "test.chaos.other")
	if other == string(manifest) {
		t.Fatal("the manifest does not carry the plugin ID")
	}
	marker := filepath.Join(t.TempDir(), "was-run")
	script := "#!/bin/sh\ntouch '" + marker + "'\ncat <<'MANIFEST'\n" + other + "\nMANIFEST\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	wasRun := func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}

	// enforce, reload of the running Zoraxy: not run, the loaded plugin stays as it is
	m.ReloadPluginFromDisk()
	if wasRun() {
		t.Fatal("enforce: a reload ran the changed program file")
	}
	if _, err := m.GetPluginByID(p1.id()); err != nil || len(m.ListLoadFailures()) != 0 {
		t.Fatalf("the loaded plugin must stay loaded and its folder is not a load failure: %v %+v", err, m.ListLoadFailures())
	}
	if err := m.StartPlugin(p1.id()); err == nil || wasRun() {
		t.Fatalf("enforce: the start must be refused without running the file (err %v, run %v)", err, wasRun())
	}

	// enforce, next boot: not run, not loaded under either ID, reported once
	next, audit := nextBoot(t, m, VerifyEnforce, pub)
	if wasRun() {
		t.Fatal("enforce: the boot ran the changed program file")
	}
	for _, id := range []string{p1.id(), "test.chaos.other"} {
		if _, err := next.GetPluginByID(id); err == nil {
			t.Fatalf("enforce: %s must not be loaded", id)
		}
	}
	fails := next.ListLoadFailures()
	if len(fails) != 1 || fails[0].Folder != "swapped" || !strings.Contains(fails[0].Error, "was not run") || !strings.Contains(fails[0].Error, p1.id()) {
		t.Fatalf("the folder must be reported with the reason: %+v", fails)
	}
	next.ReloadPluginFromDisk()
	next.ReloadPluginFromDisk()
	got := audit.of(p1.id())
	if len(got) != 1 || got[0].Event != "plugins.binary.changed" || got[0].Detail["run"] != "false" || got[0].Detail["folder"] != "swapped" {
		t.Fatalf("one audit entry for the changed file, not one per reload: %+v", got)
	}
	if wasRun() {
		t.Fatal("enforce: a reload after the boot ran the changed program file")
	}

	// warn: loaded as before (that is what warn means), but on record although the
	// file declares an ID that has no install record
	next, audit = nextBoot(t, m, VerifyWarn, pub)
	if !wasRun() {
		t.Fatal("warn must load the plugin as before")
	}
	if _, err := next.GetPluginByID("test.chaos.other"); err != nil {
		t.Fatalf("warn: the plugin loads under the ID it declares: %v", err)
	}
	got = audit.of(p1.id())
	if len(got) != 1 || got[0].Event != "plugins.binary.changed" || got[0].Detail["declared"] != "test.chaos.other" || got[0].Detail["run"] != "true" {
		t.Fatalf("warn: the changed file that declares another ID must be audited: %+v", got)
	}

	// off: nothing is compared
	os.Remove(marker)
	next, audit = nextBoot(t, m, VerifyOff, pub)
	if !wasRun() || len(audit.of(p1.id())) != 0 {
		t.Fatalf("off must not compare anything (run %v, audit %+v)", wasRun(), audit.of(p1.id()))
	}

	// The installed file back in place: loads under enforce again
	if err := os.WriteFile(bin, p1.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	next, _ = nextBoot(t, m, VerifyEnforce, pub)
	if _, err := next.GetPluginByID(p1.id()); err != nil || len(next.ListLoadFailures()) != 0 {
		t.Fatalf("the installed file must load under enforce: %v %+v", err, next.ListLoadFailures())
	}
}

// A record written before folders were recorded gets its folder at the next boot
func TestInstallRecordLearnsItsFolderAtBoot(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "older")
	f.publishSigned("index.json", priv, 1, p1)
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	sync1(t, m)
	if err := installByID(m, p1.id()); err != nil {
		t.Fatal(err)
	}
	rec := m.installRecord(p1.id())
	rec.Folder = ""
	m.saveInstallRecord(p1.id(), rec)
	m.Options.Database.Delete(installFolderDBTable, "older")

	next, _ := nextBoot(t, m, VerifyEnforce, pub)
	if id, rec := next.recordOfFolder("older"); id != p1.id() || rec == nil {
		t.Fatalf("the record must be found by its folder after a boot: %q %+v", id, rec)
	}
	// Uninstall forgets the folder with the record
	if err := next.UninstallPlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	if next.Options.Database.KeyExists(installFolderDBTable, "older") || next.Options.Database.KeyExists(installDBTable, p1.id()) {
		t.Fatal("uninstall must forget the install record and its folder")
	}
}

// Zoraxy killed between the two renames of a swap: the plugin folder has no
// program file. The next start puts the installed one back and clears .staging.
func TestInterruptedSwapIsRepairedAtBoot(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	p1 := goodV1(t, "halfway")
	f.publishSigned("index.json", priv, 1, p1)
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	sync1(t, m)
	if err := installByID(m, p1.id()); err != nil {
		t.Fatal(err)
	}
	p := mustPlugin(t, m, p1.id())
	bin := filepath.Join(p.RootDir, "halfway")
	prevDir := filepath.Join(p.RootDir, previousDirName)
	staging := filepath.Join(m.Options.PluginDir, stagingDirName)
	sumAt := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return sumOf(b)
	}

	// An update stopped after its first rename (swapIn): the installed file is in
	// .zoraxy-previous/, the download still in .staging/
	if err := os.MkdirAll(prevDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bin, filepath.Join(prevDir, "halfway")); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(staging, "test.chaos.halfway"), 0o755)
	os.WriteFile(filepath.Join(staging, "test.chaos.halfway", "halfway"), goodV2(t, "halfway").bin, 0o755)

	next, _ := nextBoot(t, m, VerifyEnforce, pub)
	np, err := next.GetPluginByID(p1.id())
	if err != nil {
		t.Fatalf("the plugin must load again after an interrupted update: %v (%+v)", err, next.ListLoadFailures())
	}
	if sumAt(bin) != sumOf(p1.bin) || versionOfSpec(np.spec()) != "1.0.0" {
		t.Fatal("the installed version must be back in place")
	}
	if _, err := os.Stat(prevDir); !os.IsNotExist(err) {
		t.Fatalf("the emptied folder of the previous version must be gone: %v", err)
	}
	noStagingLeft(t, next)
	if info := np.Status().Install; info.CanRollback || info.Version != "1.0.0" {
		t.Fatalf("record after the repair: %+v", info)
	}

	// A real update to 1.1.0, then a rollback stopped after its first rename
	// (swapBack): the installed 1.1.0 is in .staging/.rollback-<id>/, 1.0.0 still kept
	p2 := goodV2(t, "halfway")
	f.publishSigned("index.json", priv, 2, p2)
	sync1(t, next)
	if err := next.UpdatePlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	aside := filepath.Join(staging, ".rollback-test.chaos.halfway")
	if err := os.MkdirAll(aside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bin, filepath.Join(aside, "replaced-halfway")); err != nil {
		t.Fatal(err)
	}

	third, _ := nextBoot(t, next, VerifyEnforce, pub)
	tp, err := third.GetPluginByID(p1.id())
	if err != nil {
		t.Fatalf("the plugin must load again after an interrupted rollback: %v (%+v)", err, third.ListLoadFailures())
	}
	if sumAt(bin) != sumOf(p2.bin) || versionOfSpec(tp.spec()) != "1.1.0" {
		t.Fatal("the version the record describes (1.1.0) must be back in place")
	}
	if sumAt(filepath.Join(prevDir, "halfway")) != sumOf(p1.bin) {
		t.Fatal("the previous version must still be kept")
	}
	noStagingLeft(t, third)
	if info := tp.Status().Install; !info.CanRollback || info.PreviousVersion != "1.0.0" {
		t.Fatalf("record after the repair: %+v", info)
	}
	if err := third.RollbackPlugin(p1.id()); err != nil {
		t.Fatalf("the rollback must work after the repair: %v", err)
	}
	if sumAt(bin) != sumOf(p1.bin) {
		t.Fatal("rollback after the repair must restore 1.0.0")
	}

	// A folder with an entry point is left alone, also with a kept previous version
	sync1(t, third)
	if err := third.UpdatePlugin(p1.id()); err != nil {
		t.Fatal(err)
	}
	fourth, _ := nextBoot(t, third, VerifyEnforce, pub)
	if sumAt(bin) != sumOf(p2.bin) || sumAt(filepath.Join(prevDir, "halfway")) != sumOf(p1.bin) {
		t.Fatal("a complete plugin folder must not be touched at boot")
	}
	if _, err := fourth.GetPluginByID(p1.id()); err != nil {
		t.Fatal(err)
	}
}

// An index entry without an icon gets the default icon, in both index formats
// (the list reader before the signed index did that; the old store page relies on it)
func TestIndexEntryWithoutIconGetsTheDefault(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	f.publishSigned("signed.json", priv, 1, goodV1(t, "icona"))
	f.publishLegacy("legacy.json", nil, goodV1(t, "iconb"))
	m := storeManager(t, f, "signed.json", "legacy.json")
	setVerify(t, m, VerifyWarn, pub)
	sync1(t, m)
	if len(m.Options.DownloadablePluginCache) != 2 {
		t.Fatalf("want 2 store entries, got %d", len(m.Options.DownloadablePluginCache))
	}
	for _, p := range m.Options.DownloadablePluginCache {
		if p.IconPath != "/img/plugin_icon.png" {
			t.Fatalf("%s: IconPath %q", p.PluginIntroSpect.ID, p.IconPath)
		}
	}
}

// The stall timeout is a limit of its own, apart from the timeout of the whole download
func TestStalledDownloadIsEndedByTheStallTimeout(t *testing.T) {
	f := newStoreFix(t)
	priv, pub := f.keys("k")
	m := storeManager(t, f, "index.json")
	setVerify(t, m, VerifyEnforce, pub)
	p, p1 := installAndRun(t, f, m, priv, "stalls")
	pid := p.Status().PID
	p2 := goodV2(t, "stalls")
	f.publishSigned("index.json", priv, 2, p2)
	sync1(t, m)

	m.storeCfg.StallTimeout = 400 * time.Millisecond //the whole download keeps its 10 minutes
	f.handle(p2.path(), func(w http.ResponseWriter, r *http.Request) {
		// Bytes keep coming for a while (longer than the stall timeout in total:
		// every read gives the download more time), then nothing more
		for i := 0; i < 4; i++ {
			w.Write(p2.bin[i*512 : (i+1)*512])
			w.(http.Flusher).Flush()
			time.Sleep(200 * time.Millisecond)
		}
		select {
		case <-r.Context().Done():
		case <-time.After(20 * time.Second):
		}
	})
	began := time.Now()
	err := m.UpdatePlugin(p1.id())
	took := time.Since(began)
	if err == nil || !strings.Contains(err.Error(), "stalled") || !strings.Contains(err.Error(), "installed version was not touched") {
		t.Fatalf("want the stall reported, got %v", err)
	}
	if took < 800*time.Millisecond || took > 8*time.Second {
		t.Fatalf("the stall timeout must count from the last byte and end the download long before the overall timeout (took %s)", took)
	}
	if st := p.Status(); st.State != StateRunning || st.PID != pid || versionOfSpec(p.spec()) != "1.0.0" {
		t.Fatalf("the installed version must keep running untouched: %s pid %d (was %d)", st.State, st.PID, pid)
	}
	noStagingLeft(t, m)
}
