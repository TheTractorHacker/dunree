package plugins

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
	Phase 2 of docs/plugins/reliability-plan.md: tests for the findings of the
	review of items 2.1 and 2.6 (see "Phase 2 review fixes" in that document).
*/

const manifestHead = `{"id":"test.manifest.odd","name":"Odd","version_major":1,"type":1,"ui_path":"/ui"`

// An api_version that is not a whole number was an unknown key before the field
// existed, and such a manifest loaded. It must still load, as a legacy plugin,
// with one warning.
func TestContractAPIVersionThatIsNotANumberLoadsAsLegacy(t *testing.T) {
	for _, bad := range []string{`"1"`, `1.5`, `99999999999999999999`, `{"major":1}`, `[1]`, `true`, `"one"`} {
		spec, warns, err := decodeManifest([]byte(manifestHead + `,"api_version":` + bad + `}`))
		if err != nil {
			t.Fatalf("api_version %s: the manifest must load, got %v", bad, err)
		}
		if spec.APIVersion != 0 || contractStateOf(spec) != ContractLegacy {
			t.Fatalf("api_version %s: must be a legacy plugin, got version %d", bad, spec.APIVersion)
		}
		if len(warns) != 1 || !strings.Contains(warns[0], "api_version") {
			t.Fatalf("api_version %s: want one warning, got %v", bad, warns)
		}
		if more := sanitizeContractSpec(spec); len(more) != 0 {
			t.Fatalf("api_version %s: reported twice: %v", bad, more)
		}
		if spec.ID != "test.manifest.odd" || spec.Name != "Odd" || spec.VersionMajor != 1 || spec.UIPath != "/ui" || int(spec.Type) != 1 {
			t.Fatalf("api_version %s: the rest of the manifest was lost: %+v", bad, spec)
		}
	}
	//Go matches JSON keys without regard to case: the same for the other spelling
	if spec, warns, err := decodeManifest([]byte(manifestHead + `,"API_Version":"x"}`)); err != nil || spec.APIVersion != 0 || len(warns) != 1 {
		t.Fatalf("other spelling of the key: %v %v", warns, err)
	}
	//Twice in one manifest, one of them not a number
	if spec, warns, err := decodeManifest([]byte(manifestHead + `,"api_version":"x","api_version":1}`)); err != nil || spec.APIVersion != 0 || len(warns) != 1 {
		t.Fatalf("api_version twice: %+v %v %v", spec, warns, err)
	}

	//null and a plain number: no warning
	for raw, want := range map[string]int{`null`: 0, `0`: 0, `1`: 1, `99`: 99} {
		spec, warns, err := decodeManifest([]byte(manifestHead + `,"api_version":` + raw + `}`))
		if err != nil || len(warns) != 0 || spec.APIVersion != want {
			t.Fatalf("api_version %s: version %v, warnings %v, error %v", raw, spec, warns, err)
		}
	}

	//Every other field is as strict as before
	for _, broken := range []string{
		manifestHead + `,"version_minor":"2"}`,
		manifestHead + `,"api_version":"1","version_minor":"2"}`,
		manifestHead + `,"version_minor":"2","api_version":"1"}`,
		`not json`,
		`[1,2]`,
	} {
		if _, _, err := decodeManifest([]byte(broken)); err == nil {
			t.Fatalf("a manifest that never loaded must still not load: %s", broken)
		}
	}
}

// The same through the real loader, with a plugin that prints such a manifest
func TestFaultPluginWithOddAPIVersionIsLoadedAsLegacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a start.sh plugin")
	}
	m := newFaultManager(t)
	for folder, bad := range map[string]string{"text": `"1"`, "fraction": `1.5`, "huge": `99999999999999999999`, "object": `{"v":1}`} {
		dir := filepath.Join(m.Options.PluginDir, folder)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := `{"id":"test.odd.` + folder + `","name":"Odd ` + folder + `","description":"odd","author":"t","ui_path":"/ui","type":1,"api_version":` + bad + `}`
		script := "#!/bin/sh\ncat <<'EOF'\n" + manifest + "\nEOF\n"
		if err := os.WriteFile(filepath.Join(dir, "start.sh"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	for _, folder := range []string{"text", "fraction", "huge", "object"} {
		p, err := m.GetPluginByID("test.odd." + folder)
		if err != nil {
			t.Fatalf("the plugin with api_version of kind %q was not loaded: %v (load failures: %+v)", folder, err, m.ListLoadFailures())
		}
		if c := p.Status().Contract; c.State != ContractLegacy || c.APIVersion != 0 || c.Note != "" {
			t.Fatalf("%s: must be a legacy plugin: %+v", folder, c)
		}
	}
}

// With refuse on, the automatic restart of a plugin of an unsupported contract
// version stops at the refusal: failed_to_start, no retries, no crash loop.
func TestFaultRefusedPluginIsNotRetriedAfterACrash(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadChaosStopped(t, m, "future", "mode=crash\ndelay=1s\napi_version=99\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartAlways })
	mustStart(t, m, p) //contract mode warn: it starts
	if err := m.SetSettings(func(s *ManagerSettings) { s.ContractMode = ContractModeRefuse }); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, "the restart after the crash to be refused", func() bool { return p.Status().State == StateFailedToStart })
	time.Sleep(1200 * time.Millisecond) //more than the backoff delays that would lead to a crash loop
	st := p.Status()
	if st.State != StateFailedToStart || st.StartCount != 1 || st.AutoRestartCount != 0 || st.NextRestartAt != 0 || !strings.Contains(st.LastError, "contract version") {
		t.Fatalf("a refused restart must not be retried and is not a crash loop: %+v", st)
	}
	hist := p.sup.historyCopy()
	last := hist[len(hist)-1]
	if len(hist) != 2 || last.Kind != StateFailedToStart || !strings.Contains(last.Note, "unsupported contract version") || last.RestartInMs != 0 {
		t.Fatalf("exit history: %+v", hist)
	}

	//Without the setting the plugin can be started again by hand
	if err := m.SetSettings(func(s *ManagerSettings) { s.ContractMode = ContractModeWarn }); err != nil {
		t.Fatal(err)
	}
	mustStart(t, m, p)
	m.StopPlugin(p.Spec.ID)
}

// A reload (it runs on every store install and uninstall) reads the manifest of
// every folder. For a plugin that is already loaded that manifest is thrown away,
// so it must not change the approvals or be reported.
func TestFaultReloadDoesNotReviewPermissionsOfLoadedPlugins(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	m.markPermissionBaseline()
	if err := m.SetSettings(func(s *ManagerSettings) { s.RequirePermissionApproval = true }); err != nil {
		t.Fatal(err)
	}
	p := loadChaosStopped(t, m, "syncer", "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epAdd+"\n", "t")
	if err := m.SetPluginPermissionApproval(p.Spec.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	key := jsonString(startedWith(t, p.RootDir)["api_key"])
	reported := len(audit.of(p.Spec.ID))

	//The binary on disk now says something else than the loaded plugin (replaced by hand)
	rewriteChaosConf(t, p, "mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+";POST "+epRemove+"\n")
	m.ReloadPluginFromDisk()

	st := m.permissionStateOf(p)
	if len(st.Requested) != 2 || st.Pending != 0 || st.Withheld != 0 || st.Requested[1].Endpoint != epAdd || !st.Requested[1].Approved {
		t.Fatalf("a reload changed the approvals of a loaded plugin: %+v", st)
	}
	if got := audit.of(p.Spec.ID); len(got) != reported {
		t.Fatalf("a reload reported permissions of a manifest that is not loaded: %+v", got)
	}
	if !keyOpens(m, key, "POST", epAdd) || keyOpens(m, key, "POST", epRemove) {
		t.Fatal("the key of the running plugin must be what was approved for the loaded manifest")
	}
	//What the Plugin Manager shows can be approved and withdrawn
	if err := m.SetPluginPermissionApproval(p.Spec.ID, false, []PermissionKey{{Method: "POST", Endpoint: epAdd}}); err != nil {
		t.Fatalf("withdrawing an endpoint that is shown: %v", err)
	}
	if keyOpens(m, key, "POST", epAdd) {
		t.Fatal("the withdrawal did not reach the running plugin")
	}
}

// A plugin folder that could not be loaded when the baseline was taken (for
// example the introspect timed out) was installed before permissions were
// tracked too: it gets its baseline on its first successful load.
func TestPermissionBaselineCoversPluginsThatFailedToLoadThen(t *testing.T) {
	m := newFaultManager(t)
	audit := trapAudit(m)
	late := installChaos(t, m.Options.PluginDir, "late", "mode=introspect_garbage\n")
	gone := installChaos(t, m.Options.PluginDir, "gone", "mode=introspect_garbage\n")
	if err := m.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetPluginByID("test.chaos.late"); err == nil {
		t.Fatal("the fixture must fail to load at the first boot")
	}

	//The same Zoraxy, later: "late" loads now; "gone" was removed and something else is installed under that folder name
	conf := "mode=ok\nfeatures=hooks\napi_endpoints=GET " + epList + "\n"
	if err := os.WriteFile(filepath.Join(late, "chaos.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}
	m.ReloadPluginFromDisk()
	installChaos(t, m.Options.PluginDir, "gone", conf)
	installChaos(t, m.Options.PluginDir, "newcomer", conf)
	m.ReloadPluginFromDisk()

	if st := m.permissionStateOf(mustPlugin(t, m, "test.chaos.late")); st.Pending != 0 || st.Origin != permOriginBaseline {
		t.Fatalf("a plugin that failed to load when the baseline was taken must get its baseline at its first load: %+v", st)
	}
	if got := audit.of("test.chaos.late"); len(got) != 0 {
		t.Fatalf("the late baseline must not be reported as new permissions: %+v", got)
	}
	for _, id := range []string{"test.chaos.gone", "test.chaos.newcomer"} {
		if st := m.permissionStateOf(mustPlugin(t, m, id)); st.Pending != 1 || len(audit.of(id)) != 1 {
			t.Fatalf("%s is a new plugin and must wait for a review: %+v", id, st)
		}
	}

	//Only once: after an uninstall by hand and a new install the folder is new
	next := newFaultManager(t)
	next.Options.PluginDir = m.Options.PluginDir
	next.Options.Database = m.Options.Database
	next.perm.mu.Lock()
	left := len(next.deferredLocked())
	next.perm.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d folder(s) still wait for a baseline", left)
	}
}

// A plugin that fails to load at a later boot is not baselined: the baseline was taken
func TestPermissionBaselineIsNotExtendedByLaterLoadFailures(t *testing.T) {
	m := newFaultManager(t)
	if err := os.MkdirAll(m.Options.PluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadPluginsFromDisk(); err != nil { //first boot: no plugins, baseline taken
		t.Fatal(err)
	}
	dir := installChaos(t, m.Options.PluginDir, "broken", "mode=introspect_garbage\n")
	next := newFaultManager(t)
	next.Options.PluginDir = m.Options.PluginDir
	next.Options.Database = m.Options.Database
	if err := next.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chaos.conf"), []byte("mode=ok\nfeatures=hooks\napi_endpoints=GET "+epList+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	next.ReloadPluginFromDisk()
	if st := next.permissionStateOf(mustPlugin(t, next, "test.chaos.broken")); st.Pending != 1 {
		t.Fatalf("a plugin installed after the baseline is new, also when its first load failed: %+v", st)
	}
}

// Two changes of the settings at the same time must both hold
func TestSettingsConcurrentChangesDoNotUndoEachOther(t *testing.T) {
	m := newFaultManager(t)
	for i := 0; i < 200; i++ {
		if err := m.SetSettings(func(s *ManagerSettings) { s.ContractMode = ContractModeWarn; s.RequirePermissionApproval = false }); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			m.SetSettings(func(s *ManagerSettings) { s.RequirePermissionApproval = true })
		}()
		go func() {
			defer wg.Done()
			m.SetSettings(func(s *ManagerSettings) { s.ContractMode = ContractModeRefuse })
		}()
		wg.Wait()
		var stored ManagerSettings
		m.Options.Database.Read(settingsDBTable, settingsDBKey, &stored)
		if s := m.Settings(); !s.RequirePermissionApproval || s.ContractMode != ContractModeRefuse || stored != s {
			t.Fatalf("round %d: a change was lost: in memory %+v, stored %+v", i, s, stored)
		}
	}
}
