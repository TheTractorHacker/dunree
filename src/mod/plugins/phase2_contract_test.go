package plugins

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	zp "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/plugins/dunree_plugin/events"
)

/*
	Phase 2 of docs/plugins/reliability-plan.md: plugin contract version (2.1),
	SDK compatibility (2.2) and secrets off the command line with the real SDK (2.3).

	Defaults under test: a plugin without api_version is a legacy plugin and gets
	byte for byte the configure payload it always got; a plugin built for a newer
	contract is started anyway; refusing it is opt-in.
*/

/* 2.1 Contract */

// The manifests of every example plugin (built with SDK 1.0.0) and of the three
// plugins installed on the owner's proxies, as their binaries print them, must
// load without loss: every field comes back with the same value, nothing is
// added, and all of them are legacy plugins.
func TestContractGoldenManifestsParseUnchanged(t *testing.T) {
	count := map[string]int{}
	for _, group := range []string{"examples", "installed"} {
		files, err := filepath.Glob(filepath.Join("testdata", "manifests", group, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			count[group]++
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var golden map[string]any
			if err := json.Unmarshal(raw, &golden); err != nil {
				t.Fatalf("%s is not JSON: %v", file, err)
			}
			spec := &zp.IntroSpect{}
			if err := json.Unmarshal(raw, spec); err != nil {
				t.Fatalf("%s does not parse as a manifest: %v", file, err)
			}
			if err := validatePluginSpec(spec); err != nil {
				t.Fatalf("%s is refused: %v", file, err)
			}
			warns := append(sanitizeHookSpec(spec), sanitizeSupervisionSpec(spec)...)
			warns = append(warns, sanitizeContractSpec(spec)...)
			if len(warns) != 0 {
				t.Fatalf("%s: loading it changes the manifest: %v", file, warns)
			}
			if spec.APIVersion != 0 || contractStateOf(spec) != ContractLegacy {
				t.Fatalf("%s must be a legacy plugin, got api_version %d", file, spec.APIVersion)
			}
			if pc := contractOf(spec, ContractModeRefuse); pc.Note != "" || pc.Refused {
				t.Fatalf("%s: a legacy plugin must never be warned about or refused: %+v", file, pc)
			}
			again, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			var back map[string]any
			json.Unmarshal(again, &back)
			if !reflect.DeepEqual(golden, back) {
				t.Fatalf("%s does not survive a load unchanged:\n was %v\n now %v", file, golden, back)
			}
			if _, has := back["api_version"]; has {
				t.Fatalf("%s: api_version must not appear for a legacy plugin", file)
			}
		}
	}
	if count["examples"] < 11 || count["installed"] != 3 {
		t.Fatalf("golden manifests are missing: %v", count)
	}
}

func TestContractStatesAndSanitize(t *testing.T) {
	cases := []struct {
		version int
		state   string
	}{{0, ContractLegacy}, {1, ContractOK}, {ContractVersionMax, ContractOK}, {ContractVersionMax + 1, ContractUnsupported}, {99, ContractUnsupported}}
	for _, c := range cases {
		spec := &zp.IntroSpect{APIVersion: c.version}
		if got := contractStateOf(spec); got != c.state {
			t.Fatalf("api_version %d: state %q, want %q", c.version, got, c.state)
		}
	}
	warn := contractOf(&zp.IntroSpect{APIVersion: 99}, ContractModeWarn)
	if warn.Refused || !strings.Contains(warn.Note, "version 99") || !strings.Contains(warn.Note, "started anyway") {
		t.Fatalf("warn mode: %+v", warn)
	}
	refuse := contractOf(&zp.IntroSpect{APIVersion: 99}, ContractModeRefuse)
	if !refuse.Refused || !strings.Contains(refuse.Note, "does not start it") {
		t.Fatalf("refuse mode: %+v", refuse)
	}
	if ok := contractOf(&zp.IntroSpect{APIVersion: 1}, ContractModeRefuse); ok.Note != "" || ok.Refused || ok.SupportedMax != ContractVersionMax {
		t.Fatalf("a supported version needs no note: %+v", ok)
	}
	for _, bad := range []int{-1, 1000001} {
		spec := &zp.IntroSpect{APIVersion: bad}
		if warns := sanitizeContractSpec(spec); len(warns) != 1 || spec.APIVersion != 0 {
			t.Fatalf("api_version %d must be dropped with a warning: %d %v", bad, spec.APIVersion, warns)
		}
	}
	if ContractVersionMin != 0 || ContractVersionMax != zp.APIVersion {
		t.Fatalf("Dunree must support legacy plugins and the contract of its own SDK: %d to %d, SDK %d", ContractVersionMin, ContractVersionMax, zp.APIVersion)
	}
}

// What the SDK offers a plugin to look at the range Dunree sent
func TestSDKContractHelpers(t *testing.T) {
	var none zp.ConfigureSpec //an older Dunree sends no range
	if none.ContractKnown() || !none.ContractSupported() || !none.SupportsAPIVersion(0) || none.SupportsAPIVersion(1) {
		t.Fatal("without a range only the legacy contract is certain, and the plugin must not complain")
	}
	in := zp.ConfigureSpec{APIVersionMin: 0, APIVersionMax: zp.APIVersion}
	if !in.ContractKnown() || !in.ContractSupported() || !in.SupportsAPIVersion(zp.APIVersion) || in.SupportsAPIVersion(zp.APIVersion+1) {
		t.Fatalf("range 0 to %d: %+v", zp.APIVersion, in)
	}
	future := zp.ConfigureSpec{APIVersionMin: zp.APIVersion + 1, APIVersionMax: zp.APIVersion + 3}
	if future.ContractSupported() {
		t.Fatal("a Dunree that dropped this contract version must be noticed")
	}
	//The health handler of the SDK
	h := zp.HealthHandler(nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HealthHandler(nil) answered %d", rec.Code)
	}
	sick := zp.HealthHandler(func() error { return os.ErrDeadlineExceeded })
	rec = httptest.NewRecorder()
	sick.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "deadline") {
		t.Fatalf("an unhealthy plugin must answer 503 without the error text: %d %q", rec.Code, rec.Body.String())
	}
}

// Default: a plugin built for a newer contract is started and the status says so.
// Opt-in: such a plugin is not started. Legacy and supported plugins are never affected.
func TestFaultContractMismatchWarnsByDefaultAndRefusesOnOptIn(t *testing.T) {
	m := newFaultManager(t)
	if s := m.Settings(); s.ContractMode != ContractModeWarn || s.RequirePermissionApproval {
		t.Fatalf("the default settings must change nothing: %+v", s)
	}
	future := loadChaosStopped(t, m, "future", "mode=ok\napi_version=99\n", "t")
	legacy := loadChaosStopped(t, m, "oldtimer", "mode=ok\n", "t")
	current := loadChaosStopped(t, m, "modern", "mode=ok\napi_version=1\n", "t")

	if c := future.Status().Contract; c.State != ContractUnsupported || c.APIVersion != 99 || c.Refused || c.Note == "" {
		t.Fatalf("status of a plugin of a newer contract: %+v", c)
	}
	if c := legacy.Status().Contract; c.State != ContractLegacy || c.Note != "" {
		t.Fatalf("status of a legacy plugin: %+v", c)
	}
	if c := current.Status().Contract; c.State != ContractOK || c.APIVersion != 1 || c.Note != "" {
		t.Fatalf("status of a plugin of the current contract: %+v", c)
	}

	//Default: warn only
	mustStart(t, m, future)
	waitHealth(t, future, HealthOK)
	if res, _, _ := runPreAuth(m); res.Handled {
		t.Fatal("the plugin of a newer contract must work as far as it can")
	}
	if err := m.StopPlugin(future.Spec.ID); err != nil {
		t.Fatal(err)
	}

	//Opt-in: refuse, through the admin API
	if body := postForm(m.HandlePluginSettings, url.Values{"contract_mode": {"sometimes"}}); !strings.Contains(body, "error") {
		t.Fatalf("an unknown contract mode was accepted: %s", body)
	}
	if body := postForm(m.HandlePluginSettings, url.Values{"contract_mode": {ContractModeRefuse}}); strings.Contains(body, "error") {
		t.Fatalf("setting the contract mode failed: %s", body)
	}
	var view struct {
		ContractMode       string
		ContractVersionMax int
		SDKVersion         string
	}
	getJSON(t, m.HandlePluginSettings, "", &view)
	if view.ContractMode != ContractModeRefuse || view.ContractVersionMax != ContractVersionMax || view.SDKVersion != zp.SDKVersion {
		t.Fatalf("settings API: %+v", view)
	}
	err := m.StartPlugin(future.Spec.ID)
	if err == nil || !strings.Contains(err.Error(), "contract version 99") {
		t.Fatalf("with contract mode refuse the plugin must not start, got %v", err)
	}
	if st := future.Status(); st.State != StateFailedToStart || !st.Contract.Refused || !strings.Contains(st.LastError, "contract version") {
		t.Fatalf("status of the refused plugin: %+v", st)
	}
	if m.PluginIsRunning(future.Spec.ID) {
		t.Fatal("the refused plugin is running")
	}
	for _, p := range []*Plugin{legacy, current} {
		mustStart(t, m, p)
		waitHealth(t, p, HealthOK)
	}

	//The setting is stored: the next Dunree start still refuses
	next := newFaultManager(t)
	next.Options.Database = m.Options.Database
	if next.Settings().ContractMode != ContractModeRefuse {
		t.Fatal("the contract mode was not stored")
	}
}

// A refused plugin that is enabled must not be retried by the restart policy at boot
func TestFaultRefusedPluginIsNotRetriedAtBoot(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	installChaos(t, m.Options.PluginDir, "future", "mode=ok\napi_version=99\n")
	m.Options.Database.Write(policyDBTable, "test.chaos.future", PluginPolicy{Restart: RestartAlways})
	if err := m.SetSettings(func(s *ManagerSettings) { s.ContractMode = ContractModeRefuse }); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	p, err := m.GetPluginByID("test.chaos.future")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) //several backoff delays of this test
	if st := p.Status(); st.State != StateFailedToStart || st.StartCount != 0 || st.NextRestartAt != 0 {
		t.Fatalf("a refused plugin must stay refused, without restart attempts: %+v", st)
	}
}

// The supported range is only sent to plugins that declare a contract version:
// a legacy plugin gets exactly the keys it always got.
func TestFaultContractRangeOnlyForPluginsThatDeclareAVersion(t *testing.T) {
	m := newFaultManager(t)
	legacy := startChaos(t, m, "oldtimer", "mode=ok\nfeatures=hooks,api\n", "t")
	current := startChaos(t, m, "modern", "mode=ok\nfeatures=hooks,api\napi_version=1\n", "t")
	waitHealth(t, legacy, HealthOK)
	waitHealth(t, current, HealthOK)

	old := startedWith(t, legacy.RootDir)
	keys := make([]string, 0, len(old))
	for k := range old {
		keys = append(keys, k)
	}
	want := map[string]bool{"port": true, "runtime_const": true, "api_key": true, "zoraxy_port": true, "invoke_token": true}
	for _, k := range keys {
		if !want[k] {
			t.Fatalf("a legacy plugin got a configure field it never got before: %q (all: %v)", k, keys)
		}
	}
	if cl := procCmdline(t, legacy); strings.Contains(cl, "api_version") {
		t.Fatalf("command line of a legacy plugin: %q", cl)
	}
	now := startedWith(t, current.RootDir)
	if string(now["api_version_max"]) != "1" {
		t.Fatalf("a plugin that declares api_version 1 must be told the supported range, got %v", now)
	}
	if _, has := now["api_version_min"]; has {
		t.Log("api_version_min is sent")
	}
}

/* 2.2 SDK compatibility */

// sdkSuite runs the SDK fixture plugin, built against one version of the SDK,
// through the cases of the fault suite that a well-behaved plugin has to pass
// against this Dunree: load, start, filter, capture, UI, events, API key, crash,
// automatic restart, stop.
func sdkSuite(t *testing.T, version string) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadSDKPlugin(t, m, version, "fixture", "t")
	id := p.Spec.ID

	//Manifest
	wantState, wantVersion := ContractOK, zp.APIVersion
	if version == sdkOld {
		wantState, wantVersion = ContractLegacy, 0
	}
	if c := p.Status().Contract; c.State != wantState || c.APIVersion != wantVersion {
		t.Fatalf("contract of a plugin built with SDK %s: %+v", version, c)
	}
	if p.Spec.Hooks == nil || !p.Spec.Hooks.HasStage(zp.HookStagePreAuth) || len(p.Spec.StaticCapturePaths) != 1 || len(p.Spec.PermittedAPIEndpoints) != 1 || p.Spec.SubscriptionPath != "/events" {
		t.Fatalf("manifest of the SDK fixture was not understood: %+v", p.Spec)
	}

	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)

	//Configure: the old way for the old SDK, standard input and the range for the new one
	conf := startedWith(t, p.RootDir)
	apiKey, token := jsonString(conf["api_key"]), jsonString(conf["invoke_token"])
	if apiKey == "" || token == "" || token != p.invokeToken() {
		t.Fatalf("the plugin did not get its API key and the invoke token of this start: %v", conf)
	}
	cl := procCmdline(t, p)
	if version == sdkOld {
		if !strings.Contains(cl, "-configure=") || !strings.Contains(cl, apiKey) || strings.Contains(cl, "api_version") {
			t.Fatalf("a plugin built with SDK %s must be configured exactly as before: %q", version, cl)
		}
		if _, has := conf["api_version_max"]; has {
			t.Fatalf("a legacy plugin got the contract range: %v", conf)
		}
	} else {
		if string(conf["api_version_max"]) != "1" {
			t.Fatalf("a plugin built with the current SDK must get the contract range: %v", conf)
		}
	}
	if _, err := m.Options.APIKeyManager.ValidateAPIKeyForEndpoint("/plugin/api/access/list", http.MethodGet, apiKey); err != nil {
		t.Fatalf("the API key does not open the endpoint of the manifest: %v", err)
	}

	//Filter: a modify verdict and a deny verdict through the real pipeline
	filter := func(deny bool) (StageResult, *http.Request) {
		r := newReq(http.MethodGet, "http://app.example/", "")
		if deny {
			r.Header.Set("X-Sdk-Deny", "1")
		}
		return m.HandleStage(httptest.NewRecorder(), r, []string{"t"}, "198.51.100.9", zp.HookStagePreAuth), r
	}
	if res, r := filter(false); res.Handled || r.Header.Get("X-Sdk-Fixture") != "seen" {
		t.Fatalf("modify verdict: %+v, header %q", res, r.Header.Get("X-Sdk-Fixture"))
	}
	if res, _ := filter(true); !res.Denied || res.Status != http.StatusForbidden {
		t.Fatalf("deny verdict: %+v", res)
	}

	//Static capture
	capture := func() (bool, string) {
		rec := httptest.NewRecorder()
		r := newReq(http.MethodGet, "http://app.example/sdk-static/x", "")
		r.RequestURI = "/sdk-static/x"
		handled := m.HandleRoute(rec, r, []string{"t"}, "198.51.100.9")
		return handled, rec.Body.String()
	}
	if handled, body := capture(); !handled || !strings.Contains(body, "captured by the sdk fixture") {
		t.Fatalf("static capture: handled=%v body=%q", handled, body)
	}

	//UI through the proxy of the admin interface
	if rec, _ := uiOnce(m, p); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SDK fixture page") {
		t.Fatalf("plugin UI: %d %q", rec.Code, rec.Body.String())
	}

	//Events, with the invoke token
	for i := 0; i < 20; i++ {
		if err := p.Notify(events.Event{Name: events.EventName("blacklistedIpBlocked")}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, 5*time.Second, "20 events to be sent", func() bool { return p.obs.eventsSent.Load() == 20 })
	resp, err := http.Get("http://127.0.0.1:" + itoa(p.assignedPort()) + "/ui/stats")
	if err != nil {
		t.Fatal(err)
	}
	var stats struct {
		Events          int `json:"events"`
		EventsWithToken int `json:"events_with_token"`
	}
	json.NewDecoder(resp.Body).Decode(&stats)
	resp.Body.Close()
	if stats.Events != 20 || stats.EventsWithToken != 20 {
		t.Fatalf("the plugin saw %d events, %d with the invoke token", stats.Events, stats.EventsWithToken)
	}
	if c := p.Status().Counters; c.CallFailures != 0 || c.CaptureFailures != 0 || c.EventsFailed != 0 || c.EventsDropped != 0 {
		t.Fatalf("a well-behaved plugin must not produce a failure: %+v", c)
	}

	//Crash: noticed, cleaned up, and started again by the restart policy
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	firstPID := p.Status().PID
	killPID(firstPID)
	eventually(t, 5*time.Second, "the automatic restart after the crash", func() bool {
		st := p.Status()
		return st.State == StateRunning && st.PID != firstPID && st.AutoRestartCount == 1
	})
	if _, err := m.Options.APIKeyManager.ValidateAPIKey(apiKey); err == nil {
		t.Fatal("the API key of the crashed process is still valid")
	}
	waitHealth(t, p, HealthOK)
	if res, r := filter(false); res.Handled || r.Header.Get("X-Sdk-Fixture") != "seen" {
		t.Fatalf("the filter does not work after the automatic restart: %+v", res)
	}
	if hist := p.sup.historyCopy(); len(hist) != 1 || hist[0].Kind != StateCrashed {
		t.Fatalf("exit history: %+v", hist)
	}

	//Stop: the terminate request or SIGTERM ends the plugin, no kill is needed
	pid := p.Status().PID
	begin := time.Now()
	if err := m.StopPlugin(id); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(begin); took > 3*time.Second {
		t.Fatalf("the stop took %s: the plugin did not end on the terminate request", took)
	}
	//(the terminate handler of the SDK exits 100 ms after it answered, and Dunree sends SIGTERM right after the answer: either may end it)
	if st := p.Status(); st.State != StateStopped || pidAlive(pid) || !st.HasExited || strings.Contains(st.ExitReason, "killed") {
		t.Fatalf("after the stop: %+v, pid alive %v", st, pidAlive(pid))
	}
	if handled, _ := capture(); handled {
		t.Fatal("the capture path of the stopped plugin is still attached")
	}
}

// A binary built with SDK 1.0.0 (the frozen copy) passes against this Dunree
func TestSDKCompatBinaryBuiltWithOldSDKStillPasses(t *testing.T) { sdkSuite(t, sdkOld) }

// A binary built with SDK 1.1.0 (frozen when 1.2.0 was released) passes as well
func TestSDKCompatBinaryBuiltWithSDK11StillPasses(t *testing.T) { sdkSuite(t, sdk11) }

// The frozen 1.1.0 is 1.1.0: no name that 1.2.0 added
func TestSDKFrozen11IsNotTheCurrentSDK(t *testing.T) {
	dir := filepath.Join("testdata", "sdk-"+sdk11, "zoraxy_plugin")  // legacy-compat: frozen old-SDK fixture keeps the old directory name
	main, err := os.ReadFile(filepath.Join(dir, "zoraxy_plugin.go")) // legacy-compat: frozen old-SDK fixture keeps the old directory name
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), `SDKVersion = "`+sdk11+`"`) {
		t.Fatalf("the frozen SDK %s does not say it is %s: it was overwritten", sdk11, sdk11)
	}
	if _, err := os.Stat(filepath.Join(dir, "api_client.go")); err == nil {
		t.Fatalf("the frozen SDK %s contains api_client.go, which 1.2.0 added", sdk11)
	}
	ev, err := os.ReadFile(filepath.Join(dir, "events", "events.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ev), "proxyRuleAdded") {
		t.Fatalf("the frozen SDK %s knows proxyRuleAdded, which 1.2.0 added", sdk11)
	}
}

// And so does one built with the SDK of this tree
func TestSDKCompatBinaryBuiltWithCurrentSDKPasses(t *testing.T) { sdkSuite(t, sdkCurrent) }

// The frozen copy must stay what it is: the SDK as plugins in the field were built with
func TestSDKFrozenCopyIsNotTheCurrentSDK(t *testing.T) {
	old, err := os.ReadFile(filepath.Join("testdata", "sdk-"+sdkOld, "zoraxy_plugin", "zoraxy_plugin.go")) // legacy-compat: frozen old-SDK fixture keeps the old directory name
	if err != nil {
		t.Fatal(err)
	}
	for _, later := range []string{"SDKVersion", "api_version", "configure_via", "health_path", "HealthHandler"} {
		if strings.Contains(string(old), later) {
			t.Fatalf("the frozen SDK %s contains %q, which was added later: it was overwritten", sdkOld, later)
		}
	}
	now, err := os.ReadFile(filepath.Join("dunree_plugin", "dunree_plugin.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(now), `SDKVersion = "`+zp.SDKVersion+`"`) {
		t.Fatal("SDKVersion constant not found")
	}
	log, err := os.ReadFile(filepath.Join("dunree_plugin", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "## "+zp.SDKVersion+" ") {
		t.Fatalf("CHANGELOG.md has no entry for SDK %s", zp.SDKVersion)
	}
}

/* 2.3 Secrets off the command line, with the real SDK */

// A plugin built with the current SDK that declares ConfigureViaStdin: nothing a
// local user can read in the process list (ps reads /proc/<pid>/cmdline and, for
// "ps e", /proc/<pid>/environ) holds the API key or the invoke token.
func TestFaultSDKPluginSecretsAreNotInTheProcessList(t *testing.T) {
	m := newFaultManager(t)
	p := loadSDKPlugin(t, m, sdkCurrent, "discreet", "t")
	if p.Spec.ConfigureVia != zp.ConfigureViaStdin || p.Spec.HealthPath != "/health" {
		t.Fatalf("the fixture built with the current SDK must declare stdin and a health path: %+v", p.Spec)
	}
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)
	conf := startedWith(t, p.RootDir)
	apiKey, token := jsonString(conf["api_key"]), jsonString(conf["invoke_token"])
	if apiKey == "" || token == "" {
		t.Fatalf("the plugin did not read its configuration from standard input: %v", conf)
	}
	cl := procCmdline(t, p)
	if !strings.Contains(cl, zp.ConfigureStdinFlag) {
		t.Fatalf("the plugin was not started with %s: %q", zp.ConfigureStdinFlag, cl)
	}
	environ, _ := os.ReadFile("/proc/" + itoa(p.Status().PID) + "/environ")
	for name, where := range map[string]string{"command line": cl, "environment": string(environ)} {
		for _, secret := range []string{apiKey, token, "api_key", "invoke_token", "-configure="} {
			if strings.Contains(where, secret) {
				t.Fatalf("the %s of the plugin process holds %q", name, secret)
			}
		}
	}
	//What the plugin itself saw as arguments
	raw, _ := os.ReadFile(filepath.Join(p.RootDir, "last-args.json"))
	var args []string
	json.Unmarshal(raw, &args)
	if len(args) != 2 || args[1] != zp.ConfigureStdinFlag {
		t.Fatalf("arguments of the plugin: %v", args)
	}
	//The secrets work
	if _, err := m.Options.APIKeyManager.ValidateAPIKey(apiKey); err != nil {
		t.Fatal(err)
	}
	if res, _, _ := runPreAuth(m); res.Handled || p.obs.callFails.Load() != 0 {
		t.Fatal("the filter of the plugin configured over standard input does not answer")
	}
}

// HealthHandler of the SDK with the health check of the supervisor
func TestFaultSDKHealthHandlerIsSeenByTheHealthCheck(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	p := loadSDKPlugin(t, m, sdkCurrent, "patient", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.HealthCheck = HealthCheckReport })
	mustStart(t, m, p)
	eventually(t, 5*time.Second, "a passed health check", func() bool { return p.Status().Counters.HealthChecksOK >= 2 })
	if h := p.Status().Health; h != HealthOK {
		t.Fatalf("health %q", h)
	}
	if err := os.WriteFile(filepath.Join(p.RootDir, "sick"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the health check to fail", func() bool { return p.Status().Health == HealthUnhealthy })
	os.Remove(filepath.Join(p.RootDir, "sick"))
	eventually(t, 5*time.Second, "the health check to pass again", func() bool { return p.Status().Health == HealthOK })
}
