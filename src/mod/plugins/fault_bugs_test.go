package plugins

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin/events"
)

/*
	Regression tests for the plain bugs fixed in phase 0 of the plugin reliability plan
	(docs/plugins/reliability-plan.md). Every test here fails on the code from before
	the fixes. They only use API that existed before, so this file (with
	chaos_helper_test.go) can be compiled against the old package to prove that.
*/

// F2: a plugin that exits with code 0 by itself used to stay "running" and enabled for ever.
func TestBugCleanExitIsNoticed(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "exitzero", "mode=exit0\ndelay=200ms\n")
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the cleanly exited plugin to be reported as not running", func() bool {
		return !m.PluginIsRunning(p.Spec.ID)
	})
	eventually(t, 2*time.Second, "the cleanly exited plugin to be listed as not enabled", func() bool {
		return !listed(t, m, p.Spec.ID).Enabled
	})
}

// A plugin that dies during start-up must not be flipped back to "enabled" by StartPlugin.
func TestBugCrashAtStartStaysDisabled(t *testing.T) {
	m := newFaultManager(t)
	for i := 0; i < 5; i++ {
		p := loadChaos(t, m, "crashnow"+itoa(i), "mode=crash\n")
		_ = m.StartPlugin(p.Spec.ID)
		eventually(t, 5*time.Second, "the crashed plugin to be listed as not enabled", func() bool {
			return !listed(t, m, p.Spec.ID).Enabled && !m.PluginIsRunning(p.Spec.ID)
		})
	}
}

// F1: after a crash the UI proxy, the API key and the event subscriptions of the plugin were kept.
func TestBugCrashCleansUp(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "crashlater", "mode=crash\ndelay=400ms\nfeatures=hooks,static,events,api\n")
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}

	//While it runs: the UI is proxied and its API key works
	uiStatus := func() (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/plugin.ui/"+p.Spec.ID+"/", nil)
		req.RequestURI = "/plugin.ui/" + p.Spec.ID + "/"
		m.HandlePluginUI(p.Spec.ID, rec, req)
		return rec.Code, rec.Body.String()
	}
	eventually(t, 3*time.Second, "the plugin UI to be served while the plugin runs", func() bool {
		if !m.PluginIsRunning(p.Spec.ID) {
			return true //crashed already, checked below
		}
		_, body := uiStatus()
		return strings.Contains(body, "Chaos plugin")
	})

	apiKey := ""
	eventually(t, 3*time.Second, "the plugin to record its start configuration", func() bool {
		apiKey = configuredAPIKey(p.RootDir)
		return apiKey != ""
	})
	if _, err := m.Options.APIKeyManager.ValidateAPIKey(apiKey); err != nil && m.PluginIsRunning(p.Spec.ID) {
		t.Fatalf("the API key of the running plugin is not valid: %v", err)
	}

	eventually(t, 5*time.Second, "the crash to be noticed", func() bool { return !listed(t, m, p.Spec.ID).Enabled })

	eventually(t, 2*time.Second, "the UI proxy of the crashed plugin to be removed", func() bool {
		//Phase 1 answers 503 with a small page; before that it was a JSON error with status 200
		code, body := uiStatus()
		return code == http.StatusServiceUnavailable || strings.Contains(body, "Plugin does not have UI handler")
	})

	//The API key Zoraxy gave to the dead process must not stay valid
	if apiKey == "" {
		t.Fatal("the chaos plugin did not record an API key")
	}
	eventually(t, 2*time.Second, "the API key of the crashed plugin to be revoked", func() bool {
		_, err := m.Options.APIKeyManager.ValidateAPIKey(apiKey)
		return err != nil
	})

	//Events are refused for a plugin that is not running
	if err := p.Notify(events.Event{Name: events.EventName("blacklistedIpBlocked")}); err == nil {
		t.Fatal("an event was delivered to a crashed plugin")
	}
}

// configuredAPIKey returns the API key the chaos plugin in dir was started with ("" if none yet)
func configuredAPIKey(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "last-configure.json"))
	if err != nil {
		return ""
	}
	var c struct {
		APIKey string `json:"api_key"`
	}
	json.Unmarshal(raw, &c)
	return c.APIKey
}

// F25: stopping a plugin that never started was a nil-pointer panic.
func TestBugStopNeverStartedPluginDoesNotPanic(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "neverstarted", "mode=ok\n")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StopPlugin on a plugin that never started panicked: %v", r)
		}
	}()
	if err := m.StopPlugin(p.Spec.ID); err == nil {
		t.Fatal("StopPlugin on a plugin that never started must return an error")
	}
	//Whether DisablePlugin reports an error here is checked by TestFaultDisableOfDeadPluginSucceeds
	m.DisablePlugin(p.Spec.ID)
	if m.GetPluginPreviousEnableState(p.Spec.ID) {
		t.Fatal("DisablePlugin must still store enabled=false")
	}
}

// F4: a capture target that cannot be reached used to give the visitor an empty 200 OK.
func TestBugCaptureTargetDownIs502NotEmpty200(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a closed loopback port")
	}
	newDead := func() *Plugin {
		return &Plugin{
			RootDir: t.TempDir(),
			Spec: &zp.IntroSpect{
				ID: "dead", Name: "dead", Type: zp.PluginType_Router,
				StaticCapturePaths:   []zp.StaticCaptureRule{{CapturePath: "/cap"}},
				StaticCaptureIngress: "/static",
				DynamicCaptureSniff:  "/sniff", DynamicCaptureIngress: "/ingress",
			},
			Enabled:          true,
			AssignedPort:     1, //nothing listens there
			staticRouteProxy: make(map[string]*dpcore.ReverseProxy),
		}
	}

	t.Run("static", func(t *testing.T) {
		p := newDead()
		p.StartAllStaticPathRouters()
		rec := httptest.NewRecorder()
		p.HandleStaticRoute(rec, newReq(http.MethodGet, "/cap/x", ""), "/cap")
		if rec.Code != http.StatusBadGateway || rec.Body.Len() == 0 {
			t.Fatalf("want 502 with a body, got %d with %d body bytes", rec.Code, rec.Body.Len())
		}
	})
	t.Run("dynamic", func(t *testing.T) {
		p := newDead()
		if err := p.StartDynamicForwardRouter(); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		p.serveDynamicCapture(rec, newReq(http.MethodGet, "/anything", ""), "req-1")
		if rec.Code != http.StatusBadGateway || rec.Body.Len() == 0 {
			t.Fatalf("want 502 with a body, got %d with %d body bytes", rec.Code, rec.Body.Len())
		}
	})
}

// storeFixture serves the chaos binary as a plugin download
func storeFixture(t *testing.T) *httptest.Server {
	t.Helper()
	bin, err := os.ReadFile(chaosBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bin) }))
	t.Cleanup(srv.Close)
	return srv
}

// F24: a plugin installed from the store but never enabled used to start by itself at the next Zoraxy start.
func TestBugInstalledPluginDoesNotAutostartAtNextBoot(t *testing.T) {
	m := newFaultManager(t)
	if err := os.MkdirAll(m.Options.PluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := storeFixture(t)
	dl := &DownloadablePlugin{
		PluginIntroSpect: zp.IntroSpect{ID: "test.chaos.storeplugin", Name: "storeplugin"},
		DownloadURLs:     map[string]string{runtime.GOOS + "_" + runtime.GOARCH: srv.URL + "/chaos"},
	}
	if err := m.InstallPlugin(dl); err != nil {
		t.Fatal(err)
	}
	p, err := m.GetPluginByID("test.chaos.storeplugin")
	if err != nil {
		t.Fatalf("installed plugin was not loaded: %v", err)
	}
	if m.PluginIsRunning(p.Spec.ID) {
		t.Fatal("a freshly installed plugin must not be running")
	}
	if m.GetPluginPreviousEnableState(p.Spec.ID) {
		t.Fatal("a plugin that was installed but never enabled is marked to start at the next boot")
	}

	//A second manager on the same folder and database is "the next boot"
	m2 := newFaultManager(t)
	m2.Options.PluginDir = m.Options.PluginDir
	m2.Options.Database = m.Options.Database
	if err := m2.LoadPluginsFromDisk(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if m2.PluginIsRunning("test.chaos.storeplugin") {
			m2.StopPlugin("test.chaos.storeplugin")
		}
	})
	if m2.PluginIsRunning("test.chaos.storeplugin") {
		t.Fatal("the never-enabled plugin was started at the next boot")
	}

	//Enabling it is remembered as before
	t.Cleanup(func() {
		defer func() { recover() }()
		if m.PluginIsRunning("test.chaos.storeplugin") {
			m.StopPlugin("test.chaos.storeplugin")
		}
	})
	if err := m.EnablePlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if !m.GetPluginPreviousEnableState(p.Spec.ID) {
		t.Fatal("an enabled plugin must be marked to start at the next boot")
	}
}

// F16: the install folder came straight from the plugin name of the store index.
func TestBugInstallFolderCannotLeavePluginDir(t *testing.T) {
	m := newFaultManager(t)
	//Two levels below the temp root, so an escaping "../../" stays inside the test's own temp folder
	root := t.TempDir()
	m.Options.PluginDir = filepath.Join(root, "a", "plugins")
	if err := os.MkdirAll(m.Options.PluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := storeFixture(t)
	dl := &DownloadablePlugin{
		PluginIntroSpect: zp.IntroSpect{ID: "test.chaos.escape", Name: "../../escaped"},
		DownloadURLs:     map[string]string{runtime.GOOS + "_" + runtime.GOARCH: srv.URL + "/chaos"},
	}
	_ = m.InstallPlugin(dl) //refusing the install is as good as installing it somewhere safe
	if _, err := os.Stat(filepath.Join(root, "escaped")); err == nil {
		t.Fatal("the store install wrote outside the plugin directory")
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.Name() != "a" {
			t.Fatalf("unexpected entry %q outside the plugin directory", e.Name())
		}
	}
	entries, _ = os.ReadDir(filepath.Join(root, "a"))
	for _, e := range entries {
		if e.Name() != "plugins" {
			t.Fatalf("unexpected entry %q next to the plugin directory", e.Name())
		}
	}
}

// F26: Enabled was written by StopPlugin / the exit goroutine while requests read it, and
// StopPlugin polled ProcessState while another goroutine's Wait wrote it. This test only
// fails under the race detector (go test -race).
func TestBugNoDataRaceBetweenRequestsStopAndCrash(t *testing.T) {
	m := newFaultManager(t)
	p := loadChaos(t, m, "raced", "mode=crash\ndelay=300ms\n", "t")
	q := loadChaos(t, m, "raced2", "mode=ok\n", "t")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			m.HandleStage(httptest.NewRecorder(), newReq(http.MethodGet, "http://app.example/", ""), []string{"t"}, "198.51.100.9", zp.HookStagePreAuth)
			if _, err := listedErr(m, p.Spec.ID); err != nil {
				t.Error(err) //not Fatal: this is not the test goroutine
				return
			}
		}
	}()
	//Also on a failed start: end the request goroutine before the plugins are cleaned up
	defer func() {
		close(stop)
		<-done
	}()
	if err := m.StartPlugin(p.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.StartPlugin(q.Spec.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond) //p crashes meanwhile
	if err := m.StopPlugin(q.Spec.ID); err != nil {
		t.Fatal(err)
	}
}
