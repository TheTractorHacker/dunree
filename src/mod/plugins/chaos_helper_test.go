package plugins

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/auth"
	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/dpcore"
	"github.com/TheTractorHacker/dunree/mod/eventsystem"
	"github.com/TheTractorHacker/dunree/mod/info/logger"
	zp "github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
)

/*
	Helpers for the fault-injection suite (fault_bugs_test.go, fault_test.go).

	The suite starts the real chaos plugin binary (testdata/chaosplugin) through the
	real StartPlugin / StopPlugin code. This file only uses the long-standing API of
	the package, so fault_bugs_test.go can also be compiled against the code from
	before the phase 0 fixes to show that its tests fail there.
*/

var chaosBuild struct {
	once sync.Once
	dir  string
	bin  string
	err  error
}

func TestMain(m *testing.M) {
	//Like the real start-up: the event system exists before any plugin is started
	if lg, err := logger.NewFmtLogger(); err == nil {
		eventsystem.InitEventSystem(lg)
	}
	sweepStaleChaosBuilds()
	code := m.Run()
	if chaosBuild.dir != "" {
		os.RemoveAll(chaosBuild.dir)
	}
	os.Exit(code)
}

// chaosBuildRoot is where the chaos plugin is built: GOTMPDIR when set (the
// shared build machine points it at a cache folder), else the system temp folder.
func chaosBuildRoot() string {
	if d := os.Getenv("GOTMPDIR"); d != "" {
		return d
	}
	return os.TempDir()
}

// sweepStaleChaosBuilds removes build folders left by an earlier run that could
// not clean up (a panic or a test timeout ends the process without returning to
// TestMain). Only folders older than 30 minutes are removed, so a run of this
// package in another checkout at the same time is not disturbed.
func sweepStaleChaosBuilds() {
	old, _ := filepath.Glob(filepath.Join(chaosBuildRoot(), "dunree-chaos-*"))
	earlier, _ := filepath.Glob(filepath.Join(chaosBuildRoot(), "zoraxy-chaos-*")) // folders of runs before the rename
	old = append(old, earlier...)
	for _, dir := range old {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() && time.Since(fi.ModTime()) > 30*time.Minute {
			os.RemoveAll(dir)
		}
	}
}

// chaosBinary builds the chaos plugin once per test run and returns the path of the binary
func chaosBinary(t testing.TB) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fault-injection suite runs on Unix only")
	}
	chaosBuild.once.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			chaosBuild.err = errors.New("go toolchain not found: " + err.Error())
			return
		}
		dir, err := os.MkdirTemp(chaosBuildRoot(), "dunree-chaos-")
		if err != nil {
			chaosBuild.err = err
			return
		}
		chaosBuild.dir = dir
		bin := filepath.Join(dir, "chaos")
		cmd := exec.Command(goBin, "build", "-o", bin, "./testdata/chaosplugin")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-p=2")
		if out, err := cmd.CombinedOutput(); err != nil {
			chaosBuild.err = errors.New("building the chaos plugin failed: " + err.Error() + "\n" + string(out))
			return
		}
		chaosBuild.bin = bin
	})
	if chaosBuild.err != nil {
		t.Fatal(chaosBuild.err)
	}
	return chaosBuild.bin
}

// installChaos copies the chaos plugin into pluginDir/<folder>/<folder> with the given chaos.conf
func installChaos(t testing.TB, pluginDir string, folder string, conf string) string {
	t.Helper()
	src, err := os.ReadFile(chaosBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pluginDir, folder)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, folder), src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chaos.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// memBackend is an in-memory database backend
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (b *memBackend) NewTable(string) error                { return nil }
func (b *memBackend) TableExists(string) bool              { return true }
func (b *memBackend) DropTable(string) error               { return nil }
func (b *memBackend) Close()                               {}
func (b *memBackend) ListTable(string) ([][][]byte, error) { return nil, nil }
func (b *memBackend) Write(table string, key string, value interface{}) error {
	js, err := json.Marshal(value)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.data == nil {
		b.data = map[string][]byte{}
	}
	b.data[table+"/"+key] = js
	return nil
}
func (b *memBackend) Read(table string, key string, assignee interface{}) error {
	b.mu.Lock()
	js, ok := b.data[table+"/"+key]
	b.mu.Unlock()
	if !ok {
		return errors.New("key not found")
	}
	return json.Unmarshal(js, assignee)
}
func (b *memBackend) KeyExists(table string, key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[table+"/"+key]
	return ok
}
func (b *memBackend) Delete(table string, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, table+"/"+key)
	return nil
}

// newFaultManager returns a manager wired like the real one, with an empty plugin directory
func newFaultManager(t testing.TB) *Manager {
	t.Helper()
	lg, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{
		LoadedPlugins: map[string]*Plugin{},
		tagPluginList: map[string][]*Plugin{},
		PluginHash:    map[string]string{},
		Options: &ManagerOptions{
			PluginDir:     filepath.Join(t.TempDir(), "plugins"),
			PluginGroups:  map[string][]string{},
			SystemConst:   &zp.RuntimeConstantValue{DunreeVersion: "test"},
			Logger:        lg,
			Database:      &database.Database{Backend: &memBackend{}},
			APIKeyManager: auth.NewAPIKeyManager(),
			CSRFTokenGen:  func(*http.Request) string { return "test-csrf" },
		},
	}
}

// loadChaos installs a chaos plugin, introspects it with the real loader and registers it (not started).
// tags attach it to plugin groups. The plugin is stopped when the test ends.
func loadChaos(t testing.TB, m *Manager, folder string, conf string, tags ...string) *Plugin {
	t.Helper()
	dir := installChaos(t, m.Options.PluginDir, folder, conf)
	p, err := m.LoadPluginSpec(dir)
	if err != nil {
		t.Fatalf("introspect of chaos plugin %s failed: %v", folder, err)
	}
	m.reviewPermissions(p.Spec, filepath.Base(dir)) //as the loaders do for a manifest that becomes the loaded one
	p.RootDir = filepath.ToSlash(dir)
	p.staticRouteProxy = make(map[string]*dpcore.ReverseProxy)
	m.loadedPluginsMutex.Lock()
	m.LoadedPlugins[p.Spec.ID] = p
	m.loadedPluginsMutex.Unlock()
	for _, tag := range tags {
		m.Options.PluginGroups[tag] = append(m.Options.PluginGroups[tag], p.Spec.ID)
	}
	m.UpdateTagsToPluginMaps()
	id := p.Spec.ID
	t.Cleanup(func() {
		defer func() { recover() }() //the code from before phase 0 can panic here, see TestBugStopNeverStartedPluginDoesNotPanic
		if m.PluginIsRunning(id) {
			m.StopPlugin(id)
		}
	})
	return p
}

// listedPlugin is the part of the /api/plugins/list answer the suite looks at
type listedPlugin struct {
	Enabled bool
	Spec    struct {
		ID string `json:"id"`
	}
	Status PluginStatusForTest
}

// PluginStatusForTest mirrors the Status object of the API (absent before phase 0)
type PluginStatusForTest struct {
	State        string
	Health       string
	PID          int
	StartedAt    int64
	ExitedAt     int64
	LastSeen     int64
	HasExited    bool
	ExitCode     int
	ExitReason   string
	LastError    string
	StartCount   int
	RestartCount int
}

// listed asks the real list API handler for one plugin. Test goroutine only
// (it calls t.Fatalf); worker goroutines use listedErr.
func listed(t testing.TB, m *Manager, id string) listedPlugin {
	t.Helper()
	p, err := listedErr(m, id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// listedErr is listed for goroutines that are not the test goroutine
func listedErr(m *Manager, id string) (listedPlugin, error) {
	rec := httptest.NewRecorder()
	m.HandleListPlugins(rec, httptest.NewRequest(http.MethodGet, "/api/plugins/list", nil))
	body, _ := io.ReadAll(rec.Body)
	var all []listedPlugin
	if err := json.Unmarshal(body, &all); err != nil {
		return listedPlugin{}, errors.New("list API did not return JSON: " + err.Error() + "\n" + string(body))
	}
	for _, p := range all {
		if p.Spec.ID == id {
			return p, nil
		}
	}
	return listedPlugin{}, errors.New("plugin " + id + " is not in the list API answer")
}

// eventually polls cond until it is true or the timeout passes
func eventually(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out after %s waiting for: %s", timeout, what)
	}
}

// pidAlive reports whether a process with this PID exists (and is not a zombie)
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	stat, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	//Field 3, after the ")" that ends the command name, is the state: Z = zombie
	rest := string(stat)
	if i := strings.LastIndexByte(rest, ')'); i >= 0 && i+2 < len(rest) {
		return rest[i+2] != 'Z'
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
