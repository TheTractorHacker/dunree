package plugins

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/dpcore"
)

/*
	Helpers for the phase 2 tests (contract, SDK compatibility, permissions).

	The SDK fixture plugin (testdata/sdkplugin) is a plugin written against the
	public API of the dunree_plugin package. It is built twice: against the frozen
	copy of SDK 1.0.0 (testdata/sdk-1.0.0) and against the SDK of this source
	tree. Both builds are offline: the SDK has no dependency outside the standard
	library.
*/

const (
	sdkOld     = "1.0.0"   //the frozen copy: what plugins in the field were built with
	sdk11      = "1.1.0"   //the frozen copy of the release before 1.2.0 (testdata/sdk-1.1.0)
	sdk12      = "1.2.0"   //the last Zoraxy SDK, frozen from the revision before the Dunree rebrand (testdata/sdk-1.2.0): package zoraxy_plugin, zoraxy_* fields, X-Zoraxy-* headers // legacy-compat
	sdkCurrent = "current" //src/mod/plugins/dunree_plugin of this tree
)

var sdkBuild struct {
	mu   sync.Mutex
	bins map[string]string
	errs map[string]error
}

func copyTree(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}

// sdkPluginBinary builds the SDK fixture plugin against one version of the SDK (once per test run)
func sdkPluginBinary(t testing.TB, version string) string {
	t.Helper()
	chaosBinary(t) //creates the build folder that TestMain removes, and skips on Windows
	sdkBuild.mu.Lock()
	defer sdkBuild.mu.Unlock()
	if sdkBuild.bins == nil {
		sdkBuild.bins = map[string]string{}
		sdkBuild.errs = map[string]error{}
	}
	if err := sdkBuild.errs[version]; err != nil {
		t.Fatal(err)
	}
	if bin := sdkBuild.bins[version]; bin != "" {
		return bin
	}
	fail := func(err error) string {
		sdkBuild.errs[version] = err
		t.Fatal(err)
		return ""
	}
	sdkDir, tags := "dunree_plugin", "sdk11"
	if version == sdkOld {
		sdkDir, tags = filepath.Join("testdata", "sdk-"+sdkOld, "zoraxy_plugin"), "" // legacy-compat: frozen old-SDK fixture keeps the old directory name
	} else if version == sdk11 || version == sdk12 {
		sdkDir = filepath.Join("testdata", "sdk-"+version, "zoraxy_plugin") // legacy-compat: frozen old-SDK fixture keeps the old directory name
	}
	work := filepath.Join(chaosBuild.dir, "sdkplugin-"+version)
	if err := copyTree(filepath.Join("testdata", "sdkplugin"), work); err != nil {
		return fail(err)
	}
	if err := copyTree(sdkDir, filepath.Join(work, "mod", "zoraxy_plugin")); err != nil { // legacy-compat: frozen old-SDK fixture keeps the old directory name
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module example.com/zoraxy/sdkplugin\n\ngo 1.21\n"), 0o644); err != nil {
		return fail(err)
	}
	bin := filepath.Join(chaosBuild.dir, "sdkplugin-"+version+".bin")
	cmd := exec.Command("go", "build", "-tags", tags, "-o", bin, ".")
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-p=2 -mod=mod", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fail(errors.New("building the SDK fixture plugin against SDK " + version + " failed: " + err.Error() + "\n" + string(out)))
	}
	sdkBuild.bins[version] = bin
	return bin
}

// registerPluginDir introspects a plugin folder with the real loader and registers it (not started)
func registerPluginDir(t testing.TB, m *Manager, dir string, tags ...string) *Plugin {
	t.Helper()
	p, err := m.LoadPluginSpec(dir)
	if err != nil {
		t.Fatalf("introspect of %s failed: %v", dir, err)
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
		if m.PluginIsRunning(id) {
			m.StopPlugin(id)
		}
	})
	return p
}

// loadSDKPlugin installs the SDK fixture plugin built against the given SDK version and loads it (not started)
func loadSDKPlugin(t testing.TB, m *Manager, version string, folder string, tags ...string) *Plugin {
	t.Helper()
	src, err := os.ReadFile(sdkPluginBinary(t, version))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.Options.PluginDir, folder)
	if err := os.MkdirAll(filepath.Join(dir, "www"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, folder), src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "www", "index.html"), []byte("<!doctype html><title>SDK fixture</title><p>SDK fixture page</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.Options.ProbePluginPorts = true
	return registerPluginDir(t, m, dir, tags...)
}

// startedWith returns the configure payload the plugin in dir recorded at its last start, as raw JSON keys
func startedWith(t testing.TB, dir string) map[string]json.RawMessage {
	t.Helper()
	var conf map[string]json.RawMessage
	eventually(t, 3*time.Second, "the plugin to record its start configuration", func() bool {
		raw, err := os.ReadFile(filepath.Join(dir, "last-configure.json"))
		if err != nil {
			return false
		}
		conf = nil
		return json.Unmarshal(raw, &conf) == nil && len(conf["port"]) > 0
	})
	return conf
}

func jsonString(raw json.RawMessage) string {
	var s string
	json.Unmarshal(raw, &s)
	return s
}

// procCmdline returns the command line of the running process of a plugin, as ps shows it
func procCmdline(t testing.TB, p *Plugin) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(p.Status().PID) + "/cmdline")
	if err != nil {
		t.Skipf("no /proc on this system: %v", err)
	}
	return strings.ReplaceAll(string(raw), "\x00", " ")
}

// auditTrap collects what the plugin manager writes into the security audit log
type auditTrap struct {
	mu      sync.Mutex
	entries []auditEntry
}

type auditEntry struct {
	Event  string
	Target string
	Detail map[string]string
}

func trapAudit(m *Manager) *auditTrap {
	trap := &auditTrap{}
	m.Options.Audit = func(event string, target string, detail map[string]string) {
		trap.mu.Lock()
		trap.entries = append(trap.entries, auditEntry{event, target, detail})
		trap.mu.Unlock()
	}
	return trap
}

func (a *auditTrap) of(target string) []auditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []auditEntry
	for _, e := range a.entries {
		if e.Target == target {
			out = append(out, e)
		}
	}
	return out
}

// postForm calls an admin API handler of the manager with a POST form and returns the body
func postForm(handler http.HandlerFunc, values url.Values) string {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func getJSON(t testing.TB, handler http.HandlerFunc, query string, into any) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/?"+query, nil))
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		t.Fatalf("the API did not answer JSON: %v\n%s", err, rec.Body.String())
	}
}

// rewriteChaosConf replaces the chaos.conf of an installed chaos plugin (the manifest follows it at the next introspect)
func rewriteChaosConf(t testing.TB, p *Plugin, conf string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.RootDir, "chaos.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
}
