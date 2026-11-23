//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

/*
	The kit against real plugin processes.

	- the three reference plugins of the fork (example/plugins/fork-ref-*) pass
	- the chaos plugin of the fault suite (src/mod/plugins/testdata/chaosplugin)
	  passes in its well-behaved mode and fails in every bad mode, at the check
	  that mode is about

	Everything is built offline from this source tree. The tests start one plugin
	at a time and use the ports of PLUGIN_CHECK_TEST_PORTS (default 20740-20799).
*/

var built struct {
	dir   string
	chaos string
	bad   string
	refs  map[string]string
	err   error
}

var referencePlugins = []string{"fork-ref-filter", "fork-ref-events", "fork-ref-ui-api"}

func goBuild(dir, out string, pkg string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-p=2 -mod=mod", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local")
	if raw, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s in %s: %v\n%s", pkg, dir, err, raw)
	}
	return nil
}

func TestMain(m *testing.M) {
	root := os.Getenv("GOTMPDIR")
	dir, err := os.MkdirTemp(root, "plugin-check-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	built.dir, built.refs = dir, map[string]string{}
	repo, _ := filepath.Abs(filepath.Join("..", ".."))
	built.chaos = filepath.Join(dir, "chaos")
	built.err = goBuild(filepath.Join(repo, "src"), built.chaos, "./mod/plugins/testdata/chaosplugin")
	if built.err == nil {
		built.bad = filepath.Join(dir, "badbind")
		built.err = goBuild(".", built.bad, "./testdata/badbind")
	}
	for _, name := range referencePlugins {
		if built.err != nil {
			break
		}
		built.refs[name] = filepath.Join(dir, "refs", name, name)
		built.err = goBuild(filepath.Join(repo, "example", "plugins", name), built.refs[name], ".")
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func testOptions(t *testing.T, binary string) Options {
	t.Helper()
	if built.err != nil {
		t.Fatal(built.err)
	}
	o := defaultOptions()
	o.Binary = binary
	o.PortMin, o.PortMax = 20740, 20799
	if v := os.Getenv("PLUGIN_CHECK_TEST_PORTS"); v != "" {
		first, last, _ := strings.Cut(v, "-")
		o.PortMin, _ = strconv.Atoi(first)
		o.PortMax, _ = strconv.Atoi(last)
	}
	o.IntrospectTimeout, o.ReadyTimeout, o.MinRun = 2*time.Second, 2*time.Second, 1500*time.Millisecond
	o.Calls, o.LoadCalls, o.Events, o.MemCapMB = 400, 120, 20, 256
	return o
}

// installChaos puts the chaos plugin with a chaos.conf into a folder of its own
func installChaos(t *testing.T, conf string) string {
	t.Helper()
	if built.err != nil {
		t.Fatal(built.err)
	}
	dir := filepath.Join(t.TempDir(), "chaos")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(built.chaos, filepath.Join(dir, "chaos"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chaos.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "chaos")
}

func statusOf(rep *Report, id string) string {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return "missing"
}

func dump(rep *Report) string {
	var b bytes.Buffer
	writeText(&b, rep)
	return b.String()
}

func failed(rep *Report) []string {
	var ids []string
	for _, c := range rep.Checks {
		if c.Status == statusFail {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// Every reference plugin of the fork passes, without a warning, and the checks
// that are about what the plugin does were really run (not skipped).
func TestReferencePluginsPass(t *testing.T) {
	ran := map[string][]string{
		"fork-ref-filter": {"introspect", "manifest", "configure", "secrets", "readiness", "ui", "health", "verdict", "token", "load", "memory", "survive", "term", "sigterm", "cleanup", "logs"},
		"fork-ref-events": {"introspect", "manifest", "configure", "secrets", "readiness", "ui", "health", "events", "token", "memory", "survive", "term", "sigterm", "cleanup", "logs"},
		"fork-ref-ui-api": {"introspect", "manifest", "configure", "secrets", "readiness", "ui", "health", "api", "memory", "survive", "term", "sigterm", "cleanup", "logs"},
	}
	for _, name := range referencePlugins {
		t.Run(name, func(t *testing.T) {
			rep := Run(testOptions(t, built.refs[name]))
			if rep.Result != statusPass || rep.Counts[statusFail] != 0 || rep.Counts[statusWarn] != 0 {
				t.Fatalf("the reference plugin must pass without a warning:\n%s", dump(rep))
			}
			for _, id := range ran[name] {
				if statusOf(rep, id) != statusPass {
					t.Errorf("check %q: %s, want pass\n%s", id, statusOf(rep, id), dump(rep))
				}
			}
			if rep.Plugin == nil || rep.Plugin.APIVersion != 1 || len(rep.SHA256) != 64 || len(rep.Checks) != len(checkOrder) {
				t.Errorf("report head: %+v, %d checks", rep.Plugin, len(rep.Checks))
			}
		})
	}
	//The API check of the page-and-API plugin saw a real call (the read at start), made with the key
	rep := Run(testOptions(t, built.refs["fork-ref-ui-api"]))
	for _, c := range rep.Checks {
		if c.ID == "api" && fmt.Sprint(c.Data["calls"]) == "0" {
			t.Errorf("the stand-in API saw no call of fork-ref-ui-api: %+v", c)
		}
	}
}

// The chaos plugin behaves: it passes. It is a legacy plugin without a token check
// and with its configuration on the command line, which are warnings.
func TestChaosPluginThatBehavesPasses(t *testing.T) {
	rep := runChaos(t, "mode=ok\nfeatures=hooks,static,dynamic,events,health\n", nil)
	if rep.Result != statusPass {
		t.Fatalf("the chaos plugin in mode ok must pass:\n%s", dump(rep))
	}
	for id, want := range map[string]string{"verdict": statusPass, "sniff": statusPass, "events": statusPass, "health": statusPass, "load": statusPass, "memory": statusPass,
		"term": statusPass, "sigterm": statusPass, "logs": statusPass, "token": statusWarn, "secrets": statusWarn, "api": statusSkip} {
		if got := statusOf(rep, id); got != want {
			t.Errorf("check %q: %s, want %s\n%s", id, got, want, dump(rep))
		}
	}
	//A slow start that is inside the limit is not a failure either
	rep = runChaos(t, "mode=slow_start\ndelay=400ms\n", nil)
	if rep.Result != statusPass || statusOf(rep, "readiness") != statusPass {
		t.Fatalf("a plugin that opens its port after 400 ms must pass:\n%s", dump(rep))
	}
}

func runChaos(t *testing.T, conf string, tune func(*Options)) *Report {
	t.Helper()
	o := testOptions(t, installChaos(t, conf))
	o.WithFolder = true
	if tune != nil {
		tune(&o)
	}
	return Run(o)
}

// The chaos plugin in every bad mode fails, at the check that mode is about
func TestChaosPluginFailsInEveryBadMode(t *testing.T) {
	cases := []struct {
		name  string
		conf  string
		fails string //the check that has to fail
		tune  func(*Options)
	}{
		{"crash at start", "mode=crash\n", "configure", nil},
		{"crash after 600 ms", "mode=crash\ndelay=600ms\n", "survive", nil},
		{"exit 0 at start", "mode=exit0\n", "configure", nil},
		{"exit 0 after 600 ms", "mode=exit0\ndelay=600ms\n", "survive", nil},
		{"never opens its port", "mode=hang_start\n", "readiness", nil},
		{"opens its port, accepts nothing", "mode=never_ready\n", "ui", nil},
		{"accepts, never answers", "mode=hang\n", "ui", nil},
		{"slower than its own timeout", "mode=slow\n", "verdict", nil},
		{"slow inside its timeout", "mode=slow\ndelay=60ms\nfeatures=hooks\n", "load", func(o *Options) { o.MaxLatency, o.LoadCalls, o.Calls = 30*time.Millisecond, 40, 60 }},
		{"filter answer is not JSON", "mode=badjson\n", "verdict", nil},
		{"filter answer of 1 MiB", "mode=huge\n", "verdict", nil},
		{"verdict with an invalid header name", "mode=badheader\n", "verdict", nil},
		{"log flood", "mode=logflood\n", "logs", nil},
		{"health path answers 500", "mode=unhealthy\nfeatures=hooks,health\n", "health", nil},
		{"memory balloon", "mode=balloon\n", "memory", nil},
		{"ignores SIGTERM", "mode=ignore_sigterm\n", "sigterm", nil},
		{"introspect prints garbage", "mode=introspect_garbage\n", "introspect", nil},
		{"introspect hangs", "mode=introspect_hang\n", "introspect", nil},
		{"contract version 1 without a token check", "mode=ok\napi_version=1\nfeatures=hooks,events\n", "token", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			begin := time.Now()
			rep := runChaos(t, tc.conf, tc.tune)
			if rep.Result != statusFail {
				t.Fatalf("must fail:\n%s", dump(rep))
			}
			if statusOf(rep, tc.fails) != statusFail {
				t.Fatalf("check %q must fail, failed: %v\n%s", tc.fails, failed(rep), dump(rep))
			}
			if len(rep.Checks) != len(checkOrder) {
				t.Errorf("the report has %d checks, want %d", len(rep.Checks), len(checkOrder))
			}
			if took := time.Since(begin); took > 40*time.Second {
				t.Errorf("the run took %s", took)
			}
		})
	}
}

// A plugin that listens on every address fails the bind check
func TestPluginThatListensOnEveryAddressFails(t *testing.T) {
	other := false
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			other = true
		}
	}
	if !other {
		t.Skip("this machine has no address besides loopback")
	}
	rep := Run(testOptions(t, built.bad))
	if statusOf(rep, "bind") != statusFail || rep.Result != statusFail {
		t.Fatalf("a plugin on 0.0.0.0 must fail the bind check:\n%s", dump(rep))
	}
}

// The stand-in API refuses and records a call without the key and a call to an endpoint outside the manifest
func TestStubAPIRecordsWhatIsNotAllowed(t *testing.T) {
	o := testOptions(t, built.refs["fork-ref-ui-api"])
	k := &kit{o: o, logs: &logCounter{}, usedPorts: map[int]bool{}, rep: &Report{}}
	k.m = &manifest{PermittedAPIEndpoints: []permittedEndpoint{{Method: "GET", Endpoint: "/plugin/api/access/list"}}}
	if err := k.startStub(); err != nil {
		t.Fatal(err)
	}
	defer k.stub.srv.Close()
	k.stub.setKey("the-key")
	get := func(path, key string) int {
		out, err := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Authorization: Bearer "+key, "http://127.0.0.1:"+strconv.Itoa(k.stub.port)+path).Output()
		if err != nil {
			t.Skip("curl is not available: " + err.Error())
		}
		code, _ := strconv.Atoi(string(out))
		return code
	}
	if c := get("/plugin/api/access/list", "the-key"); c != 200 {
		t.Fatalf("declared endpoint with the key: %d", c)
	}
	k.checkAPI()
	if k.rep.Checks[0].Status != statusPass {
		t.Fatalf("one allowed call: %+v", k.rep.Checks[0])
	}
	if c := get("/plugin/api/access/list", "another-key"); c != 401 {
		t.Fatalf("declared endpoint with a wrong key: %d", c)
	}
	if c := get("/plugin/api/proxy/list", "the-key"); c != 403 {
		t.Fatalf("endpoint outside the manifest: %d", c)
	}
	k.rep.Checks = nil
	k.checkAPI()
	c := k.rep.Checks[0]
	if c.Status != statusFail || !strings.Contains(c.Detail, "without the API key") || !strings.Contains(c.Detail, "/plugin/api/proxy/list is not in permitted_api_endpoints") {
		t.Fatalf("calls that are not allowed must fail the check: %+v", c)
	}
}

// The command: exit codes, the JSON report, the text report, the report file
func TestCommandLine(t *testing.T) {
	o := testOptions(t, "")
	fast := []string{"-ports", fmt.Sprintf("%d-%d", o.PortMin, o.PortMax), "-min-run", "1s", "-calls", "200", "-load-calls", "50", "-events", "5"}
	var out, errOut bytes.Buffer
	file := filepath.Join(t.TempDir(), "report.json")
	if code := run(append(append([]string{"-json", "-out", file}, fast...), built.refs["fork-ref-filter"]), &out, &errOut); code != 0 {
		t.Fatalf("exit code %d for a plugin that passes\n%s%s", code, out.String(), errOut.String())
	}
	var rep, fromFile Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, out.String())
	}
	raw, _ := os.ReadFile(file)
	if err := json.Unmarshal(raw, &fromFile); err != nil || fromFile.SHA256 != rep.SHA256 {
		t.Fatalf("the report file: %v", err)
	}
	if rep.Result != statusPass || rep.Tool != "zoraxy-plugin-check" || rep.Plugin.ID != "fork.zoraxy.ref.filter" || len(rep.Checks) != len(checkOrder) || rep.Checks[0].ID != "introspect" || rep.Checks[0].Title == "" {
		t.Fatalf("JSON report: %+v", rep)
	}
	for _, c := range rep.Checks {
		if c.ID == "load" && (c.Data["p95_ms"] == nil || c.Data["calls"] == nil) {
			t.Errorf("the latency check carries no numbers: %+v", c)
		}
	}

	out.Reset()
	if code := run(append(fast, "-with-folder", installChaos(t, "mode=crash\n")), &out, &errOut); code != 1 {
		t.Fatalf("exit code %d for a plugin that fails\n%s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{"FAIL  configure", "result  FAIL", "simulated crash", "SKIP  verdict"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text report lacks %q:\n%s", want, text)
		}
	}
	for _, args := range [][]string{{}, {"/no/such/plugin"}, {"-ports", "1-2", built.chaos}, {"-calls", "0", built.chaos}, {"-nonsense"}} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("exit code %d for %v, want 2", code, args)
		}
	}
}

// The plugin is run in a scratch folder: its own folder is not written to, and the scratch folder is removed
func TestPluginFolderIsNotTouched(t *testing.T) {
	bin := installChaos(t, "mode=ok\nfeatures=hooks,stdinconf\n") //the chaos plugin writes last-configure.json into its working directory
	before, _ := os.ReadDir(filepath.Dir(bin))
	o := testOptions(t, bin)
	o.WithFolder = true
	rep := Run(o)
	if rep.Result != statusPass || statusOf(rep, "secrets") != statusPass {
		t.Fatalf("run:\n%s", dump(rep))
	}
	after, _ := os.ReadDir(filepath.Dir(bin))
	if len(after) != len(before) {
		t.Fatalf("the folder of the plugin changed: %v -> %v", before, after)
	}
	left, _ := filepath.Glob(filepath.Join(os.TempDir(), "plugin-check-*", "chaos", "last-configure.json"))
	if len(left) != 0 {
		t.Fatalf("scratch folders were left behind: %v", left)
	}
}
