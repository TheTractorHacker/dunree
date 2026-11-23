//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const toolVersion = "1.1.0"

// Options of one run. The zero value is not usable: see defaultOptions.
type Options struct {
	Binary            string        //the entry point of the plugin (the program Zoraxy starts)
	WithFolder        bool          //copy the whole folder of the plugin, not only the program file
	PortMin, PortMax  int           //ports the kit may use (0 = any free port)
	IntrospectTimeout time.Duration //Zoraxy: 10 s
	ReadyTimeout      time.Duration //Zoraxy (opt-in readiness gate): 10 s
	MinRun            time.Duration //the plugin has to stay up at least this long
	Calls             int           //calls made before the memory is compared
	LoadCalls         int           //calls of the latency check
	Concurrency       int           //parallel calls of the latency check
	Events            int           //events of the burst
	MaxLatency        time.Duration //p95 above this fails the latency check
	WarnLatency       time.Duration //p95 above this is a warning
	MemCapMB          int           //the plugin is ended when it uses more
	MemGrowthMB       int           //growth over the calls that fails the memory check
	NoEgress          bool          //point the proxy variables of the plugin at a dead address
	Env               []string      //extra environment of the plugin: NAME=VALUE, or NAME to pass the kit's own value on
	Keep              bool          //keep the scratch folder
}

func defaultOptions() Options {
	return Options{
		IntrospectTimeout: 10 * time.Second, ReadyTimeout: 10 * time.Second, MinRun: 3 * time.Second,
		Calls: 1000, LoadCalls: 300, Concurrency: 4, Events: 100,
		MaxLatency: 250 * time.Millisecond, WarnLatency: 25 * time.Millisecond,
		MemCapMB: 1024, MemGrowthMB: 64,
	}
}

const (
	statusPass = "pass"
	statusWarn = "warn"
	statusFail = "fail"
	statusSkip = "skip"
)

// Check is one line of the report
type Check struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Status string         `json:"status"`
	Detail string         `json:"detail"`
	Ms     int64          `json:"ms"`
	Data   map[string]any `json:"data,omitempty"`
}

// Report is the result of one run (also the JSON report)
type Report struct {
	Tool        string         `json:"tool"`
	ToolVersion string         `json:"tool_version"`
	Contract    int            `json:"contract_version_checked"`
	Time        string         `json:"time"`
	Binary      string         `json:"binary"`
	SHA256      string         `json:"sha256"`
	Size        int64          `json:"size"`
	Plugin      *PluginInfo    `json:"plugin,omitempty"`
	Result      string         `json:"result"`
	Counts      map[string]int `json:"counts"`
	Checks      []Check        `json:"checks"`
	LogTail     []string       `json:"log_tail,omitempty"`
}

type PluginInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Type       int    `json:"type"`
	APIVersion int    `json:"api_version"`
}

// The checks, in the order of the report
var checkOrder = []struct{ id, title string }{
	{"introspect", "Introspect answers with a manifest"},
	{"introspect_size", "Size of the introspect output"},
	{"manifest", "Fields of the manifest"},
	{"configure", "Starts with the configure payload"},
	{"secrets", "Secrets stay off the command line"},
	{"readiness", "Opens its port"},
	{"bind", "Listens on the loopback address only"},
	{"ui", "Answers on its page path"},
	{"health", "Health path"},
	{"verdict", "Filter answers are valid verdicts"},
	{"sniff", "Dynamic capture sniff answers"},
	{"events", "Acknowledges events"},
	{"token", "Refuses calls without the invoke token"},
	{"load", "Latency under load"},
	{"memory", "Memory after the calls"},
	{"api", "Calls to the Zoraxy API"},
	{"survive", "Stays up"},
	{"term", "Ends on the terminate request"},
	{"sigterm", "Ends within 5 s of SIGTERM"},
	{"cleanup", "Leaves no process behind"},
	{"logs", "Log volume"},
}

type kit struct {
	o         Options
	rep       *Report
	m         *manifest
	workDir   string
	runBin    string
	env       []string
	uuid      string
	logs      *logCounter
	stub      *stubAPI
	procs     []*proc
	p         *proc //the running plugin
	usedPorts map[int]bool
	client    *http.Client
	calls     atomic.Int64
	silent    string     //why calls are no longer made ("" = the plugin answers)
	noPort    bool       //the plugin never opened its port
	notRun    string     //why the remaining checks were not run
	mu        sync.Mutex //procs and aborted: the kit can be interrupted from another goroutine
	aborted   bool
	cleanMu   sync.Mutex
}

// The kits that are running, so an interrupted command can end their plugins
var active = struct {
	sync.Mutex
	kits map[*kit]bool
}{kits: map[*kit]bool{}}

// abortAll ends every plugin a running kit started and removes the scratch
// folders. It is what the command does on SIGINT, SIGTERM and SIGHUP: without it
// the plugin under test, which is in a process group of its own, would stay.
func abortAll() {
	active.Lock()
	kits := make([]*kit, 0, len(active.kits))
	for k := range active.kits {
		kits = append(kits, k)
	}
	active.Unlock()
	for _, k := range kits {
		k.mu.Lock()
		k.aborted = true
		k.mu.Unlock()
		k.cleanup()
	}
}

func (k *kit) procList() []*proc {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]*proc{}, k.procs...)
}

// Run puts one plugin binary through all checks
func Run(o Options) *Report {
	k := &kit{o: o, logs: &logCounter{}, usedPorts: map[int]bool{}, uuid: randomHex(16)}
	k.rep = &Report{Tool: "zoraxy-plugin-check", ToolVersion: toolVersion, Contract: contractMax, Time: time.Now().UTC().Format(time.RFC3339), Binary: o.Binary}
	k.client = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: time.Second}).DialContext,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	active.Lock()
	active.kits[k] = true
	active.Unlock()
	defer func() {
		k.cleanup()
		active.Lock()
		delete(active.kits, k)
		active.Unlock()
	}()
	k.run()
	return k.finish()
}

// cleanup ends everything the kit started: the process groups, every process that
// was seen below a plugin (also outside its group) and whatever still runs from
// the scratch folder. It may be called more than once and from the interrupt.
func (k *kit) cleanup() {
	k.cleanMu.Lock()
	defer k.cleanMu.Unlock()
	procs := k.procList()
	for _, p := range procs {
		p.track()
		if !p.exited() || p.groupAlive() {
			p.signalGroup(syscall.SIGKILL)
		}
	}
	for _, p := range procs {
		p.waitExit(3 * time.Second)
		for _, id := range p.strays() {
			id.kill()
		}
	}
	for _, id := range processesIn(k.workDir) {
		id.kill()
	}
	if k.stub != nil {
		k.stub.srv.Close()
	}
	if k.workDir != "" && !k.o.Keep {
		os.RemoveAll(k.workDir)
	}
}

func (k *kit) add(id, status, detail string, begin time.Time, data map[string]any) {
	k.rep.Checks = append(k.rep.Checks, Check{ID: id, Status: status, Detail: detail, Ms: time.Since(begin).Milliseconds(), Data: data})
}

// finish orders the checks, fills in the ones that were not run and adds up
func (k *kit) finish() *Report {
	why := k.notRun
	if why == "" {
		why = "not run"
	}
	byID := map[string]Check{}
	for _, c := range k.rep.Checks {
		byID[c.ID] = c
	}
	ordered := make([]Check, 0, len(checkOrder))
	k.rep.Counts = map[string]int{statusPass: 0, statusWarn: 0, statusFail: 0, statusSkip: 0}
	for _, co := range checkOrder {
		c, ok := byID[co.id]
		if !ok {
			c = Check{ID: co.id, Status: statusSkip, Detail: "Not run: " + why}
		}
		c.Title = co.title
		ordered = append(ordered, c)
		k.rep.Counts[c.Status]++
	}
	k.rep.Checks = ordered
	k.rep.Result = statusPass
	if k.rep.Counts[statusFail] > 0 {
		k.rep.Result = statusFail
	}
	_, _, _, k.rep.LogTail = k.logs.snapshot()
	return k.rep
}

func (k *kit) run() {
	if !k.prepare() || !k.checkIntrospect() {
		return
	}
	if len(k.m.PermittedAPIEndpoints) > 0 {
		if err := k.startStub(); err != nil {
			k.notRun = "the stand-in for the Zoraxy API could not be started: " + err.Error()
			return
		}
	}
	if k.checkStart() {
		k.checkBind()
		k.checkUI()
		k.checkHealth()
		k.checkVerdict()
		k.checkSniff()
		k.checkEvents()
		k.checkToken()
		baseline, _ := groupRSS(k.p.pid)
		k.checkLoad()
		k.checkMemory(baseline)
		k.checkSurvive()
		k.checkAPI()
		k.checkStop()
	}
	k.checkLogs()
}

// prepare copies the plugin into a scratch folder: the kit never runs a plugin in
// its own folder, so the files a plugin keeps there (settings, logs, databases)
// are neither read nor changed.
func (k *kit) prepare() bool {
	begin := time.Now()
	fail := func(msg string) bool {
		k.add("introspect", statusFail, msg, begin, nil)
		k.notRun = "the plugin could not be prepared"
		return false
	}
	abs, err := filepath.Abs(k.o.Binary)
	if err != nil {
		return fail(err.Error())
	}
	st, err := os.Stat(abs)
	if err != nil || !st.Mode().IsRegular() {
		return fail("The plugin program was not found or is not a file: " + abs)
	}
	k.rep.Binary, k.rep.Size = abs, st.Size()
	f, err := os.Open(abs)
	if err != nil {
		return fail("The plugin program cannot be read: " + err.Error())
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	k.rep.SHA256 = hex.EncodeToString(h.Sum(nil))

	k.workDir, err = os.MkdirTemp("", "plugin-check-")
	if err != nil {
		return fail(err.Error())
	}
	name := filepath.Base(abs)
	folder := filepath.Join(k.workDir, filepath.Base(filepath.Dir(abs)))
	if k.o.WithFolder {
		err = copyTree(filepath.Dir(abs), folder)
	} else {
		if err = os.MkdirAll(folder, 0o755); err == nil {
			err = copyFile(abs, filepath.Join(folder, name), 0o755)
		}
	}
	if err != nil {
		return fail("The plugin could not be copied to a scratch folder: " + err.Error())
	}
	k.runBin = filepath.Join(folder, name)
	os.Chmod(k.runBin, 0o755)

	k.env = k.pluginEnv()
	if k.o.NoEgress {
		for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			k.env = append(k.env, v+"=http://127.0.0.1:9")
		}
		k.env = append(k.env, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
	}
	return true
}

// pluginEnv is the environment of the plugin. It is NOT the environment of the
// kit: the shell of whoever certifies a plugin can hold tokens and cloud
// credentials, and the plugin is a program of somebody else. The plugin gets a
// search path, a home and a temporary folder inside the scratch folder, the
// language and time zone settings, and what Options.Env names.
func (k *kit) pluginEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	home, tmp := filepath.Join(k.workDir, "home"), filepath.Join(k.workDir, "tmp")
	os.MkdirAll(home, 0o700)
	os.MkdirAll(tmp, 0o700)
	env := []string{"PATH=" + path, "HOME=" + home, "TMPDIR=" + tmp}
	for _, name := range []string{"LANG", "LC_ALL", "LC_CTYPE", "TZ"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	for _, e := range k.o.Env {
		if strings.Contains(e, "=") {
			env = append(env, e)
		} else if v, ok := os.LookupEnv(e); ok {
			env = append(env, e+"="+v)
		}
	}
	return env
}

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	total int64
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

const (
	introspectWarnBytes = 64 << 10
	introspectMaxBytes  = 1 << 20
)

func (k *kit) checkIntrospect() bool {
	begin := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), k.o.IntrospectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, k.runBin, "-introspect")
	cmd.Dir = filepath.Dir(k.runBin)
	cmd.Env = k.env
	cmd.SysProcAttr = childAttr()
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	stdout, stderr := &cappedBuffer{limit: introspectMaxBytes + 1}, &cappedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	took := time.Since(begin)
	data := map[string]any{"bytes": stdout.total, "stderr_bytes": stderr.total}
	k.notRun = "the manifest could not be read"
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		k.add("introspect", statusFail, fmt.Sprintf("No manifest within %s: Zoraxy lists the plugin as \"could not be loaded\".", k.o.IntrospectTimeout), begin, data)
		return false
	case err != nil:
		k.add("introspect", statusFail, "The introspect call failed ("+err.Error()+"): Zoraxy lists the plugin as \"could not be loaded\". "+firstLine(stderr.buf.String()), begin, data)
		return false
	}
	if stdout.total > introspectMaxBytes {
		k.add("introspect", statusFail, fmt.Sprintf("The introspect output is %d bytes, more than the %d this kit reads.", stdout.total, introspectMaxBytes), begin, data)
		k.add("introspect_size", statusFail, fmt.Sprintf("%d bytes. A manifest is a few kilobytes.", stdout.total), begin, nil)
		return false
	}
	m, notes, err := decodeManifest(stdout.buf.Bytes())
	if err != nil {
		k.add("introspect", statusFail, "The introspect output is not a manifest in JSON ("+err.Error()+"): Zoraxy lists the plugin as \"could not be loaded\".", begin, data)
		return false
	}
	k.m = m
	k.rep.Plugin = &PluginInfo{ID: m.ID, Name: m.Name, Version: m.version(), Type: m.Type, APIVersion: m.APIVersion}
	status, detail := statusPass, fmt.Sprintf("Manifest in %d ms.", took.Milliseconds())
	if took > 2*time.Second {
		status, detail = statusWarn, fmt.Sprintf("Manifest after %d ms. Zoraxy runs this at every start, one plugin after the other, and gives up after 10 s.", took.Milliseconds())
	}
	if stderr.total > 0 {
		status = statusWarn
		detail += " The plugin also wrote to standard error: " + firstLine(stderr.buf.String())
	}
	k.add("introspect", status, detail, begin, data)

	switch {
	case stdout.total > introspectWarnBytes:
		k.add("introspect_size", statusWarn, fmt.Sprintf("%d bytes: large for a manifest (warning above %d).", stdout.total, introspectWarnBytes), begin, nil)
	default:
		k.add("introspect_size", statusPass, fmt.Sprintf("%d bytes.", stdout.total), begin, nil)
	}

	fails, warns := checkManifest(m)
	warns = append(notes, warns...)
	k.rep.Plugin.APIVersion = m.APIVersion
	contract := "legacy plugin (no api_version)"
	if m.APIVersion > 0 {
		contract = "contract version " + strconv.Itoa(m.APIVersion)
	}
	switch {
	case len(fails) > 0:
		k.add("manifest", statusFail, strings.Join(append(fails, warns...), "; ")+".", begin, nil)
		return false
	case len(warns) > 0:
		k.add("manifest", statusWarn, contract+". "+strings.Join(warns, "; ")+".", begin, nil)
	default:
		k.add("manifest", statusPass, contract+".", begin, nil)
	}
	k.notRun = ""
	return true
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.ToValidUTF8(s, "?")
}

func (k *kit) tailText() string {
	_, _, _, tail := k.logs.snapshot()
	if len(tail) == 0 {
		return "It wrote nothing."
	}
	if len(tail) > 3 {
		tail = tail[len(tail)-3:]
	}
	return "Last output: " + strings.Join(tail, " | ")
}

// checkStart: configure, secrets, readiness
func (k *kit) checkStart() bool {
	begin := time.Now()
	p, err := k.start()
	if err != nil {
		k.add("configure", statusFail, "The plugin could not be started: "+err.Error(), begin, nil)
		k.notRun = "the plugin did not start"
		return false
	}
	k.p = p
	took, ready := p.waitReady(k.o.ReadyTimeout)
	how := "-configure=<json>"
	if k.m.ConfigureVia == "stdin" {
		how = "-configure-stdin"
	}
	if !ready && p.exited() {
		k.add("configure", statusFail, fmt.Sprintf("Started with %s, the plugin ended after %d ms without opening its port (%s). %s", how, took.Milliseconds(), p.exitText(), k.tailText()), begin, nil)
		k.notRun = "the plugin did not start"
		return false
	}
	k.add("configure", statusPass, "Started with "+how+".", begin, nil)

	switch {
	case k.m.ConfigureVia == "stdin":
		k.add("secrets", statusPass, "The start configuration is read from standard input.", begin, nil)
	case len(k.m.PermittedAPIEndpoints) > 0:
		k.add("secrets", statusWarn, "The API key and the invoke token are on the command line, where every local user can read them. Declare configure_via \"stdin\" (SDK 1.1.0).", begin, nil)
	default:
		k.add("secrets", statusWarn, "The invoke token is on the command line, where every local user can read it. Declare configure_via \"stdin\" (SDK 1.1.0).", begin, nil)
	}

	if !ready {
		k.add("readiness", statusFail, fmt.Sprintf("The port %d did not accept a connection within %s.", p.port, k.o.ReadyTimeout), begin, nil)
		k.silent, k.noPort = "the plugin did not open its port", true
		return true //the stop checks still run
	}
	status, detail := statusPass, fmt.Sprintf("Port open after %d ms.", took.Milliseconds())
	if took > 5*time.Second {
		status, detail = statusWarn, fmt.Sprintf("Port open after %d ms: more than half of the 10 s Zoraxy waits.", took.Milliseconds())
	}
	k.add("readiness", status, detail, begin, map[string]any{"ms": took.Milliseconds()})
	return true
}

// gate says why a check that calls the plugin cannot run ("" = it can)
func (k *kit) gate() string {
	if k.p == nil {
		return "the plugin did not start"
	}
	if k.p.exited() {
		return "the plugin process has ended (" + k.p.exitText() + ")"
	}
	return k.silent
}

func (k *kit) skip(id, why string) {
	k.add(id, statusSkip, why, time.Now(), nil)
}

type answer struct {
	status   int
	body     []byte
	tooLarge bool
	took     time.Duration
	err      error
}

func (a answer) timedOut() bool {
	var ne net.Error
	return a.err != nil && (errors.Is(a.err, context.DeadlineExceeded) || (errors.As(a.err, &ne) && ne.Timeout()))
}

// call makes one HTTP call to the plugin
func (k *kit) call(method, path string, body []byte, header map[string]string, timeout time.Duration, limit int64) answer {
	k.calls.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	begin := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:"+strconv.Itoa(k.p.port)+path, bytes.NewReader(body))
	if err != nil {
		return answer{err: err}
	}
	for name, v := range header {
		req.Header.Set(name, v)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return answer{err: err, took: time.Since(begin)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	a := answer{status: resp.StatusCode, body: raw, took: time.Since(begin), err: err}
	if int64(len(raw)) > limit {
		a.tooLarge, a.body = true, nil
		io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20))
	}
	return a
}

func (k *kit) tokenHeader(requestID string) map[string]string {
	h := map[string]string{"Content-Type": "application/json", "X-Zoraxy-Plugin-Token": k.p.token}
	if requestID != "" {
		h["X-Zoraxy-RequestID"] = requestID
	}
	return h
}

func (k *kit) checkBind() {
	begin := time.Now()
	if why := k.gate(); why != "" {
		k.skip("bind", "Not run: "+why+".")
		return
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), strconv.Itoa(k.p.port)), 300*time.Millisecond)
		if err == nil {
			c.Close()
			k.add("bind", statusFail, "The plugin also accepts connections on "+ipn.IP.String()+": it has to listen on 127.0.0.1 only. Its page and its other paths are open to the network without the login of Zoraxy.", begin, nil)
			return
		}
		k.add("bind", statusPass, "Not reachable on "+ipn.IP.String()+".", begin, nil)
		return
	}
	k.skip("bind", "This machine has no other IPv4 address to try.")
}

func (k *kit) checkUI() {
	begin := time.Now()
	if why := k.gate(); why != "" {
		k.skip("ui", "Not run: "+why+".")
		return
	}
	a := k.call(http.MethodGet, normalizeEndpoint(k.m.UIPath)+"/", nil, nil, 2*time.Second, 4<<20)
	switch {
	case a.err != nil:
		k.silent = "the plugin did not answer on its page path"
		k.add("ui", statusFail, "No answer on "+normalizeEndpoint(k.m.UIPath)+"/ within 2 s ("+shortErr(a.err)+").", begin, nil)
	case a.status >= 500:
		k.add("ui", statusWarn, fmt.Sprintf("The page path answers HTTP %d.", a.status), begin, nil)
	default:
		k.add("ui", statusPass, fmt.Sprintf("HTTP %d in %d ms.", a.status, a.took.Milliseconds()), begin, nil)
	}
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	return s
}

func (k *kit) checkHealth() {
	begin := time.Now()
	if k.m.HealthPath == "" {
		k.skip("health", "No health_path declared. The health check of Zoraxy can then only try a TCP connect, which does not see a plugin that accepts connections and no longer answers.")
		return
	}
	if why := k.gate(); why != "" {
		k.skip("health", "Not run: "+why+".")
		return
	}
	a := k.call(http.MethodGet, k.m.HealthPath, nil, map[string]string{"X-Zoraxy-Plugin-Token": k.p.token}, 2*time.Second, 64<<10)
	switch {
	case a.err != nil:
		if a.timedOut() {
			k.silent = "the plugin did not answer its health path"
		}
		k.add("health", statusFail, "No answer on "+k.m.HealthPath+" within 2 s ("+shortErr(a.err)+").", begin, nil)
	case a.status < 200 || a.status > 299:
		k.add("health", statusFail, fmt.Sprintf("%s answers HTTP %d on a plugin that was just started: Zoraxy counts every status outside 200 to 299 as unhealthy.", k.m.HealthPath, a.status), begin, nil)
	default:
		k.add("health", statusPass, fmt.Sprintf("HTTP %d in %d ms.", a.status, a.took.Milliseconds()), begin, nil)
	}
}

func sampleRequest(method, uri string, header map[string][]string) map[string]any {
	if header == nil {
		header = map[string][]string{}
	}
	if _, ok := header["User-Agent"]; !ok {
		header["User-Agent"] = []string{"Mozilla/5.0 (plugin-check)"}
	}
	return map[string]any{
		"method": method, "hostname": "conformance.test", "url": uri, "header": header,
		"remote_addr": "198.51.100.7:40000", "client_ip": "198.51.100.7", "host": "conformance.test",
		"request_uri": uri, "proto": "HTTP/1.1", "proto_major": 1, "proto_minor": 1,
		"rule": map[string]any{"name": "conformance.test", "uuid": "plugin-check", "tags": []string{"plugin-check"}},
	}
}

type filterSample struct {
	name string
	body []byte
}

// filterSamples are the filter calls the kit makes for a stage
func (k *kit) filterSamples(stage string) []filterSample {
	requests := []struct {
		name string
		req  map[string]any
		body []byte
	}{
		{"a plain GET", sampleRequest("GET", "/", map[string][]string{"Accept": {"text/html"}}), nil},
		{"a scanner", sampleRequest("GET", "/.env?x=1%27%20OR%201=1", map[string][]string{"User-Agent": {"sqlmap/1.7"}}), nil},
		{"a POST with a body", sampleRequest("POST", "/api/login", map[string][]string{"Content-Type": {"application/json"}, "Content-Length": {"27"}}), []byte(`{"user":"a","password":"b"}`)},
		{"a long request", sampleRequest("GET", "/"+strings.Repeat("a", 2000)+"?q="+strings.Repeat("b", 2000), map[string][]string{"Cookie": {strings.Repeat("c", 4000)}, "X-Odd": {"é中\"<script>"}}), nil},
	}
	var out []filterSample
	for i, r := range requests {
		fr := map[string]any{"version": hookAPIVersion, "stage": stage, "request_id": fmt.Sprintf("plugin-check-%s-%d", stage, i), "request": r.req}
		if r.body != nil && k.m.wantsBody() && stage != "response" {
			fr["body_preview"] = r.body //[]byte is base64 in JSON, as Zoraxy sends it
		}
		if stage == "response" {
			fr["response"] = map[string]any{"status": 200, "header": map[string][]string{"Content-Type": {"text/html; charset=utf-8"}, "X-Powered-By": {"upstream"}, "Set-Cookie": {"sid=1; Path=/"}}}
		}
		js, _ := json.Marshal(fr)
		out = append(out, filterSample{name: stage + ", " + r.name, body: js})
	}
	return out
}

func (k *kit) checkVerdict() {
	begin := time.Now()
	if k.m.Hooks == nil || len(k.m.Hooks.Stages) == 0 {
		k.skip("verdict", "The plugin declares no filter hooks.")
		return
	}
	if why := k.gate(); why != "" {
		k.skip("verdict", "Not run: "+why+".")
		return
	}
	timeout := time.Duration(k.m.hookTimeoutMs()) * time.Millisecond
	var problems, warns []string
	actions := map[string]int{}
	valid := 0
	one := func(stage string, s filterSample) bool {
		a := k.call(http.MethodPost, k.m.filterPath(stage), s.body, k.tokenHeader("plugin-check"), timeout, maxVerdictBytes)
		switch {
		case a.err != nil:
			problems = append(problems, fmt.Sprintf("%s: no answer within the %d ms the plugin asked for (%s)", s.name, timeout.Milliseconds(), shortErr(a.err)))
			if a.timedOut() {
				k.silent = "the plugin did not answer a filter call in time"
				return false
			}
		case a.status != http.StatusOK:
			problems = append(problems, fmt.Sprintf("%s: HTTP %d instead of 200", s.name, a.status))
		case a.tooLarge:
			problems = append(problems, fmt.Sprintf("%s: the answer is larger than %d bytes", s.name, maxVerdictBytes))
		default:
			action, err := validateVerdictBody(stage, a.body)
			if err != nil {
				problems = append(problems, s.name+": "+err.Error())
			} else {
				valid++
				actions[action]++
				if action == "capture" && !k.m.hasSniff() {
					warns = append(warns, s.name+": the verdict is \"capture\" but the manifest has no dynamic capture ingress")
				}
				if action == "capture" && stage == "pre_auth" {
					warns = append(warns, s.name+": \"capture\" is not honoured at pre_auth (Zoraxy treats it as allow)")
				}
			}
		}
		return true
	}
stages:
	for _, stage := range k.m.Hooks.Stages {
		for _, s := range k.filterSamples(stage) {
			if !one(stage, s) {
				break stages
			}
		}
	}
	if k.silent == "" {
		//Calls Zoraxy never makes. Any answer will do, but the plugin has to answer and to go on working.
		stage := k.m.Hooks.Stages[0]
		for name, body := range map[string][]byte{"a call that is not JSON": []byte("{this is not json"), "an empty call": nil, "a call with an unknown stage": []byte(`{"version":1,"stage":"later","request":{}}`)} {
			if a := k.call(http.MethodPost, k.m.filterPath(stage), body, k.tokenHeader("plugin-check"), timeout, 8<<20); a.err != nil {
				problems = append(problems, name+": no answer ("+shortErr(a.err)+")")
				if a.timedOut() {
					k.silent = "the plugin did not answer a filter call in time"
				}
			}
		}
		if k.silent == "" && !k.p.exited() {
			one(stage, k.filterSamples(stage)[0])
		}
	}
	if k.p.exited() {
		problems = append(problems, "the plugin process ended during the filter calls ("+k.p.exitText()+")")
	}
	data := map[string]any{"valid": valid, "actions": actions, "timeout_ms": timeout.Milliseconds()}
	switch {
	case len(problems) > 0:
		k.add("verdict", statusFail, fmt.Sprintf("%d of the answers Zoraxy would refuse. %s.", len(problems), joinMax(problems, 3)), begin, data)
	case len(warns) > 0:
		k.add("verdict", statusWarn, fmt.Sprintf("%d valid verdicts. %s.", valid, joinMax(warns, 3)), begin, data)
	default:
		k.add("verdict", statusPass, fmt.Sprintf("%d valid verdicts (%s), stages %s.", valid, countText(actions), strings.Join(k.m.Hooks.Stages, ", ")), begin, data)
	}
}

func joinMax(list []string, n int) string {
	if len(list) > n {
		return strings.Join(list[:n], "; ") + fmt.Sprintf("; and %d more", len(list)-n)
	}
	return strings.Join(list, "; ")
}

func countText(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", key, m[key]))
	}
	return strings.Join(parts, ", ")
}

const sniffReplyLimit = 4096 //Zoraxy reads at most this much of a sniff answer

func (k *kit) checkSniff() {
	begin := time.Now()
	if !k.m.hasSniff() {
		k.skip("sniff", "The plugin declares no dynamic capture.")
		return
	}
	if why := k.gate(); why != "" {
		k.skip("sniff", "Not run: "+why+".")
		return
	}
	path := normalizeEndpoint(k.m.DynamicCaptureSniff) + "/"
	timeout := time.Duration(k.m.hookTimeoutMs()) * time.Millisecond
	var problems []string
	statuses := map[string]int{}
	samples := []map[string]any{
		sampleRequest("GET", "/", nil),
		sampleRequest("GET", "/.env", map[string][]string{"User-Agent": {"sqlmap/1.7"}}),
		sampleRequest("POST", "/api/login", map[string][]string{"Content-Type": {"application/json"}}),
	}
	for i, s := range samples {
		js, _ := json.Marshal(s)
		a := k.call(http.MethodPost, path, js, k.tokenHeader(fmt.Sprintf("plugin-check-sniff-%d", i)), timeout, sniffReplyLimit)
		switch {
		case a.err != nil:
			problems = append(problems, fmt.Sprintf("no answer within %d ms (%s)", timeout.Milliseconds(), shortErr(a.err)))
			if a.timedOut() {
				k.silent = "the plugin did not answer a sniff call in time"
			}
		case a.tooLarge:
			problems = append(problems, fmt.Sprintf("the answer is larger than %d bytes: Zoraxy counts that as a failed call", sniffReplyLimit))
		default:
			statuses[strconv.Itoa(a.status)]++
			if a.status == http.StatusOK {
				//The plugin wants the request: its ingress has to answer
				uri, _ := s["request_uri"].(string)
				in := k.call(fmt.Sprint(s["method"]), normalizeEndpoint(k.m.DynamicCaptureIngress)+uri, nil, map[string]string{"X-Zoraxy-Plugin-Token": k.p.token, "X-Zoraxy-RequestID": fmt.Sprintf("plugin-check-sniff-%d", i)}, 5*time.Second, 8<<20)
				if in.err != nil {
					problems = append(problems, "the plugin accepted a request and its capture ingress did not answer within 5 s ("+shortErr(in.err)+")")
				}
			}
		}
		if k.silent != "" {
			break
		}
	}
	if k.silent == "" {
		if a := k.call(http.MethodPost, path, []byte("{this is not json"), k.tokenHeader("plugin-check"), timeout, 8<<20); a.err != nil {
			problems = append(problems, "a call that is not JSON: no answer ("+shortErr(a.err)+")")
		}
	}
	if k.p.exited() {
		problems = append(problems, "the plugin process ended during the sniff calls ("+k.p.exitText()+")")
	}
	data := map[string]any{"statuses": statuses, "timeout_ms": timeout.Milliseconds()}
	if len(problems) > 0 {
		k.add("sniff", statusFail, joinMax(problems, 3)+".", begin, data)
		return
	}
	k.add("sniff", statusPass, "Answers by status: "+countText(statuses)+" (200 = the plugin takes the request, anything else = it does not).", begin, data)
}

func sampleEvent(name, pluginID string, n int) []byte {
	var data map[string]any
	switch name {
	case "blacklistedIpBlocked":
		data = map[string]any{"ip": fmt.Sprintf("192.0.2.%d", 1+n%250), "comment": "plugin-check sample", "requested_url": "/", "hostname": "conformance.test", "user_agent": "plugin-check", "method": "GET"}
	case "blacklistToggled":
		data = map[string]any{"rule_id": "plugin-check", "enabled": n%2 == 0}
	case "accessRuleCreated":
		data = map[string]any{"id": "plugin-check", "name": "plugin-check sample", "desc": "", "blacklist_enabled": false, "whitelist_enabled": false, "trust_proxy_headers_only": false}
	case "customEvent":
		data = map[string]any{"source_plugin": "plugin-check", "recipients": []string{pluginID}, "payload": map[string]any{}}
	default:
		data = map[string]any{}
	}
	js, _ := json.Marshal(map[string]any{"name": name, "timestamp": time.Now().Unix(), "uuid": randomHex(16), "data": data})
	return js
}

func (k *kit) eventNames() []string {
	names := make([]string, 0, len(k.m.SubscriptionsEvents))
	for name := range k.m.SubscriptionsEvents {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (k *kit) eventPath(name string) string {
	return normalizeEndpoint(k.m.SubscriptionPath) + "/" + name
}

func (k *kit) checkEvents() {
	begin := time.Now()
	names := k.eventNames()
	if len(names) == 0 || k.m.SubscriptionPath == "" {
		k.skip("events", "The plugin subscribes to no events.")
		return
	}
	if why := k.gate(); why != "" {
		k.skip("events", "Not run: "+why+".")
		return
	}
	var problems []string
	var total, slowest time.Duration
	sent := 0
	for i := 0; i < len(names)+k.o.Events && k.silent == ""; i++ {
		name := names[i%len(names)]
		hdr := k.tokenHeader("")
		hdr["X-Zoraxy-Event-Type"] = name
		a := k.call(http.MethodPost, k.eventPath(name), sampleEvent(name, k.m.ID, i), hdr, 10*time.Second, 1<<20)
		switch {
		case a.err != nil:
			problems = append(problems, name+": no answer within 10 s ("+shortErr(a.err)+")")
			if a.timedOut() {
				k.silent = "the plugin did not answer an event in time"
			}
		case a.status != http.StatusOK:
			if len(problems) < 8 {
				problems = append(problems, fmt.Sprintf("%s: HTTP %d instead of 200", name, a.status))
			}
		}
		sent++
		total += a.took
		if a.took > slowest {
			slowest = a.took
		}
		if len(problems) >= 8 || k.p.exited() {
			break
		}
	}
	if k.p.exited() {
		problems = append(problems, "the plugin process ended during the events ("+k.p.exitText()+")")
	}
	mean := time.Duration(0)
	if sent > 0 {
		mean = total / time.Duration(sent)
	}
	data := map[string]any{"sent": sent, "mean_ms": ms(mean), "slowest_ms": ms(slowest), "events": names}
	switch {
	case len(problems) > 0:
		k.add("events", statusFail, joinMax(problems, 3)+".", begin, data)
	case mean > 100*time.Millisecond || slowest > time.Second:
		k.add("events", statusWarn, fmt.Sprintf("%d events acknowledged, but slowly (mean %s ms, slowest %s ms). Zoraxy sends one event at a time and keeps at most 1000 waiting: acknowledge first, work later.", sent, fmtMs(mean), fmtMs(slowest)), begin, data)
	default:
		k.add("events", statusPass, fmt.Sprintf("%d events acknowledged (mean %s ms, slowest %s ms).", sent, fmtMs(mean), fmtMs(slowest)), begin, data)
	}
}

func ms(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/10) / 100 }
func fmtMs(d time.Duration) string {
	return strconv.FormatFloat(ms(d), 'f', -1, 64)
}

// checkToken calls every path Zoraxy protects with the invoke token without the
// token and with a wrong one. A plugin that answers such a call as it answers
// Zoraxy can be driven by any local process.
func (k *kit) checkToken() {
	begin := time.Now()
	type target struct {
		what, path string
		body       []byte
		accepted   func(a answer) bool
	}
	var targets []target
	if k.m.Hooks != nil {
		seen := map[string]bool{}
		for _, stage := range k.m.Hooks.Stages {
			path := k.m.filterPath(stage)
			if seen[path] {
				continue
			}
			seen[path] = true
			stage := stage
			targets = append(targets, target{"filter " + path, path, k.filterSamples(stage)[0].body, func(a answer) bool {
				if a.status != http.StatusOK || a.tooLarge {
					return false
				}
				_, err := validateVerdictBody(stage, a.body)
				return err == nil
			}})
		}
	}
	if k.m.hasSniff() {
		js, _ := json.Marshal(sampleRequest("GET", "/", nil))
		targets = append(targets, target{"sniff " + k.m.DynamicCaptureSniff, normalizeEndpoint(k.m.DynamicCaptureSniff) + "/", js, func(a answer) bool { return a.status == http.StatusOK }})
	}
	if names := k.eventNames(); len(names) > 0 && k.m.SubscriptionPath != "" {
		targets = append(targets, target{"events " + k.m.SubscriptionPath, k.eventPath(names[0]), sampleEvent(names[0], k.m.ID, 0), func(a answer) bool { return a.status == http.StatusOK }})
	}
	if len(targets) == 0 {
		k.skip("token", "The plugin has no filter, sniff or event path.")
		return
	}
	if why := k.gate(); why != "" {
		k.skip("token", "Not run: "+why+".")
		return
	}
	var open, unclear []string
	for _, t := range targets {
		//What the plugin answers to Zoraxy (with the token), to compare with
		ref := k.call(http.MethodPost, t.path, t.body, k.tokenHeader("plugin-check-token"), 2*time.Second, maxVerdictBytes)
		for _, how := range []string{"without the token", "with a wrong token"} {
			hdr := map[string]string{"Content-Type": "application/json", "X-Zoraxy-RequestID": "plugin-check-token"}
			if how == "with a wrong token" {
				hdr["X-Zoraxy-Plugin-Token"] = "wrong-" + randomHex(8)
			}
			a := k.call(http.MethodPost, t.path, t.body, hdr, 2*time.Second, maxVerdictBytes)
			switch {
			case a.err != nil:
			case t.accepted(a):
				open = append(open, t.what+" "+how)
			case ref.err == nil && !t.accepted(ref) && a.status == ref.status:
				//The plugin did not take the sample call from Zoraxy either, with the same
				//status: a refusal cannot be told from "not for me" (a sniff that skips)
				unclear = append(unclear, fmt.Sprintf("%s %s (HTTP %d, the same as with the token)", t.what, how, a.status))
			}
		}
	}
	data := map[string]any{"paths": len(targets), "open": open, "unclear": unclear}
	switch {
	case len(open) > 0 && k.m.APIVersion >= 1:
		k.add("token", statusFail, "Answered as if Zoraxy had called: "+joinMax(open, 4)+". Any local process can call these paths. Check the header X-Zoraxy-Plugin-Token (SDK: RequireInvokeToken).", begin, data)
	case len(open) > 0:
		k.add("token", statusWarn, "Answered as if Zoraxy had called: "+joinMax(open, 4)+". Any local process can call these paths. A legacy plugin is not failed for this; a plugin of contract version 1 is.", begin, data)
	case len(unclear) > 0:
		k.add("token", statusWarn, "Could not be told: "+joinMax(unclear, 2)+". The plugin does not take the sample request of the kit, with or without the token, so the kit cannot see whether it checks the token.", begin, data)
	default:
		k.add("token", statusPass, fmt.Sprintf("Protected paths: %d. Each refuses a call without the invoke token and with a wrong one.", len(targets)), begin, data)
	}
}

// requestPathTarget returns the call the latency and memory checks repeat: the
// call Zoraxy makes for every visitor request, or the page when the plugin is not
// in the request path.
func (k *kit) requestPathTarget() (what string, inPath bool, do func() answer) {
	timeout := time.Duration(k.m.hookTimeoutMs()) * time.Millisecond
	if k.m.Hooks != nil && len(k.m.Hooks.Stages) > 0 {
		stage := k.m.Hooks.Stages[0]
		s := k.filterSamples(stage)[0]
		path, hdr := k.m.filterPath(stage), k.tokenHeader("plugin-check-load")
		return "filter calls (" + stage + ")", true, func() answer {
			a := k.call(http.MethodPost, path, s.body, hdr, timeout, maxVerdictBytes)
			if a.err == nil && a.status != http.StatusOK {
				a.err = fmt.Errorf("HTTP %d", a.status)
			}
			return a
		}
	}
	if k.m.hasSniff() {
		js, _ := json.Marshal(sampleRequest("GET", "/", nil))
		path, hdr := normalizeEndpoint(k.m.DynamicCaptureSniff)+"/", k.tokenHeader("plugin-check-load")
		return "sniff calls", true, func() answer { return k.call(http.MethodPost, path, js, hdr, timeout, sniffReplyLimit) }
	}
	path := normalizeEndpoint(k.m.UIPath) + "/"
	return "requests for its page", false, func() answer { return k.call(http.MethodGet, path, nil, nil, 2*time.Second, 4<<20) }
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// burst makes n calls with the configured concurrency
func (k *kit) burst(n int, do func() answer) (took []time.Duration, errs int, firstErr string) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var next atomic.Int64
	workers := k.o.Concurrency
	if workers < 1 {
		workers = 1
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for next.Add(1) <= int64(n) && !k.p.exited() {
				a := do()
				mu.Lock()
				if a.err != nil {
					errs++
					if firstErr == "" {
						firstErr = shortErr(a.err)
					}
				} else {
					took = append(took, a.took)
				}
				stop := errs >= 20
				mu.Unlock()
				if stop {
					return
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
	return took, errs, firstErr
}

func (k *kit) checkLoad() {
	begin := time.Now()
	what, inPath, do := k.requestPathTarget()
	if !inPath {
		k.skip("load", "The plugin has no filter hooks and no dynamic capture sniff: Zoraxy does not call it for visitor requests. (Static capture paths are not exercised by this kit.)")
		return
	}
	if why := k.gate(); why != "" {
		k.skip("load", "Not run: "+why+".")
		return
	}
	timeout := time.Duration(k.m.hookTimeoutMs()) * time.Millisecond
	took, errs, firstErr := k.burst(k.o.LoadCalls, do)
	elapsed := time.Since(begin)
	p50, p95, p99 := percentile(took, 0.50), percentile(took, 0.95), percentile(took, 0.99)
	max := time.Duration(0)
	if len(took) > 0 {
		max = took[len(took)-1]
	}
	data := map[string]any{"calls": len(took) + errs, "errors": errs, "concurrency": k.o.Concurrency, "p50_ms": ms(p50), "p95_ms": ms(p95), "p99_ms": ms(p99), "max_ms": ms(max), "timeout_ms": timeout.Milliseconds(), "seconds": math.Round(elapsed.Seconds()*100) / 100}
	numbers := fmt.Sprintf("%d %s, %d at a time: p50 %s ms, p95 %s ms, p99 %s ms, slowest %s ms", len(took)+errs, what, k.o.Concurrency, fmtMs(p50), fmtMs(p95), fmtMs(p99), fmtMs(max))
	switch {
	case errs > 0:
		if errs >= 20 {
			k.silent = "the plugin failed calls under load"
		}
		k.add("load", statusFail, fmt.Sprintf("%d calls failed (%s). %s.", errs, firstErr, numbers), begin, data)
	case p99 >= timeout:
		k.add("load", statusFail, fmt.Sprintf("%s. The slowest calls reach the timeout of %d ms: Zoraxy counts them as failures.", numbers, timeout.Milliseconds()), begin, data)
	case p95 > k.o.MaxLatency:
		k.add("load", statusFail, fmt.Sprintf("%s. Every visitor request of an attached rule waits for this call; the limit of the kit for p95 is %s ms.", numbers, fmtMs(k.o.MaxLatency)), begin, data)
	case p95 > k.o.WarnLatency:
		k.add("load", statusWarn, fmt.Sprintf("%s. Every visitor request of an attached rule waits for this call (warning above %s ms).", numbers, fmtMs(k.o.WarnLatency)), begin, data)
	default:
		k.add("load", statusPass, numbers+".", begin, data)
	}
}

func mib(b int64) float64 { return math.Round(float64(b)/(1<<20)*10) / 10 }

func (k *kit) checkMemory(baseline int64) {
	begin := time.Now()
	if runtime.GOOS != "linux" {
		k.skip("memory", "The memory of a process is only read on Linux.")
		return
	}
	p := k.p
	killed := func() {
		k.add("memory", statusFail, fmt.Sprintf("The plugin used more than %d MiB (peak %.1f MiB) and was ended by the kit.", k.o.MemCapMB, mib(p.peakRSS.Load())), begin, map[string]any{"peak_mib": mib(p.peakRSS.Load()), "cap_mib": k.o.MemCapMB})
	}
	if p.memKilled.Load() {
		killed()
		return
	}
	if why := k.gate(); why != "" {
		k.skip("memory", "Not run: "+why+".")
		return
	}
	what, _, do := k.requestPathTarget()
	before := k.calls.Load()
	if rest := int64(k.o.Calls) - before; rest > 0 {
		k.burst(int(rest), do)
	}
	time.Sleep(300 * time.Millisecond)
	if p.memKilled.Load() {
		killed()
		return
	}
	after, ok := groupRSS(p.pid)
	if !ok || p.exited() {
		k.skip("memory", "The plugin process ended before its memory could be read.")
		return
	}
	growth := after - baseline
	data := map[string]any{"before_mib": mib(baseline), "after_mib": mib(after), "peak_mib": mib(p.peakRSS.Load()), "growth_mib": mib(growth), "calls": k.calls.Load()}
	numbers := fmt.Sprintf("%.1f MiB after %d calls (%s for the last %d), %.1f MiB before the load, peak %.1f MiB", mib(after), k.calls.Load(), what, k.calls.Load()-before, mib(baseline), mib(p.peakRSS.Load()))
	switch {
	case growth > int64(k.o.MemGrowthMB)<<20:
		k.add("memory", statusFail, fmt.Sprintf("%s: it grew by %.1f MiB, more than the %d MiB the kit allows.", numbers, mib(growth), k.o.MemGrowthMB), begin, data)
	case growth > int64(k.o.MemGrowthMB)<<20/4:
		k.add("memory", statusWarn, fmt.Sprintf("%s: it grew by %.1f MiB.", numbers, mib(growth)), begin, data)
	default:
		k.add("memory", statusPass, numbers+".", begin, data)
	}
}

func (k *kit) checkSurvive() {
	begin := time.Now()
	p := k.p
	if wait := k.o.MinRun - time.Since(p.started); wait > 0 && !p.exited() {
		p.waitExit(wait)
	}
	if p.memKilled.Load() {
		k.replace("memory", statusFail, fmt.Sprintf("The plugin used more than %d MiB (peak %.1f MiB) and was ended by the kit.", k.o.MemCapMB, mib(p.peakRSS.Load())), begin)
		k.skip("survive", "The plugin was ended by the kit (memory).")
		return
	}
	if p.exited() {
		k.add("survive", statusFail, fmt.Sprintf("The plugin ended by itself %d ms after its start (%s). %s", time.Since(p.started).Milliseconds(), p.exitText(), k.tailText()), begin, nil)
		return
	}
	k.add("survive", statusPass, fmt.Sprintf("Still running after %.1f s and %d calls.", time.Since(p.started).Seconds(), k.calls.Load()), begin, nil)
}

func (k *kit) replace(id, status, detail string, begin time.Time) {
	for i, c := range k.rep.Checks {
		if c.ID == id {
			k.rep.Checks[i].Status, k.rep.Checks[i].Detail = status, detail
			return
		}
	}
	k.add(id, status, detail, begin, nil)
}

func (k *kit) checkAPI() {
	begin := time.Now()
	if len(k.m.PermittedAPIEndpoints) == 0 || k.stub == nil {
		k.skip("api", "The plugin asks for no Zoraxy API endpoints (and gets no API key).")
		return
	}
	calls, total := k.stub.snapshot()
	var bad []string
	seen := map[string]bool{}
	for _, c := range calls {
		var msg string
		switch {
		case !c.KeyOK:
			msg = c.Method + " " + c.Path + " without the API key it was given"
		case !c.Declared:
			msg = c.Method + " " + c.Path + " is not in permitted_api_endpoints: Zoraxy refuses it"
		}
		if msg != "" && !seen[msg] {
			seen[msg] = true
			bad = append(bad, msg)
		}
	}
	data := map[string]any{"calls": total, "declared": len(k.m.PermittedAPIEndpoints)}
	switch {
	case len(bad) > 0:
		k.add("api", statusFail, joinMax(bad, 4)+".", begin, data)
	case total == 0:
		k.add("api", statusPass, fmt.Sprintf("The plugin asks for %d endpoints and made no call during the run. (The kit does not press buttons on the page of a plugin.)", len(k.m.PermittedAPIEndpoints)), begin, data)
	default:
		k.add("api", statusPass, fmt.Sprintf("Calls made: %d, all with the API key and all to endpoints of the manifest.", total), begin, data)
	}
}

// checkStop: the stop sequence of Zoraxy, one step at a time
func (k *kit) checkStop() {
	begin := time.Now()
	p := k.p
	if p.exited() {
		k.skip("term", "Not run: the plugin process has ended ("+p.exitText()+").")
	} else if k.noPort {
		k.skip("term", "Not run: the plugin did not open its port.")
	} else {
		p.track()
		a := k.call(http.MethodGet, normalizeEndpoint(k.m.UIPath)+"/term", nil, nil, 3*time.Second, 64<<10)
		gone := p.waitExit(2 * time.Second)
		switch {
		case a.err != nil && !gone:
			k.add("term", statusWarn, "No answer to the terminate request within 3 s ("+shortErr(a.err)+"). Zoraxy goes on with SIGTERM.", begin, nil)
		case gone:
			k.add("term", statusPass, fmt.Sprintf("Ended %d ms after the terminate request (%s).", time.Since(begin).Milliseconds(), p.exitText()), begin, nil)
		case a.status == http.StatusNotFound:
			k.add("term", statusPass, "The plugin has no terminate path (HTTP 404, which is allowed). Zoraxy ends it with SIGTERM.", begin, nil)
		default:
			k.add("term", statusWarn, fmt.Sprintf("The terminate request was answered with HTTP %d and the plugin was still running 2 s later. Zoraxy goes on with SIGTERM.", a.status), begin, nil)
		}
	}

	begin = time.Now()
	if p.exited() {
		if p.memKilled.Load() {
			k.skip("sigterm", "Not run: the plugin was ended by the kit (memory).")
			return
		}
		//The plugin is gone (terminate request, or by itself): SIGTERM is tried on a second start
		second, err := k.start()
		if err != nil {
			k.add("sigterm", statusFail, "The plugin could not be started a second time: "+err.Error(), begin, nil)
			return
		}
		if _, ready := second.waitReady(k.o.ReadyTimeout); !ready {
			k.add("sigterm", statusFail, fmt.Sprintf("Started a second time, the plugin did not open its port within %s (%s). Zoraxy starts a plugin again after every stop, update and restart.", k.o.ReadyTimeout, second.exitText()), begin, nil)
			second.signalGroup(syscall.SIGKILL)
			second.waitExit(3 * time.Second)
			k.checkCleanup()
			return
		}
		p = second
		k.p = second
	}
	p.track()
	begin = time.Now()
	p.signalGroup(syscall.SIGTERM)
	if p.waitExit(5 * time.Second) {
		k.add("sigterm", statusPass, fmt.Sprintf("Ended %d ms after SIGTERM (%s).", time.Since(begin).Milliseconds(), p.exitText()), begin, nil)
	} else {
		k.add("sigterm", statusFail, "Still running 5 s after SIGTERM: Zoraxy has to kill it (SIGKILL), and a stop or an update takes 5 s longer.", begin, nil)
		p.signalGroup(syscall.SIGKILL)
		p.waitExit(3 * time.Second)
	}
	k.checkCleanup()
}

func (k *kit) checkCleanup() {
	begin := time.Now()
	left, allGone := 0, true
	var outside []procID
	for _, p := range k.procList() {
		if !p.exited() {
			allGone = false
			continue
		}
		if p.groupAlive() || len(p.strays()) > 0 {
			time.Sleep(200 * time.Millisecond) //a child that is on its way out
		}
		if p.groupAlive() {
			left++
			p.signalGroup(syscall.SIGKILL)
			time.Sleep(100 * time.Millisecond)
		}
		//What is still there now is outside the process group of the plugin
		outside = append(outside, p.strays()...)
	}
	if allGone {
		known := map[procID]bool{}
		for _, id := range outside {
			known[id] = true
		}
		for _, id := range processesIn(k.workDir) {
			if !known[id] {
				outside = append(outside, id)
			}
		}
	}
	for _, id := range outside {
		id.kill()
	}
	data := map[string]any{"in_group": left, "outside_group": len(outside), "descendants_tracked": tracksDescendants}
	switch {
	case len(outside) > 0:
		k.add("cleanup", statusWarn, fmt.Sprintf("The plugin ended and left %d process(es) running that had left its process group (setsid or setpgid). Zoraxy ends the process group only: such a process stays after a stop, an update and a crash, until somebody ends it by hand. The kit ended it.", len(outside)), begin, data)
	case left > 0:
		k.add("cleanup", statusWarn, "The plugin ended and left processes of its process group running. Zoraxy ends the whole group at a stop; after a crash such processes stay until then.", begin, data)
	case tracksDescendants:
		k.add("cleanup", statusPass, "No process of the plugin was left, in its process group or outside it.", begin, data)
	default:
		k.add("cleanup", statusPass, "No process was left in the process group of the plugin. A child that left the group cannot be seen on this system.", begin, data)
	}
}

const (
	maxLogBytes = 1 << 20
	maxLogLine  = 64 << 10
)

func (k *kit) checkLogs() {
	begin := time.Now()
	if len(k.procList()) == 0 {
		return
	}
	lines, size, longest, _ := k.logs.snapshot()
	calls := k.calls.Load()
	data := map[string]any{"lines": lines, "bytes": size, "longest_line": longest, "calls": calls}
	numbers := fmt.Sprintf("%d lines, %d bytes during %d calls", lines, size, calls)
	switch {
	case longest > maxLogLine:
		k.add("logs", statusFail, fmt.Sprintf("%s, and one line of %d bytes: Zoraxy cuts a line at %d bytes.", numbers, longest, maxLogLine), begin, data)
	case size > maxLogBytes || lines > 200+2*calls:
		k.add("logs", statusFail, numbers+": this fills the log of the plugin and pushes everything else out of the last 200 lines Zoraxy shows.", begin, data)
	case lines > 50+calls/10:
		k.add("logs", statusWarn, numbers+": the plugin writes a line for many of its calls. Under visitor traffic that is a log line per request.", begin, data)
	default:
		k.add("logs", statusPass, numbers+".", begin, data)
	}
}
