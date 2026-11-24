package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
	dunreePlugin "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	Plugin status (read-only)

	What Dunree knows about the process of a plugin: is it running, did it stop by
	itself, with which exit code, when, and what was the last problem. Nothing here
	changes how requests are handled: it only records and reports.

	Locking: Plugin.mu guards the runtime fields of a plugin (Enabled, AssignedPort,
	the proxies, proc and the status record). The request path only takes the read
	lock. Timestamps that change on every call are atomics.
*/

// State of the process of a plugin
const (
	StateStopped       = "stopped"         //never started, or stopped by the administrator / Dunree
	StateRunning       = "running"         //process is alive
	StateCrashed       = "crashed"         //process ended by itself with a non-zero exit code or a signal
	StateExited        = "exited"          //process ended by itself with exit code 0
	StateFailedToStart = "failed_to_start" //the last start attempt did not produce a process
	StateRestarting    = "restarting"      //ended by itself, the supervisor starts it again when the backoff delay is over (only with a restart policy)
	StateCrashLoop     = "crash_loop"      //ended too often in a short time, the supervisor gave up (only with a restart policy)
)

// Health of a running plugin, from what Dunree can observe without calling it
const (
	HealthOK            = "ok"
	HealthStarting      = "starting"       //just started, port not open yet (only with the port probe: the status view of the Plugin Manager, or everywhere with ManagerOptions.ProbePluginPorts)
	HealthNotListening  = "not_listening"  //process alive, port closed (only with the port probe)
	HealthNotResponding = "not_responding" //process alive, calls from Dunree keep failing
	HealthUnhealthy     = "unhealthy"      //process alive, the health check keeps failing (only with a health check)
)

const (
	outputRingLines       = 200              //plugin output lines kept in memory per plugin
	outputRingLineMax     = 512              //longer lines are cut in the ring (the log keeps up to maxPluginLineBytes)
	maxPluginLineBytes    = 64 * 1024        //a longer output line is cut, the rest of the line is dropped
	defaultStopGrace      = 5 * time.Second  //time a plugin gets to stop after SIGTERM
	defaultStartGrace     = 10 * time.Second //a plugin that has not opened its port after this is "not listening"
	portProbeCacheTime    = 2 * time.Second
	portProbeTimeout      = 200 * time.Millisecond
	notRespondingFailures = 3 //consecutive failed calls before a running plugin is shown as not responding
)

// PluginStatus is the read-only status of a plugin as shown by the API. Times are Unix seconds, 0 = never.
type PluginStatus struct {
	State        string //running | stopped | crashed | exited | failed_to_start
	Health       string //only while running: ok | starting | not_listening | not_responding
	PID          int    //only while running
	StartedAt    int64  //last successful start
	ExitedAt     int64  //last time the process ended
	LastSeen     int64  //last sign of life: output, or an answered call from Dunree
	HasExited    bool   //ExitCode / ExitReason are from a real process exit
	ExitCode     int    //exit code of the last exit, -1 when it was ended by a signal
	ExitReason   string //e.g. "exit status 3", "signal: killed"
	LastError    string //last problem Dunree saw, worded by Dunree: no plugin output, no text from a plugin answer, no text of a network error
	LastErrorAt  int64
	StartCount   int //successful starts since Dunree started
	RestartCount int //starts after the first one (manual, update, hot reload, and automatic restarts)

	//Phase 1 (supervision), all additive
	AutoRestartCount int            //starts done by the supervisor (restart policy)
	NextRestartAt    int64          //only in state restarting: when the supervisor starts the plugin again
	RecentFailures   int            //unexpected exits inside the crash-loop window
	CrashLoopLimit   int            //that many inside the window end the automatic restarts
	Attached         bool           //only while running: the plugin takes part in the request path
	ReadyAfterMs     int64          //time the plugin needed to open its port, -1 = not measured (only measured with the readiness gate or a health check)
	LimitsNote       string         //limits applied to the running process, in words
	Policy           PluginPolicy   //what the administrator allows Dunree to do about this plugin
	Counters         PluginCounters //since Dunree started

	//Phase 2 (contract and permissions), additive
	Contract    PluginContract    //contract version of the plugin and whether this Dunree supports it
	Permissions PermissionSummary //API permissions: asked for, not approved, not granted

	//Phase 2 (signed index, safe update): where the plugin came from and whether a previous version is kept
	Install PluginInstallInfo
}

// PluginCounters counts what happened with a plugin since Dunree started
type PluginCounters struct {
	Calls            int64 //filter and sniff calls made
	CallFailures     int64 //of which failed (any reason)
	CallTimeouts     int64 //of which timed out
	BreakerOpens     int64 //times the circuit breaker of the filter calls opened
	CaptureRequests  int64 //requests handed to the plugin (static / dynamic capture, UI)
	CaptureFailures  int64 //of which failed before an answer was sent
	CaptureRejected  int64 //requests answered 503 at once because the capture circuit breaker was open
	EventsSent       int64
	EventsFailed     int64
	EventsDropped    int64 //events dropped because the queue of the plugin was full, or the plugin went away
	EventsQueued     int   //waiting right now
	LogLines         int64 //output lines read from the plugin
	LogLinesDropped  int64 //of which dropped by the rate limit
	PassedWhileDown  int64 //requests that passed unfiltered while this fail-closed plugin was not running
	BlockedWhileDown int64 //requests answered 503 because this fail-closed plugin was not running (block-when-down)
	HealthChecksOK   int64
	HealthChecksFail int64
}

// pluginStatusRecord is the internal status record, guarded by Plugin.mu
type pluginStatusRecord struct {
	state       string
	pid         int
	startedAt   time.Time
	exitedAt    time.Time
	hasExited   bool
	exitCode    int
	exitReason  string
	lastError   string
	lastErrorAt time.Time
	startCount  int
	probePort   bool //copy of ManagerOptions.ProbePluginPorts at the last start

	watched         bool          //a readiness / health goroutine watches the current process
	readyKnown      bool          //the port of the current process was seen open
	readyAfter      time.Duration //time it took
	limitsNote      string        //limits applied to the current process
	limitsProblem   string        //limits that could not be applied
	healthFailLimit int           //consecutive failed health checks that make the process "unhealthy"
}

// pluginProc is one started process of a plugin
type pluginProc struct {
	cmd           *exec.Cmd
	pid           int
	done          chan struct{} //closed when the process has been reaped
	readersDone   chan struct{} //closed when stdout and stderr are drained
	stopRequested atomic.Bool   //Dunree asked for the stop: the exit is not a crash

	startedAt    time.Time
	ctx          context.Context        //cancelled when the process is gone: ends calls that only make sense for this process
	cancel       context.CancelFunc     //
	unhealthyWhy atomic.Pointer[string] //set when the supervisor ended the process because of its health check
	memLimitMB   int                    //memory limit applied through a systemd scope, 0 = none
	logLimit     logRateLimiter         //output rate limit of this process

	sigMu       sync.Mutex //guards groupClosed and every signal to the process group
	groupClosed bool       //the process has ended and its group was reaped: its PID may belong to someone else now, never signal it again
}

func (pp *pluginProc) exited() bool {
	select {
	case <-pp.done:
		return true
	default:
		return false
	}
}

// pluginObserved holds the values that change on every call (no lock)
type pluginObserved struct {
	lastSeen     atomic.Int64 //unix nano
	failStreak   atomic.Int32 //consecutive failed calls from Dunree
	probeAt      atomic.Int64 //unix nano of the last port probe
	probeOK      atomic.Bool
	captureFails atomic.Int64

	//Phase 1 counters
	calls            atomic.Int64
	callFails        atomic.Int64
	callTimeouts     atomic.Int64
	breakerOpens     atomic.Int64
	captureCalls     atomic.Int64
	captureRejected  atomic.Int64
	eventsSent       atomic.Int64
	eventsFailed     atomic.Int64
	eventsDropped    atomic.Int64
	logLines         atomic.Int64
	logDropped       atomic.Int64
	mainLogLines     atomic.Int64 //output lines written to the main Dunree log
	passedWhileDown  atomic.Int64
	blockedWhileDown atomic.Int64
	healthFails      atomic.Int32 //consecutive failed health checks
	healthOK         atomic.Int64
	healthFailTotal  atomic.Int64
	downLogAt        atomic.Int64 //unix nano of the last "passed while down" log line
	eventLogAt       atomic.Int64 //unix nano of the last event problem log line
	captureLogAt     atomic.Int64 //unix nano of the last capture problem log line

	outMu   sync.Mutex
	outRing []string
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

/* Guarded accessors */

// spec returns the manifest of the plugin (a store update replaces it)
func (p *Plugin) spec() *dunreePlugin.IntroSpect {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Spec
}

func (p *Plugin) isEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Enabled
}

func (p *Plugin) assignedPort() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.AssignedPort
}

func (p *Plugin) currentProc() *pluginProc {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proc
}

func (p *Plugin) uiProxyAndPort() (*dpcore.ReverseProxy, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.uiProxy, p.AssignedPort
}

func (p *Plugin) staticProxyFor(prefix string) (*dpcore.ReverseProxy, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.staticRouteProxy[prefix], p.AssignedPort
}

func (p *Plugin) dynamicProxyAndPort() (*dpcore.ReverseProxy, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dynamicRouteProxy, p.AssignedPort
}

/* Recording */

// noteAlive records a sign of life of the plugin (output line or an answered call)
func (p *Plugin) noteAlive() {
	p.obs.lastSeen.Store(time.Now().UnixNano())
}

// noteError records the last problem Dunree saw with this plugin. msg must not contain plugin output.
func (p *Plugin) noteError(msg string) {
	p.mu.Lock()
	p.status.lastError = msg
	p.status.lastErrorAt = time.Now()
	p.mu.Unlock()
}

// noteCall records the result of a call from Dunree to the plugin (filter / sniff)
func (p *Plugin) noteCall(err error) {
	if err == nil {
		p.obs.failStreak.Store(0)
		p.noteAlive()
		return
	}
	p.obs.failStreak.Add(1)
	p.noteError("A call to the plugin failed: " + publicCallError(err))
}

// rejectedAnswerError is a call that failed because Dunree rejected the answer of
// the plugin. detail can quote text the plugin chose (a header name, a piece of
// its JSON), so it goes to the log only; the status shows kind alone.
type rejectedAnswerError struct {
	kind   string //fixed wording, e.g. "invalid verdict"
	detail error
}

func (e *rejectedAnswerError) Error() string { return e.kind + ": " + e.detail.Error() }
func (e *rejectedAnswerError) Unwrap() error { return e.detail }

// publicCallError is the text of a failed call that may be shown in the status,
// which read-only accounts and plugins with the list permission can read.
func publicCallError(err error) string {
	var rejected *rejectedAnswerError
	if errors.As(err, &rejected) {
		return rejected.kind + " (the answer of the plugin was rejected)"
	}
	// An error of the HTTP client or the network can quote bytes the plugin sent
	// (a malformed status line) or the address that was called: fixed wording only
	var ue *url.Error
	var ne net.Error
	if errors.As(err, &ue) || errors.As(err, &ne) {
		return publicTransportError(err)
	}
	return err.Error() //worded by Dunree itself (hooks_runtime.go, supervisor.go)
}

// publicTransportError words a failed HTTP exchange with a plugin without using
// the text of the error. That text can hold bytes of the answer of the plugin
// ("malformed HTTP response ...") and the path a visitor asked for, and the
// status can be read by read-only accounts and by plugins with the list permission.
func publicTransportError(err error) string {
	switch {
	case isTimeout(err):
		return "the plugin did not answer in time"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused (the plugin is not listening on its port)"
	case errors.Is(err, dpcore.ErrResponseAborted):
		return "the answer of the plugin broke off"
	case errors.Is(err, context.Canceled):
		return "the request was cancelled"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "the plugin closed the connection"
	}
	return "the plugin could not be reached or its answer was not valid HTTP"
}

// noteStartFailure records a start attempt that did not produce a running process
func (p *Plugin) noteStartFailure(err error) {
	p.mu.Lock()
	p.status.state = StateFailedToStart
	p.status.pid = 0
	p.status.lastError = "Failed to start: " + err.Error()
	p.status.lastErrorAt = time.Now()
	p.mu.Unlock()
}

// noteOutput keeps the last output lines of the plugin in memory
func (p *Plugin) noteOutput(stream string, line string) {
	if len(line) > outputRingLineMax {
		line = line[:outputRingLineMax] + " ..."
	}
	entry := time.Now().Format("15:04:05") + " " + stream + " " + line
	p.obs.outMu.Lock()
	if len(p.obs.outRing) >= outputRingLines {
		copy(p.obs.outRing, p.obs.outRing[1:])
		p.obs.outRing = p.obs.outRing[:outputRingLines-1]
	}
	p.obs.outRing = append(p.obs.outRing, entry)
	p.obs.outMu.Unlock()
	p.noteAlive()
}

// recentOutput returns a copy of the last output lines, oldest first
func (p *Plugin) recentOutput() []string {
	p.obs.outMu.Lock()
	defer p.obs.outMu.Unlock()
	out := make([]string, len(p.obs.outRing))
	copy(out, p.obs.outRing)
	return out
}

/* Reading */

// portOpen reports whether the port of the plugin accepts a TCP connection. The
// answer is cached for a short time so a status view stays cheap. Only used for
// the status view of the Plugin Manager (statusWith) and when
// ManagerOptions.ProbePluginPorts is on (off by default); nothing else connects
// to a plugin just to look at it.
func (p *Plugin) portOpen(port int) bool {
	now := time.Now()
	if last := p.obs.probeAt.Load(); last != 0 && now.Sub(time.Unix(0, last)) < portProbeCacheTime {
		return p.obs.probeOK.Load()
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), portProbeTimeout)
	ok := err == nil
	if ok {
		conn.Close()
	}
	p.obs.probeOK.Store(ok)
	p.obs.probeAt.Store(now.UnixNano())
	return ok
}

// Status returns the read-only status of the plugin. It never connects to the
// plugin unless the start flag -plugin_port_probe is on (see statusWith).
func (p *Plugin) Status() PluginStatus { return p.statusWith(false) }

// statusWith returns the status of the plugin. With probe it also looks whether
// the port of a running plugin accepts a TCP connection (cached for
// portProbeCacheTime), which is what tells "starting" / "not listening" from
// "running". Only the status view of the Plugin Manager asks for that
// (HandlePluginStatus with probe=true), so a connection is only made while an
// administrator looks at that page; the plugin list, which the side menu and
// plugins with the list permission read, never causes one.
func (p *Plugin) statusWith(probe bool) PluginStatus {
	p.mu.RLock()
	rec := p.status
	port := p.AssignedPort
	attached := !p.notReady
	mgr := p.mgr
	spec := p.Spec
	p.mu.RUnlock()

	st := PluginStatus{
		State:       rec.state,
		StartedAt:   unixOrZero(rec.startedAt),
		ExitedAt:    unixOrZero(rec.exitedAt),
		HasExited:   rec.hasExited,
		ExitCode:    rec.exitCode,
		ExitReason:  rec.exitReason,
		LastError:   rec.lastError,
		LastErrorAt: unixOrZero(rec.lastErrorAt),
		StartCount:  rec.startCount,
	}
	if st.State == "" {
		st.State = StateStopped
	}
	if rec.startCount > 1 {
		st.RestartCount = rec.startCount - 1
	}
	if ns := p.obs.lastSeen.Load(); ns != 0 {
		st.LastSeen = time.Unix(0, ns).Unix()
	}
	st.Policy = p.policy()
	st.Counters = p.counters()
	if mgr != nil {
		st.Contract = contractOf(spec, mgr.Settings().ContractMode)
		st.Permissions = mgr.permissionSummaryOf(p)
		st.Install = mgr.installInfoOf(p)
	} else {
		st.Contract = contractOf(spec, ContractModeWarn)
	}
	st.ReadyAfterMs = -1
	p.sup.mu.Lock()
	st.CrashLoopLimit = intOr(p.sup.loopMax, defaultCrashLoopMax)
	st.AutoRestartCount = p.sup.autoRestarts
	st.RecentFailures = len(p.sup.recent)
	if st.State == StateRestarting {
		st.NextRestartAt = unixOrZero(p.sup.nextAt)
	}
	p.sup.mu.Unlock()
	if st.State != StateRunning {
		return st
	}
	st.PID = rec.pid
	st.Health = HealthOK
	st.Attached = attached
	st.LimitsNote = rec.limitsNote
	if rec.limitsProblem != "" {
		st.LimitsNote = strings.TrimSpace(st.LimitsNote + " " + rec.limitsProblem)
	}
	if rec.readyKnown {
		st.ReadyAfterMs = rec.readyAfter.Milliseconds()
	}
	// Either breaker: the one of the filter and sniff calls, or the one of the capture
	// and UI paths (only enforced with an answer timeout). With the second one open
	// captured requests and the plugin UI are answered 503.
	breakerOpen := p.hookAdminState().BreakerOpen || (st.Policy.CaptureTimeoutMs > 0 && p.capBreaker.refusing())
	switch {
	case rec.watched && !rec.readyKnown:
		//The readiness / health goroutine of this process has not seen its port open yet
		if time.Since(rec.startedAt) < p.startGraceOrDefault() {
			st.Health = HealthStarting
		} else {
			st.Health = HealthNotListening
		}
	case p.obs.healthFails.Load() >= int32(intOr(rec.healthFailLimit, defaultHealthFailures)):
		st.Health = HealthUnhealthy
	case (rec.probePort || probe) && port > 0 && !p.portOpen(port):
		if time.Since(rec.startedAt) < p.startGraceOrDefault() {
			st.Health = HealthStarting
		} else {
			st.Health = HealthNotListening
		}
	case breakerOpen || p.obs.failStreak.Load() >= notRespondingFailures:
		st.Health = HealthNotResponding
	}
	return st
}

func (p *Plugin) startGraceOrDefault() time.Duration {
	if p.startGrace > 0 {
		return p.startGrace
	}
	return defaultStartGrace
}

func (p *Plugin) counters() PluginCounters {
	o := &p.obs
	return PluginCounters{
		Calls:            o.calls.Load(),
		CallFailures:     o.callFails.Load(),
		CallTimeouts:     o.callTimeouts.Load(),
		BreakerOpens:     o.breakerOpens.Load(),
		CaptureRequests:  o.captureCalls.Load(),
		CaptureFailures:  o.captureFails.Load(),
		CaptureRejected:  o.captureRejected.Load(),
		EventsSent:       o.eventsSent.Load(),
		EventsFailed:     o.eventsFailed.Load(),
		EventsDropped:    o.eventsDropped.Load(),
		EventsQueued:     p.evq.length(),
		LogLines:         o.logLines.Load(),
		LogLinesDropped:  o.logDropped.Load(),
		PassedWhileDown:  o.passedWhileDown.Load(),
		BlockedWhileDown: o.blockedWhileDown.Load(),
		HealthChecksOK:   o.healthOK.Load(),
		HealthChecksFail: o.healthFailTotal.Load(),
	}
}

/* JSON views */

// pluginView is what the API returns for a plugin. The first five fields are the
// historical shape of the Plugin struct, HookAdmin and Status are additions.
type pluginView struct {
	RootDir           string
	Spec              *dunreePlugin.IntroSpect
	Enabled           bool
	AssignedPort      int
	SupportHotRebuild bool
	HookAdmin         HookAdminState
	Status            PluginStatus
}

func viewOf(p *Plugin) pluginView {
	p.mu.RLock()
	v := pluginView{
		RootDir:           p.RootDir,
		Spec:              p.Spec,
		Enabled:           p.Enabled,
		AssignedPort:      p.AssignedPort,
		SupportHotRebuild: p.SupportHotRebuild,
	}
	p.mu.RUnlock()
	v.HookAdmin = p.hookAdminState()
	v.Status = p.Status()
	return v
}

// MarshalJSON gives every JSON output of a plugin the same race-free snapshot
func (p *Plugin) MarshalJSON() ([]byte, error) {
	return json.Marshal(viewOf(p))
}

/* Load failures: plugin folders that could not be loaded (introspect failed) */

// LoadFailure describes a folder in the plugin directory that is not a loadable plugin
type LoadFailure struct {
	Folder string //folder name inside the plugin directory
	Error  string
	Time   int64
}

func (m *Manager) noteLoadFailure(folder string, err error) {
	m.loadFailuresMutex.Lock()
	if m.loadFailures == nil {
		m.loadFailures = map[string]LoadFailure{}
	}
	m.loadFailures[folder] = LoadFailure{Folder: folder, Error: err.Error(), Time: time.Now().Unix()}
	m.loadFailuresMutex.Unlock()
}

func (m *Manager) clearLoadFailure(folder string) {
	m.loadFailuresMutex.Lock()
	delete(m.loadFailures, folder)
	m.loadFailuresMutex.Unlock()
}

// ListLoadFailures returns the plugin folders that failed to load, sorted by folder name
func (m *Manager) ListLoadFailures() []LoadFailure {
	m.loadFailuresMutex.Lock()
	out := make([]LoadFailure, 0, len(m.loadFailures))
	for _, f := range m.loadFailures {
		out = append(out, f)
	}
	m.loadFailuresMutex.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Folder < out[j].Folder })
	return out
}

/* Admin API */

type pluginStatusDetail struct {
	ID           string
	Name         string
	Status       PluginStatus
	RecentOutput []string     `json:",omitempty"` //last output lines of the plugin (POST only, may contain anything the plugin printed)
	ExitHistory  []ExitRecord `json:",omitempty"` //last exits of the plugin, oldest first (POST only)
	LogFile      string       `json:",omitempty"` //per plugin log file, when the policy uses one (POST only)
}

// HandlePluginStatus is the read-only status API of the admin UI (not offered to plugins).
// GET: every plugin with its status plus the folders that failed to load.
// GET ?plugin_id=<id>: the status of one plugin.
// POST plugin_id=<id>: the same plus the last output lines of the plugin. Output can
// hold anything the plugin printed, so it needs a POST: read-only (viewer) accounts
// are refused every POST that is not explicitly allowed for them.
// probe=true (any of the three): also look whether the port of each running plugin
// accepts a TCP connection (at most once per 2 s per plugin, no HTTP request). The
// Plugin Manager page sends it while it is shown; nothing else does.
func (m *Manager) HandlePluginStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		pluginID, err := utils.PostPara(r, "plugin_id")
		if err != nil {
			utils.SendErrorResponse(w, "plugin_id not found")
			return
		}
		p, err := m.GetPluginByID(pluginID)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		probe, _ := utils.PostPara(r, "probe")
		detail := pluginStatusDetail{ID: p.Spec.ID, Name: p.Spec.Name, Status: p.statusWith(probe == "true"), RecentOutput: p.recentOutput(), ExitHistory: p.sup.historyCopy()}
		if p.policy().LogTarget == LogTargetFile {
			detail.LogFile = m.pluginLogPath(p)
		}
		js, _ := json.Marshal(detail)
		utils.SendJSONResponse(w, string(js))
		return
	}
	probeArg, _ := utils.GetPara(r, "probe")
	probe := probeArg == "true"
	if pluginID, err := utils.GetPara(r, "plugin_id"); err == nil {
		p, err := m.GetPluginByID(pluginID)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		js, _ := json.Marshal(pluginStatusDetail{ID: p.Spec.ID, Name: p.Spec.Name, Status: p.statusWith(probe)})
		utils.SendJSONResponse(w, string(js))
		return
	}
	list, _ := m.ListLoadedPlugins()
	sort.Slice(list, func(i, j int) bool { return list[i].Spec.Name < list[j].Spec.Name })
	resp := struct {
		Plugins      []pluginStatusDetail
		LoadFailures []LoadFailure
	}{Plugins: make([]pluginStatusDetail, 0, len(list)), LoadFailures: m.ListLoadFailures()}
	for _, p := range list {
		resp.Plugins = append(resp.Plugins, pluginStatusDetail{ID: p.Spec.ID, Name: p.Spec.Name, Status: p.statusWith(probe)})
	}
	js, _ := json.Marshal(resp)
	utils.SendJSONResponse(w, string(js))
}
