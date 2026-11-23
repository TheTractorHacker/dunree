package plugins

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Plugin policy (phase 1 of docs/plugins/reliability-plan.md)

	What the administrator allows Zoraxy to do about one plugin: restart it, check
	its health, block traffic while it is down, limit what it may use. The zero
	value is exactly the behaviour from before these options existed: no restart,
	no probe, fail-open, no limit, output into the main log.
*/

// Restart policies
const (
	RestartNever     = "never"      //default: a plugin that stopped by itself stays stopped
	RestartOnFailure = "on-failure" //restart after a crash (non-zero exit code or signal)
	RestartAlways    = "always"     //restart after every exit the administrator did not ask for
)

// Health check modes
const (
	HealthCheckOff     = "off"     //default: Zoraxy never connects to the plugin only to look at it
	HealthCheckReport  = "report"  //probe and show the result
	HealthCheckRestart = "restart" //probe, and end a plugin that fails the probe so the restart policy starts it again
)

// Where the output of the plugin goes
const (
	LogTargetMain = "main" //default: every line into the main Zoraxy log
	LogTargetFile = "file" //own size-limited file per plugin
)

var errLimitsLinuxOnly = errors.New("resource limits for plugins are only available on Linux")

const (
	policyDBTable       = "plugin_policy"
	defaultPluginLogKB  = 1024
	minCaptureTimeoutMs = 100
	maxCaptureTimeoutMs = 600000
)

// PluginPolicy holds the per plugin settings. Field names are the API.
type PluginPolicy struct {
	Restart          string //never | on-failure | always
	ReadinessGate    bool   //attach the plugin to the request path only once its port accepts connections
	HealthCheck      string //off | report | restart
	BlockWhenDown    bool   //fail-closed also while the plugin is not running (needs fail_closed in the manifest and the consent of the administrator)
	CaptureTimeoutMs int    //0 = off. Time the plugin gets to start answering a captured request or a UI request; also turns on the circuit breaker of those paths
	LogTarget        string //main | file
	LogMaxKB         int    //size of the per plugin log file before it is rotated (one old file is kept)
	LogRateLimit     int    //lines per second that are kept, 0 = no limit (lines are only counted)
	MemoryMaxMB      int    //Linux + systemd only, 0 = no limit
	CPUQuotaPercent  int    //Linux + systemd only, 100 = one core, 0 = no limit
	TasksMax         int    //Linux + systemd only, processes and threads, 0 = no limit
	MaxOpenFiles     int    //Linux only (RLIMIT_NOFILE), 0 = unchanged
}

// normalized fills the defaults into the empty fields
func (pp PluginPolicy) normalized() PluginPolicy {
	if pp.Restart == "" {
		pp.Restart = RestartNever
	}
	if pp.HealthCheck == "" {
		pp.HealthCheck = HealthCheckOff
	}
	if pp.LogTarget == "" {
		pp.LogTarget = LogTargetMain
	}
	if pp.LogMaxKB <= 0 {
		pp.LogMaxKB = defaultPluginLogKB
	}
	return pp
}

func (pp PluginPolicy) hasLimits() bool {
	return pp.MemoryMaxMB > 0 || pp.CPUQuotaPercent > 0 || pp.TasksMax > 0 || pp.MaxOpenFiles > 0
}

func (pp PluginPolicy) hasCgroupLimits() bool {
	return pp.MemoryMaxMB > 0 || pp.CPUQuotaPercent > 0 || pp.TasksMax > 0
}

func inRange(v, lo, hi int) bool { return v == 0 || (v >= lo && v <= hi) }

// validate checks a policy for a plugin. The plugin is needed for the options that depend on its manifest.
func (pp PluginPolicy) validate(p *Plugin) error {
	switch pp.Restart {
	case RestartNever, RestartOnFailure, RestartAlways:
	default:
		return errors.New("restart policy must be never, on-failure or always")
	}
	switch pp.HealthCheck {
	case HealthCheckOff, HealthCheckReport:
	case HealthCheckRestart:
		if pp.Restart == RestartNever {
			return errors.New("the health check can only end a plugin when the restart policy is on-failure or always: otherwise it would stay stopped")
		}
	default:
		return errors.New("health check must be off, report or restart")
	}
	switch pp.LogTarget {
	case LogTargetMain, LogTargetFile:
	default:
		return errors.New("log target must be main or file")
	}
	if pp.BlockWhenDown {
		declared := p.Spec != nil && p.Spec.Hooks != nil && p.Spec.Hooks.FailurePolicy == zoraxyPlugin.FailureClosed
		if !declared {
			return errors.New("plugin does not declare fail_closed in its manifest")
		}
		if !p.failsClosed() {
			return errors.New("allow the plugin to block requests when it fails (fail-closed) first")
		}
	}
	switch {
	case !inRange(pp.CaptureTimeoutMs, minCaptureTimeoutMs, maxCaptureTimeoutMs):
		return errors.New("capture timeout must be 0 (off) or between 100 and 600000 ms")
	case pp.LogMaxKB < 16 || pp.LogMaxKB > 1024*1024:
		return errors.New("log file size must be between 16 and 1048576 KiB")
	case !inRange(pp.LogRateLimit, 1, 100000):
		return errors.New("log rate limit must be 0 (off) or between 1 and 100000 lines per second")
	case !inRange(pp.MemoryMaxMB, 16, 1024*1024):
		return errors.New("memory limit must be 0 (off) or at least 16 MB")
	case !inRange(pp.CPUQuotaPercent, 1, 6400):
		return errors.New("CPU limit must be 0 (off) or between 1 and 6400 percent")
	case !inRange(pp.TasksMax, 4, 1000000):
		return errors.New("task limit must be 0 (off) or at least 4")
	case !inRange(pp.MaxOpenFiles, 16, 1048576):
		return errors.New("open file limit must be 0 (off) or between 16 and 1048576")
	}
	return nil
}

// policy returns the current policy of the plugin with defaults filled in
func (p *Plugin) policy() PluginPolicy {
	p.polMu.RLock()
	defer p.polMu.RUnlock()
	return p.pol.normalized()
}

// loadPluginPolicy restores the policy of a plugin from the database
func (m *Manager) loadPluginPolicy(p *Plugin) {
	if m.Options == nil || m.Options.Database == nil || m.Options.Database.Backend == nil {
		return
	}
	var rec PluginPolicy
	if err := m.Options.Database.Read(policyDBTable, p.Spec.ID, &rec); err != nil {
		return
	}
	rec = rec.normalized()
	// A stored policy that is no longer valid (edited database, manifest changed by an
	// update) must never make the plugin stricter than its manifest allows
	if rec.BlockWhenDown && (p.Spec.Hooks == nil || p.Spec.Hooks.FailurePolicy != zoraxyPlugin.FailureClosed) {
		rec.BlockWhenDown = false
	}
	switch rec.Restart {
	case RestartNever, RestartOnFailure, RestartAlways:
	default:
		rec.Restart = RestartNever
	}
	p.polMu.Lock()
	p.pol = rec
	p.polMu.Unlock()
}

// SetPluginPolicy changes the policy of a plugin. change gets the current policy and edits it.
// Restart policy, block-when-down and the capture timeout apply at once; readiness gate,
// health check, log target and limits apply when the plugin is started the next time.
func (m *Manager) SetPluginPolicy(pluginID string, change func(pp *PluginPolicy)) error {
	p, err := m.GetPluginByID(pluginID)
	if err != nil {
		return err
	}
	// Under the start / stop lock: a pending automatic restart reads the policy
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	next := p.policy()
	before := next
	change(&next)
	next = next.normalized()
	if err := next.validate(p); err != nil {
		return err
	}
	p.polMu.Lock()
	p.pol = next
	p.polMu.Unlock()

	if m.Options != nil && m.Options.Database != nil && m.Options.Database.Backend != nil {
		m.Options.Database.NewTable(policyDBTable)
		if err := m.Options.Database.Write(policyDBTable, pluginID, next); err != nil {
			return err
		}
	}

	if next.Restart == RestartNever && before.Restart != RestartNever {
		//A restart that is already waiting must not happen any more
		m.cancelPendingRestart(p, "the restart policy was set to never")
	}
	if next.CaptureTimeoutMs != before.CaptureTimeoutMs {
		m.rebuildProxies(p)
	}
	return nil
}

// rebuildProxies creates the UI / capture proxies of a running plugin again so a new capture timeout applies
func (m *Manager) rebuildProxies(p *Plugin) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proc == nil || p.AssignedPort == 0 {
		return
	}
	m.startUIHandlerLocked(p, p.AssignedPort)
	p.startAllStaticPathRoutersLocked()
	if p.AcceptDynamicRoute() {
		p.startDynamicForwardRouterLocked()
	}
}

/* Admin API */

type pluginPolicyView struct {
	ID                 string
	Policy             PluginPolicy
	FailClosedDeclared bool   //block-when-down can only be used by such a plugin
	FailClosedConsent  bool   //and only with this consent
	HealthPath         string //health endpoint from the manifest, empty = TCP connect
	ConfigureVia       string //"stdin" when the secrets of the plugin are not on its command line
	LimitsSupport      string //what this host can enforce: "systemd" | "rlimit" | "none"
	LimitsNote         string //why, in words
}

func (m *Manager) policyViewOf(p *Plugin) pluginPolicyView {
	admin := p.hookAdminState()
	support, note := m.limitsSupport()
	return pluginPolicyView{
		ID:                 p.Spec.ID,
		Policy:             p.policy(),
		FailClosedDeclared: admin.FailClosedDeclared,
		FailClosedConsent:  admin.FailClosedConsent,
		HealthPath:         p.Spec.HealthPath,
		ConfigureVia:       p.Spec.ConfigureVia,
		LimitsSupport:      support,
		LimitsNote:         note,
	}
}

// HandlePluginPolicy is the admin API of the per plugin policy.
// GET ?plugin_id=<id>: the policy and what this host supports.
// POST plugin_id=<id> plus any of restart, readiness_gate, health_check, block_when_down,
// capture_timeout_ms, log_target, log_max_kb, log_rate_limit, memory_max_mb,
// cpu_quota_percent, tasks_max, max_open_files: change those values.
func (m *Manager) HandlePluginPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		pluginID, err := utils.GetPara(r, "plugin_id")
		if err != nil {
			utils.SendErrorResponse(w, "plugin_id not found")
			return
		}
		p, err := m.GetPluginByID(pluginID)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		js, _ := json.Marshal(m.policyViewOf(p))
		utils.SendJSONResponse(w, string(js))
		return
	}
	pluginID, err := utils.PostPara(r, "plugin_id")
	if err != nil {
		utils.SendErrorResponse(w, "plugin_id not found")
		return
	}
	var parseErr error
	str := func(name string, dst *string) {
		if v, err := utils.PostPara(r, name); err == nil {
			*dst = v
		}
	}
	boolean := func(name string, dst *bool) {
		if v, err := utils.PostPara(r, name); err == nil {
			*dst = v == "true"
		}
	}
	num := func(name string, dst *int) {
		if v, err := utils.PostPara(r, name); err == nil {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				parseErr = errors.New(name + " must be a whole number, 0 or more")
				return
			}
			*dst = n
		}
	}
	err = m.SetPluginPolicy(pluginID, func(pp *PluginPolicy) {
		str("restart", &pp.Restart)
		boolean("readiness_gate", &pp.ReadinessGate)
		str("health_check", &pp.HealthCheck)
		boolean("block_when_down", &pp.BlockWhenDown)
		num("capture_timeout_ms", &pp.CaptureTimeoutMs)
		str("log_target", &pp.LogTarget)
		num("log_max_kb", &pp.LogMaxKB)
		num("log_rate_limit", &pp.LogRateLimit)
		num("memory_max_mb", &pp.MemoryMaxMB)
		num("cpu_quota_percent", &pp.CPUQuotaPercent)
		num("tasks_max", &pp.TasksMax)
		num("max_open_files", &pp.MaxOpenFiles)
		if parseErr != nil {
			//Make the validation fail with the parse error instead of storing half of the request
			pp.Restart = "invalid"
		}
	})
	if parseErr != nil {
		utils.SendErrorResponse(w, parseErr.Error())
		return
	}
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleRestartPlugin stops and starts a plugin (admin API, POST plugin_id). It also
// clears a crash loop, like the Start button does.
func (m *Manager) HandleRestartPlugin(w http.ResponseWriter, r *http.Request) {
	pluginID, err := utils.PostPara(r, "plugin_id")
	if err != nil {
		utils.SendErrorResponse(w, "plugin_id not found")
		return
	}
	if err := m.StopPlugin(pluginID); err != nil && !errors.Is(err, ErrPluginNotRunning) {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := m.EnablePlugin(pluginID); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
