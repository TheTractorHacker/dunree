package plugins

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/eventsystem"
	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin/events"
)

// StartPlugin starts the process of a plugin and attaches its routes, hooks and events.
// A failed attempt is recorded in the status of the plugin (state "failed_to_start").
func (m *Manager) StartPlugin(pluginID string) error {
	thisPlugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		return err
	}

	//One start / stop at a time per plugin
	thisPlugin.lifeMu.Lock()
	defer thisPlugin.lifeMu.Unlock()

	if thisPlugin.IsRunning() {
		//Starting it again would leave the first process running without an owner
		return errors.New("plugin is already running")
	}
	// A start by the administrator (or an update / rebuild) voids a waiting automatic
	// restart and ends a crash loop
	thisPlugin.sup.resetByAdmin()
	// From here on the plugin is meant to run. When this start fails it is "down"
	// (failed to start) and not "stopped on purpose", so block-while-not-running
	// applies to it, also after a Stop, an update or a rebuild that came before.
	thisPlugin.mu.Lock()
	thisPlugin.wantDown = false
	thisPlugin.mu.Unlock()

	err = m.startPluginProcess(thisPlugin)
	if err != nil {
		thisPlugin.noteStartFailure(err)
		m.revokePluginAPIKeys(thisPlugin)
		return err
	}
	// Every stop and exit removes the capture paths of the plugin from the tag maps,
	// so every start has to put them back (not only EnablePlugin).
	m.UpdateTagsToPluginMaps()
	return nil
}

func (m *Manager) startPluginProcess(thisPlugin *Plugin) error {
	pluginID := thisPlugin.Spec.ID

	// Contract version: a plugin built for a contract this Zoraxy does not support is
	// started anyway (and logged) unless the administrator asked to refuse such plugins
	if err := m.checkContractForStart(thisPlugin); err != nil {
		return err
	}

	//Get the plugin Entry point
	pluginEntryPoint, err := m.GetPluginEntryPoint(thisPlugin.RootDir)
	if err != nil {
		//Plugin removed after introspect?
		return err
	}

	//Get the absolute path of the plugin entry point to prevent messing up with the cwd
	absolutePath, err := filepath.Abs(pluginEntryPoint)
	if err != nil {
		return err
	}

	// Signed index: is the binary still the one that was installed? Only for plugins
	// with an install record. warn (default): logged and shown. enforce: not started.
	if err := m.checkBinaryForStart(thisPlugin, absolutePath); err != nil {
		return err
	}

	//Prepare plugin start configuration
	pluginConfiguration := zoraxyPlugin.ConfigureSpec{
		Port:         getRandomPortNumber(),
		RuntimeConst: *m.Options.SystemConst,
	}
	if thisPlugin.Spec.APIVersion >= 1 {
		// A plugin that declares a contract version is told which versions this Zoraxy
		// supports. A legacy plugin gets byte for byte the payload it always got.
		pluginConfiguration.APIVersionMin = ContractVersionMin
		pluginConfiguration.APIVersionMax = ContractVersionMax
	}

	//Secret that proves to the plugin that a call comes from Zoraxy (filter / sniff / capture)
	invokeToken, err := thisPlugin.generateInvokeToken()
	if err != nil {
		return err
	}
	pluginConfiguration.InvokeToken = invokeToken

	// A key of an earlier process of this plugin must not outlive it
	m.revokePluginAPIKeys(thisPlugin)

	// Generate API key if the plugin has permitted endpoints
	if len(thisPlugin.Spec.PermittedAPIEndpoints) > 0 {
		if m.Options.APIKeyManager == nil {
			return errors.New("plugin asks for Zoraxy API access but no API key manager is configured")
		}
		// Default: every endpoint of the manifest, as always. With "require approval"
		// (opt-in) only the endpoints the administrator approved; the plugin still gets
		// a key, so its calls are answered "not permitted" and not "invalid key".
		granted := m.grantedEndpoints(thisPlugin)
		if withheld := len(requestedKeys(thisPlugin.Spec)) - len(granted); withheld > 0 {
			m.Log("plugin "+pluginID+": "+strconv.Itoa(withheld)+" of the API permissions it asks for are not granted, they wait for an approval in the Plugin Manager", nil)
		}
		apiKey, err := m.Options.APIKeyManager.GenerateAPIKey(thisPlugin.Spec.ID, granted)
		if err != nil {
			return err
		}
		pluginConfiguration.APIKey = apiKey.APIKey
		pluginConfiguration.ZoraxyPort = m.Options.ZoraxyPort
		m.Log("Generated API key for plugin "+thisPlugin.Spec.Name, nil)
	}

	js, _ := json.Marshal(pluginConfiguration)
	pol := thisPlugin.policy()

	//Start the plugin with given configuration
	m.Log("Starting plugin "+thisPlugin.Spec.Name+" at :"+strconv.Itoa(pluginConfiguration.Port), nil)
	// The configuration holds secrets (API key, invoke token). A plugin whose manifest
	// says configure_via = stdin reads it from its standard input, so it is not visible
	// in the process list. Every other plugin gets it on the command line, as always.
	viaStdin := thisPlugin.Spec.ConfigureVia == zoraxyPlugin.ConfigureViaStdin
	cmd := exec.Command(absolutePath, "-configure="+string(js))
	if viaStdin {
		cmd = exec.Command(absolutePath, zoraxyPlugin.ConfigureStdinFlag)
	}
	cmd.Dir = filepath.Dir(absolutePath)
	if err := m.applyRunAs(cmd, absolutePath); err != nil { //optional -plugin_user, see runas_unix.go
		return err
	}
	setProcessGroup(cmd) //a stop reaches the children of the plugin too
	limitsNote, limitsProblem := m.wrapWithLimits(cmd, pluginID, pol)
	if limitsProblem != "" {
		m.Log("plugin "+pluginID+": "+limitsProblem, nil)
	}
	var stdinR, stdinW *os.File
	if viaStdin {
		stdinR, stdinW, err = os.Pipe()
		if err != nil {
			return err
		}
		cmd.Stdin = stdinR
	}
	closeStdin := func() {
		if stdinR != nil {
			stdinR.Close()
			stdinW.Close()
		}
	}

	// The output goes through pipes owned by Zoraxy (not cmd.StdoutPipe), so cmd.Wait
	// returns as soon as the plugin process itself ends, even when a child of the
	// plugin keeps the pipe open, and never races with the readers.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		closeStdin()
		return err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		closeStdin()
		stdoutR.Close()
		stdoutW.Close()
		return err
	}
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	err = cmd.Start()
	//The child has its own copy of the write ends
	stdoutW.Close()
	stderrW.Close()
	if err != nil {
		closeStdin()
		stdoutR.Close()
		stderrR.Close()
		return err
	}
	if viaStdin {
		// The payload is far smaller than a pipe buffer, so this cannot block on a
		// plugin that never reads it
		stdinR.Close()
		stdinW.Write(append(js, '\n'))
		stdinW.Close()
	}
	if note, rerr := applyRlimits(cmd.Process.Pid, pol); rerr != nil {
		limitsProblem = strings.TrimSpace(limitsProblem + " " + rerr.Error())
		m.Log("plugin "+pluginID+": "+rerr.Error(), nil)
	} else if note != "" {
		limitsNote = strings.TrimSpace(limitsNote + " " + note)
	}
	m.openPluginLog(thisPlugin, pol)

	// The output readers below belong to exactly this process. Pass its PID to
	// them instead of reading shared plugin state, which may already belong to a
	// newer process after a restart.
	pid := cmd.Process.Pid
	procCtx, procCancel := context.WithCancel(context.Background())
	proc := &pluginProc{
		cmd:         cmd,
		pid:         pid,
		done:        make(chan struct{}),
		readersDone: make(chan struct{}),
		startedAt:   time.Now(),
		ctx:         procCtx,
		cancel:      procCancel,
	}
	if limitsNote != "" && pol.MemoryMaxMB > 0 && strings.Contains(limitsNote, "memory") {
		proc.memLimitMB = pol.MemoryMaxMB
	}
	proc.logLimit.perSecond = pol.LogRateLimit

	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		defer stdoutR.Close()
		readPluginOutput(stdoutR, func(line string) { m.pluginOutput(pluginID, proc, "out", line) })
	}()
	go func() {
		defer readers.Done()
		defer stderrR.Close()
		readPluginOutput(stderrR, func(line string) { m.pluginOutput(pluginID, proc, "err", line) })
	}()
	go func() {
		readers.Wait()
		close(proc.readersDone)
	}()

	// Publish the running state before the exit watcher starts, so a plugin that
	// dies immediately is recorded as crashed and not overwritten as "running".
	now := time.Now()
	thisPlugin.mu.Lock()
	thisPlugin.proc = proc
	thisPlugin.wantDown = false
	thisPlugin.mgr = m
	thisPlugin.Enabled = true
	thisPlugin.AssignedPort = pluginConfiguration.Port
	thisPlugin.status.state = StateRunning
	thisPlugin.status.pid = pid
	thisPlugin.status.startedAt = now
	thisPlugin.status.startCount++
	thisPlugin.status.probePort = m.Options != nil && m.Options.ProbePluginPorts
	// Readiness gate (opt-in): the plugin joins the request path only when its port
	// answers. Without it the plugin is attached at once, as always.
	watch := pol.ReadinessGate || pol.HealthCheck != HealthCheckOff
	thisPlugin.notReady = pol.ReadinessGate
	thisPlugin.status.watched = watch
	thisPlugin.status.readyKnown = false
	thisPlugin.status.readyAfter = 0
	thisPlugin.status.limitsNote = limitsNote
	thisPlugin.status.limitsProblem = limitsProblem
	thisPlugin.status.healthFailLimit = m.supCfg.healthFailures()
	//Create a UI forwarder if the plugin has UI
	uiErr := m.startUIHandlerLocked(thisPlugin, pluginConfiguration.Port)
	//Create a new static forwarder router for each of the static capture paths
	thisPlugin.startAllStaticPathRoutersLocked()
	//If the plugin contains dynamic capture, create a dynamic capture handler
	if thisPlugin.AcceptDynamicRoute() {
		thisPlugin.startDynamicForwardRouterLocked()
	}
	thisPlugin.mu.Unlock()
	thisPlugin.obs.failStreak.Store(0)
	thisPlugin.obs.healthFails.Store(0)
	thisPlugin.capBreaker.reset()
	thisPlugin.obs.probeAt.Store(0)
	thisPlugin.obs.lastSeen.Store(now.UnixNano())

	// Register event subscriptions
	if thisPlugin.Spec.SubscriptionsEvents != nil && eventsystem.Publisher != nil {
		for eventName := range thisPlugin.Spec.SubscriptionsEvents {
			eventType := events.EventName(eventName)
			if !eventType.IsValid() {
				m.Log("Invalid event name: "+string(eventName), nil)
				continue
			}
			err := eventsystem.Publisher.RegisterSubscriberToEvent(thisPlugin, eventType)
			if err != nil {
				m.Log("Failed to subscribe plugin "+thisPlugin.Spec.Name+" to event "+string(eventName), err)
			} else {
				m.Log("Subscribed plugin "+thisPlugin.Spec.Name+" to event "+string(eventName), nil)
			}
		}
	}

	//Watch the process: every exit is handled, with or without an error
	go func() {
		// Also ends what is left of the process group (see waitPluginProcess)
		waitErr := waitPluginProcess(proc)
		// Decide now whether this exit was asked for. A stop that arrives while the
		// last output is drained must not turn a crash into a plain "stopped".
		requested := proc.stopRequested.Load()
		m.onPluginExit(thisPlugin, proc, waitErr, requested)
	}()

	if uiErr != nil {
		//The process runs but its UI path is not usable: stop it again and report the start as failed
		m.stopProcess(thisPlugin, proc)
		m.detachPlugin(thisPlugin, proc)
		return uiErr
	}
	if watch {
		go m.watchProcess(thisPlugin, proc, pol, pluginConfiguration.Port)
	}

	return nil
}

// readPluginOutput reads the output of a plugin line by line. A line longer than
// maxPluginLineBytes is cut and the rest of that line is dropped, so a plugin
// that never prints a newline cannot grow Zoraxy's memory.
func readPluginOutput(r io.Reader, emit func(line string)) {
	br := bufio.NewReaderSize(r, maxPluginLineBytes)
	skipping := false
	for {
		chunk, err := br.ReadSlice('\n')
		switch {
		case err == bufio.ErrBufferFull:
			if !skipping {
				emit(string(chunk) + " [line cut at " + strconv.Itoa(maxPluginLineBytes) + " bytes]")
				skipping = true
			}
			continue
		case skipping:
			//The tail of an over-long line
			if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
				skipping = false
			}
		case len(chunk) > 0:
			emit(strings.TrimRight(string(chunk), "\r\n"))
		}
		if err != nil {
			return
		}
	}
}

// onPluginExit runs once for every plugin process that ends, whatever the reason.
// requested says whether Zoraxy had asked for the stop when the process ended.
func (m *Manager) onPluginExit(p *Plugin, proc *pluginProc, waitErr error, requested bool) {
	//Give the readers a moment to drain the last lines the process wrote
	select {
	case <-proc.readersDone:
	case <-time.After(300 * time.Millisecond):
	}

	exitCode := -1
	reason := ""
	if ps := proc.cmd.ProcessState; ps != nil {
		exitCode = ps.ExitCode()
		reason = ps.String()
	} else if waitErr != nil {
		reason = waitErr.Error()
	}
	proc.cancel() //ends event deliveries and probes that are still talking to this process
	ranFor := time.Since(proc.startedAt)
	kind := StateCrashed
	problem := "The plugin process ended unexpectedly (" + reason + ")"
	switch why := proc.unhealthyWhy.Load(); {
	case requested:
		kind = StateStopped
	case why != nil:
		kind = "unhealthy"
		problem = "Zoraxy ended the plugin because " + *why + " (" + reason + ")"
	case exitCode == 0:
		kind = StateExited
		problem = "The plugin stopped by itself (" + reason + ")"
	case exitCode == -1 && proc.memLimitMB > 0 && strings.Contains(reason, "killed"):
		problem = "The plugin process was killed (" + reason + "). It runs with a memory limit of " + strconv.Itoa(proc.memLimitMB) + " MB, so this was most likely the kernel ending it at that limit"
	}
	if m.exitDrainHook != nil {
		m.exitDrainHook() //tests only
	}

	p.mu.Lock()
	current := p.proc == proc
	if current {
		p.status.exitedAt = time.Now()
		p.status.hasExited = true
		p.status.exitCode = exitCode
		p.status.exitReason = reason
		p.status.pid = 0
		switch {
		case requested:
			p.status.state = StateStopped
		case kind == StateExited:
			p.status.state = StateExited
			p.status.lastError = problem
			p.status.lastErrorAt = p.status.exitedAt
		default:
			p.status.state = StateCrashed
			p.status.lastError = problem
			p.status.lastErrorAt = p.status.exitedAt
		}
	}
	p.mu.Unlock()
	if current {
		p.sup.addHistory(ExitRecord{At: time.Now().Unix(), Kind: kind, ExitCode: exitCode, Reason: reason, UptimeSec: int64(ranFor / time.Second)})
	}
	close(proc.done)

	if !current {
		return
	}
	if !requested {
		if exitCode == 0 {
			m.Log("plugin "+p.Spec.ID+" exited by itself ("+reason+"). Disabling plugin...", nil)
		} else {
			//In theory this should not happen except for a crash
			m.Log("plugin "+p.Spec.ID+" encounted a fatal error. Disabling plugin...", errors.New(reason))
		}
	}
	// Detach under the start / stop lock of the plugin. Without it a StartPlugin
	// that runs between close(proc.done) and here would get its new API key and
	// event subscriptions removed by this (old) detach. No deadlock: StopPlugin and
	// the failed-UI path of StartPlugin hold the lock while they wait on proc.done,
	// which is closed above; when they are done this detach is a no-op.
	p.lifeMu.Lock()
	detached := m.detachPlugin(p, proc)
	if detached && !requested {
		// Still the process this exit belongs to, and nobody asked for the exit: the
		// restart policy decides (default never: only a log line)
		m.superviseFailure(p, exitCode != 0, ranFor)
	}
	p.lifeMu.Unlock()
}

// detachPlugin removes everything that points at the process of a plugin: enabled
// flag, UI proxy, capture routers, API key, event subscriptions and the tag maps.
// It is safe to call more than once; it does nothing when proc is no longer the
// current process of the plugin (a newer start owns the state).
func (m *Manager) detachPlugin(p *Plugin, proc *pluginProc) bool {
	p.mu.Lock()
	if p.proc != proc {
		p.mu.Unlock()
		return false
	}
	p.proc = nil
	p.Enabled = false
	p.notReady = false
	p.uiProxy = nil
	p.staticRouteProxy = make(map[string]*dpcore.ReverseProxy)
	p.dynamicRouteProxy = nil
	if p.status.state == StateRunning {
		p.status.state = StateStopped
		p.status.pid = 0
	}
	p.mu.Unlock()

	m.revokePluginAPIKeys(p)
	//Unsubscribe from all events
	if eventsystem.Publisher != nil {
		if err := eventsystem.Publisher.UnregisterSubscriber(eventsystem.ListenerID(p.Spec.ID)); err != nil {
			m.Log("Failed to unsubscribe plugin "+p.Spec.Name+" from events", err)
		}
	}
	//Events that were still waiting were meant for this process
	p.evq.clear(&p.obs)
	//Generate a new static forwarder radix tree
	m.UpdateTagsToPluginMaps()
	return true
}

func (m *Manager) revokePluginAPIKeys(p *Plugin) {
	if m.Options == nil || m.Options.APIKeyManager == nil {
		return
	}
	if err := m.Options.APIKeyManager.RevokeAPIKeysForPlugin(p.Spec.ID); err != nil {
		m.Log("Failed to revoke API keys for plugin "+p.Spec.Name, err)
	}
}

// StartUIHandlerForPlugin starts a UI handler for the plugin
func (m *Manager) StartUIHandlerForPlugin(targetPlugin *Plugin, pluginListeningPort int) error {
	targetPlugin.mu.Lock()
	defer targetPlugin.mu.Unlock()
	return m.startUIHandlerLocked(targetPlugin, pluginListeningPort)
}

func (m *Manager) startUIHandlerLocked(targetPlugin *Plugin, pluginListeningPort int) error {
	// Create a dpcore object to reverse proxy the plugin ui
	pluginUIRelPath := targetPlugin.Spec.UIPath
	if !strings.HasPrefix(pluginUIRelPath, "/") {
		pluginUIRelPath = "/" + pluginUIRelPath
	}

	// Remove the trailing slash if it exists
	pluginUIRelPath = strings.TrimSuffix(pluginUIRelPath, "/")

	pluginUIURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(pluginListeningPort) + pluginUIRelPath)
	if err != nil {
		return err
	}

	// Generate the plugin subpath to be trimmed
	pluginMatchingPath := filepath.ToSlash(filepath.Join("/plugin.ui/"+targetPlugin.Spec.ID+"/")) + "/"
	if targetPlugin.Spec.UIPath != "" {
		targetPlugin.uiProxy = dpcore.NewDynamicProxyCore(
			pluginUIURL,
			pluginMatchingPath,
			targetPlugin.captureProxyOptions(),
		)
		targetPlugin.AssignedPort = pluginListeningPort
	}
	return nil
}

// handlePluginSTDOUT logs one stdout line of the plugin process with the given
// PID. The PID is passed in by the reader goroutine that owns the process, so
// no shared plugin state is read concurrently with StartPlugin.
func (m *Manager) handlePluginSTDOUT(pluginID string, processID int, line string) {
	thisPlugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		m.Log("[unknown:"+strconv.Itoa(processID)+"] "+line, err)
		return
	}
	m.routePluginOutput(thisPlugin, nil, processID, "out", line)
}

// handlePluginSTDERR logs one stderr line of the plugin process with the given PID.
func (m *Manager) handlePluginSTDERR(pluginID string, processID int, line string) {
	thisPlugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		return
	}
	m.routePluginOutput(thisPlugin, nil, processID, "err", line)
}

// pluginOutput handles one output line of a plugin process (called by its reader goroutines)
func (m *Manager) pluginOutput(pluginID string, proc *pluginProc, stream string, line string) {
	thisPlugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		if stream == "out" {
			m.Log("[unknown:"+strconv.Itoa(proc.pid)+"] "+line, err)
		}
		return
	}
	m.routePluginOutput(thisPlugin, proc, proc.pid, stream, line)
}

// StopPlugin stops a plugin, it is garanteed that the plugin is stopped after this function.
// Stopping a plugin that is not running returns ErrPluginNotRunning and changes nothing.
func (m *Manager) StopPlugin(pluginID string) error {
	thisPlugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		return err
	}

	//One start / stop at a time per plugin
	thisPlugin.lifeMu.Lock()
	defer thisPlugin.lifeMu.Unlock()
	return m.stopPluginLocked(thisPlugin)
}

// stopPluginLocked is StopPlugin for a caller that holds lifeMu of the plugin
func (m *Manager) stopPluginLocked(thisPlugin *Plugin) error {
	// A stop by the administrator voids a waiting automatic restart and ends a crash loop
	hadPending := thisPlugin.sup.resetByAdmin()
	thisPlugin.mu.Lock()
	thisPlugin.wantDown = true //also for a plugin that already crashed: after Stop it is stopped on purpose
	thisPlugin.mu.Unlock()

	proc := thisPlugin.currentProc()
	if proc == nil {
		//Never started, already stopped, or it ended by itself
		if hadPending {
			thisPlugin.mu.Lock()
			if thisPlugin.status.state == StateRestarting || thisPlugin.status.state == StateCrashLoop {
				thisPlugin.status.state = StateStopped
			}
			thisPlugin.mu.Unlock()
		}
		return ErrPluginNotRunning
	}

	m.stopProcess(thisPlugin, proc)
	m.detachPlugin(thisPlugin, proc)
	return nil
}

// stopProcess ends one plugin process: termination request, SIGTERM, then kill.
func (m *Manager) stopProcess(thisPlugin *Plugin, proc *pluginProc) {
	//From here on the end of this process is expected, not a crash
	proc.stopRequested.Store(true)

	//Make a GET request to plugin ui path /term to gracefully stop the plugin
	if uiProxy, port := thisPlugin.uiProxyAndPort(); uiProxy != nil && !proc.exited() {
		uiRelativePath := thisPlugin.Spec.UIPath
		if !strings.HasPrefix(uiRelativePath, "/") {
			uiRelativePath = "/" + uiRelativePath
		}
		requestURI := "http://127.0.0.1:" + strconv.Itoa(port) + uiRelativePath + "/term"

		client := http.Client{
			Timeout: 3 * time.Second,
		}
		resp, err := client.Get(requestURI)
		if err != nil {
			// Plugin does not support termination request, do it the hard way
			m.Log("Plugin "+thisPlugin.Spec.ID+" termination request failed. Force shutting down", nil)
		} else {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				if resp.StatusCode == http.StatusNotFound {
					m.Log("Plugin "+thisPlugin.Spec.ID+" does not support termination request", nil)
				} else {
					m.Log("Plugin "+thisPlugin.Spec.ID+" termination request returned status: "+resp.Status, nil)
				}
			}
		}
	}

	grace := m.stopGrace
	if grace <= 0 {
		grace = defaultStopGrace
	}

	if runtime.GOOS == "windows" {
		//There is no SIGTERM in windows, kill the process directly
		waitProcDone(proc, 300*time.Millisecond)
		if !proc.exited() {
			proc.cmd.Process.Kill()
		}
	} else if !proc.exited() {
		//Send SIGTERM to the plugin process, if it is still running
		err := signalPluginProcess(proc, syscall.SIGTERM)
		if err != nil && !proc.exited() {
			m.Log("Failed to send Interrupt signal to plugin "+thisPlugin.Spec.Name+": "+err.Error(), nil)
		}

		//Wait for the plugin to stop. The exit watcher closes proc.done, nothing here reads ProcessState
		if waitProcDone(proc, grace) {
			m.Log("Plugin "+thisPlugin.Spec.Name+" background process stopped", nil)
		} else {
			m.Log("Plugin "+thisPlugin.Spec.Name+" failed to stop gracefully, killing it", nil)
			signalPluginProcess(proc, syscall.SIGKILL)
		}
	}

	//A killed process is reaped almost at once
	if !waitProcDone(proc, 3*time.Second) {
		m.Log("Plugin "+thisPlugin.Spec.Name+" (pid "+strconv.Itoa(proc.pid)+") did not end after being killed", nil)
		thisPlugin.noteError("The plugin process (pid " + strconv.Itoa(proc.pid) + ") did not end after being killed")
	}
}

// waitProcDone waits until the process has been reaped, or the timeout passes
func waitProcDone(proc *pluginProc, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-proc.done:
		return true
	case <-timer.C:
		return false
	}
}

// Check if the plugin is still running
func (m *Manager) PluginIsRunning(pluginID string) bool {
	plugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		return false
	}
	return plugin.IsRunning()
}
