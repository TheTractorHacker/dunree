package plugins

/*
	Dunree Plugin Manager

	This module is responsible for managing plugins
	loading plugins from the disk
	enable / disable plugins
	and forwarding traffic to plugins
*/

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
	"github.com/foleyit/dunree/mod/utils"
)

// NewPluginManager creates a new plugin manager
func NewPluginManager(options *ManagerOptions) *Manager {
	//Create plugin directory if not exists
	if options.PluginDir == "" {
		options.PluginDir = "./plugins"
	}
	if !utils.FileExists(options.PluginDir) {
		os.MkdirAll(options.PluginDir, 0755)
	}

	//Create the plugin config file if not exists
	if !utils.FileExists(options.PluginGroupsConfig) {
		js, _ := json.Marshal(map[string][]string{})
		err := os.WriteFile(options.PluginGroupsConfig, js, 0644)
		if err != nil {
			options.Logger.PrintAndLog("plugin-manager", "Failed to create plugin group config file", err)
		}
	}

	//Create database table
	options.Database.NewTable("plugins")
	options.Database.NewTable(hookDBTable)
	options.Database.NewTable(policyDBTable) //reading from a table that does not exist panics in the bolt backend
	options.Database.NewTable(settingsDBTable)
	options.Database.NewTable(permDBTable)
	options.Database.NewTable(installDBTable)

	thisManager := &Manager{
		LoadedPlugins:      make(map[string]*Plugin),
		tagPluginMap:       sync.Map{},
		tagPluginListMutex: sync.RWMutex{},
		tagPluginList:      make(map[string][]*Plugin),
		Options:            options,
		PluginHash:         make(map[string]string),
		/* Internal */
		loadedPluginsMutex: sync.RWMutex{},
	}

	// Store sources: none on a new installation; an installation that existed
	// before keeps the source it synced from (once, see store_sources.go)
	if state := thisManager.migrateStoreSources(); state == "existing-migrated" && options.Logger != nil {
		options.Logger.PrintAndLog("plugin-manager", "This installation used the plugin store of the Zoraxy project before. It was kept as a store source (\"Zoraxy community store (third party)\"); remove it under System > Add-ons > Sources if you do not want it. Dunree itself ships without a store source.", nil) // legacy-compat
	}

	//Check if hot reload is enabled
	if options.EnableHotReload {
		err := thisManager.StartHotReloadTicker()
		if err != nil {
			options.Logger.PrintAndLog("plugin-manager", "Failed to start hot reload ticker", err)
		}
	}

	return thisManager
}

// Reload all plugins from disk
func (m *Manager) ReloadPluginFromDisk() {
	//Check each of the current plugins if the directory exists
	//If not, remove the plugin from the loaded plugins list
	m.loadedPluginsMutex.Lock()
	for pluginID, plugin := range m.LoadedPlugins {
		if !utils.FileExists(plugin.RootDir) {
			m.Log("Plugin directory not found, removing plugin from runtime: "+pluginID, nil)
			delete(m.LoadedPlugins, pluginID)
			//Remove the plugin enable state from the database
			m.Options.Database.Delete("plugins", pluginID)
			m.forgetInstallRecord(pluginID) //and where it was installed from
		}
	}

	m.loadedPluginsMutex.Unlock()

	//Scan the plugin directory for new plugins
	foldersInPluginDir, err := os.ReadDir(m.Options.PluginDir)
	if err != nil {
		m.Log("Failed to read plugin directory", err)
		return
	}

	m.pruneDeferredBaseline(dirNames(foldersInPluginDir))

	for _, folder := range foldersInPluginDir {
		if folder.IsDir() && folder.Name() != stagingDirName { //the staging folder of downloads is not a plugin
			pluginPath := filepath.Join(m.Options.PluginDir, folder.Name())
			// Before the program file is run for its manifest: is it the installed one?
			changedFrom, err := m.checkBinaryBeforeLoad(folder.Name(), pluginPath)
			if err != nil {
				if m.folderIsLoaded(pluginPath) {
					// The plugin of this folder is loaded (its manifest was read from
					// the installed file). Its next start reports the changed file.
					continue
				}
				m.Log("Failed to load plugin: "+filepath.Base(pluginPath), err)
				m.noteLoadFailure(folder.Name(), err)
				continue
			}
			thisPlugin, err := m.LoadPluginSpec(pluginPath)
			if err != nil {
				m.Log("Failed to load plugin: "+filepath.Base(pluginPath), err)
				m.noteLoadFailure(folder.Name(), err)
				continue
			}
			m.clearLoadFailure(folder.Name())
			m.noteChangedBinaryLoaded(folder.Name(), pluginPath, changedFrom, thisPlugin.Spec.ID)

			//Check if the plugin id is already loaded into the runtime
			m.loadedPluginsMutex.RLock()
			_, ok := m.LoadedPlugins[thisPlugin.Spec.ID]
			m.loadedPluginsMutex.RUnlock()
			if ok {
				// Plugin already loaded, skip it. Its API permissions are not reviewed:
				// the manifest just read from disk is not the one that is loaded (the
				// binary may have been replaced by hand), and the approvals must match
				// the plugin that runs.
				continue
			}

			// A new plugin: compare what it asks for with what is approved for its ID
			m.reviewPermissions(thisPlugin.Spec, folder.Name())

			thisPlugin.RootDir = filepath.ToSlash(pluginPath)
			thisPlugin.staticRouteProxy = make(map[string]*dpcore.ReverseProxy)
			m.loadHookAdminSettings(thisPlugin)
			m.loadedPluginsMutex.Lock()
			m.LoadedPlugins[thisPlugin.Spec.ID] = thisPlugin
			m.loadedPluginsMutex.Unlock()
			versionNumber := strconv.Itoa(thisPlugin.Spec.VersionMajor) + "." + strconv.Itoa(thisPlugin.Spec.VersionMinor) + "." + strconv.Itoa(thisPlugin.Spec.VersionPatch)
			//Check if the plugin is enabled
			m.Log("Found plugin: "+thisPlugin.Spec.Name+" (v"+versionNumber+")", nil)

			// The default state of the plugin is disabled, so no need to start it
		}
	}

	//Generate a hash list for plugins
	m.InitPluginHashList()
}

// LoadPluginsFromDisk loads all plugins from the plugin directory
func (m *Manager) LoadPluginsFromDisk() error {
	// Load all plugins from the plugin directory
	foldersInPluginDir, err := os.ReadDir(m.Options.PluginDir)
	if err != nil {
		return err
	}

	m.pruneDeferredBaseline(dirNames(foldersInPluginDir))
	failedFolders := []string{} //for the permission baseline, see markPermissionBaseline

	for _, folder := range foldersInPluginDir {
		if folder.IsDir() && folder.Name() != stagingDirName { //the staging folder of downloads is not a plugin
			pluginPath := filepath.Join(m.Options.PluginDir, folder.Name())
			// A crash of Dunree in the middle of an update or rollback can leave the
			// folder without its program file: put it back
			m.repairPluginFolder(folder.Name(), pluginPath)
			// Before the program file is run for its manifest: is it the installed one?
			changedFrom, err := m.checkBinaryBeforeLoad(folder.Name(), pluginPath)
			var thisPlugin *Plugin
			if err == nil {
				thisPlugin, err = m.LoadPluginSpec(pluginPath)
			}
			if err != nil {
				m.Log("Failed to load plugin: "+filepath.Base(pluginPath), err)
				m.noteLoadFailure(folder.Name(), err)
				failedFolders = append(failedFolders, folder.Name())
				continue
			}
			m.clearLoadFailure(folder.Name())
			m.noteChangedBinaryLoaded(folder.Name(), pluginPath, changedFrom, thisPlugin.Spec.ID)
			if changedFrom == "" {
				m.noteRecordFolder(thisPlugin.Spec.ID, folder.Name()) //a record from before folders were recorded
			}
			// API permissions: compare what the manifest asks for with what is approved
			// for this plugin ID, and report what is new (log-only unless approval is
			// required). Before the start below, which grants what is approved.
			m.reviewPermissions(thisPlugin.Spec, folder.Name())
			thisPlugin.RootDir = filepath.ToSlash(pluginPath)
			thisPlugin.staticRouteProxy = make(map[string]*dpcore.ReverseProxy)
			m.loadHookAdminSettings(thisPlugin)
			m.loadedPluginsMutex.Lock()
			m.LoadedPlugins[thisPlugin.Spec.ID] = thisPlugin
			m.loadedPluginsMutex.Unlock()
			m.Log("Loaded plugin: "+thisPlugin.Spec.Name, nil)

			// If the plugin was enabled, start it now
			//fmt.Println("Plugin enabled state", m.GetPluginPreviousEnableState(thisPlugin.Spec.ID))
			if m.GetPluginPreviousEnableState(thisPlugin.Spec.ID) {
				err = m.StartPlugin(thisPlugin.Spec.ID)
				if err != nil {
					m.Log("Failed to enable plugin: "+thisPlugin.Spec.Name, err)
					var refused *errContractRefused
					if errors.As(err, &refused) {
						//Not a failure a retry can fix: the administrator asked not to start such plugins
						continue
					}
					// With a restart policy a plugin that fails to start at boot is tried
					// again with the same backoff as a crashed one (default never: nothing)
					thisPlugin.lifeMu.Lock()
					thisPlugin.sup.addHistory(ExitRecord{At: time.Now().Unix(), Kind: StateFailedToStart, ExitCode: -1, Reason: "start at boot failed"})
					m.superviseFailure(thisPlugin, true, 0)
					thisPlugin.lifeMu.Unlock()
				}
			}
		}
	}

	m.clearStagingAtBoot() //leftovers of a download or swap that the end of Dunree cut off

	// Every plugin that was installed before API permissions were tracked has its
	// record now (see reviewPermissions). A plugin that shows up later starts with
	// nothing approved. A folder that could not be loaded this time gets its baseline
	// on its first successful load.
	m.markPermissionBaseline(failedFolders...)

	if m.Options.PluginGroupsConfig != "" {
		//Load the plugin groups from the config file
		err = m.LoadPluginGroupsFromConfig()
		if err != nil {
			m.Log("Failed to load plugin groups", err)
		}
	}

	//Generate the static forwarder radix tree
	m.UpdateTagsToPluginMaps()

	//Generate a hash list for plugins
	m.InitPluginHashList()
	return nil
}

func dirNames(entries []os.DirEntry) map[string]bool {
	names := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names[e.Name()] = true
		}
	}
	return names
}

// GetPluginByID returns a plugin by its ID
func (m *Manager) GetPluginByID(pluginID string) (*Plugin, error) {
	m.loadedPluginsMutex.RLock()
	plugin, ok := m.LoadedPlugins[pluginID]
	m.loadedPluginsMutex.RUnlock()
	if !ok {
		return nil, errors.New("plugin not found")
	}
	return plugin, nil
}

// EnablePlugin enables a plugin
func (m *Manager) EnablePlugin(pluginID string) error {
	m.Options.Database.Write("plugins", pluginID, true)
	err := m.StartPlugin(pluginID)
	if err != nil {
		return err
	}
	//Generate the static forwarder radix tree
	m.UpdateTagsToPluginMaps()
	return nil
}

// ErrPluginNotRunning is returned by StopPlugin when the plugin has no running process
var ErrPluginNotRunning = errors.New("plugin is not running")

// DisablePlugin disables a plugin: it stops the process and stores enabled=false.
// A plugin that is not running any more (it crashed, or was never started) is
// still disabled with success: the stored state is what the administrator asked for.
func (m *Manager) DisablePlugin(pluginID string) error {
	err := m.StopPlugin(pluginID)
	m.Options.Database.Write("plugins", pluginID, false)
	if err != nil && !errors.Is(err, ErrPluginNotRunning) {
		return err
	}
	//Generate the static forwarder radix tree
	m.UpdateTagsToPluginMaps()
	return nil
}

// GetPluginPreviousEnableState returns the previous enable state of a plugin
func (m *Manager) GetPluginPreviousEnableState(pluginID string) bool {
	enableState := true
	err := m.Options.Database.Read("plugins", pluginID, &enableState)
	if err != nil {
		//Default to true
		return true
	}
	return enableState
}

// ListLoadedPlugins returns a list of loaded plugins
func (m *Manager) ListLoadedPlugins() ([]*Plugin, error) {
	plugins := []*Plugin{}
	m.loadedPluginsMutex.RLock()
	for _, plugin := range m.LoadedPlugins {
		plugins = append(plugins, plugin)
	}
	m.loadedPluginsMutex.RUnlock()
	return plugins, nil
}

// Log a message with the plugin name
func (m *Manager) LogForPlugin(p *Plugin, message string, err error) {
	processID := -1
	if pp := p.currentProc(); pp != nil {
		// Get the process ID of the plugin
		processID = pp.pid
	}
	m.Log("["+p.Spec.Name+":"+strconv.Itoa(processID)+"] "+message, err)
}

// Terminate all plugins and exit
func (m *Manager) Close() {
	m.closing.Store(true) //no automatic restart from here on
	m.loadedPluginsMutex.Lock()
	loaded := make([]*Plugin, 0, len(m.LoadedPlugins))
	for _, plugin := range m.LoadedPlugins {
		plugin.sup.resetByAdmin() //void restarts that are waiting
		loaded = append(loaded, plugin)
	}
	m.loadedPluginsMutex.Unlock()

	for _, thisPlugin := range loaded {
		// An automatic restart that passed its "closing" check before the line above
		// holds lifeMu until its process runs (a start can take seconds). Look at the
		// plugin only after it: a start that is under way is then seen and stopped,
		// and no later one begins, because every automatic restart checks "closing"
		// again under this lock.
		thisPlugin.lifeMu.Lock()
		running := thisPlugin.IsRunning()
		thisPlugin.lifeMu.Unlock()
		if !running {
			continue
		}
		m.Options.Logger.PrintAndLog("plugin-manager", "Stopping plugin: "+thisPlugin.Spec.Name, nil)
		m.StopPlugin(thisPlugin.Spec.ID)
		thisPlugin.logw.close()
	}

}

/* Plugin Functions */
func (m *Plugin) StartAllStaticPathRouters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startAllStaticPathRoutersLocked()
}

func (m *Plugin) startAllStaticPathRoutersLocked() {
	if m.staticRouteProxy == nil {
		m.staticRouteProxy = make(map[string]*dpcore.ReverseProxy)
	}
	// Create a dpcore object for each of the static capture paths of the plugin
	for _, captureRule := range m.Spec.StaticCapturePaths {
		//Make sure the captureRule consists / prefix and no trailing /
		if captureRule.CapturePath == "" {
			continue
		}
		if !strings.HasPrefix(captureRule.CapturePath, "/") {
			captureRule.CapturePath = "/" + captureRule.CapturePath
		}
		captureRule.CapturePath = strings.TrimSuffix(captureRule.CapturePath, "/")

		// Create a new dpcore object to forward the traffic to the plugin
		targetURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(m.AssignedPort) + m.Spec.StaticCaptureIngress)
		if err != nil {
			fmt.Println("Failed to parse the static capture target URL of plugin "+m.Spec.ID, err)
			continue
		}
		thisRouter := dpcore.NewDynamicProxyCore(targetURL, captureRule.CapturePath, m.captureProxyOptions())
		m.staticRouteProxy[captureRule.CapturePath] = thisRouter
	}
}

// StopAllStaticPathRouters stops all static path routers
func (m *Plugin) StopAllStaticPathRouters() {
	m.mu.Lock()
	m.staticRouteProxy = make(map[string]*dpcore.ReverseProxy)
	m.mu.Unlock()
}

// HandleStaticRoute handles the request to the plugin via static path captures (static forwarder)
func (p *Plugin) HandleStaticRoute(w http.ResponseWriter, r *http.Request, longestPrefix string) {
	longestPrefix = strings.TrimSuffix(longestPrefix, "/")
	targetRouter, port := p.staticProxyFor(longestPrefix)
	if targetRouter == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error: target router not found for prefix", longestPrefix)
		return
	}

	originalRequestURI := r.RequestURI

	//Rewrite the request path to the plugin UI path
	rewrittenURL := r.RequestURI
	rewrittenURL = strings.TrimPrefix(rewrittenURL, longestPrefix)
	rewrittenURL = strings.ReplaceAll(rewrittenURL, "//", "/")
	if rewrittenURL == "" {
		rewrittenURL = "/"
	}
	r.URL, _ = url.Parse(rewrittenURL)

	//Every header of the host goes out under its Dunree name and the name Zoraxy used (hostHeaders, wire.go) // legacy-compat
	upstreamHeaders := hostHeaders("Capture", longestPrefix)
	upstreamHeaders = append(upstreamHeaders, hostHeaders("URI", originalRequestURI)...)
	upstreamHeaders = append(upstreamHeaders, hostHeaders("RequestID", requestID(r))...)
	if tok := p.invokeToken(); tok != "" {
		upstreamHeaders = append(upstreamHeaders, hostHeaders("Plugin-Token", tok)...)
	}
	if !p.beginCapture() {
		writeCaptureUnavailable(w)
		return
	}
	cw := p.newCaptureWriter(w)
	//A transport error is returned without anything written: finishCapture answers 502 instead of an empty 200
	_, err := targetRouter.ServeHTTP(cw, r, &dpcore.ResponseRewriteRuleSet{
		UseTLS:          false,
		OriginalHost:    r.Host,
		ProxyDomain:     "127.0.0.1:" + strconv.Itoa(port),
		NoCache:         true,
		PathPrefix:      longestPrefix,
		AllowUpgrade:    true,
		UpstreamHeaders: upstreamHeaders,
	})
	p.finishCapture(cw, "static", err)
}

// IsRunning checks if the plugin is currently running
func (p *Plugin) IsRunning() bool {
	pp := p.currentProc()
	return pp != nil && !pp.exited()
}
