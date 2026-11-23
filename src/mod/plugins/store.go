package plugins

import (
	"encoding/json"
	"fmt"
	"imuslab.com/zoraxy/mod/offline"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/eventsystem"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin/events"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Plugin Store
*/

// See https://github.com/aroz-online/zoraxy-official-plugins/blob/main/directories/index2.json for the standard format

type DownloadablePlugin struct {
	IconPath         string                   `json:"IconPath"`         //Icon path or URL for the plugin
	PluginIntroSpect zoraxy_plugin.IntroSpect `json:"PluginIntroSpect"` //Plugin introspect information
	DownloadURLs     map[string]string        `json:"DownloadURLs"`     //Download URLs for different platforms
	Source           string                   `json:"Source"`           //The plugin store index URL this plugin was fetched from
}

/* Plugin Store Index List Sync */
//Update the plugin list from the plugin store URLs
func (m *Manager) UpdateDownloadablePluginList() error {
	//Get downloadable plugins from each of the plugin store URLS
	newCache := []*DownloadablePlugin{}
	var lastErr error
	succCount := 0
	for _, url := range m.GetAllStoreURLs() {
		pluginList, err := m.getPluginListFromURL(url)
		if err != nil {
			//One broken source should not prevent the other sources from syncing
			lastErr = fmt.Errorf("failed to get plugin list from %s: %w", url, err)
			m.Log("Failed to sync plugin list from "+url, err)
			continue
		}
		for _, plugin := range pluginList {
			plugin.Source = url
		}
		newCache = append(newCache, pluginList...)
		succCount++
	}

	if succCount == 0 && lastErr != nil {
		return lastErr
	}

	m.Options.DownloadablePluginCache = newCache
	m.Options.LastSuccPluginSyncTime = time.Now().Unix()

	return nil
}

// Get the plugin list from the URL
func (m *Manager) getPluginListFromURL(url string) ([]*DownloadablePlugin, error) {
	if err := offline.Check(); err != nil {
		return nil, err
	}
	//Get the plugin list from the URL
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get plugin list from %s: %s", url, resp.Status)
	}

	var pluginList []*DownloadablePlugin
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin list from %s: %w", url, err)
	}
	content = []byte(strings.TrimSpace(string(content)))

	err = json.Unmarshal(content, &pluginList)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal plugin list from %s: %w", url, err)
	}

	// Filter out if IconPath is empty string, set it to "/img/plugin_icon.png"
	for _, plugin := range pluginList {
		if strings.TrimSpace(plugin.IconPath) == "" {
			plugin.IconPath = "/img/plugin_icon.png"
		}
	}

	return pluginList, nil
}

func (m *Manager) ListDownloadablePlugins() []*DownloadablePlugin {
	//List all downloadable plugins
	if len(m.Options.DownloadablePluginCache) == 0 {
		return []*DownloadablePlugin{}
	}
	return m.Options.DownloadablePluginCache
}

// InstallPlugin installs the given plugin by moving it to the PluginDir.
func (m *Manager) InstallPlugin(plugin *DownloadablePlugin) (err error) {
	// The folder (and binary) name comes from the store index, which is remote input:
	// it must never be able to point outside the plugin directory.
	folderName, err := safePluginFolderName(plugin.PluginIntroSpect.Name, plugin.PluginIntroSpect.ID)
	if err != nil {
		return err
	}
	pluginDir := filepath.Join(m.Options.PluginDir, folderName)
	if rel, err := filepath.Rel(m.Options.PluginDir, pluginDir); err != nil || rel != folderName {
		return fmt.Errorf("invalid plugin folder name: %q", plugin.PluginIntroSpect.Name)
	}
	pluginFile := folderName
	if runtime.GOOS == "windows" {
		pluginFile += ".exe"
	}

	//Check if the plugin id already exists in runtime plugin map
	if _, err := m.GetPluginByID(plugin.PluginIntroSpect.ID); err == nil {
		return fmt.Errorf("plugin already installed: %s", plugin.PluginIntroSpect.ID)
	}

	// Two different store names can end up as the same folder name ("Foo/Bar" and
	// "Foo_Bar"), and a folder can be left from a plugin that no longer loads.
	// Never write into a folder that already holds something.
	if entries, statErr := os.ReadDir(pluginDir); statErr == nil && len(entries) > 0 {
		return fmt.Errorf("the plugin folder %q already exists and is not empty, remove it first", folderName)
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("failed to check the plugin folder: %w", statErr)
	}

	// Create the plugin directory if it doesn't exist
	err = os.MkdirAll(pluginDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}
	// The folder was absent or empty: a failed install must not leave a half
	// written plugin behind (it would block the next attempt, see above)
	defer func() {
		if err != nil {
			os.RemoveAll(pluginDir)
		}
	}()

	// Download the plugin binary
	downloadURL, ok := plugin.DownloadURLs[runtime.GOOS+"_"+runtime.GOARCH]
	if !ok {
		return fmt.Errorf("no download URL available for the current platform")
	}

	if err := offline.Check(); err != nil {
		return err
	}
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download plugin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download plugin: %s", resp.Status)
	}

	// Write the plugin binary to the plugin directory
	pluginPath := filepath.Join(pluginDir, pluginFile)
	out, err := os.Create(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to create plugin file: %w", err)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		out.Close()
		return fmt.Errorf("failed to write plugin file: %w", err)
	}

	// Make the plugin executable
	err = os.Chmod(pluginPath, 0755)
	if err != nil {
		out.Close()
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}
	//Close the plugin executable before anything else can fail
	out.Close()

	//Ok, also download the icon if exists
	//Note the IconPath might be a relative path pointing to the default
	//icon on the webmin server, only download it if it is a full URL
	iconURL := strings.TrimSpace(plugin.IconPath)
	if strings.HasPrefix(iconURL, "http://") || strings.HasPrefix(iconURL, "https://") {
		err = downloadFileTo(iconURL, filepath.Join(pluginDir, "icon.png"))
		if err != nil {
			return fmt.Errorf("failed to download plugin icon: %w", err)
		}
	}
	//Reload the plugin list
	m.ReloadPluginFromDisk()

	// A freshly installed plugin is shown as stopped. Store that, otherwise a
	// missing flag counts as "enabled" (and a flag left from an earlier install of
	// the same ID may say "enabled"), and the plugin starts by itself at the next
	// Zoraxy start although nobody enabled this install.
	m.markInstalledPluginDisabled(pluginDir, plugin.PluginIntroSpect.ID)

	return nil
}

// markInstalledPluginDisabled writes enabled=false for a newly installed plugin.
// InstallPlugin refuses IDs that are loaded and folders that hold something, so
// this never touches the state of a plugin that is already installed.
func (m *Manager) markInstalledPluginDisabled(pluginDir string, indexID string) {
	if m.Options == nil || m.Options.Database == nil || m.Options.Database.Backend == nil {
		return
	}
	ids := map[string]bool{}
	if indexID != "" {
		ids[indexID] = true
	}
	//The manifest of the downloaded binary decides the real ID, it may differ from the index
	wantDir := filepath.ToSlash(filepath.Clean(pluginDir))
	m.loadedPluginsMutex.RLock()
	for id, p := range m.LoadedPlugins {
		if filepath.ToSlash(filepath.Clean(p.RootDir)) == wantDir {
			ids[id] = true
		}
	}
	m.loadedPluginsMutex.RUnlock()
	for id := range ids {
		if err := m.Options.Database.Write("plugins", id, false); err != nil {
			m.Log("Failed to store the initial state of plugin "+id, err)
		}
	}
}

// safePluginFolderName turns the plugin name of a store index into a single safe
// folder name. Letters, digits, space, dot, dash and underscore are kept (so the
// folders of existing plugins keep their names), everything else becomes "_".
// It falls back to the plugin ID when nothing usable is left.
func safePluginFolderName(name string, id string) (string, error) {
	clean := func(in string) string {
		var b strings.Builder
		for _, r := range in {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '-', r == '_':
				b.WriteRune(r)
			case r == '.':
				//No ".." and no leading dot (hidden folder)
				if b.Len() == 0 || strings.HasSuffix(b.String(), ".") {
					b.WriteRune('_')
				} else {
					b.WriteRune(r)
				}
			default:
				b.WriteRune('_')
			}
		}
		out := strings.Trim(b.String(), " .")
		if len(out) > 100 {
			out = strings.Trim(out[:100], " .")
		}
		if strings.Trim(out, "_ ") == "" {
			return ""
		}
		return out
	}
	if out := clean(name); out != "" {
		return out, nil
	}
	if out := clean(id); out != "" {
		return out, nil
	}
	return "", fmt.Errorf("plugin has no usable name or ID to install it under")
}

// UninstallPlugin uninstalls the plugin by removing its directory.
func (m *Manager) UninstallPlugin(pluginID string) error {

	//Stop the plugin process if it's running
	plugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		return fmt.Errorf("plugin not found: %s", pluginID)
	}

	if plugin.IsRunning() {
		err := m.StopPlugin(plugin.Spec.ID)
		if err != nil {
			return fmt.Errorf("failed to stop plugin: %w", err)
		}
	}

	//Make sure the plugin process is stopped
	m.Options.Logger.PrintAndLog("plugin-manager", "Removing plugin in 3 seconds...", nil)
	time.Sleep(3 * time.Second)

	// Remove the plugin directory
	err = os.RemoveAll(plugin.RootDir)
	if err != nil {
		return fmt.Errorf("failed to remove plugin directory: %w", err)
	}

	// What the administrator allowed this install (restart policy, limits, block while
	// not running, global attach, fail-closed consent) ends with it: a plugin that is
	// installed later under the same ID starts with the defaults again
	if m.Options.Database != nil && m.Options.Database.Backend != nil {
		m.Options.Database.Delete(policyDBTable, pluginID)
		m.Options.Database.Delete(hookDBTable, pluginID)
	}

	//Reload the plugin list
	m.ReloadPluginFromDisk()
	return nil
}

/*
	Handlers for Plugin Store
*/

func (m *Manager) HandleListDownloadablePlugins(w http.ResponseWriter, r *http.Request) {
	//List all downloadable plugins
	plugins := m.ListDownloadablePlugins()
	js, _ := json.Marshal(plugins)
	utils.SendJSONResponse(w, string(js))
}

// HandleResyncPluginList is the handler for resyncing the plugin list from the plugin store URLs
func (m *Manager) HandleResyncPluginList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		//Make sure this function require csrf token
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	//Resync the plugin list from the plugin store URLs
	err := m.UpdateDownloadablePluginList()
	if err != nil {
		utils.SendErrorResponse(w, "Failed to resync plugin list: "+err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleInstallPlugin is the handler for installing a plugin
func (m *Manager) HandleInstallPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	pluginID, err := utils.PostPara(r, "pluginID")
	if err != nil {
		utils.SendErrorResponse(w, "pluginID is required")
		return
	}

	// Find the plugin info from cache, picking the newest version
	// if multiple sources offer the same plugin
	plugin := m.getDownloadablePluginByID(pluginID)
	if plugin == nil {
		utils.SendErrorResponse(w, "Plugin not found")
		return
	}

	// Install the plugin (implementation depends on your system)
	err = m.InstallPlugin(plugin)
	if err != nil {
		utils.SendErrorResponse(w, "Failed to install plugin: "+err.Error())
		return
	}

	utils.SendOK(w)
}

// HandleUninstallPlugin is the handler for uninstalling a plugin
func (m *Manager) HandleUninstallPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	pluginID, err := utils.PostPara(r, "pluginID")
	if err != nil {
		utils.SendErrorResponse(w, "pluginID is required")
		return
	}

	// Uninstall the plugin (implementation depends on your system)
	err = m.UninstallPlugin(pluginID)
	if err != nil {
		utils.SendErrorResponse(w, "Failed to uninstall plugin: "+err.Error())
		return
	}

	utils.SendOK(w)
}

// HandleEmitCustomEvent is the handler for emitting a custom event from a plugin to other plugins
func (m *Manager) HandleEmitCustomEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" || !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		utils.SendErrorResponse(w, "Invalid or missing Content-Type, expected application/json")
		return
	}

	// parse the event payload from the request body
	var payload events.CustomEvent
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		utils.SendErrorResponse(w, "Failed to parse event: "+err.Error())
		return
	}

	// collect the recipients
	if len(payload.Recipients) > 0 {
		recipients := make([]eventsystem.ListenerID, 0, len(payload.Recipients))
		for _, rid := range payload.Recipients {
			recipients = append(recipients, eventsystem.ListenerID(rid))
		}
		// Emit the event to subscribers and specified recipients
		eventsystem.Publisher.EmitToSubscribersAnd(recipients, &payload)
	} else {
		// Emit the event to all subscribers
		eventsystem.Publisher.Emit(&payload)
	}

	utils.SendOK(w)
}
