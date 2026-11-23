package plugins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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

	//Set by Zoraxy when the index is read (store_verify.go), never taken from an unsigned index
	Downloads   map[string]PinnedDownload `json:"Downloads,omitempty"` //signed index only: URL, SHA-256 and size per platform
	Signature   string                    `json:"Signature"`           //signed | unsigned | no_key | missing | bad_signature | replayed | downgraded | unchecked
	IndexSerial int64                     `json:"IndexSerial"`         //serial of the signed index, 0 for an unsigned one

	// Fingerprint of the public key the signature of the index was verified with
	// (only for Signature "signed"). An entry counts as signed only as long as that
	// is the configured key: replacing the key revokes what the old key signed.
	verifiedKey string
}

/* Plugin Store Index List Sync */
//Update the plugin list from the plugin store URLs
func (m *Manager) UpdateDownloadablePluginList() error {
	//Get downloadable plugins from each of the plugin store URLS
	newCache := []*DownloadablePlugin{}
	var lastErr error
	succCount := 0
	enforce := m.Settings().VerifyMode == VerifyEnforce
	keyNow := m.indexKeyFingerprint()
	for _, url := range m.GetAllStoreURLs() {
		pluginList, st, err := m.fetchIndex(url)
		if err != nil {
			//One broken source should not prevent the other sources from syncing
			lastErr = fmt.Errorf("failed to get plugin list from %s: %w", url, err)
			m.Log("Failed to sync plugin list from "+url, err)
			prev := m.sourceStatusOf(url)
			prev.Error, prev.CheckedAt = "The last sync of this index failed.", st.CheckedAt
			m.setSourceStatus(url, prev)
			continue
		}
		for _, plugin := range pluginList {
			plugin.Source = url
		}
		// A finding: an index in the signed format whose signature is not good, or an
		// address that served a signed index before and now serves the upstream list
		if st.Signature != SigSigned && st.Signature != SigUnchecked && st.Signature != SigUnsigned {
			was := m.sourceStatusOf(url)
			if was.Signature != st.Signature || was.Serial != st.Serial {
				//Once per change, not at every sync
				m.Log("plugin index "+url+": "+st.Note, nil)
				m.audit("plugins.index.signature", url, map[string]string{"state": st.Signature, "serial": strconv.FormatInt(st.Serial, 10), "mode": m.Settings().VerifyMode})
			}
			if enforce {
				// Keep what the last good index of this address offered: it is validly
				// signed and newer than what is being served now. Only entries that
				// were verified with the key that is configured now: after a change of
				// the key nothing the old key signed stays on offer.
				kept := []*DownloadablePlugin{}
				for _, old := range m.Options.DownloadablePluginCache {
					if old != nil && old.Source == url && old.Signature == SigSigned && keyNow != "" && old.verifiedKey == keyNow {
						kept = append(kept, old)
					}
				}
				if len(kept) > 0 {
					pluginList = kept
					st.Note += " The plugins of the last valid index are still offered."
					st.Plugins = len(kept)
				}
			}
		}
		m.setSourceStatus(url, st)
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
	pluginList, _, err := m.fetchIndex(url)
	if err != nil {
		return nil, err
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

	installTargetFree := func() error {
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
		return nil
	}
	if err = installTargetFree(); err != nil {
		return err
	}

	// Download into the staging folder, verify and introspect there. The plugin
	// folder only appears when all of that went well. The download runs without the
	// store lock: a slow store does not hold up a rollback or another plugin.
	release, err := m.beginStaging(plugin.PluginIntroSpect.ID)
	if err != nil {
		return err
	}
	defer release()
	staged, err := m.stageDownload(plugin, plugin.PluginIntroSpect.ID, pluginFile)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged.dir)

	//Ok, also download the icon if exists
	//Note the IconPath might be a relative path pointing to the default
	//icon on the webmin server, only download it if it is a full URL
	if _, err = m.stageIcon(plugin, staged.dir); err != nil {
		return fmt.Errorf("failed to download plugin icon: %w", err)
	}

	// From here on files of the plugin directory change: one such change at a time.
	// What was checked before the download is checked again, it took a while.
	m.store.opMu.Lock()
	defer m.store.opMu.Unlock()
	if err = installTargetFree(); err != nil {
		return err
	}
	if err = m.declaredIDCollision(staged.spec.ID, plugin.PluginIntroSpect.ID); err != nil {
		return err
	}

	// Move the whole staged folder into place (one rename inside the plugin directory)
	if err = os.Remove(pluginDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to prepare the plugin folder: %w", err)
	}
	if err = os.Rename(staged.dir, pluginDir); err != nil {
		return fmt.Errorf("failed to move the plugin into place: %w", err)
	}

	// Where it came from and what was installed: updates only come from this index.
	// The record goes under the ID the binary declares (the ID the plugin is loaded
	// under). declaredIDCollision made sure that is not the ID of another plugin.
	rec := &InstallRecord{Source: plugin.Source, Folder: folderName, Current: staged.version(plugin), LastChange: "install", LastChangeAt: time.Now().Unix()}
	m.forgetInstallRecord(plugin.PluginIntroSpect.ID) //of an earlier install under this ID that was removed by hand
	m.saveInstallRecord(staged.spec.ID, rec)
	for _, id := range []string{plugin.PluginIntroSpect.ID, staged.spec.ID} {
		m.bumpStoreGen(id)
		m.dropUITickets(id) //page addresses handed out for an earlier plugin of this ID
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
	// Not while an update or a rollback swaps files of the plugin directory. An
	// update of this plugin that is still downloading notices the change and stops.
	m.store.opMu.Lock()
	defer m.store.opMu.Unlock()
	m.bumpStoreGen(pluginID)

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
	// Also what was approved of its API permissions: a later install under the same
	// ID is a new plugin to review
	m.forgetPermissions(pluginID)
	// And where it was installed from
	m.forgetInstallRecord(pluginID)
	// And the addresses of its isolated page that were handed out
	m.dropUITickets(pluginID)

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
	// if multiple sources offer the same plugin. The optional parameter
	// "source" names the index to install from.
	source, _ := utils.PostPara(r, "source")
	plugin := m.installCandidate(pluginID, source)
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
