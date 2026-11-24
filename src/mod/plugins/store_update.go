package plugins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	dunreePlugin "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	Plugin Store Update

	Check if an installed plugin has a newer version available on the
	plugin store index, and update the plugin binary in place.
*/

type PluginUpdateInfo struct {
	PluginID         string `json:"pluginID"`         //The ID of the plugin
	Name             string `json:"name"`             //The name of the plugin
	InstalledVersion string `json:"installedVersion"` //The version currently installed
	LatestVersion    string `json:"latestVersion"`    //The latest version available on the plugin store
	UpdateAvailable  bool   `json:"updateAvailable"`  //Whether the store version is newer than the installed one
	Source           string `json:"source"`           //The index the update would come from
	BoundToSource    bool   `json:"boundToSource"`    //The plugin was installed from that index and is only updated from it
	Signature        string `json:"signature"`        //Signature state of that index (see DownloadablePlugin)
	Blocked          string `json:"blocked"`          //Why the update cannot be installed under the current signature checking mode, empty = it can
}

// versionToString formats a plugin version tuple as a string
func versionToString(major int, minor int, patch int) string {
	return strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(patch)
}

// storeVersionIsNewer compares the store copy against the installed copy of a plugin
func storeVersionIsNewer(storeCopy *DownloadablePlugin, installedCopy *Plugin) bool {
	storeVer := [3]int{storeCopy.PluginIntroSpect.VersionMajor, storeCopy.PluginIntroSpect.VersionMinor, storeCopy.PluginIntroSpect.VersionPatch}
	installedVer := [3]int{installedCopy.Spec.VersionMajor, installedCopy.Spec.VersionMinor, installedCopy.Spec.VersionPatch}
	for i := 0; i < 3; i++ {
		if storeVer[i] != installedVer[i] {
			return storeVer[i] > installedVer[i]
		}
	}
	return false
}

// getDownloadablePluginByID finds a plugin in the downloadable plugin cache by its ID.
// If the same plugin is offered by multiple sources, the one with the highest version wins.
func (m *Manager) getDownloadablePluginByID(pluginID string) *DownloadablePlugin {
	return newestOf(m.candidatesFor(pluginID, ""))
}

// installCandidate picks the store entry a new install uses: the newest one of
// the named index, or of all indexes. With signature checking set to enforce an
// entry that may be installed wins over a newer one that may not.
func (m *Manager) installCandidate(pluginID string, source string) *DownloadablePlugin {
	all := m.candidatesFor(pluginID, source)
	if m.Settings().VerifyMode == VerifyEnforce {
		ok := []*DownloadablePlugin{}
		for _, p := range all {
			if m.installBlockedReason(p) == "" {
				ok = append(ok, p)
			}
		}
		if len(ok) > 0 {
			return newestOf(ok)
		}
	}
	return newestOf(all)
}

// downloadableVersionIsNewer checks if candidate has a higher version than current
func downloadableVersionIsNewer(candidate *DownloadablePlugin, current *DownloadablePlugin) bool {
	candidateVer := [3]int{candidate.PluginIntroSpect.VersionMajor, candidate.PluginIntroSpect.VersionMinor, candidate.PluginIntroSpect.VersionPatch}
	currentVer := [3]int{current.PluginIntroSpect.VersionMajor, current.PluginIntroSpect.VersionMinor, current.PluginIntroSpect.VersionPatch}
	for i := 0; i < 3; i++ {
		if candidateVer[i] != currentVer[i] {
			return candidateVer[i] > currentVer[i]
		}
	}
	return false
}

// GetPluginUpdateInfos returns the update state of all installed plugins
// that are also available on the plugin store
func (m *Manager) GetPluginUpdateInfos() []*PluginUpdateInfo {
	updateInfos := []*PluginUpdateInfo{}
	loaded, _ := m.ListLoadedPlugins()
	for _, plugin := range loaded {
		spec := plugin.spec()
		storeCopy, source, _ := m.updateCandidate(spec.ID)
		if storeCopy == nil {
			//Not from the plugin store (or not offered by the index it was installed from), cannot check for updates
			continue
		}
		info := &PluginUpdateInfo{
			PluginID:         spec.ID,
			Name:             spec.Name,
			InstalledVersion: versionOfSpec(spec),
			LatestVersion:    versionToString(storeCopy.PluginIntroSpect.VersionMajor, storeCopy.PluginIntroSpect.VersionMinor, storeCopy.PluginIntroSpect.VersionPatch),
			UpdateAvailable:  storeVersionIsNewerThanSpec(storeCopy, spec),
			Source:           storeCopy.Source,
			BoundToSource:    source != "",
			Signature:        storeCopy.Signature,
		}
		if info.UpdateAvailable {
			info.Blocked = m.installBlockedReason(storeCopy)
		}
		updateInfos = append(updateInfos, info)
	}
	return updateInfos
}

func storeVersionIsNewerThanSpec(storeCopy *DownloadablePlugin, spec *dunreePlugin.IntroSpect) bool {
	storeVer := [3]int{storeCopy.PluginIntroSpect.VersionMajor, storeCopy.PluginIntroSpect.VersionMinor, storeCopy.PluginIntroSpect.VersionPatch}
	installedVer := [3]int{spec.VersionMajor, spec.VersionMinor, spec.VersionPatch}
	for i := 0; i < 3; i++ {
		if storeVer[i] != installedVer[i] {
			return storeVer[i] > installedVer[i]
		}
	}
	return false
}

// UpdatePlugin downloads the latest binary of an installed plugin from the
// plugin store index it was installed from and swaps it in. The download is
// verified and introspected in the staging folder while the installed version
// keeps running; the replaced binary is kept for a rollback. If the plugin was
// running before the update, it is restarted afterwards and has to pass a
// health check.
func (m *Manager) UpdatePlugin(pluginID string) error {
	installedPlugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		return fmt.Errorf("plugin is not installed: %s", pluginID)
	}

	storeCopy, source, elsewhere := m.updateCandidate(pluginID)
	if storeCopy == nil {
		if elsewhere {
			return fmt.Errorf("plugin %s was installed from %s, which does not offer it; another index does, but a plugin is only updated from the index it was installed from", pluginID, source)
		}
		return fmt.Errorf("plugin not found on the plugin store: %s", pluginID)
	}

	if !storeVersionIsNewer(storeCopy, installedPlugin) {
		return fmt.Errorf("plugin is already up to date")
	}

	//Locate the plugin binary to overwrite
	entryPoint, err := m.GetPluginEntryPoint(installedPlugin.RootDir)
	if err != nil {
		return fmt.Errorf("failed to locate plugin entry point: %w", err)
	}
	entryBase := filepath.Base(entryPoint)
	if entryBase == "start.sh" || entryBase == "start.bat" {
		return fmt.Errorf("script based plugins cannot be updated automatically")
	}

	// Download, verify and introspect in the staging folder. The installed version
	// is not touched and keeps running until all of that went well. The store lock
	// is not held meanwhile: a slow or stalled download does not hold up a rollback
	// (of this plugin or another), an install or the update of another plugin.
	release, err := m.beginStaging(pluginID)
	if err != nil {
		return err
	}
	defer release()
	gen := m.storeGen(pluginID)
	staged, err := m.stageDownload(storeCopy, pluginID, entryBase)
	if err != nil {
		m.store.opMu.Lock()
		m.noteChange(pluginID, "update", "The update to version "+versionToString(storeCopy.PluginIntroSpect.VersionMajor, storeCopy.PluginIntroSpect.VersionMinor, storeCopy.PluginIntroSpect.VersionPatch)+" was not installed: the download or its checks failed. The installed version was not touched.", false)
		m.store.opMu.Unlock()
		return fmt.Errorf("failed to download plugin update: %w (the installed version was not touched)", err)
	}
	defer os.RemoveAll(staged.dir)
	iconPath, iconErr := m.stageIcon(storeCopy, staged.dir)
	if iconErr != nil {
		//Icon is not critical, log and continue
		m.Log("Failed to update plugin icon for "+pluginID, iconErr)
	}

	// From here on files of the plugin change: one such change at a time. The
	// download took a while; what happened to the plugin meanwhile decides.
	m.store.opMu.Lock()
	defer m.store.opMu.Unlock()
	if m.storeGen(pluginID) != gen {
		return fmt.Errorf("plugin %s was rolled back, updated or removed while its update was downloading: the update was not installed (the installed version was not touched)", pluginID)
	}
	if cur, getErr := m.GetPluginByID(pluginID); getErr != nil {
		return fmt.Errorf("plugin %s was removed while its update was downloading", pluginID)
	} else {
		installedPlugin = cur
	}
	if entryPoint, err = m.GetPluginEntryPoint(installedPlugin.RootDir); err != nil || filepath.Base(entryPoint) != entryBase {
		return fmt.Errorf("the program file of plugin %s changed while its update was downloading: the update was not installed", pluginID)
	}
	if err = m.declaredIDCollision(staged.spec.ID, pluginID); err != nil {
		return fmt.Errorf("failed to download plugin update: %w (the installed version was not touched)", err)
	}

	// What is installed now, for the rollback
	rec := m.installRecord(pluginID)
	if rec == nil {
		rec = &InstallRecord{}
		rec.Current.Version = versionOfSpec(installedPlugin.spec())
	}
	if rec.Current.SHA256 == "" {
		rec.Current.SHA256, rec.Current.Size, _ = fileSHA256(entryPoint)
	}
	oldVersion := rec.Current

	//Stop the plugin if it is running
	wantRun, err := m.holdPlugin(installedPlugin)
	if err != nil {
		return fmt.Errorf("failed to stop plugin before update: %w", err)
	}

	//Swap: the installed binary goes to .zoraxy-previous/, the staged one takes its place
	if err = swapIn(entryPoint, staged.binPath); err != nil {
		if wantRun {
			m.StartPlugin(pluginID)
		}
		return err
	}
	m.bumpStoreGen(pluginID)
	if iconPath != "" {
		if err := os.Rename(iconPath, filepath.Join(installedPlugin.RootDir, "icon.png")); err != nil {
			m.Log("Failed to update plugin icon for "+pluginID, err)
		}
	}
	rec.Previous = &oldVersion
	rec.Current = staged.version(storeCopy)
	rec.Folder = filepath.Base(filepath.FromSlash(installedPlugin.RootDir)) //also for a record from before folders were recorded
	if rec.Source == "" {
		// The plugin had no known source. From now on it is updated from this index only
		rec.Source = storeCopy.Source
	}
	rec.LastChange, rec.LastChangeAt, rec.LastChangeIssue = "update", time.Now().Unix(), false
	rec.LastChangeNote = "Updated from version " + oldVersion.Version + " to " + rec.Current.Version + "."
	m.saveInstallRecord(pluginID, rec)

	//Reload the plugin spec from the updated binary
	newID, err := m.adoptSpec(installedPlugin, pluginID)
	if err != nil {
		// The new binary cannot be loaded in its place: put the old one back
		if _, rbErr := m.rollback(installedPlugin, wantRun, "auto_rollback", "The manifest of the new version could not be read."); rbErr != nil {
			return fmt.Errorf("plugin updated but failed to reload plugin spec (%v), and the previous version could not be put back: %w", err, rbErr)
		}
		return fmt.Errorf("the update was undone: the manifest of the new version could not be read: %w", err)
	}
	if newID != pluginID {
		//Plugin changed its ID after the update: its record moves with it
		m.saveInstallRecord(newID, rec)
		m.forgetInstallRecord(pluginID)
	}
	updatedSpec := installedPlugin.spec()
	m.Log("Plugin "+updatedSpec.Name+" updated to v"+versionOfSpec(updatedSpec), nil)

	//Restart the plugin if it was running before the update
	if !wantRun {
		return nil
	}
	err = m.StartPlugin(newID)
	if err == nil {
		err = m.waitHealthyAfterUpdate(installedPlugin)
	}
	if err == nil {
		return nil
	}
	problem := "Version " + rec.Current.Version + " did not start properly after the update: " + publicUpdateProblem(err) + "."
	m.Log("plugin "+newID+": "+problem, nil)
	m.audit("plugins.update.unhealthy", newID, map[string]string{"version": rec.Current.Version, "previous": oldVersion.Version, "auto_rollback": strconv.FormatBool(m.Settings().AutoRollback)})
	if m.Settings().AutoRollback {
		if _, rbErr := m.rollback(installedPlugin, true, "auto_rollback", problem); rbErr != nil {
			m.noteChange(newID, "update", problem+" The automatic rollback failed.", true)
			return fmt.Errorf("the new version did not start properly (%v) and the automatic rollback failed: %w", err, rbErr)
		}
		return fmt.Errorf("the new version did not start properly (%v). Version %s was put back and started", err, oldVersion.Version)
	}
	m.noteChange(newID, "update", problem+" Version "+oldVersion.Version+" is kept: use Roll back to return to it.", true)
	return fmt.Errorf("plugin updated but the new version did not start properly: %v. The previous version is kept, use Roll back in the Plugin Manager to return to it", err)
}

// publicUpdateProblem words a failed start or health check for the status of the
// plugin. Text of a contract refusal is Dunree's own; anything else may quote the
// operating system, which is fine for the administrator who reads it.
func publicUpdateProblem(err error) string {
	return clipText(strings.TrimRight(err.Error(), ". "), 300)
}

// downloadFileTo downloads the content of the given URL to the given file path
// (with the size cap and the timeout of every store download)
func downloadFileTo(downloadURL string, destPath string) error {
	m := &Manager{}
	_, _, err := m.downloadTo(downloadURL, destPath, int64(defaultMaxDownloadMB)<<20)
	return err
}

/*
	Handlers for Plugin Update
*/

// HandleCheckPluginUpdates returns the update state of all installed plugins
// that are available on the plugin store
func (m *Manager) HandleCheckPluginUpdates(w http.ResponseWriter, r *http.Request) {
	updateInfos := m.GetPluginUpdateInfos()
	js, _ := json.Marshal(updateInfos)
	utils.SendJSONResponse(w, string(js))
}

// HandleUpdatePlugin updates an installed plugin to the latest version on the plugin store
func (m *Manager) HandleUpdatePlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	pluginID, err := utils.PostPara(r, "pluginID")
	if err != nil {
		utils.SendErrorResponse(w, "pluginID is required")
		return
	}

	err = m.UpdatePlugin(pluginID)
	if err != nil {
		utils.SendErrorResponse(w, "Failed to update plugin: "+err.Error())
		return
	}

	utils.SendOK(w)
}
