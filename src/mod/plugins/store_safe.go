package plugins

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	dunreePlugin "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	Safe install, update and rollback (phase 2 of docs/plugins/reliability-plan.md, item 2.5)

	A download never touches an installed plugin. It goes to
	<plugin dir>/.staging/<plugin id>/, with a size cap and a timeout, is compared
	with the index (store_verify.go) and is introspected there, as the plugin user
	when one is configured. Only then is the plugin stopped and the binary swapped
	by renaming files inside the plugin directory; the binary that was replaced is
	kept in <plugin folder>/.zoraxy-previous/. After the swap the plugin is started again
	and has to answer (its health path, or a TCP connect) and stay up for a moment.

	A new version that fails that check is left in place and reported, and the
	administrator can roll back with one click; with the setting "roll back
	automatically" (off by default) Dunree does it by itself. One previous version
	is kept; a rollback uses it up.
*/

const (
	stagingDirName = ".staging"
	// The folder inside a plugin folder that holds the binary an update replaced.
	// A name of Dunree's own: a plugin that keeps data in a folder called
	// "previous" must not lose it to an update.
	previousDirName = ".zoraxy-previous"
)

// stagedPlugin is a download that passed every check and waits to be moved into place
type stagedPlugin struct {
	dir      string                   //the staging folder of this plugin
	binPath  string                   //the downloaded binary inside it
	spec     *dunreePlugin.IntroSpect //what the binary says about itself
	sum      string
	size     int64
	verified string //Verified...
	url      string
}

func (m *Manager) stagingDir(pluginID string) (string, error) {
	name, err := safePluginFolderName(pluginID, "")
	if err != nil {
		return "", err
	}
	return filepath.Join(m.Options.PluginDir, stagingDirName, name), nil
}

func versionOfSpec(spec *dunreePlugin.IntroSpect) string {
	return versionToString(spec.VersionMajor, spec.VersionMinor, spec.VersionPatch)
}

// stageDownload downloads the binary of a store entry into the staging folder,
// verifies it and introspects it there. binName is the file name the binary will
// have in the plugin folder. Nothing outside the staging folder is touched; on
// error the staging folder is removed.
func (m *Manager) stageDownload(entry *DownloadablePlugin, pluginID string, binName string) (staged *stagedPlugin, err error) {
	downloadURL, ok := entry.DownloadURLs[platformKey()]
	if !ok || downloadURL == "" {
		return nil, fmt.Errorf("no download URL available for the current platform")
	}
	if reason := m.installBlockedReason(entry); reason != "" {
		return nil, errors.New(reason)
	}
	if reason := addonBlockedReason(entry); reason != "" {
		return nil, errors.New(reason) //add-on index only: this host is older than the add-on needs
	}
	if reason := localArtifactRefused(entry.Source, downloadURL); reason != "" {
		return nil, errors.New(reason) //a file of this server only from the folder of the local source the entry came from
	}
	dir, err := m.stagingDir(pluginID)
	if err != nil {
		return nil, err
	}
	if rel, relErr := filepath.Rel(m.Options.PluginDir, dir); relErr != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("invalid staging folder for plugin %q", pluginID)
	}
	os.RemoveAll(dir) //left by an attempt that was interrupted
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create the staging folder: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()

	mode := m.Settings().VerifyMode
	limit := m.maxDownloadBytes()
	if d, pinned := entry.Downloads[platformKey()]; pinned && mode == VerifyEnforce && d.Size > 0 && d.Size < limit {
		limit = d.Size //one byte more than the index says ends the download
	}
	binPath := filepath.Join(dir, binName)
	sum, size, err := m.downloadTo(downloadURL, binPath, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to download plugin: %w", err)
	}
	if err = os.Chmod(binPath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to set executable permissions: %w", err)
	}

	verified, problem := m.checkDownload(entry, sum, size)
	if problem != "" {
		m.audit("plugins.download.mismatch", pluginID, map[string]string{"url": clipText(downloadURL, 300), "problem": problem, "mode": mode})
		if mode == VerifyEnforce {
			return nil, errors.New("the download does not match its index: " + problem)
		}
		m.Log("plugin "+pluginID+": the download does not match its index: "+problem+". It is installed anyway (signature checking: warn)", nil)
	}
	if mode != VerifyOff && entry.Signature != SigSigned && entry.Signature != SigUnsigned {
		m.Log("plugin "+pluginID+": installing from an index whose signature could not be confirmed ("+entry.Signature+") (signature checking: warn)", nil)
	}

	// The first run of a downloaded binary: as the plugin user when one is configured
	spec, err := m.getPluginSpec(binPath, true)
	if err != nil {
		return nil, fmt.Errorf("the downloaded plugin could not be introspected: %w", err)
	}
	if err = validatePluginSpec(spec); err != nil {
		return nil, fmt.Errorf("the downloaded plugin has an invalid manifest: %w", err)
	}
	if spec.ID != pluginID && mode == VerifyEnforce {
		err = fmt.Errorf("the downloaded plugin says its ID is %q, the index says %q (signature checking: enforce)", clipText(spec.ID, 80), pluginID)
		return nil, err
	}
	// In every mode: never the ID of another plugin (checked again before the swap)
	if err = m.declaredIDCollision(spec.ID, pluginID); err != nil {
		return nil, err
	}
	return &stagedPlugin{dir: dir, binPath: binPath, spec: spec, sum: sum, size: size, verified: verified, url: downloadURL}, nil
}

func (s *stagedPlugin) version(entry *DownloadablePlugin) InstalledVersion {
	return InstalledVersion{
		Version:     versionOfSpec(s.spec),
		SHA256:      s.sum,
		Size:        s.size,
		URL:         s.url,
		Signature:   entry.Signature,
		Verified:    s.verified,
		IndexSerial: entry.IndexSerial,
		InstalledAt: time.Now().Unix(),
	}
}

// stageIcon downloads the icon of a store entry into the staging folder (when it is a full URL)
func (m *Manager) stageIcon(entry *DownloadablePlugin, dir string) (string, error) {
	iconURL := strings.TrimSpace(entry.IconPath)
	if !strings.HasPrefix(iconURL, "http://") && !strings.HasPrefix(iconURL, "https://") {
		return "", nil
	}
	dest := filepath.Join(dir, "icon.png")
	if _, _, err := m.downloadTo(iconURL, dest, 4<<20); err != nil {
		return "", err
	}
	return dest, nil
}

// holdPlugin makes sure the plugin is not running and will not be started by the
// supervisor while its files are swapped. It returns whether the plugin was meant
// to run (running, or waiting for an automatic restart). A plugin that is neither
// is left exactly as it is.
func (m *Manager) holdPlugin(p *Plugin) (wantRun bool, err error) {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()
	running := p.IsRunning()
	waiting := p.Status().State == StateRestarting
	if !running && !waiting {
		return false, nil
	}
	if err := m.stopPluginLocked(p); err != nil && !errors.Is(err, ErrPluginNotRunning) {
		return false, err
	}
	return true, nil
}

// adoptSpec makes the manifest of the binary that is now in the plugin folder the
// loaded one. It returns the plugin ID after it (an update may change the ID).
func (m *Manager) adoptSpec(p *Plugin, oldID string) (string, error) {
	fresh, err := m.LoadPluginSpec(p.RootDir)
	if err != nil {
		return oldID, err
	}
	m.loadedPluginsMutex.Lock()
	changed := fresh.Spec.ID != oldID
	if changed {
		// Never take the slot of another plugin
		if other, taken := m.LoadedPlugins[fresh.Spec.ID]; taken && other != p {
			m.loadedPluginsMutex.Unlock()
			return oldID, fmt.Errorf("its manifest declares the ID %q, which is the ID of another installed plugin", clipText(fresh.Spec.ID, 80))
		}
		delete(m.LoadedPlugins, oldID)
	}
	p.mu.Lock()
	p.Spec = fresh.Spec
	p.SupportHotRebuild = fresh.SupportHotRebuild
	p.binaryState = ""
	p.mu.Unlock()
	m.LoadedPlugins[fresh.Spec.ID] = p
	m.loadedPluginsMutex.Unlock()
	if changed {
		// Page addresses handed out for the old ID end with it, and none that may
		// be around for the new ID is inherited
		m.dropUITickets(oldID)
		m.dropUITickets(fresh.Spec.ID)
	}
	// The new manifest is the loaded one now: compare what it asks for with what is
	// approved. The plugin is stopped here; the next start grants what is approved.
	m.reviewPermissions(fresh.Spec, "")
	m.InitPluginHashList()
	return fresh.Spec.ID, nil
}

// swapIn moves newBin to entryPoint and keeps the binary that was there in
// .zoraxy-previous/ (previousDirName). Both are renames inside the plugin directory. When the second
// rename fails the first one is undone, so the plugin folder always holds a binary.
func swapIn(entryPoint string, newBin string) error {
	prevDir := filepath.Join(filepath.Dir(entryPoint), previousDirName)
	if err := os.RemoveAll(prevDir); err != nil {
		return fmt.Errorf("failed to clear the previous version: %w", err)
	}
	if err := os.MkdirAll(prevDir, 0o755); err != nil {
		return fmt.Errorf("failed to create the folder for the previous version: %w", err)
	}
	kept := filepath.Join(prevDir, filepath.Base(entryPoint))
	if err := os.Rename(entryPoint, kept); err != nil {
		return fmt.Errorf("failed to set the installed version aside: %w", err)
	}
	if err := os.Rename(newBin, entryPoint); err != nil {
		if backErr := os.Rename(kept, entryPoint); backErr != nil {
			return fmt.Errorf("failed to move the new version into place (%v) and to put the installed version back (%v): the installed version is in %s", err, backErr, kept)
		}
		os.RemoveAll(prevDir)
		return fmt.Errorf("failed to move the new version into place: %w", err)
	}
	return nil
}

// swapBack puts the binary of .zoraxy-previous/ back to entryPoint. The binary that was
// there is removed. Renames only; when the second one fails the first is undone.
func (m *Manager) swapBack(pluginID string, entryPoint string) error {
	prevDir := filepath.Join(filepath.Dir(entryPoint), previousDirName)
	kept := filepath.Join(prevDir, filepath.Base(entryPoint))
	if _, err := os.Stat(kept); err != nil {
		return errors.New("the previous version is not in the plugin folder any more")
	}
	// Not the staging folder of the plugin: an update of it may be downloading
	// there right now. No plugin ID becomes a folder name with a leading dot.
	name, err := safePluginFolderName(pluginID, "")
	if err != nil {
		return err
	}
	dir := filepath.Join(m.Options.PluginDir, stagingDirName, ".rollback-"+name)
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	discard := filepath.Join(dir, "replaced-"+filepath.Base(entryPoint))
	if err := os.Rename(entryPoint, discard); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to set the installed version aside: %w", err)
	}
	if err := os.Rename(kept, entryPoint); err != nil {
		os.Rename(discard, entryPoint)
		os.RemoveAll(dir)
		return fmt.Errorf("failed to move the previous version into place: %w", err)
	}
	os.RemoveAll(prevDir)
	os.RemoveAll(dir)
	return nil
}

// waitHealthyAfterUpdate is the health check after an update: the process that was
// just started has to answer (the health path of its manifest, else a TCP connect
// to its port) and then stay up, as the same process, for a moment.
func (m *Manager) waitHealthyAfterUpdate(p *Plugin) error {
	proc := p.currentProc()
	if proc == nil {
		return errors.New("the process ended right after its start")
	}
	timeout, settle := m.storeCfg.healthTimeout(), m.storeCfg.healthSettle()
	deadline := time.Now().Add(timeout)
	var okSince time.Time
	for {
		if cur := p.currentProc(); cur != proc || proc.exited() {
			st := p.Status()
			if st.ExitReason != "" {
				return errors.New("the process ended (" + st.ExitReason + ")")
			}
			return errors.New("the process ended")
		}
		if okSince.IsZero() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := m.probeHealth(ctx, p, p.assignedPort())
			cancel()
			if err == nil {
				okSince = time.Now()
			}
		} else if time.Since(okSince) >= settle {
			return nil
		}
		if okSince.IsZero() && time.Now().After(deadline) {
			return errors.New("it did not answer within " + plainDuration(timeout))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (m *Manager) noteChange(pluginID string, kind string, note string, issue bool) {
	rec := m.installRecord(pluginID)
	if rec == nil {
		return //a plugin without an install record gets one when something is installed, not for an attempt
	}
	rec.LastChange, rec.LastChangeAt, rec.LastChangeNote, rec.LastChangeIssue = kind, time.Now().Unix(), note, issue
	m.saveInstallRecord(pluginID, rec)
}

// RollbackPlugin puts the previous version of a plugin back (the binary an update
// replaced) and starts it when the plugin was meant to run.
func (m *Manager) RollbackPlugin(pluginID string) error {
	m.store.opMu.Lock()
	defer m.store.opMu.Unlock()
	p, err := m.GetPluginByID(pluginID)
	if err != nil {
		return fmt.Errorf("plugin is not installed: %s", pluginID)
	}
	st := p.Status()
	wantRun := p.IsRunning()
	if !wantRun && m.GetPluginPreviousEnableState(pluginID) {
		switch st.State {
		case StateCrashed, StateExited, StateFailedToStart, StateRestarting, StateCrashLoop:
			wantRun = true //it was meant to run and the version that is rolled back did not
		}
	}
	_, err = m.rollback(p, wantRun, "rollback", "Rolled back by the administrator.")
	return err
}

// rollback does the work of RollbackPlugin. opMu is held.
func (m *Manager) rollback(p *Plugin, wantRun bool, kind string, why string) (string, error) {
	pluginID := p.Spec.ID
	rec := m.installRecord(pluginID)
	if rec == nil || rec.Previous == nil {
		return pluginID, errors.New("no previous version of this plugin is kept")
	}
	entryPoint, err := m.GetPluginEntryPoint(p.RootDir)
	if err != nil {
		// The new version may be gone altogether; the binary name is the folder name
		entryPoint = filepath.Join(p.RootDir, filepath.Base(p.RootDir))
		if runtime.GOOS == "windows" {
			entryPoint += ".exe"
		}
	}
	kept := filepath.Join(filepath.Dir(entryPoint), previousDirName, filepath.Base(entryPoint))
	if rec.Previous.SHA256 != "" && m.Settings().VerifyMode != VerifyOff {
		if sum, _, hashErr := fileSHA256(kept); hashErr == nil && sum != rec.Previous.SHA256 {
			if m.Settings().VerifyMode == VerifyEnforce {
				return pluginID, errors.New("the previous version in the plugin folder is not the file that was set aside (its checksum changed), and signature checking is set to enforce")
			}
			m.Log("plugin "+pluginID+": the previous version in the plugin folder is not the file that was set aside (its checksum changed). It is restored anyway (signature checking: warn)", nil)
		}
	}
	if _, err := m.holdPlugin(p); err != nil {
		return pluginID, fmt.Errorf("failed to stop plugin before the rollback: %w", err)
	}
	from := rec.Current.Version
	if err := m.swapBack(pluginID, entryPoint); err != nil {
		return pluginID, err
	}
	m.bumpStoreGen(pluginID) //an update of this plugin that is still downloading is not installed on top
	restored := *rec.Previous
	rec.Current, rec.Previous = restored, nil
	rec.LastChange, rec.LastChangeAt, rec.LastChangeIssue = kind, time.Now().Unix(), kind == "auto_rollback"
	rec.LastChangeNote = why + " Version " + from + " was replaced by the previous version " + restored.Version + "."
	m.saveInstallRecord(pluginID, rec)

	newID, err := m.adoptSpec(p, pluginID)
	if err != nil {
		return pluginID, fmt.Errorf("the previous version was put back but its manifest could not be read: %w", err)
	}
	if newID != pluginID {
		m.saveInstallRecord(newID, rec)
		m.forgetInstallRecord(pluginID)
	}
	m.Log("Plugin "+p.Spec.Name+" rolled back from v"+from+" to v"+restored.Version, nil)
	m.audit("plugins.rollback", newID, map[string]string{"from": from, "to": restored.Version, "kind": kind})
	if wantRun {
		if err := m.StartPlugin(newID); err != nil {
			return newID, fmt.Errorf("the previous version was put back but failed to start: %w", err)
		}
	}
	return newID, nil
}

// HandleRollbackPlugin puts the previous version of a plugin back
func (m *Manager) HandleRollbackPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}
	pluginID, err := utils.PostPara(r, "pluginID")
	if err != nil {
		utils.SendErrorResponse(w, "pluginID is required")
		return
	}
	if err := m.RollbackPlugin(pluginID); err != nil {
		utils.SendErrorResponse(w, "Failed to roll back plugin: "+err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleReleaseInstallSource forgets the index a plugin was installed from, so
// that any index may update it again (the behaviour of a plugin without a record)
func (m *Manager) HandleReleaseInstallSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}
	pluginID, err := utils.PostPara(r, "pluginID")
	if err != nil {
		utils.SendErrorResponse(w, "pluginID is required")
		return
	}
	rec := m.installRecord(pluginID)
	if rec == nil || rec.Source == "" {
		utils.SendErrorResponse(w, "This plugin is not bound to an index")
		return
	}
	was := rec.Source
	rec.Source = ""
	m.saveInstallRecord(pluginID, rec)
	m.Log("plugin "+pluginID+": updates are no longer limited to the index it was installed from ("+was+")", nil)
	utils.SendOK(w)
}

// folderIsLoaded says whether a loaded plugin lives in this folder of the plugin directory
func (m *Manager) folderIsLoaded(pluginPath string) bool {
	want := filepath.Clean(pluginPath)
	m.loadedPluginsMutex.RLock()
	defer m.loadedPluginsMutex.RUnlock()
	for _, p := range m.LoadedPlugins {
		if filepath.Clean(filepath.FromSlash(p.RootDir)) == want {
			return true
		}
	}
	return false
}

// repairPluginFolder is called for every plugin folder when Dunree starts, before
// anything of it is run. An update and a rollback swap the program file with two
// renames; when Dunree is killed between the two, the folder has no program file
// and the plugin would not load (and the Roll back button needs a loaded plugin).
// The file that was installed at that moment is renamed back:
//   - a rollback was interrupted: it waits in .staging/.rollback-<id>/replaced-<file>
//   - an update was interrupted: it waits in <plugin folder>/.zoraxy-previous/<file>
//
// Either way the folder holds again what its install record describes. Nothing is
// done for a folder that has an entry point, and nothing outside a start of Dunree
// (a reload may run while a swap is in progress).
func (m *Manager) repairPluginFolder(folder string, pluginPath string) {
	if _, err := m.GetPluginEntryPoint(pluginPath); err == nil {
		return
	}
	bin := folder
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	entryPoint := filepath.Join(pluginPath, bin)
	isFile := func(path string) bool {
		info, err := os.Lstat(path)
		return err == nil && info.Mode().IsRegular()
	}

	// The program file is named after the folder, so the name tells which plugin a set-aside file belongs to
	stagingRoot := filepath.Join(m.Options.PluginDir, stagingDirName)
	if entries, err := os.ReadDir(stagingRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), ".rollback-") {
				continue
			}
			aside := filepath.Join(stagingRoot, e.Name(), "replaced-"+bin)
			if !isFile(aside) {
				continue
			}
			if err := os.Rename(aside, entryPoint); err != nil {
				m.Log("plugin folder "+folder+": a rollback was interrupted and the program file could not be put back from "+aside, err)
				return
			}
			m.Log("plugin folder "+folder+": a rollback was interrupted (Dunree stopped in the middle of it). The program file that was installed was put back; the previous version is still kept, roll back again if you want it", nil)
			return
		}
	}

	prevDir := filepath.Join(pluginPath, previousDirName)
	kept := filepath.Join(prevDir, bin)
	if !isFile(kept) {
		return
	}
	if err := os.Rename(kept, entryPoint); err != nil {
		m.Log("plugin folder "+folder+": an update was interrupted and the program file could not be put back from "+kept, err)
		return
	}
	os.Remove(prevDir) //only when it is empty now
	m.Log("plugin folder "+folder+": an update was interrupted (Dunree stopped in the middle of it). The program file that was installed was put back from "+previousDirName+"; the update was not installed", nil)
	// The version an earlier update had kept was cleared to make room: there is nothing to roll back to
	if id, rec := m.recordOfFolder(folder); rec != nil && rec.Previous != nil {
		rec.Previous = nil
		m.saveInstallRecord(id, rec)
	}
}

// clearStagingAtBoot removes what a download, update or rollback that was cut off
// by the end of Dunree left in the staging folder. Only at a start of Dunree,
// after repairPluginFolder had its look: nothing is downloading then.
func (m *Manager) clearStagingAtBoot() {
	stagingRoot := filepath.Join(m.Options.PluginDir, stagingDirName)
	entries, err := os.ReadDir(stagingRoot)
	if err != nil || len(entries) == 0 {
		return
	}
	if err := os.RemoveAll(stagingRoot); err != nil {
		m.Log("Failed to clear the staging folder of plugin downloads", err)
		return
	}
	m.Log("Cleared "+strconv.Itoa(len(entries))+" leftover item(s) of interrupted plugin downloads from "+stagingDirName, nil)
}
