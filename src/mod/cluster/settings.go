package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

/*
	Settings sync (optional, Config.SyncSettings on the primary)

	Proxy rules and the other synced objects are files. A few settings live in
	the database instead (listening port and TLS mode, SSO provider
	configuration, ZorxAuth users), and a database file cannot be swapped under
	a running process. So they travel as files too:

	  primary   Options.ExportSettings renders the allow-listed settings as JSON
	            files, which are added to the snapshot under SettingsRoot
	            (never written to the primary's disk), next to the files in
	            conf/sso the ZorxAuth users refer to.
	  follower  the snapshot is applied like any other (staging, backup,
	            rollback, boot guard), which leaves the files in
	            conf/dbsync. The restart that follows calls
	            ImportSyncedSettings before any module reads the database.

	Before the first import the follower saves its own values of the same
	settings (.cluster/dbsync-baseline.json), including which single keys it
	did not have. They are restored (and those keys removed again) if
	conf/dbsync disappears, which is what a rollback of the first settings
	snapshot does. The listener part of them also comes back when "keep this
	node's own listening ports" is switched on after an import.
*/

const (
	settingsAppliedFile  = "dbsync-applied.json"
	settingsBaselineFile = "dbsync-baseline.json"
	// this node's listener settings, saved when "keep own listening ports" was switched off after it had been on
	settingsOwnListenerFile = "dbsync-own-listener.json"
	maxSettingsFiles        = 32
)

// addSettings adds the settings files and the SSO folder to a primary snapshot.
func (m *Manager) addSettings(p *Payload) error {
	if m.opt.ExportSettings == nil {
		return errors.New("settings sync is on but this build cannot export settings")
	}
	files, err := m.opt.ExportSettings()
	if err != nil {
		return fmt.Errorf("settings export failed: %w", err)
	}
	if len(files) > maxSettingsFiles {
		return errors.New("settings export returned too many files")
	}
	sso, err := collectRoots(m.opt.ConfDir, []string{ssoRoot})
	if err != nil {
		return err
	}
	p.Files = append(p.Files, sso.Files...)
	for name, data := range files {
		entry := FileEntry{Path: SettingsRoot + "/" + name, Mode: 0o600, Data: data}
		if !validEntryPath(entry.Path, []string{SettingsRoot}) || !json.Valid(data) {
			return fmt.Errorf("settings export returned an invalid file %q", name)
		}
		p.Files = append(p.Files, entry)
	}
	p.Roots = append(p.Roots, ssoRoot, SettingsRoot)
	p.IncludesSettings = true
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Path < p.Files[j].Path })
	p.ContentHash = HashFiles(p.Files)
	return nil
}

// SettingsFiles returns the settings files of a payload by file name.
func SettingsFiles(p *Payload) map[string][]byte {
	out := map[string][]byte{}
	for _, f := range p.Files {
		if strings.HasPrefix(f.Path, SettingsRoot+"/") {
			out[strings.TrimPrefix(f.Path, SettingsRoot+"/")] = f.Data
		}
	}
	return out
}

type settingsApplied struct {
	Hash              string `json:"hash"` //"" once the primary stopped syncing settings: a resumed sync imports again
	KeepLocalListener bool   `json:"keepLocalListener"`
	// OwnListenerSaved: dbsync-own-listener.json holds this node's listener
	// settings from the moment "keep own listening ports" was switched off.
	OwnListenerSaved bool `json:"ownListenerSaved,omitempty"`
}

func (m *Manager) settingsStatePath(name string) string {
	return filepath.Join(m.opt.ConfDir, StateDirName, name)
}

func readSettingsDir(dir string) (map[string][]byte, string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	files := map[string][]byte{}
	var list []FileEntry
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, "", err
		}
		files[e.Name()] = b
		list = append(list, FileEntry{Path: e.Name(), Data: b})
	}
	if len(files) == 0 {
		return nil, "", nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	return files, HashFiles(list), nil
}

// SettingsStore is the database side of the settings sync (the main program).
type SettingsStore struct {
	// Export returns this node's current values as settings files. Unlike
	// Options.ExportSettings it also records which single keys do not exist,
	// so that Restore can remove them again.
	Export func() (map[string][]byte, error)
	// Import writes the settings files of a snapshot into the database;
	// keepLocalListener tells it to leave the node's own listener settings alone.
	Import func(files map[string][]byte, keepLocalListener bool) error
	// Restore puts values saved by Export back, removing the keys Export
	// recorded as missing. With listenerOnly it touches nothing but the
	// listener settings (ports, TLS mode, SSO portal port).
	Restore func(saved map[string][]byte, listenerOnly bool) error
}

func (m *Manager) readSavedSettings(name string) (map[string][]byte, error) {
	b, err := os.ReadFile(m.settingsStatePath(name))
	if err != nil {
		return nil, err
	}
	var saved map[string]json.RawMessage
	if err := json.Unmarshal(b, &saved); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, data := range saved {
		out[name] = data
	}
	return out, nil
}

func (m *Manager) writeSavedSettings(name string, files map[string][]byte) error {
	saved := map[string]json.RawMessage{}
	for name, data := range files {
		saved[name] = data
	}
	b, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	return m.writeSettingsState(name, b)
}

// writeSettingsState replaces a state file in one step (no half-written file after a crash).
func (m *Manager) writeSettingsState(name string, b []byte) error {
	tmp := m.settingsStatePath(name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.settingsStatePath(name))
}

func (m *Manager) writeSettingsApplied(a settingsApplied) error {
	b, _ := json.Marshal(a)
	return m.writeSettingsState(settingsAppliedFile, b)
}

// restoreOwnListener puts this node's own listener settings back: the ones
// saved when "keep own listening ports" was last switched off, else the ones
// from before the first import.
func (m *Manager) restoreOwnListener(s SettingsStore, applied settingsApplied) error {
	name := settingsBaselineFile
	if applied.OwnListenerSaved {
		name = settingsOwnListenerFile
	}
	saved, err := m.readSavedSettings(name)
	if err != nil {
		return fmt.Errorf("this node's own listening ports cannot be restored, the saved values cannot be read: %w", err)
	}
	return s.Restore(saved, true)
}

// ImportSyncedSettings brings the database in line with the settings files
// of the applied snapshot. Call it on every start, after the database is open
// and before modules read their settings. It does nothing unless this node is
// a follower that received settings, and nothing when they were imported
// already. It reports whether the database was changed.
func (m *Manager) ImportSyncedSettings(s SettingsStore) (bool, error) {
	cfg := m.Config()
	if cfg.Role != RoleFollower {
		return false, nil
	}
	m.mu.RLock()
	settingsSynced := m.status.SettingsSynced
	m.mu.RUnlock()
	var applied settingsApplied
	hasApplied := false
	if b, err := os.ReadFile(m.settingsStatePath(settingsAppliedFile)); err == nil && json.Unmarshal(b, &applied) == nil {
		hasApplied = true
	}
	files, hash, err := readSettingsDir(filepath.Join(m.opt.ConfDir, SettingsRoot))
	if err != nil {
		return false, err
	}

	if files == nil {
		if !hasApplied {
			return false, nil
		}
		// The settings files are gone (the snapshot that brought them was
		// rolled back): return to the values from before the first import.
		baseline, err := m.readSavedSettings(settingsBaselineFile)
		if err != nil {
			return false, fmt.Errorf("settings were rolled back but the saved local values cannot be read or are not valid: %w", err)
		}
		// The listener settings may be newer than the baseline: still the
		// node's own in the database (keep on), or saved when keep went off.
		var ownListener map[string][]byte
		if applied.KeepLocalListener {
			if ownListener, err = s.Export(); err != nil {
				return false, fmt.Errorf("settings were rolled back but this node's own listening ports cannot be read: %w", err)
			}
		} else if applied.OwnListenerSaved {
			ownListener, _ = m.readSavedSettings(settingsOwnListenerFile)
		}
		if err := s.Restore(baseline, false); err != nil {
			return false, err
		}
		if ownListener != nil {
			if err := s.Restore(ownListener, true); err != nil {
				return true, err
			}
		}
		os.Remove(m.settingsStatePath(settingsAppliedFile))
		os.Remove(m.settingsStatePath(settingsBaselineFile))
		os.Remove(m.settingsStatePath(settingsOwnListenerFile))
		m.opt.Logf("[cluster] synced settings were rolled back; this node's own settings are restored")
		return true, nil
	}

	keepOn := hasApplied && cfg.KeepLocalListener && !applied.KeepLocalListener
	keepOff := hasApplied && !cfg.KeepLocalListener && applied.KeepLocalListener

	if !settingsSynced {
		// The primary does not sync settings (any more): the files on disk
		// are old and this node's settings are editable again, so nothing is
		// imported from them. Forget their hash so that a resumed sync
		// imports even if the primary's settings are the same as back then.
		if !hasApplied {
			return false, nil
		}
		changed := false
		if keepOn {
			if err := m.restoreOwnListener(s, applied); err != nil {
				return false, err
			}
			applied.KeepLocalListener, applied.OwnListenerSaved, changed = true, false, true
			m.opt.Logf("[cluster] this node's own listening ports are restored")
		}
		if changed || applied.Hash != "" {
			applied.Hash = ""
			if err := m.writeSettingsApplied(applied); err != nil {
				return changed, err
			}
		}
		return changed, nil
	}

	if hasApplied && applied.Hash == hash && !keepOn && !keepOff {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Join(m.opt.ConfDir, StateDirName), 0o700); err != nil {
		return false, err
	}
	if _, err := os.Stat(m.settingsStatePath(settingsBaselineFile)); os.IsNotExist(err) {
		own, err := s.Export()
		if err != nil {
			return false, fmt.Errorf("cannot save this node's own settings before the import: %w", err)
		}
		if err := m.writeSavedSettings(settingsBaselineFile, own); err != nil {
			return false, err
		}
	}
	if keepOn {
		// switched on after an import overwrote them: take the node's own values back
		if err := m.restoreOwnListener(s, applied); err != nil {
			return false, err
		}
	}
	if keepOff && !applied.OwnListenerSaved {
		// about to be overwritten: remember the node's own values for the day the
		// switch goes on again. Recorded first, so a retry after a failed import
		// does not save half imported values.
		own, err := s.Export()
		if err != nil {
			return false, fmt.Errorf("cannot save this node's own listening ports before the import: %w", err)
		}
		if err := m.writeSavedSettings(settingsOwnListenerFile, own); err != nil {
			return false, err
		}
		applied.OwnListenerSaved = true
		if err := m.writeSettingsApplied(applied); err != nil {
			return false, err
		}
	}
	if err := s.Import(files, cfg.KeepLocalListener); err != nil {
		return keepOn, err
	}
	next := settingsApplied{Hash: hash, KeepLocalListener: cfg.KeepLocalListener, OwnListenerSaved: !cfg.KeepLocalListener && applied.OwnListenerSaved}
	if err := m.writeSettingsApplied(next); err != nil {
		return true, err
	}
	m.opt.Logf("[cluster] imported synced settings (%d files)", len(files))
	return true, nil
}

// SettingsReadOnly reports whether the database-stored settings of this node
// are a copy of the primary's that local changes would not survive.
func (m *Manager) SettingsReadOnly() bool {
	if m == nil || m.opt.AllowLocalEdits {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Role == RoleFollower && m.status.SettingsSynced
}
