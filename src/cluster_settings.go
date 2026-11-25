package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TheTractorHacker/dunree/mod/auth/sso/forward"
	"github.com/TheTractorHacker/dunree/mod/auth/sso/oauth2"
	"github.com/TheTractorHacker/dunree/mod/auth/sso/zorxauth"
	"github.com/TheTractorHacker/dunree/mod/cluster"
)

/*
	cluster_settings.go

	Which database-stored settings a cluster primary offers to its followers
	(high availability, issue #81, "sync settings" on the Cluster page, off by
	default) and how a follower writes them into its own database. The
	transport, versioning, rollback and the moment of the import are in
	mod/cluster/settings.go.

	Only what is listed here can leave or enter the database through the sync:
	admin accounts, sessions, statistics and everything else stay node local.
*/

// syncedTable is one database table (or a few keys of it) in a settings file.
type syncedTable struct {
	table string
	keys  []string //nil: the whole table, and an import replaces its content
	// export returns the value as offered to followers (node local parts removed)
	export func(key string, raw []byte) []byte
	// merge returns the value a follower stores, given its current one (nil if none)
	merge func(key string, incoming, local []byte, keepLocalListener bool) []byte
	// ownListener is set for tables outside the listener group that hold a
	// listener setting inside a value: it returns current with that part
	// taken from saved (nil if the node had no such key)
	ownListener func(key string, saved, current []byte) []byte
}

type syncedGroup struct {
	file     string
	listener bool //skipped on a follower that keeps its own listener settings
	tables   []syncedTable
}

func clusterSettingsGroups() []syncedGroup {
	sso := []syncedTable{{table: forward.DatabaseTable}}
	for _, t := range oauth2.SettingsTables() {
		sso = append(sso, syncedTable{table: t})
	}
	sso = append(sso, syncedTable{
		table: zorxauth.DB_NAME, keys: zorxauth.SyncedSettingKeys(),
		export: func(key string, raw []byte) []byte {
			if key == zorxauth.OptionsKey {
				return zorxauth.ExportOptionsForSync(raw)
			}
			return raw
		},
		merge: func(key string, incoming, local []byte, keepLocalListener bool) []byte {
			if key == zorxauth.OptionsKey {
				return zorxauth.MergeSyncedOptions(incoming, local, keepLocalListener)
			}
			return incoming
		},
		ownListener: func(key string, saved, current []byte) []byte {
			if key == zorxauth.OptionsKey {
				return zorxauth.RestoreGatewayPort(current, saved)
			}
			return current
		},
	})
	return []syncedGroup{
		{file: "listener.json", listener: true, tables: []syncedTable{
			{table: "settings", keys: []string{"inbound", "usetls", "minTLSVersion", "tlsCipherProfile", "listenP80", "redirect"}},
		}},
		{file: "sso.json", tables: sso},
		{file: "zorxauth_users.json", tables: []syncedTable{{
			table:  zorxauth.DB_USERS_TABLE,
			export: func(_ string, raw []byte) []byte { return zorxauth.ExportUserForSync(raw) },
			merge: func(_ string, incoming, local []byte, _ bool) []byte {
				return zorxauth.MergeSyncedUser(incoming, local)
			},
		}}},
	}
}

// settingsFile is the content of one settings file: table -> key -> JSON value.
type settingsFile map[string]map[string]json.RawMessage

func readSyncedTable(t syncedTable) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	if !sysdb.TableExists(t.table) {
		return out, nil
	}
	rows, err := sysdb.ListTable(t.table)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, k := range t.keys {
		wanted[k] = true
	}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		key := string(row[0])
		if (t.keys != nil && !wanted[key]) || !json.Valid(row[1]) {
			continue
		}
		out[key] = append(json.RawMessage{}, row[1]...)
	}
	return out, nil
}

// exportClusterSettings renders the synced settings of this node. The output
// is deterministic: it is part of the snapshot's content hash.
func exportClusterSettings() (map[string][]byte, error) {
	return renderClusterSettings(false)
}

// exportOwnClusterSettings is the export a follower saves before the primary's
// values replace its own. It also names the single keys this node does not
// have (as JSON null): most listener settings exist only once an admin changed
// them, and putting the node's own state back means removing them again.
func exportOwnClusterSettings() (map[string][]byte, error) {
	return renderClusterSettings(true)
}

func renderClusterSettings(markMissing bool) (map[string][]byte, error) {
	if sysdb == nil {
		return nil, errors.New("database not ready")
	}
	out := map[string][]byte{}
	for _, g := range clusterSettingsGroups() {
		file := settingsFile{}
		for _, t := range g.tables {
			rows, err := readSyncedTable(t)
			if err != nil {
				return nil, fmt.Errorf("table %s: %w", t.table, err)
			}
			if t.export != nil {
				for k, v := range rows {
					if e := t.export(k, v); json.Valid(e) {
						rows[k] = e
					}
				}
			}
			if markMissing {
				for _, k := range t.keys {
					if _, ok := rows[k]; !ok {
						rows[k] = json.RawMessage("null")
					}
				}
			}
			file[t.table] = rows
		}
		b, err := json.Marshal(file)
		if err != nil {
			return nil, err
		}
		out[g.file] = b
	}
	return out, nil
}

// importClusterSettings writes settings files into the database. Files,
// tables and keys that are not in clusterSettingsGroups are ignored.
func importClusterSettings(files map[string][]byte, keepLocalListener bool) error {
	return writeClusterSettings(files, keepLocalListener, false, false)
}

// restoreClusterSettings puts values saved by exportOwnClusterSettings back
// and deletes the keys recorded there as missing. With listenerOnly it leaves
// everything but the listener settings (ports, TLS mode, SSO portal port) as
// it is.
func restoreClusterSettings(saved map[string][]byte, listenerOnly bool) error {
	return writeClusterSettings(saved, false, true, listenerOnly)
}

func isJSONNull(v []byte) bool { return string(bytes.TrimSpace(v)) == "null" }

func writeClusterSettings(files map[string][]byte, keepLocalListener, restore, listenerOnly bool) error {
	if sysdb == nil {
		return errors.New("database not ready")
	}
	for _, g := range clusterSettingsGroups() {
		data, ok := files[g.file]
		if !ok || (g.listener && keepLocalListener) {
			continue
		}
		var file settingsFile
		if err := json.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("%s: %w", g.file, err)
		}
		for _, t := range g.tables {
			incoming, ok := file[t.table]
			if !ok {
				continue //an older primary that does not know this table: keep ours
			}
			if listenerOnly && !g.listener {
				if t.ownListener == nil || !sysdb.TableExists(t.table) {
					continue
				}
				local, err := readSyncedTable(t)
				if err != nil {
					return fmt.Errorf("table %s: %w", t.table, err)
				}
				for _, key := range t.keys {
					current, ok := local[key]
					if !ok {
						continue //no value here: the defaults apply, which is what this node had
					}
					var saved []byte
					if v, ok := incoming[key]; ok && !isJSONNull(v) {
						saved = v
					}
					if v := t.ownListener(key, saved, current); json.Valid(v) && !bytes.Equal(v, current) {
						if err := sysdb.Write(t.table, key, json.RawMessage(v)); err != nil {
							return fmt.Errorf("table %s key %s: %w", t.table, key, err)
						}
					}
				}
				continue
			}
			if err := sysdb.NewTable(t.table); err != nil {
				return fmt.Errorf("table %s: %w", t.table, err)
			}
			local, err := readSyncedTable(t)
			if err != nil {
				return fmt.Errorf("table %s: %w", t.table, err)
			}
			allowed := map[string]bool{}
			for _, k := range t.keys {
				allowed[k] = true
			}
			for key, value := range incoming {
				if t.keys != nil && !allowed[key] {
					continue
				}
				if restore && t.keys != nil && isJSONNull(value) {
					//this node did not have the key: the built-in default applies again
					if _, has := local[key]; has {
						if err := sysdb.Delete(t.table, key); err != nil {
							return fmt.Errorf("table %s key %s: %w", t.table, key, err)
						}
					}
					continue
				}
				if t.merge != nil {
					if m := t.merge(key, value, local[key], keepLocalListener); json.Valid(m) {
						value = m
					}
				}
				if err := sysdb.Write(t.table, key, value); err != nil {
					return fmt.Errorf("table %s key %s: %w", t.table, key, err)
				}
			}
			if t.keys == nil {
				for key := range local {
					if _, keep := incoming[key]; !keep {
						sysdb.Delete(t.table, key)
					}
				}
			}
		}
	}
	return nil
}

// clusterImportSettings runs once per start, after the database is open and
// before any module reads its settings. On anything but a follower that
// received settings it does nothing.
func clusterImportSettings() {
	if clusterMgr == nil || sysdb == nil {
		return
	}
	store := cluster.SettingsStore{Export: exportOwnClusterSettings, Import: importClusterSettings, Restore: restoreClusterSettings}
	if _, err := clusterMgr.ImportSyncedSettings(store); err != nil {
		SystemWideLogger.PrintAndLog("cluster", "Synced settings were not imported, this node keeps the values it has", err)
	}
}

// validateSettingsFile is the schema check of a settings file inside a snapshot.
func validateSettingsFile(data []byte) error {
	var file settingsFile
	return json.Unmarshal(data, &file)
}
