// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package updater

import "strings"

// Pre-update backups are written as dunree-pre-update-<ts>.zip. Backups an earlier build wrote
// are called zoraxy-pre-update-<ts>.zip; they stay listed, counted and pruned (plan row 33).
const (
	BackupPrefix       = "dunree-pre-update-"
	LegacyBackupPrefix = "zoraxy-pre-update-" // legacy-compat
)

// IsBackupName reports whether a file name is a pre-update backup, under either prefix.
func IsBackupName(name string) bool {
	return strings.HasSuffix(name, ".zip") && (strings.HasPrefix(name, BackupPrefix) || strings.HasPrefix(name, LegacyBackupPrefix))
}

// backupStamp is the part of a backup name after its prefix (the timestamp)
func backupStamp(name string) string {
	if strings.HasPrefix(name, BackupPrefix) {
		return name[len(BackupPrefix):]
	}
	return strings.TrimPrefix(name, LegacyBackupPrefix)
}
