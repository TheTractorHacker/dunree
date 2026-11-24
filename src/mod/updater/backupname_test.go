// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Backups written before the rename are listed and pruned together with the new ones, oldest first.
func TestBackupsUnderBothPrefixes(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"zoraxy-pre-update-20260101-000000.zip", // legacy-compat
		"dunree-pre-update-20260102-000000.zip",
		"zoraxy-pre-update-20260103-000000.zip", // legacy-compat
		"dunree-pre-update-20260104-000000.zip",
		"unrelated.zip",
	}
	for _, n := range names {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o640)
	}
	info, err := ScanBackups(dir)
	if err != nil || info.Count != 4 {
		t.Fatalf("count %d err %v", info.Count, err)
	}
	for i := 0; i < 10; i++ { // more than keepBackups files, so pruning has to drop the oldest
		os.WriteFile(filepath.Join(dir, BackupPrefix+time.Date(2026, 2, 1+i, 0, 0, 0, 0, time.UTC).Format("20060102-150405")+".zip"), []byte("x"), 0o640)
	}
	pruneBackups(dir)
	if _, err := os.Stat(filepath.Join(dir, "zoraxy-pre-update-20260101-000000.zip")); !os.IsNotExist(err) { // legacy-compat
		t.Error("the oldest (legacy-named) backup was not pruned first")
	}
	if _, err := os.Stat(filepath.Join(dir, "unrelated.zip")); err != nil {
		t.Error("an unrelated file was removed")
	}
}
