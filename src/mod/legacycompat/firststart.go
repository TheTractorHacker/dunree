// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package legacycompat

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

/*
	First Dunree start on a configuration folder

	Dunree reads the configuration folder, the database, the certificates, the API tokens and the plugin
	folder of the program it is based on without converting anything: none of those files carries the old
	product name. What the first start adds is a safety net and a record:

	  <conf>.pre-dunree-<UTC time>     a copy of the configuration folder as it was (without geodb/, which
	                                   is downloaded data)
	  <dbpath>.pre-dunree-<UTC time>   a copy of the database, unless it is larger than the limit
	  <conf>/dunree_install.json       the marker: where the install came from and where the copies are

	With the marker in place the next start does nothing, so the copy is taken exactly once. Nothing in the
	configuration folder is changed, moved or deleted by this code; it only adds the marker file.
*/

const (
	// MarkerFile is written into the configuration folder at the first Dunree start.
	MarkerFile = "dunree_install.json"
	// BackupInfix separates the copied path from the time stamp: conf.pre-dunree-20261124-101500
	BackupInfix = ".pre-dunree-"
	// DefaultMaxDBCopy is the largest database the first start copies by itself.
	DefaultMaxDBCopy int64 = 1 << 30

	OriginLegacy = "zoraxy" // legacy-compat: the install was created by the program Dunree is based on
	OriginDunree = "dunree" // the install was created by Dunree

	ActionNone     = "none"     // marker present: nothing done
	ActionFresh    = "fresh"    // new install: marker written, nothing to copy
	ActionMigrated = "migrated" // existing install: copy taken, marker written
	ActionAdopted  = "adopted"  // existing install whose copy already exists (marker was lost): marker written again
)

// Marker is the content of MarkerFile.
type Marker struct {
	Product      string   `json:"product"`
	Origin       string   `json:"origin"`
	FirstStart   string   `json:"first_start"`
	FirstVersion string   `json:"first_version,omitempty"`
	BasedOn      string   `json:"based_on,omitempty"`
	ConfBackup   string   `json:"conf_backup,omitempty"`
	DBBackup     string   `json:"db_backup,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// FirstStartOptions are the inputs of FirstStart.
type FirstStartOptions struct {
	ConfDir   string    // configuration folder (-conf)
	DBPath    string    // database path (-dbpath), "" = no database copy
	Fresh     bool      // true when this start found no configuration and no database at all
	Version   string    // Dunree version, recorded in the marker
	BasedOn   string    // version of the base the install is compatible with, recorded in the marker
	Now       time.Time // zero = time.Now()
	MaxDBCopy int64     // 0 = DefaultMaxDBCopy, negative = never copy the database
	SkipDirs  []string  // top level folders of ConfDir left out of the copy, nil = {"geodb"}
}

// FirstStartResult says what FirstStart did.
type FirstStartResult struct {
	Action string
	Marker Marker
	Files  int   // files copied from the configuration folder
	Bytes  int64 // their size
}

// ReadMarker returns the marker of confDir. ok is false when there is none or it cannot be read.
func ReadMarker(confDir string) (m Marker, ok bool) {
	b, err := os.ReadFile(filepath.Join(confDir, MarkerFile))
	if err != nil {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil || m.Product == "" {
		return Marker{}, false
	}
	return m, true
}

// FirstStart records the first Dunree start in o.ConfDir and, for an install that existed before, copies
// the configuration folder and the database aside first. It is idempotent: with a marker in place it
// returns ActionNone without touching anything. When the copy of the configuration folder fails, the
// partial copy is removed, no marker is written and the error is returned, so the next start tries again;
// the caller is expected to log the error and carry on (the configuration itself was not touched).
func FirstStart(o FirstStartOptions) (*FirstStartResult, error) {
	res := &FirstStartResult{Action: ActionNone}
	if o.ConfDir == "" {
		return res, errors.New("no configuration folder given")
	}
	if m, ok := ReadMarker(o.ConfDir); ok {
		res.Marker = m
		return res, nil
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	stamp := now.UTC().Format("20060102-150405")
	m := Marker{Product: OriginDunree, Origin: OriginDunree, FirstStart: now.UTC().Format(time.RFC3339),
		FirstVersion: o.Version, BasedOn: o.BasedOn}

	if o.Fresh {
		res.Action = ActionFresh
		res.Marker = m
		return res, writeMarker(o.ConfDir, m)
	}

	m.Origin = OriginLegacy
	res.Action = ActionMigrated
	//absolute: "-conf ." must not put the copy inside the folder it copies ("..pre-dunree-..." in the working folder)
	confBase := absClean(o.ConfDir)

	if prev := existingBackups(confBase); len(prev) > 0 {
		// The copy was taken by an earlier start and the marker went missing since (for example a full
		// configuration import replaced the folder). Do not fill the disk with a second copy.
		res.Action = ActionAdopted
		m.ConfBackup = prev[len(prev)-1]
		m.Notes = append(m.Notes, "marker written again; the copy from the first start was kept")
	} else if st, err := os.Stat(confBase); err == nil && st.IsDir() {
		dst := freeName(confBase + BackupInfix + stamp)
		skip := o.SkipDirs
		if skip == nil {
			skip = []string{"geodb"}
		}
		n, size, err := copyTreeAtomic(confBase, dst, skip)
		if err != nil {
			return res, fmt.Errorf("could not copy %s to %s before the first Dunree start: %w", confBase, dst, err)
		}
		res.Files, res.Bytes = n, size
		m.ConfBackup = dst
		if len(skip) > 0 {
			m.Notes = append(m.Notes, "left out of the copy: "+strings.Join(skip, ", "))
		}
	}

	if res.Action == ActionMigrated && o.DBPath != "" {
		dbBackup, note := backupDatabase(absClean(o.DBPath), stamp, o.MaxDBCopy)
		m.DBBackup = dbBackup
		if note != "" {
			m.Notes = append(m.Notes, note)
		}
	}

	res.Marker = m
	return res, writeMarker(o.ConfDir, m)
}

func writeMarker(confDir string, m Marker) error {
	if err := os.MkdirAll(confDir, 0o775); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := filepath.Join(confDir, MarkerFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(confDir, MarkerFile))
}

// absClean returns p as an absolute, clean path (p itself when the working folder cannot be read).
func absClean(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

// existingBackups lists finished copies of base, oldest first (the time stamp sorts). It reads the parent
// folder instead of using a glob: glob escaping does not exist on Windows, so a path with [ or \ in it would
// never match there and every start after a lost marker would take another copy.
func existingBackups(base string) []string {
	dir, prefix := filepath.Split(base)
	if dir == "" {
		dir = "."
	}
	prefix += BackupInfix
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents { //ReadDir sorts by name
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || strings.HasSuffix(name, partialSuffix) {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// freeName returns p, or p-2, p-3 ... when p exists already.
func freeName(p string) string {
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return p
	}
	for i := 2; ; i++ {
		c := fmt.Sprintf("%s-%d", p, i)
		if _, err := os.Lstat(c); errors.Is(err, fs.ErrNotExist) {
			return c
		}
	}
}

const partialSuffix = ".partial"

// copyTreeAtomic copies src to dst through dst.partial, so a copy that was interrupted never looks finished.
func copyTreeAtomic(src, dst string, skipTop []string) (files int, size int64, err error) {
	tmp := dst + partialSuffix
	os.RemoveAll(tmp)
	files, size, err = copyTree(src, tmp, skipTop)
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.RemoveAll(tmp)
		return 0, 0, err
	}
	return files, size, nil
}

// copyTree copies regular files and symbolic links (as links) with their permission bits. The top folder
// of the copy is private (0700): the configuration holds keys and credentials.
func copyTree(src, dst string, skipTop []string) (files int, size int64, err error) {
	root, err := filepath.EvalSymlinks(src) //WalkDir does not descend into a root that is a link
	if err != nil {
		return 0, 0, err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return 0, 0, err
	}
	//the copy itself can lie inside the tree (a configuration folder of "/", or a link that points above
	//itself): never walk into it, or the copy copies itself until the path is too long
	dstReal, err := filepath.EvalSymlinks(dst)
	if err != nil {
		return 0, 0, err
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir() && p == dstReal:
			return filepath.SkipDir
		case d.IsDir():
			for _, s := range skipTop {
				if rel == s {
					return filepath.SkipDir
				}
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			n, err := copyFile(p, target)
			files++
			size += n
			return err
		}
		return nil //sockets, devices: nothing to copy
	})
	return files, size, err
}

func copyFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, st.Mode().Perm())
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		os.Chtimes(dst, st.ModTime(), st.ModTime())
	}
	return n, err
}

func treeSize(p string) (int64, error) {
	var total int64
	err := filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}

// backupDatabase copies the database (one file for BoltDB, a folder for LevelDB) next to itself. It never
// fails the start: when the copy is skipped or fails, the reason is returned as a note for the marker.
func backupDatabase(dbPath, stamp string, max int64) (backup string, note string) {
	if max == 0 {
		max = DefaultMaxDBCopy
	}
	st, err := os.Stat(dbPath)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ""
	}
	if err != nil {
		return "", "database not copied: " + err.Error()
	}
	if max < 0 {
		return "", "database not copied (disabled)"
	}
	size := st.Size()
	if st.IsDir() {
		if size, err = treeSize(dbPath); err != nil {
			return "", "database not copied: " + err.Error()
		}
	}
	if size > max {
		return "", fmt.Sprintf("database not copied: %d bytes is over the limit of %d bytes for an automatic copy; copy %s by hand while Dunree is stopped if you want one", size, max, dbPath)
	}
	dst := freeName(dbPath + BackupInfix + stamp)
	if st.IsDir() {
		if _, _, err := copyTreeAtomic(dbPath, dst, nil); err != nil {
			return "", "database not copied: " + err.Error()
		}
		return dst, ""
	}
	tmp := dst + partialSuffix
	os.Remove(tmp)
	if _, err := copyFile(dbPath, tmp); err == nil {
		err = os.Rename(tmp, dst)
		if err == nil {
			return dst, ""
		}
	}
	os.Remove(tmp)
	return "", "database not copied: could not write " + dst
}
