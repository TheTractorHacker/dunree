package confpack

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

// SchemaFile is the config schema stamp, stored in the config folder next to the other config files.
const SchemaFile = "config_schema.json"

// CurrentConfigSchema is the config schema this build writes. Version 1 only introduces the stamp
// (nothing in the config files changed), so there is no migration step yet.
const CurrentConfigSchema = 1

type schemaStamp struct {
	Schema  int    `json:"schema"`
	Updated string `json:"updated"`
	By      string `json:"by,omitempty"`
}

// Migration upgrades the config folder from schema From to From+1. Run must be idempotent: it can be
// interrupted and started again from the same state.
type Migration struct {
	From int
	Name string
	Run  func(confDir string) error
}

// Migrations is the registry, ordered by From. Add an entry (and raise CurrentConfigSchema) for a change
// that needs existing files rewritten.
var Migrations = []Migration{}

// MigrateResult says what Migrate did.
type MigrateResult struct {
	From, To int
	Stamped  bool     // the stamp file was written
	Ran      []string // migrations that ran
	Backup   string   // folder holding the copy taken before the first migration ("" = none needed)
	Newer    bool     // the folder was written by a newer build: nothing was changed
}

// ReadSchema returns the stamped schema, 0 when the folder has no stamp (config of an older build).
func ReadSchema(confDir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(confDir, SchemaFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var s schemaStamp
	if err := json.Unmarshal(b, &s); err != nil || s.Schema < 0 {
		return 0, fmt.Errorf("%s is damaged: %v", SchemaFile, err)
	}
	return s.Schema, nil
}

func writeStamp(confDir string, v int, by string, now time.Time) error {
	b, _ := json.MarshalIndent(schemaStamp{Schema: v, Updated: now.UTC().Format(time.RFC3339), By: by}, "", "  ")
	tmp := filepath.Join(confDir, SchemaFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(confDir, SchemaFile))
}

// Migrate brings confDir to the current schema. A missing folder is left alone. A folder stamped with a
// newer schema is not touched (Newer = true). When migration steps have to run, the folder is first copied
// to <confDir>.premigrate_<from>_<unix> (without .history and geodb); a stamp-only upgrade changes no data and
// needs no copy. A failing step stops everything and leaves the stamp unchanged, so the next start retries.
// Running it again at the current schema does nothing.
func Migrate(confDir string, reg []Migration, by string, now time.Time) (*MigrateResult, error) {
	res := &MigrateResult{To: CurrentConfigSchema}
	if st, err := os.Stat(confDir); err != nil || !st.IsDir() {
		return res, nil
	}
	cur, err := ReadSchema(confDir)
	if err != nil {
		return res, err
	}
	res.From = cur
	if cur > CurrentConfigSchema {
		res.Newer = true
		return res, nil
	}
	if cur == CurrentConfigSchema {
		return res, nil
	}
	var pending []Migration
	for v := cur; v < CurrentConfigSchema; v++ {
		for _, m := range reg {
			if m.From == v {
				pending = append(pending, m)
			}
		}
	}
	if len(pending) > 0 {
		bak := fmt.Sprintf("%s.premigrate_%d_%d", confDir, cur, now.Unix())
		if err := copyTree(confDir, bak); err != nil {
			os.RemoveAll(bak)
			return res, fmt.Errorf("could not back up the configuration before migrating: %w", err)
		}
		res.Backup = bak
		for _, m := range pending {
			if err := m.Run(confDir); err != nil {
				return res, fmt.Errorf("migration %q failed (the copy %s is untouched): %w", m.Name, bak, err)
			}
			res.Ran = append(res.Ran, m.Name)
		}
	}
	if err := writeStamp(confDir, CurrentConfigSchema, by, now); err != nil {
		return res, err
	}
	res.Stamped = true
	return res, nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if rel == ".history" || rel == "geodb" || strings.Contains(rel, ".premigrate_") {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o775)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(p, filepath.Join(dst, rel))
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
