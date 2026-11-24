package confpack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ExportOptions configures WriteExport.
type ExportOptions struct {
	ConfDir       string
	DBPath        string // "" = no system database (never used in shareable mode)
	Mode          string // ModeFull (default) or ModeShareable
	DunreeVersion string
	// SkipFull names conf files that even a full backup leaves out (per install secrets the app keeps sealed,
	// the audit log). The shareable mode has its own, stricter rules.
	SkipFull func(rel string) bool
	Now      func() time.Time
	// OmitManifest (full mode only) leaves manifest.json out, which gives the byte for byte layout of the historic
	// backup: a Dunree that predates the manifest restores that archive, and refuses one that carries manifest.json.
	OmitManifest bool
}

type zipSink struct {
	zw    *zip.Writer
	files []ManifestFile
}

func (z *zipSink) add(name string, r io.Reader) error {
	w, err := z.zw.Create(name)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), r)
	if err != nil {
		return err
	}
	z.files = append(z.files, ManifestFile{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

// WriteExport writes the archive and returns its manifest (already stored as the last entry).
func WriteExport(out io.Writer, o ExportOptions) (*Manifest, error) {
	if o.Mode == "" {
		o.Mode = ModeFull
	}
	if o.Mode != ModeFull && o.Mode != ModeShareable {
		return nil, fmt.Errorf("unknown export mode %q", o.Mode)
	}
	if o.OmitManifest && o.Mode != ModeFull {
		return nil, fmt.Errorf("a shareable export always carries its manifest")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	sink := &zipSink{zw: zip.NewWriter(out)}
	m := &Manifest{Format: ManifestFmt, SchemaVersion: SchemaVersion, ConfigSchema: CurrentConfigSchema, DunreeVersion: o.DunreeVersion,
		Mode: o.Mode, Created: o.Now().UTC().Format(time.RFC3339)}

	var rels []string
	err := filepath.WalkDir(o.ConfDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(o.ConfDir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".history" {
				return filepath.SkipDir //the sealed change history is per install and stays out of every export
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil //symlinks, sockets
		}
		if rel == SchemaFile+".tmp" {
			return nil //a half written stamp left by a crash
		}
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		sink.zw.Close()
		return nil, err
	}
	sort.Strings(rels)
	for _, rel := range rels {
		src := filepath.Join(o.ConfDir, filepath.FromSlash(rel))
		if o.Mode == ModeFull {
			if o.SkipFull != nil && o.SkipFull(rel) {
				continue
			}
			f, err := os.Open(src)
			if err != nil {
				sink.zw.Close()
				return nil, err
			}
			err = sink.add(ConfPrefix+rel, f)
			f.Close()
			if err != nil {
				sink.zw.Close()
				return nil, err
			}
			continue
		}
		// shareable
		kind, why := ShareableKind(rel)
		if kind == "" {
			if bad, w := NeverExported(rel); bad || inShareableRoot(rel) {
				m.Excluded = append(m.Excluded, Excluded{Path: rel, Reason: firstNonEmpty(w, why)})
			}
			continue //unlisted files (statistics, logs, geo data) are simply not configuration
		}
		data, err := os.ReadFile(src)
		if err != nil {
			sink.zw.Close()
			return nil, err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
			m.Excluded = append(m.Excluded, Excluded{Path: rel, Reason: "contains a private key"})
			continue
		}
		if kind == "json" {
			red, n, err := RedactJSON(data)
			if err != nil {
				m.Excluded = append(m.Excluded, Excluded{Path: rel, Reason: "not valid JSON, cannot be checked for secrets"})
				continue
			}
			data = red
			m.RedactedFields += n
		}
		if err := sink.add(ConfPrefix+rel, bytes.NewReader(data)); err != nil {
			sink.zw.Close()
			return nil, err
		}
	}
	if o.Mode == ModeFull && o.DBPath != "" {
		f, err := os.Open(o.DBPath)
		if err != nil {
			sink.zw.Close()
			return nil, err
		}
		err = sink.add(DBEntry, f)
		f.Close()
		if err != nil {
			sink.zw.Close()
			return nil, err
		}
		m.IncludesDB = true
	}
	if o.Mode == ModeShareable && o.DBPath != "" {
		m.Excluded = append(m.Excluded, Excluded{Path: DBEntry, Reason: "system database holds credentials and API tokens"})
	}
	m.Files = sink.files
	if o.OmitManifest && o.Mode == ModeFull {
		return m, sink.zw.Close()
	}
	if m.Files == nil {
		m.Files = []ManifestFile{}
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		sink.zw.Close()
		return nil, err
	}
	w, err := sink.zw.Create(ManifestName)
	if err == nil {
		_, err = w.Write(raw)
	}
	if err != nil {
		sink.zw.Close()
		return nil, err
	}
	return m, sink.zw.Close()
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
