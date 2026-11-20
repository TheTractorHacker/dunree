package confpack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// Limits bound what an uploaded archive may ask of the machine. Sizes are checked against the
// sizes the archive declares and again against the bytes actually produced while reading (a lying
// header cannot get past it).
type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxJSONBytes  int64 // largest JSON file that is parsed in memory
}

// DefaultLimits are generous for a real configuration (certificates, rule files, a system database).
var DefaultLimits = Limits{MaxFiles: 20000, MaxFileBytes: 1 << 30, MaxTotalBytes: 2 << 30, MaxJSONBytes: 16 << 20}

// Entry is one validated archive member.
type Entry struct {
	Name string // as stored
	Rel  string // conf relative path ("" for sys.db)
	DB   bool
	Size int64
	SHA  string // sha256 of the stored bytes, computed while checking
	f    *zip.File
}

// Archive is an archive that passed every check; nothing has been written anywhere yet.
type Archive struct {
	Entries  []Entry
	Manifest *Manifest // nil for archives of older builds
	Verified bool      // a manifest was present and every checksum matched
	Mode     string    // ModeFull for archives without manifest
	HasDB    bool
	Warnings []string
}

// jsonSanity validates the files whose damage would break the proxy: syntax for every JSON file,
// shape for proxy rules and access rules.
func jsonSanity(rel string, data []byte) error {
	if !isJSONName(rel) {
		return nil
	}
	v, err := decodeJSON(data)
	if err != nil {
		return fmt.Errorf("%q is not valid JSON: %v", rel, err)
	}
	obj, isObj := v.(map[string]any)
	switch {
	case strings.HasPrefix(rel, "proxy/") && strings.Count(rel, "/") == 1:
		if !isObj {
			return fmt.Errorf("%q: a proxy rule must be a JSON object", rel)
		}
		if s, ok := obj["RootOrMatchingDomain"].(string); !ok || s == "" {
			return fmt.Errorf("%q: proxy rule has no RootOrMatchingDomain", rel)
		}
	case strings.HasPrefix(rel, "access/") && strings.Count(rel, "/") == 1:
		if !isObj {
			return fmt.Errorf("%q: an access rule must be a JSON object", rel)
		}
		if s, ok := obj["ID"].(string); !ok || s == "" {
			return fmt.Errorf("%q: access rule has no ID", rel)
		}
	}
	return nil
}

// Inspect validates the whole archive before anything is written: entry names (zip-slip, absolute
// paths, drive letters, backslashes, symlinks, duplicates), counts and sizes, the manifest (format,
// schema version, a checksum for every entry) and the JSON of the proxy and access rule files.
// A "shareable" archive is also refused when it carries a system database.
func Inspect(zr *zip.Reader, lim Limits) (*Archive, error) {
	if lim.MaxFiles <= 0 {
		lim = DefaultLimits
	}
	if len(zr.File) > lim.MaxFiles {
		return nil, fmt.Errorf("the archive has %d entries, more than the limit of %d", len(zr.File), lim.MaxFiles)
	}
	a := &Archive{Mode: ModeFull}
	var manifestFile *zip.File
	seen := map[string]bool{}
	var total uint64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			if f.Name != "conf/" && f.Name != "conf" {
				if _, _, err := ValidEntryName(strings.TrimSuffix(f.Name, "/")); err != nil && f.Name != "" {
					return nil, err
				}
			}
			continue
		}
		if f.Mode()&fs.ModeSymlink != 0 || f.Mode()&(fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeIrregular) != 0 {
			return nil, fmt.Errorf("entry %q is not a regular file", clip(f.Name))
		}
		rel, kind, err := ValidEntryName(f.Name)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(f.Name)
		if seen[key] {
			return nil, fmt.Errorf("entry %q appears more than once", clip(f.Name))
		}
		seen[key] = true
		if f.UncompressedSize64 > uint64(lim.MaxFileBytes) {
			return nil, fmt.Errorf("entry %q is larger than the limit of %d bytes", clip(f.Name), lim.MaxFileBytes)
		}
		total += f.UncompressedSize64
		if total > uint64(lim.MaxTotalBytes) {
			return nil, fmt.Errorf("the archive expands to more than the limit of %d bytes", lim.MaxTotalBytes)
		}
		switch kind {
		case "manifest":
			if f.UncompressedSize64 > 8<<20 {
				return nil, ErrBadManifest
			}
			manifestFile = f
		case "db":
			a.HasDB = true
			a.Entries = append(a.Entries, Entry{Name: f.Name, DB: true, Size: int64(f.UncompressedSize64), f: f})
		default:
			a.Entries = append(a.Entries, Entry{Name: f.Name, Rel: rel, Size: int64(f.UncompressedSize64), f: f})
		}
	}
	if len(a.Entries) == 0 {
		return nil, errors.New("the zip file contains no configuration")
	}

	if manifestFile != nil {
		raw, err := readLimited(manifestFile, 8<<20)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
		}
		var m Manifest
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&m); err != nil || m.Format != ManifestFmt {
			return nil, fmt.Errorf("%w: not a Zoraxy export manifest", ErrBadManifest)
		}
		if m.SchemaVersion > SchemaVersion || m.ConfigSchema > CurrentConfigSchema {
			return nil, ErrNewerSchema
		}
		if m.SchemaVersion < 1 {
			return nil, fmt.Errorf("%w: schemaVersion missing", ErrBadManifest)
		}
		if m.Mode != ModeFull && m.Mode != ModeShareable {
			return nil, fmt.Errorf("%w: unknown mode %q", ErrBadManifest, clip(m.Mode))
		}
		if m.Mode == ModeShareable && a.HasDB {
			return nil, fmt.Errorf("%w: a shareable export cannot contain the system database", ErrBadManifest)
		}
		listed := map[string]ManifestFile{}
		for _, mf := range m.Files {
			if _, _, err := ValidEntryName(mf.Path); err != nil || mf.Path == ManifestName {
				return nil, fmt.Errorf("%w: bad path %q in the file list", ErrBadManifest, clip(mf.Path))
			}
			if _, dup := listed[strings.ToLower(mf.Path)]; dup {
				return nil, fmt.Errorf("%w: %q listed twice", ErrBadManifest, clip(mf.Path))
			}
			listed[strings.ToLower(mf.Path)] = mf
		}
		for _, e := range a.Entries {
			if _, ok := listed[strings.ToLower(e.Name)]; !ok {
				return nil, fmt.Errorf("%w: %q is in the archive but not in the manifest", ErrBadManifest, clip(e.Name))
			}
		}
		if len(listed) != len(a.Entries) {
			return nil, fmt.Errorf("%w: the manifest lists files that are not in the archive", ErrBadManifest)
		}
		a.Manifest, a.Mode = &m, m.Mode
	}

	// one pass over every member: real size bound, checksum, JSON sanity
	var actual int64
	for i := range a.Entries {
		e := &a.Entries[i]
		want := int64(-1)
		if e.Rel != "" && isJSONName(e.Rel) {
			want = lim.MaxJSONBytes
		}
		if a.Mode == ModeShareable && e.Rel != "" {
			if k, _ := ShareableKind(e.Rel); k == "" {
				return nil, fmt.Errorf("%w: a shareable archive contains %q, which a shareable export never carries", ErrBadManifest, clip(e.Rel))
			}
		}
		sum, n, data, err := hashEntry(e.f, lim.MaxFileBytes, want)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %v", clip(e.Name), err)
		}
		actual += n
		if actual > lim.MaxTotalBytes {
			return nil, fmt.Errorf("the archive expands to more than the limit of %d bytes", lim.MaxTotalBytes)
		}
		e.SHA, e.Size = sum, n
		if a.Manifest != nil {
			var mf ManifestFile
			for _, c := range a.Manifest.Files {
				if strings.EqualFold(c.Path, e.Name) {
					mf = c
					break
				}
			}
			if mf.SHA256 != sum || mf.Size != n {
				return nil, fmt.Errorf("%w: checksum of %q does not match (the archive was changed or is damaged)", ErrBadManifest, clip(e.Name))
			}
		}
		if data != nil {
			if err := jsonSanity(e.Rel, data); err != nil {
				return nil, err
			}
		} else if want >= 0 {
			return nil, fmt.Errorf("%s is larger than %d bytes for a configuration file", clip(e.Rel), lim.MaxJSONBytes)
		}
	}
	if a.Manifest != nil {
		a.Verified = true
	} else {
		a.Warnings = append(a.Warnings, "unverified: this archive has no manifest (created by an older Zoraxy), so its integrity cannot be checked")
	}
	return a, nil
}

func readLimited(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("too large")
	}
	return b, nil
}

// hashEntry reads a member once, counting real bytes. keep >= 0 also returns the content when it is at
// most keep bytes (nil when larger).
func hashEntry(f *zip.File, maxBytes, keep int64) (sum string, n int64, data []byte, err error) {
	rc, err := f.Open()
	if err != nil {
		return "", 0, nil, err
	}
	defer rc.Close()
	h := sha256.New()
	var buf bytes.Buffer
	keeping := keep >= 0
	r := io.LimitReader(rc, maxBytes+1)
	chunk := make([]byte, 64<<10)
	for {
		k, rerr := r.Read(chunk)
		if k > 0 {
			n += int64(k)
			if n > maxBytes {
				return "", n, nil, fmt.Errorf("expands to more than %d bytes", maxBytes)
			}
			h.Write(chunk[:k])
			if keeping {
				if n > keep {
					keeping, buf = false, bytes.Buffer{}
				} else {
					buf.Write(chunk[:k])
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", n, nil, rerr
		}
	}
	if keep >= 0 && keeping {
		data = buf.Bytes()
		if data == nil {
			data = []byte{}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), n, data, nil
}
