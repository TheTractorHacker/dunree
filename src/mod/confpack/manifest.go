package confpack

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"strings"
)

const (
	ManifestName  = "manifest.json"
	ManifestFmt   = "zoraxy-config-export"
	SchemaVersion = 1 // archive format version written by this build and the newest one it accepts
	ModeFull      = "full"
	ModeShareable = "shareable"
	DBEntry       = "sys.db"
	ConfPrefix    = "conf/"
)

// ManifestFile lists one archive entry. Path is the entry name ("conf/proxy/a.config", "sys.db").
type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Excluded names a file a shareable export left out and why (never its content).
type Excluded struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Manifest describes an archive.
type Manifest struct {
	Format         string         `json:"format"`
	SchemaVersion  int            `json:"schemaVersion"`
	ConfigSchema   int            `json:"configSchema"`
	ZoraxyVersion  string         `json:"zoraxyVersion"`
	Mode           string         `json:"mode"`
	Created        string         `json:"created"`
	IncludesDB     bool           `json:"includesDB"`
	RedactedFields int            `json:"redactedFields,omitempty"`
	Files          []ManifestFile `json:"files"`
	Excluded       []Excluded     `json:"excluded,omitempty"`
}

var (
	// ErrNewerSchema: the archive was written by a newer build.
	ErrNewerSchema = errors.New("this archive was created by a newer Zoraxy (manifest schema version is higher than this build supports); update Zoraxy before importing it")
	// ErrBadManifest: manifest.json is unreadable or does not match the archive.
	ErrBadManifest = errors.New("manifest.json is invalid")
)

// ValidEntryName checks an archive entry name and returns the clean relative path below conf/
// ("" for sys.db and the manifest). It refuses everything that could leave the target folder:
// absolute paths, drive letters, backslashes, parent references, NUL and empty or "." segments.
func ValidEntryName(name string) (rel string, kind string, err error) {
	if name == DBEntry {
		return "", "db", nil
	}
	if name == ManifestName {
		return "", "manifest", nil
	}
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") {
		return "", "", fmt.Errorf("invalid entry name %q", clip(name))
	}
	if !strings.HasPrefix(name, ConfPrefix) {
		return "", "", fmt.Errorf("entry %q is outside conf/ (not a Zoraxy backup, or from a version that is too old)", clip(name))
	}
	rel = strings.TrimPrefix(name, ConfPrefix)
	if rel == "" || strings.HasPrefix(rel, "/") || strings.HasSuffix(rel, "/") {
		return "", "", fmt.Errorf("invalid entry name %q", clip(name))
	}
	if len(rel) > 1 && rel[1] == ':' { //C:...
		return "", "", fmt.Errorf("invalid entry name %q", clip(name))
	}
	for _, r := range name { //control characters forge log lines; U+2028/2029 break them too
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return "", "", fmt.Errorf("entry %q contains a control character", clip(name))
		}
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", "", fmt.Errorf("entry %q contains a path traversal or empty segment", clip(name))
		}
		//only where it matters: a Linux install may hold an old rule whose name has ':' in it and its backup must still import
		if runtime.GOOS == "windows" && windowsUnsafeName(seg) {
			return "", "", fmt.Errorf("entry %q has a name Windows cannot store safely (reserved device name, ':' or a trailing dot or space)", clip(name))
		}
	}
	if path.Clean(rel) != rel {
		return "", "", fmt.Errorf("entry %q is not a clean path", clip(name))
	}
	return rel, "conf", nil
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// windowsUnsafeName: alternate data streams (x.config:s), names that end in a dot or a space and device names (CON, NUL, COM1 ...)
func windowsUnsafeName(seg string) bool {
	return strings.Contains(seg, ":") || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") || reservedDeviceName(seg)
}

func reservedDeviceName(seg string) bool {
	base := strings.ToUpper(seg)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " ")
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
		return true
	}
	return false
}
