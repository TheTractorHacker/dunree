// Package addonindex reads the Dunree add-on index, format version 1.
//
// The format is specified in docs/plugins/addon-store.md. This package only
// parses and validates the document and picks the artifact for a platform. It
// does no network or file access and checks no signature: the plugin manager
// (mod/plugins, store_addon.go) fetches the index, verifies the detached
// ed25519 signature over its exact bytes and applies the verification mode.
//
// tools/addon-store writes this format. That tool is a standalone program
// outside the Go module, so it has its own copy of these structs; the tests of
// mod/plugins build the tool and read its output with this package, which keeps
// the two in step.
package addonindex

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	// Format is the value of "format" in a Dunree add-on index
	Format = "dunree-addon-index"
	// Version is the format version this package reads
	Version = 1

	maxAddons      = 5000
	maxListEntries = 64
	maxTextLen     = 4000
)

// Index is one add-on index document
type Index struct {
	Format    string     `json:"format"`
	Version   int        `json:"version"`
	Serial    int64      `json:"serial"`
	Generated string     `json:"generated,omitempty"`
	Store     *StoreInfo `json:"store,omitempty"`
	Addons    []*Addon   `json:"addons"`
}

// StoreInfo says whose store this is. It is information for people; trust comes
// from the signature of the index, never from these fields.
type StoreInfo struct {
	Name      string `json:"name,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Addon is one add-on of the index
type Addon struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Publisher      string              `json:"publisher"`
	Description    string              `json:"description,omitempty"`
	Homepage       string              `json:"homepage,omitempty"`
	Licence        string              `json:"licence,omitempty"`
	License        string              `json:"license,omitempty"` //accepted spelling, folded into Licence
	Version        string              `json:"version"`
	APIVersion     int                 `json:"api_version"`
	MinHostVersion string              `json:"min_host_version,omitempty"`
	Type           string              `json:"type,omitempty"` //router | utility
	Categories     []string            `json:"categories,omitempty"`
	Permissions    []Permission        `json:"permissions,omitempty"`
	Changelog      []ChangelogEntry    `json:"changelog,omitempty"`
	Screenshots    []string            `json:"screenshots,omitempty"`
	Icon           string              `json:"icon,omitempty"`
	Featured       bool                `json:"featured,omitempty"`
	Artifacts      map[string]Artifact `json:"artifacts"`
}

// Permission is one endpoint of the Dunree API the add-on asks to call. It is
// shown before the install; what the installed program declares is what the
// administrator approves.
type Permission struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason,omitempty"`
}

// ChangelogEntry describes one released version
type ChangelogEntry struct {
	Version string `json:"version"`
	Date    string `json:"date,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

// Artifact is the program file of an add-on for one platform
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Skipped is an add-on entry that was left out, and why
type Skipped struct {
	ID     string
	Reason string
}

// Types of an add-on
const (
	TypeRouter  = "router"
	TypeUtility = "utility"
)

// Parse reads an index. An error means the document is not a version 1 add-on
// index at all. An entry that breaks a rule is left out and reported in skipped;
// the other entries stay usable.
func Parse(raw []byte) (idx *Index, skipped []Skipped, err error) {
	var doc Index
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("not an add-on index: %w", err)
	}
	if doc.Format != Format {
		return nil, nil, fmt.Errorf("not an add-on index (format %q)", clip(doc.Format, 40))
	}
	if doc.Version != Version {
		return nil, nil, fmt.Errorf("add-on index of version %d, this Dunree reads version %d", doc.Version, Version)
	}
	if len(doc.Addons) > maxAddons {
		return nil, nil, fmt.Errorf("the index lists more than %d add-ons", maxAddons)
	}
	seen := map[string]bool{}
	kept := make([]*Addon, 0, len(doc.Addons))
	for i, a := range doc.Addons {
		if a == nil {
			skipped = append(skipped, Skipped{ID: "#" + strconv.Itoa(i), Reason: "empty entry"})
			continue
		}
		if reason := a.normalise(); reason != "" {
			skipped = append(skipped, Skipped{ID: clip(a.ID, 80), Reason: reason})
			continue
		}
		if seen[a.ID] {
			skipped = append(skipped, Skipped{ID: a.ID, Reason: "listed twice"})
			continue
		}
		seen[a.ID] = true
		kept = append(kept, a)
	}
	doc.Addons = kept
	return &doc, skipped, nil
}

// normalise tidies one entry and returns why it cannot be used, "" when it can
func (a *Addon) normalise() string {
	a.ID = strings.TrimSpace(a.ID)
	a.Name = strings.TrimSpace(a.Name)
	a.Publisher = strings.TrimSpace(a.Publisher)
	a.Version = strings.TrimSpace(a.Version)
	a.MinHostVersion = strings.TrimSpace(a.MinHostVersion)
	if a.Licence == "" {
		a.Licence = a.License
	}
	a.License = ""
	if !ValidID(a.ID) {
		return "the id is missing or has characters other than letters, digits, dot, dash and underscore"
	}
	if a.Name == "" || len(a.Name) > 100 {
		return "the name is missing or longer than 100 characters"
	}
	if a.Publisher == "" || len(a.Publisher) > 100 {
		return "the publisher is missing or longer than 100 characters"
	}
	if _, ok := ParseVersion(a.Version); !ok {
		return "the version is not of the form major.minor.patch"
	}
	if a.MinHostVersion != "" {
		if _, ok := ParseVersion(a.MinHostVersion); !ok {
			return "min_host_version is not of the form major.minor.patch"
		}
	}
	if a.APIVersion < 0 {
		return "api_version is negative"
	}
	switch strings.ToLower(strings.TrimSpace(a.Type)) {
	case "", TypeUtility, "utilities":
		a.Type = TypeUtility
	case TypeRouter:
		a.Type = TypeRouter
	default:
		return "type is neither router nor utility"
	}
	if len(a.Description) > maxTextLen {
		return "the description is too long"
	}
	if len(a.Categories) > maxListEntries || len(a.Permissions) > 4*maxListEntries || len(a.Changelog) > 4*maxListEntries || len(a.Screenshots) > maxListEntries {
		return "a list of the entry is too long"
	}
	for i, c := range a.Categories {
		a.Categories[i] = strings.TrimSpace(c)
	}
	if len(a.Artifacts) == 0 {
		return "no artifacts"
	}
	clean := make(map[string]Artifact, len(a.Artifacts))
	for key, art := range a.Artifacts {
		platform, ok := NormalisePlatform(key)
		if !ok {
			return "artifact platform " + strconv.Quote(clip(key, 40)) + " is not of the form os_arch"
		}
		if _, dup := clean[platform]; dup {
			return "platform " + platform + " is listed twice"
		}
		art.URL = strings.TrimSpace(art.URL)
		art.SHA256 = strings.ToLower(strings.TrimSpace(art.SHA256))
		if art.URL == "" {
			return "the " + platform + " artifact has no url"
		}
		if !validSHA256(art.SHA256) {
			return "the " + platform + " artifact has no sha256 of 64 hex digits"
		}
		if art.Size <= 0 {
			return "the " + platform + " artifact has no size"
		}
		clean[platform] = art
	}
	a.Artifacts = clean
	return ""
}

// ValidID says whether s can be the id of an add-on: 1 to 128 letters, digits,
// dots, dashes and underscores, starting with a letter or digit, without "..".
func ValidID(s string) bool {
	if s == "" || len(s) > 128 || strings.Contains(s, "..") {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '.' || r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

/* Platforms */

var osAlias = map[string]string{"macos": "darwin", "osx": "darwin", "win": "windows", "win32": "windows"}
var archAlias = map[string]string{"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64", "i386": "386", "x86": "386", "armv7": "arm", "armhf": "arm"}

// PlatformKey is the key of an artifact for an operating system and CPU
// architecture as Go names them (runtime.GOOS, runtime.GOARCH): "linux_amd64".
func PlatformKey(goos, goarch string) string {
	return strings.ToLower(goos) + "_" + strings.ToLower(goarch)
}

// NormalisePlatform turns the spellings people use ("Linux/amd64",
// "windows-x86_64", "macos_arm64") into the key form "os_arch".
func NormalisePlatform(key string) (string, bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	sep := strings.IndexAny(k, "_/-")
	if sep <= 0 || sep == len(k)-1 {
		return "", false
	}
	goos, goarch := k[:sep], k[sep+1:]
	if alias, ok := osAlias[goos]; ok {
		goos = alias
	}
	if alias, ok := archAlias[goarch]; ok {
		goarch = alias
	}
	for _, part := range []string{goos, goarch} {
		if part == "" || len(part) > 20 {
			return "", false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
				return "", false
			}
		}
	}
	return goos + "_" + goarch, true
}

// SelectArtifact picks the artifact of an add-on for a platform. Only an exact
// match of operating system and architecture is used: an add-on is a native
// program, and a build for another architecture is never installed in its place.
func SelectArtifact(artifacts map[string]Artifact, goos, goarch string) (key string, art Artifact, ok bool) {
	want, valid := NormalisePlatform(PlatformKey(goos, goarch))
	if !valid {
		return "", Artifact{}, false
	}
	if art, ok = artifacts[want]; ok {
		return want, art, true
	}
	//An index that was not read through Parse may still carry other spellings
	for k, candidate := range artifacts {
		if n, valid := NormalisePlatform(k); valid && n == want {
			return k, candidate, true
		}
	}
	return "", Artifact{}, false
}

// Platforms lists the platform keys of an add-on, sorted
func (a *Addon) Platforms() []string {
	out := make([]string, 0, len(a.Artifacts))
	for k := range a.Artifacts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ExecutableName is the file name of a program on an operating system: Windows
// only runs it with the extension .exe.
func ExecutableName(base string, goos string) string {
	if strings.EqualFold(goos, "windows") && !strings.HasSuffix(strings.ToLower(base), ".exe") {
		return base + ".exe"
	}
	return base
}

/* Versions */

// ParseVersion reads "major.minor.patch", with an optional leading "v" and an
// optional pre-release or build suffix ("1.0.0-beta.1"), which is not compared.
func ParseVersion(s string) (v [3]int, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if cut := strings.IndexAny(s, "-+"); cut >= 0 {
		s = s[:cut]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if p == "" || len(p) > 9 {
			return v, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// CompareVersions returns -1, 0 or 1
func CompareVersions(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ErrHostVersionUnknown: the version of the host could not be read, so a
// minimum host version could not be compared
var ErrHostVersionUnknown = errors.New("the version of this host is not known")

// HostSatisfies says whether a host of version hostVersion may run an add-on
// that needs at least minHostVersion. An empty minimum is always satisfied. A
// pre-release of a version counts as that version ("1.0.0-beta.1" satisfies
// "1.0.0"): the beta line is where add-ons for it are built.
func HostSatisfies(minHostVersion string, hostVersion string) (bool, error) {
	if strings.TrimSpace(minHostVersion) == "" {
		return true, nil
	}
	min, ok := ParseVersion(minHostVersion)
	if !ok {
		return false, fmt.Errorf("min_host_version %q is not a version", clip(minHostVersion, 40))
	}
	host, ok := ParseVersion(hostVersion)
	if !ok {
		return false, ErrHostVersionUnknown
	}
	return CompareVersions(host, min) >= 0, nil
}
