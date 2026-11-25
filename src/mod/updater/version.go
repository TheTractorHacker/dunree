package updater

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Product is the product name signed into the header of SHA256SUMS and required there.
const Product = "dunree"

// AssetPrefix starts the name of every program file of a Dunree release.
const AssetPrefix = "dunree_"

// Tag is a parsed Dunree release tag: v<major>.<minor>.<patch> with an optional
// pre-release part, as in Semantic Versioning 2.0.0 (v1.0.0-beta.1, v1.0.0-rc.2, v1.0.0).
type Tag struct {
	Raw   string
	Major int
	Minor int
	Patch int
	Pre   []string // pre-release identifiers ("beta", "1"); empty for a final release
}

var tagRe = regexp.MustCompile(`^v?(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$`)

// ParseTag parses tags such as v1.0.0, v1.0.0-beta.1 or 1.2.3-rc.1 (the leading v is optional,
// so a bare version number parses too). Build metadata ("+...") is not accepted, nor is a numeric
// pre-release identifier with a leading zero (beta.01): it would order like beta.1 under another tag.
func ParseTag(s string) (Tag, error) {
	m := tagRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Tag{}, fmt.Errorf("unrecognised release tag %q", s)
	}
	atoi := func(x string) int { n, _ := strconv.Atoi(x); return n }
	t := Tag{Raw: s, Major: atoi(m[1]), Minor: atoi(m[2]), Patch: atoi(m[3])}
	if m[4] != "" {
		t.Pre = strings.Split(m[4], ".")
	}
	return t, nil
}

// BaseVersion returns "major.minor.patch".
func (t Tag) BaseVersion() string { return fmt.Sprintf("%d.%d.%d", t.Major, t.Minor, t.Patch) }

// Version returns the version without the leading v: "1.0.0-beta.1".
func (t Tag) Version() string {
	if len(t.Pre) == 0 {
		return t.BaseVersion()
	}
	return t.BaseVersion() + "-" + strings.Join(t.Pre, ".")
}

// IsPrerelease reports whether the tag has a pre-release part.
func (t Tag) IsPrerelease() bool { return len(t.Pre) > 0 }

// CompareTags orders two versions by Semantic Versioning precedence: -1 if a is
// older than b, 0 if they have the same precedence, +1 if a is newer.
//
// The triple is compared first. With equal triples a pre-release is older than
// the final release (1.0.0-rc.1 < 1.0.0), and two pre-releases are compared
// identifier by identifier: numbers as numbers (beta.2 < beta.10), a number
// before a word, words in ASCII order (alpha < beta < rc), and the shorter list
// first when one is the start of the other (beta < beta.1).
func CompareTags(a, b Tag) int {
	for _, p := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if p[0] != p[1] {
			return sign(p[0] - p[1])
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		if c := compareIdent(a.Pre[i], b.Pre[i]); c != 0 {
			return c
		}
	}
	return sign(len(a.Pre) - len(b.Pre))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func compareIdent(a, b string) int {
	an, bn := isNumeric(a), isNumeric(b)
	switch {
	case an && bn:
		// compare as numbers without converting: no leading zeros to trust, so strip them
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			return sign(len(a) - len(b))
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// BuildID identifies one build for ordering. Published is informational; it does
// not take part in the order.
type BuildID struct {
	Tag       Tag
	Published time.Time
}

// CompareReleases orders two builds by their version alone (CompareTags). The
// time a release was published and the signed build number are not part of the
// order: the first can change when a release is edited, the second is checked
// separately against replays (CheckSumsHeader).
func CompareReleases(a, b BuildID) int { return CompareTags(a.Tag, b.Tag) }

// Release is the subset of a GitHub release the updater needs.
type Release struct {
	Tag        string `json:"tag"`
	Name       string `json:"name"`
	Notes      string `json:"notes"`
	URL        string `json:"url"`
	Prerelease bool   `json:"prerelease"`
	// EarlyAccess marks releases the UI must label as early access: GitHub pre-releases and every
	// tag with a pre-release part (-beta.N, -rc.N), even when the GitHub pre-release flag was not
	// ticked (upstream #969). Such a release is never offered on the stable channel.
	EarlyAccess bool      `json:"early_access"`
	Published   time.Time `json:"published"`
	Assets      []Asset   `json:"assets"`
}

// Asset is a release asset.
type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"-"`
}

// MarkEarlyAccess sets EarlyAccess from the GitHub flag and the tag.
func (r *Release) MarkEarlyAccess() {
	r.EarlyAccess = r.Prerelease
	if t, err := ParseTag(r.Tag); err == nil && t.IsPrerelease() {
		r.EarlyAccess = true
	}
}

// ID returns the ordering identity of the release.
func (r Release) ID() (BuildID, error) {
	t, err := ParseTag(r.Tag)
	return BuildID{Tag: t, Published: r.Published}, err
}

// IsDunreeRelease reports whether a release of the source is a Dunree release as far as the
// release list can tell: it carries at least one program file named dunree_<os>_<arch>. A
// release of another product in the same repository (the fork Dunree comes from publishes
// v3.x tags with other file names) is not one, whatever its version number says. This is only
// the first filter; the signed header of SHA256SUMS must name the product too (CheckSumsHeader).
func IsDunreeRelease(r Release) bool {
	for _, a := range r.Assets {
		if isProgramAsset(a.Name) {
			return true
		}
	}
	return false
}

var programAssetRe = regexp.MustCompile(`^dunree_[a-z0-9]+_[a-z0-9]+(?:\.exe)?$`)

// isProgramAsset matches dunree_<os>_<arch>[.exe] and nothing else (not the
// archives and packages, whose names carry a version).
func isProgramAsset(name string) bool { return programAssetRe.MatchString(name) }

// Update channels.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// ValidChannel reports whether c is a known channel.
func ValidChannel(c string) bool { return c == ChannelStable || c == ChannelBeta }

// ErrNoRelease is returned by LatestForChannel when the source has no Dunree
// release on the channel. It is a state, not a failure of the check.
type ErrNoRelease struct {
	Channel string
	Other   int // releases that were skipped because they are not Dunree releases
}

func (e *ErrNoRelease) Error() string {
	msg := "no Dunree release found on the " + e.Channel + " channel"
	if e.Other > 0 {
		msg += fmt.Sprintf(" (%d release(s) of another product in this source were ignored)", e.Other)
	}
	return msg
}

// LatestForChannel returns the newest Dunree release visible on the channel.
// stable: final releases only (no GitHub pre-release flag and no pre-release part in the tag).
// beta: everything. Releases that are not Dunree releases (IsDunreeRelease) and
// releases with unparseable tags are skipped. Drafts must be filtered by the caller.
func LatestForChannel(rels []Release, channel string) (*Release, error) {
	type item struct {
		r  Release
		id BuildID
	}
	var items []item
	other := 0
	for _, r := range rels {
		if !IsDunreeRelease(r) {
			other++
			continue
		}
		id, err := r.ID()
		if err != nil {
			continue
		}
		if channel != ChannelBeta && (r.Prerelease || id.Tag.IsPrerelease()) {
			continue
		}
		items = append(items, item{r, id})
	}
	if len(items) == 0 {
		return nil, &ErrNoRelease{Channel: channel, Other: other}
	}
	sort.SliceStable(items, func(i, j int) bool { return CompareReleases(items[i].id, items[j].id) > 0 })
	r := items[0].r
	return &r, nil
}

// AssetName returns the release asset name for a platform: dunree_<os>_<arch>,
// with .exe for Windows.
func AssetName(goos, goarch string) string {
	n := AssetPrefix + goos + "_" + goarch
	if goos == "windows" {
		n += ".exe"
	}
	return n
}

// FindAsset finds a named asset in a release.
func FindAsset(r Release, name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Names of the signing assets attached to every release.
const (
	SumsAsset = "SHA256SUMS"
	SigAsset  = "SHA256SUMS.sig"
)

// VersionInOutput reports whether the output of `<program> -version` names
// exactly this version: the version must stand as a whole word, so that
// "1.0.0-beta.2" does not pass for "1.0.0".
func VersionInOutput(out, version string) bool {
	for _, f := range strings.Fields(out) {
		if strings.Trim(f, "(),;") == version || strings.Trim(f, "(),;") == "v"+version {
			return true
		}
	}
	return false
}
