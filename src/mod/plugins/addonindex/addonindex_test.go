package addonindex

import (
	"errors"
	"strings"
	"testing"
)

const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func sample() string {
	return `{
  "format": "dunree-addon-index", "version": 1, "serial": 7,
  "store": {"name": "Test store", "publisher": "Example Ltd"},
  "addons": [
    {"id": "ie.example.good", "name": "Good", "publisher": "Example Ltd", "version": "1.2.3", "api_version": 1,
     "min_host_version": "1.0.0", "license": "AGPL-3.0-only", "type": "router", "categories": [" Security "],
     "permissions": [{"method": "GET", "endpoint": "/plugin/api/access/list", "reason": "read the list"}],
     "changelog": [{"version": "1.2.3", "date": "2026-11-01", "notes": "First"}],
     "screenshots": ["shots/1.png"], "icon": "icon.png",
     "artifacts": {
       "Linux/amd64": {"url": "a/good_linux_amd64", "sha256": "` + strings.ToUpper(sum) + `", "size": 10},
       "windows-x86_64": {"url": "a/good_windows_amd64.exe", "sha256": "` + sum + `", "size": 11},
       "macos_arm64": {"url": "a/good_darwin_arm64", "sha256": "` + sum + `", "size": 12}
     }},
    {"id": "ie.example.good", "name": "Twice", "publisher": "X", "version": "1.0.0", "artifacts": {"linux_amd64": {"url": "x", "sha256": "` + sum + `", "size": 1}}},
    {"id": "../evil", "name": "Bad id", "publisher": "X", "version": "1.0.0", "artifacts": {"linux_amd64": {"url": "x", "sha256": "` + sum + `", "size": 1}}},
    {"id": "ie.example.nosum", "name": "No sum", "publisher": "X", "version": "1.0.0", "artifacts": {"linux_amd64": {"url": "x", "sha256": "", "size": 1}}},
    {"id": "ie.example.nosize", "name": "No size", "publisher": "X", "version": "1.0.0", "artifacts": {"linux_amd64": {"url": "x", "sha256": "` + sum + `", "size": 0}}},
    {"id": "ie.example.badver", "name": "Bad version", "publisher": "X", "version": "one", "artifacts": {"linux_amd64": {"url": "x", "sha256": "` + sum + `", "size": 1}}},
    {"id": "ie.example.noart", "name": "No artifacts", "publisher": "X", "version": "1.0.0", "artifacts": {}},
    {"id": "ie.example.nopub", "name": "No publisher", "version": "1.0.0", "artifacts": {"linux_amd64": {"url": "x", "sha256": "` + sum + `", "size": 1}}},
    {"id": "ie.example.dupplat", "name": "Dup", "publisher": "X", "version": "1.0.0", "artifacts": {"linux_amd64": {"url": "x", "sha256": "` + sum + `", "size": 1}, "linux/x86_64": {"url": "y", "sha256": "` + sum + `", "size": 1}}},
    null
  ]
}`
}

func TestParseKeepsGoodEntriesAndReportsTheRest(t *testing.T) {
	idx, skipped, err := Parse([]byte(sample()))
	if err != nil {
		t.Fatal(err)
	}
	if idx.Serial != 7 || len(idx.Addons) != 1 {
		t.Fatalf("want serial 7 and one usable add-on, got serial %d and %d add-ons", idx.Serial, len(idx.Addons))
	}
	if len(skipped) != 9 {
		t.Fatalf("want 9 skipped entries, got %d: %+v", len(skipped), skipped)
	}
	a := idx.Addons[0]
	if a.Licence != "AGPL-3.0-only" || a.License != "" {
		t.Errorf("\"license\" must be folded into Licence, got %q / %q", a.Licence, a.License)
	}
	if a.Type != TypeRouter || a.Categories[0] != "Security" {
		t.Errorf("type or categories not normalised: %q %q", a.Type, a.Categories)
	}
	if got := strings.Join(a.Platforms(), ","); got != "darwin_arm64,linux_amd64,windows_amd64" {
		t.Errorf("platform keys not normalised: %s", got)
	}
	if a.Artifacts["linux_amd64"].SHA256 != sum {
		t.Errorf("sha256 must be lower case, got %s", a.Artifacts["linux_amd64"].SHA256)
	}
}

func TestParseRefusesOtherDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":       `nope`,
		"a list":         `[]`,
		"other format":   `{"format":"zoraxy-plugin-index","version":1,"addons":[]}`,
		"newer version":  `{"format":"dunree-addon-index","version":2,"addons":[]}`,
		"missing format": `{"version":1,"addons":[]}`,
	} {
		if _, _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if idx, _, err := Parse([]byte(`{"format":"dunree-addon-index","version":1,"serial":1,"addons":[]}`)); err != nil || len(idx.Addons) != 0 {
		t.Errorf("an empty index is valid: %v", err)
	}
}

func TestSelectArtifactByPlatform(t *testing.T) {
	idx, _, err := Parse([]byte(sample()))
	if err != nil {
		t.Fatal(err)
	}
	arts := idx.Addons[0].Artifacts
	for _, c := range []struct {
		goos, goarch, wantURL string
		ok                    bool
	}{
		{"linux", "amd64", "a/good_linux_amd64", true},
		{"windows", "amd64", "a/good_windows_amd64.exe", true},
		{"darwin", "arm64", "a/good_darwin_arm64", true},
		{"darwin", "amd64", "", false},  //never the build of another architecture
		{"linux", "arm64", "", false},   //never the build of another architecture
		{"windows", "arm64", "", false}, //no emulation guess
		{"freebsd", "amd64", "", false},
		{"", "", "", false},
	} {
		key, art, ok := SelectArtifact(arts, c.goos, c.goarch)
		if ok != c.ok || art.URL != c.wantURL {
			t.Errorf("%s/%s: got %q (%v, key %s), want %q (%v)", c.goos, c.goarch, art.URL, ok, key, c.wantURL, c.ok)
		}
	}
	//A map that did not go through Parse
	raw := map[string]Artifact{"Windows/x86_64": {URL: "w.exe"}}
	if _, art, ok := SelectArtifact(raw, "windows", "amd64"); !ok || art.URL != "w.exe" {
		t.Errorf("spelling variants must be found: %v %v", art, ok)
	}
}

func TestNormalisePlatform(t *testing.T) {
	for in, want := range map[string]string{
		"linux_amd64": "linux_amd64", "Linux/AMD64": "linux_amd64", "linux-aarch64": "linux_arm64", "macos_x86_64": "darwin_amd64",
		"windows_386": "windows_386", "linux_armv7": "linux_arm", "freebsd_riscv64": "freebsd_riscv64",
	} {
		if got, ok := NormalisePlatform(in); !ok || got != want {
			t.Errorf("%q: got %q (%v), want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "linux", "_amd64", "linux_", "li nux_amd64", "linux_amd64/../x", "linux_ämd"} {
		if got, ok := NormalisePlatform(bad); ok {
			t.Errorf("%q must be refused, got %q", bad, got)
		}
	}
}

func TestExecutableName(t *testing.T) {
	for _, c := range [][3]string{
		{"addon", "windows", "addon.exe"}, {"addon.exe", "windows", "addon.exe"}, {"Addon.EXE", "windows", "Addon.EXE"},
		{"addon", "linux", "addon"}, {"addon", "darwin", "addon"},
	} {
		if got := ExecutableName(c[0], c[1]); got != c[2] {
			t.Errorf("ExecutableName(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestVersionsAndMinimumHost(t *testing.T) {
	for in, want := range map[string][3]int{"1.2.3": {1, 2, 3}, "v1.0.0-beta.1": {1, 0, 0}, " 10.20.30+build5 ": {10, 20, 30}} {
		if got, ok := ParseVersion(in); !ok || got != want {
			t.Errorf("ParseVersion(%q) = %v (%v)", in, got, ok)
		}
	}
	for _, bad := range []string{"", "1", "1.2", "1.2.x", "1.2.3.4", "-1.0.0", "1..3"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) must fail", bad)
		}
	}
	for _, c := range []struct {
		min, host string
		want      bool
	}{
		{"", "anything", true},
		{"1.0.0", "1.0.0-beta.1", true},
		{"1.0.0", "1.0.0", true},
		{"1.0.1", "1.0.0", false},
		{"1.1.0", "1.0.9", false},
		{"1.0.0", "2.0.0", true},
		{"2.0.0", "1.99.99", false},
	} {
		got, err := HostSatisfies(c.min, c.host)
		if err != nil || got != c.want {
			t.Errorf("HostSatisfies(%q, %q) = %v, %v; want %v", c.min, c.host, got, err, c.want)
		}
	}
	if _, err := HostSatisfies("1.0.0", "test"); !errors.Is(err, ErrHostVersionUnknown) {
		t.Errorf("an unreadable host version must be reported as unknown, got %v", err)
	}
}

func TestValidID(t *testing.T) {
	for _, ok := range []string{"a", "ie.foleyit.geo-block", "Com.Example_1"} {
		if !ValidID(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "a..b", "a/b", `a\b`, "a b", "-x", strings.Repeat("a", 129), "ä"} {
		if ValidID(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
}
