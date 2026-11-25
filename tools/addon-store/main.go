// addon-store - static site generator for a Dunree add-on store.
//
// This is a standalone program (stdlib only). It is NOT part of the Dunree
// binary and not part of the Go module; run it with
// `go run tools/addon-store/main.go` from the repository root.
//
// It reads add-on manifests from a folder, verifies the program files they
// name, and writes a folder that any static web server can serve (or that a
// Dunree reads as a "Local folder" source):
//
//	OUT/index.json        the Dunree add-on index, format version 1
//	OUT/index.json.sig    its detached ed25519 signature
//	OUT/index.pub         the public key administrators give to Dunree (with -pub)
//	OUT/index.html        a catalogue people can browse
//	OUT/addons/<id>/<version>/<file>     the program files (artifacts)
//	OUT/addons/<id>/icon.*, screenshots/ pictures
//
// The format is specified in docs/plugins/addon-store.md; how an add-on is
// published with this tool is in docs/plugins/publishing-addons.md.
//
// Usage:
//
//	go run tools/addon-store/main.go -in ADDONS -out OUT -key PRIVATE.pem [-pub PUBLIC.pem]
//	       [-serial N] [-base-url https://host/path/] [-store-name NAME] [-publisher NAME]
//	       [-introspect] [-skip-binary-check] [-signer BINARY | -signer-src FILE.go]
//	go run tools/addon-store/main.go -in ADDONS -check        verify the manifests and files, write nothing
//	go run tools/addon-store/main.go -in ADDONS -out OUT -unsigned   no signature (tests, a private folder)
//
// Signing is done by tools/plugin-index/sign_plugin_index.go (-sign-raw): this
// program never opens the private key, it only passes its path on. The key is
// the plugin index key, created with `sign_plugin_index.go -genkey`; it is never
// the key Dunree releases are signed with.
//
// Input: one folder per add-on, with a manifest addon.json:
//
//	ADDONS/geo-block/addon.json
//	ADDONS/geo-block/icon.png
//	ADDONS/geo-block/artifacts/geo-block_linux_amd64
//	ADDONS/geo-block/artifacts/geo-block_windows_amd64.exe
//
//	{
//	  "id": "ie.foleyit.geo-block", "name": "Geo block", "publisher": "Foley IT",
//	  "description": "...", "homepage": "https://...", "licence": "AGPL-3.0-only",
//	  "version": "1.2.0", "api_version": 1, "min_host_version": "1.0.0",
//	  "type": "router", "categories": ["Security"],
//	  "permissions": [{"method": "GET", "endpoint": "/plugin/api/access/list", "reason": "..."}],
//	  "changelog": [{"version": "1.2.0", "date": "2026-11-20", "notes": "..."}],
//	  "icon": "icon.png", "screenshots": ["screenshots/rules.png"],
//	  "artifacts": {"linux_amd64": "artifacts/geo-block_linux_amd64"}
//	}
//
// Without "artifacts" every file in artifacts/ whose name ends in
// _<os>_<arch> (plus .exe for Windows) is taken.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	indexFormat  = "dunree-addon-index"
	indexVersion = 1
	maxArtifact  = 1 << 30
	maxPicture   = 4 << 20
)

/* The index, as docs/plugins/addon-store.md specifies it (and src/mod/plugins/addonindex reads it) */

type index struct {
	Format    string     `json:"format"`
	Version   int        `json:"version"`
	Serial    int64      `json:"serial"`
	Generated string     `json:"generated,omitempty"`
	Store     *storeInfo `json:"store,omitempty"`
	Addons    []*addon   `json:"addons"`
}

type storeInfo struct {
	Name      string `json:"name,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	URL       string `json:"url,omitempty"`
}

type addon struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Publisher      string              `json:"publisher"`
	Description    string              `json:"description,omitempty"`
	Homepage       string              `json:"homepage,omitempty"`
	Licence        string              `json:"licence,omitempty"`
	Version        string              `json:"version"`
	APIVersion     int                 `json:"api_version"`
	MinHostVersion string              `json:"min_host_version,omitempty"`
	Type           string              `json:"type,omitempty"`
	Categories     []string            `json:"categories,omitempty"`
	Permissions    []permission        `json:"permissions,omitempty"`
	Changelog      []changelogEntry    `json:"changelog,omitempty"`
	Screenshots    []string            `json:"screenshots,omitempty"`
	Icon           string              `json:"icon,omitempty"`
	Featured       bool                `json:"featured,omitempty"`
	Artifacts      map[string]artifact `json:"artifacts"`
}

type permission struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason,omitempty"`
}

type changelogEntry struct {
	Version string `json:"version"`
	Date    string `json:"date,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

type artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

/* The manifest a publisher writes */

type manifest struct {
	ID             string                     `json:"id"`
	Name           string                     `json:"name"`
	Publisher      string                     `json:"publisher"`
	Description    string                     `json:"description"`
	Homepage       string                     `json:"homepage"`
	Licence        string                     `json:"licence"`
	License        string                     `json:"license"`
	Version        string                     `json:"version"`
	APIVersion     int                        `json:"api_version"`
	MinHostVersion string                     `json:"min_host_version"`
	Type           string                     `json:"type"`
	Categories     []string                   `json:"categories"`
	Permissions    []permission               `json:"permissions"`
	Changelog      []changelogEntry           `json:"changelog"`
	Screenshots    []string                   `json:"screenshots"`
	Icon           string                     `json:"icon"`
	Featured       bool                       `json:"featured"`
	Artifacts      map[string]json.RawMessage `json:"artifacts"`
}

// manifestArtifact is the long form of an artifact in a manifest; the short form is just the file path
type manifestArtifact struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"` //optional: the checksum the publisher expects, compared with the file
}

// built is an add-on that passed every check, with the files to publish
type built struct {
	entry *addon
	files []publishFile
}

type publishFile struct {
	src string //file on disk
	rel string //path below the output folder, with forward slashes
}

type options struct {
	in, out            string
	keyPath, pubPath   string
	serial             int64
	baseURL            string
	storeName          string
	publisher          string
	storeURL           string
	signer, signerSrc  string
	unsigned, check    bool
	introspect         bool
	skipBinaryCheck    bool
	now                func() time.Time
	stdout, stderr     io.Writer
	hostGOOS, hostArch string
}

func main() {
	o := options{now: time.Now, stdout: os.Stdout, stderr: os.Stderr, hostGOOS: runtime.GOOS, hostArch: runtime.GOARCH}
	flag.StringVar(&o.in, "in", "", "folder with one sub-folder per add-on, each with an addon.json")
	flag.StringVar(&o.out, "out", "", "folder the store is written to (kept between runs: older program files stay available)")
	flag.StringVar(&o.keyPath, "key", "", "path of the private add-on index key; passed on to the signer, never opened here. Empty: the signer reads $ZORAXY_PLUGIN_INDEX_KEY")
	flag.StringVar(&o.pubPath, "pub", "", "path of the public add-on index key: the signature is verified with it and it is published as index.pub")
	flag.Int64Var(&o.serial, "serial", 0, "serial number of this index. Default: one more than the index that is already in -out")
	flag.StringVar(&o.baseURL, "base-url", "", "address the output folder will be served at, e.g. https://addons.example.org/. Empty: addresses relative to index.json, which work wherever the folder is served, and in a local folder")
	flag.StringVar(&o.storeName, "store-name", "Dunree add-on store", "name of the store, shown in the catalogue")
	flag.StringVar(&o.publisher, "publisher", "", "who runs the store, shown in the catalogue")
	flag.StringVar(&o.storeURL, "store-url", "", "home page of the store (optional)")
	flag.StringVar(&o.signer, "signer", "", "a built sign_plugin_index program. Default: go run -signer-src")
	flag.StringVar(&o.signerSrc, "signer-src", "", "path of sign_plugin_index.go. Default: tools/plugin-index/sign_plugin_index.go, looked up from the working directory")
	flag.BoolVar(&o.unsigned, "unsigned", false, "write the index without a signature (tests, a private local folder). Dunree shows such an index as not signed and refuses it in enforce mode")
	flag.BoolVar(&o.check, "check", false, "verify the manifests and program files and write nothing")
	flag.BoolVar(&o.introspect, "introspect", false, "also run the program file for this machine with -introspect and compare its id and version with the manifest")
	flag.BoolVar(&o.skipBinaryCheck, "skip-binary-check", false, "do not check that a program file is an executable for the platform it is listed under")
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.in == "" {
		return errors.New("-in is required")
	}
	if !o.check && o.out == "" {
		return errors.New("-out is required (or -check to only verify)")
	}
	base, err := parseBaseURL(o.baseURL)
	if err != nil {
		return err
	}
	addons, err := loadAddons(o, base)
	if err != nil {
		return err
	}
	if o.check {
		fmt.Fprintf(o.stdout, "OK: %d add-ons verified, nothing written\n", len(addons))
		return nil
	}
	if !o.unsigned && o.keyPath == "" && os.Getenv("ZORAXY_PLUGIN_INDEX_KEY") == "" {
		return errors.New("no private key: pass -key (or set ZORAXY_PLUGIN_INDEX_KEY), or -unsigned for an index without a signature")
	}

	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	indexPath := filepath.Join(o.out, "index.json")
	previous := previousSerial(indexPath)
	serial := o.serial
	if serial == 0 {
		serial = previous + 1
	}
	if serial <= previous {
		return fmt.Errorf("the index in %s has serial %d: -serial must be higher (Dunree refuses an index that is older than one it has seen)", o.out, previous)
	}

	// Program files and pictures first: an index never names a file that is not there yet
	for _, b := range addons {
		for _, f := range b.files {
			if err := publish(f.src, filepath.Join(o.out, filepath.FromSlash(f.rel))); err != nil {
				return fmt.Errorf("add-on %s: %w", b.entry.ID, err)
			}
		}
	}

	doc := &index{Format: indexFormat, Version: indexVersion, Serial: serial, Generated: o.now().UTC().Format(time.RFC3339)}
	if o.storeName != "" || o.publisher != "" || o.storeURL != "" {
		doc.Store = &storeInfo{Name: o.storeName, Publisher: o.publisher, URL: o.storeURL}
	}
	for _, b := range addons {
		doc.Addons = append(doc.Addons, b.entry)
	}
	if doc.Addons == nil {
		doc.Addons = []*addon{}
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	// The new index is written and signed next to the old one and then moved into
	// place, so a failed signing leaves the published index and its signature alone
	staged := filepath.Join(o.out, "index.json.new")
	defer os.Remove(staged)
	defer os.Remove(staged + ".sig")
	if err := os.WriteFile(staged, raw, 0o644); err != nil {
		return err
	}
	fingerprint := ""
	if !o.unsigned {
		if fingerprint, err = sign(o, staged); err != nil {
			return err
		}
		if got, err := os.ReadFile(staged); err != nil || !bytes.Equal(got, raw) {
			return errors.New("the signer changed the index; nothing was published")
		}
	}
	page, err := renderCatalogue(doc, o, fingerprint)
	if err != nil {
		return err
	}
	if o.unsigned {
		os.Remove(indexPath + ".sig") //a signature of the previous index would not match
	} else if err := os.Rename(staged+".sig", indexPath+".sig"); err != nil {
		return err
	}
	if err := os.Rename(staged, indexPath); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.out, "index.html"), page, 0o644); err != nil {
		return err
	}
	if o.pubPath != "" && !o.unsigned {
		pub, err := os.ReadFile(o.pubPath)
		if err != nil {
			return err
		}
		if bytes.Contains(pub, []byte("PRIVATE")) {
			return errors.New("-pub names a private key; it was not published")
		}
		if err := os.WriteFile(filepath.Join(o.out, "index.pub"), pub, 0o644); err != nil {
			return err
		}
	}
	state := "signed"
	if o.unsigned {
		state = "NOT signed"
	}
	fmt.Fprintf(o.stdout, "wrote %s: %d add-ons, serial %d, %s\n", indexPath, len(doc.Addons), serial, state)
	if fingerprint != "" {
		fmt.Fprintf(o.stdout, "public key fingerprint: %s\n", fingerprint)
	}
	return nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("-base-url %q is not a web address", raw)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}

// address is where a published file is found: relative to index.json, or below -base-url
func address(base *url.URL, rel string) string {
	if base == nil {
		return (&url.URL{Path: rel}).String()
	}
	return base.ResolveReference(&url.URL{Path: rel}).String()
}

func previousSerial(indexPath string) int64 {
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		return 0
	}
	var old struct {
		Serial int64 `json:"serial"`
	}
	if json.Unmarshal(raw, &old) != nil {
		return 0
	}
	return old.Serial
}

/* Reading and verifying the add-ons */

func loadAddons(o options, base *url.URL) ([]*built, error) {
	entries, err := os.ReadDir(o.in)
	if err != nil {
		return nil, err
	}
	var out []*built
	seen := map[string]string{}
	var problems []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(o.in, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "addon.json")); err != nil {
			continue //not an add-on folder
		}
		b, err := loadAddon(o, base, dir)
		if err != nil {
			problems = append(problems, e.Name()+": "+err.Error())
			continue
		}
		if other, dup := seen[b.entry.ID]; dup {
			problems = append(problems, e.Name()+": the id "+b.entry.ID+" is also used by "+other)
			continue
		}
		seen[b.entry.ID] = e.Name()
		out = append(out, b)
	}
	if len(problems) > 0 {
		// Nothing is published while one add-on is wrong: a store never goes out half-checked
		return nil, errors.New("not published:\n  " + strings.Join(problems, "\n  "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].entry.ID < out[j].entry.ID })
	return out, nil
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})([-+][0-9A-Za-z.+-]+)?$`)
var platformPattern = regexp.MustCompile(`^[a-z0-9]{1,20}_[a-z0-9]{1,20}$`)
var artifactNamePattern = regexp.MustCompile(`_([a-z0-9]+)_([a-z0-9]+?)(\.exe)?$`)

var knownOS = map[string]bool{"linux": true, "windows": true, "darwin": true, "freebsd": true, "openbsd": true, "netbsd": true}

func loadAddon(o options, base *url.URL, dir string) (*built, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "addon.json"))
	if err != nil {
		return nil, err
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() //a misspelled field would silently be missing from the store
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("addon.json: %w", err)
	}
	if m.Licence == "" {
		m.Licence = m.License
	}
	m.ID, m.Name, m.Publisher, m.Version = strings.TrimSpace(m.ID), strings.TrimSpace(m.Name), strings.TrimSpace(m.Publisher), strings.TrimSpace(m.Version)
	switch {
	case !idPattern.MatchString(m.ID) || strings.Contains(m.ID, ".."):
		return nil, errors.New("\"id\" is missing or has characters other than letters, digits, dot, dash and underscore")
	case m.Name == "" || len(m.Name) > 100:
		return nil, errors.New("\"name\" is missing or longer than 100 characters")
	case m.Publisher == "" || len(m.Publisher) > 100:
		return nil, errors.New("\"publisher\" is missing or longer than 100 characters")
	case !versionPattern.MatchString(m.Version):
		return nil, errors.New("\"version\" must be major.minor.patch")
	case m.MinHostVersion != "" && !versionPattern.MatchString(m.MinHostVersion):
		return nil, errors.New("\"min_host_version\" must be major.minor.patch")
	case m.APIVersion < 0:
		return nil, errors.New("\"api_version\" is negative")
	case strings.TrimSpace(m.Licence) == "":
		return nil, errors.New("\"licence\" is missing: say under which licence the add-on is published (an SPDX identifier such as AGPL-3.0-only)")
	case len(m.Description) > 4000:
		return nil, errors.New("\"description\" is longer than 4000 characters")
	}
	switch m.Type {
	case "":
		m.Type = "utility"
	case "router", "utility":
	default:
		return nil, errors.New("\"type\" must be router or utility")
	}
	if m.Homepage != "" {
		if u, err := url.Parse(m.Homepage); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("\"homepage\" is not a web address")
		}
	}
	for _, p := range m.Permissions {
		if strings.TrimSpace(p.Method) == "" || !strings.HasPrefix(p.Endpoint, "/") {
			return nil, errors.New("a permission needs a method and an endpoint that starts with /")
		}
	}

	b := &built{entry: &addon{
		ID: m.ID, Name: m.Name, Publisher: m.Publisher, Description: m.Description, Homepage: m.Homepage, Licence: strings.TrimSpace(m.Licence),
		Version: m.Version, APIVersion: m.APIVersion, MinHostVersion: m.MinHostVersion, Type: m.Type, Categories: m.Categories,
		Permissions: m.Permissions, Changelog: m.Changelog, Featured: m.Featured, Artifacts: map[string]artifact{},
	}}

	files, err := artifactFiles(dir, m)
	if err != nil {
		return nil, err
	}
	platforms := make([]string, 0, len(files))
	for p := range files {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, platform := range platforms {
		ma := files[platform]
		src, err := insideDir(dir, ma.File)
		if err != nil {
			return nil, fmt.Errorf("%s artifact: %w", platform, err)
		}
		sum, size, err := verifyArtifact(src, platform, o.skipBinaryCheck)
		if err != nil {
			return nil, fmt.Errorf("%s artifact %s: %w", platform, ma.File, err)
		}
		if want := strings.ToLower(strings.TrimSpace(ma.SHA256)); want != "" && want != sum {
			return nil, fmt.Errorf("%s artifact %s: the manifest says sha256 %s, the file is %s", platform, ma.File, want, sum)
		}
		if o.introspect && platform == o.hostGOOS+"_"+o.hostArch {
			if err := introspectMatches(src, m.ID, m.Version); err != nil {
				return nil, fmt.Errorf("%s artifact %s: %w", platform, ma.File, err)
			}
		}
		// The version is part of the address: the file behind an address never changes
		rel := path.Join("addons", m.ID, m.Version, filepath.Base(src))
		b.files = append(b.files, publishFile{src: src, rel: rel})
		b.entry.Artifacts[platform] = artifact{URL: address(base, rel), SHA256: sum, Size: size}
	}

	if m.Icon != "" {
		src, err := pictureFile(dir, m.Icon)
		if err != nil {
			return nil, fmt.Errorf("icon: %w", err)
		}
		rel := path.Join("addons", m.ID, "icon"+strings.ToLower(filepath.Ext(src)))
		b.files = append(b.files, publishFile{src: src, rel: rel})
		b.entry.Icon = address(base, rel)
	}
	names := map[string]bool{}
	for _, shot := range m.Screenshots {
		src, err := pictureFile(dir, shot)
		if err != nil {
			return nil, fmt.Errorf("screenshot %s: %w", shot, err)
		}
		name := filepath.Base(src)
		if names[name] {
			return nil, fmt.Errorf("two screenshots are called %s", name)
		}
		names[name] = true
		rel := path.Join("addons", m.ID, "screenshots", name)
		b.files = append(b.files, publishFile{src: src, rel: rel})
		b.entry.Screenshots = append(b.entry.Screenshots, address(base, rel))
	}
	return b, nil
}

// artifactFiles returns platform -> file of an add-on: what the manifest lists,
// or every file of artifacts/ that is named *_<os>_<arch>[.exe]
func artifactFiles(dir string, m manifest) (map[string]manifestArtifact, error) {
	out := map[string]manifestArtifact{}
	if len(m.Artifacts) > 0 {
		for key, raw := range m.Artifacts {
			platform := strings.ToLower(strings.TrimSpace(key))
			if !platformPattern.MatchString(platform) {
				return nil, fmt.Errorf("artifact platform %q must be os_arch as Go names them, e.g. linux_amd64, windows_amd64, darwin_arm64", key)
			}
			var ma manifestArtifact
			if err := json.Unmarshal(raw, &ma.File); err != nil {
				if err := json.Unmarshal(raw, &ma); err != nil {
					return nil, fmt.Errorf("artifact %s must be a file path or {\"file\": ..., \"sha256\": ...}", key)
				}
			}
			if ma.File == "" {
				return nil, fmt.Errorf("artifact %s names no file", key)
			}
			out[platform] = ma
		}
		return out, nil
	}
	entries, err := os.ReadDir(filepath.Join(dir, "artifacts"))
	if err != nil {
		return nil, errors.New("no \"artifacts\" in addon.json and no artifacts folder")
	}
	for _, e := range entries {
		match := artifactNamePattern.FindStringSubmatch(strings.ToLower(e.Name()))
		if e.IsDir() || match == nil || !knownOS[match[1]] {
			continue
		}
		platform := match[1] + "_" + match[2]
		if other, dup := out[platform]; dup {
			return nil, fmt.Errorf("artifacts/%s and %s are both for %s", e.Name(), other.File, platform)
		}
		out[platform] = manifestArtifact{File: path.Join("artifacts", e.Name())}
	}
	if len(out) == 0 {
		return nil, errors.New("the artifacts folder holds no file named *_<os>_<arch> (for example myaddon_linux_amd64, myaddon_windows_amd64.exe)")
	}
	return out, nil
}

// insideDir resolves a path of a manifest and refuses one that leaves the add-on folder
func insideDir(dir string, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", fmt.Errorf("%q must be a path inside the add-on folder", rel)
	}
	target := filepath.Join(dir, filepath.FromSlash(rel))
	back, err := filepath.Rel(dir, target)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q leaves the add-on folder", rel)
	}
	return target, nil
}

func pictureFile(dir string, rel string) (string, error) {
	src, err := insideDir(dir, rel)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(filepath.Ext(src)) {
	case ".png", ".jpg", ".jpeg", ".webp", ".gif":
	default:
		return "", errors.New("pictures must be png, jpg, webp or gif") //no svg: it can carry script
	}
	st, err := os.Stat(src)
	if err != nil || !st.Mode().IsRegular() {
		return "", errors.New("file not found")
	}
	if st.Size() == 0 || st.Size() > maxPicture {
		return "", fmt.Errorf("must be between 1 byte and %d MB", maxPicture>>20)
	}
	return src, nil
}

// verifyArtifact checks one program file and returns its checksum and size
func verifyArtifact(src string, platform string, skipBinaryCheck bool) (string, int64, error) {
	st, err := os.Lstat(src)
	if err != nil {
		return "", 0, errors.New("file not found")
	}
	if !st.Mode().IsRegular() {
		return "", 0, errors.New("not a regular file (a link or a folder is not published)")
	}
	if st.Size() == 0 || st.Size() > maxArtifact {
		return "", 0, errors.New("empty, or larger than 1 GB")
	}
	goos, goarch, _ := strings.Cut(platform, "_")
	isExe := strings.HasSuffix(strings.ToLower(src), ".exe")
	if goos == "windows" && !isExe {
		return "", 0, errors.New("a Windows program file must end in .exe")
	}
	if goos != "windows" && isExe {
		return "", 0, errors.New("only a Windows program file ends in .exe")
	}
	f, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	if !skipBinaryCheck {
		if err := checkExecutable(head[:n], goos, goarch); err != nil {
			return "", 0, err
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

var elfMachine = map[string]uint16{"386": 3, "amd64": 62, "arm": 40, "arm64": 183, "riscv64": 243, "ppc64": 21, "ppc64le": 21, "s390x": 22, "loong64": 258, "mips": 8, "mipsle": 8, "mips64": 8, "mips64le": 8}
var peMachine = map[string]uint16{"386": 0x14c, "amd64": 0x8664, "arm": 0x1c4, "arm64": 0xaa64}
var machoCPU = map[string]uint32{"amd64": 0x01000007, "arm64": 0x0100000c}

// checkExecutable says whether head starts a program file for goos/goarch: an
// ELF file for Linux and the BSDs, a PE file for Windows, a Mach-O file for
// macOS, with the CPU type of the architecture. It catches the file that was
// put under the wrong platform; it does not run anything.
func checkExecutable(head []byte, goos, goarch string) error {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		if len(head) < 20 || !bytes.HasPrefix(head, []byte("\x7fELF")) {
			return errors.New("not an ELF program file, which " + goos + " needs")
		}
		var order binary.ByteOrder = binary.LittleEndian
		if head[5] == 2 {
			order = binary.BigEndian
		}
		if want, known := elfMachine[goarch]; known && order.Uint16(head[18:20]) != want {
			return fmt.Errorf("an ELF file for another CPU than %s (machine %d)", goarch, order.Uint16(head[18:20]))
		}
	case "windows":
		if len(head) < 0x40 || head[0] != 'M' || head[1] != 'Z' {
			return errors.New("not a Windows program file (PE)")
		}
		at := int(binary.LittleEndian.Uint32(head[0x3c:0x40]))
		if at < 0 || at+6 > len(head) || !bytes.Equal(head[at:at+4], []byte("PE\x00\x00")) {
			return errors.New("not a Windows program file (PE)")
		}
		if want, known := peMachine[goarch]; known && binary.LittleEndian.Uint16(head[at+4:at+6]) != want {
			return fmt.Errorf("a Windows program file for another CPU than %s", goarch)
		}
	case "darwin":
		if len(head) < 8 {
			return errors.New("not a macOS program file (Mach-O)")
		}
		switch binary.LittleEndian.Uint32(head[0:4]) {
		case 0xfeedfacf: //64 bit
			if want, known := machoCPU[goarch]; known && binary.LittleEndian.Uint32(head[4:8]) != want {
				return fmt.Errorf("a macOS program file for another CPU than %s", goarch)
			}
		case 0xbebafeca, 0xbfbafeca: //universal: holds several CPUs
		default:
			return errors.New("not a 64 bit macOS program file (Mach-O)")
		}
	}
	return nil
}

// introspectMatches runs a program file with -introspect, as Dunree does before
// it installs it, and compares what it says with the manifest
func introspectMatches(src string, id string, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, src, "-introspect").Output()
	if err != nil {
		return fmt.Errorf("-introspect failed: %w", err)
	}
	var spec struct {
		ID    string `json:"id"`
		Major int    `json:"version_major"`
		Minor int    `json:"version_minor"`
		Patch int    `json:"version_patch"`
	}
	if err := json.Unmarshal(out, &spec); err != nil {
		return errors.New("-introspect did not print a manifest")
	}
	if spec.ID != id {
		return fmt.Errorf("the program says its id is %q, addon.json says %q", spec.ID, id)
	}
	got := strconv.Itoa(spec.Major) + "." + strconv.Itoa(spec.Minor) + "." + strconv.Itoa(spec.Patch)
	want := version
	if cut := strings.IndexAny(want, "-+"); cut >= 0 {
		want = want[:cut]
	}
	if got != want {
		return fmt.Errorf("the program says its version is %s, addon.json says %s", got, version)
	}
	return nil
}

// publish copies a file into the output folder. A file that is already there
// must be the same: what an address serves never changes (publish a new version
// instead), because installed copies and older indexes pin its checksum.
func publish(src string, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		same, cmpErr := sameContent(src, dst)
		if cmpErr != nil {
			return cmpErr
		}
		if same {
			return nil
		}
		if isVersionedPath(dst) { //a picture may be replaced, a program file may not
			return fmt.Errorf("%s was already published with other content. A published version is never replaced: raise \"version\"", filepath.Base(dst))
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// isVersionedPath: OUT/addons/<id>/<version>/<file> is a program file; icon and screenshots are not
func isVersionedPath(dst string) bool {
	parent := filepath.Base(filepath.Dir(dst))
	return versionPattern.MatchString(parent)
}

func sameContent(a, b string) (bool, error) {
	sa, _, err := sumFile(a)
	if err != nil {
		return false, err
	}
	sb, _, err := sumFile(b)
	if err != nil {
		return false, err
	}
	return sa == sb, nil
}

func sumFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

/* Signing: done by tools/plugin-index/sign_plugin_index.go -sign-raw */

var fingerprintLine = regexp.MustCompile(`public key fingerprint: ([0-9a-f]{16})`)

func signerCommand(o options) ([]string, error) {
	if o.signer != "" {
		return []string{o.signer}, nil
	}
	src := o.signerSrc
	if src == "" {
		for _, candidate := range []string{filepath.Join("tools", "plugin-index", "sign_plugin_index.go"), filepath.Join("..", "plugin-index", "sign_plugin_index.go")} {
			if _, err := os.Stat(candidate); err == nil {
				src = candidate
				break
			}
		}
	}
	if src == "" {
		return nil, errors.New("tools/plugin-index/sign_plugin_index.go was not found from here: run from the repository root, or pass -signer-src or -signer")
	}
	return []string{"go", "run", src}, nil
}

// sign has the staged index signed and returns the fingerprint of the key
func sign(o options, indexPath string) (string, error) {
	argv, err := signerCommand(o)
	if err != nil {
		return "", err
	}
	argv = append(argv, "-sign-raw", "-index", indexPath)
	if o.keyPath != "" {
		argv = append(argv, "-key", o.keyPath)
	}
	if o.pubPath != "" {
		argv = append(argv, "-pub", o.pubPath)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("signing failed, nothing was published: %s", strings.TrimSpace(string(out)))
	}
	if st, err := os.Stat(indexPath + ".sig"); err != nil || st.Size() != 64 {
		return "", errors.New("the signer wrote no signature of 64 bytes; nothing was published")
	}
	if m := fingerprintLine.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	return "", nil
}

/* The catalogue */

type cataloguePage struct {
	Store       storeInfo
	Serial      int64
	Generated   string
	Signed      bool
	Fingerprint string
	HasPub      bool
	IndexURL    string
	Addons      []catalogueAddon
}

type catalogueAddon struct {
	*addon
	Platforms []cataloguePlatform
	Search    string
}

type cataloguePlatform struct {
	Key, Label, URL, SHA256, Size string
}

func platformLabel(key string) string {
	goos, goarch, _ := strings.Cut(key, "_")
	osName := map[string]string{"linux": "Linux", "windows": "Windows", "darwin": "macOS", "freebsd": "FreeBSD", "openbsd": "OpenBSD", "netbsd": "NetBSD"}[goos]
	if osName == "" {
		osName = goos
	}
	arch := map[string]string{"amd64": "x86 64-bit", "386": "x86 32-bit", "arm64": "ARM 64-bit", "arm": "ARM 32-bit", "riscv64": "RISC-V 64-bit"}[goarch]
	if arch == "" {
		arch = goarch
	}
	return osName + " " + arch
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64) + " kB"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

func renderCatalogue(doc *index, o options, fingerprint string) ([]byte, error) {
	page := cataloguePage{Serial: doc.Serial, Generated: doc.Generated, Signed: !o.unsigned, Fingerprint: fingerprint, HasPub: o.pubPath != "" && !o.unsigned, IndexURL: "index.json"}
	if doc.Store != nil {
		page.Store = *doc.Store
	}
	if page.Store.Name == "" {
		page.Store.Name = "Add-on store"
	}
	if base, _ := parseBaseURL(o.baseURL); base != nil {
		page.IndexURL = address(base, "index.json")
	}
	for _, a := range doc.Addons {
		ca := catalogueAddon{addon: a, Search: strings.ToLower(a.Name + " " + a.Publisher + " " + a.Description + " " + a.ID + " " + strings.Join(a.Categories, " "))}
		keys := make([]string, 0, len(a.Artifacts))
		for k := range a.Artifacts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			art := a.Artifacts[k]
			ca.Platforms = append(ca.Platforms, cataloguePlatform{Key: k, Label: platformLabel(k), URL: art.URL, SHA256: art.SHA256, Size: humanSize(art.Size)})
		}
		page.Addons = append(page.Addons, ca)
	}
	var buf bytes.Buffer
	if err := catalogueTemplate.Execute(&buf, page); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// safeLink keeps only web and relative addresses out of manifests in href/src
func safeLink(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "#"
	}
	if u.Scheme == "" || u.Scheme == "https" || u.Scheme == "http" {
		return raw
	}
	return "#"
}

// The page is self-contained: one file, no script, style or font from another host
var catalogueTemplate = template.Must(template.New("catalogue").Funcs(template.FuncMap{"link": safeLink}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Store.Name}}</title>
<style>
:root { --bg: #f6f7f9; --surface: #fff; --text: #1b1f24; --muted: #5b6470; --border: #d9dde3; --accent: #1a56c4; --accent-soft: #e8effb; --ok: #1a7f37; --warn: #9a6700; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f1216; --surface: #171b21; --text: #e6e9ee; --muted: #9aa4b2; --border: #2a313b; --accent: #6d9bff; --accent-soft: #1b2740; --ok: #4ac26b; --warn: #d4a72c; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); }
main { max-width: 68rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
.sub { margin: 0 0 1rem; color: var(--muted); }
.how { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; margin: 0 0 1.25rem; }
.how h2 { margin: 0 0 .5rem; font-size: 1rem; }
.how ol { margin: 0; padding-left: 1.25rem; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85em; overflow-wrap: anywhere; }
.badge { display: inline-block; padding: 0 .5rem; border: 1px solid var(--border); border-radius: 999px; font-size: .8rem; color: var(--muted); }
.badge.ok { color: var(--ok); border-color: var(--ok); }
.badge.warn { color: var(--warn); border-color: var(--warn); }
#q { width: 100%; max-width: 26rem; padding: .55rem .75rem; margin: 0 0 1rem; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font: inherit; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr)); gap: 1rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; min-width: 0; }
.head { display: flex; gap: .75rem; align-items: center; margin: 0 0 .5rem; }
.head img, .head .noicon { flex: 0 0 auto; width: 44px; height: 44px; border-radius: 8px; border: 1px solid var(--border); object-fit: contain; background: var(--accent-soft); }
.card h3 { margin: 0; font-size: 1.1rem; overflow-wrap: anywhere; }
.by { color: var(--muted); font-size: .9rem; }
.desc { margin: .5rem 0; }
.tags { display: flex; flex-wrap: wrap; gap: .35rem; margin: .5rem 0; }
details { margin: .5rem 0 0; border-top: 1px solid var(--border); padding-top: .5rem; }
summary { cursor: pointer; color: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
td, th { text-align: left; vertical-align: top; padding: .25rem .5rem .25rem 0; }
.shots { display: flex; gap: .5rem; overflow-x: auto; margin: .5rem 0 0; }
.shots img { height: 120px; border: 1px solid var(--border); border-radius: 6px; }
.empty { color: var(--muted); padding: 2rem 0; }
footer { margin-top: 2rem; color: var(--muted); font-size: .85rem; }
</style>
</head>
<body>
<main>
<h1>{{.Store.Name}}</h1>
<p class="sub">{{if .Store.Publisher}}Published by {{.Store.Publisher}}. {{end}}Add-ons for Dunree, the reverse proxy and web gateway.
{{if .Signed}}<span class="badge ok">Signed index</span>{{else}}<span class="badge warn">Index not signed</span>{{end}}</p>

<section class="how">
<h2>Use this store in Dunree</h2>
<ol>
<li>Open <b>System &gt; Add-ons &gt; Sources</b> and choose <b>Custom index URL</b>.</li>
<li>Enter the address of the index: <code>{{.IndexURL}}</code>{{if eq .IndexURL "index.json"}} (next to this page){{end}}.</li>
{{if .Signed}}<li>Give Dunree the public key of this store under <b>Plugin Manager &gt; Plugin safety settings</b>{{if .HasPub}}: <a href="index.pub">index.pub</a>{{end}}{{if .Fingerprint}} (fingerprint <code>{{.Fingerprint}}</code>){{end}}. With signature checking set to <b>enforce</b>, only add-ons of a correctly signed index are installed.</li>{{end}}
</ol>
</section>

<input id="q" type="search" placeholder="Search add-ons" aria-label="Search add-ons" autocomplete="off">
<div class="grid" id="grid">
{{range .Addons}}
{{$name := .Name}}<article class="card" data-search="{{.Search}}">
  <div class="head">
    {{if .Icon}}<img src="{{link .Icon}}" alt="" loading="lazy">{{else}}<span class="noicon" aria-hidden="true"></span>{{end}}
    <div>
      <h3>{{.Name}}</h3>
      <span class="by">{{.Publisher}} · v{{.Version}}</span>
    </div>
  </div>
  {{if .Description}}<p class="desc">{{.Description}}</p>{{end}}
  <div class="tags">
    {{range .Categories}}<span class="badge">{{.}}</span>{{end}}
    {{if .Licence}}<span class="badge">{{.Licence}}</span>{{end}}
    {{if .MinHostVersion}}<span class="badge">Dunree {{.MinHostVersion}} or newer</span>{{end}}
  </div>
  <details>
    <summary>Downloads and details</summary>
    <table>
      <tr><th>ID</th><td class="mono">{{.ID}}</td></tr>
      {{if .Homepage}}<tr><th>Website</th><td><a href="{{link .Homepage}}" rel="noopener noreferrer">{{.Homepage}}</a></td></tr>{{end}}
      <tr><th>Kind</th><td>{{if eq .Type "router"}}Router: can handle requests of the sites it is assigned to{{else}}Utility: adds a tool, does not touch traffic{{end}}</td></tr>
      <tr><th>Plugin contract</th><td>{{.APIVersion}}</td></tr>
      {{range .Platforms}}<tr><th>{{.Label}}</th><td><a href="{{link .URL}}">{{.Key}}</a> ({{.Size}})<br><span class="mono">sha256 {{.SHA256}}</span></td></tr>{{end}}
      {{if .Permissions}}<tr><th>Dunree API it asks for</th><td>{{range .Permissions}}<div><b>{{.Method}}</b> <span class="mono">{{.Endpoint}}</span>{{if .Reason}} - {{.Reason}}{{end}}</div>{{end}}</td></tr>{{end}}
      {{if .Changelog}}<tr><th>Changes</th><td>{{range .Changelog}}<div><b>{{.Version}}</b>{{if .Date}} ({{.Date}}){{end}}{{if .Notes}}: {{.Notes}}{{end}}</div>{{end}}</td></tr>{{end}}
    </table>
    {{if .Screenshots}}<div class="shots">{{range .Screenshots}}<img src="{{link .}}" alt="Screenshot of {{$name}}" loading="lazy">{{end}}</div>{{end}}
  </details>
</article>
{{else}}
<p class="empty">This store has no add-ons yet.</p>
{{end}}
</div>
<p class="empty" id="none" hidden>No add-on matches.</p>
<footer>Index serial {{.Serial}}, generated {{.Generated}}. An add-on is a program that runs on the server of the proxy: install only what you trust.</footer>
</main>
<script>
(function () {
  var q = document.getElementById("q"), cards = document.querySelectorAll("#grid .card"), none = document.getElementById("none");
  q.addEventListener("input", function () {
    var word = q.value.toLowerCase().trim(), shown = 0;
    cards.forEach(function (c) { var hit = word === "" || c.dataset.search.indexOf(word) !== -1; c.hidden = !hit; if (hit) { shown++; } });
    none.hidden = shown !== 0 || cards.length === 0;
  });
})();
</script>
</body>
</html>
`))
