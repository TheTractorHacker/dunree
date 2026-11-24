package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/foleyit/dunree/mod/plugins/addonindex"
	"github.com/foleyit/dunree/mod/plugins/dunree_plugin"
)

/*
	Dunree add-on index, format version 1 (docs/plugins/addon-store.md)

	The third index format the store reads, next to the list of the Zoraxy plugin // legacy-compat
	store and the signed plugin index (store_verify.go). It is a signed index too:
	the same detached ed25519 signature at "<index>.sig", the same plugin index
	key, the same serial number against replay, the same modes off / warn /
	enforce. What it adds is what a store page needs (publisher, licence,
	categories, changelog, screenshots, the minimum host version) and artifacts
	that may be named relative to the index, so one folder can be served from any
	web server or read from a local folder.

	Every entry becomes a DownloadablePlugin, so install, update, health check and
	rollback (store_safe.go) are the ones every other index uses.
*/

// What SourceStatus.Schema says an index is
const (
	SchemaAddonV1     = addonindex.Format + "/1"
	SchemaSignedIndex = signedIndexFormat + "/1"
	SchemaList        = "list"
)

// AddonMeta is what an add-on index says about an add-on beyond the manifest fields
type AddonMeta struct {
	Publisher      string                      `json:"publisher"`
	Licence        string                      `json:"licence"`
	Homepage       string                      `json:"homepage"`
	Version        string                      `json:"version"`
	APIVersion     int                         `json:"apiVersion"`
	MinHostVersion string                      `json:"minHostVersion"`
	Categories     []string                    `json:"categories"`
	Changelog      []addonindex.ChangelogEntry `json:"changelog"`
	Screenshots    []string                    `json:"screenshots"`
	Featured       bool                        `json:"featured"`
	Platforms      []string                    `json:"platforms"`
	// Why this host cannot run the add-on ("" = it can, as far as the index says).
	// An install of an incompatible add-on is refused in every verification mode.
	Incompatible string `json:"incompatible"`
	// Something to know that does not stop an install
	Note string `json:"note"`
}

// hostVersion is the version of this Dunree as plugins are told it
func (m *Manager) hostVersion() string {
	if m.Options == nil || m.Options.SystemConst == nil {
		return ""
	}
	return m.Options.SystemConst.DunreeVersion
}

// readAddonIndex turns an add-on index into store entries. raw is the exact
// content that was fetched: the signature is over those bytes.
func (m *Manager) readAddonIndex(indexURL string, raw []byte, st SourceStatus) ([]*DownloadablePlugin, SourceStatus, error) {
	idx, skipped, err := addonindex.Parse(raw)
	if err != nil {
		return nil, st, fmt.Errorf("%s: %w", indexURL, err)
	}
	base, err := url.Parse(indexURL)
	if err != nil {
		return nil, st, fmt.Errorf("invalid index address: %s", indexURL)
	}
	st.Format = "signed"
	st.Schema = SchemaAddonV1
	st.Serial = idx.Serial
	keyFP := ""
	if m.Settings().VerifyMode == VerifyOff {
		st.Signature = SigUnchecked
	} else {
		st.Signature, st.Note, keyFP = m.checkIndexSignature(indexURL, raw, idx.Serial)
	}

	list := make([]*DownloadablePlugin, 0, len(idx.Addons))
	for _, a := range idx.Addons {
		p, reason := m.addonEntry(base, a)
		if p == nil {
			skipped = append(skipped, addonindex.Skipped{ID: a.ID, Reason: reason})
			continue
		}
		p.Signature = st.Signature
		p.IndexSerial = idx.Serial
		p.verifiedKey = keyFP
		list = append(list, p)
	}
	st.Plugins = len(list)
	if len(skipped) > 0 {
		first := skipped[0]
		note := strconv.Itoa(len(skipped)) + " entries of this index were left out, the first one (" + clipText(first.ID, 80) + "): " + first.Reason + "."
		if m.Options != nil && m.Options.Logger != nil {
			m.Log("add-on index "+indexURL+": "+note, nil)
		}
		st.Note = strings.TrimSpace(st.Note + " " + note)
	}
	return list, st, nil
}

// addonEntry converts one add-on. It returns nil and the reason when nothing of
// the entry can be used.
func (m *Manager) addonEntry(base *url.URL, a *addonindex.Addon) (*DownloadablePlugin, string) {
	ver, _ := addonindex.ParseVersion(a.Version)
	spec := dunree_plugin.IntroSpect{
		ID:           a.ID,
		Name:         a.Name,
		Author:       a.Publisher,
		Description:  a.Description,
		URL:          a.Homepage,
		Type:         dunree_plugin.PluginType_Utilities,
		VersionMajor: ver[0],
		VersionMinor: ver[1],
		VersionPatch: ver[2],
		APIVersion:   a.APIVersion,
	}
	if a.Type == addonindex.TypeRouter {
		spec.Type = dunree_plugin.PluginType_Router
	}
	for _, perm := range a.Permissions {
		spec.PermittedAPIEndpoints = append(spec.PermittedAPIEndpoints, dunree_plugin.PermittedAPIEndpoint{Method: perm.Method, Endpoint: perm.Endpoint, Reason: perm.Reason})
	}
	p := &DownloadablePlugin{
		IconPath:         defaultStoreIcon,
		PluginIntroSpect: spec,
		DownloadURLs:     map[string]string{},
		Downloads:        map[string]PinnedDownload{},
	}
	refused := ""
	for platform, art := range a.Artifacts {
		target, err := resolveStoreRef(base, art.URL, true)
		if err != nil {
			refused = "the " + platform + " artifact: " + err.Error()
			continue
		}
		p.Downloads[platform] = PinnedDownload{URL: target, SHA256: art.SHA256, Size: art.Size}
		p.DownloadURLs[platform] = target
	}
	if len(p.Downloads) == 0 {
		return nil, refused
	}
	meta := &AddonMeta{
		Publisher:      a.Publisher,
		Licence:        a.Licence,
		Homepage:       a.Homepage,
		Version:        a.Version,
		APIVersion:     a.APIVersion,
		MinHostVersion: a.MinHostVersion,
		Categories:     a.Categories,
		Changelog:      a.Changelog,
		Featured:       a.Featured,
		Screenshots:    []string{},
	}
	for platform := range p.Downloads {
		meta.Platforms = append(meta.Platforms, platform)
	}
	sort.Strings(meta.Platforms)
	// Pictures are loaded by the browser of the administrator: web addresses only
	if icon, err := resolveStoreRef(base, a.Icon, false); err == nil && isWebURL(icon) {
		p.IconPath = icon
	}
	for _, shot := range a.Screenshots {
		if target, err := resolveStoreRef(base, shot, false); err == nil && isWebURL(target) {
			meta.Screenshots = append(meta.Screenshots, target)
		}
	}
	if ok, err := addonindex.HostSatisfies(a.MinHostVersion, m.hostVersion()); err != nil {
		if errors.Is(err, addonindex.ErrHostVersionUnknown) {
			meta.Note = "This add-on asks for Dunree " + a.MinHostVersion + " or newer. The version of this Dunree could not be read, so that was not compared."
		}
	} else if !ok {
		meta.Incompatible = "This add-on needs Dunree " + a.MinHostVersion + " or newer, this is Dunree " + clipText(m.hostVersion(), 40) + "."
	}
	if meta.Incompatible == "" {
		if _, _, here := addonindex.SelectArtifact(a.Artifacts, runtime.GOOS, runtime.GOARCH); !here {
			meta.Note = "This add-on has no build for this server (" + platformKey() + ")."
		} else if a.APIVersion > ContractVersionMax && meta.Note == "" {
			meta.Note = "This add-on was built for plugin contract " + strconv.Itoa(a.APIVersion) + ", this Dunree knows " + contractRangeText() + ". The plugin safety settings decide whether it is loaded."
		}
	}
	p.Addon = meta
	return p, ""
}

func isWebURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// resolveStoreRef resolves what an add-on index names (an artifact, an icon)
// against the address of the index. An index on the web may only name web
// addresses: it must never make Dunree read a file of this server. An index in
// a local folder may name files inside that folder, or web addresses.
func resolveStoreRef(base *url.URL, ref string, required bool) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		if required {
			return "", errors.New("no address")
		}
		return "", errors.New("empty")
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", errors.New("its address cannot be read")
	}
	target := base.ResolveReference(u)
	switch target.Scheme {
	case "https", "http":
		if target.Host == "" {
			return "", errors.New("its address has no host")
		}
		return target.String(), nil
	case "file":
		if base.Scheme != "file" {
			return "", errors.New("an index on the web may not point at a file of this server")
		}
		dir, okDir := pathFromFileURL(base.String())
		file, okFile := pathFromFileURL(target.String())
		if !okDir || !okFile || !pathWithin(filepath.Dir(dir), file) {
			return "", errors.New("it is outside the folder of its index")
		}
		return target.String(), nil
	}
	return "", errors.New("its address is neither a web address nor a file of the index folder")
}

/* Indexes and artifacts in a local folder */

// fileURLFromPath is the address a local file has as a store source
func fileURLFromPath(abs string) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p //C:/store -> /C:/store
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// pathFromFileURL is the reverse of fileURLFromPath. Only local files: a file
// address with a host (a network share written as a URL) is refused.
func pathFromFileURL(raw string) (string, bool) {
	return pathFromFileURLOn(raw, runtime.GOOS)
}

func pathFromFileURLOn(raw string, goos string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") || u.Path == "" {
		return "", false
	}
	p := u.Path
	if goos == "windows" {
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:] // /C:/store -> C:/store
		}
		return strings.ReplaceAll(p, "/", `\`), true
	}
	return p, true
}

// pathWithin says whether target is dir or a file below it
func pathWithin(dir string, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(target))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isLocalSource says whether a store source is a local folder
func isLocalSource(sourceURL string) bool {
	return strings.HasPrefix(sourceURL, "file:")
}

// readLocalStoreFile reads an index or a signature from a local folder
func readLocalStoreFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("file not found")
		}
		return nil, errors.New("the file cannot be read")
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, errors.New("the file cannot be read")
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return content, nil
}

// localArtifactRefused says why the artifact address of a store entry may not be
// read, "" when it may: a file of this server only when the entry came from a
// local source and the file is inside the folder of THAT source. An index of the
// web (any format, the list format carries addresses as they are) never makes
// Dunree read a file of this server, not even one inside another local source.
func localArtifactRefused(source string, artifactURL string) string {
	if !isLocalSource(artifactURL) {
		return ""
	}
	const refused = "this file is not inside the folder of a configured local add-on store the entry came from: an index may only name files of its own folder"
	if !isLocalSource(source) {
		return refused
	}
	indexPath, okIndex := pathFromFileURL(source)
	file, okFile := pathFromFileURL(artifactURL)
	if !okIndex || !okFile || !pathWithin(filepath.Dir(indexPath), file) {
		return refused
	}
	return ""
}

// localArtifactAllowed says whether a file may be installed from: only files
// inside the folder of a local source that is configured. This is checked where
// the file is read, whatever index named it.
func (m *Manager) localArtifactAllowed(path string) bool {
	if m.Options == nil || !m.hasDB() {
		return false
	}
	for _, source := range m.GetAllStoreURLs() {
		if !isLocalSource(source) {
			continue
		}
		if indexPath, ok := pathFromFileURL(source); ok && pathWithin(filepath.Dir(indexPath), path) {
			return true
		}
	}
	return false
}

// copyLocalArtifact is downloadTo for an artifact of a local folder: the same
// size cap, the same checksum, nothing left at destPath on error.
func (m *Manager) copyLocalArtifact(fileURL string, destPath string, limit int64) (sum string, size int64, err error) {
	path, ok := pathFromFileURL(fileURL)
	// The checked path is the one that is opened: pathWithin compares cleaned
	// paths, and the OS resolves "dir/link/../x" through the link, not lexically
	path = filepath.Clean(path)
	if !ok || !m.localArtifactAllowed(path) {
		return "", 0, errors.New("this file is not inside the folder of a configured local add-on store")
	}
	in, err := os.Open(path)
	if err != nil {
		return "", 0, errors.New("the file of the local add-on store cannot be read")
	}
	defer in.Close()
	if st, statErr := in.Stat(); statErr != nil || !st.Mode().IsRegular() {
		return "", 0, errors.New("the file of the local add-on store is not a regular file")
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		out.Close()
		if err != nil {
			os.Remove(destPath)
		}
	}()
	h := sha256.New()
	size, err = io.Copy(io.MultiWriter(out, h), io.LimitReader(in, limit+1))
	if err != nil {
		return "", 0, err
	}
	if size > limit {
		err = fmt.Errorf("the file is larger than the limit of %d bytes", limit)
		return "", 0, err
	}
	if err = out.Sync(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// addonBlockedReason says why an add-on of an add-on index is not installed on
// this host, in every verification mode. Empty: nothing of the index speaks against it.
func addonBlockedReason(p *DownloadablePlugin) string {
	if p == nil || p.Addon == nil {
		return ""
	}
	return p.Addon.Incompatible
}
