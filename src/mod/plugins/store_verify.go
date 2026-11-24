package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/foleyit/dunree/mod/offline"
	"github.com/foleyit/dunree/mod/plugins/addonindex"
	"github.com/foleyit/dunree/mod/plugins/dunree_plugin"
)

/*
	Signed plugin index (phase 2 of docs/plugins/reliability-plan.md, item 2.4)

	A plugin store index is one of two things:

	- the Dunree add-on index (store_addon.go, docs/plugins/addon-store.md): a signed
	  index with the store metadata of every add-on. It is checked exactly like the
	  signed format below;
	- the upstream format: a JSON list of plugins with download URLs. It carries no
	  checksum and no signature and is shown as "unsigned";
	- the signed format of this fork: a JSON object {"format":"zoraxy-plugin-index",
	  "serial":N,"plugins":[...]} in which every download has a URL, a SHA-256 and a
	  size, with a detached signature next to it at "<index URL>.sig": the raw 64
	  bytes of an ed25519 signature over the exact bytes of the index, the format of
	  tools/sign_release.go. The serial number only ever goes up, so an older signed
	  index cannot be served again later (replay).

	The index is signed with a plugin key of its own, never with the release key.
	Dunree only holds the public half, which the administrator configures (plugin
	safety settings or the start flag -plugin_index_pubkey). tools/plugin-index
	creates a key pair and signs an index.

	Verification mode (plugin safety settings):
	  off      nothing is fetched or compared
	  warn     default. Every problem is logged and shown, nothing is refused
	  enforce  only plugins of a validly signed index, with a download that matches
	           the checksum and size of the index, are installed or updated

	Updates of a plugin come only from the index it was installed from (F15).
*/

// Verification modes
const (
	VerifyOff     = "off"
	VerifyWarn    = "warn"
	VerifyEnforce = "enforce"
)

// Signature states of an index, and of the plugins listed in it
const (
	SigSigned    = "signed"        //signed format, valid signature of the configured key, not older than the last one seen
	SigUnsigned  = "unsigned"      //upstream format: no checksum, no signature
	SigNoKey     = "no_key"        //signed format, but no public key is configured
	SigMissing   = "missing"       //signed format, but the signature file could not be fetched
	SigBad       = "bad_signature" //signed format, the signature does not match
	SigReplayed  = "replayed"      //validly signed, but older than an index already seen from this URL
	SigUnchecked = "unchecked"     //verification is off
	// This address served a validly signed index before and now serves the upstream
	// list, which nothing can be checked on. Whoever controls the address (or the
	// connection to it) would switch verification off for it that way.
	SigDowngraded = "downgraded"
)

// What a download was compared with
const (
	VerifiedHashOK    = "hash_ok"       //checksum and size as the index says
	VerifiedMismatch  = "hash_mismatch" //checksum or size differ from the index (only installed in warn mode)
	VerifiedNotPinned = "not_pinned"    //the index has no checksum for this download
	VerifiedUnchecked = "unchecked"     //verification is off
)

const (
	signedIndexFormat    = "zoraxy-plugin-index"
	signedIndexVersion   = 1
	installDBTable       = "plugin_installs"
	installFolderDBTable = "plugin_install_folders" //plugin folder name -> plugin ID of its install record
	indexSeenDBKey       = "index_seen"
	defaultMaxDownloadMB = 256
	maxIndexBytes        = 8 << 20
	// What the store pages show for an index entry without an icon (as before the
	// signed index: the old list reader set it too)
	defaultStoreIcon = "/img/plugin_icon.png"
)

// PinnedDownload is one download of a signed index
type PinnedDownload struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// signedIndex is the signed index format
type signedIndex struct {
	Format    string              `json:"format"`
	Version   int                 `json:"version"`
	Serial    int64               `json:"serial"`
	Generated string              `json:"generated,omitempty"`
	Plugins   []*signedIndexEntry `json:"plugins"`
}

type signedIndexEntry struct {
	IconPath         string                    `json:"IconPath"`
	PluginIntroSpect dunree_plugin.IntroSpect  `json:"PluginIntroSpect"`
	Downloads        map[string]PinnedDownload `json:"Downloads"`
}

// SourceStatus is what the last sync found out about one index URL
type SourceStatus struct {
	Format    string `json:"format"`    //signed | legacy | "" (never fetched)
	Schema    string `json:"schema"`    //which index format it is: dunree-addon-index/1 | zoraxy-plugin-index/1 | list | "" (never fetched)
	Signature string `json:"signature"` //one of the Sig... states
	Serial    int64  `json:"serial"`    //serial of the signed index, 0 for the upstream format
	Plugins   int    `json:"plugins"`   //plugins this index offers
	Note      string `json:"note"`      //one sentence when something needs attention
	CheckedAt int64  `json:"checkedAt"` //unix time of the last sync
	Error     string `json:"error"`     //the last sync of this index failed
}

type indexSeen struct {
	Serial int64
	SHA256 string
}

// storeTunables shorten timeouts in tests. The zero value means the defaults.
type storeTunables struct {
	MaxBytes        int64         //size cap of one download, 0 = setting MaxDownloadMB
	DownloadTimeout time.Duration //whole download, default 10 min
	IndexTimeout    time.Duration //index and signature file, default 30 s
	HealthTimeout   time.Duration //time the new version gets to answer after an update, default 15 s
	HealthSettle    time.Duration //time it has to stay up after its first answer, default 2 s
	StallTimeout    time.Duration //a download that delivers no byte for this long is ended, default 60 s
}

func (c storeTunables) downloadTimeout() time.Duration {
	return durOr(c.DownloadTimeout, 10*time.Minute)
}
func (c storeTunables) indexTimeout() time.Duration  { return durOr(c.IndexTimeout, 30*time.Second) }
func (c storeTunables) healthTimeout() time.Duration { return durOr(c.HealthTimeout, 15*time.Second) }
func (c storeTunables) healthSettle() time.Duration  { return durOr(c.HealthSettle, 2*time.Second) }
func (c storeTunables) stallTimeout() time.Duration  { return durOr(c.StallTimeout, 60*time.Second) }

// storeState is the state of the store that is not in the options
type storeState struct {
	// opMu: one change of the files of the plugin directory at a time (the move of
	// an install into place, the swap, start and health check of an update, a
	// rollback, an uninstall). It is NOT held while something is downloaded.
	opMu sync.Mutex

	mu      sync.Mutex
	staging map[string]bool   //staging folder name -> a download into it is running
	gen     map[string]uint64 //plugin ID -> counts installs, updates, rollbacks and uninstalls of it
	sources map[string]SourceStatus
	seen    map[string]indexSeen //index URL -> highest serial seen with a valid signature
	seenOK  bool
	records map[string]*InstallRecord //plugin ID -> install record, nil entry = known to be absent
	folders map[string]string         //plugin folder name -> plugin ID of its install record, "" = known to have none
	// plugin folder name -> checksum of the changed program file that was last reported for it
	changedSeen map[string]string
}

/* One download per staging folder, and noticing what happened meanwhile */

// beginStaging reserves the staging folder of a plugin ID for one download. A
// second install or update of the same plugin is refused while one is running
// instead of queueing behind it. The caller calls release when it is done.
func (m *Manager) beginStaging(pluginID string) (release func(), err error) {
	name, err := safePluginFolderName(pluginID, "")
	if err != nil {
		return nil, err
	}
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	if m.store.staging[name] {
		return nil, fmt.Errorf("an install or update of plugin %s is already running, wait for it to finish", pluginID)
	}
	if m.store.staging == nil {
		m.store.staging = map[string]bool{}
	}
	m.store.staging[name] = true
	return func() {
		m.store.mu.Lock()
		delete(m.store.staging, name)
		m.store.mu.Unlock()
	}, nil
}

func (m *Manager) storeGen(pluginID string) uint64 {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	return m.store.gen[pluginID]
}

func (m *Manager) bumpStoreGen(pluginID string) {
	m.store.mu.Lock()
	if m.store.gen == nil {
		m.store.gen = map[string]uint64{}
	}
	m.store.gen[pluginID]++
	m.store.mu.Unlock()
}

// declaredIDCollision refuses a downloaded binary whose manifest declares another
// ID than the index lists (ownID) when that ID belongs to another plugin: one
// that is loaded, or one Dunree has an install record for. Otherwise installing
// an innocent looking plugin of one index would take over the record of a plugin
// that was installed from another index (its source of updates, its checksum)
// and, on an update, its slot in the plugin list. In every verification mode.
func (m *Manager) declaredIDCollision(declaredID string, ownID string) error {
	if declaredID == ownID {
		return nil
	}
	what := ""
	if _, err := m.GetPluginByID(declaredID); err == nil {
		what = "the ID of another installed plugin"
	} else if m.installRecord(declaredID) != nil {
		what = "an ID Dunree has the install record of another plugin for"
	}
	if what == "" {
		return nil
	}
	m.audit("plugins.download.id_collision", ownID, map[string]string{"declared": clipText(declaredID, 120), "mode": m.Settings().VerifyMode})
	return fmt.Errorf("the downloaded plugin says its ID is %q, the index says %q, and %q is %s: refused", clipText(declaredID, 80), ownID, clipText(declaredID, 80), what)
}

/* Public key */

// parseIndexPublicKey reads an ed25519 public key: the PEM file tools/plugin-index
// writes (SPKI), or the 32 raw bytes in base64 or hex.
func parseIndexPublicKey(text string) (ed25519.PublicKey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("no public key")
	}
	if blk, _ := pem.Decode([]byte(text)); blk != nil {
		if blk.Type == "PRIVATE KEY" || strings.Contains(blk.Type, "PRIVATE") {
			return nil, errors.New("this is a private key. Only the public key belongs here; keep the private key away from the proxy")
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("the public key is not a valid PEM public key")
		}
		pk, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("the public key is not an ed25519 key")
		}
		return pk, nil
	}
	if raw, err := hex.DecodeString(text); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if raw, err := base64.StdEncoding.DecodeString(text); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, errors.New("the public key is neither a PEM public key nor 32 bytes in base64 or hex")
}

// publicKeyFingerprint is a short name for a key, to compare by eye
func publicKeyFingerprint(pk ed25519.PublicKey) string {
	sum := sha256.Sum256(pk)
	return hex.EncodeToString(sum[:8])
}

// indexPublicKey returns the configured plugin index key: the start flag wins over the setting
func (m *Manager) indexPublicKey() (ed25519.PublicKey, string, error) {
	if m.Options != nil && strings.TrimSpace(m.Options.IndexPublicKeyFile) != "" {
		raw, err := os.ReadFile(m.Options.IndexPublicKeyFile)
		if err != nil {
			return nil, "flag", errors.New("the plugin index public key file of the start flag cannot be read")
		}
		pk, err := m.usableIndexPublicKey(string(raw))
		return pk, "flag", err
	}
	text := m.Settings().IndexPublicKey
	if strings.TrimSpace(text) == "" {
		return nil, "", nil
	}
	pk, err := m.usableIndexPublicKey(text)
	return pk, "setting", err
}

// usableIndexPublicKey parses a plugin index public key and refuses the release
// key of Dunree (decision D4: the plugin index has a key of its own). Both are
// ed25519 signatures over the plain bytes of a file, with nothing that says what
// kind of file was signed: with one key for both, a signature made for one could
// be presented for the other.
func (m *Manager) usableIndexPublicKey(text string) (ed25519.PublicKey, error) {
	pk, err := parseIndexPublicKey(text)
	if err != nil {
		return nil, err
	}
	if m.Options != nil && len(m.Options.ReleasePublicKey) == ed25519.PublicKeySize && pk.Equal(ed25519.PublicKey(m.Options.ReleasePublicKey)) {
		return nil, errors.New("this is the key Dunree releases are signed with. The plugin index needs a key of its own (tools/plugin-index/sign_plugin_index.go -genkey)")
	}
	return pk, nil
}

// indexKeyFingerprint is the fingerprint of the plugin index key in use, "" when there is none
func (m *Manager) indexKeyFingerprint() string {
	pk, _, err := m.indexPublicKey()
	if err != nil || pk == nil {
		return ""
	}
	return publicKeyFingerprint(pk)
}

/* Fetching */

// storeGet fetches a small document (index, signature) with a size cap and a timeout.
// The default transport is used on purpose: offline mode and its tests hook into it.
func (m *Manager) storeGet(target string, limit int64) ([]byte, error) {
	if isLocalSource(target) {
		// An index in a local folder: no network, so offline mode does not apply
		path, ok := pathFromFileURL(target)
		if !ok {
			return nil, errors.New("not the address of a local file")
		}
		return readLocalStoreFile(path, limit)
	}
	if err := offline.Check(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.storeCfg.indexTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return content, nil
}

// signatureURL is where the detached signature of an index lives: "<path>.sig"
func signatureURL(indexURL string) string {
	u, err := url.Parse(indexURL)
	if err != nil {
		return indexURL + ".sig"
	}
	u.Path += ".sig"
	u.RawPath = ""
	return u.String()
}

// fetchIndex downloads one index and says what it is worth. An error means the
// index could not be read at all; a problem with its signature is not an error
// here, it is in the status, and the caller decides by the verification mode.
func (m *Manager) fetchIndex(indexURL string) ([]*DownloadablePlugin, SourceStatus, error) {
	st := SourceStatus{CheckedAt: time.Now().Unix()}
	raw, err := m.storeGet(indexURL, maxIndexBytes)
	if err != nil {
		return nil, st, err
	}
	trimmed := bytes.TrimSpace(raw)
	mode := m.Settings().VerifyMode

	if len(trimmed) == 0 || trimmed[0] != '{' {
		//The upstream format: a list
		var list []*DownloadablePlugin
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, st, fmt.Errorf("failed to unmarshal plugin list from %s: %w", indexURL, err)
		}
		st.Format = "legacy"
		st.Schema = SchemaList
		st.Signature = SigUnsigned
		if mode == VerifyOff {
			st.Signature = SigUnchecked
		} else if last := m.seenSerialOf(indexURL); last > 0 {
			st.Signature = SigDowngraded
			st.Note = "This address served a signed index before (serial " + strconv.FormatInt(last, 10) + ") and now serves a list without checksums and without a signature. Nothing about its plugins can be checked. If that is not your own change, the index or the connection to it has been tampered with."
		}
		for _, p := range list {
			if p == nil {
				continue
			}
			p.Downloads = nil //only a signed index can pin a download
			if strings.TrimSpace(p.IconPath) == "" {
				p.IconPath = defaultStoreIcon
			}
			p.Signature = st.Signature
			p.IndexSerial = 0
		}
		list = compactPlugins(list)
		st.Plugins = len(list)
		return list, st, nil
	}

	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil, st, fmt.Errorf("failed to unmarshal plugin index from %s: %w", indexURL, err)
	}
	if probe.Format == addonindex.Format {
		//The Dunree add-on index (store_addon.go)
		return m.readAddonIndex(indexURL, raw, st)
	}

	var idx signedIndex
	if err := json.Unmarshal(trimmed, &idx); err != nil {
		return nil, st, fmt.Errorf("failed to unmarshal plugin index from %s: %w", indexURL, err)
	}
	if idx.Format != signedIndexFormat {
		return nil, st, fmt.Errorf("%s is not a plugin index (format %q)", indexURL, clipText(idx.Format, 40))
	}
	if idx.Version != signedIndexVersion {
		return nil, st, fmt.Errorf("%s is a plugin index of version %d, this Dunree reads version %d", indexURL, idx.Version, signedIndexVersion)
	}
	st.Format = "signed"
	st.Schema = SchemaSignedIndex
	st.Serial = idx.Serial

	keyFP := ""
	switch {
	case mode == VerifyOff:
		st.Signature = SigUnchecked
	default:
		st.Signature, st.Note, keyFP = m.checkIndexSignature(indexURL, raw, idx.Serial)
	}

	list := make([]*DownloadablePlugin, 0, len(idx.Plugins))
	for _, e := range idx.Plugins {
		if e == nil {
			continue
		}
		if strings.TrimSpace(e.IconPath) == "" {
			e.IconPath = defaultStoreIcon
		}
		p := &DownloadablePlugin{
			IconPath:         e.IconPath,
			PluginIntroSpect: e.PluginIntroSpect,
			DownloadURLs:     map[string]string{},
			Downloads:        map[string]PinnedDownload{},
			Signature:        st.Signature,
			IndexSerial:      idx.Serial,
			verifiedKey:      keyFP,
		}
		for platform, d := range e.Downloads {
			d.SHA256 = strings.ToLower(strings.TrimSpace(d.SHA256))
			p.Downloads[platform] = d
			p.DownloadURLs[platform] = d.URL //the shape the store page and older code read
		}
		list = append(list, p)
	}
	st.Plugins = len(list)
	return list, st, nil
}

func compactPlugins(list []*DownloadablePlugin) []*DownloadablePlugin {
	out := list[:0]
	for _, p := range list {
		if p != nil {
			out = append(out, p)
		}
	}
	return out
}

// checkIndexSignature verifies the detached signature of a signed index and its
// serial number. It returns the state, one sentence about it and, for a valid
// signature, the fingerprint of the key it was verified with.
func (m *Manager) checkIndexSignature(indexURL string, raw []byte, serial int64) (string, string, string) {
	pk, _, err := m.indexPublicKey()
	if err != nil {
		return SigNoKey, "The configured plugin index public key cannot be used: " + err.Error() + ".", ""
	}
	if pk == nil {
		return SigNoKey, "This index is signed, but no plugin index public key is configured, so the signature cannot be checked.", ""
	}
	sig, err := m.storeGet(signatureURL(indexURL), 4096)
	if err != nil {
		if errors.Is(err, offline.ErrOffline) {
			return SigMissing, "The signature file of this index was not fetched (offline mode).", ""
		}
		return SigMissing, "The signature file of this index (" + clipText(signatureURL(indexURL), 200) + ") could not be fetched.", ""
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pk, raw, sig) {
		return SigBad, "The signature of this index does not match the configured plugin index public key. The index was changed after it was signed, or it was signed with another key.", ""
	}
	if serial <= 0 {
		return SigBad, "This index is signed but carries no serial number, so an old copy of it could not be told from a new one.", ""
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.loadSeenLocked()
	last := m.store.seen[indexURL]
	switch {
	case serial < last.Serial:
		return SigReplayed, "This index is validly signed but older (serial " + strconv.FormatInt(serial, 10) + ") than the one this Dunree has already seen from this address (serial " + strconv.FormatInt(last.Serial, 10) + "). An old index is being served again.", ""
	case serial == last.Serial && last.SHA256 != "" && last.SHA256 != digest:
		return SigReplayed, "This index is validly signed but has the same serial number (" + strconv.FormatInt(serial, 10) + ") as a different index this Dunree has already seen from this address. Every signed index needs a higher serial number.", ""
	case serial > last.Serial:
		m.store.seen[indexURL] = indexSeen{Serial: serial, SHA256: digest}
		m.storeSeenLocked()
	}
	return SigSigned, "", publicKeyFingerprint(pk)
}

// seenSerialOf is the highest serial of a validly signed index this Dunree has seen from an address, 0 = none
func (m *Manager) seenSerialOf(indexURL string) int64 {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.loadSeenLocked()
	return m.store.seen[indexURL].Serial
}

func (m *Manager) loadSeenLocked() {
	if m.store.seenOK {
		return
	}
	m.store.seen = map[string]indexSeen{}
	if m.hasDB() && m.Options.Database.KeyExists(settingsDBTable, indexSeenDBKey) {
		m.Options.Database.Read(settingsDBTable, indexSeenDBKey, &m.store.seen)
		if m.store.seen == nil {
			m.store.seen = map[string]indexSeen{}
		}
	}
	m.store.seenOK = true
}

func (m *Manager) storeSeenLocked() {
	if !m.hasDB() {
		return
	}
	m.Options.Database.NewTable(settingsDBTable)
	if err := m.Options.Database.Write(settingsDBTable, indexSeenDBKey, m.store.seen); err != nil {
		m.Log("Failed to store the serial numbers of the plugin indexes", err)
	}
}

// sourceStatusOf returns what the last sync found out about an index URL
func (m *Manager) sourceStatusOf(indexURL string) SourceStatus {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	return m.store.sources[indexURL]
}

func (m *Manager) setSourceStatus(indexURL string, st SourceStatus) {
	m.store.mu.Lock()
	if m.store.sources == nil {
		m.store.sources = map[string]SourceStatus{}
	}
	m.store.sources[indexURL] = st
	m.store.mu.Unlock()
}

/* What may be installed */

func platformKey() string { return runtime.GOOS + "_" + runtime.GOARCH }

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// installBlockedReason says why a plugin of the store may not be installed or
// updated under the current verification mode. Empty: it may.
func (m *Manager) installBlockedReason(p *DownloadablePlugin) string {
	if m.Settings().VerifyMode != VerifyEnforce {
		return ""
	}
	switch p.Signature {
	case SigSigned:
		// Signed counts for the key it was verified with. After a change of the key
		// an entry that is still in the list from before is not signed any more.
		if now := m.indexKeyFingerprint(); now == "" || p.verifiedKey != now {
			return "signature checking is set to enforce and this plugin was listed by an index that was checked with another plugin index public key than the one configured now"
		}
	case SigDowngraded:
		return "signature checking is set to enforce and the index of this plugin, which was signed before, is now served without a signature"
	case SigUnsigned, SigUnchecked, "":
		return "signature checking is set to enforce and this plugin comes from an index that is not signed"
	case SigNoKey:
		return "signature checking is set to enforce and no usable plugin index public key is configured"
	case SigMissing:
		return "signature checking is set to enforce and the signature of the index could not be fetched"
	case SigReplayed:
		return "signature checking is set to enforce and the index is an old one that is being served again"
	default:
		return "signature checking is set to enforce and the signature of the index is not valid"
	}
	d, ok := p.Downloads[platformKey()]
	if !ok {
		return "" //no download for this platform at all: the install says so
	}
	if !validSHA256(d.SHA256) || d.Size <= 0 {
		return "signature checking is set to enforce and the index has no checksum and size for this download"
	}
	return ""
}

// checkDownload compares a finished download with what the index says about it.
// It returns how the download was verified and, when it does not match, why.
func (m *Manager) checkDownload(p *DownloadablePlugin, sum string, size int64) (verified string, problem string) {
	if m.Settings().VerifyMode == VerifyOff {
		return VerifiedUnchecked, ""
	}
	d, ok := p.Downloads[platformKey()]
	if !ok || d.SHA256 == "" {
		return VerifiedNotPinned, ""
	}
	if d.Size > 0 && d.Size != size {
		return VerifiedMismatch, fmt.Sprintf("the download is %d bytes, the index says %d", size, d.Size)
	}
	if !strings.EqualFold(d.SHA256, sum) {
		return VerifiedMismatch, "the SHA-256 of the download is " + sum + ", the index says " + clipText(d.SHA256, 64)
	}
	return VerifiedHashOK, ""
}

func (m *Manager) maxDownloadBytes() int64 {
	if m.storeCfg.MaxBytes > 0 {
		return m.storeCfg.MaxBytes
	}
	mb := m.Settings().MaxDownloadMB
	if mb <= 0 {
		mb = defaultMaxDownloadMB
	}
	return int64(mb) << 20
}

// downloadTo downloads a file with a size cap and a timeout for the whole
// transfer and returns its SHA-256 and size. Nothing is left at destPath on error.
func (m *Manager) downloadTo(downloadURL string, destPath string, limit int64) (sum string, size int64, err error) {
	if isLocalSource(downloadURL) {
		// An artifact of a local folder (store_addon.go). Only files inside the
		// folder of a configured local source are read, whatever index named this one.
		return m.copyLocalArtifact(downloadURL, destPath, limit)
	}
	if err := offline.Check(); err != nil {
		return "", 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.storeCfg.downloadTimeout())
	defer cancel()
	// Stall detection: a store that stops sending does not keep the download (and
	// the admin request that waits for it) open for the whole timeout
	stallAfter := m.storeCfg.stallTimeout()
	var stalled atomic.Bool
	watch := time.AfterFunc(stallAfter, func() {
		stalled.Store(true)
		cancel()
	})
	defer watch.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if stalled.Load() {
			return "", 0, fmt.Errorf("no answer within %s", plainDuration(stallAfter))
		}
		if ctx.Err() != nil {
			return "", 0, fmt.Errorf("no answer within %s", plainDuration(m.storeCfg.downloadTimeout()))
		}
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.ContentLength > limit {
		return "", 0, fmt.Errorf("the download is %d bytes, more than the limit of %d bytes", resp.ContentLength, limit)
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
	body := &progressReader{r: io.LimitReader(resp.Body, limit+1), progress: func() { watch.Reset(stallAfter) }}
	size, err = io.Copy(io.MultiWriter(out, h), body)
	if err != nil {
		if stalled.Load() {
			return "", 0, fmt.Errorf("the download stalled: no data for %s", plainDuration(stallAfter))
		}
		if ctx.Err() != nil {
			return "", 0, fmt.Errorf("the download was not complete after %s", plainDuration(m.storeCfg.downloadTimeout()))
		}
		return "", 0, err
	}
	if size > limit {
		return "", 0, fmt.Errorf("the download is larger than the limit of %d bytes", limit)
	}
	if err = out.Sync(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// progressReader calls progress whenever bytes arrived
type progressReader struct {
	r        io.Reader
	progress func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.progress()
	}
	return n, err
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
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

/* Install records: where a plugin came from and what was installed */

// InstalledVersion describes one binary of a plugin
type InstalledVersion struct {
	Version     string //as the manifest of the binary says
	SHA256      string //of the binary as it was installed
	Size        int64
	URL         string //where it was downloaded from
	Signature   string //state of the index at that time (Sig...)
	Verified    string //how the download was checked (Verified...)
	IndexSerial int64  //serial of the signed index it came from
	InstalledAt int64
}

// InstallRecord is what Dunree knows about the install of one plugin ID
type InstallRecord struct {
	Source          string            //index URL the plugin was installed from. Updates only come from there. Empty: not known (installed before this was recorded, or copied in by hand), any index may update it
	Current         InstalledVersion  //the binary in the plugin folder
	Folder          string            //name of the plugin folder inside the plugin directory. The record is found by it before the program file is run for its manifest (checkBinaryBeforeLoad), so a replaced file cannot get around the comparison by declaring another ID
	Previous        *InstalledVersion //the binary kept in .zoraxy-previous/, nil = none
	LastChange      string            //install | update | rollback | auto_rollback
	LastChangeAt    int64
	LastChangeNote  string //one sentence, worded by Dunree
	LastChangeIssue bool   //the last update did not end well (failed health check, rolled back)
}

func (m *Manager) installRecord(pluginID string) *InstallRecord {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	if rec, ok := m.store.records[pluginID]; ok {
		if rec == nil {
			return nil
		}
		cp := *rec
		if rec.Previous != nil {
			prev := *rec.Previous
			cp.Previous = &prev
		}
		return &cp
	}
	if m.store.records == nil {
		m.store.records = map[string]*InstallRecord{}
	}
	var rec *InstallRecord
	if m.hasDB() && m.Options.Database.KeyExists(installDBTable, pluginID) {
		loaded := InstallRecord{}
		if err := m.Options.Database.Read(installDBTable, pluginID, &loaded); err == nil {
			rec = &loaded
		}
	}
	m.store.records[pluginID] = rec
	if rec == nil {
		return nil
	}
	cp := *rec
	if rec.Previous != nil {
		prev := *rec.Previous
		cp.Previous = &prev
	}
	return &cp
}

func (m *Manager) saveInstallRecord(pluginID string, rec *InstallRecord) {
	m.store.mu.Lock()
	if m.store.records == nil {
		m.store.records = map[string]*InstallRecord{}
	}
	cp := *rec
	m.store.records[pluginID] = &cp
	if rec.Folder != "" {
		if m.store.folders == nil {
			m.store.folders = map[string]string{}
		}
		m.store.folders[rec.Folder] = pluginID
	}
	m.store.mu.Unlock()
	if m.hasDB() {
		m.Options.Database.NewTable(installDBTable)
		if err := m.Options.Database.Write(installDBTable, pluginID, rec); err != nil {
			m.Log("Failed to store the install record of plugin "+pluginID, err)
		}
		if rec.Folder != "" {
			m.Options.Database.NewTable(installFolderDBTable)
			if err := m.Options.Database.Write(installFolderDBTable, rec.Folder, pluginID); err != nil {
				m.Log("Failed to store the plugin folder of the install record of plugin "+pluginID, err)
			}
		}
	}
}

// recordOfFolder returns the install record of the plugin that was installed into
// a folder of the plugin directory, and the plugin ID it is stored under. It does
// not run anything: it is what is known before the program file is asked for its ID.
func (m *Manager) recordOfFolder(folder string) (string, *InstallRecord) {
	m.store.mu.Lock()
	id, ok := m.store.folders[folder]
	m.store.mu.Unlock()
	if !ok {
		if m.hasDB() && m.Options.Database.KeyExists(installFolderDBTable, folder) {
			if err := m.Options.Database.Read(installFolderDBTable, folder, &id); err != nil {
				id = ""
			}
		}
		m.store.mu.Lock()
		if m.store.folders == nil {
			m.store.folders = map[string]string{}
		}
		if cur, raced := m.store.folders[folder]; raced {
			id = cur
		} else {
			m.store.folders[folder] = id
		}
		m.store.mu.Unlock()
	}
	if id == "" {
		return "", nil
	}
	rec := m.installRecord(id)
	if rec == nil || rec.Folder != folder {
		return "", nil
	}
	return id, rec
}

// noteRecordFolder writes the folder into an install record that has none (a
// record of a plugin that was loaded by its ID before folders were recorded).
func (m *Manager) noteRecordFolder(pluginID string, folder string) {
	rec := m.installRecord(pluginID)
	if rec == nil || rec.Folder != "" || folder == "" {
		return
	}
	rec.Folder = folder
	m.saveInstallRecord(pluginID, rec)
}

// errBinaryChanged: the program file of a plugin folder is not the installed one
// and signature checking is set to enforce, so it was not run at all
type errBinaryChanged struct{ msg string }

func (e *errBinaryChanged) Error() string { return e.msg }

// checkBinaryBeforeLoad compares the program file of a plugin folder with its
// install record BEFORE the file is run with -introspect (boot and reload run
// every plugin that way, as the user of Dunree). The record is found by the folder,
// not by the ID the file declares. enforce: a file that is not the installed one
// is not run (error). warn: recordID is the ID of the record the file does not
// match; the caller loads it as before and calls noteChangedBinaryLoaded. off, or
// no record, or the installed file: "", nil.
func (m *Manager) checkBinaryBeforeLoad(folder string, pluginPath string) (recordID string, err error) {
	mode := m.Settings().VerifyMode
	if mode == VerifyOff {
		return "", nil
	}
	id, rec := m.recordOfFolder(folder)
	if rec == nil || rec.Current.SHA256 == "" {
		return "", nil
	}
	entryPoint, epErr := m.GetPluginEntryPoint(pluginPath)
	if epErr != nil {
		return "", nil //the load itself reports a folder without a program file
	}
	sum, _, hashErr := fileSHA256(entryPoint)
	if hashErr != nil || sum == rec.Current.SHA256 {
		return "", nil
	}
	if mode == VerifyEnforce {
		if m.auditOncePerFile(folder, sum, "plugins.binary.changed", id, map[string]string{"folder": folder, "sha256": sum, "installed": rec.Current.SHA256, "started": "false", "run": "false"}) {
			m.Log("plugin folder "+folder+": the program file is not the one that was installed as plugin "+id+" (SHA-256 "+sum+", installed "+rec.Current.SHA256+"). It is not run (signature checking: enforce)", nil)
		}
		return id, &errBinaryChanged{msg: "the program file in this folder is not the one that was installed as plugin " + id + " (SHA-256 " + sum + ", installed " + rec.Current.SHA256 + "), and signature checking is set to enforce: the file was not run and the plugin is not loaded. Put the installed file back, or remove the folder and install the plugin again, or set signature checking to warn and restart Dunree"}
	}
	return id, nil
}

// noteChangedBinaryLoaded is the warn half of checkBinaryBeforeLoad: the changed
// program file of a folder was run for its manifest. When it declares the ID of
// its install record, the start of the plugin reports it (checkBinaryForStart).
// When it declares another ID no record is found for it at its start, so it is
// reported here: logged and audited once per changed file.
func (m *Manager) noteChangedBinaryLoaded(folder string, pluginPath string, recordID string, declaredID string) {
	if recordID == "" || recordID == declaredID {
		return
	}
	sum := ""
	if entryPoint, err := m.GetPluginEntryPoint(pluginPath); err == nil {
		sum, _, _ = fileSHA256(entryPoint)
	}
	if m.auditOncePerFile(folder, sum, "plugins.binary.changed", recordID, map[string]string{"folder": folder, "sha256": sum, "declared": clipText(declaredID, 120), "run": "true"}) {
		m.Log("plugin folder "+folder+": the program file is not the one that was installed as plugin "+recordID+", and it now says its ID is "+strconv.Quote(clipText(declaredID, 80))+". It is loaded anyway (signature checking: warn)", nil)
	}
}

// auditOncePerFile writes an audit entry the first time a folder is seen with a
// file of this checksum, and says whether it did.
func (m *Manager) auditOncePerFile(folder string, sum string, event string, target string, detail map[string]string) bool {
	m.store.mu.Lock()
	if m.store.changedSeen == nil {
		m.store.changedSeen = map[string]string{}
	}
	seen := m.store.changedSeen[folder] == sum
	m.store.changedSeen[folder] = sum
	m.store.mu.Unlock()
	if seen {
		return false
	}
	m.audit(event, target, detail)
	return true
}

func (m *Manager) forgetInstallRecord(pluginID string) {
	folder := ""
	if rec := m.installRecord(pluginID); rec != nil {
		folder = rec.Folder
	}
	m.store.mu.Lock()
	delete(m.store.records, pluginID)
	dropFolder := false
	if folder != "" {
		if cur, ok := m.store.folders[folder]; ok && cur == pluginID {
			delete(m.store.folders, folder)
			dropFolder = true
		} else if !ok {
			dropFolder = true //not cached: look at the stored row below
		}
	}
	m.store.mu.Unlock()
	if m.hasDB() {
		m.Options.Database.Delete(installDBTable, pluginID)
		if dropFolder && m.Options.Database.KeyExists(installFolderDBTable, folder) {
			owner := ""
			if err := m.Options.Database.Read(installFolderDBTable, folder, &owner); err != nil || owner == pluginID {
				m.Options.Database.Delete(installFolderDBTable, folder)
			}
		}
	}
}

// PluginInstallInfo is what the API says about the install of a plugin
type PluginInstallInfo struct {
	Known           bool   //there is an install record. false: installed before installs were recorded, or copied in by hand
	Source          string //index the plugin was installed from; updates only come from there
	Signature       string //state of that index when this version was installed
	Verified        string //how the download of this version was checked
	Version         string
	SHA256          string
	InstalledAt     int64
	BinaryState     string //"" not looked at | ok | changed: the binary in the plugin folder is not the one that was installed (looked at when the plugin is started)
	PreviousVersion string //the version kept for a rollback, empty = none
	CanRollback     bool
	LastChange      string
	LastChangeAt    int64
	LastChangeNote  string
	LastChangeIssue bool
	Note            string //one sentence when something needs attention
}

func (m *Manager) installInfoOf(p *Plugin) PluginInstallInfo {
	p.mu.RLock()
	id := p.Spec.ID
	binState := p.binaryState
	p.mu.RUnlock()
	info := PluginInstallInfo{BinaryState: binState}
	rec := m.installRecord(id)
	if rec == nil {
		return info
	}
	info.Known = true
	info.Source = rec.Source
	info.Signature = rec.Current.Signature
	info.Verified = rec.Current.Verified
	info.Version = rec.Current.Version
	info.SHA256 = rec.Current.SHA256
	info.InstalledAt = rec.Current.InstalledAt
	info.LastChange = rec.LastChange
	info.LastChangeAt = rec.LastChangeAt
	info.LastChangeNote = rec.LastChangeNote
	info.LastChangeIssue = rec.LastChangeIssue
	if rec.Previous != nil {
		info.PreviousVersion = rec.Previous.Version
		info.CanRollback = true
	}
	switch {
	case binState == "changed":
		info.Note = "The program file of this plugin is not the one that was installed: it was replaced or changed on disk."
	case rec.LastChangeIssue:
		info.Note = rec.LastChangeNote
	case rec.Current.Verified == VerifiedMismatch:
		info.Note = "The download of this version did not match the checksum of its index. It was installed because signature checking was set to warn."
	}
	return info
}

// checkBinaryForStart compares the binary of a plugin with what was installed
// (only for plugins with an install record, and not with verification off). warn:
// a changed binary is logged and shown. enforce: it is not started.
func (m *Manager) checkBinaryForStart(p *Plugin, entryPoint string) error {
	mode := m.Settings().VerifyMode
	rec := m.installRecord(p.Spec.ID)
	if mode == VerifyOff || rec == nil || rec.Current.SHA256 == "" {
		p.mu.Lock()
		p.binaryState = ""
		p.mu.Unlock()
		return nil
	}
	sum, _, err := fileSHA256(entryPoint)
	if err != nil {
		return nil //the start itself reports a binary that cannot be read
	}
	state := "ok"
	if sum != rec.Current.SHA256 {
		state = "changed"
	}
	p.mu.Lock()
	was := p.binaryState
	p.binaryState = state
	p.mu.Unlock()
	if state == "ok" {
		return nil
	}
	if mode == VerifyEnforce {
		return &errContractRefused{
			note:  "the program file of plugin " + p.Spec.ID + " is not the one that was installed (SHA-256 " + sum + ", installed " + rec.Current.SHA256 + "), and signature checking is set to enforce: it is not started. Update or reinstall the plugin, or roll it back",
			short: "the program file is not the one that was installed (signature checking: enforce)",
		}
	}
	if was != "changed" {
		m.Log("plugin "+p.Spec.ID+": the program file is not the one that was installed (SHA-256 "+sum+", installed "+rec.Current.SHA256+"). It is started anyway (signature checking: warn)", nil)
		m.audit("plugins.binary.changed", p.Spec.ID, map[string]string{"sha256": sum, "installed": rec.Current.SHA256, "started": "true"})
	}
	return nil
}

// candidatesFor returns the store entries of a plugin ID an install or update may
// use: for a plugin with a known install source only the entries of that index.
func (m *Manager) candidatesFor(pluginID string, source string) []*DownloadablePlugin {
	var out []*DownloadablePlugin
	for _, p := range m.Options.DownloadablePluginCache {
		if p == nil || p.PluginIntroSpect.ID != pluginID {
			continue
		}
		if source != "" && p.Source != source {
			continue
		}
		out = append(out, p)
	}
	return out
}

func newestOf(list []*DownloadablePlugin) *DownloadablePlugin {
	var best *DownloadablePlugin
	for _, p := range list {
		if best == nil || downloadableVersionIsNewer(p, best) {
			best = p
		}
	}
	return best
}

// updateCandidate returns the store entry an installed plugin is updated from:
// the newest one of the index it was installed from, or, for a plugin whose
// source is not known, the newest one of any index (as before installs were recorded).
// offeredElsewhere says that only other indexes offer the plugin.
func (m *Manager) updateCandidate(pluginID string) (best *DownloadablePlugin, source string, offeredElsewhere bool) {
	if rec := m.installRecord(pluginID); rec != nil {
		source = rec.Source
	}
	best = newestOf(m.candidatesFor(pluginID, source))
	if best == nil && source != "" {
		offeredElsewhere = len(m.candidatesFor(pluginID, "")) > 0
	}
	return best, source, offeredElsewhere
}
