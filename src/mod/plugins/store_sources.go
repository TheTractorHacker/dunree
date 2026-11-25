package plugins

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TheTractorHacker/dunree/mod/utils"
)

/*
	Add-on store sources

	Dunree ships without a store: nothing is fetched until the administrator
	chooses a source. A source is one of

	  - the Dunree add-on store (DunreeAddonStoreIndexURL, one click),
	  - a custom index URL,
	  - a local folder that holds an index.json (no network at all),
	  - a built-in source of ManagerOptions.PluginStoreURLs (empty in the Dunree
	    binary; a packager or a test may fill it; cannot be removed in the UI).

	The chosen sources are kept in the database (key custom_store_urls of the
	table "plugins", the list community sources always were in).

	An installation that already existed before it ran Dunree keeps the source it
	always had: at its first Dunree start the plugin store of the Zoraxy project // legacy-compat
	(LegacyZoraxyStoreIndexURL) is written into that list once, where it is shown // legacy-compat
	as a third-party source and can be removed like any other. A new installation
	never gets it.
*/

// ---------------------------------------------------------------------------
// OWNER: SET BEFORE THE FIRST RELEASE WITH A STORE.
//
// These two constants are the only place the address and the key of the Dunree
// add-on store are written down. They point at the store repository
// TheTractorHacker/dunree-addons (GitHub Pages); move them here when the store moves:
//
//   - DunreeAddonStoreIndexURL is the index.json that tools/addon-store
//     publishes (docs/plugins/publishing-addons.md). While its host is a
//     reserved placeholder name (.example, .invalid, .test) or it is empty, the
//     one-click choice "Dunree add-on store" is shown as not available yet and
//     Dunree never contacts it.
//   - DunreeAddonStorePublicKey is the PUBLIC half of the add-on index key (the
//     PEM text, or the 32 bytes in base64 or hex). When it is set and the
//     administrator has configured no plugin index key, choosing the Dunree
//     add-on store configures this one. Never put a private key here.
//
// ---------------------------------------------------------------------------
const (
	DunreeAddonStoreIndexURL  = "https://thetractorhacker.github.io/dunree-addons/index.json"
	DunreeAddonStorePublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAEaDXYOjHyrKrLdbJYA0frdmww/Wd2xIfrRCpnHn+PMw=
-----END PUBLIC KEY-----`
)

// LegacyZoraxyStoreIndexURL is the plugin store of the Zoraxy project, a third // legacy-compat
// party to Dunree. It is not a default: it is only the value that is migrated
// into the settings of an installation that used it before it ran Dunree (see
// migrateStoreSources). Set it to "" to migrate nothing. // legacy-compat
const LegacyZoraxyStoreIndexURL = "https://raw.githubusercontent.com/aroz-online/zoraxy-official-plugins/refs/heads/main/directories/index2.json" // legacy-compat: migrated value only, never a default

const (
	dbKeyCustomStoreURLs  = "custom_store_urls"
	dbKeyStoreSourcesInit = "store_sources_init" //set at the first start: "fresh" | "existing" | "existing-migrated"
)

// Kinds of a store source
const (
	SourceKindBuiltin = "builtin"          //ManagerOptions.PluginStoreURLs
	SourceKindDunree  = "dunree"           //the Dunree add-on store
	SourceKindCustom  = "custom"           //an index URL the administrator entered
	SourceKindLocal   = "local"            //a folder on this server
	SourceKindZoraxy  = "zoraxy-community" //the plugin store of the Zoraxy project (third party) // legacy-compat
)

type StoreSource struct {
	URL          string `json:"url"`      //The plugin store index URL
	Official     bool   `json:"official"` //Whether this is a built-in source (cannot be removed)
	Kind         string `json:"kind"`     //builtin | dunree | custom | local | zoraxy-community
	Label        string `json:"label"`    //What to call it
	Folder       string `json:"folder"`   //local only: the folder on this server
	SourceStatus        //What the last sync found out about the index (format, signature, serial)
}

// DunreeStoreReady says whether this build carries a real address of the Dunree
// add-on store (and not the placeholder)
func DunreeStoreReady() bool { return storeURLReady(DunreeAddonStoreIndexURL) }

func storeURLReady(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, reserved := range []string{"example", "invalid", "test", "localhost", "example.com", "example.net", "example.org"} {
		if host == reserved || strings.HasSuffix(host, "."+reserved) {
			return false
		}
	}
	return true
}

func sourceKindOf(sourceURL string, builtin bool) string {
	switch {
	case builtin:
		return SourceKindBuiltin
	case isLocalSource(sourceURL):
		return SourceKindLocal
	case DunreeAddonStoreIndexURL != "" && sourceURL == DunreeAddonStoreIndexURL:
		return SourceKindDunree
	case LegacyZoraxyStoreIndexURL != "" && sourceURL == LegacyZoraxyStoreIndexURL: // legacy-compat
		return SourceKindZoraxy // legacy-compat
	}
	return SourceKindCustom
}

func (m *Manager) describeSource(sourceURL string, builtin bool) *StoreSource {
	src := &StoreSource{URL: sourceURL, Official: builtin, Kind: sourceKindOf(sourceURL, builtin), SourceStatus: m.sourceStatusOf(sourceURL)}
	switch src.Kind {
	case SourceKindBuiltin:
		src.Label = "Built-in source"
	case SourceKindDunree:
		src.Label = "Dunree add-on store"
	case SourceKindZoraxy: // legacy-compat
		src.Label = "Zoraxy community store (third party)" // legacy-compat
	case SourceKindLocal:
		src.Label = "Local folder"
		if indexPath, ok := pathFromFileURL(sourceURL); ok {
			src.Folder = filepath.Dir(indexPath)
		}
	default:
		src.Label = "Custom index"
	}
	return src
}

// getCustomStoreURLs returns the user-defined plugin store URLs from database
func (m *Manager) getCustomStoreURLs() []string {
	customURLs := []string{}
	err := m.Options.Database.Read("plugins", dbKeyCustomStoreURLs, &customURLs)
	if err != nil {
		return []string{}
	}
	return customURLs
}

// saveCustomStoreURLs persists the user-defined plugin store URLs to database
func (m *Manager) saveCustomStoreURLs(urls []string) error {
	return m.Options.Database.Write("plugins", dbKeyCustomStoreURLs, urls)
}

// isOfficialStoreURL checks if the given URL is one of the built-in store URLs
func (m *Manager) isOfficialStoreURL(targetURL string) bool {
	for _, url := range m.Options.PluginStoreURLs {
		if url == targetURL {
			return true
		}
	}
	return false
}

// GetAllStoreURLs returns the merged list of official and user-defined store URLs
func (m *Manager) GetAllStoreURLs() []string {
	allURLs := []string{}
	allURLs = append(allURLs, m.Options.PluginStoreURLs...)
	for _, customURL := range m.getCustomStoreURLs() {
		if !m.isOfficialStoreURL(customURL) {
			allURLs = append(allURLs, customURL)
		}
	}
	return allURLs
}

// StoreConfigured says whether any store source is configured. While none is,
// the store fetches nothing.
func (m *Manager) StoreConfigured() bool {
	return len(m.GetAllStoreURLs()) > 0
}

// ListStoreSources returns all registered plugin store sources
func (m *Manager) ListStoreSources() []*StoreSource {
	sources := []*StoreSource{}
	for _, url := range m.Options.PluginStoreURLs {
		sources = append(sources, m.describeSource(url, true))
	}
	for _, customURL := range m.getCustomStoreURLs() {
		if !m.isOfficialStoreURL(customURL) {
			sources = append(sources, m.describeSource(customURL, false))
		}
	}
	return sources
}

// migrateStoreSources runs once per installation, at the first start of a
// Dunree that knows it (NewPluginManager). An installation that existed before
// keeps the store it always synced from: the plugin store of the Zoraxy project // legacy-compat
// is written into the list of sources, visible and removable. A new
// installation gets no source. It returns what was done, for the log.
func (m *Manager) migrateStoreSources() string {
	if !m.hasDB() || m.Options.Database.KeyExists("plugins", dbKeyStoreSourcesInit) {
		return ""
	}
	state := "fresh"
	if m.Options.ExistingInstall {
		state = "existing"
		legacy := LegacyZoraxyStoreIndexURL // legacy-compat
		if legacy != "" && !m.isOfficialStoreURL(legacy) {
			urls := m.getCustomStoreURLs()
			known := false
			for _, u := range urls {
				known = known || u == legacy
			}
			if !known {
				// First in the list, where the built-in source was
				if err := m.saveCustomStoreURLs(append([]string{legacy}, urls...)); err != nil {
					return "" //try again at the next start
				}
			}
			state = "existing-migrated"
		}
	}
	if err := m.Options.Database.Write("plugins", dbKeyStoreSourcesInit, state); err != nil {
		return ""
	}
	return state
}

// AddStoreSource registers a new community plugin store index URL
func (m *Manager) AddStoreSource(sourceURL string) error {
	sourceURL = strings.TrimSpace(sourceURL)
	parsedURL, err := url.Parse(sourceURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("invalid plugin store URL: %s", sourceURL)
	}
	return m.addSource(sourceURL)
}

func (m *Manager) addSource(sourceURL string) error {
	//Check for duplicates
	for _, existingURL := range m.GetAllStoreURLs() {
		if existingURL == sourceURL {
			return fmt.Errorf("plugin store source already exists: %s", sourceURL)
		}
	}

	//Make sure the URL points to a valid plugin store index
	_, err := m.getPluginListFromURL(sourceURL)
	if err != nil {
		return fmt.Errorf("unable to load plugin index from source: %w", err)
	}

	customURLs := append(m.getCustomStoreURLs(), sourceURL)
	return m.saveCustomStoreURLs(customURLs)
}

// AddDunreeStore registers the Dunree add-on store (the one-click choice). It
// refuses, without contacting anything, while this build only carries the
// placeholder address.
func (m *Manager) AddDunreeStore() error {
	if !DunreeStoreReady() {
		return errors.New("the Dunree add-on store is not open yet: this version of Dunree carries no address for it. Use a custom index URL or a local folder")
	}
	// The public key of the store, unless the administrator configured a key
	if key := strings.TrimSpace(DunreeAddonStorePublicKey); key != "" {
		if pk, _, _ := m.indexPublicKey(); pk == nil && strings.TrimSpace(m.Settings().IndexPublicKey) == "" {
			if _, err := m.usableIndexPublicKey(key); err == nil {
				if err := m.SetSettings(func(s *ManagerSettings) { s.IndexPublicKey = key }); err != nil {
					m.Log("The public key of the Dunree add-on store could not be stored", err)
				}
			}
		}
	}
	return m.addSource(DunreeAddonStoreIndexURL)
}

// AddLocalStoreSource registers a folder of this server as a store source. The
// folder holds an index.json (and, for a signed index, index.json.sig) as
// tools/addon-store writes them. A path to the index file itself works too.
func (m *Manager) AddLocalStoreSource(folder string) error {
	folder = strings.TrimSpace(folder)
	if folder == "" {
		return errors.New("enter the folder that holds the index.json of the add-on store")
	}
	abs, err := filepath.Abs(folder)
	if err != nil {
		return errors.New("this is not a usable folder path")
	}
	st, err := os.Stat(abs)
	if err != nil {
		return errors.New("this folder does not exist on the server Dunree runs on, or Dunree may not read it")
	}
	indexPath := abs
	if st.IsDir() {
		indexPath = filepath.Join(abs, "index.json")
		if fi, err := os.Stat(indexPath); err != nil || !fi.Mode().IsRegular() {
			return errors.New("this folder holds no index.json")
		}
	} else if !st.Mode().IsRegular() {
		return errors.New("this is neither a folder nor an index file")
	}
	return m.addSource(fileURLFromPath(indexPath))
}

// RemoveStoreSource removes a community plugin store index URL
func (m *Manager) RemoveStoreSource(sourceURL string) error {
	if m.isOfficialStoreURL(sourceURL) {
		return fmt.Errorf("cannot remove built-in plugin store source")
	}

	customURLs := m.getCustomStoreURLs()
	newURLs := []string{}
	found := false
	for _, customURL := range customURLs {
		if customURL == sourceURL {
			found = true
			continue
		}
		newURLs = append(newURLs, customURL)
	}
	if !found {
		return fmt.Errorf("plugin store source not found: %s", sourceURL)
	}
	return m.saveCustomStoreURLs(newURLs)
}

// StoreSetup is what the store page needs to know before it shows anything
type StoreSetup struct {
	Configured  bool             `json:"configured"`  //false: no source at all, nothing is fetched
	Sources     int              `json:"sources"`     //how many sources are configured
	Platform    string           `json:"platform"`    //the builds this server installs, e.g. linux_amd64
	DunreeStore DunreeStoreState `json:"dunreeStore"` //the one-click choice
	Orphaned    []OrphanedSource `json:"orphaned"`    //sources installed plugins came from that are not configured any more
}

type DunreeStoreState struct {
	URL   string `json:"url"`
	Ready bool   `json:"ready"` //false: this build only carries the placeholder address
	Added bool   `json:"added"`
}

// OrphanedSource is an index installed plugins came from that is no longer a
// source: they keep running, but get no updates until it is added again.
type OrphanedSource struct {
	Source  string   `json:"source"`
	Kind    string   `json:"kind"`
	Plugins []string `json:"plugins"`
}

// StoreSetupInfo describes the state of the store sources
func (m *Manager) StoreSetupInfo() StoreSetup {
	urls := m.GetAllStoreURLs()
	configured := map[string]bool{}
	for _, u := range urls {
		configured[u] = true
	}
	info := StoreSetup{
		Configured: len(urls) > 0,
		Sources:    len(urls),
		Platform:   platformKey(),
		Orphaned:   []OrphanedSource{},
		DunreeStore: DunreeStoreState{
			URL:   DunreeAddonStoreIndexURL,
			Ready: DunreeStoreReady(),
			Added: configured[DunreeAddonStoreIndexURL],
		},
	}
	m.loadedPluginsMutex.RLock()
	ids := make([]string, 0, len(m.LoadedPlugins))
	for id := range m.LoadedPlugins {
		ids = append(ids, id)
	}
	m.loadedPluginsMutex.RUnlock()
	sort.Strings(ids)
	at := map[string]int{}
	for _, id := range ids {
		rec := m.installRecord(id)
		if rec == nil || rec.Source == "" || configured[rec.Source] {
			continue
		}
		i, ok := at[rec.Source]
		if !ok {
			i = len(info.Orphaned)
			at[rec.Source] = i
			info.Orphaned = append(info.Orphaned, OrphanedSource{Source: rec.Source, Kind: sourceKindOf(rec.Source, false)})
		}
		info.Orphaned[i].Plugins = append(info.Orphaned[i].Plugins, id)
	}
	return info
}

/*
	Handlers for Plugin Store Sources
*/

// HandleListStoreSources lists all the registered plugin store sources
func (m *Manager) HandleListStoreSources(w http.ResponseWriter, r *http.Request) {
	sources := m.ListStoreSources()
	js, _ := json.Marshal(sources)
	utils.SendJSONResponse(w, string(js))
}

// HandleStoreSetup says whether a store is configured and what the one-click choices are (read-only)
func (m *Manager) HandleStoreSetup(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(m.StoreSetupInfo())
	utils.SendJSONResponse(w, string(js))
}

// HandleAddStoreSource adds a new community plugin store source
func (m *Manager) HandleAddStoreSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	// kind: "" or "url" (a custom index URL, parameter url), "dunree" (the Dunree
	// add-on store), "local" (a folder of this server, parameter folder)
	kind, _ := utils.PostPara(r, "kind")
	var err error
	switch kind {
	case SourceKindDunree:
		err = m.AddDunreeStore()
	case SourceKindLocal:
		folder, perr := utils.PostPara(r, "folder")
		if perr != nil {
			utils.SendErrorResponse(w, "folder is required")
			return
		}
		err = m.AddLocalStoreSource(folder)
	case "", "url", SourceKindCustom:
		sourceURL, perr := utils.PostPara(r, "url")
		if perr != nil {
			utils.SendErrorResponse(w, "url is required")
			return
		}
		err = m.AddStoreSource(sourceURL)
	default:
		utils.SendErrorResponse(w, "unknown kind of source")
		return
	}
	if err != nil {
		utils.SendErrorResponse(w, "Failed to add plugin store source: "+err.Error())
		return
	}

	//Resync the downloadable plugin list to include the new source
	err = m.UpdateDownloadablePluginList()
	if err != nil {
		m.Log("Failed to resync plugin list after adding source", err)
	}

	utils.SendOK(w)
}

// HandleRemoveStoreSource removes a community plugin store source
func (m *Manager) HandleRemoveStoreSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}

	sourceURL, err := utils.PostPara(r, "url")
	if err != nil {
		utils.SendErrorResponse(w, "url is required")
		return
	}

	err = m.RemoveStoreSource(sourceURL)
	if err != nil {
		utils.SendErrorResponse(w, "Failed to remove plugin store source: "+err.Error())
		return
	}

	//Resync the downloadable plugin list to drop plugins from the removed source
	err = m.UpdateDownloadablePluginList()
	if err != nil {
		m.Log("Failed to resync plugin list after removing source", err)
	}

	utils.SendOK(w)
}
