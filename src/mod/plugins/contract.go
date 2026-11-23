package plugins

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/offline"
	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Plugin contract version and the plugin manager settings
	(phase 2 of docs/plugins/reliability-plan.md, items 2.1 and 2.6)

	The contract is written down in docs/plugins/contract.md. A plugin says which
	version it was built for with api_version in its manifest; a plugin that says
	nothing is a legacy plugin (version 0) and runs exactly as before.

	Defaults: a plugin built for a newer contract than this Zoraxy supports is
	started anyway and the administrator is told (log line, status). Refusing such
	a plugin, and requiring an approval for API permissions, are opt-in settings.
*/

// Contract versions this Zoraxy supports (inclusive)
const (
	ContractVersionMin = 0                       //legacy plugins: no api_version in the manifest
	ContractVersionMax = zoraxyPlugin.APIVersion //the version of the SDK in this source tree
)

// What Zoraxy does with a plugin built for a contract version it does not support
const (
	ContractModeWarn   = "warn"   //default: start it, log it, show it
	ContractModeRefuse = "refuse" //do not start it
)

// Contract states of a plugin
const (
	ContractLegacy      = "legacy"      //no api_version: the contract from before versions were counted
	ContractOK          = "ok"          //inside the supported range
	ContractUnsupported = "unsupported" //outside the supported range (built for a newer Zoraxy)
)

const (
	settingsDBTable = "plugin_settings"
	settingsDBKey   = "global"
)

// PluginContract is what the API says about the contract version of a plugin
type PluginContract struct {
	APIVersion   int    //api_version of the manifest, 0 = none
	SupportedMin int    //what this Zoraxy supports
	SupportedMax int    //
	State        string //legacy | ok | unsupported
	Refused      bool   //State is unsupported and the administrator asked Zoraxy not to start such plugins. From the setting as it is now: also true for a plugin that is still running and will be refused at its next start
	Note         string //one sentence for the administrator, empty when there is nothing to say
}

// contractStateOf classifies a manifest
func contractStateOf(spec *zoraxyPlugin.IntroSpect) string {
	switch {
	case spec == nil || spec.APIVersion == 0:
		return ContractLegacy
	case spec.APIVersion < ContractVersionMin || spec.APIVersion > ContractVersionMax:
		return ContractUnsupported
	}
	return ContractOK
}

func contractRangeText() string {
	return strconv.Itoa(ContractVersionMin) + " to " + strconv.Itoa(ContractVersionMax)
}

// contractOf returns the contract view of a plugin under the given mode
func contractOf(spec *zoraxyPlugin.IntroSpect, mode string) PluginContract {
	pc := PluginContract{SupportedMin: ContractVersionMin, SupportedMax: ContractVersionMax, State: contractStateOf(spec)}
	if spec != nil {
		pc.APIVersion = spec.APIVersion
	}
	if pc.State == ContractUnsupported {
		pc.Refused = mode == ContractModeRefuse
		pc.Note = "This plugin was built for plugin contract version " + strconv.Itoa(pc.APIVersion) + ", this Zoraxy supports " + contractRangeText() + "."
		if pc.Refused {
			pc.Note += " Zoraxy does not start it (plugin safety settings)."
		} else {
			pc.Note += " It is started anyway and may not work as expected."
		}
	}
	return pc
}

// sanitizeContractSpec checks api_version of a manifest. A value that cannot be a
// version is dropped, which makes the plugin a legacy plugin.
func sanitizeContractSpec(spec *zoraxyPlugin.IntroSpect) []string {
	if spec.APIVersion < 0 || spec.APIVersion > 1000000 {
		spec.APIVersion = 0
		return []string{"api_version in the manifest is not a version number, the plugin is treated as a legacy plugin"}
	}
	return nil
}

// errContractRefused is returned by StartPlugin for a plugin of an unsupported
// contract version while the contract mode is "refuse"
type errContractRefused struct {
	note  string
	short string //for the exit history, empty = the contract version wording
}

// why is the short reason for the exit history and the log
func (e *errContractRefused) why() string {
	if e.short != "" {
		return e.short
	}
	return "plugins of an unsupported contract version are not started (plugin safety settings)"
}

func (e *errContractRefused) Error() string { return e.note }

// checkContractForStart is called by every start of a plugin process
func (m *Manager) checkContractForStart(p *Plugin) error {
	pc := contractOf(p.Spec, m.Settings().ContractMode)
	if pc.State != ContractUnsupported {
		return nil
	}
	if pc.Refused {
		return &errContractRefused{note: "plugin was built for plugin contract version " + strconv.Itoa(pc.APIVersion) + ", this Zoraxy supports " + contractRangeText() + ", and plugins of an unsupported contract version are not started (plugin safety settings)"}
	}
	m.Log("plugin "+p.Spec.ID+" was built for plugin contract version "+strconv.Itoa(pc.APIVersion)+", this Zoraxy supports "+contractRangeText()+": it is started anyway and may not work as expected", nil)
	return nil
}

/* Plugin manager settings */

// ManagerSettings are the settings of the plugin manager that are not per plugin.
// The zero value is the behaviour from before these settings existed.
type ManagerSettings struct {
	ContractMode              string //warn (default) | refuse
	RequirePermissionApproval bool   //default false: every endpoint a plugin asks for in its manifest is granted, new ones are only reported. true: only endpoints the administrator approved are granted

	//Signed plugin index and safe update (store_verify.go, store_safe.go)
	VerifyMode     string //off | warn (default) | enforce
	IndexPublicKey string //ed25519 public key of the plugin index: PEM, or the 32 bytes in base64 or hex. Empty = none. The start flag -plugin_index_pubkey wins over it
	AutoRollback   bool   //default false: a new version that fails its health check after an update is left in place and reported. true: the previous version is put back and started
	MaxDownloadMB  int    //size cap of one plugin download, 0 = 256

	//Isolated plugin UI (ui_isolation.go)
	IsolatePluginUI bool   //default false: plugin pages are served under the admin origin, as before. true: from a listener of their own, without the admin cookie and CSRF token
	PluginUIListen  string //listen address of that listener, e.g. ":8001" or "127.0.0.1:8001". Empty = the default of this instance
	PluginUIOrigin  string //the address a browser reaches that listener at, e.g. "https://plugins.example.com". Empty = the host of the admin page with the port of the listener
}

func (s ManagerSettings) normalized() ManagerSettings {
	if s.ContractMode != ContractModeRefuse {
		s.ContractMode = ContractModeWarn
	}
	if s.VerifyMode != VerifyOff && s.VerifyMode != VerifyEnforce {
		s.VerifyMode = VerifyWarn
	}
	if s.MaxDownloadMB < 0 {
		s.MaxDownloadMB = 0
	}
	return s
}

type settingsState struct {
	writeMu sync.Mutex //one change of the settings at a time: read, change, store, swap
	mu      sync.RWMutex
	loaded  bool
	val     ManagerSettings
}

func (m *Manager) hasDB() bool {
	return m.Options != nil && m.Options.Database != nil && m.Options.Database.Backend != nil
}

// Settings returns the plugin manager settings with defaults filled in
func (m *Manager) Settings() ManagerSettings {
	m.settings.mu.RLock()
	if m.settings.loaded {
		v := m.settings.val
		m.settings.mu.RUnlock()
		return v
	}
	m.settings.mu.RUnlock()

	m.settings.mu.Lock()
	defer m.settings.mu.Unlock()
	if !m.settings.loaded {
		var rec ManagerSettings
		if m.hasDB() && m.Options.Database.KeyExists(settingsDBTable, settingsDBKey) {
			m.Options.Database.Read(settingsDBTable, settingsDBKey, &rec)
		}
		m.settings.val = rec.normalized()
		m.settings.loaded = true
	}
	return m.settings.val
}

// SetSettings changes the plugin manager settings. Both settings apply at once:
// the API keys of running plugins are narrowed or widened to what is granted now.
// A running plugin of an unsupported contract version is not stopped by "refuse":
// the setting is about starts.
func (m *Manager) SetSettings(change func(s *ManagerSettings)) error {
	// Two changes at the same time must not both start from the same settings (the
	// later one would undo the earlier one), and what is stored must be what is in
	// memory. The API keys are narrowed or widened after the lock is released.
	m.settings.writeMu.Lock()
	before := m.Settings()
	next := before
	change(&next)
	fail := func(err error) error {
		m.settings.writeMu.Unlock()
		return err
	}
	if next.ContractMode != ContractModeWarn && next.ContractMode != ContractModeRefuse {
		return fail(errors.New("contract mode must be warn or refuse"))
	}
	if next.VerifyMode != VerifyOff && next.VerifyMode != VerifyWarn && next.VerifyMode != VerifyEnforce {
		return fail(errors.New("signature checking must be off, warn or enforce"))
	}
	next.IndexPublicKey = strings.TrimSpace(next.IndexPublicKey)
	if next.IndexPublicKey != "" && next.IndexPublicKey != before.IndexPublicKey {
		if _, err := m.usableIndexPublicKey(next.IndexPublicKey); err != nil {
			return fail(err)
		}
	}
	if next.MaxDownloadMB < 0 || next.MaxDownloadMB > 4096 {
		return fail(errors.New("the size cap of a plugin download must be between 1 and 4096 MB (0 = default)"))
	}
	next.PluginUIListen = strings.TrimSpace(next.PluginUIListen)
	next.PluginUIOrigin = strings.TrimRight(strings.TrimSpace(next.PluginUIOrigin), "/")
	if !validUIOrigin(next.PluginUIOrigin) {
		return fail(errors.New("the address of the isolated plugin pages must look like https://host or https://host:port"))
	}
	uiChanged := before.IsolatePluginUI != next.IsolatePluginUI || before.PluginUIListen != next.PluginUIListen
	if uiChanged && next.IsolatePluginUI {
		// Open the listener before the setting is stored: isolation that cannot be
		// served is refused, it does not take the plugin pages away
		if err := m.applyUIIsolation(next); err != nil {
			return fail(err)
		}
	}
	if m.hasDB() {
		m.Options.Database.NewTable(settingsDBTable)
		if err := m.Options.Database.Write(settingsDBTable, settingsDBKey, next); err != nil {
			if uiChanged {
				m.applyUIIsolation(before)
			}
			return fail(err)
		}
	}
	m.settings.mu.Lock()
	m.settings.val = next
	m.settings.loaded = true
	m.settings.mu.Unlock()
	if uiChanged && !next.IsolatePluginUI {
		m.applyUIIsolation(next)
	}
	m.settings.writeMu.Unlock()

	if before.IsolatePluginUI != next.IsolatePluginUI {
		if next.IsolatePluginUI {
			m.Log("Plugin pages are now isolated: they are served from a listener of their own, without the admin cookie and CSRF token", nil)
		} else {
			m.Log("Plugin pages are no longer isolated: they are served under the admin origin again", nil)
		}
		m.audit("plugins.ui.isolation", "plugin pages", map[string]string{"isolated": strconv.FormatBool(next.IsolatePluginUI)})
	}
	if before.VerifyMode != next.VerifyMode {
		m.Log("Signature checking of plugin indexes and downloads is now: "+next.VerifyMode, nil)
	}
	if before.RequirePermissionApproval != next.RequirePermissionApproval {
		if next.RequirePermissionApproval {
			m.Log("API permissions of plugins now need an approval: only approved endpoints are granted", nil)
		} else {
			m.Log("API permissions of plugins no longer need an approval: every endpoint a plugin asks for is granted", nil)
		}
		list, _ := m.ListLoadedPlugins()
		for _, p := range list {
			m.applyGrantedEndpoints(p)
		}
	}
	return nil
}

// HandlePluginSettings is the admin API of the plugin manager settings.
// GET: the settings and the supported contract versions.
// POST contract_mode=warn|refuse and / or require_permission_approval=true|false.
func (m *Manager) HandlePluginSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var bad error
		r.ParseForm()
		was := m.Settings()
		err := m.SetSettings(func(s *ManagerSettings) {
			before := *s
			if v, err := utils.PostPara(r, "contract_mode"); err == nil {
				s.ContractMode = v
			}
			boolPara := func(name string, into *bool) {
				v, err := utils.PostPara(r, name)
				if err != nil {
					return
				}
				switch v {
				case "true":
					*into = true
				case "false":
					*into = false
				default:
					bad = errors.New(name + " must be true or false")
				}
			}
			boolPara("require_permission_approval", &s.RequirePermissionApproval)
			boolPara("auto_rollback", &s.AutoRollback)
			boolPara("isolate_plugin_ui", &s.IsolatePluginUI)
			if v, err := utils.PostPara(r, "verify_mode"); err == nil {
				s.VerifyMode = v
			}
			if _, has := r.PostForm["index_public_key"]; has {
				s.IndexPublicKey = r.PostForm.Get("index_public_key")
			}
			if _, has := r.PostForm["plugin_ui_listen"]; has {
				s.PluginUIListen = r.PostForm.Get("plugin_ui_listen")
			}
			if _, has := r.PostForm["plugin_ui_origin"]; has {
				s.PluginUIOrigin = r.PostForm.Get("plugin_ui_origin")
			}
			if v, err := utils.PostPara(r, "max_download_mb"); err == nil {
				n, convErr := strconv.Atoi(v)
				if convErr != nil {
					bad = errors.New("max_download_mb must be a number")
				} else {
					s.MaxDownloadMB = n
				}
			}
			if bad != nil {
				//Nothing of a request with an invalid value is applied
				*s = before
			}
		})
		if bad != nil {
			err = bad
		}
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		// What the cached store entries say about the signature of their index was
		// decided with the old mode and key: read the indexes again. (Whether or not
		// that works: under enforce an entry counts as signed only for the key it was
		// verified with, see installBlockedReason.)
		if now := m.Settings(); (was.VerifyMode != now.VerifyMode || was.IndexPublicKey != now.IndexPublicKey) &&
			m.Options != nil && len(m.Options.DownloadablePluginCache) > 0 && offline.Check() == nil {
			if err := m.UpdateDownloadablePluginList(); err != nil {
				m.Log("Failed to read the plugin indexes again after a change of the signature settings", err)
			}
		}
		utils.SendOK(w)
		return
	}
	s := m.Settings()
	view := struct {
		ContractMode              string
		RequirePermissionApproval bool
		ContractVersionMin        int
		ContractVersionMax        int
		SDKVersion                string

		VerifyMode           string
		IndexPublicKey       string //the key of the settings (a public key, not a secret)
		IndexKeyFromFlag     bool   //the start flag -plugin_index_pubkey is set and wins over the setting
		IndexKeyFingerprint  string //of the key in use, empty = none or unusable
		IndexKeyProblem      string
		AutoRollback         bool
		MaxDownloadMB        int
		DefaultMaxDownloadMB int
		Sources              []*StoreSource //the plugin indexes and what the last sync found out about their signature

		IsolatePluginUI bool
		PluginUIListen  string
		PluginUIOrigin  string
		UIIsolation     UIIsolationState
	}{
		ContractMode: s.ContractMode, RequirePermissionApproval: s.RequirePermissionApproval,
		ContractVersionMin: ContractVersionMin, ContractVersionMax: ContractVersionMax, SDKVersion: zoraxyPlugin.SDKVersion,
		VerifyMode: s.VerifyMode, IndexPublicKey: s.IndexPublicKey, AutoRollback: s.AutoRollback,
		MaxDownloadMB: s.MaxDownloadMB, DefaultMaxDownloadMB: defaultMaxDownloadMB,
		IsolatePluginUI: s.IsolatePluginUI, PluginUIListen: s.PluginUIListen, PluginUIOrigin: s.PluginUIOrigin,
		UIIsolation: m.uiIsolationState(),
	}
	pk, from, err := m.indexPublicKey()
	view.IndexKeyFromFlag = from == "flag"
	if err != nil {
		view.IndexKeyProblem = err.Error()
	} else if pk != nil {
		view.IndexKeyFingerprint = publicKeyFingerprint(pk)
	}
	if m.Options != nil && m.Options.Database != nil {
		view.Sources = m.ListStoreSources()
	}
	js, _ := json.Marshal(view)
	utils.SendJSONResponse(w, string(js))
}
