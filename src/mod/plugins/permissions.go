package plugins

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dunreePlugin "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	Permission approval (phase 2 of docs/plugins/reliability-plan.md, item 2.6)

	A plugin lists the Dunree API endpoints it wants in its manifest
	(permitted_api_endpoints). Dunree remembers, per plugin ID, which of them the
	administrator has approved, and compares the manifest with that list every
	time the plugin is loaded (boot, install, update, reload).

	Default (log-only): every endpoint of the manifest is granted, as always.
	Endpoints that are not approved are reported once: a log line, an entry in the
	security audit log and a badge in the Plugin Manager.

	Opt-in "require approval" (ManagerSettings.RequirePermissionApproval): only
	approved endpoints are granted. An update that adds an endpoint does not get
	it until the administrator approves it.

	Plugins that are installed when this code runs for the first time are recorded
	as approved with what they ask for at that moment (the "baseline"), so turning
	the option on later does not cut off a plugin that already had its rights.
*/

const (
	permDBTable          = "plugin_permissions"
	permBaselineKey      = "permission_baseline"          //in settingsDBTable: the baseline was taken
	permDeferredKey      = "permission_baseline_deferred" //in settingsDBTable: plugin folders that could not be loaded when the baseline was taken
	permOriginBaseline   = "baseline"                     //approved because the plugin was installed before permissions were tracked
	permOriginAdmin      = "admin"                        //approved (or withdrawn) by the administrator
	maxPermissionEntries = 256                            //more endpoints than Dunree has; a longer list in an approval request is refused
)

// PermissionKey names one API endpoint a plugin may call
type PermissionKey struct {
	Method   string
	Endpoint string
}

func (k PermissionKey) String() string { return k.Method + " " + k.Endpoint }

// permissionRecord is what is stored per plugin ID
type permissionRecord struct {
	Approved  []PermissionKey //endpoints the administrator approved (or the baseline)
	Notified  []PermissionKey //not approved endpoints that were already reported, so a restart of Dunree does not report them again
	Origin    string          //baseline | admin
	UpdatedAt int64
}

// PermissionEntry is one endpoint of a manifest with what Dunree does about it
type PermissionEntry struct {
	Method   string
	Endpoint string
	Reason   string //text of the plugin author, untrusted
	Approved bool   //the administrator approved it (or it is part of the baseline)
	Granted  bool   //a process of the plugin started now may call it
}

// PermissionState is the permission view of one plugin (GET /api/plugins/permissions)
type PermissionState struct {
	ID              string
	RequireApproval bool              //the opt-in setting: only approved endpoints are granted
	Requested       []PermissionEntry //in the order of the manifest, without duplicates
	Pending         int               //requested and not approved
	Withheld        int               //requested and not granted (0 unless RequireApproval)
	Origin          string            //how the approvals came about: baseline | admin | "" (none stored)
	UpdatedAt       int64
}

// PermissionSummary is the part of PermissionState that is in every plugin listing
type PermissionSummary struct {
	Requested       int
	Pending         int  //not approved: new since the last approval, or never reviewed
	Withheld        int  //not granted
	RequireApproval bool //
}

type permState struct {
	mu           sync.Mutex
	cache        map[string]*permissionRecord //plugin ID => record, nil = known to have none
	baselineRead bool
	baselineDone bool
	deferredRead bool
	deferred     map[string]bool //plugin folder names that failed to load when the baseline was taken: baselined on their first successful load
}

func requestedKeys(spec *dunreePlugin.IntroSpect) []PermissionKey {
	if spec == nil {
		return nil
	}
	seen := map[PermissionKey]bool{}
	out := make([]PermissionKey, 0, len(spec.PermittedAPIEndpoints))
	for _, ep := range spec.PermittedAPIEndpoints {
		k := PermissionKey{Method: ep.Method, Endpoint: ep.Endpoint}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

func keySet(keys []PermissionKey) map[PermissionKey]bool {
	set := make(map[PermissionKey]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set
}

func sameKeySet(a, b []PermissionKey) bool {
	as, bs := keySet(a), keySet(b)
	if len(as) != len(bs) {
		return false
	}
	for k := range as {
		if !bs[k] {
			return false
		}
	}
	return true
}

func joinKeys(keys []PermissionKey) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// recordLocked returns the stored record of a plugin ID. Caller holds perm.mu.
func (m *Manager) recordLocked(id string) (permissionRecord, bool) {
	if rec, ok := m.perm.cache[id]; ok {
		if rec == nil {
			return permissionRecord{}, false
		}
		return *rec, true
	}
	if m.perm.cache == nil {
		m.perm.cache = map[string]*permissionRecord{}
	}
	var rec permissionRecord
	if m.hasDB() && m.Options.Database.KeyExists(permDBTable, id) {
		if err := m.Options.Database.Read(permDBTable, id, &rec); err == nil {
			m.perm.cache[id] = &rec
			return rec, true
		}
	}
	m.perm.cache[id] = nil
	return permissionRecord{}, false
}

func (m *Manager) storeRecordLocked(id string, rec permissionRecord) {
	rec.UpdatedAt = time.Now().Unix()
	if m.perm.cache == nil {
		m.perm.cache = map[string]*permissionRecord{}
	}
	m.perm.cache[id] = &rec
	if m.hasDB() {
		m.Options.Database.NewTable(permDBTable)
		if err := m.Options.Database.Write(permDBTable, id, rec); err != nil {
			m.Log("Failed to store the approved API permissions of plugin "+id, err)
		}
	}
}

// forgetPermissions removes what was approved for a plugin ID (uninstall)
func (m *Manager) forgetPermissions(id string) {
	m.perm.mu.Lock()
	defer m.perm.mu.Unlock()
	if m.perm.cache != nil {
		m.perm.cache[id] = nil
	}
	if m.hasDB() {
		m.Options.Database.Delete(permDBTable, id)
	}
}

func (m *Manager) baselineDoneLocked() bool {
	if !m.perm.baselineRead {
		m.perm.baselineRead = true
		if m.hasDB() && m.Options.Database.KeyExists(settingsDBTable, permBaselineKey) {
			m.perm.baselineDone = true
		}
	}
	return m.perm.baselineDone
}

// deferredLocked returns the plugin folders that were there when the baseline was
// taken but could not be loaded then. Caller holds perm.mu.
func (m *Manager) deferredLocked() map[string]bool {
	if !m.perm.deferredRead {
		m.perm.deferredRead = true
		m.perm.deferred = map[string]bool{}
		var names []string
		if m.hasDB() && m.Options.Database.KeyExists(settingsDBTable, permDeferredKey) {
			m.Options.Database.Read(settingsDBTable, permDeferredKey, &names)
		}
		for _, n := range names {
			m.perm.deferred[n] = true
		}
	}
	return m.perm.deferred
}

func (m *Manager) storeDeferredLocked() {
	if !m.hasDB() {
		return
	}
	names := make([]string, 0, len(m.perm.deferred))
	for n := range m.perm.deferred {
		names = append(names, n)
	}
	sort.Strings(names)
	m.Options.Database.NewTable(settingsDBTable)
	m.Options.Database.Write(settingsDBTable, permDeferredKey, names)
}

// pruneDeferredBaseline forgets deferred folders that are gone from the plugin
// directory, so a plugin installed later under the same folder name is new.
func (m *Manager) pruneDeferredBaseline(present map[string]bool) {
	m.perm.mu.Lock()
	defer m.perm.mu.Unlock()
	deferred := m.deferredLocked()
	changed := false
	for n := range deferred {
		if !present[n] {
			delete(deferred, n)
			changed = true
		}
	}
	if changed {
		m.storeDeferredLocked()
	}
}

// markPermissionBaseline ends the baseline: from now on a plugin that Dunree has
// no record of starts with nothing approved. Called once the plugins that were
// installed before permissions were tracked have been loaded. failedFolders are
// the plugin folders that were there but could not be loaded this time (introspect
// timed out, ...): they were installed before permissions were tracked too, so
// they get their baseline when they load for the first time.
func (m *Manager) markPermissionBaseline(failedFolders ...string) {
	m.perm.mu.Lock()
	defer m.perm.mu.Unlock()
	if m.baselineDoneLocked() {
		return
	}
	m.perm.baselineDone = true
	if len(failedFolders) > 0 {
		deferred := m.deferredLocked()
		for _, n := range failedFolders {
			deferred[n] = true
		}
		m.storeDeferredLocked()
	}
	if m.hasDB() {
		m.Options.Database.NewTable(settingsDBTable)
		m.Options.Database.Write(settingsDBTable, permBaselineKey, time.Now().Unix())
	}
}

// reviewPermissions compares the manifest of a plugin with what is approved for
// its ID, and reports endpoints that are not approved (once per change). It never
// changes what is approved, except for two things: the baseline, and dropping
// approvals of endpoints the plugin no longer asks for (so an endpoint that comes
// back in a later version is new again).
//
// It must only be called for a manifest that becomes the loaded one (boot, a new
// plugin found by a reload, an update after the swap), never for a manifest that
// is read from disk and thrown away: the record has to describe the plugin that
// runs. folder is the name of the plugin folder, "" when it is not a first load.
func (m *Manager) reviewPermissions(spec *dunreePlugin.IntroSpect, folder string) {
	if spec == nil || spec.ID == "" {
		return
	}
	requested := requestedKeys(spec)

	m.perm.mu.Lock()
	rec, found := m.recordLocked(spec.ID)
	baseline := !m.baselineDoneLocked()
	if folder != "" && m.deferredLocked()[folder] {
		//First successful load of a folder that failed to load when the baseline was taken
		delete(m.perm.deferred, folder)
		m.storeDeferredLocked()
		baseline = true
	}
	if !found && baseline {
		if len(requested) > 0 {
			m.storeRecordLocked(spec.ID, permissionRecord{Approved: requested, Origin: permOriginBaseline})
		}
		m.perm.mu.Unlock()
		if len(requested) > 0 {
			m.Log("plugin "+spec.ID+": the "+strconv.Itoa(len(requested))+" API permission(s) it asks for were recorded as approved, because it was installed before permissions were tracked", nil)
		}
		return
	}
	if !found && len(requested) == 0 {
		m.perm.mu.Unlock()
		return
	}
	want := keySet(requested)
	kept := make([]PermissionKey, 0, len(rec.Approved))
	for _, k := range rec.Approved {
		if want[k] {
			kept = append(kept, k)
		}
	}
	approved := keySet(kept)
	pending := make([]PermissionKey, 0)
	for _, k := range requested {
		if !approved[k] {
			pending = append(pending, k)
		}
	}
	changed := !found || len(kept) != len(rec.Approved)
	report := false
	if !sameKeySet(pending, rec.Notified) {
		report = len(pending) > 0
		changed = true
	}
	if changed {
		rec.Approved = kept
		rec.Notified = pending
		m.storeRecordLocked(spec.ID, rec)
	}
	m.perm.mu.Unlock()

	if !report {
		return
	}
	require := m.Settings().RequirePermissionApproval
	granted := "yes (approval is not required)"
	text := "plugin " + spec.ID + " asks for " + strconv.Itoa(len(pending)) + " API permission(s) that were not approved: " + clipText(joinKeys(pending), 600)
	if require {
		granted = "no (waiting for approval)"
		text += ". They are not granted until an administrator approves them in the Plugin Manager"
	} else {
		text += ". They are granted (approval is not required); review them in the Plugin Manager"
	}
	m.Log(text, nil)
	m.audit("plugins.permissions.new", spec.ID, map[string]string{
		"plugin":    spec.Name,
		"endpoints": clipText(joinKeys(pending), 1500),
		"count":     strconv.Itoa(len(pending)),
		"granted":   granted,
		"version":   versionToString(spec.VersionMajor, spec.VersionMinor, spec.VersionPatch),
	})
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// audit writes one entry into the security audit log, when one is configured
func (m *Manager) audit(event string, target string, detail map[string]string) {
	if m.Options != nil && m.Options.Audit != nil {
		m.Options.Audit(event, target, detail)
	}
}

// permissionStateOf returns the permission view of a plugin
func (m *Manager) permissionStateOf(p *Plugin) PermissionState {
	spec := p.spec()
	require := m.Settings().RequirePermissionApproval
	st := PermissionState{ID: spec.ID, RequireApproval: require, Requested: []PermissionEntry{}}
	m.perm.mu.Lock()
	rec, found := m.recordLocked(spec.ID)
	m.perm.mu.Unlock()
	if found {
		st.Origin = rec.Origin
		st.UpdatedAt = rec.UpdatedAt
	}
	approved := keySet(rec.Approved)
	seen := map[PermissionKey]bool{}
	for _, ep := range spec.PermittedAPIEndpoints {
		k := PermissionKey{Method: ep.Method, Endpoint: ep.Endpoint}
		if seen[k] {
			continue
		}
		seen[k] = true
		e := PermissionEntry{Method: ep.Method, Endpoint: ep.Endpoint, Reason: ep.Reason, Approved: approved[k]}
		e.Granted = e.Approved || !require
		if !e.Approved {
			st.Pending++
		}
		if !e.Granted {
			st.Withheld++
		}
		st.Requested = append(st.Requested, e)
	}
	return st
}

func (m *Manager) permissionSummaryOf(p *Plugin) PermissionSummary {
	st := m.permissionStateOf(p)
	return PermissionSummary{Requested: len(st.Requested), Pending: st.Pending, Withheld: st.Withheld, RequireApproval: st.RequireApproval}
}

// grantedEndpoints returns the endpoints a process of the plugin may call
func (m *Manager) grantedEndpoints(p *Plugin) []dunreePlugin.PermittedAPIEndpoint {
	spec := p.spec()
	if !m.Settings().RequirePermissionApproval {
		//As always: what the manifest asks for
		return spec.PermittedAPIEndpoints
	}
	m.perm.mu.Lock()
	rec, _ := m.recordLocked(spec.ID)
	m.perm.mu.Unlock()
	approved := keySet(rec.Approved)
	out := make([]dunreePlugin.PermittedAPIEndpoint, 0, len(spec.PermittedAPIEndpoints))
	for _, ep := range spec.PermittedAPIEndpoints {
		if approved[PermissionKey{Method: ep.Method, Endpoint: ep.Endpoint}] {
			out = append(out, ep)
		}
	}
	return out
}

// applyGrantedEndpoints gives the API key of a running plugin exactly what is
// granted now (after an approval, a withdrawal, or a change of the setting)
func (m *Manager) applyGrantedEndpoints(p *Plugin) {
	if m.Options == nil || m.Options.APIKeyManager == nil {
		return
	}
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()
	if !p.IsRunning() {
		return
	}
	m.Options.APIKeyManager.SetPermittedEndpointsForPlugin(p.Spec.ID, m.grantedEndpoints(p))
}

// SetPluginPermissionApproval approves (approve=true) or withdraws the approval
// of endpoints of a plugin. keys == nil means every endpoint the manifest asks
// for. An endpoint the manifest does not ask for is refused. It applies at once,
// also to a running plugin.
func (m *Manager) SetPluginPermissionApproval(pluginID string, approve bool, keys []PermissionKey) error {
	p, err := m.GetPluginByID(pluginID)
	if err != nil {
		return err
	}
	requested := requestedKeys(p.spec())
	want := keySet(requested)
	if keys == nil {
		keys = requested
	}
	for _, k := range keys {
		if !want[k] {
			return errors.New("the plugin does not ask for " + k.String() + " (its manifest may have changed, load the list again)")
		}
	}
	change := keySet(keys)

	m.perm.mu.Lock()
	rec, _ := m.recordLocked(pluginID)
	next := make([]PermissionKey, 0, len(requested))
	approvedBefore := keySet(rec.Approved)
	for _, k := range requested { //manifest order, and nothing the plugin no longer asks for
		keep := approvedBefore[k]
		if change[k] {
			keep = approve
		}
		if keep {
			next = append(next, k)
		}
	}
	nextSet := keySet(next)
	pending := make([]PermissionKey, 0)
	for _, k := range requested {
		if !nextSet[k] {
			pending = append(pending, k)
		}
	}
	rec.Approved = next
	rec.Notified = pending //the administrator has seen them
	rec.Origin = permOriginAdmin
	m.storeRecordLocked(pluginID, rec)
	m.perm.mu.Unlock()

	verb := "approved"
	if !approve {
		verb = "withdrew the approval of"
	}
	m.Log("An administrator "+verb+" "+strconv.Itoa(len(keys))+" API permission(s) of plugin "+pluginID+": "+clipText(joinKeys(keys), 600), nil)
	m.applyGrantedEndpoints(p)
	return nil
}

// HandlePluginPermissions is the admin API of the API permissions of a plugin.
// GET ?plugin_id=<id>: what the plugin asks for, what is approved and what is granted.
// POST plugin_id=<id>, action=approve|revoke, endpoints=<JSON array of {"Method","Endpoint"}>
// (optional, default: every endpoint the plugin asks for).
func (m *Manager) HandlePluginPermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		pluginID, err := utils.GetPara(r, "plugin_id")
		if err != nil {
			utils.SendErrorResponse(w, "plugin_id not found")
			return
		}
		p, err := m.GetPluginByID(pluginID)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		js, _ := json.Marshal(m.permissionStateOf(p))
		utils.SendJSONResponse(w, string(js))
		return
	}
	pluginID, err := utils.PostPara(r, "plugin_id")
	if err != nil {
		utils.SendErrorResponse(w, "plugin_id not found")
		return
	}
	action, _ := utils.PostPara(r, "action")
	if action != "approve" && action != "revoke" {
		utils.SendErrorResponse(w, "action must be approve or revoke")
		return
	}
	var keys []PermissionKey
	if raw, err := utils.PostPara(r, "endpoints"); err == nil && strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &keys); err != nil || len(keys) == 0 || len(keys) > maxPermissionEntries {
			utils.SendErrorResponse(w, "endpoints must be a JSON list of {\"Method\", \"Endpoint\"}")
			return
		}
	}
	if err := m.SetPluginPermissionApproval(pluginID, action == "approve", keys); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
