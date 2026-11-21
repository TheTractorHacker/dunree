package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/baseline"
	"imuslab.com/zoraxy/mod/deployrole"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/secaudit"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	baselineapi.go

	Enterprise baseline: a short list of safe, reversible settings (mod/baseline).
	  Fresh installs get it applied once at their first start (decision stored, never repeated).
	  Existing installs are never changed by an update; Security Center > Overview offers a preview, an Apply
	  button and an Undo.

	  GET  /api/baseline/get     status of every item, the preview of what Apply would change, the stored state
	  POST /api/baseline/apply   apply (source "button")
	  POST /api/baseline/undo    restore the previous values of the items that still hold the baseline value

	Closed for viewer accounts (viewerDeniedPrefixes). Apply and Undo are written to the security audit log
	as baseline.apply (with the source) and baseline.undo.

	What is NEVER in the baseline: the internal peer gate, the admin allow-list, roles, CrowdSec fail-closed or
	enforce mode, rate-limit enforcement, destination allow-lists, the destination guard for diagnostic tools (it
	also refuses loopback backends in the uptime monitor), frame blocking and the Permissions-Policy header
	(they break embedding, cameras, microphones and maps), and per site settings of existing sites. See
	docs/ux/changes.md.
*/

var (
	baselineMgr   *baseline.Manager
	baselineProbe baseline.Probe //captured in main() before anything is created
)

// baselineHSTSAge is 30 days: long enough to matter, short enough to recover from a certificate mistake
const baselineHSTSAge = 2592000

func baselineHeaderTarget() *dynamicproxy.HardenedHeaders {
	hh := &dynamicproxy.HardenedHeaders{
		Enabled: true, HSTS: true, HSTSMaxAge: baselineHSTSAge, NoSniff: true,
		ReferrerPolicy: "strict-origin-when-cross-origin",
		//no FrameProtection, no PermissionsPolicy, no includeSubDomains, no preload
	}
	_ = hh.Validate()
	return hh
}

func jsonRaw(v interface{}) json.RawMessage { b, _ := json.Marshal(v); return b }

/* ---- item: forwarded client address header clean-up ---- */

type baselineHardenItem struct{}

func (baselineHardenItem) Info() baseline.Info {
	return baseline.Info{
		ID:     "harden-headers",
		Title:  "Clean up forwarded client-address headers",
		Why:    "A visitor can write X-Forwarded-For, X-Real-Ip and similar headers themselves. With the clean-up on, those headers are only believed when they come from a proxy listed under Trusted Proxies, so rate limits, bans, GeoIP and logs cannot be fooled by a forged address.",
		Effect: "Does not block anything. If this Zoraxy sits behind a proxy or CDN that is not listed under Trusted Proxies, the client address (and X-Forwarded-Proto/Host) that proxy sends is ignored and sites see the proxy's address instead. List the proxy first. On an existing install the button only applies it when the trusted proxy list is not empty.",
		Page:   "seccenter", Anchor: "deployment",
	}
}
func (baselineHardenItem) Current() (json.RawMessage, error) {
	if deployRoleMgr == nil {
		return nil, fmt.Errorf("deployment settings not loaded")
	}
	return jsonRaw(deployRoleMgr.HardenActive()), nil
}
func (baselineHardenItem) Target() json.RawMessage { return jsonRaw(true) }
func (baselineHardenItem) Eligible(fresh bool) (bool, string) {
	if deployRoleMgr == nil {
		return false, "deployment settings not loaded"
	}
	if deployRoleMgr.Role() != deployrole.RoleStandalone {
		return false, "the deployment role manages this itself"
	}
	if !fresh && (accessController == nil || len(accessController.ListTrustedProxies()) == 0) {
		return false, "no trusted proxy is listed. If a proxy or CDN is in front of this Zoraxy, list it under Trusted Proxies first, otherwise its client addresses would be ignored"
	}
	return true, ""
}
func (baselineHardenItem) Set(v json.RawMessage) error {
	var on bool
	if err := json.Unmarshal(v, &on); err != nil {
		return err
	}
	s := deployRoleMgr.Settings()
	s.HardenHeaders = on
	return deployRoleMgr.Set(s)
}
func (baselineHardenItem) Display(v json.RawMessage) string {
	if string(v) == "true" {
		return "on"
	}
	return "off"
}

/* ---- item: default security headers for NEW sites ---- */

type baselineHeadersItem struct{}

func (baselineHeadersItem) Info() baseline.Info {
	return baseline.Info{
		ID:     "new-site-headers",
		Title:  "Safe security headers for sites created later",
		Why:    "New sites start with X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin and, on HTTPS only, Strict-Transport-Security for 30 days (no includeSubDomains, no preload). Headers the website itself sends are never overwritten.",
		Effect: "Only the default for sites you create afterwards. No existing site is touched. Frame blocking and Permissions-Policy are not included, because they break embedding and camera, microphone or map features. Each site can still turn the preset off or change it.",
		Page:   "seccenter", Anchor: "headers",
	}
}
func (baselineHeadersItem) read() (*dynamicproxy.HardenedHeaders, error) {
	if sysdb == nil {
		return nil, fmt.Errorf("database not open")
	}
	if !sysdb.KeyExists("settings", hardenedDefaultKey) {
		return nil, nil
	}
	var hh dynamicproxy.HardenedHeaders
	if err := sysdb.Read("settings", hardenedDefaultKey, &hh); err != nil {
		return nil, err
	}
	return &hh, nil
}
func (b baselineHeadersItem) Current() (json.RawMessage, error) {
	hh, err := b.read()
	if err != nil {
		return nil, err
	}
	if hh == nil {
		return json.RawMessage("null"), nil
	}
	return jsonRaw(hh), nil
}
func (baselineHeadersItem) Target() json.RawMessage { return jsonRaw(baselineHeaderTarget()) }
func (b baselineHeadersItem) Eligible(fresh bool) (bool, string) {
	hh, err := b.read()
	if err != nil {
		return false, "the current default could not be read"
	}
	if hh != nil { //a stored record, on or off, is the administrator's own choice
		return false, "you already chose your own default for new sites"
	}
	return true, ""
}
func (baselineHeadersItem) Set(v json.RawMessage) error {
	if sysdb == nil {
		return fmt.Errorf("database not open")
	}
	if strings.TrimSpace(string(v)) == "null" {
		if sysdb.KeyExists("settings", hardenedDefaultKey) {
			return sysdb.Delete("settings", hardenedDefaultKey)
		}
		return nil
	}
	var hh dynamicproxy.HardenedHeaders
	if err := json.Unmarshal(v, &hh); err != nil {
		return err
	}
	return sysdb.Write("settings", hardenedDefaultKey, &hh)
}
func (baselineHeadersItem) Display(v json.RawMessage) string {
	var hh *dynamicproxy.HardenedHeaders
	if json.Unmarshal(v, &hh) != nil || hh == nil || !hh.Enabled {
		return "off"
	}
	var p []string
	if hh.NoSniff {
		p = append(p, "nosniff")
	}
	if hh.ReferrerPolicy != "" {
		p = append(p, "Referrer-Policy "+hh.ReferrerPolicy)
	}
	if hh.HSTS {
		p = append(p, fmt.Sprintf("HSTS %d days on HTTPS", hh.HSTSMaxAge/86400))
	}
	if hh.FrameProtection != "" {
		p = append(p, "frame protection "+hh.FrameProtection)
	}
	if hh.PermissionsPolicy {
		p = append(p, "Permissions-Policy")
	}
	return "on: " + strings.Join(p, ", ")
}

/* ---- info items: shown, never changed ---- */

type baselineInfoItem struct {
	info baseline.Info
	cur  func() string
}

func (i baselineInfoItem) Info() baseline.Info               { return i.info }
func (i baselineInfoItem) Current() (json.RawMessage, error) { return jsonRaw(i.cur()), nil }
func (i baselineInfoItem) Target() json.RawMessage           { return nil }
func (i baselineInfoItem) Eligible(bool) (bool, string)      { return false, "shown only" }
func (i baselineInfoItem) Set(json.RawMessage) error {
	return fmt.Errorf("this item is never changed by the baseline")
}
func (i baselineInfoItem) Display(v json.RawMessage) string {
	var s string
	_ = json.Unmarshal(v, &s)
	return s
}

var baselineItemsFn = baselineItems //replaced by tests

func baselineItems() []baseline.Item {
	return []baseline.Item{
		baselineInfoItem{
			info: baseline.Info{
				ID: "audit-log", Title: "Security audit log", Info: true,
				Why:    "Every security-relevant change made through the admin interface or the REST API is written to a tamper-evident log (who, from where, what).",
				Effect: "Always on, there is no switch. Shown here so you can see that it is working.",
				Page:   "seccenter", Anchor: "auditlog",
			},
			cur: func() string {
				if secAudit == nil {
					return "not available (the log file could not be opened)"
				}
				return "recording"
			},
		},
		baselineHardenItem{},
		baselineHeadersItem{},
		baselineInfoItem{
			info: baseline.Info{
				ID: "crowdsec", Title: "CrowdSec", Info: true,
				Why:    "Blocks addresses that the CrowdSec community and your own CrowdSec engine have decided on. It starts in log-only mode, so the first thing you see is what it would block.",
				Effect: "The baseline cannot turn it on: it needs the address of your CrowdSec local API and an API key. Configure it once and the log-only-first behaviour applies by itself.",
				Page:   "seccenter", Anchor: "crowdsec",
			},
			cur: func() string {
				if crowdsecMgr == nil {
					return "not configured"
				}
				s := crowdsecMgr.Settings()
				switch {
				case s.LAPIURL == "":
					return "not configured"
				case !s.Enabled:
					return "configured, switched off"
				case s.Mode == "enforce":
					return "on, enforcing"
				}
				return "on, log only"
			},
		},
	}
}

// initBaseline builds the manager and, once, decides whether this start is a new install. It runs after the
// database, the security audit log, the deployment settings and the access controller exist.
func initBaseline() {
	baselineMgr = baseline.New(sysdb, baselineItemsFn())
	if baselineMgr.Decided() {
		return
	}
	fresh, why := baseline.IsFresh(baselineProbe)
	res, err := baselineMgr.Decide(fresh)
	if err != nil {
		if res == nil { //the decision itself could not be stored
			SystemWideLogger.PrintAndLog("baseline", "Enterprise baseline: could not record the decision", err)
			return
		}
		//the decision is stored, the apply failed and was rolled back: say so in the log and the audit log
		SystemWideLogger.PrintAndLog("baseline", "Enterprise baseline: the first-start apply failed, nothing was changed. Security Center > Overview offers the button.", err)
		recordBaseline("baseline.apply", "system", "", baseline.SourceFresh, res, "error", err.Error())
		return
	}
	if !fresh {
		SystemWideLogger.Println("Enterprise baseline: existing installation (" + why + "), nothing was changed. Security Center > Overview offers it with a preview.")
		return
	}
	if res != nil && res.Changed > 0 {
		msg := fmt.Sprintf("Enterprise baseline applied to this new installation (%d settings). Security Center > Overview shows them and can undo them.", res.Changed)
		warn := ""
		if w := baselineWarnings(); len(w) > 0 {
			warn = w[0]
			msg += " NOTE: " + warn
		}
		SystemWideLogger.Println(msg)
		recordBaseline("baseline.apply", "system", "", baseline.SourceFresh, res, "ok", warn)
	}
}

// baselineWarnings lists conditions the card must show next to the status. The forwarded-header clean-up
// is applied on a new install without a trusted proxy (a directly exposed Zoraxy is the common case), but
// behind a CDN or another proxy it would hide the real visitor address until that proxy is listed.
func baselineWarnings() []string {
	var w []string
	if deployRoleMgr != nil && deployRoleMgr.HardenActive() && (accessController == nil || len(accessController.ListTrustedProxies()) == 0) {
		w = append(w, "The forwarded-header clean-up is on and no trusted proxy is listed. If a proxy or CDN is in front of this Zoraxy, add it under Trusted Proxies now, otherwise every visitor appears with the proxy's address and X-Forwarded-Proto/Host are ignored.")
	}
	return w
}

func recordBaseline(event, actor, ip, source string, res *baseline.Result, outcome string, note ...string) {
	detail := map[string]string{}
	if len(note) > 0 && note[0] != "" {
		if outcome == "ok" {
			detail["warning"] = note[0]
		} else {
			detail["error"] = note[0]
		}
	}
	if source != "" {
		detail["source"] = source
	}
	var parts []string
	if res != nil {
		detail["changed"] = fmt.Sprint(res.Changed)
		for _, c := range res.Changes {
			switch c.Status {
			case "changed", "restored":
				parts = append(parts, c.ID+": "+c.From+" -> "+c.To)
			case "skipped":
				if event == "baseline.undo" {
					parts = append(parts, c.ID+": left as is ("+c.Reason+")")
				}
			}
		}
	}
	if len(parts) > 0 {
		detail["items"] = strings.Join(parts, "; ")
	}
	secAudit.Record(secaudit.Event{Actor: actor, IP: ip, Event: event, Target: "enterprise baseline", Outcome: outcome, Detail: detail})
}

type baselineView struct {
	Available bool                  `json:"available"`
	Items     []baseline.ItemStatus `json:"items"`
	Preview   []baseline.Change     `json:"preview"`
	Pending   int                   `json:"pending"`
	State     baseline.State        `json:"state"`
	CanUndo   bool                  `json:"canUndo"`
	Warnings  []string              `json:"warnings"`
}

func baselineStatus() baselineView {
	v := baselineView{Items: []baseline.ItemStatus{}, Preview: []baseline.Change{}, Warnings: []string{}}
	if baselineMgr == nil {
		return v
	}
	v.Available = true
	v.Items = baselineMgr.Status()
	v.Preview = baselineMgr.Preview(false)
	for _, c := range v.Preview {
		if c.Status == "change" {
			v.Pending++
		}
	}
	v.State = baselineMgr.State()
	v.CanUndo = len(v.State.Items) > 0
	v.Warnings = baselineWarnings()
	return v
}

// RegisterBaselineAPIs registers the three endpoints on the admin router
func RegisterBaselineAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/baseline/get", HandleBaselineGet)
	authRouter.HandleFunc("/api/baseline/apply", HandleBaselineApply)
	authRouter.HandleFunc("/api/baseline/undo", HandleBaselineUndo)
}

func HandleBaselineGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	js, _ := json.Marshal(baselineStatus())
	utils.SendJSONResponse(w, string(js))
}

func baselineClient(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func HandleBaselineApply(w http.ResponseWriter, r *http.Request) {
	baselineChange(w, r, "baseline.apply")
}

func HandleBaselineUndo(w http.ResponseWriter, r *http.Request) {
	baselineChange(w, r, "baseline.undo")
}

func baselineChange(w http.ResponseWriter, r *http.Request, event string) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if baselineMgr == nil {
		utils.SendErrorResponse(w, "the enterprise baseline is not available")
		return
	}
	actor, _ := historyActor(r)
	if actor == "" {
		actor = "unknown"
	}
	ip := baselineClient(r)
	var res *baseline.Result
	var err error
	source := ""
	if event == "baseline.apply" {
		source = baseline.SourceButton
		res, err = baselineMgr.Apply(source)
	} else {
		res, err = baselineMgr.Undo()
	}
	invalidateSecurityOverview()
	if err != nil {
		if res != nil && (res.Changed > 0 || event == "baseline.apply") {
			recordBaseline(event, actor, ip, source, res, "error", err.Error())
		}
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if res.Changed > 0 {
		recordBaseline(event, actor, ip, source, res, "ok")
		SystemWideLogger.PrintAndLog("baseline", fmt.Sprintf("%s by %s: %d settings", event, actor, res.Changed), nil)
	}
	out := map[string]interface{}{"result": res, "status": baselineStatus()}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}
