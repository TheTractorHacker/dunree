package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TheTractorHacker/dunree/mod/auth"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
	"github.com/TheTractorHacker/dunree/mod/notify"
	"github.com/TheTractorHacker/dunree/mod/utils"
)

/*
	authauditapi.go

	Authentication audit (upstream #1109 follow-up), logic in mod/dynamicproxy/authaudit.go
	  GET  /api/authaudit/get            rows (effective provider + weaknesses per proxy rule), lint setting and violations
	  POST /api/authaudit/autotag        optional ep (one rule, unknown = error); replaces the auth:* tags by auth:<provider>; returns Changed, with ep also Tag
	  POST /api/authaudit/setRequire     enable (bool): lint "every rule must have authentication" (report only)
	  POST /api/authaudit/setAutoTag     enable (bool): refresh the auth:* tag when a rule is saved with an explicit login (off by default)

	The lint never blocks or changes a rule, it only lists the offenders.

	Tag drift (issue #216): a rule whose auth:* tag does not name its effective login is listed in "Drift" and
	announced once as the opt-in notify event auth.drift (checkAuthDrift, every minute and on every get).
	Nothing is corrected automatically; /api/authaudit/autotag with ep fixes the tag of one rule.
*/

func RegisterAuthAuditAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/authaudit/get", HandleAuthAuditGet)
	authRouter.HandleFunc("/api/authaudit/autotag", HandleAuthAuditAutoTag)
	authRouter.HandleFunc("/api/authaudit/setRequire", HandleAuthAuditSetRequire)
	authRouter.HandleFunc("/api/authaudit/setAutoTag", HandleAuthAuditSetAutoTag)
}

const (
	authAuditAutoTagKey   = "authAuditAutoTag"
	authDriftAnnouncedKey = "authDriftAnnounced"
	authDriftCheckEvery   = time.Minute
)

// authAuditAutoTag is the opt-in "keep the auth:* tag in step with the login" setting
func authAuditAutoTag() bool {
	v := false
	if sysdb != nil {
		sysdb.Read("settings", authAuditAutoTagKey, &v)
	}
	return v
}

// autoTagAuthOnSave refreshes the auth:* tag of an endpoint that is about to be saved with a login the caller
// chose explicitly (new rule, or an edit that carries the auth provider). No-op unless the setting is on.
// An edit that does not carry the provider must not call it: there the tag keeps recording the intended login.
func autoTagAuthOnSave(ep *dynamicproxy.ProxyEndpoint) {
	if ep == nil || ep.ProxyType == dynamicproxy.ProxyTypeRoot || !authAuditAutoTag() {
		return
	}
	ep.Tags = dynamicproxy.RetagAuth(ep.Tags, dynamicproxy.AuditAuth(ep).WantedTag)
}

var authDriftMu sync.Mutex

// checkAuthDrift returns the rules whose auth:* tag does not match their effective login and emits auth.drift
// for each one that was not announced in this state yet. The announced states are kept in the system database,
// so a restart does not repeat them; a rule is announced again when its tags or login change into another
// drifting state, or after the drift was cleared and came back. A state only counts as announced when a
// destination that lists auth.drift was there to receive it: drift found while nobody subscribed (an upgrade,
// a page load before the event was ticked) is sent once a destination subscribes, and without a subscriber
// nothing is written to the database.
func checkAuthDrift(rows []dynamicproxy.AuthAuditRow) []string {
	drifting := []string{}
	current := map[string]string{}
	for _, row := range rows {
		if row.TagDrift {
			drifting = append(drifting, row.Name)
			current[row.Name] = strings.Join(row.AuthTags, ",") + "|" + row.Method
		}
	}
	if sysdb == nil {
		return drifting
	}
	authDriftMu.Lock()
	defer authDriftMu.Unlock()
	announced := map[string]string{}
	sysdb.Read("settings", authDriftAnnouncedKey, &announced)
	subscribed := notifyManager != nil && notifyManager.Subscribed(notify.EventAuthDrift)
	next := map[string]string{}
	changed := false
	for _, row := range rows {
		sig, ok := current[row.Name]
		if !ok {
			continue
		}
		if announced[row.Name] == sig {
			next[row.Name] = sig
			continue
		}
		if !subscribed {
			continue // not announced: it is sent when a destination subscribes
		}
		changed = true
		next[row.Name] = sig
		notifyManager.Emit(notify.Event{Event: notify.EventAuthDrift, Source: "security", Subject: row.Name,
			Extra: map[string]string{"tagged": strings.Join(row.AuthTags, ", "), "method": row.Method, "wanted": row.WantedTag}})
	}
	// a state that is gone or was replaced is forgotten, so the same drift is news when it comes back
	if changed || len(next) != len(announced) {
		sysdb.Write("settings", authDriftAnnouncedKey, next)
	}
	return drifting
}

// watchAuthDrift looks for tag drift once a minute, whichever way a rule was changed (editor, import, restore,
// cluster sync, a file edited by hand and reloaded)
func watchAuthDrift() {
	for {
		time.Sleep(authDriftCheckEvery)
		if dynamicProxyRouter == nil || sysdb == nil {
			continue
		}
		checkAuthDrift(dynamicProxyRouter.AuditAllAuth())
	}
}

func authAuditRequireAll() bool {
	v := false
	if sysdb != nil {
		sysdb.Read("settings", "authAuditRequireAll", &v)
	}
	return v
}

func HandleAuthAuditGet(w http.ResponseWriter, r *http.Request) {
	rows := dynamicProxyRouter.AuditAllAuth()
	require := authAuditRequireAll()
	violations := []string{}
	for _, row := range rows {
		if !row.Disabled && row.Method == "none" {
			violations = append(violations, row.Name)
		}
	}
	if !require {
		violations = []string{}
	}
	js, _ := json.Marshal(map[string]interface{}{"Rows": rows, "RequireAll": require, "Violations": violations,
		"AutoTag": authAuditAutoTag(), "Drift": checkAuthDrift(rows)})
	utils.SendJSONResponse(w, string(js))
}

func HandleAuthAuditAutoTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	only, _ := utils.PostPara(r, "ep")
	changed, found, tag := 0, false, ""
	for _, row := range dynamicProxyRouter.AuditAllAuth() {
		if only != "" && row.Name != only {
			continue
		}
		found, tag = true, row.WantedTag
		want := dynamicproxy.RetagAuth(row.Tags, row.WantedTag)
		if equalStrings(want, row.Tags) {
			continue
		}
		if err := applyNetworkingChange(row.Name, func(e *dynamicproxy.ProxyEndpoint) error {
			e.Tags = dynamicproxy.RetagAuth(e.Tags, row.WantedTag)
			return nil
		}); err != nil {
			utils.SendErrorResponse(w, row.Name+": "+err.Error())
			return
		}
		changed++
	}
	if only != "" && !found {
		utils.SendErrorResponse(w, "proxy rule not found: "+only)
		return
	}
	out := map[string]interface{}{"Changed": changed}
	if only != "" {
		out["Tag"] = tag // the tag the rule carries now (what the caller saw may be out of date)
	}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}

func HandleAuthAuditSetRequire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	enable, err := utils.PostBool(r, "enable")
	if err != nil {
		utils.SendErrorResponse(w, "enable missing")
		return
	}
	if err := sysdb.Write("settings", "authAuditRequireAll", enable); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleAuthAuditSetAutoTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	enable, err := utils.PostBool(r, "enable")
	if err != nil {
		utils.SendErrorResponse(w, "enable missing")
		return
	}
	if err := sysdb.Write("settings", authAuditAutoTagKey, enable); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
