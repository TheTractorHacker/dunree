// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/foleyit/dunree/mod/auth"
	"github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/utils"
	"github.com/foleyit/dunree/mod/wirecompat"
)

/*
	wirecompatapi.go

	The setting "Also send legacy X-Zoraxy-* headers" (Listeners > Compatibility).

	Dunree is based on Zoraxy. Its response headers, webhook headers and Prometheus metrics have
	Dunree names (X-Dunree-*, dunree_*). While this setting is on, which is the default, the names
	Zoraxy used (X-Zoraxy-*, zoraxy_*) are sent as well, so monitors, webhook receivers, dashboards // legacy-compat
	and alert rules of an existing install keep working. Logic: mod/wirecompat.

	Not covered by the setting, on purpose:
	  - input: X-Zoraxy-* request headers and the /.zoraxy/... paths are always accepted
	  - plugins and cluster peers always get both header names (a plugin built with the Zoraxy // legacy-compat
	    SDK only knows the old ones)

	GET  /api/compat/legacy               {"enabled":true,"default":true,"legacyPathHits":{"/.zoraxy/health":3}}
	POST /api/compat/legacy  enable=bool  change the setting (applies immediately, stored in the database)

	The value is node-local: it is not part of the cluster settings sync.
*/

const legacyEmitKey = "legacyEmit" //table "settings"; no key = the default (on)

// initWireCompat loads the setting. It runs once at startup, before any listener serves.
func initWireCompat() {
	on := true
	if sysdb != nil && sysdb.KeyExists("settings", legacyEmitKey) {
		if err := sysdb.Read("settings", legacyEmitKey, &on); err != nil {
			on = true //unreadable value: keep the behaviour existing monitors rely on
		}
	}
	wirecompat.SetEmitLegacy(on)
	if SystemWideLogger == nil {
		return
	}
	wirecompat.SetLegacyPathLogger(func(path string, hits uint64) {
		SystemWideLogger.PrintAndLog("compat", "A client requested the legacy path "+path+" ("+strconv.FormatUint(hits, 10)+" since start). It is still answered; the Dunree path is "+wirecompat.PathPrefix+path[len(wirecompat.LegacyPathPrefix):]+". This is logged once a day per path", nil)
	})
	if on {
		SystemWideLogger.PrintAndLog("compat", "Legacy names are on: X-Zoraxy-* response and webhook headers and zoraxy_* metrics are sent next to the Dunree names (Listeners > Compatibility)", nil)
	}
}

func RegisterWireCompatAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/compat/legacy", HandleLegacyNames)
}

// HandleLegacyNames reads (GET) or changes (POST enable=true|false) the setting
func HandleLegacyNames(w http.ResponseWriter, r *http.Request) {
	if !isStateChangingRequest(r) {
		if r.URL.Query().Has("enable") {
			//A value in the query string of a GET must not change the setting (no CSRF token, viewer accounts)
			http.Error(w, "405 - Method not allowed, use POST to change this setting", http.StatusMethodNotAllowed)
			return
		}
		js, _ := json.Marshal(map[string]interface{}{
			"enabled":        wirecompat.EmitLegacy(),
			"default":        true,
			"legacyPathHits": wirecompat.LegacyPathHits(),
		})
		utils.SendJSONResponse(w, string(js))
		return
	}
	enable, err := utils.PostBool(r, "enable")
	if err != nil {
		utils.SendErrorResponse(w, "enable (true or false) is required")
		return
	}
	if sysdb != nil {
		if err := sysdb.Write("settings", legacyEmitKey, enable); err != nil {
			utils.SendErrorResponse(w, "Unable to save the setting: "+err.Error())
			return
		}
	}
	wirecompat.SetEmitLegacy(enable)
	if SystemWideLogger != nil {
		state := "off: only the Dunree names are sent"
		if enable {
			state = "on: the Zoraxy names are sent next to the Dunree names" // legacy-compat
		}
		SystemWideLogger.PrintAndLog("compat", "Legacy names switched "+state, nil)
	}
	utils.SendOK(w)
}

// zoraxyBaseVersion is the Zoraxy release Dunree is based on. Plugins built with the Zoraxy SDK // legacy-compat
// read it as runtime_const.zoraxy_version: it must stay a Zoraxy version number (a plugin that // legacy-compat
// checks for "3.x or newer" would otherwise refuse to run), whatever version Dunree itself has.
const zoraxyBaseVersion = "3.3.6" // legacy-compat

// pluginRuntimeConst is what plugins are told about this host (runtime_const of the configure
// payload). The plugin manager sends the dunree_* fields only to plugins built for Dunree and the
// zoraxy_* fields to every plugin (mod/plugins/wire.go).
func pluginRuntimeConst() *dunree_plugin.RuntimeConstantValue {
	return &dunree_plugin.RuntimeConstantValue{
		DunreeVersion:    SYSTEM_VERSION,
		DunreeUUID:       nodeUUID,
		ZoraxyVersion:    zoraxyBaseVersion, // legacy-compat
		ZoraxyUUID:       nodeUUID,          // legacy-compat
		DevelopmentBuild: *development_build,
	}
}
