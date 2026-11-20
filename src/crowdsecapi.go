package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/crowdsec"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	crowdsecapi.go

	CrowdSec bouncer (mod/crowdsec, docs/guides/crowdsec.md). Settings live in sys.db (settings/crowdsec); the
	bouncer API key lives sealed in conf/crowdsec/ and is never returned by any endpoint: the API only says whether
	one is set. Off until enabled; the first mode is "log only".

	GET  /api/crowdsec/get        settings, key set indicator
	POST /api/crowdsec/set        config (JSON), apikey (optional, empty keeps), clearkey, confirmfailclosed
	POST /api/crowdsec/test       one authenticated call to the LAPI (config + apikey optional: test unsaved values)
	GET  /api/crowdsec/status     health
	GET  /api/crowdsec/decisions  recent decisions and matches (bounded)
	All are closed for viewer accounts (internal addresses, decisions) and recorded by the security audit log (set, test).
*/

var crowdsecMgr *crowdsec.Manager

// initCrowdSec loads the settings and starts the pull loop (it does nothing until the feature is enabled)
func initCrowdSec() {
	if crowdsecMgr != nil {
		return //the router is rebuilt on some settings changes; the manager (cache, counters) is kept
	}
	m, err := crowdsec.New(sysdb, crowdsec.NewVault(CONF_FOLDER+"/"+crowdsec.DirName))
	if err != nil {
		SystemWideLogger.PrintAndLog("crowdsec", "CrowdSec", err)
	}
	m.Log = func(msg string) { SystemWideLogger.PrintAndLog("crowdsec", msg, nil) }
	m.Protect = func(a netip.Addr) bool {
		if accessController == nil {
			return false
		}
		return a.String() == accessController.ServerPublicIP || accessController.IsTrustedProxy(a.String())
	}
	crowdsecMgr = m
	m.Start()
}

func stopCrowdSec() {
	if crowdsecMgr != nil {
		crowdsecMgr.Stop()
	}
}

type crowdsecView struct {
	crowdsec.Settings
	KeySet bool `json:"keySet"`
}

// HandleCrowdSecGet returns the settings and whether a key is set (never the key)
func HandleCrowdSecGet(w http.ResponseWriter, r *http.Request) {
	v := crowdsecView{Settings: crowdsecMgr.Settings(), KeySet: crowdsecMgr.KeySet()}
	if v.Settings.ExemptSites == nil {
		v.Settings.ExemptSites = []string{}
	}
	if v.Settings.PinsSHA256 == nil {
		v.Settings.PinsSHA256 = []string{}
	}
	js, _ := json.Marshal(v)
	utils.SendJSONResponse(w, string(js))
}

func parseCrowdSecConfig(raw string) (crowdsec.Settings, error) {
	var s crowdsec.Settings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	return s, nil
}

// HandleCrowdSecSet (POST) replaces the settings
func HandleCrowdSecSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	next, err := parseCrowdSecConfig(raw)
	if err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	key, _ := utils.PostPara(r, "apikey")
	clear, _ := utils.PostPara(r, "clearkey")
	confirm, _ := utils.PostPara(r, "confirmfailclosed")
	old := crowdsecMgr.Settings()
	if err := crowdsecMgr.Set(crowdsec.SetInput{Settings: next, APIKey: strings.TrimSpace(key), ClearKey: clear == "true",
		ConfirmFailClosed: confirm == "true"}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	actor, _ := historyActor(r)
	cur := crowdsecMgr.Settings()
	note := ""
	if key != "" {
		note += ", API key replaced"
	}
	if clear == "true" {
		note += ", API key removed"
	}
	SystemWideLogger.PrintAndLog("crowdsec", "CrowdSec settings changed by "+actor+": "+boolWord(old.Enabled)+" -> "+boolWord(cur.Enabled)+
		", mode "+old.Mode+" -> "+cur.Mode+", fail-closed "+boolWord(old.FailClosed)+" -> "+boolWord(cur.FailClosed)+note, nil)
	utils.SendOK(w)
}

// HandleCrowdSecTest (POST) makes one authenticated call to the LAPI. The destination is checked first
// (metadata, link-local and similar addresses are refused, loopback and private ranges are allowed).
func HandleCrowdSecTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cfg *crowdsec.Settings
	if raw, err := utils.PostPara(r, "config"); err == nil && strings.TrimSpace(raw) != "" {
		s, err := parseCrowdSecConfig(raw)
		if err != nil {
			utils.SendErrorResponse(w, "invalid config JSON")
			return
		}
		cfg = &s
	}
	key, _ := utils.PostPara(r, "apikey")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	js, _ := json.Marshal(crowdsecMgr.Test(ctx, cfg, key))
	utils.SendJSONResponse(w, string(js))
}

// HandleCrowdSecStatus returns the health summary
func HandleCrowdSecStatus(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(crowdsecMgr.Status())
	utils.SendJSONResponse(w, string(js))
}

// HandleCrowdSecDecisions returns the recent decisions and matches (at most 100 each; ?limit= lowers it)
func HandleCrowdSecDecisions(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v, err := utils.GetPara(r, "limit"); err == nil {
		limit, _ = strconv.Atoi(v)
	}
	recent, matches := crowdsecMgr.Decisions(limit)
	js, _ := json.Marshal(map[string]interface{}{"decisions": recent, "matches": matches})
	utils.SendJSONResponse(w, string(js))
}
