package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Hardened security headers preset: admin API (logic in mod/dynamicproxy/hardenedheaders.go)

	  /api/proxy/header/hardened            per site (GET reads, POST saves). Audited as proxy.header.hardened by the
	                                        /api/proxy/ route of mod/secaudit, configuration history sees the saved rule.
	  /api/securityheaders/default          global default for NEW sites (GET reads, POST saves). Off by default.
	                                        Audited as securityheaders.default, hidden from viewer accounts.

	GET with a "settings" parameter (JSON) only previews: nothing is saved.
*/

const hardenedDefaultKey = "hardenedHeadersDefault"

type hardenedView struct {
	Settings *dynamicproxy.HardenedHeaders //nil = never configured
	Defaults *dynamicproxy.HardenedHeaders //what the GUI pre-fills on "turn on"
	HTTPS    []dynamicproxy.HardenedHeaderEntry
	HTTP     []dynamicproxy.HardenedHeaderEntry
}

func hardenedPreviewView(hr *dynamicproxy.HeaderRewriteRules, hh *dynamicproxy.HardenedHeaders) hardenedView {
	v := hardenedView{Settings: hh, Defaults: dynamicproxy.DefaultHardenedHeaders()}
	if hh != nil {
		v.HTTPS = hh.Plan(hr, true)
		v.HTTP = hh.Plan(hr, false)
	}
	return v
}

// parseHardenedSettings reads the JSON "settings" parameter and validates it
func parseHardenedSettings(raw string) (*dynamicproxy.HardenedHeaders, error) {
	hh := &dynamicproxy.HardenedHeaders{}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(hh); err != nil {
		return nil, err
	}
	if err := hh.Validate(); err != nil {
		return nil, err
	}
	return hh, nil
}

// HandleHardenedHeaders reads, previews or saves the preset of one site
func HandleHardenedHeaders(w http.ResponseWriter, r *http.Request) {
	domain, err := utils.PostPara(r, "domain")
	if err != nil {
		domain, err = utils.GetPara(r, "domain")
		if err != nil {
			utils.SendErrorResponse(w, "domain or matching rule not defined")
			return
		}
	}
	target, err := dynamicProxyRouter.LoadProxy(domain)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not exists")
		return
	}
	rules := target.HeaderRewriteRules //read only here; the POST path works on a copy
	if rules == nil {
		rules = dynamicproxy.GetDefaultHeaderRewriteRules()
	}

	switch r.Method {
	case http.MethodGet:
		hh := rules.HardenedHeaders
		if raw, _ := utils.GetPara(r, "settings"); raw != "" { //preview of unsaved values
			parsed, err := parseHardenedSettings(raw)
			if err != nil {
				utils.SendErrorResponse(w, err.Error())
				return
			}
			hh = parsed
		}
		js, _ := json.Marshal(hardenedPreviewView(rules, hh))
		utils.SendJSONResponse(w, string(js))
	case http.MethodPost:
		raw, err := utils.PostPara(r, "settings")
		if err != nil {
			utils.SendErrorResponse(w, "settings not defined")
			return
		}
		hh, err := parseHardenedSettings(raw)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		hr := *rules
		hr.HardenedHeaders = hh
		target.HeaderRewriteRules = &hr
		if err := SaveReverseProxyConfig(target); err != nil {
			utils.SendErrorResponse(w, "save failed: "+err.Error())
			return
		}
		target.UpdateToRuntime()
		utils.SendOK(w)
	default:
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
	}
}

// loadHardenedDefault returns the global default for new sites (nil = off)
func loadHardenedDefault() *dynamicproxy.HardenedHeaders {
	var hh dynamicproxy.HardenedHeaders
	if sysdb == nil || sysdb.Read("settings", hardenedDefaultKey, &hh) != nil || !hh.Enabled {
		return nil
	}
	if hh.Validate() != nil {
		return nil //a damaged value never turns anything on
	}
	return &hh
}

// applyHardenedDefault gives a NEW site the global default. It never touches a site that already has its own choice.
func applyHardenedDefault(ep *dynamicproxy.ProxyEndpoint) {
	hh := loadHardenedDefault()
	if hh == nil || ep == nil {
		return
	}
	if ep.HeaderRewriteRules == nil {
		ep.HeaderRewriteRules = dynamicproxy.GetDefaultHeaderRewriteRules()
	}
	if ep.HeaderRewriteRules.HardenedHeaders == nil {
		ep.HeaderRewriteRules.HardenedHeaders = hh
	}
}

// HandleHardenedHeadersDefault reads or saves the global default for new sites
func HandleHardenedHeadersDefault(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cur := loadHardenedDefault()
		hh := cur
		if raw, _ := utils.GetPara(r, "settings"); raw != "" {
			parsed, err := parseHardenedSettings(raw)
			if err != nil {
				utils.SendErrorResponse(w, err.Error())
				return
			}
			hh = parsed
		}
		js, _ := json.Marshal(hardenedPreviewView(nil, hh))
		utils.SendJSONResponse(w, string(js))
	case http.MethodPost:
		raw, err := utils.PostPara(r, "settings")
		if err != nil {
			utils.SendErrorResponse(w, "settings not defined")
			return
		}
		hh, err := parseHardenedSettings(raw)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		if err := sysdb.Write("settings", hardenedDefaultKey, hh); err != nil {
			utils.SendErrorResponse(w, "save failed: "+err.Error())
			return
		}
		utils.SendOK(w)
	default:
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
	}
}
