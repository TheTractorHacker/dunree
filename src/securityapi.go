package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/foleyit/dunree/mod/auth"
	"github.com/foleyit/dunree/mod/botrules"
	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	securityapi.go

	Admin APIs of the optional security features:
	  GET  /api/botrules/get                   active bot rule config + available categories / good bots
	  POST /api/botrules/set                   config (JSON)
	  POST /api/botrules/endpoint              ep, policy ("", "on", "off")
	  POST /api/botrules/allowua               ep, op ("add"|"remove"), pattern: the per-site User-Agent allow list (ProxyEndpoint.BotAllowUA)
	  GET  /api/headerrules/get?ep=<rule>      header rules of a proxy rule
	  POST /api/headerrules/set                ep, rules (JSON array of HeaderRule)
	       optional: mode (all | any), except (JSON array of addresses / CIDRs that skip the check); left out = kept
	  GET  /api/headerrules/get?ep=..&meta=true  {Mode, Except, Rules} instead of the plain list
*/

var (
	botEngine     *botrules.Engine
	botEngineOnce sync.Once
)

func getBotEngine() *botrules.Engine {
	botEngineOnce.Do(func() {
		e := botrules.New(CONF_FOLDER + "/botrules.json")
		if err := e.Load(); err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("botrules", "Unable to load bot rules, starting disabled", err)
		}
		botEngine = e
	})
	return botEngine
}

func RegisterSecurityAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/botrules/get", HandleBotRulesGet)
	authRouter.HandleFunc("/api/botrules/set", HandleBotRulesSet)
	authRouter.HandleFunc("/api/botrules/endpoint", HandleBotRulesEndpoint)
	authRouter.HandleFunc("/api/botrules/allowua", HandleBotAllowUA)
	authRouter.HandleFunc("/api/headerrules/get", HandleHeaderRulesGet)
	authRouter.HandleFunc("/api/headerrules/set", HandleHeaderRulesSet)
}

func HandleBotRulesGet(w http.ResponseWriter, r *http.Request) {
	type catInfo struct {
		ID, Title string
		Count     int
	}
	cats := []catInfo{}
	for _, c := range botrules.Categories() {
		cats = append(cats, catInfo{c.ID, c.Title, len(c.Items)})
	}
	bots := []string{}
	for _, g := range botrules.GoodBots() {
		bots = append(bots, g.Name)
	}
	cfg := getBotEngine().Config()
	if cfg.Categories == nil {
		cfg.Categories = botrules.DefaultConfig().Categories
	}
	//Per proxy rule policy
	policies := map[string]string{}
	captchaSites := 0 //sites with a working CAPTCHA: a Challenge action only challenges there, everywhere else it blocks
	if dynamicProxyRouter != nil {
		for name, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
			policies[name] = ep.BotPolicy
			if ep.EffectiveCaptchaConfig() != nil && ep.EffectiveCaptchaConfig().IsConfigured() {
				captchaSites++
			}
		}
	}
	js, _ := json.Marshal(map[string]interface{}{"Config": cfg, "Categories": cats, "GoodBots": bots, "Policies": policies, "CaptchaSites": captchaSites})
	utils.SendJSONResponse(w, string(js))
}

func HandleBotRulesSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	cfg := botrules.DefaultConfig()
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	if err := getBotEngine().SetConfig(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleBotRulesEndpoint(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	policy, _ := utils.PostPara(r, "policy")
	if policy != "" && policy != "on" && policy != "off" {
		utils.SendErrorResponse(w, "policy must be empty, on or off")
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		e.BotPolicy = policy
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleBotAllowUA edits the per-site User-Agent allow list (the site editor lists it with remove buttons)
func HandleBotAllowUA(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	if blockViewer(r) {
		http.Error(w, "403 - Read-only account (viewer role)", http.StatusForbidden)
		return
	}
	op, _ := utils.PostPara(r, "op")
	pattern, _ := utils.PostPara(r, "pattern")
	var err error
	switch op {
	case "add":
		var norm string
		if norm, err = botrules.NormalizeAllowUA(pattern); err != nil {
			break
		}
		err = mutateBotAllowUA(ep, func(list []string) ([]string, error) {
			for _, h := range list {
				if h == norm {
					return list, nil
				}
			}
			if len(list) >= botrules.MaxAllowUAs {
				return nil, fmt.Errorf("too many allowed User-Agents (max %d)", botrules.MaxAllowUAs)
			}
			return append(list, norm), nil
		})
	case "remove":
		want := strings.ToLower(strings.TrimSpace(pattern))
		err = mutateBotAllowUA(ep, func(list []string) ([]string, error) {
			out := make([]string, 0, len(list))
			for _, h := range list {
				if h != want {
					out = append(out, h)
				}
			}
			if len(out) == len(list) {
				return nil, errors.New("this User-Agent is not on the list (it may have been removed already)")
			}
			if len(out) == 0 {
				return nil, nil
			}
			return out, nil
		})
	default:
		err = errors.New("op must be add or remove")
	}
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleHeaderRulesGet(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	target, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	rules := target.HeaderRules
	if rules == nil {
		rules = []*dynamicproxy.HeaderRule{}
	}
	//Values of "equals" rules are secrets: the admin UI shows their count, never the stored text
	masked := make([]*dynamicproxy.HeaderRule, 0, len(rules))
	for _, hr := range rules {
		c := *hr
		if c.Match == "" || c.Match == dynamicproxy.HeaderMatchEquals {
			c.Values = make([]string, len(hr.Values))
			for i := range c.Values {
				c.Values[i] = ""
			}
		}
		masked = append(masked, &c)
	}
	//meta=true: the rules together with the rule set options. Without it the answer stays the plain list.
	if meta, _ := utils.GetPara(r, "meta"); meta == "true" {
		except := target.HeaderRulesExcept
		if except == nil {
			except = []string{}
		}
		mode := target.HeaderRulesMode
		if mode == "" {
			mode = dynamicproxy.HeaderRulesModeAll
		}
		out := map[string]interface{}{"Mode": mode, "Except": except, "Rules": masked}
		//A hand-edited config can hold a rule set the proxy refuses to run (the site then answers 503): name the reason.
		//The message never carries a secret: it names the rule number, a pattern, a mode or an address.
		if err := dynamicproxy.ValidateHeaderRuleSet(rules, target.HeaderRulesMode, target.HeaderRulesExcept); err != nil && len(rules) > 0 {
			out["Invalid"] = err.Error()
		}
		js, _ := json.Marshal(out)
		utils.SendJSONResponse(w, string(js))
		return
	}
	js, _ := json.Marshal(masked)
	utils.SendJSONResponse(w, string(js))
}

// HandleHeaderRulesSet replaces the header rules. For "equals" rules an empty value in an
// existing slot keeps the stored secret (the GET API never returns secrets), so the UI can
// edit other fields without re-entering them.
func HandleHeaderRulesSet(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	raw, err := utils.PostPara(r, "rules")
	if err != nil {
		utils.SendErrorResponse(w, "rules missing")
		return
	}
	var rules []*dynamicproxy.HeaderRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		utils.SendErrorResponse(w, "rules must be a JSON array")
		return
	}
	//Optional rule set options; a request without them keeps what is stored
	mode, modeErr := utils.PostPara(r, "mode")
	var except []string
	exceptRaw, exceptErr := utils.PostPara(r, "except")
	if exceptErr == nil {
		if err := json.Unmarshal([]byte(exceptRaw), &except); err != nil {
			utils.SendErrorResponse(w, "except must be a JSON array of addresses")
			return
		}
		kept := except[:0]
		for _, e := range except {
			if e = strings.TrimSpace(e); e != "" {
				kept = append(kept, e)
			}
		}
		except = kept
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		for i, nr := range rules {
			if nr == nil || (nr.Match != "" && nr.Match != dynamicproxy.HeaderMatchEquals) {
				continue
			}
			if i < len(e.HeaderRules) && e.HeaderRules[i] != nil {
				old := e.HeaderRules[i]
				if len(nr.Values) == len(old.Values) {
					for j := range nr.Values {
						if nr.Values[j] == "" {
							nr.Values[j] = old.Values[j]
						}
					}
				}
			}
		}
		newMode, newExcept := e.HeaderRulesMode, e.HeaderRulesExcept
		if modeErr == nil {
			newMode = mode
		}
		if exceptErr == nil {
			newExcept = except
		}
		if len(rules) == 0 {
			//The options belong to the rules: without rules nothing is checked, and a mode or exception list left
			//behind would silently apply to the rules a later client adds without knowing about it
			newMode, newExcept = "", nil
		}
		if err := dynamicproxy.ValidateHeaderRuleSet(rules, newMode, newExcept); err != nil {
			return err
		}
		if newMode == dynamicproxy.HeaderRulesModeAll {
			newMode = "" //the default is not written to the config file
		}
		if len(newExcept) == 0 {
			newExcept = nil
		}
		e.HeaderRules, e.HeaderRulesMode, e.HeaderRulesExcept = rules, newMode, newExcept
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
