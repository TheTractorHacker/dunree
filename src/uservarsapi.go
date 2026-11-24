package main

import (
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
	"imuslab.com/zoraxy/mod/uservars"
)

/*
	uservarsapi.go

	User defined variables (upstream #370), conf/variables.json.

	GET  /api/vars/list     variables, the built-ins and the limits
	POST /api/vars/set      {name, value, description, create}   create:true refuses an existing name
	POST /api/vars/delete   {name}

	A variable is referenced as {{name}} in custom header values, redirect targets, static
	responses and error pages (expanded per request), as an entry of an ip or string list of the
	security rules (resolved when a value changes, at the latest userVarsRefresh later for
	{{external_ip}}) and as an IP entry of an access rule's black / whitelist (read per request).
	Nothing is expanded until a variable is defined and referenced.
*/

// userVarsRefresh is how often the rule lists pick up a changed {{external_ip}}
const userVarsRefresh = 30 * time.Second

var (
	userVarStore *uservars.Store
	userVarOnce  sync.Once
	userVarTick  sync.Once
)

// currentExternalIP is the server's public address, "" when the public IP check is disabled or
// has not answered yet
func currentExternalIP() string {
	if dynamicProxyRouter == nil || dynamicProxyRouter.Option.AccessController == nil {
		return ""
	}
	ip := dynamicProxyRouter.Option.AccessController.PublicIP()
	if ip == "127.0.0.1" {
		return "" //public IP check disabled or not resolved yet
	}
	return ip
}

// getUserVars loads conf/variables.json on first use and connects the consumers
func getUserVars() *uservars.Store {
	userVarOnce.Do(func() {
		s, err := uservars.Open(CONF_FOLDER + "/variables.json")
		if err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("variables", "Problem loading the variables", err)
		}
		s.SetBuiltin("external_ip", currentExternalIP)
		rewrite.SetUserVarProvider(s.LookupUser)
		access.SetVarResolver(s.Lookup)
		s.OnChange(func() { getRulesEngine().RefreshVars() })
		userVarStore = s
	})
	return userVarStore
}

// initUserVars wires the variables at startup and keeps the rule lists that use {{external_ip}}
// current (the public address is re-checked in the background by the access controller)
func initUserVars() {
	getUserVars()
	userVarTick.Do(func() {
		go func() {
			t := time.NewTicker(userVarsRefresh)
			defer t.Stop()
			for range t.C {
				if getRulesEngine().RefreshVars() && SystemWideLogger != nil {
					SystemWideLogger.PrintAndLog("variables", "A variable used by a rule list changed, the rules were updated", nil)
				}
			}
		}()
	})
}

func RegisterUserVarAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/vars/list", HandleUserVarList)
	authRouter.HandleFunc("/api/vars/set", HandleUserVarSet)
	authRouter.HandleFunc("/api/vars/delete", HandleUserVarDelete)
}

// userVarUsage maps a variable name to the rule lists and access rules that reference it.
// Header values, redirect targets and response bodies are not scanned.
func userVarUsage() map[string][]string {
	out := map[string][]string{}
	add := func(name, where string) {
		for _, w := range out[name] {
			if w == where {
				return
			}
		}
		out[name] = append(out[name], where)
	}
	if e := getRulesEngine(); e != nil {
		for _, l := range e.Lists() {
			for _, it := range l.Items {
				if name, ok := uservars.RefName(it); ok {
					add(name, "list $"+l.Name)
				}
			}
		}
	}
	if accessController != nil {
		for _, rule := range accessController.ListAllAccessRules() {
			for _, m := range []*map[string]string{rule.WhiteListIP, rule.BlackListIP} {
				if m == nil {
					continue
				}
				for entry := range *m {
					if name, ok := access.EntryVar(entry); ok {
						add(name, "access rule "+rule.Name)
					}
				}
			}
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

func HandleUserVarList(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) {
		return
	}
	s := getUserVars()
	usage := userVarUsage()
	type varView struct {
		uservars.Variable
		UsedBy []string `json:"used_by"`
	}
	type builtinView struct {
		uservars.Builtin
		UsedBy []string `json:"used_by"`
	}
	vars := []varView{}
	for _, v := range s.List() {
		u := usage[v.Name]
		if u == nil {
			u = []string{}
		}
		vars = append(vars, varView{v, u})
	}
	builtins := []builtinView{}
	for _, b := range s.Builtins() {
		u := usage[b.Name]
		if u == nil {
			u = []string{}
		}
		builtins = append(builtins, builtinView{b, u})
	}
	// a file that could not be read at start is never overwritten silently: the page says so
	loadError, loadBackup := s.LoadProblem()
	rsJSON(w, http.StatusOK, map[string]interface{}{
		"load_error":  loadError,
		"load_backup": loadBackup,
		"variables":   vars,
		"builtins":    builtins,
		// per request built-ins: only meaningful in header values, redirect targets and responses
		"request_builtins": []string{"host", "client_ip", "request_id", "rule_name"},
		"limits": map[string]int{"variables": uservars.MaxVariables, "name": uservars.MaxNameLen,
			"value": uservars.MaxValueLen, "description": uservars.MaxDescLen},
		"refresh_seconds": int(userVarsRefresh / time.Second),
	})
}

func userVarFail(w http.ResponseWriter, err error) {
	var ve uservars.ValidationError
	switch {
	case errors.As(err, &ve):
		rsErr(w, http.StatusBadRequest, ve.Msg)
	case errors.Is(err, uservars.ErrNotFound):
		rsErr(w, http.StatusNotFound, err.Error())
	default:
		rsErr(w, http.StatusInternalServerError, "could not save: "+err.Error())
	}
}

func HandleUserVarSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Value       string `json:"value"`
		Description string `json:"description"`
		Create      bool   `json:"create"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	v, err := getUserVars().Set(uservars.Variable{Name: req.Name, Value: req.Value, Description: req.Description}, req.Create)
	if err != nil {
		userVarFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, v)
}

func HandleUserVarDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	if err := getUserVars().Delete(req.Name); err != nil {
		userVarFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
