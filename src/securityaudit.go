package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"imuslab.com/zoraxy/mod/apitoken"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/secaudit"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	securityaudit.go

	Security audit log (conf/security_audit.log), logic in mod/secaudit.
	  GET /api/security/audit/list    paginated entries, newest first. event (exact or "prefix*"), actor, before (cursor), limit
	  GET /api/security/audit/verify  checks the hash chain of the kept files

	Recording is one middleware in front of the admin API (and one in front of the REST API v1), the
	same place the change history hooks in; the events and what is never logged are in mod/secaudit.
	The log is admin only (see viewerDeniedPrefixes) and is not part of configuration exports or imports.
*/

// securityAuditFile is kept out of exports and survives a configuration import
const securityAuditFile = "security_audit.log"

var secAudit *secaudit.Logger

func initSecurityAudit() {
	l, err := secaudit.New(secaudit.Options{
		Path: filepath.Join(CONF_FOLDER, securityAuditFile),
		Logf: func(format string, a ...any) {
			if SystemWideLogger != nil {
				SystemWideLogger.Println("[secaudit] " + fmt.Sprintf(format, a...))
			}
		},
	})
	if err != nil {
		//Auditing must never keep the proxy from starting, but the person has to know
		if SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("secaudit", "Security audit log is unavailable", err)
		}
		return
	}
	secAudit = l
}

// secAuditWrap records security relevant changes made through the admin API.
func secAuditWrap(next http.Handler) http.Handler {
	return secAudit.Middleware(func(r *http.Request) (string, bool) { return historyActor(r) })(next)
}

// secAuditWrapV1 records the same for the token authenticated REST API.
func secAuditWrapV1(next http.Handler) http.Handler {
	return secAudit.Middleware(func(r *http.Request) (string, bool) {
		name := apitoken.TokenName(r)
		if name == "" || name == "-" {
			return "", false
		}
		return "token " + name, true
	})(next)
}

// RegisterSecurityAuditAPIs registers the viewer endpoints (admin session + CSRF like all others).
func RegisterSecurityAuditAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/security/audit/list", HandleSecurityAuditList)
	authRouter.HandleFunc("/api/security/audit/verify", HandleSecurityAuditVerify)
}

func HandleSecurityAuditList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := secaudit.Query{Event: r.URL.Query().Get("event"), Actor: r.URL.Query().Get("actor")}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			utils.SendErrorResponse(w, "invalid limit")
			return
		}
		q.Limit = n
	}
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			utils.SendErrorResponse(w, "invalid cursor")
			return
		}
		q.Before = n
	}
	page, err := secAudit.List(q)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	js, _ := json.Marshal(map[string]any{
		"available": secAudit != nil, "entries": page.Entries, "next": page.Next, "stats": page.Stats,
		"neverLogged": secaudit.NeverLogFields(),
	})
	utils.SendJSONResponse(w, string(js))
}

func HandleSecurityAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	js, _ := json.Marshal(secAudit.Verify())
	utils.SendJSONResponse(w, string(js))
}
