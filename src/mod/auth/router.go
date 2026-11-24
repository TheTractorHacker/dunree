package auth

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type RouterOption struct {
	AuthAgent     *AuthAgent
	RequireAuth   bool                                     //This router require authentication
	DeniedHandler func(http.ResponseWriter, *http.Request) //Things to do when request is rejected
	TargetMux     *http.ServeMux
}

type RouterDef struct {
	option    RouterOption
	endpoints map[string]func(http.ResponseWriter, *http.Request)
}

func NewManagedHTTPRouter(option RouterOption) *RouterDef {
	return &RouterDef{
		option:    option,
		endpoints: map[string]func(http.ResponseWriter, *http.Request){},
	}
}

/*
Viewer role enforcement.

A "viewer" account is read-only: every method other than GET / HEAD / OPTIONS is refused,
except the POST endpoints below that only read data. A few GET endpoints expose secrets or
a shell-like capability and are admin-only as well. The allow-list is explicit: anything new
is refused for viewers until it is added here on purpose.
*/
var viewerReadOnlyPOST = map[string]bool{}

var viewerDeniedPrefixes = []string{
	"/api/conf/export",       //configuration archive (full mode includes secrets)
	"/api/conf/import",       //configuration import and its dry run (importcheck)
	"/api/info/pprof",        //heap / goroutine dumps
	"/api/system/dbusage",    //database file path and table sizes
	"/api/users/",            //account management
	"/api/history/",          //configuration history (diffs, restore)
	"/api/security/audit/",   //security audit log (actors, addresses, what changed)
	"/api/deployrole/get",    //deployment role, trusted proxy count, direct CIDRs, peer gate counters
	"/api/destguard/get",     //allowed backend destinations and the rules that would be refused (internal topology)
	"/api/adminallow/get",    //admin allow-list, the caller's address and the admin listen address
	"/api/abuse/config",      //auto-ban settings
	"/api/securityheaders/",  //default hardened header preset for new sites
	"/api/crowdsec/",         //CrowdSec LAPI address, health and the decided client addresses
	"/api/security/overview", //dashboard: listener addresses, host names, client addresses, audit events
	"/api/baseline/",         //enterprise baseline: preview, apply and undo change security settings
	"/api/netplan/",          //network plan (VLAN networks, admin access) and the firewall recommendations
	"/api/cert/download",     //certificate archive, includes the TLS private key
	"/api/ech/export",        //ECH private key
	"/api/ech/fallbacks",     //names probed by clients and scanners
	"/api/zrok/logs",         //zrok tunnel output (share tokens, URLs)
	"/api/proxy/script/",     //Lua script source (may hold secrets); editing is admin only
	"/web.ssh/",              //terminal
	"/plugin.ui/",            //plugin UIs can mutate
}

/*
Outbound probing tools: each of these makes the proxy host open connections (TCP, TLS, HTTP,
ICMP, DNS, whois) to a destination chosen by the caller and reports what answered, so they can
be used to map the internal network or reach a cloud metadata service. Admin only, for every
method. Matched exactly (not as a prefix) so that neighbours such as /api/tools/dnsresponder
and /api/tools/netcalc stay readable.
*/
var viewerDeniedExact = map[string]bool{
	"/api/proxy/testupstream":   true, //TCP dial + TLS handshake + HTTP GET to any host:port
	"/api/tools/httptest":       true, //HTTP request to any URL (allowmetadata lifts the metadata guard)
	"/api/tools/tlsinspect":     true, //TLS handshake to any host:port (allowmetadata as above)
	"/api/tools/portscan":       true, //port scan of any address
	"/api/tools/ipscan":         true, //host discovery over a range
	"/api/tools/ping":           true,
	"/api/tools/traceroute":     true,
	"/api/tools/dns":            true, //lookup through any resolver
	"/api/tools/whois":          true,
	"/api/sso/OAuth2/discovery": true, //HTTP GET to any issuer / well-known URL taken from the query string
}

/*
Endpoints that change state without reading any form field (or that read their input from
the URL query string). GET / HEAD / OPTIONS / TRACE are refused for them: those methods are
not covered by the CSRF token check and are open to viewer accounts. Handlers that take
their input through utils.PostPara / PostBool / PostInt are protected by those helpers
already and do not need to be listed here.
*/
var writeOnlyEndpoints = map[string]bool{
	"/api/trustedproxy/reset":      true, //replace the trusted proxy list with the defaults
	"/api/acme/autoRenew/renewNow": true, //run the certificate renewal now
	"/api/acme/autoRenew/setEAB":   true, //store ACME external account binding credentials
	"/api/cert/selfsign":           true, //generate (and overwrite) a self-signed certificate
	"/api/webserv/start":           true, //static web server
	"/api/webserv/stop":            true,
	"/api/webserv/webdav/start":    true, //WebDAV server
	"/api/webserv/webdav/stop":     true,
	"/api/log/rotate/trigger":      true, //force a log rotation
}

// WriteMethodRequired reports whether the endpoint only accepts a state changing method
func WriteMethodRequired(endpoint string) bool {
	return writeOnlyEndpoints[endpoint]
}

func isStateChangingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func isMutatingMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// ViewerAllowed reports whether a viewer may perform a request
func ViewerAllowed(method, path string) bool {
	if viewerDeniedExact[path] || (len(path) > 1 && viewerDeniedExact[strings.TrimRight(path, "/")]) {
		return false
	}
	for _, p := range viewerDeniedPrefixes {
		if len(path) >= len(p) && path[:len(p)] == p || path+"/" == p {
			return false
		}
	}
	if isMutatingMethod(method) {
		return viewerReadOnlyPOST[path]
	}
	return true
}

// RoleGuard refuses the request (and returns false) when the logged-in account is a
// viewer and the request is not allowed for viewers.
func (a *AuthAgent) RoleGuard(w http.ResponseWriter, r *http.Request) bool {
	if a.RequestRole(r) == RoleViewer && !ViewerAllowed(r.Method, r.URL.Path) {
		http.Error(w, "403 - Read-only account (viewer role)", http.StatusForbidden)
		return false
	}
	return true
}

// Endpoints lists the registered endpoint paths (used by tests / audits)
func (router *RouterDef) Endpoints() []string {
	out := make([]string, 0, len(router.endpoints))
	for e := range router.endpoints {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func (router *RouterDef) HandleFunc(endpoint string, handler func(http.ResponseWriter, *http.Request)) error {
	//Check if the endpoint already registered
	if _, exist := router.endpoints[endpoint]; exist {
		fmt.Println("WARNING! Duplicated registering of web endpoint: " + endpoint)
		return errors.New("endpoint register duplicated")
	}

	authAgent := router.option.AuthAgent

	writeOnly := WriteMethodRequired(endpoint)

	wrapped := func(w http.ResponseWriter, r *http.Request) {
		if writeOnly && !isStateChangingMethod(r.Method) {
			//A state changing endpoint must not be reachable with a method that skips the CSRF check
			w.Header().Set("Allow", "POST")
			http.Error(w, "405 - Method not allowed, use POST", http.StatusMethodNotAllowed)
			return
		}
		//Check authentication of the user
		if router.option.RequireAuth {
			authAgent.HandleCheckAuth(w, r, func(w http.ResponseWriter, r *http.Request) {
				if !authAgent.RoleGuard(w, r) {
					return
				}
				if IsActivityRequest(r) {
					authAgent.RefreshSession(w, r) //sliding expiry (off by default)
				}
				handler(w, r)
			})
		} else {
			handler(w, r)
		}
	}

	//OK. Register handler
	if router.option.TargetMux == nil {
		http.HandleFunc(endpoint, wrapped)
	} else {
		router.option.TargetMux.HandleFunc(endpoint, wrapped)
	}

	router.endpoints[endpoint] = handler

	return nil
}
