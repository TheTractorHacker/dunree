package dynamicproxy

import (
	"net/http"
	"sync/atomic"

	"github.com/TheTractorHacker/dunree/mod/blocklog"
	"github.com/TheTractorHacker/dunree/mod/errorpages"
)

/*
	errorpages_hook.go

	Customisable error pages (mod/errorpages) for the answers Dunree gives a visitor by itself.

	Off unless the owner saved and enabled a customisation: serveCustomErrorPage then returns false
	before it touches the response, and every caller goes on to write exactly what it always wrote.
	The same holds for a page class (or host) the owner did not customise, and for a template that
	fails to render (logged once by the manager).

	Callers and their class
	  serveProxyRequestError  403 -> ClassForbidden, 404 -> ClassNotFound, 521 -> ClassServerError
	  writeForbiddenPage      ClassForbidden (access rules, countries, WAF, auto-ban, CrowdSec)
	  serve404PageWithTemplate ClassNoHost (Default Site "not found" page)
	  rate limits (site, path rule, security rule)  ClassRateLimit
	  every upstream at its connection limit        ClassMaintenance (503)
	  route timeouts answered by Dunree (504)       ClassServerError
	  "Block common exploits" / "Block AI crawlers" (exploitErrorPage): action 403 -> ClassForbidden,
	  action 404 -> ClassNotFound

	Not covered: an error status the upstream itself answers (that is the per site "error pages" option
	of ops_config.go), the CAPTCHA pages, plain text refusals of misconfigured rules, the 400 and
	"drop the connection" actions of the exploit detector, the 502 answers of Dunree itself (WebSocket
	upgrade, virtual directory target: plain http.Error).
*/

var customErrorPages atomic.Pointer[errorpages.Manager]

// SetCustomErrorPages installs the error page customisation (nil removes it)
func SetCustomErrorPages(m *errorpages.Manager) {
	customErrorPages.Store(m)
}

// errorClass maps the built-in page of serveProxyRequestError to its class
func (e ErrorTemplateType) errorClass() errorpages.Class {
	switch e {
	case ErrorTemplateForbidden:
		return errorpages.ClassForbidden
	case ErrorTemplateHostError:
		return errorpages.ClassNotFound
	default:
		return errorpages.ClassServerError
	}
}

// serveCustomErrorPage writes the owner's page for this answer and returns true. It returns false,
// without having changed the response, when nothing is customised for the class and host.
// Headers the caller already set (Retry-After, X-Request-Id ...) are kept; the status is the caller's.
func (router *Router) serveCustomErrorPage(w http.ResponseWriter, r *http.Request, status int, class errorpages.Class) bool {
	m := customErrorPages.Load()
	if !m.Active() || r == nil {
		return false
	}
	// the Host as the visitor sent it: the proxy rewrites r.Host before it calls the upstream
	host := r.Host
	st := opsStateFrom(r)
	if st != nil && st.host != "" {
		host = st.host
	}
	if !m.Has(class, host) {
		return false
	}
	// A site whose own "error pages" option (ops_config.go) replaces this status keeps doing so: it is the more specific setting
	if ow, isOps := w.(*opsWriter); isOps && ow.errPages != nil && ow.st.armed.Load() && ow.errPages.statuses[status] {
		return false
	}
	req := errorpages.Request{Class: class, Status: status, Host: host}
	ref := ""
	if class == errorpages.ClassForbidden {
		if ref = blocklog.FormatRef(router.requestRef(r)); ref != "" {
			req.RequestID = ref
		}
	}
	if req.RequestID == "" {
		req.RequestID = w.Header().Get("X-Request-Id") //WAF transaction ID, or the exposed request ID of the site
	}
	if st != nil {
		if req.RequestID == "" {
			req.RequestID = st.id
		}
		req.ClientIP = st.clientIP
	} else if router != nil {
		req.ClientIP = router.GetClientIPForEndpoint(r, nil)
	}
	body, ok := m.Render(req)
	if !ok {
		return false
	}
	if ref != "" {
		setRefHeader(w.Header(), ref)
	}
	errorpages.SetHeaders(w.Header(), len(body))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
	return true
}

// exploitErrorPage is the exploits.PageResponder of the exploit / AI crawler detector: its plain text
// "Forbidden" (403) and http.NotFound (404) answers can be a customised page. False = nothing written.
func (router *Router) exploitErrorPage(w http.ResponseWriter, r *http.Request, status int) bool {
	switch status {
	case http.StatusForbidden:
		return router.serveCustomErrorPage(w, r, status, errorpages.ClassForbidden)
	case http.StatusNotFound:
		return router.serveCustomErrorPage(w, r, status, errorpages.ClassNotFound)
	}
	return false
}

// serveGatewayStatus answers a status Dunree decided on for a proxied request (route limits: 413, 504 ...).
// 5xx statuses can have a customised page; everything else, and the default, is the plain text it always was.
func (router *Router) serveGatewayStatus(w http.ResponseWriter, r *http.Request, status int) {
	if status >= 500 && router.serveCustomErrorPage(w, r, status, errorpages.ClassServerError) {
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// BuiltinErrorPage returns what a visitor gets for a class while nothing is customised (English,
// without a block reference), for the "Send a test" link of the admin UI. html is false for the
// classes that are answered without a page.
func BuiltinErrorPage(class errorpages.Class) (body []byte, html bool) {
	switch class {
	case errorpages.ClassForbidden:
		return renderErrorPage(page_forbidden, "", false), true
	case errorpages.ClassNotFound, errorpages.ClassNoHost:
		return page_hosterror, true
	case errorpages.ClassServerError:
		return page_rperror, true
	case errorpages.ClassMaintenance:
		return []byte("Service Unavailable\n"), false
	default:
		return nil, false
	}
}
