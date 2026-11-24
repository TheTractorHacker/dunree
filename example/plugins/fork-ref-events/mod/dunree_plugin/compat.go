package dunree_plugin

import "net/http"

/*
	compat.go

	Names on the wire between the host and a plugin.

	Dunree is based on Zoraxy and keeps its plugin contract (contract version 1). Dunree
	sends its headers as X-Dunree-<name>; Dunree 1.x also sends every one of them as
	X-Zoraxy-<name>, which is what a plugin built with the Zoraxy SDK reads. Upstream // legacy-compat
	Zoraxy only sends X-Zoraxy-<name>. // legacy-compat

	A plugin built with this package runs on both: HostHeader reads the Dunree name and
	falls back to the Zoraxy name. // legacy-compat

	Headers of the host (the <name> part):
	  Plugin-Token   secret of this plugin process, see VerifyInvokeToken
	  RequestID      id of the request, the same across every call made for it
	  Capture        static capture: the capture path that matched
	  Uri            static capture: the request URI as the client sent it
	  Csrf           UI: CSRF token of the admin session (not sent to an isolated UI)
	  Ui-Isolated    UI: "true" when the page is served from the isolated listener
	  Event-Type     event delivery: name of the event
*/

const (
	HostHeaderPrefix       = "X-Dunree-"
	LegacyHostHeaderPrefix = "X-Zoraxy-"
)

// HostHeader returns the value of a header the host sets on its calls to the plugin:
// HostHeader(r, "RequestID") reads X-Dunree-RequestID, and X-Zoraxy-RequestID when
// the first is absent (a Zoraxy host). name is the part after the prefix. // legacy-compat
//
// When both names are present with different values, the Zoraxy name wins. A Dunree 1.x // legacy-compat
// host always sends both with the same value, so a pair that differs comes from an upstream
// Zoraxy host, which sets (and overwrites) only X-Zoraxy-<name> and passes on an // legacy-compat
// X-Dunree-<name> header a client put into its request. Without this rule a client could
// choose the capture path or the request ID a plugin sees on such a host.
func HostHeader(r *http.Request, name string) string {
	if r == nil {
		return ""
	}
	v := r.Header.Get(HostHeaderPrefix + name)
	legacy := r.Header.Get(LegacyHostHeaderPrefix + name)
	if v == "" || (legacy != "" && legacy != v) {
		return legacy
	}
	return v
}
