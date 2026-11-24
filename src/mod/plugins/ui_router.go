package plugins

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
	"github.com/foleyit/dunree/mod/wirecompat"
)

// HandlePluginUI handles the request to the plugin UI
// This function will route the request to the correct plugin UI handler
func (m *Manager) HandlePluginUI(pluginID string, w http.ResponseWriter, r *http.Request) {
	plugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		writePluginUIError(w, http.StatusNotFound, "Plugin not found", "No plugin with this ID is installed.")
		return
	}
	if m.Settings().IsolatePluginUI {
		// Plugin pages are isolated (plugin safety settings): under the admin origin a
		// plugin page would run with the session of the administrator
		writePluginUIError(w, http.StatusForbidden, "Plugin pages are isolated", "Plugin pages are served from an address of their own. Open the plugin from the side menu of the Dunree admin page.")
		return
	}
	m.servePluginUI(plugin, w, r, "/plugin.ui/"+plugin.Spec.ID, false)
}

// servePluginUI proxies one request to the UI of a plugin. matchingPath is the
// path prefix the page lives under for the browser. isolated: the request comes
// from the isolated listener, and nothing of the admin session goes to the plugin.
func (m *Manager) servePluginUI(plugin *Plugin, w http.ResponseWriter, r *http.Request, matchingPath string, isolated bool) {
	//Check if the plugin has UI
	if plugin.Spec.UIPath == "" {
		writePluginUIError(w, http.StatusNotFound, "This plugin has no page", "The plugin does not offer a page of its own.")
		return
	}

	//Check if the plugin has UI handler
	uiProxy, port := plugin.uiProxyAndPort()
	if uiProxy == nil {
		writePluginUIError(w, http.StatusServiceUnavailable, "The plugin is not running", "Its page is available again when the plugin has been started.")
		return
	}
	if !plugin.beginCapture() {
		w.Header().Set("Retry-After", "30")
		writePluginUIError(w, http.StatusServiceUnavailable, "The plugin is not answering", "Several requests to the plugin failed in a row. Dunree tries it again in a moment.")
		return
	}

	upstreamOrigin := "127.0.0.1:" + strconv.Itoa(port)
	upstreamHeaders := hostHeaders("Csrf", m.Options.CSRFTokenGen(r))
	if isolated {
		// Nothing of the admin session: no cookie, no credentials, no CSRF token
		for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization", "X-Csrf-Token", wirecompat.Header("Csrf"), wirecompat.LegacyHeader("Csrf")} {
			r.Header.Del(h)
		}
		upstreamHeaders = hostHeaders("Ui-Isolated", "true")
	}

	//Rewrite the request path to the plugin UI path
	rewrittenURL := r.RequestURI
	rewrittenURL = strings.TrimPrefix(rewrittenURL, matchingPath)
	rewrittenURL = strings.ReplaceAll(rewrittenURL, "//", "/")
	if rewrittenURL == "" {
		rewrittenURL = "/"
	}
	r.URL, _ = url.Parse(rewrittenURL)

	//Call the plugin UI handler
	cw := plugin.newCaptureWriter(w)
	rules := &dpcore.ResponseRewriteRuleSet{
		UseTLS:          false,
		OriginalHost:    r.Host,
		ProxyDomain:     upstreamOrigin,
		PathPrefix:      matchingPath,
		AllowUpgrade:    true,
		Version:         m.Options.SystemConst.DunreeVersion,
		UpstreamHeaders: upstreamHeaders,
	}
	if isolated {
		// A protocol upgrade (101, e.g. a WebSocket) is written to the hijacked
		// connection, past isolatedWriter: its headers are cleaned here
		rules.UpgradeResponseHeaders = stripIsolatedResponseHeaders
	}
	_, err := uiProxy.ServeHTTP(cw, r, rules)

	status := plugin.captureResult(cw, "plugin UI", err)
	if err == nil {
		return
	}
	if errors.Is(err, dpcore.ErrResponseAborted) {
		//Headers are already on the wire: abort the connection so a cut-off page is not taken for a complete one
		panic(http.ErrAbortHandler)
	}
	if cw.wrote || cw.hijacked {
		return
	}
	if status == http.StatusGatewayTimeout {
		writePluginUIError(w, status, "The plugin did not answer in time", "The plugin is running but its page did not answer within the capture timeout set for it.")
		return
	}
	writePluginUIError(w, http.StatusBadGateway, "The page of the plugin could not be loaded", "Dunree could not reach the plugin. It may have stopped or it may not be listening yet.")

}
