package plugins

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
)

// HandlePluginUI handles the request to the plugin UI
// This function will route the request to the correct plugin UI handler
func (m *Manager) HandlePluginUI(pluginID string, w http.ResponseWriter, r *http.Request) {
	plugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		writePluginUIError(w, http.StatusNotFound, "Plugin not found", "No plugin with this ID is installed.")
		return
	}

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
		writePluginUIError(w, http.StatusServiceUnavailable, "The plugin is not answering", "Several requests to the plugin failed in a row. Zoraxy tries it again in a moment.")
		return
	}

	upstreamOrigin := "127.0.0.1:" + strconv.Itoa(port)
	matchingPath := "/plugin.ui/" + plugin.Spec.ID

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
	_, err = uiProxy.ServeHTTP(cw, r, &dpcore.ResponseRewriteRuleSet{
		UseTLS:       false,
		OriginalHost: r.Host,
		ProxyDomain:  upstreamOrigin,
		PathPrefix:   matchingPath,
		AllowUpgrade: true,
		Version:      m.Options.SystemConst.ZoraxyVersion,
		UpstreamHeaders: [][]string{
			{"X-Zoraxy-Csrf", m.Options.CSRFTokenGen(r)},
		},
	})

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
	writePluginUIError(w, http.StatusBadGateway, "The page of the plugin could not be loaded", "Zoraxy could not reach the plugin. It may have stopped or it may not be listening yet.")

}
