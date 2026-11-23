package plugins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// StartDynamicForwardRouter create and start a dynamic forward router for
// this plugin
func (p *Plugin) StartDynamicForwardRouter() error {
	// Create a new dpcore object to forward the traffic to the plugin
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startDynamicForwardRouterLocked()
}

func (p *Plugin) startDynamicForwardRouterLocked() error {
	targetURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(p.AssignedPort) + p.Spec.DynamicCaptureIngress)
	if err != nil {
		fmt.Println("Failed to parse the dynamic capture target URL of plugin "+p.Spec.ID, err)
		return err
	}
	thisRouter := dpcore.NewDynamicProxyCore(targetURL, "", p.captureProxyOptions())
	p.dynamicRouteProxy = thisRouter
	return nil
}

// StopDynamicForwardRouter stops the dynamic forward router for this plugin
func (p *Plugin) StopDynamicForwardRouter() {
	p.mu.Lock()
	p.dynamicRouteProxy = nil
	p.mu.Unlock()
}

// hasDynamicProxy reports whether the dynamic capture ingress of the plugin is attached
func (p *Plugin) hasDynamicProxy() bool {
	proxy, _ := p.dynamicProxyAndPort()
	return proxy != nil
}

// AcceptDynamicRoute returns whether this plugin accepts dynamic route
func (p *Plugin) AcceptDynamicRoute() bool {
	return p.Spec.DynamicCaptureSniff != "" && p.Spec.DynamicCaptureIngress != ""
}

// sniffPlugin asks the legacy dynamic capture sniff endpoint of the plugin whether it
// wants this request. A non-200 answer is a regular "skip"; only transport problems
// (connection refused, timeout) are failures and feed the circuit breaker.
func (m *Manager) sniffPlugin(p *Plugin, r *http.Request, clientIP string, reqID string) (accepted bool, err error) {
	if !p.AcceptDynamicRoute() {
		return false, nil
	}
	if !m.breakerAdmit(p) {
		return false, errBreakerOpen
	}
	forwardReq := zoraxy_plugin.EncodeForwardRequestPayload(r, clientIP)
	forwardReq.Rule = RuleInfoFromRequest(r)
	jsonData, err := json.Marshal(forwardReq)
	if err != nil {
		m.breakerRecord(p, nil)
		return false, nil
	}
	//The sniff endpoint has always been called with a trailing slash
	status, _, err := m.callPlugin(p, normalizeEndpoint(p.Spec.DynamicCaptureSniff)+"/", jsonData, reqID, 4096)
	m.breakerRecord(p, err)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK, nil
}

func normalizeEndpoint(s string) string {
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return strings.TrimSuffix(s, "/")
}

// serveDynamicCapture proxies the whole request to the dynamic capture ingress of the plugin
func (p *Plugin) serveDynamicCapture(w http.ResponseWriter, r *http.Request, reqID string) {
	headers := [][]string{{"X-Zoraxy-RequestID", reqID}}
	if tok := p.invokeToken(); tok != "" {
		headers = append(headers, []string{zoraxy_plugin.InvokeTokenHeader, tok})
	}
	proxy, port := p.dynamicProxyAndPort()
	if proxy == nil {
		//The plugin stopped between the decision to capture and now
		p.noteError("A dynamic capture request failed: the plugin is not running")
		writePluginError(w, http.StatusBadGateway, "502 Bad Gateway: the plugin handling this request is not reachable")
		return
	}
	if !p.beginCapture() {
		writeCaptureUnavailable(w)
		return
	}
	cw := p.newCaptureWriter(w)
	//A transport error is returned without anything written: finishCapture answers 502 instead of an empty 200
	_, err := proxy.ServeHTTP(cw, r, &dpcore.ResponseRewriteRuleSet{
		UseTLS:          false,
		OriginalHost:    r.Host,
		ProxyDomain:     "127.0.0.1:" + strconv.Itoa(port),
		NoCache:         true,
		PathPrefix:      normalizeEndpoint(p.Spec.DynamicCaptureIngress),
		AllowUpgrade:    true,
		UpstreamHeaders: headers,
	})
	p.finishCapture(cw, "dynamic", err)
}
