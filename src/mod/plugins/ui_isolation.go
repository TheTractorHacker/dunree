package plugins

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TheTractorHacker/dunree/mod/utils"
)

/*
	Isolated plugin UI (phase 2 of docs/plugins/reliability-plan.md, item 2.7)

	Default (off): the page of a plugin is served under the admin origin at
	/plugin.ui/<id>/, the plugin is handed the CSRF token of the administrator and
	the admin session cookie, and the page runs with the rights of the admin UI.

	With the setting on, plugin pages are served by a listener of their own (another
	port, so another origin for the browser):

	- the admin UI asks for a ticket (an unguessable path) and opens
	  <origin>/t/<ticket>/ in an iframe that is sandboxed without allow-same-origin;
	- the request is proxied to the plugin without Cookie, Authorization and CSRF
	  token; Set-Cookie of the plugin is dropped (cookies are per host, not per
	  port, so a plugin could otherwise plant a cookie for the admin origin);
	- every answer carries "Content-Security-Policy: sandbox ...", so the page has
	  an opaque origin also when its address is opened outside the iframe;
	- /plugin.ui/ under the admin origin answers 403.

	A plugin page that needs the admin API stops working when this is on. That is
	the point of it, and why it is off by default.
*/

const (
	uiTicketLifetime = 8 * time.Hour
	uiTicketMax      = 512
	uiTicketPrefix   = "/t/"
	// What an isolated plugin page may do. No allow-same-origin: the page gets an
	// opaque origin, so it has no cookies, no storage and no same-origin access to
	// anything, the listener it is served from included.
	uiSandbox = "allow-scripts allow-forms allow-popups allow-modals allow-downloads"
)

type uiTicket struct {
	pluginID string
	expires  time.Time
}

type uiIsolation struct {
	mu      sync.Mutex
	ln      net.Listener
	srv     *http.Server
	want    string //the address that was asked for
	addr    string //the address the listener is bound to
	lastErr string
	tickets map[string]*uiTicket
}

// UIIsolationState is what the settings API says about the isolated plugin UI
type UIIsolationState struct {
	Enabled       bool
	Listening     bool
	ListenAddr    string //the address the listener is bound to
	DefaultListen string //used when the setting names no address
	Error         string
	Sandbox       string //sandbox tokens of an isolated plugin page
}

func (m *Manager) uiListenAddress(s ManagerSettings) string {
	if a := strings.TrimSpace(s.PluginUIListen); a != "" {
		return a
	}
	if m.Options != nil {
		return strings.TrimSpace(m.Options.IsolatedUIDefaultListen)
	}
	return ""
}

func validUIOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// applyUIIsolation brings the listener in line with the settings: opened when the
// isolation is on (again when the address changed), closed when it is off.
func (m *Manager) applyUIIsolation(s ManagerSettings) error {
	iso := &m.uiIso
	iso.mu.Lock()
	defer iso.mu.Unlock()
	if !s.IsolatePluginUI {
		iso.closeLocked()
		iso.lastErr = ""
		return nil
	}
	want := m.uiListenAddress(s)
	if want == "" {
		iso.lastErr = "no listen address is set for the isolated plugin pages"
		return errors.New(iso.lastErr)
	}
	if iso.ln != nil && iso.want == want {
		return nil
	}
	ln, err := net.Listen("tcp", want)
	if err != nil {
		if iso.ln == nil {
			iso.lastErr = "the listener for the isolated plugin pages could not be opened on " + want
		}
		return errors.New("the listener for the isolated plugin pages could not be opened on " + want + ": " + err.Error())
	}
	iso.closeLocked()
	iso.addr = ln.Addr().String()
	iso.want = want
	iso.lastErr = ""
	var handler http.Handler = http.HandlerFunc(m.serveIsolatedUI)
	var serveOn net.Listener = ln
	if m.Options != nil {
		if m.Options.UIHandlerWrap != nil {
			handler = m.Options.UIHandlerWrap(handler)
		}
		if m.Options.UIListenerWrap != nil {
			serveOn = m.Options.UIListenerWrap(ln)
		}
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	iso.ln, iso.srv = ln, srv
	go srv.Serve(serveOn)
	m.Log("Isolated plugin pages are served on "+iso.addr, nil)
	return nil
}

func (iso *uiIsolation) closeLocked() {
	if iso.srv != nil {
		iso.srv.Close()
	}
	if iso.ln != nil {
		iso.ln.Close()
	}
	iso.ln, iso.srv, iso.addr, iso.want = nil, nil, "", ""
	iso.tickets = nil
}

// StartIsolatedUI opens the listener of the isolated plugin UI when the setting
// is on. Called once at start-up; a change of the settings applies by itself.
func (m *Manager) StartIsolatedUI() {
	s := m.Settings()
	if !s.IsolatePluginUI {
		return
	}
	if err := m.applyUIIsolation(s); err != nil {
		m.Log("Isolated plugin pages are turned on but cannot be served; plugin pages are not available until this is fixed", err)
	}
}

func (m *Manager) uiIsolationState() UIIsolationState {
	s := m.Settings()
	st := UIIsolationState{Enabled: s.IsolatePluginUI, Sandbox: uiSandbox}
	if m.Options != nil {
		st.DefaultListen = m.Options.IsolatedUIDefaultListen
	}
	m.uiIso.mu.Lock()
	st.Listening = m.uiIso.ln != nil
	st.ListenAddr = m.uiIso.addr
	st.Error = m.uiIso.lastErr
	m.uiIso.mu.Unlock()
	return st
}

// newUITicket makes a ticket for the page of one plugin
func (m *Manager) newUITicket(pluginID string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	iso := &m.uiIso
	iso.mu.Lock()
	defer iso.mu.Unlock()
	if iso.ln == nil {
		return "", errors.New("the listener for the isolated plugin pages is not running")
	}
	now := time.Now()
	if iso.tickets == nil {
		iso.tickets = map[string]*uiTicket{}
	}
	var oldest string
	for k, t := range iso.tickets {
		if now.After(t.expires) {
			delete(iso.tickets, k)
			continue
		}
		if oldest == "" || t.expires.Before(iso.tickets[oldest].expires) {
			oldest = k
		}
	}
	if len(iso.tickets) >= uiTicketMax && oldest != "" {
		delete(iso.tickets, oldest)
	}
	iso.tickets[token] = &uiTicket{pluginID: pluginID, expires: now.Add(uiTicketLifetime)}
	return token, nil
}

func (m *Manager) uiTicketPlugin(token string) (string, bool) {
	iso := &m.uiIso
	iso.mu.Lock()
	defer iso.mu.Unlock()
	t, ok := iso.tickets[token]
	if !ok {
		return "", false
	}
	if time.Now().After(t.expires) {
		delete(iso.tickets, token)
		return "", false
	}
	return t.pluginID, true
}

// dropUITickets ends the tickets of one plugin, or all of them (""). Called when a
// plugin is uninstalled, when an install puts a plugin under that ID and when an
// update or rollback changes the ID: a plugin that is installed later under the
// same ID does not inherit addresses handed out for the earlier one. Stopping a
// plugin does not end its tickets (its page answers "not running" meanwhile).
func (m *Manager) dropUITickets(pluginID string) {
	iso := &m.uiIso
	iso.mu.Lock()
	for k, t := range iso.tickets {
		if pluginID == "" || t.pluginID == pluginID {
			delete(iso.tickets, k)
		}
	}
	iso.mu.Unlock()
}

// isolatedStaticPath says whether a path is one of the public style and script
// files of the admin UI that plugin pages load by absolute path
func isolatedStaticPath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	return strings.HasPrefix(p, "/script/") || strings.HasPrefix(p, "/img/public/") || strings.HasPrefix(p, "/locales/") ||
		p == "/main.css" || p == "/darktheme.css" || p == "/favicon.png"
}

func setIsolationHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "sandbox "+uiSandbox)
	h.Set("Referrer-Policy", "no-referrer") //the ticket is in the address of the page
	h.Set("X-Content-Type-Options", "nosniff")
}

// serveIsolatedUI is the handler of the isolated listener
func (m *Manager) serveIsolatedUI(w http.ResponseWriter, r *http.Request) {
	setIsolationHeaders(w.Header())
	if !m.Settings().IsolatePluginUI {
		http.NotFound(w, r)
		return
	}
	path := r.URL.Path
	if !strings.HasPrefix(path, uiTicketPrefix) {
		if isolatedStaticPath(path) && m.Options != nil && m.Options.UIStaticAssets != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			// Files anyone may read. The page that asks has an opaque origin, so fonts
			// and scripts with CORS mode need the header.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			r.Header.Del("Cookie")
			r.Header.Del("Authorization")
			m.Options.UIStaticAssets.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(path, uiTicketPrefix)
	token, _, hasSlash := strings.Cut(rest, "/")
	pluginID, ok := m.uiTicketPlugin(token)
	if !ok {
		writePluginUIError(w, http.StatusForbidden, "This plugin page link is not valid any more", "Open the plugin from the Dunree admin page again.")
		return
	}
	// The page has an opaque origin: a request of its scripts to its own address is
	// a cross-origin request to the browser ("Origin: null"). Allow exactly that.
	// The ticket in the path is what protects the page, not the origin.
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
			if h := r.Header.Get("Access-Control-Request-Headers"); h != "" {
				w.Header().Set("Access-Control-Allow-Headers", h)
			}
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if !hasSlash {
		http.Redirect(w, r, uiTicketPrefix+token+"/", http.StatusTemporaryRedirect)
		return
	}
	plugin, err := m.GetPluginByID(pluginID)
	if err != nil {
		writePluginUIError(w, http.StatusNotFound, "Plugin not found", "No plugin with this ID is installed.")
		return
	}
	m.servePluginUI(plugin, &isolatedWriter{ResponseWriter: w}, r, uiTicketPrefix+token, true)
}

// isolatedWriter drops Set-Cookie from the answers of a plugin page
type isolatedWriter struct {
	http.ResponseWriter
	done bool
}

func (iw *isolatedWriter) strip() {
	if iw.done {
		return
	}
	iw.done = true
	stripIsolatedResponseHeaders(iw.Header())
}

// stripIsolatedResponseHeaders is what the isolated listener does to the headers
// of every answer of a plugin, the 101 answer of a protocol upgrade included
// (ui_router.go passes it to the proxy for that case): no cookie is set, and
// whatever the plugin sent for the isolation headers, the listener decides.
func stripIsolatedResponseHeaders(h http.Header) {
	h.Del("Set-Cookie")
	h.Del("Set-Cookie2")
	setIsolationHeaders(h)
}

func (iw *isolatedWriter) WriteHeader(code int) {
	iw.strip()
	iw.ResponseWriter.WriteHeader(code)
}

func (iw *isolatedWriter) Write(b []byte) (int, error) {
	iw.strip()
	return iw.ResponseWriter.Write(b)
}

func (iw *isolatedWriter) Flush() {
	if f, ok := iw.ResponseWriter.(http.Flusher); ok {
		iw.strip()
		f.Flush()
	}
}

func (iw *isolatedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := iw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (iw *isolatedWriter) Unwrap() http.ResponseWriter { return iw.ResponseWriter }

// uiOriginFor is the address a browser reaches the isolated listener at
func (m *Manager) uiOriginFor(r *http.Request) (string, error) {
	s := m.Settings()
	if o := strings.TrimRight(strings.TrimSpace(s.PluginUIOrigin), "/"); o != "" {
		return o, nil
	}
	m.uiIso.mu.Lock()
	addr := m.uiIso.addr
	m.uiIso.mu.Unlock()
	if addr == "" {
		return "", errors.New("the listener for the isolated plugin pages is not running")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + host + ":" + port, nil
}

// HandlePluginUITicket tells the admin UI where the page of a plugin is.
// POST plugin_id. Isolation off: the address under the admin origin, as always.
// Isolation on: a fresh ticket address on the isolated listener and the sandbox
// tokens for the iframe.
func (m *Manager) HandlePluginUITicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not allowed")
		return
	}
	pluginID, err := utils.PostPara(r, "plugin_id")
	if err != nil {
		utils.SendErrorResponse(w, "plugin_id is required")
		return
	}
	if _, err := m.GetPluginByID(pluginID); err != nil {
		utils.SendErrorResponse(w, "plugin not found")
		return
	}
	type answer struct {
		Isolated bool   `json:"isolated"`
		URL      string `json:"url"`
		Sandbox  string `json:"sandbox"`
	}
	if !m.Settings().IsolatePluginUI {
		js, _ := json.Marshal(answer{URL: "/plugin.ui/" + url.PathEscape(pluginID) + "/", Sandbox: "allow-scripts allow-same-origin"})
		utils.SendJSONResponse(w, string(js))
		return
	}
	origin, err := m.uiOriginFor(r)
	if err != nil {
		utils.SendErrorResponse(w, "Plugin pages are isolated, but "+err.Error()+". See the plugin safety settings in the Plugin Manager.")
		return
	}
	token, err := m.newUITicket(pluginID)
	if err != nil {
		utils.SendErrorResponse(w, "Plugin pages are isolated, but "+err.Error()+". See the plugin safety settings in the Plugin Manager.")
		return
	}
	js, _ := json.Marshal(answer{Isolated: true, URL: origin + uiTicketPrefix + token + "/", Sandbox: uiSandbox})
	utils.SendJSONResponse(w, string(js))
}
