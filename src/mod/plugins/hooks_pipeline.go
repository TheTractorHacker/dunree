package plugins

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	dunreePlugin "github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
	"github.com/google/uuid"
)

/*
	Hook pipeline

	RunRequestStage executes the filter plugins of a request stage,
	WrapResponse installs the response stage.
	See dunree_plugin/hooks.go for the documented semantics.
*/

// Endpoint opt-out tags. Add them to a HTTP proxy rule to exclude plugins from it.
const (
	OptOutAllGlobalTag = "no-global-plugins" //exclude every plugin that is attached globally
	OptOutPluginPrefix = "no-plugin:"        //"no-plugin:<plugin id>" excludes that plugin completely
)

// StageResult tells the caller what happened in a stage
type StageResult struct {
	Handled  bool   //The response has been written (or the request captured), stop the chain
	Denied   bool   //Handled because of a deny verdict or fail-closed failure
	Status   int    //Status code written on deny
	PluginID string //Plugin responsible for the decision
	Reason   string
}

type requestIDKey struct{}

// requestID returns the stable ID of this request, creating it on first use. It cannot be
// spoofed by the client because it lives in the request context, not in a header.
func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(requestIDKey{}).(string); ok {
		return v
	}
	id := uuid.New().String()
	*r = *r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
	return id
}

// pluginsForRequest returns the enabled plugins that apply to a request with the
// given tags (tagged + global, minus opt-outs), in deterministic priority order.
func (m *Manager) pluginsForRequest(tags []string) []*Plugin {
	active, _ := m.pluginsFor(tags)
	return active
}

// pluginsFor returns the plugins that apply to a request with the given tags. active
// are the ones in the request path, in deterministic priority order. down are
// fail-closed plugins (declared and consented) that apply to the request but are not
// running although they should be: see guardDown.
func (m *Manager) pluginsFor(tags []string) (active []*Plugin, down []*Plugin) {
	optOutGlobal := false
	optOut := map[string]bool{}
	for _, t := range tags {
		if t == OptOutAllGlobalTag {
			optOutGlobal = true
		} else if strings.HasPrefix(t, OptOutPluginPrefix) {
			optOut[strings.TrimPrefix(t, OptOutPluginPrefix)] = true
		}
	}

	seen := map[string]bool{}
	var list []*Plugin
	add := func(p *Plugin) {
		if p == nil || p.Spec == nil || seen[p.Spec.ID] || optOut[p.Spec.ID] {
			return
		}
		switch p.pathState() {
		case pathActive:
			seen[p.Spec.ID] = true
			list = append(list, p)
		case pathDown:
			if p.failsClosed() {
				seen[p.Spec.ID] = true
				down = append(down, p)
			}
		}
	}

	m.tagPluginListMutex.RLock()
	for _, tag := range tags {
		for _, p := range m.tagPluginList[tag] {
			add(p)
		}
	}
	m.tagPluginListMutex.RUnlock()

	if !optOutGlobal {
		var globals []*Plugin
		m.loadedPluginsMutex.RLock()
		for _, p := range m.LoadedPlugins {
			if p.Spec != nil && p.Spec.Type == dunreePlugin.PluginType_Router && p.pathState() != pathOut && p.isGlobal() {
				globals = append(globals, p)
			}
		}
		m.loadedPluginsMutex.RUnlock()
		sort.Slice(globals, func(i, j int) bool { return globals[i].Spec.ID < globals[j].Spec.ID })
		for _, p := range globals {
			add(p)
		}
	}

	//Stable: ties keep tag / group order, then globals by plugin ID
	sort.SliceStable(list, func(i, j int) bool { return list[i].priority() < list[j].priority() })
	return list, down
}

// Where a plugin stands for the request path
const (
	pathOut    = iota //not running and not expected to: stopped by the administrator, never started
	pathActive        //running and attached: it is called
	pathDown          //should be running but is not: crashed, exited, failed to start, waiting for a restart, or not ready yet
)

func (p *Plugin) pathState() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Enabled {
		if !p.notReady {
			return pathActive
		}
		return pathDown //the readiness gate is still waiting for its port
	}
	if p.wantDown {
		return pathOut //stopped on purpose, also when it had crashed before
	}
	switch p.status.state {
	case StateCrashed, StateExited, StateFailedToStart, StateRestarting, StateCrashLoop:
		return pathDown
	}
	return pathOut
}

// inRequestPath reports whether the plugin is running and attached to the request path
func (p *Plugin) inRequestPath() bool { return p.pathState() == pathActive }

const downLogEvery = time.Minute

// guardStage says at which point of a request a down fail-closed plugin is accounted
// for: the first request stage it registered for, "legacy" when it only has a
// dynamic capture, "" when it has nothing in the request path.
func guardStage(p *Plugin) string {
	if h := p.Spec.Hooks; h != nil {
		for _, st := range []dunreePlugin.HookStage{dunreePlugin.HookStagePreAuth, dunreePlugin.HookStagePostAuth, dunreePlugin.HookStageResponse} {
			if h.HasStage(st) && h.PathForStage(st) != "" {
				return string(st)
			}
		}
	}
	if p.AcceptDynamicRoute() {
		return "legacy"
	}
	return ""
}

// guardDown handles the fail-closed plugins of a request that are not running.
// Such a plugin was allowed by the administrator to block requests when it fails,
// but a plugin that is not running cannot fail a call. By default the request
// passes (as it always did) and is counted; with the per plugin option "block
// while not running" (PluginPolicy.BlockWhenDown) it is refused.
// It returns the plugin that blocks the request, or nil.
func (m *Manager) guardDown(down []*Plugin, at string) *Plugin {
	for _, p := range down {
		if guardStage(p) != at {
			continue
		}
		if p.policy().BlockWhenDown {
			p.obs.blockedWhileDown.Add(1)
			m.downLog(p, "requests are refused (503) while this fail-closed plugin is not running")
			return p
		}
		p.obs.passedWhileDown.Add(1)
		m.downLog(p, "requests pass unfiltered while this fail-closed plugin is not running (turn on \"block while not running\" for the plugin to refuse them instead)")
	}
	return nil
}

// downLog logs at most once per minute per plugin
func (m *Manager) downLog(p *Plugin, msg string) {
	now := time.Now().UnixNano()
	last := p.obs.downLogAt.Load()
	if last != 0 && time.Duration(now-last) < downLogEvery {
		return
	}
	if !p.obs.downLogAt.CompareAndSwap(last, now) {
		return
	}
	m.logf(p, fmt.Sprintf("%s (passed %d, refused %d since Dunree started)", msg, p.obs.passedWhileDown.Load(), p.obs.blockedWhileDown.Load()), nil)
}

func filterPluginsForStage(all []*Plugin, stage dunreePlugin.HookStage) []*Plugin {
	var out []*Plugin
	for _, p := range all {
		h := p.Spec.Hooks
		if h != nil && h.HasStage(stage) && h.PathForStage(stage) != "" {
			out = append(out, p)
		}
	}
	return out
}

type filterOutcome struct {
	plugin  *Plugin
	verdict *cleanVerdict
	err     error
}

// runFilters calls the plugins concurrently with their own payload
func (m *Manager) runFilters(plugins []*Plugin, stage dunreePlugin.HookStage, build func(p *Plugin) *dunreePlugin.FilterRequest) []filterOutcome {
	out := make([]filterOutcome, len(plugins))
	run := func(i int) {
		p := plugins[i]
		cv, err := m.callFilter(p, stage, build(p))
		out[i] = filterOutcome{plugin: p, verdict: cv, err: err}
	}
	if len(plugins) == 1 {
		run(0)
		return out
	}
	var wg sync.WaitGroup
	for i := range plugins {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			run(i)
		}(i)
	}
	wg.Wait()
	return out
}

// RunRequestStage runs the filter hooks of pre_auth or post_auth.
// For post_auth use HandleStage which also performs the legacy capture.
func (m *Manager) RunRequestStage(w http.ResponseWriter, r *http.Request, tags []string, clientIP string, stage dunreePlugin.HookStage) StageResult {
	if stage == dunreePlugin.HookStageResponse {
		return StageResult{}
	}
	active, down := m.pluginsFor(tags)
	if len(down) > 0 {
		if p := m.guardDown(down, string(stage)); p != nil {
			writePluginError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
			return StageResult{Handled: true, Denied: true, Status: http.StatusServiceUnavailable, PluginID: p.Spec.ID, Reason: "fail_closed: plugin is not running"}
		}
	}
	plugins := filterPluginsForStage(active, stage)
	if len(plugins) == 0 {
		return StageResult{}
	}
	reqID := requestID(r)
	n, bodyBuf := m.previewBody(w, r, plugins)
	snapshot := dunreePlugin.EncodeForwardRequestPayload(r, clientIP)

	results := m.runFilters(plugins, stage, func(p *Plugin) *dunreePlugin.FilterRequest {
		fr := &dunreePlugin.FilterRequest{
			Version:   dunreePlugin.HookAPIVersion,
			Stage:     stage,
			RequestID: reqID,
			Request:   snapshot,
		}
		if limit := p.Spec.Hooks.EffectiveBodyPreviewBytes(); limit > 0 && n > 0 && p.Spec.Hooks.WantsBodyFor(r.Header.Get("Content-Type")) {
			take := n
			if take > limit {
				take = limit
			}
			fr.BodyPreview = bodyBuf[:take]
			fr.BodyTruncated = n > limit
		}
		return fr
	})

	for _, res := range results {
		p := res.plugin
		if res.err != nil {
			if res.err != errBreakerOpen {
				m.logf(p, "filter call failed at "+string(stage)+" (request "+reqID+")", res.err)
			}
			if p.failsClosed() {
				writePluginError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
				return StageResult{Handled: true, Denied: true, Status: http.StatusServiceUnavailable, PluginID: p.Spec.ID, Reason: "fail_closed: " + res.err.Error()}
			}
			continue //fail open
		}
		cv := res.verdict
		switch cv.Action {
		case dunreePlugin.ActionDeny:
			writeDeny(w, cv)
			return StageResult{Handled: true, Denied: true, Status: cv.DenyStatus, PluginID: p.Spec.ID, Reason: cv.Reason}
		case dunreePlugin.ActionModify:
			applyRequestModify(r, cv)
		case dunreePlugin.ActionCapture:
			if stage != dunreePlugin.HookStagePostAuth {
				m.logf(p, "capture verdict ignored at "+string(stage)+": capture would bypass authentication, register for post_auth instead", nil)
				continue
			}
			if !p.AcceptDynamicRoute() || !p.hasDynamicProxy() {
				m.logf(p, "capture verdict ignored: plugin declares no dynamic capture ingress", nil)
				continue
			}
			p.serveDynamicCapture(w, r, reqID)
			return StageResult{Handled: true, PluginID: p.Spec.ID, Reason: cv.Reason}
		}
	}
	return StageResult{}
}

func writePluginError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, msg)
}

func writeDeny(w http.ResponseWriter, cv *cleanVerdict) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	for k, v := range cv.DenyHeader {
		h.Set(k, v)
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(cv.DenyStatus)
	io.WriteString(w, cv.DenyBody)
}

/* Body preview */

var methodsWithBody = map[string]bool{
	http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// previewBody reads at most the largest requested preview from the request body and
// puts it back in front of the remaining body, so the upstream still gets the whole body.
// It returns the number of bytes read (up to limit+1) and the buffer.
func (m *Manager) previewBody(w http.ResponseWriter, r *http.Request, plugins []*Plugin) (int, []byte) {
	if !methodsWithBody[r.Method] || r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return 0, nil
	}
	ct := r.Header.Get("Content-Type")
	limit := 0
	var timeout time.Duration
	for _, p := range plugins {
		if p.Spec.Hooks.WantsBodyFor(ct) {
			if l := p.Spec.Hooks.EffectiveBodyPreviewBytes(); l > limit {
				limit = l
			}
			if t := p.callTimeout(); t > timeout {
				timeout = t
			}
		}
	}
	if limit == 0 {
		return 0, nil
	}
	//Do not let a slow client hold the request open while we wait for the preview
	rc := http.NewResponseController(w)
	deadlineSet := rc.SetReadDeadline(time.Now().Add(timeout)) == nil

	buf := make([]byte, limit+1)
	n, err := io.ReadFull(r.Body, buf)
	if deadlineSet {
		rc.SetReadDeadline(time.Time{})
	}
	orig := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf[:n]), orig), orig}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, nil //could not read a clean preview, do not hand out a partial one
	}
	return n, buf
}

/* Response stage */

// WrapResponse returns a ResponseWriter that runs the response stage hooks just before
// the response header is sent. It returns w itself when no plugin registered for the
// response stage for this request, so the cost is one map lookup in the common case.
func (m *Manager) WrapResponse(w http.ResponseWriter, r *http.Request, tags []string, clientIP string) http.ResponseWriter {
	active, down := m.pluginsFor(tags)
	downBlock := false
	if len(down) > 0 {
		downBlock = m.guardDown(down, string(dunreePlugin.HookStageResponse)) != nil
	}
	plugins := filterPluginsForStage(active, dunreePlugin.HookStageResponse)
	if len(plugins) == 0 && !downBlock {
		return w
	}
	return &hookResponseWriter{ResponseWriter: w, m: m, r: r, plugins: plugins, clientIP: clientIP, downBlock: downBlock}
}

type hookResponseWriter struct {
	http.ResponseWriter
	m        *Manager
	r        *http.Request
	plugins  []*Plugin
	clientIP string

	wroteHeader bool
	suppress    bool
	downBlock   bool //a fail-closed response plugin is not running and may block: answer 502 instead of the upstream response
}

func (h *hookResponseWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

func (h *hookResponseWriter) WriteHeader(code int) {
	if h.wroteHeader || h.suppress {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		h.ResponseWriter.WriteHeader(code) //informational, the final header is still to come
		return
	}
	h.wroteHeader = true
	if code == http.StatusSwitchingProtocols {
		h.ResponseWriter.WriteHeader(code)
		return
	}
	h.runHooks(code)
}

func (h *hookResponseWriter) Write(b []byte) (int, error) {
	if !h.wroteHeader {
		h.WriteHeader(http.StatusOK)
	}
	if h.suppress {
		return len(b), nil
	}
	return h.ResponseWriter.Write(b)
}

func (h *hookResponseWriter) Flush() {
	if !h.wroteHeader {
		h.WriteHeader(http.StatusOK)
	}
	if f, ok := h.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *hookResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := h.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	h.wroteHeader = true
	return hj.Hijack()
}

func (h *hookResponseWriter) runHooks(code int) {
	if h.downBlock {
		h.failClosed()
		return
	}
	reqID := requestID(h.r)
	snapshot := dunreePlugin.EncodeForwardRequestPayload(h.r, h.clientIP)
	hdr := h.ResponseWriter.Header()
	resInfo := &dunreePlugin.FilterResponseInfo{Status: code, Header: map[string][]string(hdr.Clone())}

	results := h.m.runFilters(h.plugins, dunreePlugin.HookStageResponse, func(p *Plugin) *dunreePlugin.FilterRequest {
		return &dunreePlugin.FilterRequest{
			Version:   dunreePlugin.HookAPIVersion,
			Stage:     dunreePlugin.HookStageResponse,
			RequestID: reqID,
			Request:   snapshot,
			Response:  resInfo,
		}
	})
	for _, res := range results {
		p := res.plugin
		if res.err != nil {
			if res.err != errBreakerOpen {
				h.m.logf(p, "filter call failed at response stage (request "+reqID+")", res.err)
			}
			if p.failsClosed() {
				h.failClosed()
				return
			}
			continue
		}
		if res.verdict.Action == dunreePlugin.ActionModify {
			applyHeaderOps(hdr, res.verdict.ResHeaders)
		}
	}
	h.ResponseWriter.WriteHeader(code)
}

// failClosed replaces the upstream response by a plain 502
func (h *hookResponseWriter) failClosed() {
	hdr := h.ResponseWriter.Header()
	for k := range hdr {
		delete(hdr, k)
	}
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	h.ResponseWriter.WriteHeader(http.StatusBadGateway)
	io.WriteString(h.ResponseWriter, "Bad Gateway")
	h.suppress = true
}
