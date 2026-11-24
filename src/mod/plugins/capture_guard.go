package plugins

import (
	"bufio"
	"context"
	"errors"
	"html"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
)

/*
	Capture error handling

	A capturing plugin (static capture path or dynamic capture ingress) owns the
	whole response. When the plugin cannot be reached the reverse proxy core returns
	an error without writing anything; the callers used to ignore it, so the visitor
	got an empty "200 OK". finishCapture turns that into a 502.
*/

// captureWriter remembers whether anything was sent to the client
type captureWriter struct {
	http.ResponseWriter
	wrote    bool
	hijacked bool
	answered bool   //the plugin has started to answer (final status, 101 or a taken-over connection)
	onAnswer func() //called once, at that moment
}

// newCaptureWriter wraps the writer of a request that is handed to the plugin.
// The moment the plugin starts to answer counts as the success of the request for
// the capture breaker: a WebSocket or a long download must not hold the single
// probe slot of an open breaker for as long as it lasts.
func (p *Plugin) newCaptureWriter(w http.ResponseWriter) *captureWriter {
	return &captureWriter{ResponseWriter: w, onAnswer: func() {
		p.capBreaker.record(false)
		p.noteAlive()
	}}
}

func (c *captureWriter) markAnswered() {
	if c.answered {
		return
	}
	c.answered = true
	if c.onAnswer != nil {
		c.onAnswer()
	}
}

func (c *captureWriter) WriteHeader(code int) {
	c.wrote = true
	if code >= 200 || code == http.StatusSwitchingProtocols {
		c.markAnswered() //not for 100 Continue and other interim answers
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.wrote = true
	c.markAnswered()
	return c.ResponseWriter.Write(b)
}

func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := c.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("http server does not support hijacker")
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		c.hijacked = true
		c.markAnswered()
	}
	return conn, rw, err
}

// Unwrap lets http.ResponseController reach the original writer
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

/*
	Capture timeout and circuit breaker (opt-in: PluginPolicy.CaptureTimeoutMs > 0)

	Without the option the capture and UI paths behave as before: no timeout, every
	request is tried. With it the plugin gets that long to start answering (504 when
	it does not), and after a number of failed requests in a row the following ones
	are answered 503 at once until one probe request succeeds again. Failures are
	counted either way.
*/

const (
	captureBreakerThreshold = 5
	captureBreakerCooldown  = 30 * time.Second
	captureLogEvery         = time.Minute
)

type captureBreaker struct {
	mu         sync.Mutex
	consecFail int
	openUntil  time.Time
	probing    bool
	threshold  int           //tests only, 0 = captureBreakerThreshold
	cooldown   time.Duration //tests only, 0 = captureBreakerCooldown
}

func (b *captureBreaker) limit() int { return intOr(b.threshold, captureBreakerThreshold) }

func (b *captureBreaker) reset() {
	b.mu.Lock()
	b.consecFail, b.openUntil, b.probing = 0, time.Time{}, false
	b.mu.Unlock()
}

// refusing reports whether the breaker is open: enough requests in a row failed
// and none has succeeded since. Requests are then refused, except the one that
// probes the plugin after each cooldown. (Only enforced with a capture timeout.)
func (b *captureBreaker) refusing() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consecFail >= b.limit()
}

// admit reports whether a request may be sent to the plugin now
func (b *captureBreaker) admit() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.consecFail < b.limit() {
		return true
	}
	if time.Now().Before(b.openUntil) {
		return false
	}
	if b.probing {
		return false
	}
	b.probing = true //half open: one request tries the plugin
	return true
}

// release gives the half-open probe slot back without a verdict: the request
// ended for a reason that says nothing about the plugin (the visitor went away).
// The failure streak and the open time stay as they are.
func (b *captureBreaker) release() {
	b.mu.Lock()
	b.probing = false
	b.mu.Unlock()
}

// record returns true when this failure opened the breaker
func (b *captureBreaker) record(failed bool) (opened bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	if !failed {
		b.consecFail, b.openUntil = 0, time.Time{}
		return false
	}
	was := b.consecFail >= b.limit()
	b.consecFail++
	if b.consecFail >= b.limit() {
		b.openUntil = time.Now().Add(durOr(b.cooldown, captureBreakerCooldown))
		return !was
	}
	return false
}

// captureProxyOptions are the reverse proxy options of the capture and UI proxies of the plugin
func (p *Plugin) captureProxyOptions() *dpcore.DpcoreOptions {
	return &dpcore.DpcoreOptions{ResponseHeaderTimeout: int64(p.policy().CaptureTimeoutMs)}
}

// beginCapture counts a request that is about to be handed to the plugin. With the
// capture timeout on it returns false while the capture breaker is open.
func (p *Plugin) beginCapture() bool {
	if p.policy().CaptureTimeoutMs > 0 && !p.capBreaker.admit() {
		p.obs.captureRejected.Add(1)
		return false
	}
	p.obs.captureCalls.Add(1)
	return true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// captureResult records the outcome of a request handed to the plugin and returns
// the status code an error answer should carry (0 = no error). When the plugin
// had started to answer, the breaker already has its verdict (see newCaptureWriter)
// and is left alone here.
func (p *Plugin) captureResult(cw *captureWriter, what string, err error) int {
	if err == nil {
		if !cw.answered {
			p.capBreaker.record(false)
		}
		p.noteAlive()
		return 0
	}
	aborted := errors.Is(err, dpcore.ErrResponseAborted)
	if errors.Is(err, context.Canceled) && !aborted {
		// The visitor went away before the plugin answered: says nothing about the
		// plugin, so it is neither a success (which would close the breaker and
		// reset the streak of a hung plugin) nor a failure
		if !cw.answered {
			p.capBreaker.release()
		}
		return http.StatusBadGateway
	}
	p.obs.captureFails.Add(1)
	// Fixed wording in the status (it is readable beyond administrators); the text of
	// the error, which can quote bytes of the plugin or the path of the visitor, goes
	// to the log only, at most once a minute per plugin
	p.noteError("A " + what + " request failed: " + publicTransportError(err))
	p.captureProblem(what, err)
	if cw.answered {
		// The plugin had answered; a tunnel or a body broke later. Not a reason to cut the plugin off.
		return http.StatusBadGateway
	}
	if aborted {
		// The plugin had answered; the body broke, or the visitor stopped a download.
		// Not a reason to cut the plugin off.
		p.capBreaker.record(false)
		return http.StatusBadGateway
	}
	if p.capBreaker.record(true) && p.policy().CaptureTimeoutMs > 0 {
		p.noteError("The plugin failed " + strconv.Itoa(p.capBreaker.limit()) + " " + what + " requests in a row. Requests to it are answered 503 until it works again")
	}
	if isTimeout(err) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// captureProblem logs a failed capture or UI request of this plugin, at most once
// per minute. The error text is quoted and cut, so it cannot forge log lines.
func (p *Plugin) captureProblem(what string, err error) {
	now := time.Now().UnixNano()
	last := p.obs.captureLogAt.Load()
	if last != 0 && time.Duration(now-last) < captureLogEvery {
		return
	}
	if !p.obs.captureLogAt.CompareAndSwap(last, now) {
		return
	}
	text := err.Error()
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	p.mu.RLock()
	mgr := p.mgr
	p.mu.RUnlock()
	if mgr != nil && mgr.Options != nil && mgr.Options.Logger != nil {
		mgr.Log("plugin "+p.Spec.ID+": a "+what+" request failed: "+strconv.Quote(text)+" ("+strconv.FormatInt(p.obs.captureFails.Load(), 10)+" failed since Dunree started; further failures are not logged for "+captureLogEvery.String()+")", nil)
	}
}

// finishCapture handles the result of proxying a captured request to a plugin
func (p *Plugin) finishCapture(cw *captureWriter, kind string, err error) {
	status := p.captureResult(cw, kind+" capture", err)
	if err == nil {
		return
	}
	if errors.Is(err, dpcore.ErrResponseAborted) {
		//Headers are already on the wire: abort the connection so a cut-off body is not taken for a complete one
		panic(http.ErrAbortHandler)
	}
	if cw.wrote || cw.hijacked {
		return
	}
	if status == http.StatusGatewayTimeout {
		writePluginError(cw.ResponseWriter, status, "504 Gateway Timeout: the plugin handling this request did not answer in time")
		return
	}
	writePluginError(cw.ResponseWriter, http.StatusBadGateway, "502 Bad Gateway: the plugin handling this request is not reachable")
}

// writeCaptureUnavailable answers a captured request while the capture breaker is open
func writeCaptureUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	writePluginError(w, http.StatusServiceUnavailable, "503 Service Unavailable: the plugin handling this request is not answering, try again later")
}

// writePluginUIError answers a request for the UI of a plugin that cannot be served.
// The answer is shown inside the admin UI (an iframe), so it is a small page, with
// the right status code instead of a JSON error and "200 OK".
func writePluginUIError(w http.ResponseWriter, status int, title string, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><title>` +
		html.EscapeString(title) + `</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:2rem;line-height:1.5}` +
		`main{max-width:38rem}h1{font-size:1.15rem;margin:0 0 .5rem}p{margin:0 0 .5rem}.s{opacity:.7;font-size:.875rem}</style></head><body><main role="alert"><h1>` +
		html.EscapeString(title) + `</h1><p>` + html.EscapeString(detail) + `</p><p class="s">HTTP ` + strconv.Itoa(status) + ` &middot; Plugin Manager shows the status of the plugin.</p></main></body></html>`))
}
