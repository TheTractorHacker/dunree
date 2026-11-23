// implements `eventsystem.Listener` for Plugin

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/eventsystem"
	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin/events"
)

/*
	Event delivery to plugins

	Events used to be sent with one goroutine, one new HTTP client and one 10 s
	wait per event, without any limit: a plugin that answers slowly while events
	arrive fast (one per blocked request) piled up goroutines and connections in
	Zoraxy. Now every plugin has one queue of at most eventQueueMax events and one
	worker that sends them in order. When the queue is full the oldest waiting
	event is dropped and counted. Problems are logged at most once per minute per
	plugin, not once per event.
*/

const (
	eventQueueMax    = 1000
	eventSendTimeout = 10 * time.Second
	eventLogEvery    = time.Minute
)

// eventHTTPClient is shared by all event deliveries: no proxy, no redirects, a few kept connections
var eventHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// eventQueue is a bounded FIFO of events for one plugin
type eventQueue struct {
	mu      sync.Mutex
	buf     []events.Event //ring, allocated on first use
	head    int
	n       int
	working bool //the worker goroutine of this queue is running
	max     int  //tests only, 0 = eventQueueMax
}

func (q *eventQueue) capacity() int { return intOr(q.max, eventQueueMax) }

func (q *eventQueue) length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// push adds an event. dropped is true when the oldest waiting event had to make
// room; start is true when the caller has to start the worker.
func (q *eventQueue) push(ev events.Event) (dropped bool, start bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.buf == nil || len(q.buf) != q.capacity() {
		//First use (or a test changed the size while the queue was empty)
		q.buf = make([]events.Event, q.capacity())
		q.head, q.n = 0, 0
	}
	if q.n == len(q.buf) {
		q.buf[q.head] = events.Event{}
		q.head = (q.head + 1) % len(q.buf)
		q.n--
		dropped = true
	}
	q.buf[(q.head+q.n)%len(q.buf)] = ev
	q.n++
	if !q.working {
		q.working = true
		start = true
	}
	return dropped, start
}

// pop takes the oldest event. When the queue is empty it marks the worker as stopped.
func (q *eventQueue) pop() (events.Event, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		q.working = false
		return events.Event{}, false
	}
	ev := q.buf[q.head]
	q.buf[q.head] = events.Event{}
	q.head = (q.head + 1) % len(q.buf)
	q.n--
	return ev, true
}

// clear drops everything that is waiting (the plugin process is gone) and counts it
func (q *eventQueue) clear(obs *pluginObserved) {
	q.mu.Lock()
	n := q.n
	for i := range q.buf {
		q.buf[i] = events.Event{}
	}
	q.head, q.n = 0, 0
	q.mu.Unlock()
	if n > 0 {
		obs.eventsDropped.Add(int64(n))
	}
}

func (p *Plugin) GetID() eventsystem.ListenerID {
	return eventsystem.ListenerID(p.Spec.ID)
}

// Notify queues an event for the plugin. It returns at once: the event is sent by
// the worker of the plugin. An error means the event was not queued.
func (p *Plugin) Notify(event events.Event) error {
	p.mu.RLock()
	enabled, port := p.Enabled, p.AssignedPort
	p.mu.RUnlock()
	if !enabled || port == 0 {
		return fmt.Errorf("plugin %s is not running", p.Spec.ID)
	}
	if p.Spec.SubscriptionPath == "" {
		return fmt.Errorf("plugin %s has no subscription path configured", p.Spec.ID)
	}
	dropped, start := p.evq.push(event)
	if dropped {
		p.obs.eventsDropped.Add(1)
		p.eventProblem("the event queue of the plugin is full (" + fmt.Sprint(p.evq.capacity()) + "), the oldest waiting events are dropped")
	}
	if start {
		go p.eventWorker()
	}
	return nil
}

// eventWorker sends the queued events one after the other and ends when the queue is empty
func (p *Plugin) eventWorker() {
	for {
		ev, ok := p.evq.pop()
		if !ok {
			return
		}
		if err := p.sendEvent(ev); err != nil {
			p.obs.eventsFailed.Add(1)
			p.eventProblem("sending the event `" + string(ev.Name) + "` failed: " + err.Error())
		} else {
			p.obs.eventsSent.Add(1)
			p.noteAlive()
		}
	}
}

// eventProblem logs a problem with the events of this plugin, at most once per minute
func (p *Plugin) eventProblem(msg string) {
	now := time.Now().UnixNano()
	last := p.obs.eventLogAt.Load()
	if last != 0 && time.Duration(now-last) < eventLogEvery {
		return
	}
	if !p.obs.eventLogAt.CompareAndSwap(last, now) {
		return
	}
	c := p.counters()
	text := fmt.Sprintf("events for plugin %s: %s (sent %d, failed %d, dropped %d since Zoraxy started; further problems are not logged for %s)",
		p.Spec.ID, msg, c.EventsSent, c.EventsFailed, c.EventsDropped, eventLogEvery)
	p.mu.RLock()
	mgr := p.mgr
	p.mu.RUnlock()
	if mgr != nil && mgr.Options != nil && mgr.Options.Logger != nil {
		mgr.Log(text, nil)
	}
}

// sendEvent delivers one event to the running process of the plugin
func (p *Plugin) sendEvent(event events.Event) error {
	p.mu.RLock()
	enabled, port, proc := p.Enabled, p.AssignedPort, p.proc
	p.mu.RUnlock()
	if !enabled || port == 0 || proc == nil {
		return fmt.Errorf("the plugin is not running")
	}

	subscriptionPath := p.Spec.SubscriptionPath
	if !strings.HasPrefix(subscriptionPath, "/") {
		subscriptionPath = "/" + subscriptionPath
	}
	subscriptionPath = strings.TrimSuffix(subscriptionPath, "/")
	url := fmt.Sprintf("http://127.0.0.1:%d%s/%s", port, subscriptionPath, event.Name)

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Bound to the process: when it ends, a delivery that is still waiting ends too
	ctx, cancel := context.WithTimeout(proc.ctx, eventSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(eventData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Zoraxy-Event-Type", string(event.Name))
	if tok := p.invokeToken(); tok != "" {
		//Lets the plugin tell an event from Zoraxy from one faked by another local process
		req.Header.Set(zoraxyPlugin.InvokeTokenHeader, tok)
	}

	resp, err := eventHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)) //so the connection can be reused
	if resp.StatusCode != http.StatusOK {
		//The body of the answer is chosen by the plugin: it is not put into the log
		return fmt.Errorf("the plugin answered %s", resp.Status)
	}
	return nil
}
