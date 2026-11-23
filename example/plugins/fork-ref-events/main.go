package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	plugin "example.com/zoraxy/fork-ref-events/mod/zoraxy_plugin"
)

/*
	Fork reference plugin: events

	The smallest plugin that subscribes to Zoraxy events the way the fork recommends.
	It is a reference and a test fixture (the conformance kit tools/plugin-check and
	the event back-pressure tests run against it), not a feature. It counts the
	events it gets and shows the last few.

	What it shows
	- the event path requires the invoke token: another local process cannot fake events
	- every event is acknowledged at once and worked on later. Zoraxy delivers events
	  to a plugin one at a time and keeps at most 1000 waiting, so a plugin that
	  works before it answers makes Zoraxy drop events
	- the waiting list of the plugin itself is bounded (256). When it is full the
	  OLDEST event is dropped and counted, so memory stays flat under an event storm
	- one log line per minute at most about dropped events, none per event

	FORK_REF_EVENTS_WORK_MS (environment, default 0) makes the worker take that many
	milliseconds per event. It exists for the back-pressure tests.
*/

const (
	uiPath     = "/ui"
	healthPath = "/health"
	eventPath  = "/events"
	queueSize  = 256
	maxEvent   = 64 << 10
	keepLast   = 20
)

type item struct {
	name string
	body []byte
	at   time.Time
}

type summary struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	At   string `json:"at"`
}

type state struct {
	mu        sync.Mutex
	received  int64
	processed int64
	dropped   int64
	byName    map[string]int64
	last      []summary
	queue     chan item
}

func (s *state) enqueue(it item) {
	s.mu.Lock()
	s.received++
	s.mu.Unlock()
	for {
		select {
		case s.queue <- it:
			return
		default:
		}
		//Full: make room by dropping the oldest event that is waiting
		select {
		case <-s.queue:
			s.mu.Lock()
			s.dropped++
			s.mu.Unlock()
		default:
		}
	}
}

func (s *state) work(delay time.Duration) {
	for it := range s.queue {
		if delay > 0 {
			time.Sleep(delay)
		}
		var ev struct {
			UUID string `json:"uuid"`
		}
		json.Unmarshal(it.body, &ev) //an event this plugin cannot read is still counted
		if len(ev.UUID) > 64 {
			ev.UUID = ev.UUID[:64]
		}
		s.mu.Lock()
		s.processed++
		s.byName[it.name]++
		s.last = append(s.last, summary{Name: it.name, UUID: ev.UUID, At: it.at.UTC().Format(time.RFC3339)})
		if len(s.last) > keepLast {
			s.last = s.last[len(s.last)-keepLast:]
		}
		s.mu.Unlock()
	}
}

func (s *state) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := map[string]int64{}
	for k, v := range s.byName {
		names[k] = v
	}
	return map[string]any{
		"received": s.received, "processed": s.processed, "dropped": s.dropped,
		"queued": len(s.queue), "queue_size": queueSize, "by_name": names,
		"last": append([]summary{}, s.last...),
	}
}

func main() {
	subscriptions := map[string]string{
		"blacklistedIpBlocked": "counted and listed on the page of the plugin",
		"blacklistToggled":     "counted and listed on the page of the plugin",
		"accessRuleCreated":    "counted and listed on the page of the plugin",
	}
	cfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:                  "fork.zoraxy.ref.events",
		Name:                "Fork Reference Events",
		Author:              "Zoraxy fork",
		AuthorContact:       "see the repository of the fork",
		Description:         "Reference event subscriber and test fixture: counts the events Zoraxy sends, with a bounded waiting list. Not a feature.",
		Type:                plugin.PluginType_Utilities,
		VersionMajor:        1,
		UIPath:              uiPath,
		HealthPath:          healthPath,
		ConfigureVia:        plugin.ConfigureViaStdin,
		SubscriptionPath:    eventPath,
		SubscriptionsEvents: subscriptions,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-events: no start configuration:", err)
		os.Exit(64)
	}

	st := &state{byName: map[string]int64{}, queue: make(chan item, queueSize)}
	workMs, _ := strconv.Atoi(os.Getenv("FORK_REF_EVENTS_WORK_MS"))
	if workMs < 0 || workMs > 10000 {
		workMs = 0
	}
	go st.work(time.Duration(workMs) * time.Millisecond)
	go func() {
		var reported int64
		for range time.Tick(time.Minute) {
			st.mu.Lock()
			d := st.dropped
			st.mu.Unlock()
			if d != reported {
				fmt.Printf("fork-ref-events: %d events dropped so far because the waiting list (%d) was full\n", d, queueSize)
				reported = d
			}
		}
	}()

	stop := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.Handle(eventPath+"/", plugin.RequireInvokeToken(cfg.InvokeToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, eventPath), "/")
		if _, known := subscriptions[name]; !known {
			http.Error(w, "not subscribed", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxEvent+1))
		if err != nil || len(body) > maxEvent {
			http.Error(w, "event too large", http.StatusRequestEntityTooLarge)
			return
		}
		st.enqueue(item{name: name, body: body, at: time.Now()})
		w.WriteHeader(http.StatusOK) //acknowledged; the work happens in the worker
	})))
	mux.Handle(healthPath, plugin.HealthHandler(nil))
	mux.HandleFunc(uiPath+"/term", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case stop <- struct{}{}:
		default:
		}
	})
	mux.HandleFunc(uiPath+"/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(st.snapshot())
	})
	mux.HandleFunc(uiPath+"/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, page)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(cfg.Port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-events: cannot listen:", err)
		os.Exit(65)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		select {
		case <-sig:
		case <-stop:
		}
		fmt.Println("fork-ref-events: stopping")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	fmt.Println("fork-ref-events: listening on " + ln.Addr().String())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "fork-ref-events: server stopped:", err)
		os.Exit(66)
	}
}

// The page only talks to the plugin itself (a relative address), so it also works
// when the administrator turned plugin page isolation on. Event data is written
// with textContent: an event carries text chosen by visitors (URL, User-Agent).
const page = `<!doctype html><meta charset="utf-8"><title>Fork Reference Events</title>
<body style="font-family:sans-serif;max-width:44em;margin:2em">
<h3>Fork Reference Events</h3>
<p>Reference plugin and test fixture. It counts the events Zoraxy sends and keeps the last 20.</p>
<p id="counts">Loading</p>
<table id="last" style="border-collapse:collapse"></table>
<script>
function cell(row, text) { var td = document.createElement("td"); td.style.padding = "2px 12px 2px 0"; td.textContent = text; row.appendChild(td); }
function load() {
  fetch("stats").then(function (r) { return r.json(); }).then(function (s) {
    document.getElementById("counts").textContent = "Received " + s.received + ", worked on " + s.processed +
      ", waiting " + s.queued + " of " + s.queue_size + ", dropped " + s.dropped + ".";
    var table = document.getElementById("last"); table.textContent = "";
    (s.last || []).slice().reverse().forEach(function (e) { var tr = document.createElement("tr"); cell(tr, e.at); cell(tr, e.name); cell(tr, e.uuid); table.appendChild(tr); });
  }).catch(function () { document.getElementById("counts").textContent = "The plugin did not answer."; });
}
load(); setInterval(load, 5000);
</script></body>`
