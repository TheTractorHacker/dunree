// Chaos plugin: a fault-injection test fixture for the Zoraxy plugin manager.
//
// It speaks just enough of the plugin contract (-introspect, -configure=<json>,
// UI path with /term, a filter hook, static and dynamic capture) to be started by
// the real lifecycle code, and then misbehaves in the way its mode asks for.
//
// It uses only the Go standard library and builds offline:
//
//	go build -o chaos ./mod/plugins/testdata/chaosplugin     (from src/)
//
// Zoraxy looks for "<folder>/<folder name>" as the entry point, so copy the binary
// to plugins/<name>/<name>. Settings are read from a "chaos.conf" file next to the
// binary (key=value lines), the environment variable CHAOS_MODE overrides "mode".
//
//	mode      one of the modes below (default "ok")
//	delay     duration before / for the fault, e.g. 300ms, 2s (meaning depends on the mode)
//	features  comma list: hooks, static, dynamic, events, failclosed, api (default "hooks,static"), and
//	          health     declares health_path /health and serves it
//	          stdinconf  declares configure_via stdin (secrets not on the command line)
//	          children   starts one child process that outlives the plugin unless Zoraxy ends the process group
//	api_version    declares that plugin contract version in the manifest (default: none = legacy plugin)
//	api_endpoints  permitted API endpoints the manifest asks for, "METHOD /path" separated by ";"
//	               (replaces the single endpoint of the feature "api"). The file is read at every
//	               -introspect, so a test can change it to play an update that asks for more
//	name      display name (default "Chaos <folder>")
//	version   version of the manifest, "major.minor.patch" (default 0.1.0)
//	          adminprobe (feature)  the UI page tries to call the Zoraxy admin API with what it was given
//	                                (see /ui/adminprobe and the script of the page), for the UI isolation tests
//	id, author, author_contact, description   replace that manifest field (for hostile-manifest UI tests)
//
// Modes
//
//	ok              behaves well
//	crash           prints an error and exits with code 3 after delay (default 0 = at start)
//	exit0           exits with code 0 after delay (default 0)
//	hang_start      never opens its port, sleeps forever
//	never_ready     opens the port but never accepts a connection
//	hang            accepts connections, never answers a request
//	slow            answers every request after delay (default 500ms)
//	badjson         the filter answers 200 with a body that is not JSON
//	huge            the filter answers with a 1 MiB body
//	badheader       the filter answers with a verdict that sets a header with an invalid name
//	logflood        writes log lines as fast as it can (and one 1 MiB line without newline)
//	crash_once      like crash, but only the first start (a marker file remembers it); later starts behave well
//	slow_start      opens its port only after delay (default 1s), then behaves well
//	unhealthy       behaves well except that /health answers 500
//	balloon         allocates memory until something stops it (16 MiB every 20 ms)
//	ignore_sigterm  ignores SIGTERM and the /term request
//	introspect_garbage / introspect_hang   break the -introspect call
//
// A binary can carry settings of its own: everything after the last line "##CHAOS-TRAILER##" at the
// end of the executable file is read like chaos.conf and wins over it. The update and rollback tests
// append such a trailer to make "version 2" of a plugin: another checksum, another version, and for
// example mode=crash, while chaos.conf in the plugin folder stays what it was.
//
// Never install this on a real proxy.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var eventsSeen, eventsWithToken atomic.Int64
var balloon [][]byte

type config struct {
	mode         string
	delay        time.Duration
	hasDelay     bool
	features     map[string]bool
	name         string
	folder       string
	manifest     map[string]string //overrides of manifest text fields: id, author, author_contact, description
	apiVersion   int               //api_version of the manifest, 0 = not declared
	apiEndpoints []string          //"METHOD /path"
	version      [3]int            //version of the manifest
}

const trailerMark = "\n##CHAOS-TRAILER##\n"

func loadConfig() config {
	c := config{mode: "ok", features: map[string]bool{"hooks": true, "static": true}, version: [3]int{0, 1, 0}}
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	dir := filepath.Dir(exe)
	c.folder = strings.TrimSuffix(filepath.Base(exe), ".exe")
	c.name = "Chaos " + c.folder
	apply := func(text string) {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "mode":
				c.mode = v
			case "delay":
				if d, err := time.ParseDuration(v); err == nil {
					c.delay, c.hasDelay = d, true
				}
			case "name":
				c.name = v
			case "version":
				parts := strings.SplitN(v, ".", 3)
				for i := 0; i < len(parts) && i < 3; i++ {
					c.version[i], _ = strconv.Atoi(parts[i])
				}
			case "api_version":
				c.apiVersion, _ = strconv.Atoi(v)
			case "api_endpoints":
				for _, ep := range strings.Split(v, ";") {
					if ep = strings.TrimSpace(ep); ep != "" {
						c.apiEndpoints = append(c.apiEndpoints, ep)
					}
				}
			case "id", "author", "author_contact", "description":
				//Lets a test serve a hostile manifest (markup, quotes) to the admin UI
				if c.manifest == nil {
					c.manifest = map[string]string{}
				}
				c.manifest[k] = v
			case "features":
				c.features = map[string]bool{}
				for _, ft := range strings.Split(v, ",") {
					if ft = strings.TrimSpace(ft); ft != "" {
						c.features[ft] = true
					}
				}
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "chaos.conf")); err == nil {
		apply(string(raw))
	}
	//Settings carried by the binary itself (see the package comment)
	if f, err := os.Open(exe); err == nil {
		if st, err := f.Stat(); err == nil {
			n := int64(4096)
			if st.Size() < n {
				n = st.Size()
			}
			tail := make([]byte, n)
			if _, err := f.ReadAt(tail, st.Size()-n); err == nil {
				if i := strings.LastIndex(string(tail), trailerMark); i >= 0 {
					apply(string(tail[i+len(trailerMark):]))
				}
			}
		}
		f.Close()
	}
	if m := os.Getenv("CHAOS_MODE"); m != "" {
		c.mode = m
	}
	return c
}

func (c config) delayOr(def time.Duration) time.Duration {
	if c.hasDelay {
		return c.delay
	}
	return def
}

func introspect(c config) map[string]any {
	spec := map[string]any{
		"id":                      "test.chaos." + strings.ToLower(c.folder),
		"name":                    c.name,
		"author":                  "Zoraxy fork test suite",
		"author_contact":          "https://example.invalid/chaos",
		"description":             "Fault-injection test plugin, mode \"" + c.mode + "\". Not for production.",
		"url":                     "https://example.invalid/chaos",
		"type":                    0,
		"version_major":           c.version[0],
		"version_minor":           c.version[1],
		"version_patch":           c.version[2],
		"ui_path":                 "/ui",
		"static_capture_paths":    []any{},
		"subscriptions_events":    map[string]string{},
		"permitted_api_endpoints": []any{},
	}
	for k, v := range c.manifest {
		spec[k] = v
	}
	if c.features["static"] {
		spec["static_capture_paths"] = []any{map[string]string{"capture_path": "/chaos-static"}}
		spec["static_capture_ingress"] = "/static"
	}
	if c.features["dynamic"] {
		spec["dynamic_capture_sniff"] = "/sniff"
		spec["dynamic_capture_ingress"] = "/ingress"
	}
	if c.features["hooks"] {
		hooks := map[string]any{
			"version":             1,
			"stages":              []string{"pre_auth"},
			"filter_request_path": "/filter",
			"timeout_ms":          300,
		}
		if c.features["failclosed"] {
			hooks["failure_policy"] = "fail_closed"
		}
		spec["hooks"] = hooks
	}
	if c.features["events"] {
		spec["subscription_path"] = "/events"
		spec["subscriptions_events"] = map[string]string{"blacklistedIpBlocked": "chaos test subscription"}
	}
	if c.features["health"] {
		spec["health_path"] = "/health"
	}
	if c.features["stdinconf"] {
		spec["configure_via"] = "stdin"
	}
	if c.features["api"] {
		spec["permitted_api_endpoints"] = []any{map[string]string{"method": "GET", "endpoint": "/plugin/api/access/list", "reason": "chaos test permission"}}
	}
	if len(c.apiEndpoints) > 0 {
		list := []any{}
		for _, ep := range c.apiEndpoints {
			method, path, _ := strings.Cut(ep, " ")
			list = append(list, map[string]string{"method": method, "endpoint": strings.TrimSpace(path), "reason": "chaos test permission"})
		}
		spec["permitted_api_endpoints"] = list
	}
	if c.apiVersion != 0 {
		spec["api_version"] = c.apiVersion
	}
	return spec
}

// adminProbePage is the script of the UI page with the feature "adminprobe": the page
// tries, as hard as a hostile plugin page could, to use the admin session of whoever
// looks at it. It reads the plugin list and turns the plugin safety setting
// "contract_mode" to "refuse" (the test reads that back from the admin API).
const adminProbePage = `<pre id="probe">probing</pre><script>
(async function () {
  var out = {};
  var admin = (location.ancestorOrigins && location.ancestorOrigins.length) ? location.ancestorOrigins[0] : location.origin;
  var tok = "";
  try { var h = await (await fetch("headers")).json(); tok = h.csrf || ""; out.cookieSeen = !!h.cookie; out.csrfSeen = !!h.csrf; out.isolated = h.isolated || ""; } catch (e) { out.headers = "failed"; }
  try { var r = await fetch(admin + "/api/plugins/list", { credentials: "include" }); out.read = r.status; } catch (e) { out.read = "blocked"; }
  try {
    var w = await fetch(admin + "/api/plugins/settings", { method: "POST", credentials: "include",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": tok }, body: "contract_mode=refuse" });
    out.write = w.status;
  } catch (e) { out.write = "blocked"; }
  try { await fetch(admin + "/api/plugins/settings", { method: "POST", mode: "no-cors", credentials: "include", body: new URLSearchParams({ contract_mode: "refuse" }) }); out.nocors = "sent"; } catch (e) { out.nocors = "blocked"; }
  try { out.cookieJS = document.cookie.length; } catch (e) { out.cookieJS = "denied"; }
  document.getElementById("probe").textContent = JSON.stringify(out);
})();
</script>`

// sleepForever blocks without tripping the "all goroutines are asleep" check of the Go runtime
func sleepForever() {
	for {
		time.Sleep(time.Hour)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-chaos-child" {
		//Child of a chaos plugin with the feature "children": just stays around
		os.WriteFile("child.pid", []byte(strconv.Itoa(os.Getpid())), 0o644)
		sleepForever()
	}
	c := loadConfig()

	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		switch c.mode {
		case "introspect_garbage":
			fmt.Println("<html>this is not a manifest</html>")
			os.Exit(0)
		case "introspect_hang":
			sleepForever()
		}
		js, _ := json.MarshalIndent(introspect(c), "", " ")
		fmt.Println(string(js))
		os.Exit(0)
	}

	var conf struct {
		Port        int    `json:"port"`
		InvokeToken string `json:"invoke_token"`
	}
	for _, arg := range os.Args[1:] {
		if arg == "-configure-stdin" {
			raw, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
			if err := json.Unmarshal(raw, &conf); err != nil {
				fmt.Fprintln(os.Stderr, "chaos: bad configure payload on stdin:", err)
				os.Exit(64)
			}
			os.WriteFile("last-configure.json", raw, 0o600)
		}
		if strings.HasPrefix(arg, "-configure=") {
			raw := []byte(arg[len("-configure="):])
			if err := json.Unmarshal(raw, &conf); err != nil {
				fmt.Fprintln(os.Stderr, "chaos: bad -configure payload:", err)
				os.Exit(64)
			}
			//Tests read what Zoraxy handed over (port, API key) from this file
			os.WriteFile("last-configure.json", raw, 0o600)
		}
	}
	if conf.Port == 0 {
		fmt.Fprintln(os.Stderr, "chaos: no -configure flag with a port")
		os.Exit(64)
	}
	fmt.Printf("chaos: starting in mode %q on port %d\n", c.mode, conf.Port)
	if c.features["children"] {
		if exe, err := os.Executable(); err == nil {
			child := exec.Command(exe, "-chaos-child")
			child.Dir = filepath.Dir(exe)
			if err := child.Start(); err != nil {
				fmt.Fprintln(os.Stderr, "chaos: cannot start the child:", err)
			}
		}
	}
	if c.mode == "crash_once" {
		if _, err := os.Stat("crashed-once"); err != nil {
			os.WriteFile("crashed-once", []byte("1"), 0o644)
			c.mode = "crash"
		} else {
			c.mode = "ok"
		}
	}

	switch c.mode {
	case "crash":
		go func() {
			time.Sleep(c.delayOr(0))
			fmt.Fprintln(os.Stderr, "chaos: fatal: simulated crash")
			os.Exit(3)
		}()
		if !c.hasDelay || c.delay == 0 {
			sleepForever()
		}
	case "exit0":
		go func() {
			time.Sleep(c.delayOr(0))
			fmt.Println("chaos: work done, exiting cleanly")
			os.Exit(0)
		}()
		if !c.hasDelay || c.delay == 0 {
			sleepForever()
		}
	case "hang_start":
		sleepForever()
	case "slow_start":
		time.Sleep(c.delayOr(time.Second))
	case "balloon":
		go func() {
			for {
				b := make([]byte, 16<<20)
				for i := 0; i < len(b); i += 4096 {
					b[i] = 1 //touch every page so the memory is really used
				}
				balloon = append(balloon, b)
				time.Sleep(20 * time.Millisecond)
			}
		}()
	case "ignore_sigterm":
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
	case "logflood":
		go func() {
			big := strings.Repeat("x", 1<<20)
			fmt.Print(big) //one very long line without a newline
			fmt.Println()
			for i := 0; ; i++ {
				fmt.Printf("chaos: flood line %d %s\n", i, strings.Repeat("=", 80))
				if i%2 == 0 {
					fmt.Fprintf(os.Stderr, "chaos: flood error line %d\n", i)
				}
			}
		}()
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", conf.Port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "chaos: cannot listen:", err)
		os.Exit(65)
	}
	if c.mode == "never_ready" {
		sleepForever() //port is open, nothing is ever accepted
	}

	misbehave := func(w http.ResponseWriter, r *http.Request) bool {
		switch c.mode {
		case "hang":
			select {
			case <-r.Context().Done():
			case <-time.After(time.Hour):
			}
			return true
		case "slow":
			time.Sleep(c.delayOr(500 * time.Millisecond))
		}
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ui/term", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if c.mode == "ignore_sigterm" {
			return
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			os.Exit(0)
		}()
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if misbehave(w, r) {
			return
		}
		if c.mode == "unhealthy" {
			http.Error(w, "not well", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/ui/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"events":%d,"events_with_token":%d}`, eventsSeen.Load(), eventsWithToken.Load())
	})
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		if misbehave(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Chaos</title><body style=\"font-family:sans-serif\"><h3>Chaos plugin</h3><p>Mode: %s</p><p id=\"ver\">Version: %d.%d.%d</p>", c.mode, c.version[0], c.version[1], c.version[2])
		if c.features["adminprobe"] {
			io.WriteString(w, adminProbePage)
		}
		io.WriteString(w, "</body>")
	})
	// What Zoraxy handed to the plugin with a request for its page: the admin session
	// cookie and the CSRF token of the admin (or nothing, with the isolated plugin UI)
	mux.HandleFunc("/ui/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "chaosplanted=1; Path=/") //a plugin that plants a cookie for the host of the admin UI
		js, _ := json.Marshal(map[string]string{
			"cookie":   r.Header.Get("Cookie"),
			"csrf":     r.Header.Get("X-Zoraxy-Csrf"),
			"auth":     r.Header.Get("Authorization"),
			"isolated": r.Header.Get("X-Zoraxy-Ui-Isolated"),
		})
		w.Write(js)
	})
	// The plugin process itself calls an admin API (?url=) with the cookie and the CSRF
	// token it was handed with this request, and answers with the status it got
	mux.HandleFunc("/ui/adminprobe", func(w http.ResponseWriter, r *http.Request) {
		if !c.features["adminprobe"] {
			http.NotFound(w, r)
			return
		}
		req, err := http.NewRequest(http.MethodPost, r.URL.Query().Get("url"), strings.NewReader("probe=1"))
		if err != nil {
			http.Error(w, "bad url", http.StatusBadRequest)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if v := r.Header.Get("Cookie"); v != "" {
			req.Header.Set("Cookie", v)
		}
		if v := r.Header.Get("X-Zoraxy-Csrf"); v != "" {
			req.Header.Set("X-CSRF-Token", v)
		}
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			fmt.Fprint(w, "error")
			return
		}
		resp.Body.Close()
		fmt.Fprint(w, resp.StatusCode)
	})
	mux.HandleFunc("/filter", func(w http.ResponseWriter, r *http.Request) {
		if misbehave(w, r) {
			return
		}
		switch c.mode {
		case "badjson":
			w.Write([]byte("{this is not json"))
		case "badheader":
			//A verdict Zoraxy rejects, with a header name chosen by the plugin
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":1,"action":"modify","modify":{"request_headers":{"set":{"X-Leak <b>from-plugin</b>":"1"}}}}`))
		case "huge":
			w.Write([]byte(`{"action":"allow","reason":"` + strings.Repeat("A", 1<<20) + `"}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"action":"allow"}`))
		}
	})
	mux.HandleFunc("/sniff/", func(w http.ResponseWriter, r *http.Request) {
		if misbehave(w, r) {
			return
		}
		w.WriteHeader(284) //unhandled: let Zoraxy continue
	})
	capture := func(w http.ResponseWriter, r *http.Request) {
		if misbehave(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "captured by chaos plugin")
	}
	mux.HandleFunc("/static/", capture)
	mux.HandleFunc("/ingress/", capture)
	mux.HandleFunc("/events/", func(w http.ResponseWriter, r *http.Request) {
		if misbehave(w, r) {
			return
		}
		eventsSeen.Add(1)
		if conf.InvokeToken != "" && r.Header.Get("X-Zoraxy-Plugin-Token") == conf.InvokeToken {
			eventsWithToken.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})

	fmt.Println("chaos: ready")
	if err := http.Serve(ln, mux); err != nil {
		fmt.Fprintln(os.Stderr, "chaos: server stopped:", err)
		os.Exit(66)
	}
}
