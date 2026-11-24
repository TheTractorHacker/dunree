package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	plugin "example.com/dunree/fork-ref-ui-api/mod/dunree_plugin"
)

/*
	Fork reference plugin: page and Dunree API

	The smallest plugin with a page of its own that calls the Dunree plugin API. It
	asks for exactly two endpoints, one that reads and one that writes. It is a
	reference and a test fixture (the conformance kit tools/plugin-check, the
	permission tests and the page isolation tests run against it), not a feature.

	- read:  GET  /plugin/api/access/list        at start (once it is answered) and with the button "Read"
	- write: POST /plugin/api/blacklist/ip/add   ONLY when the administrator fills in the
	         form on the page and presses "Add". Nothing is ever written by itself.

	What it shows
	- start configuration on standard input: the API key is not on the command line
	- the page only talks to the plugin (relative addresses), never to the admin API
	  of Dunree. It therefore keeps working when the administrator turns plugin
	  page isolation on
	- the API key stays in the plugin process and is never sent to the browser
	- the write needs a POST with a value from the page of this start, and the
	  address is checked by the plugin before it is passed on
	- what Dunree answers is shown as text, never as markup

	What it does NOT show: authentication. The port of a plugin is a loopback port
	without a login. Dunree's admin login guards the way through the admin address
	only; any user or process on the same host can call the plugin directly, read
	the page (and the value in it) and press the same buttons with the API key of
	the plugin. The contract gives a plugin nothing to tell the two apart (the page
	proxy carries no secret). So this reference keeps what such a caller can reach
	harmless by construction, and a real plugin has to do the same:
	- the write takes documentation addresses only (RFC 5737 and RFC 3849: they are
	  never routed, so blocking them blocks nobody), at most maxWrites per start
	- the read hands out a number, not the access rules
	The page value only stops another web page in the browser of the administrator
	from posting the form (cross-site request forgery).
*/

const (
	uiPath     = "/ui"
	healthPath = "/health"
	readAPI    = "/plugin/api/access/list"
	writeAPI   = "/plugin/api/blacklist/ip/add"
	maxAnswer  = 256 << 10
	maxWrites  = 16 //writes passed on to Dunree per start
)

// The only addresses the write passes on: the documentation ranges, which are never routed
var documentationRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// documentationAddress reports whether addr (an address or a CIDR range) lies
// completely inside one of the documentation ranges. 0.0.0.0/0, a private range
// or a real address is refused: anybody on the host can reach this plugin.
func documentationAddress(addr string) bool {
	ip := net.ParseIP(addr)
	ones := -1
	if ip == nil {
		parsed, n, err := net.ParseCIDR(addr)
		if err != nil || !parsed.Equal(n.IP) {
			return false
		}
		ip = n.IP
		ones, _ = n.Mask.Size()
	}
	for _, doc := range documentationRanges {
		docOnes, docBits := doc.Mask.Size()
		if (ip.To4() != nil) != (docBits == 32) {
			continue
		}
		if doc.Contains(ip) && (ones == -1 || ones >= docOnes) {
			return true
		}
	}
	return false
}

// countRules turns the answer of the read into a number: the rules themselves are
// not handed to whoever asks the plugin
func countRules(r apiResult) apiResult {
	if r.OK {
		var list []json.RawMessage
		if err := json.Unmarshal([]byte(r.Body), &list); err == nil {
			r.Body = strconv.Itoa(len(list)) + " access rules"
		} else {
			r.Body = "an answer that is not a list"
		}
	} else {
		r.Body = ""
	}
	return r
}

type apiResult struct {
	OK     bool   `json:"ok"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error,omitempty"`
	At     string `json:"at"`
}

var client = &http.Client{
	Timeout:       5 * time.Second,
	Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// callDunree makes one call to the Dunree plugin API with the key of this start
func callDunree(cfg *plugin.ConfigureSpec, method, endpoint string, form url.Values) apiResult {
	res := apiResult{At: time.Now().UTC().Format(time.RFC3339)}
	if cfg.APIKey == "" || cfg.DunreePort == 0 {
		res.Error = "Dunree handed no API key to this plugin"
		return res
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, "http://127.0.0.1:"+strconv.Itoa(cfg.DunreePort)+endpoint, body)
	if err != nil {
		res.Error = "request could not be built"
		return res
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Error = "Dunree did not answer"
		return res
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	res.Status, res.Body = resp.StatusCode, string(raw)
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 300
	return res
}

func main() {
	cfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            "fork.zoraxy.ref.ui-api",
		Name:          "Fork Reference Page and API",
		Author:        "Dunree fork",
		AuthorContact: "see the repository of the fork",
		Description:   "Reference plugin and test fixture with a page and two Dunree API permissions: it reads the access rules and adds an address to a blacklist when you ask it to. Not a feature.",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  1,
		UIPath:        uiPath,
		HealthPath:    healthPath,
		ConfigureVia:  plugin.ConfigureViaStdin,
		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{Method: http.MethodGet, Endpoint: readAPI, Reason: "Shows how many access rules exist (read only)"},
			{Method: http.MethodPost, Endpoint: writeAPI, Reason: "Adds one address to the blacklist of an access rule, only when you press Add on the page of the plugin"},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-ui-api: no start configuration:", err)
		os.Exit(64)
	}

	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-ui-api: no random numbers:", err)
		os.Exit(67)
	}
	nonce := hex.EncodeToString(nonceRaw)

	var mu sync.Mutex
	writes := 0
	startCheck := apiResult{Error: "not done yet"}
	go func() {
		//One read at start: tells the administrator at once whether the permission works.
		//At a start of Dunree itself plugins are started before its API listens, so an
		//unanswered call is tried again for a while (once a second, at most 30 times).
		r := callDunree(cfg, http.MethodGet, readAPI, nil)
		for try := 0; try < 30 && r.Status == 0 && cfg.APIKey != ""; try++ {
			time.Sleep(time.Second)
			r = callDunree(cfg, http.MethodGet, readAPI, nil)
		}
		r.Body = "" //only the outcome is kept
		mu.Lock()
		startCheck = r
		mu.Unlock()
	}()

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		json.NewEncoder(w).Encode(v)
	}

	stop := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.Handle(healthPath, plugin.HealthHandler(nil))
	mux.HandleFunc(uiPath+"/term", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case stop <- struct{}{}:
		default:
		}
	})
	mux.HandleFunc(uiPath+"/api/status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, startCheck)
	})
	mux.HandleFunc(uiPath+"/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, countRules(callDunree(cfg, http.MethodGet, readAPI, nil)))
	})
	mux.HandleFunc(uiPath+"/api/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Fork-Ref-Nonce")), []byte(nonce)) != 1 {
			http.Error(w, "reload the page of the plugin and try again", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		addr := strings.TrimSpace(r.PostForm.Get("ip"))
		rule := strings.TrimSpace(r.PostForm.Get("id"))
		if rule == "" {
			rule = "default"
		}
		if !documentationAddress(addr) {
			writeJSON(w, apiResult{Error: "only documentation addresses are accepted (inside 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 or 2001:db8::/32): this is a reference plugin, and its port has no login", At: time.Now().UTC().Format(time.RFC3339)})
			return
		}
		if len(rule) > 128 || strings.ContainsAny(rule, "/\\ \t\r\n") {
			writeJSON(w, apiResult{Error: "not an access rule ID", At: time.Now().UTC().Format(time.RFC3339)})
			return
		}
		mu.Lock()
		writes++
		over := writes > maxWrites
		mu.Unlock()
		if over {
			writeJSON(w, apiResult{Error: "this start of the plugin has passed on " + strconv.Itoa(maxWrites) + " writes, which is its limit. Restart the plugin for more", At: time.Now().UTC().Format(time.RFC3339)})
			return
		}
		//Not "the administrator": the port has no login, any local process can make this request
		fmt.Printf("fork-ref-ui-api: adding the documentation address %s to the blacklist of access rule %q, asked for on the plugin port (no login: the admin page or any local process)\n", addr, rule)
		writeJSON(w, callDunree(cfg, http.MethodPost, writeAPI+"?comment="+url.QueryEscape("added with the fork reference plugin"), url.Values{"ip": {addr}, "id": {rule}}))
	})
	mux.HandleFunc(uiPath+"/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != uiPath+"/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		//The CSRF token of the admin page: Dunree asks for it on a POST below the admin
		//address. It is empty (and not needed) when plugin pages are isolated.
		p := strings.ReplaceAll(page, "{{nonce}}", nonce)
		p = strings.ReplaceAll(p, "{{csrf}}", html.EscapeString(plugin.HostHeader(r, "Csrf")))
		io.WriteString(w, p)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(cfg.Port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-ui-api: cannot listen:", err)
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
		fmt.Println("fork-ref-ui-api: stopping")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	fmt.Println("fork-ref-ui-api: listening on " + ln.Addr().String())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "fork-ref-ui-api: server stopped:", err)
		os.Exit(66)
	}
}

const page = `<!doctype html><meta charset="utf-8"><title>Fork Reference Page and API</title>
<meta name="fork-ref-nonce" content="{{nonce}}"><meta name="dunree-csrf" content="{{csrf}}">
<body style="font-family:sans-serif;max-width:44em;margin:2em">
<h3>Fork Reference Page and API</h3>
<p>Reference plugin and test fixture. It may count the access rules and add a documentation address (one that is never routed) to a blacklist. It only writes when asked to on this page.</p>
<p>The port of a plugin has no login: every user and process on the host of Dunree can ask this plugin for the same. That is why it accepts documentation addresses only.</p>
<p id="start">Check at start: loading</p>
<h4>Read</h4>
<p><button id="read" type="button">Count the access rules</button></p>
<pre id="readout" style="white-space:pre-wrap;word-break:break-all;background:#8881;padding:8px;max-height:16em;overflow:auto"></pre>
<h4>Write</h4>
<form id="block">
<p><label>Address or range <input name="ip" value="192.0.2.1" required maxlength="64"></label>
<label>Access rule ID <input name="id" value="default" maxlength="128"></label>
<button type="submit">Add to the blacklist</button></p>
</form>
<pre id="writeout" style="white-space:pre-wrap;word-break:break-all;background:#8881;padding:8px"></pre>
<script>
function meta(name) { var m = document.querySelector('meta[name="' + name + '"]'); return m ? m.content : ""; }
function show(id, r) {
  var text = r.error ? "Failed: " + r.error : "HTTP " + r.status + (r.ok ? " (accepted)" : " (refused)") + "\n" + r.body;
  document.getElementById(id).textContent = text;
}
fetch("api/status").then(function (r) { return r.json(); }).then(function (s) {
  document.getElementById("start").textContent = "Check at start: " + (s.error ? s.error : (s.ok ? "the read permission works" : "Dunree answered HTTP " + s.status + ": the read permission is not granted"));
}).catch(function () { document.getElementById("start").textContent = "Check at start: the plugin did not answer"; });
document.getElementById("read").addEventListener("click", function () {
  fetch("api/rules").then(function (r) { return r.json(); }).then(function (r) { show("readout", r); })
    .catch(function () { document.getElementById("readout").textContent = "The plugin did not answer."; });
});
document.getElementById("block").addEventListener("submit", function (ev) {
  ev.preventDefault();
  var headers = { "Content-Type": "application/x-www-form-urlencoded", "X-Fork-Ref-Nonce": meta("fork-ref-nonce") };
  if (meta("dunree-csrf")) { headers["X-CSRF-Token"] = meta("dunree-csrf"); }
  fetch("api/block", { method: "POST", headers: headers, body: new URLSearchParams(new FormData(ev.target)).toString() })
    .then(function (r) { if (!r.ok) { return r.text().then(function (t) { return { error: t }; }); } return r.json(); })
    .then(function (r) { show("writeout", r); })
    .catch(function () { document.getElementById("writeout").textContent = "The plugin did not answer."; });
});
</script></body>`
