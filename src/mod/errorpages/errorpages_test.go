package errorpages

import (
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestManager(t *testing.T) (*Manager, *[]string) {
	t.Helper()
	logs := &[]string{}
	m := NewManager(filepath.Join(t.TempDir(), FileName), func(s string) { *logs = append(*logs, s) })
	m.now = func() time.Time { return time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC) }
	return m, logs
}

func mustSet(t *testing.T, m *Manager, cfg *Config) {
	t.Helper()
	if err := m.Set(cfg); err != nil {
		t.Fatal(err)
	}
}

// Nothing saved: no class, no host ever gets a customised page
func TestDefaultIsOff(t *testing.T) {
	m, _ := newTestManager(t)
	if m.Active() {
		t.Fatal("a fresh manager must be inactive")
	}
	for _, ci := range Classes() {
		if m.Has(ci.ID, "app.example.com") {
			t.Fatalf("class %s is customised without a saved config", ci.ID)
		}
		if body, ok := m.Render(Request{Class: ci.ID, Status: ci.SampleStatus, Host: "app.example.com"}); ok || body != nil {
			t.Fatalf("class %s rendered without a saved config", ci.ID)
		}
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("a fresh manager must not create the file")
	}
	var nilMgr *Manager
	if nilMgr.Active() || nilMgr.Has(ClassForbidden, "x") {
		t.Fatal("a nil manager must be inactive")
	}
	if _, ok := nilMgr.Render(Request{Class: ClassForbidden}); ok {
		t.Fatal("a nil manager must not render")
	}
}

// A saved customisation that is not switched on changes nothing; switched on, only the touched classes change
func TestOnlyTouchedClassesChange(t *testing.T) {
	m, _ := newTestManager(t)
	cfg := DefaultConfig()
	cfg.Pages[ClassForbidden] = &Page{Title: "Stop"}
	mustSet(t, m, cfg)
	if m.Active() || m.Has(ClassForbidden, "a") {
		t.Fatal("saved but not enabled must stay off")
	}
	cfg.Enabled = true
	mustSet(t, m, cfg)
	if !m.Has(ClassForbidden, "a") {
		t.Fatal("403 should be customised")
	}
	for _, c := range []Class{ClassNotFound, ClassRateLimit, ClassServerError, ClassNoHost, ClassMaintenance} {
		if m.Has(c, "a") {
			t.Fatalf("class %s was not touched and must stay built-in", c)
		}
	}
	cfg.Theme.ApplyToBuiltin = true
	mustSet(t, m, cfg)
	for _, ci := range Classes() {
		body, ok := m.Render(Request{Class: ci.ID, Status: ci.SampleStatus, Host: "a.example.com"})
		if !ok || !strings.Contains(string(body), "<h1>") {
			t.Fatalf("class %s should use the themed built-in page", ci.ID)
		}
	}
}

func TestRenderValuesAndEscaping(t *testing.T) {
	m, _ := newTestManager(t)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Theme.LogoText = `Acme <b>& Co</b>`
	cfg.Theme.FooterText = `</footer><script>alert(1)</script>`
	cfg.Theme.AccentColor = "#ff0000"
	cfg.Pages[ClassForbidden] = &Page{Title: `<img src=x onerror=alert(1)>`, Message: "line one\nline <two>",
		Template: `<html><head><style>a{color:{{.Theme.Accent}}}</style></head><body data-host="{{.Host}}"><a href="/?h={{.Host}}">x</a>` +
			`<h1>{{.Status}} {{.StatusText}} {{.Title}}</h1><p>{{.Message}}</p><i>{{.Host}}</i><u>{{.RequestID}}</u><s>{{.ClientIP}}</s><b>{{.Time}}</b>` +
			`<em>{{.Theme.LogoText}}</em><footer>{{.Theme.FooterText}}</footer></body></html>`}
	mustSet(t, m, cfg)
	hostile := `"><script>alert('h')</script>.example.com`
	body, ok := m.Render(Request{Class: ClassForbidden, Status: 403, Host: hostile, RequestID: "ZX-AAAA-BBBB", ClientIP: "203.0.113.9"})
	if !ok {
		t.Fatal("not rendered")
	}
	s := string(body)
	for _, bad := range []string{"<script>", "<img src=x", "<b>&", "line <two>", `data-host=""><`} {
		if strings.Contains(s, bad) {
			t.Fatalf("markup from a value reached the page (%q):\n%s", bad, s)
		}
	}
	for _, want := range []string{"403 Forbidden", "&lt;img src=x onerror=alert(1)&gt;", "line one\nline &lt;two&gt;", "<u>ZX-AAAA-BBBB</u>",
		"<s></s>", "<b>2026-03-04 05:06:07 UTC</b>", "a{color:#ff0000}", "&lt;script&gt;alert(&#39;h&#39;)&lt;/script&gt;.example.com", "Acme &lt;b&gt;&amp; Co&lt;/b&gt;"} {
		if !strings.Contains(s, want) {
			t.Fatalf("page lacks %q:\n%s", want, s)
		}
	}
	// the client address only appears after the opt-in, the request ID disappears when it is switched off
	cfg.Theme.ShowClientIP = true
	cfg.Theme.ShowRequestID = false
	mustSet(t, m, cfg)
	body, _ = m.Render(Request{Class: ClassForbidden, Status: 403, Host: "a", RequestID: "ZX-AAAA-BBBB", ClientIP: "203.0.113.9"})
	if s := string(body); !strings.Contains(s, "<s>203.0.113.9</s>") || !strings.Contains(s, "<u></u>") {
		t.Fatalf("opt-in / opt-out not honoured:\n%s", s)
	}
}

// The themed built-in page with hostile values in every field stays one document without foreign markup
func TestBuiltinTemplateEscapes(t *testing.T) {
	m, _ := newTestManager(t)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Theme = Theme{ApplyToBuiltin: true, LogoText: `"><script>1</script>`, FooterText: `<script>2</script>`, AccentColor: "#abc", ShowRequestID: true, ShowClientIP: true,
		LogoURL: "https://cdn.example.com/logo.png?a=1&b=2"}
	mustSet(t, m, cfg)
	body, ok := m.Render(Request{Class: ClassServerError, Status: 521, Host: `x"onload="alert(1)`, RequestID: `<script>3</script>`, ClientIP: `<script>4</script>`})
	if !ok {
		t.Fatal("not rendered")
	}
	s := string(body)
	if strings.Count(s, "<script") != 0 || strings.Contains(s, `"onload="`) {
		t.Fatalf("hostile value became markup:\n%s", s)
	}
	if !strings.Contains(s, `<img src="https://cdn.example.com/logo.png?a=1&amp;b=2"`) || !strings.Contains(s, "--accent:#abc") || !strings.Contains(s, "521 Web Server Is Down") {
		t.Fatalf("theme values missing:\n%s", s)
	}
	// starters compile and render
	for _, st := range Starters() {
		if _, err := Compile(st.HTML); err != nil {
			t.Fatalf("starter %s: %v", st.ID, err)
		}
	}
	if len(Starters()) != 3 {
		t.Fatal("three starter templates expected")
	}
}

func TestValidation(t *testing.T) {
	m, _ := newTestManager(t)
	bad := map[string]func(c *Config){
		"oversized template": func(c *Config) { c.Pages[ClassForbidden] = &Page{Template: strings.Repeat("a", MaxTemplateBytes+1)} },
		"syntax error":       func(c *Config) { c.Pages[ClassForbidden] = &Page{Template: "<p>{{.Title</p>"} },
		"unknown field":      func(c *Config) { c.Pages[ClassForbidden] = &Page{Template: "<p>{{.Secret}}</p>"} },
		"unknown function":   func(c *Config) { c.Pages[ClassForbidden] = &Page{Template: `<p>{{env "HOME"}}</p>`} },
		"legacy ref tag":     func(c *Config) { c.Pages[ClassForbidden] = &Page{Template: `<p>{{ref}}</p>`} },
		"nested range": func(c *Config) {
			c.Pages[ClassForbidden] = &Page{Template: `{{range 100000}}{{range 100000}}{{end}}{{end}}`}
		},
		"endless recursion": func(c *Config) {
			c.Pages[ClassForbidden] = &Page{Template: `{{define "a"}}{{template "a" .}}{{end}}{{template "a" .}}`}
		},
		"unknown class":        func(c *Config) { c.Pages["500x"] = &Page{Title: "x"} },
		"javascript logo":      func(c *Config) { c.Theme.LogoURL = "javascript:alert(1)" },
		"http logo":            func(c *Config) { c.Theme.LogoURL = "http://example.com/a.png" },
		"protocol relative":    func(c *Config) { c.Theme.LogoURL = "//evil.example/a.png" },
		"data html logo":       func(c *Config) { c.Theme.LogoURL = "data:text/html;base64,PHNjcmlwdD4=" },
		"colour with css":      func(c *Config) { c.Theme.AccentColor = "red;background:url(https://x)" },
		"bad host":             func(c *Config) { c.Hosts["exa mple.com"] = map[Class]*Page{ClassForbidden: {Title: "x"}} },
		"long title":           func(c *Config) { c.Pages[ClassForbidden] = &Page{Title: strings.Repeat("a", MaxTextLen+1)} },
		"control char in text": func(c *Config) { c.Pages[ClassForbidden] = &Page{Title: "a\x00b"} },
	}
	for name, mut := range bad {
		cfg := DefaultConfig()
		mut(cfg)
		if err := m.Set(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("a refused config must not be written")
	}
	// exactly the limit is fine, and so are the three kinds of logo address
	cfg := DefaultConfig()
	cfg.Pages[ClassForbidden] = &Page{Template: "<p>{{.Title}}</p>" + strings.Repeat("a", MaxTemplateBytes-18)}
	for _, u := range []string{"https://example.com/l.svg", "/logo.png", "data:image/png;base64,iVBORw0KGgo="} {
		cfg.Theme.LogoURL = u
		if err := m.Set(cfg); err != nil {
			t.Fatalf("%s refused: %v", u, err)
		}
	}
	// the output of one render is cut off at 1 MiB: without loops only large values can reach it (the
	// logo address), so it shows at request time and the caller's built-in page answers
	if _, err := execute(template.Must(template.New("t").Parse(strings.Repeat("x", MaxRenderedBytes+1))), &PageData{}); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("runaway output: %v", err)
	}
	cfg = DefaultConfig()
	cfg.Enabled = true
	cfg.Theme.LogoURL = "data:image/png;base64," + strings.Repeat("A", 90*1024)
	cfg.Pages[ClassForbidden] = &Page{Template: strings.Repeat("{{.Theme.LogoURL}}", 12)}
	mustSet(t, m, cfg)
	if _, ok := m.Render(Request{Class: ClassForbidden, Status: 403, Host: "a"}); ok {
		t.Fatal("a page larger than 1 MiB must fall back to the built-in page")
	}
}

// Loops, sub-templates and string building functions are refused when a template is saved or previewed,
// before anything runs: {{range 100000}}{{range 100000}}{{end}}{{end}} writes nothing (the 1 MiB cap
// never triggers) and would keep a CPU busy for hours.
func TestTemplatesAreStraightLine(t *testing.T) {
	m, _ := newTestManager(t)
	bad := map[string]string{
		"nested range over integers": `{{range 100000}}{{range 100000}}{{end}}{{end}}`,
		"range over an integer":      `<p>{{range 3}}x{{end}}</p>`,
		"range over a string":        `{{range .Title}}x{{end}}`,
		"range in an else branch":    `{{if .Nope}}a{{else}}{{range 1000000000}}{{end}}{{end}}`,
		"range inside with":          `{{with .Title}}{{range 1000000000}}{{end}}{{end}}`,
		"range with break":           `{{range 1000000000}}{{break}}{{end}}`,
		"define":                     `{{define "a"}}x{{end}}ok`,
		"define with range":          `{{define "a"}}{{range 1000000000}}{{end}}{{end}}ok`,
		"template":                   `{{define "a"}}x{{end}}{{template "a"}}`,
		"block":                      `{{block "a" .}}x{{end}}`,
		"self recursion":             `{{template "errorpage" .}}`,
		"printf":                     `{{printf "%1000000d" 1}}`,
		"print doubling":             `{{$a := print .Title .Title}}{{$b := print $a $a}}`,
		"call":                       `{{call .Title}}`,
		"html in a pipeline":         `{{.Title | html}}`,
		"index":                      `{{index .Title 0}}`,
		"function as an argument":    `{{if eq (printf "%d" .Status) "403"}}x{{end}}`,
	}
	for name, src := range bad {
		start := time.Now()
		_, err := Compile(src)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "not available in an error page") {
			t.Errorf("%s: refused for another reason: %v", name, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %s, the template must be refused before it runs", name, d)
		}
		cfg := DefaultConfig()
		cfg.Pages[ClassRateLimit] = &Page{Template: src}
		if m.Set(cfg) == nil {
			t.Errorf("%s: saved", name)
		}
		if _, err := m.Preview(PreviewRequest{Class: ClassRateLimit, Page: &Page{Template: src}}); err == nil {
			t.Errorf("%s: previewed", name)
		}
	}
	// what a page needs keeps working: conditions, with, variables, comparisons, comments
	good := `{{/* note */}}{{$t := .Title}}{{if and (eq .Status 403) (not .ClientIP)}}a{{else if or (ge .Status 500) (ne .Host "")}}b{{else}}c{{end}}` +
		`{{with .RequestID}}<i>{{.}}</i>{{end}}{{if gt (len .Message) 3}}{{$t}}{{end}}{{if lt .Status 600}}{{if le .Status 599}}.{{end}}{{end}}`
	if _, err := Compile(good); err != nil {
		t.Fatalf("a straight-line template was refused: %v", err)
	}
	for _, st := range Starters() {
		if _, err := Compile(st.HTML); err != nil {
			t.Errorf("starter template %s: %v", st.ID, err)
		}
	}
	// a hand edited file cannot bring a loop in either: the page is skipped when the file is loaded
	raw := `{"Version":1,"Enabled":true,"Pages":{"429":{"Template":"{{range 1000000000}}{{range 1000000000}}{{end}}{{end}}"}}}`
	if err := os.WriteFile(m.path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	m.load()
	if _, ok := m.Render(Request{Class: ClassRateLimit, Status: 429, Host: "a"}); ok || time.Since(start) > 2*time.Second {
		t.Fatal("a loop from a hand edited file must be skipped without running")
	}
}

// The limit of a title or message is 500 characters, not 500 bytes
func TestTextLimitCountsCharacters(t *testing.T) {
	m, _ := newTestManager(t)
	for _, ch := range []string{"a", "ü", "я", "語", "😀"} {
		cfg := DefaultConfig()
		cfg.Pages[ClassForbidden] = &Page{Title: strings.Repeat(ch, MaxTextLen), Message: strings.Repeat(ch, 300)}
		cfg.Theme.FooterText = strings.Repeat(ch, MaxTextLen)
		if err := m.Set(cfg); err != nil {
			t.Errorf("%d x %q refused: %v", MaxTextLen, ch, err)
		}
		cfg.Pages[ClassForbidden].Title += ch
		if err := m.Set(cfg); err == nil || !strings.Contains(err.Error(), "500 characters") {
			t.Errorf("%d x %q: %v", MaxTextLen+1, ch, err)
		}
	}
	cfg := DefaultConfig()
	cfg.Pages[ClassForbidden] = &Page{Title: "a\xffb"}
	if m.Set(cfg) == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

// {{.Host}} is the host name without the port
func TestHostIsShownWithoutPort(t *testing.T) {
	for in, want := range map[string]string{
		"nosuch.test:19861":   "nosuch.test",
		"App.Example.com":     "App.Example.com",
		"app.example.com:443": "app.example.com",
		"[2001:db8::1]:8443":  "[2001:db8::1]",
		"[2001:db8::1]":       "[2001:db8::1]",
		"2001:db8::1":         "2001:db8::1",
		"host:notaport":       "host:notaport",
		"a\x00b:80":           "ab",
		"":                    "",
		"<b>:80":              "<b>",
	} {
		if got := displayHost(in); got != want {
			t.Errorf("displayHost(%q) = %q, want %q", in, got, want)
		}
	}
	m, _ := newTestManager(t)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Pages[ClassNoHost] = &Page{Template: "<i>{{.Host}}</i>"}
	mustSet(t, m, cfg)
	if body, ok := m.Render(Request{Class: ClassNoHost, Status: 404, Host: "nosuch.test:19861"}); !ok || string(body) != "<i>nosuch.test</i>" {
		t.Fatalf("got %q %v", body, ok)
	}
}

// The status badge of the UI names only statuses a hooked path really sends
func TestServerErrorStatuses(t *testing.T) {
	ci, _ := classInfo(ClassServerError)
	if ci.Statuses != "504, 521" {
		t.Fatalf("statuses of the 5xx class: %q", ci.Statuses)
	}
}

// A template that fails while a request is served: the caller's built-in page answers, one log line
func TestBrokenTemplateFallsBackAndLogsOnce(t *testing.T) {
	m, logs := newTestManager(t)
	// valid JSON, but a template that Set would refuse: only a hand edited or damaged file can hold it
	raw := `{"Version":1,"Enabled":true,"Theme":{"ShowRequestID":true},"Pages":{"403":{"Template":"<p>{{.Nope}}</p>"},"429":{"Template":"<p>{{.Title}}</p>"}}}`
	if err := os.WriteFile(m.path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	m.load()
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "403") {
		t.Fatalf("expected one log line about the 403 template, got %v", *logs)
	}
	if _, ok := m.Render(Request{Class: ClassForbidden, Status: 403, Host: "a"}); ok {
		t.Fatal("the broken 403 template must not render")
	}
	if body, ok := m.Render(Request{Class: ClassRateLimit, Status: 429, Host: "a"}); !ok || string(body) != "<p>Too many requests</p>" {
		t.Fatalf("the healthy 429 template must keep working, got %q %v", body, ok)
	}

	// a template that only fails for some requests (the failing branch is not reached by the test render)
	st := m.state.Load()
	*logs = nil
	st.pages[ClassNotFound] = &compiledPage{tpl: template.Must(template.New("t").Parse(`{{if eq .Host "boom"}}{{index .Title 99999}}{{end}}ok`)), key: "404"}
	if body, ok := m.Render(Request{Class: ClassNotFound, Status: 404, Host: "fine"}); !ok || string(body) != "ok" {
		t.Fatalf("got %q %v", body, ok)
	}
	for i := 0; i < 3; i++ {
		if _, ok := m.Render(Request{Class: ClassNotFound, Status: 404, Host: "boom"}); ok {
			t.Fatal("a failing render must report false")
		}
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "built-in page is served instead") {
		t.Fatalf("a failing template must be logged exactly once, got %v", *logs)
	}
}

func TestDamagedFileLeavesEverythingOff(t *testing.T) {
	m, logs := newTestManager(t)
	os.WriteFile(m.path, []byte("{broken"), 0600)
	m.load()
	if m.Active() || len(*logs) != 1 {
		t.Fatalf("a damaged file must leave error pages off and say so once: active=%v logs=%v", m.Active(), *logs)
	}
}

func TestPersistAndReset(t *testing.T) {
	m, _ := newTestManager(t)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Pages[ClassRateLimit] = &Page{Title: "Slow down"}
	cfg.Pages[ClassNotFound] = &Page{} //empty entries are dropped
	cfg.Hosts["App.Example.com:8443"] = map[Class]*Page{ClassForbidden: {Message: "host text"}}
	mustSet(t, m, cfg)
	fi, err := os.Stat(m.path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("file missing or wrong mode: %v %v", err, fi)
	}
	m2 := NewManager(m.path, nil)
	got := m2.Get()
	if !got.Enabled || got.Pages[ClassRateLimit].Title != "Slow down" || got.Pages[ClassNotFound] != nil || got.Hosts["app.example.com"][ClassForbidden].Message != "host text" {
		t.Fatalf("not read back: %+v", got)
	}
	// Get hands out a copy
	got.Pages[ClassRateLimit].Title = "changed"
	if m2.Get().Pages[ClassRateLimit].Title != "Slow down" {
		t.Fatal("Get must return a copy")
	}
	if err := m2.Reset(); err != nil {
		t.Fatal(err)
	}
	if m2.Active() || m2.Has(ClassRateLimit, "a") {
		t.Fatal("still active after reset")
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("reset must remove the file")
	}
}

func TestHostOverride(t *testing.T) {
	m, _ := newTestManager(t)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Pages[ClassForbidden] = &Page{Template: "global"}
	cfg.Hosts["shop.example.com"] = map[Class]*Page{ClassForbidden: {Template: "shop"}}
	cfg.Hosts["*.example.com"] = map[Class]*Page{ClassForbidden: {Template: "wild"}, ClassRateLimit: {Template: "wild429"}}
	cfg.Hosts["*.eu.example.com"] = map[Class]*Page{ClassForbidden: {Template: "eu"}}
	mustSet(t, m, cfg)
	for host, want := range map[string]string{"shop.example.com": "shop", "SHOP.example.com:443": "shop", "blog.example.com": "wild", "a.eu.example.com": "eu",
		"example.com": "global", "other.test": "global", "": "global"} {
		body, ok := m.Render(Request{Class: ClassForbidden, Status: 403, Host: host})
		if !ok || string(body) != want {
			t.Errorf("%q: got %q, want %q", host, body, want)
		}
	}
	if body, _ := m.Render(Request{Class: ClassRateLimit, Host: "shop.example.com"}); string(body) != "wild429" {
		t.Errorf("a host without its own 429 falls to the wildcard, got %q", body)
	}
	if m.Has(ClassRateLimit, "other.test") {
		t.Error("429 of an unrelated host must stay built-in")
	}
}

func TestPreview(t *testing.T) {
	m, _ := newTestManager(t)
	// nothing saved: the preview shows the themed built-in page with the default text
	out, err := m.Preview(PreviewRequest{Class: ClassRateLimit})
	if err != nil || !strings.Contains(out, "Too many requests") || !strings.Contains(out, "ZX-7K2M-9QXD") || strings.Contains(out, "203.0.113.7") {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	out, err = m.Preview(PreviewRequest{Class: ClassForbidden, Theme: &Theme{LogoText: "Acme", ShowClientIP: true}, Page: &Page{Template: "{{.Theme.LogoText}}|{{.ClientIP}}|{{.Host}}|{{.Status}}"}, Host: "shop.example.com"})
	if err != nil || out != "Acme|203.0.113.7|shop.example.com|403" {
		t.Fatalf("preview: %v %q", err, out)
	}
	if _, err := m.Preview(PreviewRequest{Class: ClassForbidden, Page: &Page{Template: "{{.Nope}}"}}); err == nil {
		t.Fatal("a broken template must be an error in the preview")
	}
	if _, err := m.Preview(PreviewRequest{Class: "x"}); err == nil {
		t.Fatal("unknown class accepted")
	}
	if _, err := m.Preview(PreviewRequest{Class: ClassForbidden, Theme: &Theme{LogoURL: "javascript:1"}}); err == nil {
		t.Fatal("invalid theme accepted")
	}
	if m.Active() {
		t.Fatal("a preview must not switch anything on")
	}
}

func TestSetHeaders(t *testing.T) {
	h := http.Header{}
	SetHeaders(h, 12)
	if h.Get("Cache-Control") != "no-store" || h.Get("Content-Length") != "12" || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") ||
		strings.Contains(h.Get("Content-Security-Policy"), "script-src") || h.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("headers: %v", h)
	}
}
