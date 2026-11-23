package errorpages

/*
	errorpages.go

	Customisable error pages for the answers Zoraxy itself gives a visitor (403 block pages, 404, 429,
	the 5xx "upstream is down" pages, the "no such host" page of the Default Site and the 503 "busy" answer).

	OFF BY DEFAULT. Until the owner saves a customisation (and switches it on) Render reports false for
	every request, and the callers in mod/dynamicproxy write exactly the bytes and headers they always
	wrote. The same is true for every page class the owner did not touch.

	What can be customised
	  - a theme (logo URL or text, accent colour, footer text, show the request ID, show the client address),
	    used by the themed built-in page and available to custom templates as .Theme
	  - per page class: title and message (the themed built-in page shows them), or a whole HTML template
	  - per host: the same three fields, for one host name or one *.wildcard

	Safety
	  - templates are html/template: every value is escaped for the place it is written to. The Host header
	    is attacker controlled and is only ever written through the template engine
	  - no template functions are added, the data is a flat struct of strings: a template cannot read files,
	    environment or configuration
	  - a template is straight-line: no loops (range), no sub-templates (define, template, block) and only
	    the comparison functions and len. The work of one render is bounded by the size of the template
	  - a template is at most 256 KiB, the rendered page at most 1 MiB
	  - the server never fetches anything: a logo is a URL the visitor's browser loads
	  - a template that fails to render falls back to the built-in page of the caller and is logged once

	State lives in one JSON file in the conf folder (errorpages.json, 0600, written atomically).
*/

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/template/parse"
	"time"
	"unicode/utf8"
)

const (
	MaxTemplateBytes = 256 * 1024  //one template
	MaxRenderedBytes = 1024 * 1024 //one rendered page
	MaxTotalBytes    = 8 * 1024 * 1024
	MaxHosts         = 64
	MaxTextLen       = 500       //characters (runes) of a title, message, logo or footer text; at most 4 bytes each
	MaxLogoURLLen    = 96 * 1024 //room for a small data: image
	FileName         = "errorpages.json"

	// ContentSecurityPolicy of every customised page: a static document. Inline styles and images are
	// allowed (the logo), scripts, frames, forms and plugins are not.
	ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

// Class is one kind of answer Zoraxy gives by itself
type Class string

const (
	ClassForbidden   Class = "403"
	ClassNotFound    Class = "404"
	ClassRateLimit   Class = "429"
	ClassServerError Class = "5xx"
	ClassNoHost      Class = "nohost"
	ClassMaintenance Class = "maintenance"
)

// ClassInfo describes a page class to the admin UI
type ClassInfo struct {
	ID           Class  `json:"id"`
	Label        string `json:"label"`
	Statuses     string `json:"statuses"`     //the status codes it is served with
	When         string `json:"when"`         //one sentence: when a visitor sees it
	SampleStatus int    `json:"sampleStatus"` //status used by the preview
	Title        string `json:"title"`        //default title
	Message      string `json:"message"`      //default message
}

var classList = []ClassInfo{
	{ClassForbidden, "Access denied", "403", "A visitor is blocked: access rules, countries, the WAF, auto-ban, CrowdSec, bot rules, security rules, \"Block common exploits\" and \"Block AI crawlers\" when they answer 403.", 403,
		"Access denied", "You do not have permission to open this page."},
	{ClassNotFound, "Not found", "404", "Zoraxy answers 404 for a site: the host name of the upstream cannot be resolved, a header rule answers 404, or \"Block common exploits\" / \"Block AI crawlers\" is set to answer 404.", 404,
		"Page not found", "The page you asked for could not be found."},
	{ClassRateLimit, "Too many requests", "429", "A rate limit of a site, a path rule or a security rule was reached.", 429,
		"Too many requests", "You sent too many requests in a short time. Wait a moment and try again."},
	{ClassServerError, "Server error", "504, 521", "The server behind a site is down, refuses the connection or does not answer in time.", 521,
		"This site is not available right now", "The server behind this address did not answer. Please try again in a few minutes."},
	{ClassNoHost, "No such host", "404", "Nobody configured a site for the host name, and the Default Site is set to show a \"not found\" page.", 404,
		"Nothing here", "No site is configured for this address."},
	{ClassMaintenance, "Busy or maintenance", "503", "Zoraxy answers 503 itself: every upstream of the site is at its connection limit.", 503,
		"We will be right back", "The site is busy or being worked on. Please try again shortly."},
}

// Classes lists every page class in display order
func Classes() []ClassInfo { return append([]ClassInfo(nil), classList...) }

func classInfo(c Class) (ClassInfo, bool) {
	for _, ci := range classList {
		if ci.ID == c {
			return ci, true
		}
	}
	return ClassInfo{}, false
}

// Theme is the global look. The zero value changes nothing.
type Theme struct {
	ApplyToBuiltin bool   //use the themed built-in page for every class, also the ones without own text or template
	LogoURL        string //https://..., a path starting with / or a data:image/ URL; loaded by the visitor's browser
	LogoText       string //shown when there is no logo URL (and as its alt text)
	AccentColor    string //#rgb, #rrggbb or #rrggbbaa
	FooterText     string
	ShowRequestID  bool //.RequestID is filled in (the block reference of a 403, else the request ID)
	ShowClientIP   bool //.ClientIP is filled in. Off unless the owner opts in
}

// Page is the customisation of one class
type Page struct {
	Title    string `json:",omitempty"`
	Message  string `json:",omitempty"`
	Template string `json:",omitempty"` //html/template source; empty = the themed built-in page
}

func (p *Page) empty() bool {
	return p == nil || (p.Title == "" && p.Message == "" && p.Template == "")
}

// Config is what the file holds
type Config struct {
	Version int
	Enabled bool //master switch. Off = every response is the one Zoraxy always gave
	Theme   Theme
	Pages   map[Class]*Page            `json:",omitempty"`
	Hosts   map[string]map[Class]*Page `json:",omitempty"` //host name or *.wildcard -> pages
}

// DefaultConfig is what the editor starts from: nothing switched on
func DefaultConfig() *Config {
	return &Config{Version: 1, Theme: Theme{AccentColor: "#2563eb", ShowRequestID: true}, Pages: map[Class]*Page{}, Hosts: map[string]map[Class]*Page{}}
}

// PageData is everything a template can read
type PageData struct {
	Status     int
	StatusText string
	Title      string
	Message    string
	Host       string
	RequestID  string //empty unless the theme shows it and the request has one
	Time       string //UTC, "2006-01-02 15:04:05 UTC"
	ClientIP   string //empty unless the owner opted in
	Theme      ThemeData
}

type ThemeData struct {
	LogoURL    template.URL //validated when saved
	LogoText   string
	Accent     string
	FooterText string
}

// Variable documents a placeholder for the editor's help
type Variable struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

func Variables() []Variable {
	return []Variable{
		{"{{.Status}}", "Status code of the answer, for example 403"},
		{"{{.StatusText}}", "Standard name of the status, for example Forbidden"},
		{"{{.Title}}", "Title of this page (your text, or the built-in one)"},
		{"{{.Message}}", "Message of this page (your text, or the built-in one)"},
		{"{{.Host}}", "Host name the visitor asked for, without the port"},
		{"{{.RequestID}}", "Reference the visitor can give you (the block reference of a 403). Empty when the theme hides it"},
		{"{{.Time}}", "Time of the answer, UTC"},
		{"{{.ClientIP}}", "Address of the visitor. Empty unless you switch on \"Show the visitor's address\""},
		{"{{.Theme.LogoURL}}", "Logo address of the theme"},
		{"{{.Theme.LogoText}}", "Logo text of the theme"},
		{"{{.Theme.Accent}}", "Accent colour of the theme"},
		{"{{.Theme.FooterText}}", "Footer text of the theme"},
	}
}

// ---- validation ----

var (
	colorRe   = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
	dataImgRe = regexp.MustCompile(`^data:image/(?:png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/]+=*$`)
	hostRe    = regexp.MustCompile(`^(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$`)
)

func hasControl(s string, allowNewline bool) bool {
	for _, c := range s {
		if c == '\n' && allowNewline {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func validText(name, s string, multiline bool) error {
	// characters, not bytes: 300 Cyrillic or CJK characters are 600 to 900 bytes and fit. The byte test
	// comes first so an oversized input is refused without being counted.
	if len(s) > MaxTextLen*utf8.UTFMax || utf8.RuneCountInString(s) > MaxTextLen {
		return fmt.Errorf("%s is longer than %d characters", name, MaxTextLen)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8 text", name)
	}
	if hasControl(s, multiline) {
		return fmt.Errorf("%s contains control characters", name)
	}
	return nil
}

// ValidLogoURL accepts https URLs, absolute paths of the same site and small inline images
func ValidLogoURL(u string) error {
	if u == "" {
		return nil
	}
	if len(u) > MaxLogoURLLen {
		return errors.New("the logo address is too long (an inline image can be about 70 KB)")
	}
	if hasControl(u, false) || strings.ContainsAny(u, " \"'<>\\`") {
		return errors.New("the logo address contains characters that are not allowed")
	}
	switch {
	case strings.HasPrefix(u, "https://") && len(u) > len("https://"):
		return nil
	case strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//"):
		return nil
	case dataImgRe.MatchString(u):
		return nil
	}
	return errors.New("the logo address must start with https://, be a path that starts with /, or be a data:image/ URL")
}

func (t *Theme) validate() error {
	if err := ValidLogoURL(t.LogoURL); err != nil {
		return err
	}
	if t.AccentColor != "" && !colorRe.MatchString(t.AccentColor) {
		return errors.New("the accent colour must look like #2563eb")
	}
	if err := validText("the logo text", t.LogoText, false); err != nil {
		return err
	}
	return validText("the footer text", t.FooterText, false)
}

// NormalizeHost lower-cases a host name and removes the port and a trailing dot
func NormalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if strings.HasPrefix(h, "[") { //IPv6 literal
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(h, ".")
}

func validHostKey(h string) error {
	if h == "" || len(h) > 253 || !hostRe.MatchString(h) {
		return fmt.Errorf("%q is not a host name (use app.example.com or *.example.com)", h)
	}
	return nil
}

func (p *Page) validate(c Class) error {
	if _, ok := classInfo(c); !ok {
		return fmt.Errorf("unknown page %q", string(c))
	}
	if p == nil {
		return nil
	}
	if err := validText("the title", p.Title, false); err != nil {
		return err
	}
	if err := validText("the message", p.Message, true); err != nil {
		return err
	}
	if _, err := Compile(p.Template); err != nil {
		return err
	}
	return nil
}

// normalize drops empty entries and normalises host keys (in place)
func (c *Config) normalize() {
	c.Version = 1
	if c.Pages == nil {
		c.Pages = map[Class]*Page{}
	}
	for k, p := range c.Pages {
		if p.empty() {
			delete(c.Pages, k)
		}
	}
	hosts := map[string]map[Class]*Page{}
	for h, pages := range c.Hosts {
		nh := NormalizeHost(h)
		for k, p := range pages {
			if p.empty() {
				continue
			}
			if hosts[nh] == nil {
				hosts[nh] = map[Class]*Page{}
			}
			hosts[nh][k] = p
		}
	}
	c.Hosts = hosts
}

// Validate checks a whole config (after normalising it)
func (c *Config) Validate() error {
	c.normalize()
	if err := c.Theme.validate(); err != nil {
		return err
	}
	total := 0
	for k, p := range c.Pages {
		if err := p.validate(k); err != nil {
			return fmt.Errorf("%s: %w", string(k), err)
		}
		total += len(p.Template)
	}
	if len(c.Hosts) > MaxHosts {
		return fmt.Errorf("too many hosts with own pages (max %d)", MaxHosts)
	}
	for h, pages := range c.Hosts {
		if err := validHostKey(h); err != nil {
			return err
		}
		for k, p := range pages {
			if err := p.validate(k); err != nil {
				return fmt.Errorf("%s, %s: %w", h, string(k), err)
			}
			total += len(p.Template)
		}
	}
	if total > MaxTotalBytes {
		return fmt.Errorf("all templates together are larger than %d MiB", MaxTotalBytes/1024/1024)
	}
	return nil
}

func (c *Config) clone() *Config {
	out := &Config{Version: c.Version, Enabled: c.Enabled, Theme: c.Theme, Pages: map[Class]*Page{}, Hosts: map[string]map[Class]*Page{}}
	for k, p := range c.Pages {
		if p != nil {
			cp := *p
			out.Pages[k] = &cp
		}
	}
	for h, pages := range c.Hosts {
		out.Hosts[h] = map[Class]*Page{}
		for k, p := range pages {
			if p != nil {
				cp := *p
				out.Hosts[h][k] = &cp
			}
		}
	}
	return out
}

// ---- templates ----

var sampleData = []PageData{
	{Status: 403, StatusText: "Forbidden", Title: "Access denied", Message: "You do not have permission to open this page.", Host: "app.example.com",
		RequestID: "ZX-7K2M-9QXD", Time: "2026-01-02 15:04:05 UTC", ClientIP: "203.0.113.7",
		Theme: ThemeData{LogoURL: "https://example.com/logo.png", LogoText: "Example", Accent: "#2563eb", FooterText: "Example Ltd."}},
	{Status: 521, StatusText: "Web Server Is Down", Title: "T", Message: "M", Host: "app.example.com", Time: "2026-01-02 15:04:05 UTC"},
}

// errTooLarge stops a template whose output runs away
var errTooLarge = errors.New("the rendered page is larger than 1 MiB")

type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errTooLarge
	}
	return b.Buffer.Write(p)
}

func execute(t *template.Template, d *PageData) ([]byte, error) {
	buf := &cappedBuffer{max: MaxRenderedBytes}
	if err := t.Execute(buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Compile parses a template and test-renders it with sample values (with and without the optional
// ones). An empty source is the themed built-in page.
func Compile(src string) (*template.Template, error) {
	if src == "" {
		return builtinTemplate, nil
	}
	if len(src) > MaxTemplateBytes {
		return nil, fmt.Errorf("the template is larger than %d KiB", MaxTemplateBytes/1024)
	}
	t, err := template.New("errorpage").Parse(src)
	if err != nil {
		return nil, fmt.Errorf("template error: %s", cleanTemplateError(err))
	}
	// before anything is executed: a loop or a recursion could run for hours without writing a byte
	if err := checkStraightLine(t); err != nil {
		return nil, fmt.Errorf("template error: %s", err.Error())
	}
	for i := range sampleData {
		if _, err := execute(t, &sampleData[i]); err != nil {
			return nil, fmt.Errorf("the template cannot be rendered: %s", cleanTemplateError(err))
		}
	}
	return t, nil
}

// allowedFuncs are the template functions a page may call. None of them loops or builds a value that
// is larger than its arguments (print, printf, html ... can double a string with every action).
var allowedFuncs = map[string]bool{
	"and": true, "or": true, "not": true, "len": true,
	"eq": true, "ne": true, "lt": true, "le": true, "gt": true, "ge": true,
}

// checkStraightLine refuses everything that makes the cost of a render independent of the size of the
// template: range (text/template loops over integers, {{range 100000}}, without any data), template /
// define / block (recursion) and the functions that are not in allowedFuncs (call, print, printf ...).
// What is left is if / with / variables / comparisons: every node runs at most once per render.
func checkStraightLine(t *template.Template) error {
	for _, tt := range t.Templates() {
		if tt.Name() != t.Name() {
			return errors.New("{{define}} and {{block}} are not available in an error page")
		}
	}
	if t.Tree == nil || t.Tree.Root == nil {
		return nil
	}
	return walkNode(t.Tree.Root)
}

func walkNode(n parse.Node) error {
	switch n := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := walkNode(c); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		return walkPipe(n.Pipe)
	case *parse.IfNode:
		return walkBranch(&n.BranchNode)
	case *parse.WithNode:
		return walkBranch(&n.BranchNode)
	case *parse.RangeNode:
		return errors.New("{{range}} is not available in an error page (there is nothing to loop over)")
	case *parse.TemplateNode:
		return errors.New("{{template}} and {{block}} are not available in an error page")
	case *parse.PipeNode:
		return walkPipe(n)
	case *parse.CommandNode:
		for _, a := range n.Args {
			if err := walkNode(a); err != nil {
				return err
			}
		}
	case *parse.ChainNode:
		return walkNode(n.Node)
	case *parse.IdentifierNode:
		if !allowedFuncs[n.Ident] {
			return fmt.Errorf("the function %q is not available in an error page (available: and, or, not, eq, ne, lt, le, gt, ge, len)", n.Ident)
		}
	case *parse.TextNode, *parse.CommentNode, *parse.FieldNode, *parse.VariableNode, *parse.DotNode, *parse.NilNode,
		*parse.BoolNode, *parse.NumberNode, *parse.StringNode:
		// leaves
	default: // break, continue and whatever a later Go version adds: refused until it is looked at
		return fmt.Errorf("%s is not available in an error page", strings.TrimSpace(n.String()))
	}
	return nil
}

func walkBranch(b *parse.BranchNode) error {
	if err := walkPipe(b.Pipe); err != nil {
		return err
	}
	if b.List != nil {
		if err := walkNode(b.List); err != nil {
			return err
		}
	}
	if b.ElseList != nil {
		return walkNode(b.ElseList)
	}
	return nil
}

func walkPipe(p *parse.PipeNode) error {
	if p == nil {
		return nil
	}
	for _, c := range p.Cmds {
		if err := walkNode(c); err != nil {
			return err
		}
	}
	return nil
}

func cleanTemplateError(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, "html/template:")
	s = strings.TrimPrefix(s, "template: ")
	return strings.TrimSpace(s)
}

var builtinTemplate = template.Must(template.New("builtin").Parse(BuiltinTemplate))

// ---- compiled state ----

type compiledPage struct {
	tpl     *template.Template
	title   string
	message string
	key     string //for the log-once of a failing template
}

type compiled struct {
	enabled   bool
	theme     Theme
	themeData ThemeData
	pages     map[Class]*compiledPage
	hosts     map[string]map[Class]*compiledPage
	wildcards []string //suffixes (".example.com"), longest first
	logged    sync.Map //template key -> struct{}: a failing template is reported once per saved state
}

func compilePage(p *Page, key string) (*compiledPage, error) {
	t, err := Compile(p.Template)
	if err != nil {
		return nil, err
	}
	return &compiledPage{tpl: t, title: p.Title, message: p.Message, key: key}, nil
}

// compile builds the request-time state. A page that does not compile is skipped (reported through
// warn): the next level, in the end the built-in page of the caller, answers instead.
func compile(c *Config, warn func(string)) *compiled {
	out := &compiled{enabled: c.Enabled, theme: c.Theme, pages: map[Class]*compiledPage{}, hosts: map[string]map[Class]*compiledPage{}}
	out.themeData = ThemeData{LogoText: c.Theme.LogoText, Accent: c.Theme.AccentColor, FooterText: c.Theme.FooterText}
	if ValidLogoURL(c.Theme.LogoURL) == nil {
		out.themeData.LogoURL = template.URL(c.Theme.LogoURL)
	}
	if out.themeData.Accent == "" || !colorRe.MatchString(out.themeData.Accent) {
		out.themeData.Accent = "#2563eb"
	}
	for k, p := range c.Pages {
		if p.empty() {
			continue
		}
		cp, err := compilePage(p, string(k))
		if err != nil {
			warn("error page " + string(k) + " is ignored: " + err.Error())
			continue
		}
		out.pages[k] = cp
	}
	for h, pages := range c.Hosts {
		for k, p := range pages {
			if p.empty() {
				continue
			}
			cp, err := compilePage(p, h+"|"+string(k))
			if err != nil {
				warn("error page " + string(k) + " of " + h + " is ignored: " + err.Error())
				continue
			}
			if out.hosts[h] == nil {
				out.hosts[h] = map[Class]*compiledPage{}
			}
			out.hosts[h][k] = cp
		}
		if strings.HasPrefix(h, "*.") && out.hosts[h] != nil {
			out.wildcards = append(out.wildcards, h[1:])
		}
	}
	sort.Slice(out.wildcards, func(i, j int) bool {
		if len(out.wildcards[i]) != len(out.wildcards[j]) {
			return len(out.wildcards[i]) > len(out.wildcards[j])
		}
		return out.wildcards[i] < out.wildcards[j]
	})
	return out
}

// find returns the page that answers (host, class), nil when nothing is customised for it
func (s *compiled) find(c Class, host string) *compiledPage {
	if s == nil || !s.enabled {
		return nil
	}
	if len(s.hosts) > 0 && host != "" {
		if pages := s.hosts[host]; pages != nil && pages[c] != nil {
			return pages[c]
		}
		for _, suffix := range s.wildcards {
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				if p := s.hosts["*"+suffix][c]; p != nil {
					return p
				}
			}
		}
	}
	if p := s.pages[c]; p != nil {
		return p
	}
	if s.theme.ApplyToBuiltin {
		return themedBuiltin
	}
	return nil
}

var themedBuiltin = &compiledPage{tpl: builtinTemplate, key: "builtin"}

// ---- manager ----

// Manager holds the saved customisation and renders pages
type Manager struct {
	path  string
	logf  func(string)
	mu    sync.Mutex //serialises Set / Reset / Load
	cfg   atomic.Pointer[Config]
	state atomic.Pointer[compiled]
	now   func() time.Time
}

// NewManager creates a manager for the file (it does not have to exist) and loads it. logf may be nil.
// A file that cannot be read or parsed leaves everything off.
func NewManager(path string, logf func(string)) *Manager {
	if logf == nil {
		logf = func(string) {}
	}
	m := &Manager{path: path, logf: logf, now: time.Now}
	m.load()
	return m
}

func (m *Manager) load() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := DefaultConfig()
	if m.path != "" {
		raw, err := os.ReadFile(m.path)
		switch {
		case err == nil:
			loaded := DefaultConfig()
			if jerr := json.Unmarshal(raw, loaded); jerr != nil {
				m.logf("error pages: " + m.path + " cannot be read, custom error pages stay off: " + jerr.Error())
			} else {
				loaded.normalize()
				if verr := loaded.Theme.validate(); verr != nil {
					m.logf("error pages: the saved theme is not valid and is ignored: " + verr.Error())
					loaded.Theme = DefaultConfig().Theme
				}
				cfg = loaded
			}
		case !os.IsNotExist(err):
			m.logf("error pages: " + m.path + " cannot be read, custom error pages stay off: " + err.Error())
		}
	}
	m.swap(cfg)
}

func (m *Manager) swap(cfg *Config) {
	m.cfg.Store(cfg)
	m.state.Store(compile(cfg, func(s string) { m.logf("error pages: " + s) }))
}

// Get returns a copy of the saved config
func (m *Manager) Get() *Config {
	return m.cfg.Load().clone()
}

// Active reports whether any request can get a customised page (cheap, for the request path)
func (m *Manager) Active() bool {
	if m == nil {
		return false
	}
	s := m.state.Load()
	return s != nil && s.enabled
}

// Set validates, saves and applies a config
func (m *Manager) Set(cfg *Config) error {
	if cfg == nil {
		return errors.New("no configuration given")
	}
	cfg = cfg.clone()
	if err := cfg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.write(cfg); err != nil {
		return err
	}
	m.swap(cfg)
	return nil
}

// Reset removes every customisation: all pages are the built-in ones again
func (m *Manager) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path != "" {
		if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	m.swap(DefaultConfig())
	return nil
}

func (m *Manager) write(cfg *Config) error {
	if m.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(cfg, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0775); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// Request describes the answer a caller is about to give
type Request struct {
	Class     Class
	Status    int
	Host      string //as received (may carry a port)
	RequestID string
	ClientIP  string
}

// Has reports whether (class, host) has a customised page. Nothing is rendered.
func (m *Manager) Has(c Class, host string) bool {
	if m == nil {
		return false
	}
	return m.state.Load().find(c, NormalizeHost(host)) != nil
}

// Render returns the customised page for the request. ok is false when nothing is customised for
// it or the template failed (logged once): the caller then answers with its built-in page.
func (m *Manager) Render(req Request) (body []byte, ok bool) {
	if m == nil {
		return nil, false
	}
	s := m.state.Load()
	p := s.find(req.Class, NormalizeHost(req.Host))
	if p == nil {
		return nil, false
	}
	body, err := renderPage(p, &s.theme, s.themeData, req, m.now())
	if err != nil {
		if _, seen := s.logged.LoadOrStore(p.key, struct{}{}); !seen {
			m.logf("error pages: the template of " + p.key + " failed, the built-in page is served instead: " + cleanTemplateError(err))
		}
		return nil, false
	}
	return body, true
}

func cleanHost(h string) string {
	if len(h) > 255 {
		h = h[:255]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, h)
}

// displayHost is the Host header as a page shows it: without the port (and without control characters).
// Unlike NormalizeHost it keeps the spelling of the visitor and the brackets of an IPv6 literal.
func displayHost(h string) string {
	h = cleanHost(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && i == strings.Index(h, ":") && isDigits(h[i+1:]) {
		return h[:i]
	}
	return h
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func renderPage(p *compiledPage, theme *Theme, td ThemeData, req Request, now time.Time) ([]byte, error) {
	ci, _ := classInfo(req.Class)
	status := req.Status
	if status == 0 {
		status = ci.SampleStatus
	}
	d := &PageData{Status: status, StatusText: StatusText(status), Title: p.title, Message: p.message, Host: displayHost(req.Host),
		Time: now.UTC().Format("2006-01-02 15:04:05") + " UTC", Theme: td}
	if d.Title == "" {
		d.Title = ci.Title
	}
	if d.Message == "" {
		d.Message = ci.Message
	}
	if theme.ShowRequestID {
		d.RequestID = cleanHost(req.RequestID)
	}
	if theme.ShowClientIP {
		d.ClientIP = cleanHost(req.ClientIP)
	}
	return execute(p.tpl, d)
}

// StatusText is http.StatusText plus the non standard codes Zoraxy answers with
func StatusText(code int) string {
	if code == 521 {
		return "Web Server Is Down"
	}
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "Error"
}

// PreviewRequest is an unsaved page plus theme, rendered with sample values
type PreviewRequest struct {
	Class Class
	Theme *Theme //nil = the saved theme
	Page  *Page  //nil = the saved page of the class (of Host when given)
	Host  string //host whose saved page is previewed; also the sample host name
}

// Preview renders without saving. Unlike Render a broken template is an error.
func (m *Manager) Preview(pr PreviewRequest) (string, error) {
	ci, ok := classInfo(pr.Class)
	if !ok {
		return "", fmt.Errorf("unknown page %q", string(pr.Class))
	}
	cfg := m.cfg.Load()
	theme := cfg.Theme
	if pr.Theme != nil {
		theme = *pr.Theme
		if err := theme.validate(); err != nil {
			return "", err
		}
	}
	page := pr.Page
	host := NormalizeHost(pr.Host)
	if page == nil {
		page = &Page{}
		if hp := cfg.Hosts[host][pr.Class]; hp != nil {
			page = hp
		} else if gp := cfg.Pages[pr.Class]; gp != nil {
			page = gp
		}
	}
	if err := page.validate(pr.Class); err != nil {
		return "", err
	}
	one := compile(&Config{Enabled: true, Theme: theme, Pages: map[Class]*Page{pr.Class: {Title: page.Title, Message: page.Message, Template: page.Template}}}, func(string) {})
	p := one.pages[pr.Class]
	if p == nil {
		p = themedBuiltin
	}
	if host == "" || strings.HasPrefix(host, "*.") {
		host = "app.example.com"
	}
	body, err := renderPage(p, &theme, one.themeData, Request{Class: pr.Class, Status: ci.SampleStatus, Host: host, RequestID: "ZX-7K2M-9QXD", ClientIP: "203.0.113.7"}, m.now())
	if err != nil {
		return "", fmt.Errorf("the template cannot be rendered: %s", cleanTemplateError(err))
	}
	return string(body), nil
}

// SetHeaders puts the headers of a customised page on a response (before WriteHeader)
func SetHeaders(h http.Header, bodyLen int) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", fmt.Sprint(bodyLen))
}
