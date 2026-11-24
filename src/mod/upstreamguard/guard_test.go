package upstreamguard

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

/*
	No default call to a host of the upstream project.

	Scanned: every file under src/ that is compiled or embedded into Dunree: Go
	(not tests, not testdata) and the web sources (html, js, json, css, txt, md).
	Not scanned: folders a running Dunree creates (conf, log, plugins, tmp, www).

	A line that names an upstream HOST (not just the authors, who are credited by
	name all over the code) must be one of:

	  1. a comment (Go and JS): never executed;
	  2. attribution text: a credit that says where the code comes from. A link
	     in such a line is followed by a person, never fetched by Dunree;
	  3. an entry of the list below, each with the reason why it is not a call
	     Dunree makes by default.

	Anything else fails: in particular a URL of those hosts in a Go string, or in
	a script, img, link, fetch or ajax of the admin interface.
*/

// Hosts and repository paths of the upstream project
var upstreamHost = regexp.MustCompile(`(?i)aroz\.org|imuslab\.com|aroz-online|(github|githubusercontent)\.com/tobychui|tobychui\.github\.io|zoraxydocker`)

// Wording that makes a line a credit
var attribution = regexp.MustCompile(`(?i)based on|developed by|powered by|proudly|original (implementation|author|work|project)|derived from|derivative|fork of|forked from|upstream|credits?\b|copyright|©|licen[cs]ed? under|not endorsed|third party|third-party`)

// Constructs that make a browser (or a script) fetch an address. A line with one
// of them is never a credit, whatever words it carries: "upstream" is everyday
// wording in a reverse proxy, and <script src=...> next to it would still load.
var loads = regexp.MustCompile(`(?i)\bsrc\s*=|\bsrcset\s*=|\bfetch\s*\(|\$\.(get|post|ajax|getjson|getscript)\b|\.ajax\s*\(|\.load\s*\(|xmlhttprequest|eventsource\s*\(|websocket\s*\(|<link\b|<iframe\b|<object\b|<embed\b|\burl\s*\(|@import|\baction\s*=|\bimport\s*\(|\bdata\s*=`)

type allowed struct {
	file   string //path below src/, forward slashes
	has    string //text the line contains
	reason string
}

var allowList = []allowed{
	// The add-on store. The one address of the upstream store in the product: it is
	// written into the settings of an installation that used it before it ran
	// Dunree, once, where it is shown as a third-party source and can be removed.
	// A new installation never contacts it (TestNoStoreAndNoConnectionByDefault,
	// TestExistingInstallKeepsItsStoreSourceOnce in mod/plugins).
	{"mod/plugins/store_sources.go", "LegacyZoraxyStoreIndexURL = ", "migrated setting of existing installations, never a default"}, // legacy-compat

	// Links a person may click. Dunree does not fetch them. The footer credit links,
	// the CAPTCHA footer default and its placeholders, the About card, the language
	// help link and the default page of the static web server were on this list
	// until the brand work removed those addresses from the product.
	{"web/snippet/intermediateCertConv.html", "//Basically just concat both together. See https://github.com/tobychui", "a comment in a script block"},
}

var scannedExt = map[string]bool{".go": true, ".html": true, ".htm": true, ".js": true, ".json": true, ".css": true, ".txt": true, ".md": true, ".tmpl": true, ".svg": true}

// Folders below src/ a running Dunree creates; they are not part of the product
var runtimeDirs = map[string]bool{"conf": true, "log": true, "plugins": true, "tmp": true, "www": true}

type hit struct {
	file string
	line int
	text string
}

// codeOf returns the part of a Go or JS line that is not a comment. inBlock
// says whether the line starts inside a block comment, and is returned for the next line.
func codeOf(line string, inBlock bool) (string, bool) {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inBlock {
			if c == '*' && i+1 < len(line) && line[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		}
		if quote != 0 {
			b.WriteByte(c)
			if c == '\\' && quote != '`' && i+1 < len(line) {
				i++
				b.WriteByte(line[i])
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch {
		case c == '"' || c == '\'' || c == '`':
			quote = c
			b.WriteByte(c)
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return b.String(), false
		case c == '/' && i+1 < len(line) && line[i+1] == '*':
			inBlock = true
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), inBlock
}

func scan(t *testing.T, root string) []hit {
	t.Helper()
	var hits []hit
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			name := d.Name()
			if name == "testdata" || name == "node_modules" || strings.HasPrefix(name, ".") && rel != "." || (runtimeDirs[name] && rel == name) {
				return filepath.SkipDir
			}
			return nil
		}
		if !scannedExt[strings.ToLower(filepath.Ext(path))] || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		ext := strings.ToLower(filepath.Ext(path))
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20) //minified scripts have very long lines
		inBlock := false
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			checked := line
			if ext == ".go" || ext == ".js" {
				checked, inBlock = codeOf(line, inBlock)
			}
			if upstreamHost.MatchString(checked) {
				hits = append(hits, hit{file: rel, line: n, text: strings.TrimSpace(line)})
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func srcRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("src/ not found from the test folder: %v", err)
	}
	return root
}

func TestNoDefaultCallToUpstreamHosts(t *testing.T) {
	root := srcRoot(t)
	used := make([]bool, len(allowList))
	var bad []string
	for _, h := range scan(t, root) {
		ok := false
		for i, a := range allowList {
			if a.file == h.file && strings.Contains(h.text, a.has) {
				used[i], ok = true, true
				break
			}
		}
		// Attribution text. Never for Go code: a credit in Go is a comment, and a
		// host in a Go string is something the program can use.
		if !ok && !strings.HasSuffix(h.file, ".go") && isCredit(h.text) {
			ok = true
		}
		if !ok {
			text := h.text
			if len(text) > 220 {
				text = text[:220] + "..."
			}
			bad = append(bad, h.file+":"+itoa(h.line)+": "+text)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("%d lines name a host of the upstream project outside a comment or a credit.\n"+
			"Dunree must not contact upstream services by default: make the address a setting, or (for a link a person clicks, or an identifier) add it to allowList in this file with the reason.\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
	for i, a := range allowList {
		if !used[i] {
			t.Logf("note: the allowList entry %s (%q) matches nothing any more and can be removed", a.file, a.has)
		}
	}
}

// The address of the Dunree add-on store is written down in one place only
func TestDunreeStoreAddressIsDefinedOnce(t *testing.T) {
	root := srcRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "mod", "plugins", "store_sources.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`DunreeAddonStoreIndexURL\s*=\s*"([^"]*)"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("DunreeAddonStoreIndexURL is not defined in mod/plugins/store_sources.go")
	}
	address := string(m[1])
	if address == "" {
		return //no address at all: nothing to find elsewhere
	}
	host := regexp.MustCompile(`^https?://([^/]+)`).FindStringSubmatch(address)
	if host == nil {
		t.Fatalf("DunreeAddonStoreIndexURL %q is not a web address", address)
	}
	var places []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "node_modules" || (runtimeDirs[d.Name()] && rel == d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !scannedExt[strings.ToLower(filepath.Ext(path))] || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if n := strings.Count(string(content), host[1]); n > 0 {
			places = append(places, rel+" ("+itoa(n)+")")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(places) != 1 || places[0] != "mod/plugins/store_sources.go (1)" {
		t.Fatalf("the host of the Dunree add-on store (%s) must appear exactly once, in mod/plugins/store_sources.go; found in: %s", host[1], strings.Join(places, ", "))
	}
}

func TestCodeOfStripsComments(t *testing.T) {
	for _, c := range []struct {
		line    string
		inBlock bool
		want    string
		after   bool
	}{
		{`x := "https://zoraxy.aroz.org" // see https://imuslab.com`, false, `x := "https://zoraxy.aroz.org" `, false},
		{`// See https://github.com/tobychui/zoraxy/issues/77`, false, ``, false},
		{`a /* aroz.org */ b`, false, `a  b`, false},
		{`still a comment aroz.org`, true, ``, true},
		{`end */ url = 'https://aroz.org/x'`, true, ` url = 'https://aroz.org/x'`, false},
		{`s := "a \" // not a comment aroz.org"`, false, `s := "a \" // not a comment aroz.org"`, false},
		{"s := `raw // aroz.org`", false, "s := `raw // aroz.org`", false},
		{`/* opens`, false, ``, true},
	} {
		got, after := codeOf(c.line, c.inBlock)
		if got != c.want || after != c.after {
			t.Errorf("codeOf(%q, %v) = %q, %v; want %q, %v", c.line, c.inBlock, got, after, c.want, c.after)
		}
	}
}

// The scanner finds what it is meant to find
func TestGuardCatchesACall(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "web"), 0o755)
	os.MkdirAll(filepath.Join(dir, "plugins"), 0o755)
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n// Author: tobychui, see https://github.com/tobychui/zoraxy\nvar u = \"https://raw.githubusercontent.com/aroz-online/x/index.json\"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "a_test.go"), []byte("package a\nvar t = \"https://zoraxy.aroz.org\"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "web", "p.html"), []byte("<p>Based on <a href=\"https://zoraxy.aroz.org\">Zoraxy</a></p>\n<script src=\"https://zoraxy.aroz.org/x.js\"></script>\n"), 0o644) // legacy-compat
	os.WriteFile(filepath.Join(dir, "plugins", "data.json"), []byte("{\"u\":\"https://zoraxy.aroz.org\"}\n"), 0o644)
	hits := scan(t, dir)
	if len(hits) != 3 {
		t.Fatalf("want the Go string and both html lines, got %+v", hits)
	}
	if hits[0].file != "a.go" || hits[0].line != 3 {
		t.Errorf("the Go string literal must be found, the comment not: %+v", hits[0])
	}
	if !attribution.MatchString(hits[1].text) || attribution.MatchString(hits[2].text) {
		t.Errorf("the credit link is attribution, the script tag is not: %+v", hits[1:])
	}
}

// isCredit says whether a line of a web or text file is attribution text and
// nothing that fetches an address
func isCredit(line string) bool {
	return attribution.MatchString(line) && !loads.MatchString(line)
}

// Credit wording does not excuse a line that loads something
func TestCreditWordingDoesNotExcuseALoad(t *testing.T) {
	for _, line := range []string{
		`<script src="https://zoraxy.aroz.org/x.js"></script> <!-- upstream -->`,
		`<img src="https://imuslab.com/logo.png" alt="based on Zoraxy">`,
		`$.get("https://raw.githubusercontent.com/tobychui/zoraxy/main/x.json") // upstream version check`,
		`fetch("https://zoraxy.aroz.org/api") /* credit */`,
		`<link rel="stylesheet" href="https://zoraxy.aroz.org/x.css"> Copyright tobychui`,
		`<iframe src="//aroz.org"></iframe> developed by tobychui`,
		`background: url(https://zoraxy.aroz.org/bg.png); /* upstream */`,
	} {
		if isCredit(line) {
			t.Errorf("a line that loads an upstream address must not count as a credit: %s", line)
		}
	}
	for _, line := range []string{
		`<p>Proudly powered by <a href="https://zoraxy.aroz.org" target="_blank">Zoraxy</a></p>`, // legacy-compat: sample of a credit line
		`Original implementation: https://github.com/tobychui/zoraxy/pull/568`,
	} {
		if !isCredit(line) {
			t.Errorf("a credit link must stay a credit: %s", line)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
