package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/foleyit/dunree/mod/brand"
)

/*
	The brand inside the product and the project documents (Dunree rebrand).

	What these tests hold:
	  - the admin interface is told name, version, publisher and base by the server (mod/brand);
	  - logo and icon files of the admin interface are the files of brand/, in a light and a dark variant;
	  - the credit to Zoraxy, tobychui and imuslab is on the pages that show the Dunree name;
	  - LICENSE and NOTICE are shipped with the interface, unchanged;
	  - pages a visitor sees say Dunree and do not lead to the website of the Zoraxy project;
	  - README, SECURITY, CONTRIBUTING, CODEOWNERS, CHANGELOG, ROADMAP and the docs index exist and say what they must.
*/

func brandRead(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// repoRoot is the folder above src/. A source archive that only holds src/ skips the tests that need it.
func repoRoot(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join("..", "LICENSE")); err != nil {
		t.Skip("repository root (../LICENSE) not present")
	}
	return ".."
}

const brandAttribution = "Based on Zoraxy v3.3.6 by tobychui and imuslab, AGPL-3.0"

// /api/info/x: the About page and the footer take everything from here.
func TestInfoEndpointReportsBrand(t *testing.T) {
	oldAuth := requireAuth
	requireAuth = false
	t.Cleanup(func() { requireAuth = oldAuth })

	w := httptest.NewRecorder()
	HandleDunreeInfo(w, httptest.NewRequest(http.MethodGet, "/api/info/x", nil))
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v: %s", err, w.Body.String())
	}
	want := map[string]string{
		"Product": "Dunree", "ProductVersion": brand.Version, "Publisher": "Foley IT", "License": "AGPL-3.0",
		"BasedOn": "Zoraxy", "BasedOnVersion": "3.3.6", "BasedOnAuthors": "tobychui and imuslab",
		"Tagline": "Reverse proxy and web gateway", "SourceURL": "", "ProductURL": "",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %q", k, got[k], v)
		}
	}
	// The fields the interface had before are still there, with their meaning: Version is what the
	// updater and the configuration migrations compare, not the Dunree version.
	if got["Version"] != PRODUCT_VERSION || got["CompatVersion"] != COMPAT_VERSION {
		t.Errorf("Version = %v, CompatVersion = %v, want %q and %q", got["Version"], got["CompatVersion"], PRODUCT_VERSION, COMPAT_VERSION)
	}
	for _, k := range []string{"NodeUUID", "Development", "BootTime", "EnableSshLoopback", "ZerotierConnected"} {
		if _, ok := got[k]; !ok {
			t.Errorf("existing field %s is gone", k)
		}
	}
	if got["BasedOn"].(string)+" v"+got["BasedOnVersion"].(string) != "Zoraxy v3.3.6" || !strings.Contains(brand.BasedOn(), "tobychui and imuslab") {
		t.Error("the base and its authors are not reported")
	}
}

// Every logo and icon file of the admin interface is a copy of a file in brand/.
var webBrandFiles = map[string]string{
	"img/public/brand/dunree-mark.svg":                "dunree-mark.svg",
	"img/public/brand/dunree-mark-dark.svg":           "dunree-mark-dark.svg",
	"img/public/brand/dunree-mark-white.svg":          "dunree-mark-white.svg",
	"img/public/brand/dunree-mark-mono.svg":           "dunree-mark-mono.svg",
	"img/public/brand/dunree-lockup.svg":              "dunree-lockup.svg",
	"img/public/brand/dunree-lockup-dark.svg":         "dunree-lockup-dark.svg",
	"img/public/brand/dunree-lockup-stacked.svg":      "dunree-lockup-stacked.svg",
	"img/public/brand/dunree-lockup-stacked-dark.svg": "dunree-lockup-stacked-dark.svg",
	"img/public/brand/dunree-app-icon.svg":            "dunree-app-icon.svg",
	"img/public/brand/dunree-app-icon-192.png":        "dunree-app-icon-192.png",
	"img/public/brand/dunree-app-icon-512.png":        "dunree-app-icon-512.png",
	"img/public/brand/favicon.svg":                    "favicon.svg",
	"img/public/brand/favicon.ico":                    "favicon.ico",
	"img/public/brand/favicon-16.png":                 "favicon-16.png",
	"img/public/brand/favicon-32.png":                 "favicon-32.png",
	"img/public/brand/apple-touch-icon.png":           "apple-touch-icon-180.png",
	// paths from before the rebrand keep working and hold the Dunree files
	"img/logo.svg":        "dunree-lockup.svg",
	"img/logo_white.svg":  "dunree-lockup-dark.svg",
	"img/public/logo.svg": "dunree-lockup.svg",
	"img/public/icon.svg": "dunree-app-icon.svg",
	"img/icon.png":        "dunree-app-icon-512.png",
	"img/public/icon.png": "dunree-app-icon-512.png",
	"favicon.png":         "dunree-app-icon-512.png",
}

func TestWebBrandAssetsMatchBrandFolder(t *testing.T) {
	root := repoRoot(t)
	for web, src := range webBrandFiles {
		got, err := os.ReadFile(filepath.Join("web", filepath.FromSlash(web)))
		if err != nil {
			t.Errorf("web/%s is missing: %v", web, err)
			continue
		}
		want, err := os.ReadFile(filepath.Join(root, "brand", src))
		if err != nil {
			t.Fatalf("brand/%s: %v", src, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("web/%s differs from brand/%s: change the file in brand/ and copy it, do not edit the copy", web, src)
		}
	}
	// Other paths from before the rebrand that pages or plugins may still link: present, and PNG files
	for _, p := range []string{"img/logo.png", "img/logo_white.png", "img/public/logo.png", "img/small_icon.png", "img/desktop_icon.png"} {
		b, err := os.ReadFile(filepath.Join("web", filepath.FromSlash(p)))
		if err != nil || !bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) {
			t.Errorf("web/%s must stay a PNG file (old path, now the Dunree logo): %v", p, err)
		}
	}
	// The sign-in portal for visitors carries the Dunree mark by default
	if b := brandRead(t, "mod", "auth", "sso", "zorxauth", "brand_mark.svg"); !strings.Contains(b, "M4 4H20V16H28V4H36V16H44V4H60V36A24 24 0 0 1 36 60H4Z") {
		t.Error("the default mark of the sign-in portal is not the Dunree mark")
	}
	portalIcon, err := os.ReadFile(filepath.Join("mod", "auth", "sso", "zorxauth", "favicon.png"))
	appIcon, _ := os.ReadFile(filepath.Join(root, "brand", "dunree-app-icon-512.png"))
	if err != nil || !bytes.Equal(portalIcon, appIcon) {
		t.Error("the default icon of the sign-in portal is not the Dunree app icon")
	}
}

// brand/README.md: the SVG files carry no style sheet and no script, so they follow the theme the page
// chooses; the blue for light backgrounds is never used in a file for dark backgrounds.
func TestWebBrandSVGRules(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("web", "img", "public", "brand", "*.svg"))
	if err != nil || len(files) < 8 {
		t.Fatalf("brand SVG files not found: %v %v", files, err)
	}
	for _, f := range files {
		s := strings.ToLower(brandRead(t, f))
		for _, bad := range []string{"<style", "<script", "prefers-color-scheme", "href=", "<image", "<foreignobject", "font-family"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
		name := filepath.Base(f)
		switch {
		case strings.Contains(name, "-dark"):
			if strings.Contains(s, "#1a56c4") || !strings.Contains(s, "#6d9bff") {
				t.Errorf("%s: a file for dark backgrounds uses #6d9bff, never #1a56c4", name)
			}
		case name == "dunree-mark.svg" || name == "dunree-lockup.svg" || name == "dunree-lockup-stacked.svg":
			if !strings.Contains(s, "#1a56c4") || strings.Contains(s, "#6d9bff") {
				t.Errorf("%s: a file for light backgrounds uses #1a56c4", name)
			}
		}
	}
	manifest := brandRead(t, "web", "img", "public", "brand", "manifest.json")
	var m struct {
		Name  string `json:"name"`
		Icons []struct {
			Src string `json:"src"`
		} `json:"icons"`
	}
	if err := json.Unmarshal([]byte(manifest), &m); err != nil || m.Name != "Dunree" || len(m.Icons) == 0 {
		t.Fatalf("manifest.json: %v %+v", err, m)
	}
	for _, i := range m.Icons {
		if _, err := os.Stat(filepath.Join("web", "img", "public", "brand", i.Src)); err != nil {
			t.Errorf("manifest.json names an icon that is not there: %s", i.Src)
		}
	}
}

var (
	brandLinkRe  = regexp.MustCompile(`<link rel="(icon|shortcut icon|apple-touch-icon|manifest)"[^>]*href="([^"]+)"`)
	brandTitleRe = regexp.MustCompile(`(?s)<title>(.*?)</title>`)
)

// Pages of the admin interface that have a head of their own: the full icon set, from the folder that is
// readable without a login, and every file it names exists.
func TestAdminPagesUseDunreeIcons(t *testing.T) {
	pages := []string{"index.html", "login.html", "reset.html", "ui/kit.html", "snippet/logview.html", "snippet/logsearch.html", "snippet/notifications.html",
		"tools/https.html", "tools/ipscan.html", "tools/mdns.html", "tools/portscan.html", "tools/sshconn.html"}
	for _, page := range pages {
		s := brandRead(t, "web", filepath.FromSlash(page))
		seen := map[string]bool{}
		for _, m := range brandLinkRe.FindAllStringSubmatch(s, -1) {
			href := m[2]
			if !strings.Contains(href, "img/public/brand/") {
				t.Errorf("%s: %s icon %q is not in img/public/brand", page, m[1], href)
				continue
			}
			target := filepath.Join("web", filepath.Dir(filepath.FromSlash(page)), filepath.FromSlash(href))
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s: %s icon %q does not exist (looked for %s)", page, m[1], href, target)
			}
			seen[m[1]+" "+filepath.Base(href)] = true
		}
		for _, want := range []string{"icon favicon.svg", "icon favicon-32.png", "icon favicon-16.png", "shortcut icon favicon.ico", "apple-touch-icon apple-touch-icon.png", "manifest manifest.json"} {
			if !seen[want] {
				t.Errorf("%s: no <link> for %s", page, want)
			}
		}
	}
}

// Page titles carry the product name; no page of the interface is titled with the old one.
func TestPageTitlesSayDunree(t *testing.T) {
	for page, want := range map[string]string{"index.html": "Control Panel | Dunree", "login.html": "Login | Dunree", "reset.html": "Account Reset | Dunree", "apidocs.html": "Dunree REST API"} {
		m := brandTitleRe.FindStringSubmatch(brandRead(t, "web", page))
		if m == nil || strings.TrimSpace(m[1]) != want {
			t.Errorf("%s: title %q, want %q", page, m, want)
		}
	}
	if s := brandRead(t, "web", "index.html"); !strings.Contains(s, `document.title = (tabLabel ? tabLabel + ' | ' : '') + 'Dunree';`) {
		t.Error("index.html no longer sets the title of a page to \"<page> | Dunree\"")
	}
	err := filepath.WalkDir("web", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".html" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range brandTitleRe.FindAllStringSubmatch(string(b), -1) {
			if strings.Contains(strings.ToLower(m[1]), "zoraxy") { // legacy-compat: the test names the old name
				t.Errorf("%s: title %q carries the old product name", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The logo in the top bar and on the login page: both variants are in the page, the theme picks one.
func TestLogoHasLightAndDarkVariant(t *testing.T) {
	index := brandRead(t, "web", "index.html")
	for _, f := range []string{"dunree-lockup.svg", "dunree-lockup-dark.svg", "dunree-mark.svg", "dunree-mark-dark.svg"} {
		if !strings.Contains(index, `src="img/public/brand/`+f+`"`) {
			t.Errorf("index.html: the top bar does not carry %s", f)
		}
	}
	if !strings.Contains(index, `class="zx-top-logo" href="#status" aria-label="Dunree, go to Status"`) {
		t.Error("index.html: the logo link lost its name")
	}
	css := brandRead(t, "web", "ui", "topbar.css")
	for _, rule := range []string{".zx-top-logo .zx-brand { display: none; height: 32px; width: auto; }", "body:not(.darkTheme) .zx-top-logo .zx-brand--lockup.zx-brand--light,\nbody.darkTheme .zx-top-logo .zx-brand--lockup.zx-brand--dark { display: block; }",
		"body.darkTheme .zx-top-logo .zx-brand--mark.zx-brand--dark { display: block; }"} {
		if !strings.Contains(css, rule) {
			t.Errorf("ui/topbar.css: missing rule %q", rule)
		}
	}
	login := brandRead(t, "web", "login.html")
	for _, want := range []string{`src="img/public/brand/dunree-lockup.svg" alt="Dunree"`, `src="img/public/brand/dunree-lockup-dark.svg"`, "body.night #loginForm .lg-logo--dark { display: block; }"} {
		if !strings.Contains(login, want) {
			t.Errorf("login.html: missing %q", want)
		}
	}
	if strings.Contains(login, "filter: invert") {
		t.Error("login.html: the logo is recoloured with a CSS filter; use the dark file")
	}
	utils := brandRead(t, "web", "components", "utils.html")
	if !strings.Contains(utils, `ut-about__logo--light" src="img/public/brand/dunree-lockup.svg"`) || !strings.Contains(utils, `ut-about__logo--dark" src="img/public/brand/dunree-lockup-dark.svg"`) {
		t.Error("utils.html: the About card does not carry both logo variants")
	}
}

// Attribution: where the interface shows the Dunree name as its own, it also says what Dunree is based
// on and who wrote that. It never presents the Zoraxy authors as the makers of Dunree, and it does not
// send people to their website for Dunree.
func TestAttributionInAdminUI(t *testing.T) {
	for _, page := range []string{"index.html", "login.html", filepath.Join("components", "utils.html")} {
		s := brandRead(t, "web", page)
		for _, want := range []string{brandAttribution, "Published by Foley IT"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: missing %q", page, want)
			}
		}
		for _, bad := range []string{"zoraxy.aroz.org", "imuslab.com", "Dunree is developed by tobychui", "Zoraxy is developed by", "tobychui. Licensed under", "Proudly powered by", "github.com/tobychui"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: still contains %q", page, bad)
			}
		}
	}
	utils := brandRead(t, "web", "components", "utils.html")
	for _, want := range []string{
		`id="dunreeabout"`, `href="legal/LICENSE.txt"`, `href="legal/NOTICE.txt"`, `href="legal/THIRD_PARTY_NOTICES.txt"`, `id="abSource"`,
		"It is not affiliated with or endorsed by tobychui, imuslab or the Zoraxy contributors.",
		`tf("Based on {0} by {1}, {2}"`, `tf("Published by {0}"`, "data.ProductVersion",
		"Supporters of Zoraxy", "they did not donate to Dunree",
	} {
		if !strings.Contains(utils, want) {
			t.Errorf("utils.html: missing %q", want)
		}
	}
	// the source link is built from an address the page checks itself
	if !strings.Contains(utils, `lower.indexOf("https://") === 0 || lower.indexOf("http://") === 0`) || !strings.Contains(utils, "if (plain){") {
		t.Error("utils.html: the source address is no longer checked before it becomes a link")
	}
	if strings.Contains(utils, "Dunree is made possible by the generosity of its supporters") {
		t.Error("utils.html: the supporters of Zoraxy are presented as supporters of Dunree")
	}
	if s := brandRead(t, "web", "script", "supporters.txt"); !strings.Contains(s, "These people donated to\n# Zoraxy.") || strings.Contains(s, "to the Dunree project") {
		t.Error("supporters.txt: the list must say that these people supported Zoraxy, not Dunree")
	}
	index := brandRead(t, "web", "index.html")
	for _, want := range []string{`id="zxBrandFooter"`, `href="legal/LICENSE.txt"`, `href="legal/NOTICE.txt"`} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html footer: missing %q", want)
		}
	}
}

// LICENSE and NOTICE are shipped with the interface (the About page links them) and are the files of the
// repository, byte for byte. The licence text itself is pinned: it must never be edited.
func TestLegalFilesShippedWithUI(t *testing.T) {
	root := repoRoot(t)
	for web, src := range map[string]string{"LICENSE.txt": "LICENSE", "NOTICE.txt": "NOTICE", "THIRD_PARTY_NOTICES.txt": "THIRD_PARTY_NOTICES.md"} {
		got, err := os.ReadFile(filepath.Join("web", "legal", web))
		if err != nil {
			t.Errorf("web/legal/%s: %v", web, err)
			continue
		}
		want, err := os.ReadFile(filepath.Join(root, src))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("web/legal/%s is not the same as %s: copy the file again (cp %s src/web/legal/%s)", web, src, src, web)
		}
	}
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(license)
	if got := hex.EncodeToString(sum[:]); got != "8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef" {
		t.Errorf("LICENSE changed (sha256 %s): the text of the AGPL-3.0 must stay as it is", got)
	}
	if !bytes.Contains(license, []byte("GNU AFFERO GENERAL PUBLIC LICENSE")) || !bytes.Contains(license, []byte("Version 3, 19 November 2007")) {
		t.Error("LICENSE is not the AGPL-3.0")
	}
	notice := strings.Join(strings.Fields(brandRead(t, root, "NOTICE")), " ")
	for _, want := range []string{
		"Dunree", "Copyright (C) 2026 Foley IT", "Dunree is based on Zoraxy v3.3.6", "tobychui", "imuslab",
		"modified, independent derivative of Zoraxy", "not affiliated with, sponsored by or endorsed by tobychui, imuslab",
		"They did not write, review or approve the parts that were added or changed for Dunree",
		"GNU Affero General Public License, version 3", "THIRD_PARTY_NOTICES.md", "section 13",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("NOTICE: missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "THIRD_PARTY_NOTICES.md")); err != nil {
		t.Error("THIRD_PARTY_NOTICES.md is gone")
	}
}

// Pages a visitor of a proxied site can see: Dunree by name, nothing of the old name, no address of the
// Zoraxy project. The copies under web/ and the embedded defaults under mod/dynamicproxy/templates agree.
func TestVisitorPagesCarryDunreeNaming(t *testing.T) {
	upstream := regexp.MustCompile(`(?i)zoraxy|aroz\.org|imuslab|tobychui`) // legacy-compat: the test names the old names
	files := map[string]string{
		filepath.Join("web", "hosterror.html"):                              "Powered by Dunree",
		filepath.Join("web", "rperror.html"):                                "Powered by Dunree",
		filepath.Join("web", "forbidden.html"):                              "Dunree Forbidden Template",
		filepath.Join("web", "notfound.html"):                               "Dunree Not Found Template",
		filepath.Join("mod", "dynamicproxy", "templates", "hosterror.html"): "Powered by Dunree",
		filepath.Join("mod", "dynamicproxy", "templates", "rperror.html"):   "Powered by Dunree",
		filepath.Join("mod", "dynamicproxy", "templates", "forbidden.html"): "Dunree Forbidden Template",
		filepath.Join("mod", "webserv", "templates", "index.html"):          "Welcome to Dunree Static Web Server!",
		filepath.Join("mod", "dynamicproxy", "captcha", "page_base.html"):   `<span class="footer-name">{{.Strings.FooterLink}}</span>`,
		filepath.Join("mod", "dynamicproxy", "captcha", "challenge.html"):   "",
		filepath.Join("mod", "dynamicproxy", "captcha", "failed.html"):      "",
		filepath.Join("mod", "dynamicproxy", "captcha", "blocked.html"):     "",
		filepath.Join("mod", "errorpages", "templates.go"):                  "",
	}
	for f, want := range files {
		s := brandRead(t, f)
		if want != "" && !strings.Contains(s, want) {
			t.Errorf("%s: missing %q", f, want)
		}
		for i, line := range strings.Split(s, "\n") {
			if upstream.MatchString(line) && !strings.Contains(line, "rebrand:keep") && !strings.Contains(line, "legacy-compat") {
				t.Errorf("%s:%d names the old product or its authors: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	// The CAPTCHA settings show the defaults a visitor gets: the Dunree name, and no address of the Zoraxy project
	for _, f := range []string{filepath.Join("web", "components", "captcha.html"), filepath.Join("web", "components", "httprp.html")} {
		s := brandRead(t, f)
		if !strings.Contains(s, `data-cp="captchaFooterLinkText" maxlength="120" placeholder="Dunree"`) || strings.Contains(s, "aroz.org") {
			t.Errorf("%s: the footer placeholders must show the Dunree default and no address of the Zoraxy project", f)
		}
	}
	for _, pair := range [][2]string{{"hosterror.html", "hosterror.html"}, {"rperror.html", "rperror.html"}, {"forbidden.html", "forbidden.html"}} {
		if brandRead(t, "web", pair[0]) != brandRead(t, "mod", "dynamicproxy", "templates", pair[1]) {
			t.Errorf("web/%s and mod/dynamicproxy/templates/%s differ", pair[0], pair[1])
		}
	}
}

var mdLinkRe = regexp.MustCompile(`\]\(([^)#\s]+)(#[^)]*)?\)`)

// checkRelativeLinks fails for a link of a Markdown file to a file or folder that is not there.
func checkRelativeLinks(t *testing.T, file string) {
	t.Helper()
	s := brandRead(t, file)
	for _, m := range mdLinkRe.FindAllStringSubmatch(s, -1) {
		target := m[1]
		if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(file), filepath.FromSlash(target))); err != nil {
			t.Errorf("%s links to %q, which does not exist", file, target)
		}
	}
}

func TestProjectDocs(t *testing.T) {
	root := repoRoot(t)

	readme := brandRead(t, root, "README.md")
	for _, want := range []string{
		"# Dunree", "Reverse proxy and web gateway", "Published by Foley IT", "v1.0.0-beta.1", "Dunree is based on Zoraxy v3.3.6 by tobychui and imuslab",
		"## Features", "### Sites and routing", "### Certificates and TLS", "### Security", "### Traffic and monitoring", "### Operations", "### Extending",
		"## Screenshots", "<!-- screenshots:begin", "<!-- screenshots:end -->", "docs/img/screenshots/",
		"## Install", "### Build from source (all platforms)", "### Linux", "### Windows", "### macOS and FreeBSD", "### Docker",
		"## Migrating from Zoraxy", "docs/migrating-from-zoraxy.md",
		"## Plugins and add-ons", "docs/plugins/addon-store.md",
		"## Security policy", "SECURITY.md",
		"## Licence and attribution", "GNU Affero General Public License, version 3", "[`NOTICE`](NOTICE)", "THIRD_PARTY_NOTICES.md",
		"It is not affiliated with or endorsed by tobychui, imuslab or the Zoraxy contributors.",
		"They are not the work of the Zoraxy authors.",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md: missing %q", want)
		}
	}
	// The README does not send people to the downloads, wiki, website, store, image or donation pages of the Zoraxy project
	for _, bad := range []string{"zoraxy.aroz.org", "tobychui/zoraxy/releases", "tobychui/zoraxy/wiki", "zoraxydocker", "aroz-online", "paypal.me", "git clone https://github.com/tobychui"} {
		if strings.Contains(readme, bad) {
			t.Errorf("README.md: still contains %q", bad)
		}
	}
	checkRelativeLinks(t, filepath.Join(root, "README.md"))
	for _, img := range []string{"brand/dunree-lockup.svg", "brand/dunree-lockup-dark.svg"} {
		if !strings.Contains(readme, img) {
			t.Errorf("README.md: the logo %s is not used", img)
		}
	}
	if fi, err := os.Stat(filepath.Join(root, "docs", "img", "screenshots")); err != nil || !fi.IsDir() {
		t.Error("docs/img/screenshots/ (where the screenshot step writes) is missing")
	}

	security := brandRead(t, root, "SECURITY.md")
	for _, want := range []string{"Dunree", "Foley IT", "Reporting a vulnerability", "Security contact:", "Supported versions", "Do not report Dunree vulnerabilities to the Zoraxy project."} {
		if !strings.Contains(security, want) {
			t.Errorf("SECURITY.md: missing %q", want)
		}
	}

	contributing := brandRead(t, root, "CONTRIBUTING.md")
	for _, want := range []string{"AGPL-3.0", "Developer Certificate of Origin", "Do not remove or change the copyright and licence headers of the original authors", "docs/ux/changes.md", "go test -p 1 ./..."} {
		if !strings.Contains(contributing, want) {
			t.Errorf("CONTRIBUTING.md: missing %q", want)
		}
	}
	checkRelativeLinks(t, filepath.Join(root, "CONTRIBUTING.md"))

	// CODEOWNERS: nobody of the Zoraxy project is asked to review Dunree changes
	for i, line := range strings.Split(brandRead(t, root, "CODEOWNERS"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, who := range []string{"@tobychui", "@PassiveLemon", "@james-d-elliott", "@jemmy1794", "@AnthonyMichaelTDM"} {
			if strings.Contains(line, who) {
				t.Errorf("CODEOWNERS:%d makes %s an owner of Dunree code", i+1, who)
			}
		}
	}

	changelog := brandRead(t, root, "CHANGELOG.md")
	if !strings.HasPrefix(changelog, "# Dunree change log") || !strings.Contains(changelog, "# Dunree v1.0.0-beta.1") || !strings.Contains(changelog, "Based on Zoraxy v3.3.6") {
		t.Error("CHANGELOG.md does not start the Dunree line (v1.0.0-beta.1, based on Zoraxy v3.3.6)")
	}
	// the history of Zoraxy stays, with the names of the people who did the work
	hist := strings.Index(changelog, "# History: Zoraxy")
	if hist < 0 || !strings.Contains(changelog[hist:], "# v3.3.4 22 Aug 2026") || !strings.Contains(changelog[hist:], "# v3.3.3 09 Jun 2026") ||
		strings.Count(changelog[hist:], "tobychui") < 100 || strings.Index(changelog, "# Dunree v1.0.0-beta.1") > hist {
		t.Error("CHANGELOG.md: the change log of Zoraxy must stay below the Dunree line, unchanged")
	}

	roadmap := brandRead(t, root, "ROADMAP.md")
	if !strings.HasPrefix(roadmap, "# Dunree roadmap") || strings.Count(roadmap, "\n") > 120 {
		t.Error("ROADMAP.md is not the short Dunree roadmap")
	}
	checkRelativeLinks(t, filepath.Join(root, "ROADMAP.md"))
	if s := brandRead(t, root, "docs", "roadmap-history.md"); !strings.Contains(s, "## 6. High availability") || !strings.Contains(s, "## 8. Plugins / add-ons") {
		t.Error("docs/roadmap-history.md lost the sections other documents refer to")
	}

	index := brandRead(t, root, "docs", "README.md")
	if !strings.HasPrefix(index, "# Dunree documentation") {
		t.Error("docs/README.md is not the documentation index")
	}
	checkRelativeLinks(t, filepath.Join(root, "docs", "README.md"))
	// every guide is in the index
	guides, _ := filepath.Glob(filepath.Join(root, "docs", "guides", "*.md"))
	for _, g := range guides {
		if !strings.Contains(index, "guides/"+filepath.Base(g)) {
			t.Errorf("docs/README.md does not list guides/%s", filepath.Base(g))
		}
	}
	// publishing docs/ must never claim the address of the Zoraxy website
	if _, err := os.Stat(filepath.Join(root, "docs", "CNAME")); err == nil {
		t.Error("docs/CNAME exists: it would point a published docs folder at a domain")
	}

	for _, f := range []string{filepath.Join("docs", "ux", "design-v2.md"), filepath.Join("docs", "ux", "components.md")} {
		s := brandRead(t, root, f)
		if !strings.Contains(s, "brand/README.md") {
			t.Errorf("%s does not refer to the brand rules", f)
		}
		for i, line := range strings.Split(s, "\n") {
			if regexp.MustCompile(`Zoraxy`).MatchString(line) && !strings.Contains(line, "tobychui") && !strings.Contains(line, "rebrand:keep") { // legacy-compat
				t.Errorf("%s:%d still uses the old product name: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// SECURITY.md carries a placeholder until the owner sets the contact. The test does not fail on it (the
// decision is the owner's); it makes sure the placeholder is the documented one and reports it.
func TestSecurityPolicyNamesAContact(t *testing.T) {
	root := repoRoot(t)
	s := brandRead(t, root, "SECURITY.md")
	const placeholder = "SECURITY-CONTACT-NOT-SET"
	if strings.Contains(s, placeholder) {
		if !strings.Contains(s, "OWNER: set the security contact before the first public release") {
			t.Error("SECURITY.md has the placeholder but no longer tells the owner what to do")
		}
		if brand.SecurityContact != "" {
			t.Error("mod/brand has a security contact but SECURITY.md still shows the placeholder")
		}
		t.Log("NOTE for the owner: SECURITY.md still carries the placeholder security contact. Set it (and brand.SecurityContact) before the first public release.")
		return
	}
	if !regexp.MustCompile(`\*\*Security contact:\*\* \S+`).MatchString(s) {
		t.Error("SECURITY.md names no security contact")
	}
}
