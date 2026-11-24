package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// WEB-XSS-02: snippet/pluginInfo.html runs in the admin origin but renders
// fields that come straight from a plugin's own introspect output. Those
// values must never reach an HTML sink or an unchecked href, otherwise a
// plugin escapes the UI isolation origin and runs script as the admin.
func TestPluginInfoSnippetDoesNotRenderPluginSpecAsHTML(t *testing.T) {
	raw, err := os.ReadFile("web/snippet/pluginInfo.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	// No template interpolation may flow into a jQuery HTML sink, and no
	// markup may be built by interpolating into a tag or attribute.
	for name, re := range map[string]*regexp.Regexp{
		"interpolation inside .html()":            regexp.MustCompile("\\.html\\(\\s*`[^`]*\\$\\{"),
		"interpolation inside .append()/.prepend": regexp.MustCompile("\\.(append|prepend|after|before)\\(\\s*`[^`]*\\$\\{"),
		"interpolation inside markup":             regexp.MustCompile("`[^`]*<[a-zA-Z][^`]*\\$\\{[^`]*`"),
		"innerHTML assignment":                    regexp.MustCompile(`\.(innerHTML|outerHTML)\s*=`),
		"document.write":                          regexp.MustCompile(`document\.write`),
	} {
		if loc := re.FindStringIndex(src); loc != nil {
			line := 1 + strings.Count(src[:loc[0]], "\n")
			t.Errorf("%s at pluginInfo.html:%d: %q", name, line, src[loc[0]:loc[1]])
		}
	}

	// The only remaining .html() calls must take a constant string literal
	// (or a ternary of constant literals keyed on data.Enabled).
	htmlCall := regexp.MustCompile(`\.html\(([^;\n]*)\);`)
	for _, m := range htmlCall.FindAllStringSubmatch(src, -1) {
		arg := strings.TrimSpace(m[1])
		arg = strings.TrimPrefix(arg, "data.Enabled?")
		isLiteral := strings.HasPrefix(arg, "'") || strings.HasPrefix(arg, "\"") || strings.HasPrefix(arg, "`")
		if !isLiteral || strings.Contains(arg, "data.") || strings.Contains(arg, "${") || strings.Contains(arg, "+") {
			t.Errorf(".html() called with non-constant argument: %s", m[0])
		}
	}

	// Links are built through the scheme allowlist helper only.
	if !regexp.MustCompile(`\["http:",\s*"https:",\s*"mailto:"\]\.includes\(parsed\.protocol\)`).MatchString(src) {
		t.Error("href scheme allowlist (http, https, mailto) is missing")
	}
	if n := strings.Count(src, ".attr({href:") + strings.Count(src, `.attr("href"`) + strings.Count(src, `.attr('href'`); n != 1 {
		t.Errorf("expected exactly one place that sets an href (inside setPluginLink), found %d", n)
	}
	if strings.Contains(src, `href="${`) {
		t.Error("href is interpolated from untrusted data")
	}
	for _, want := range []string{
		`setPluginLink("#plugin_author", authorContact, data.Spec.author)`,
		`setPluginLink("#plugin_url", data.Spec.url, data.Spec.url)`,
		`setPluginLink("#plugin_contact", authorContact, data.Spec.author_contact)`,
		"plugin_id=${encodeURIComponent(pluginId)}",
		"plugin_id=${encodeURIComponent(data.Spec.id)}",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("expected pluginInfo.html to contain %q", want)
		}
	}
}
