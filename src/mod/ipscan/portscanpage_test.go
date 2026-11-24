package ipscan

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The port scan page takes the target from the ?ip= query parameter and runs
// the scan on load. This handler only validates the "ip" parameter, so a value
// such as "1.1.1.1&x=<img src=x onerror=...>" used to pass the server check
// and then be written into the page as HTML (WEB-XSS-01). These checks keep
// the page from regressing to that pattern.
func TestPortScanPageDoesNotRenderTargetAsHTML(t *testing.T) {
	raw, err := os.ReadFile("../../web/tools/portscan.html")
	if err != nil {
		t.Fatalf("read portscan.html: %v", err)
	}
	page := string(raw)

	// The request must carry the target as one encoded parameter value
	if !strings.Contains(page, `"/api/tools/portscan?ip=" + encodeURIComponent(ipToScan)`) {
		t.Error("portscan.html must pass the target through encodeURIComponent")
	}
	if regexp.MustCompile(`portscan\?ip="\s*\+\s*ipToScan`).MatchString(page) {
		t.Error("portscan.html appends the raw target to the request URL")
	}

	// The target must never reach an HTML sink
	for _, sink := range []string{".html(", "innerHTML", "document.write", "insertAdjacentHTML"} {
		if strings.Contains(page, sink) {
			t.Errorf("portscan.html uses the HTML sink %q", sink)
		}
	}
	// jQuery parses a string argument of $() / append() as HTML too, so the
	// target must not be concatenated or interpolated into one
	for _, line := range strings.Split(page, "\n") {
		if !strings.Contains(line, "ipToScan") && !strings.Contains(line, "fullPath") && !strings.Contains(line, "hostPart") {
			continue
		}
		if strings.Contains(line, "<") && !strings.Contains(line, "$(\"<a></a>\")") && !strings.Contains(line, "i <") {
			t.Errorf("target is combined with markup: %s", strings.TrimSpace(line))
		}
		if strings.Contains(line, "${") {
			t.Errorf("target is interpolated into a template string: %s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(page, `.text(fullPath)`) {
		t.Error("the result link label must be set with .text()")
	}

	// The scan must be refused before any request unless the value is a bare IP
	guard := strings.Index(page, "if (!isBareIP(ipToScan))")
	request := strings.Index(page, "$.get(")
	if guard < 0 || request < 0 || guard > request {
		t.Fatal("portscan.html must reject a non-IP target before it starts the scan")
	}
}

// Mirror of the two patterns isBareIP uses in portscan.html. The test fails if
// the page stops using them, so the accept / reject table below stays honest.
func TestPortScanPageBareIPPatterns(t *testing.T) {
	raw, err := os.ReadFile("../../web/tools/portscan.html")
	if err != nil {
		t.Fatalf("read portscan.html: %v", err)
	}
	page := string(raw)

	const v4 = `^(\d{1,3}\.){3}\d{1,3}$`
	const v6 = `^[0-9a-fA-F:.]+$`
	for _, pattern := range []string{v4, v6} {
		if !strings.Contains(page, "/"+pattern+"/.test(value)") {
			t.Fatalf("portscan.html no longer uses the pattern %s", pattern)
		}
	}
	v4re, v6re := regexp.MustCompile(v4), regexp.MustCompile(v6)
	accepts := func(value string) bool {
		return v4re.MatchString(value) || (strings.Contains(value, ":") && v6re.MatchString(value))
	}

	for _, good := range []string{"1.1.1.1", "192.168.0.10", "::1", "2001:db8::1", "::ffff:10.0.0.1"} {
		if !accepts(good) {
			t.Errorf("%q should be accepted", good)
		}
	}
	for _, bad := range []string{
		"",
		`1.1.1.1&x=<img src=x onerror=alert(1)>`,
		`1.1.1.1"><script>alert(1)</script>`,
		"1.1.1.1&x=1",
		"1.1.1.1 ",
		"1.1.1.1/24",
		"example.com",
		"javascript:alert(1)",
		"::1%eth0",
		"[::1]",
		"1.1.1.1\n<b>",
	} {
		if accepts(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
