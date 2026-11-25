package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
)

/*
	h2c option of virtual directories through the API (issue #201):
	/api/proxy/vdir/add and /api/proxy/vdir/edit take "h2c", default off.
*/

func postVdir(t *testing.T, handler http.HandlerFunc, values url.Values) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/proxy/vdir/x", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler(w, r)
	return strings.TrimSpace(w.Body.String())
}

func TestVdirH2CAddAndEdit(t *testing.T) {
	router := setupEditTest(t)
	const host = "app.example.com"
	vdirOf := func(path string) (h2c bool, tls bool, found bool) {
		ep, err := router.LoadProxy(host)
		if err != nil {
			t.Fatal(err)
		}
		v := ep.GetVirtualDirectoryRuleByMatchingPath(path)
		if v == nil {
			return false, false, false
		}
		return v.H2C, v.RequireTLS, true
	}
	add := func(path string, extra url.Values) string {
		v := url.Values{"type": {"host"}, "endpoint": {host}, "path": {path}, "domain": {"203.0.113.10:80" + path}}
		for k, val := range extra {
			v[k] = val
		}
		return postVdir(t, ReverseProxyAddVdir, v)
	}
	edit := func(path string, extra url.Values) string {
		v := url.Values{"type": {"host"}, "path": {host}, "vdir": {path}, "domain": {"203.0.113.10:80" + path}}
		for k, val := range extra {
			v[k] = val
		}
		return postVdir(t, ReverseProxyEditVdir, v)
	}

	// default: off, and nothing about it in the stored file
	if out := add("/api/", nil); strings.Contains(out, "error") {
		t.Fatalf("add without h2c: %s", out)
	}
	if h2c, _, found := vdirOf("/api/"); !found || h2c {
		t.Fatalf("a directory added without the parameter must have h2c off (found=%v h2c=%v)", found, h2c)
	}
	stored := readStoredProxyConfigs(t)
	if strings.Contains(stored, "H2C\":true") {
		t.Fatalf("h2c stored without being asked for: %s", stored)
	}

	// opt in
	const grpcPath = "/management.ManagementService/"
	if out := add(grpcPath, url.Values{"h2c": {"true"}}); strings.Contains(out, "error") {
		t.Fatalf("add with h2c: %s", out)
	}
	if h2c, _, found := vdirOf(grpcPath); !found || !h2c {
		t.Fatalf("h2c not stored on add (found=%v h2c=%v)", found, h2c)
	}
	if stored := readStoredProxyConfigs(t); !strings.Contains(stored, "\"H2C\":true") && !strings.Contains(stored, "\"H2C\": true") {
		t.Fatalf("h2c is not in the saved configuration: %s", stored)
	}

	// h2c together with TLS is refused with a reason, nothing is created
	if out := add("/tls/", url.Values{"h2c": {"true"}, "reqTLS": {"true"}}); !strings.Contains(out, "h2c") || !strings.Contains(out, "error") {
		t.Fatalf("h2c with TLS must be refused, got %s", out)
	}
	if _, _, found := vdirOf("/tls/"); found {
		t.Fatal("a refused directory was created")
	}

	// an edit that does not name h2c (older scripts) keeps it
	if out := edit(grpcPath, nil); strings.Contains(out, "error") {
		t.Fatalf("edit without h2c: %s", out)
	}
	if h2c, _, _ := vdirOf(grpcPath); !h2c {
		t.Fatal("an edit without the h2c parameter switched h2c off")
	}
	// ... but switching TLS on that way drops it, the two do not go together
	if out := edit(grpcPath, url.Values{"reqTLS": {"true"}}); strings.Contains(out, "error") {
		t.Fatalf("edit to TLS: %s", out)
	}
	if h2c, tls, _ := vdirOf(grpcPath); h2c || !tls {
		t.Fatalf("after switching TLS on: h2c=%v tls=%v, want false true", h2c, tls)
	}
	// explicit on / refused with TLS / explicit off
	if out := edit(grpcPath, url.Values{"h2c": {"true"}, "reqTLS": {"true"}}); !strings.Contains(out, "error") {
		t.Fatalf("edit h2c with TLS must be refused, got %s", out)
	}
	if out := edit(grpcPath, url.Values{"h2c": {"true"}, "reqTLS": {"false"}}); strings.Contains(out, "error") {
		t.Fatalf("edit h2c on: %s", out)
	}
	if h2c, tls, _ := vdirOf(grpcPath); !h2c || tls {
		t.Fatalf("edit h2c on: h2c=%v tls=%v", h2c, tls)
	}
	if out := edit(grpcPath, url.Values{"h2c": {"false"}}); strings.Contains(out, "error") {
		t.Fatalf("edit h2c off: %s", out)
	}
	if h2c, _, _ := vdirOf(grpcPath); h2c {
		t.Fatal("h2c could not be switched off")
	}

	// an edit without the parameter that moves the target to https:// drops the stored flag too
	// (the flag would be ignored there, and the list would still claim h2c)
	if out := edit(grpcPath, url.Values{"h2c": {"true"}}); strings.Contains(out, "error") {
		t.Fatalf("edit h2c on again: %s", out)
	}
	if out := edit(grpcPath, url.Values{"domain": {"https://203.0.113.10:443" + grpcPath}}); strings.Contains(out, "error") {
		t.Fatalf("edit to an https:// target: %s", out)
	}
	if h2c, _, _ := vdirOf(grpcPath); h2c {
		t.Fatal("h2c stayed stored on a target address with https://")
	}

	// a value that is not true or false is refused instead of being read as off / unchanged
	for _, bad := range []string{"1", "on", "yes"} {
		if out := add("/bad/", url.Values{"h2c": {bad}}); !strings.Contains(out, "error") || !strings.Contains(out, "h2c must be true or false") {
			t.Fatalf("add with h2c=%s must be refused, got %s", bad, out)
		}
		if _, _, found := vdirOf("/bad/"); found {
			t.Fatalf("a directory with h2c=%s was created", bad)
		}
		if out := edit(grpcPath, url.Values{"h2c": {bad}}); !strings.Contains(out, "h2c must be true or false") {
			t.Fatalf("edit with h2c=%s must be refused, got %s", bad, out)
		}
	}
	// an empty value counts as not given, as before
	if out := add("/empty/", url.Values{"h2c": {""}}); strings.Contains(out, "error") {
		t.Fatalf("add with an empty h2c: %s", out)
	}
}

// The uptime monitor probes with HTTP/1.1. An h2c target would always be reported as down,
// so it is left out; the other path routes of the host are still monitored.
func TestVdirH2CNotInUptimeTargets(t *testing.T) {
	router := setupEditTest(t)
	ep, err := router.LoadProxy("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ep.DisableUptimeMonitor = false
	ep.VirtualDirectories = []*dynamicproxy.VirtualDirectoryEndpoint{
		{MatchingPath: "/grpc.Service/", Domain: "203.0.113.10:80/grpc.Service/", H2C: true},
		{MatchingPath: "/api/", Domain: "203.0.113.10:80/api/"},
	}
	names := []string{}
	for _, target := range GetUptimeTargetsFromReverseProxyRules(router) {
		names = append(names, target.Name)
	}
	joined := strings.Join(names, " ")
	if strings.Contains(joined, "/grpc.Service/") {
		t.Errorf("the h2c path route is probed by the uptime monitor: %v", names)
	}
	if !strings.Contains(joined, "app.example.com/api/") {
		t.Errorf("the plain path route is no longer monitored: %v", names)
	}
}

func readStoredProxyConfigs(t *testing.T) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(CONF_HTTP_PROXY, "*"))
	all := ""
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all += string(b)
	}
	if all == "" {
		t.Fatal("no proxy configuration was saved")
	}
	return all
}
