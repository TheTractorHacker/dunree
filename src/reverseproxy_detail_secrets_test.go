package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
)

// API-04: /api/proxy/detail and /api/proxy/list (readable by viewers and by plugins) must not
// return basic auth password hashes or header rule secrets, for host rules and for the default site.
func TestProxyReadEndpointsDoNotLeakSecrets(t *testing.T) {
	router := setupEditTest(t)
	const host = "app.example.com"
	const hashSentinel, headerSentinel = "API04-HASH-SENTINEL", "API04-HEADER-SENTINEL"
	arm := func(ep *dynamicproxy.ProxyEndpoint) {
		ep.AuthenticationProvider = &dynamicproxy.AuthenticationProvider{
			AuthMethod: dynamicproxy.AuthMethodBasic,
			BasicAuthCredentials: []*dynamicproxy.BasicAuthCredentials{
				{Username: "alice", PasswordHash: hashSentinel + "-1"},
				{Username: "bob", PasswordHash: hashSentinel + "-2"},
			},
		}
		ep.HeaderRules = []*dynamicproxy.HeaderRule{{Name: "X-Edge-Key", Values: []string{headerSentinel}}}
	}
	live, err := router.LoadProxy(host)
	if err != nil {
		t.Fatal(err)
	}
	arm(live)
	root := dynamicproxy.CopyEndpoint(live)
	root.ProxyType = dynamicproxy.ProxyTypeRoot
	root.RootOrMatchingDomain = "/"
	arm(root)
	oldRoot := router.Root
	router.Root = root
	t.Cleanup(func() { router.Root = oldRoot })

	get := func(h http.HandlerFunc, target string) string {
		t.Helper()
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, target, nil))
		return w.Body.String()
	}
	for _, c := range []struct {
		name string
		body string
		list bool
	}{
		{"detail host", get(ReverseProxyListDetail, "/api/proxy/detail?type=host&epname="+host), false},
		{"detail root", get(ReverseProxyListDetail, "/api/proxy/detail?type=root"), false},
		{"list host", get(ReverseProxyList, "/api/proxy/list?type=host"), true},
		{"list root", get(ReverseProxyList, "/api/proxy/list?type=root"), false},
	} {
		for _, bad := range []string{hashSentinel, headerSentinel} {
			if strings.Contains(c.body, bad) {
				t.Errorf("%s leaks %q:\n%s", c.name, bad, c.body)
			}
		}
		// the response keeps its shape: user names and the rule slots are still there
		ep := &dynamicproxy.ProxyEndpoint{}
		if c.list {
			var eps []*dynamicproxy.ProxyEndpoint
			if err := json.Unmarshal([]byte(c.body), &eps); err != nil || len(eps) != 1 {
				t.Fatalf("%s: %v %s", c.name, err, c.body)
			}
			ep = eps[0]
		} else if err := json.Unmarshal([]byte(c.body), ep); err != nil {
			t.Fatalf("%s: %v %s", c.name, err, c.body)
		}
		creds := ep.AuthenticationProvider.BasicAuthCredentials
		if len(creds) != 2 || creds[0].Username != "alice" || creds[1].Username != "bob" || creds[0].PasswordHash != "" || creds[1].PasswordHash != "" {
			t.Errorf("%s: credentials = %s", c.name, c.body)
		}
		if len(ep.HeaderRules) != 1 || ep.HeaderRules[0].Name != "X-Edge-Key" || len(ep.HeaderRules[0].Values) != 1 || ep.HeaderRules[0].Values[0] != "" {
			t.Errorf("%s: header rules = %s", c.name, c.body)
		}
	}

	// masking works on a copy: the running rules keep their secrets
	for _, ep := range []*dynamicproxy.ProxyEndpoint{live, root} {
		if ep.AuthenticationProvider.BasicAuthCredentials[0].PasswordHash != hashSentinel+"-1" || ep.HeaderRules[0].Values[0] != headerSentinel {
			t.Fatal("the read endpoints changed the live rule")
		}
	}

	// no default site configured: still "null", as before
	router.Root = nil
	if body := strings.TrimSpace(get(ReverseProxyListDetail, "/api/proxy/detail?type=root")); body != "null" {
		t.Fatalf("nil root = %q", body)
	}
}
