package dynamicproxy

import (
	"sync"
	"testing"
)

func TestZorxAuthSessionTarget(t *testing.T) {
	sso := &AuthenticationProvider{AuthMethod: AuthMethodZorxAuth}
	router := &Router{Option: &RouterOption{UseTls: true}, ProxyEndpoints: &sync.Map{}}
	for _, ep := range []*ProxyEndpoint{
		{RootOrMatchingDomain: "app.example.com", MatchingDomainAlias: []string{"alias.example.com"}, AuthenticationProvider: sso},
		{RootOrMatchingDomain: "*.wild.example.com", AuthenticationProvider: sso},
		{RootOrMatchingDomain: "plain.example.com", AuthenticationProvider: sso, BypassGlobalTLS: true},
		{RootOrMatchingDomain: "ports.example.com", AuthenticationProvider: sso, ListeningPorts: []string{":8080"}},
		{RootOrMatchingDomain: "off.example.com", AuthenticationProvider: sso, Disabled: true},
		{RootOrMatchingDomain: "basic.example.com", AuthenticationProvider: &AuthenticationProvider{AuthMethod: AuthMethodBasic}},
		{RootOrMatchingDomain: "open.example.com"},
	} {
		router.ProxyEndpoints.Store(ep.RootOrMatchingDomain, ep)
	}

	for host, want := range map[string][2]bool{
		"app.example.com":    {true, true},
		"alias.example.com":  {true, true},
		"a.wild.example.com": {true, true},
		"plain.example.com":  {true, false},
		"ports.example.com":  {true, false},
		"off.example.com":    {false, false},
		"basic.example.com":  {false, false},
		"open.example.com":   {false, false},
		"evil.tld":           {false, false}, //default site: never authenticated by ZorxAuth
		"":                   {false, false},
	} {
		protected, httpsOnly := router.ZorxAuthSessionTarget(host)
		if protected != want[0] || httpsOnly != want[1] {
			t.Errorf("%q: got protected=%v httpsOnly=%v, want %v", host, protected, httpsOnly, want)
		}
	}

	router.Option.UseTls = false
	if protected, httpsOnly := router.ZorxAuthSessionTarget("app.example.com"); !protected || httpsOnly {
		t.Errorf("plain http proxy: got protected=%v httpsOnly=%v", protected, httpsOnly)
	}
	var none *Router
	if protected, _ := none.ZorxAuthSessionTarget("app.example.com"); protected {
		t.Error("no router: nothing is protected")
	}
}
