package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A GET request skips the CSRF token check (gorilla/csrf only validates unsafe methods) and is
// allowed for viewer accounts, so it must never change anything: not through a query string
// handed to a handler that reads with utils.PostPara, and not through the ?enable= setters.
func TestGetRequestCannotChangeProxyState(t *testing.T) {
	router := setupEditTest(t)
	const host = "app.example.com"

	get := func(h http.HandlerFunc, target string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, target, nil))
		return w
	}

	//Delete: the rule stays in the runtime
	w := get(DeleteProxyEndpoint, "/api/proxy/del?ep="+host)
	if !strings.Contains(w.Body.String(), "error") {
		t.Errorf("GET /api/proxy/del answered %q, want an error", w.Body.String())
	}
	ep, err := router.LoadProxy(host)
	if err != nil || ep == nil {
		t.Fatalf("GET /api/proxy/del?ep=%s removed the rule: %v", host, err)
	}

	//Toggle: the rule stays enabled
	get(ReverseProxyToggleRuleSet, "/api/proxy/toggle?ep="+host+"&enable=false")
	if ep, err = router.LoadProxy(host); err != nil || ep.Disabled {
		t.Fatalf("GET /api/proxy/toggle disabled the rule (err %v)", err)
	}

	//Global setters that take ?enable= from the query string
	router.Option.NoCache = false
	router.Option.SanitiseClientIPHeaders = false
	router.Option.UseProxyProtocol = false
	for path, h := range map[string]http.HandlerFunc{
		"/api/proxy/developmentMode":  HandleDevelopmentModeChange,
		"/api/proxy/sanitiseClientIP": HandleSanitiseClientIPChange,
		"/api/proxy/proxyProtocol":    HandleProxyProtocolChange,
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := httptest.NewRecorder()
			h(w, httptest.NewRequest(method, path+"?enable=true", nil))
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s?enable=true = %d, want 405", method, path, w.Code)
			}
		}
		//Reading the current value with a plain GET keeps working
		if w := get(h, path); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "false" {
			t.Errorf("GET %s = %d %q, want 200 false", path, w.Code, w.Body.String())
		}
	}
	if router.Option.NoCache || router.Option.SanitiseClientIPHeaders || router.Option.UseProxyProtocol {
		t.Fatalf("a GET changed a global setting: %+v", []bool{router.Option.NoCache, router.Option.SanitiseClientIPHeaders, router.Option.UseProxyProtocol})
	}
}

// The read endpoints the admin UI and the v1 API call with GET and a query string keep working.
func TestGetReadEndpointsKeepQueryParameters(t *testing.T) {
	setupEditTest(t)
	const host = "app.example.com"
	for target, h := range map[string]http.HandlerFunc{
		"/api/proxy/list?type=host":                  ReverseProxyList,
		"/api/proxy/detail?type=host&epname=" + host: ReverseProxyListDetail,
		"/api/proxy/vdir/list?type=host&ep=" + host:  ReverseProxyListVdir,
	} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, target, nil))
		body := w.Body.String()
		if w.Code != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Errorf("GET %s = %d %s", target, w.Code, body)
		}
	}
	w := httptest.NewRecorder()
	ReverseProxyList(w, httptest.NewRequest(http.MethodGet, "/api/proxy/list?type=host", nil))
	if !strings.Contains(w.Body.String(), host) {
		t.Errorf("GET /api/proxy/list?type=host does not list %s: %s", host, w.Body.String())
	}
}
