package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// API-06: the outbound probing tools (upstream test, HTTP / TLS test, port and IP scan, ping,
// traceroute, DNS, whois) let the caller make the proxy host connect to any destination. A viewer
// (read-only) account must not reach them with any method; an admin still does.
func TestViewerCannotUseProbingTools(t *testing.T) {
	probes := []string{
		"/api/proxy/testupstream", "/api/tools/httptest", "/api/tools/tlsinspect", "/api/tools/portscan",
		"/api/tools/ipscan", "/api/tools/ping", "/api/tools/traceroute", "/api/tools/dns", "/api/tools/whois",
		"/api/sso/OAuth2/discovery",
	}
	for _, p := range probes {
		for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST"} {
			if ViewerAllowed(m, p) {
				t.Errorf("a viewer may %s %s", m, p)
			}
		}
		if ViewerAllowed("GET", p+"/") {
			t.Errorf("a viewer may GET %s/", p)
		}
	}
	//Exact match only: read-only neighbours stay available to viewers
	for _, p := range []string{"/api/tools/dnsresponder", "/api/tools/netcalc", "/api/tools/websshSupported", "/api/proxy/list", "/api/sso/OAuth2/providers", "/"} {
		if !ViewerAllowed("GET", p) {
			t.Errorf("a viewer can no longer GET %s", p)
		}
	}

	//Through the router: the handler is never reached by a viewer, whatever the query says
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	a.CreateUser("view", "password-2", RoleViewer)
	vc := login(t, a, "view", "password-2")
	ac := login(t, a, "root", "password-1")
	a.LoginRedirectionHandler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "login", http.StatusTemporaryRedirect) }

	calls := 0
	mux := http.NewServeMux()
	rt := NewManagedHTTPRouter(RouterOption{AuthAgent: a, RequireAuth: true, TargetMux: mux})
	for _, p := range probes {
		rt.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { calls++ })
	}
	do := func(target string, c *http.Cookie) int {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	for _, p := range probes {
		if code := do(p+"?url=http://169.254.169.254/latest/meta-data/&allowmetadata=true&ip=10.0.0.5&host=10.0.0.5&target=10.0.0.5&oauth2WellKnownUrl=http://169.254.169.254/", vc); code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", p, code)
		}
	}
	if calls != 0 {
		t.Fatalf("a probing handler ran %d times for a viewer", calls)
	}
	for _, p := range probes {
		if code := do(p+"?url=127.0.0.1:1", ac); code != http.StatusOK {
			t.Errorf("admin GET %s = %d, want 200", p, code)
		}
	}
	if calls != len(probes) {
		t.Fatalf("admin reached %d of %d probing handlers", calls, len(probes))
	}
}
