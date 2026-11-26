package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The floating IP routes expose the node topology and (in generate) the VRRP
// password: viewers get nothing, with any method, and anonymous callers get no
// handler call either.
func TestViewerAndAnonymousCannotUseFloatingIPRoutes(t *testing.T) {
	routes := []string{
		"/api/cluster/vip/config", "/api/cluster/vip/shared", "/api/cluster/vip/local",
		"/api/cluster/vip/preflight", "/api/cluster/vip/generate", "/api/cluster/vip/status",
	}
	for _, p := range routes {
		for _, m := range []string{"GET", "HEAD", "POST"} {
			if ViewerAllowed(m, p) {
				t.Errorf("a viewer may %s %s", m, p)
			}
		}
	}
	if !ViewerAllowed("GET", "/api/cluster/status") {
		t.Error("the cluster status page stays readable for viewers")
	}

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
	for _, p := range routes {
		rt.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { calls++ })
	}
	do := func(method, target string, c *http.Cookie) int {
		r := httptest.NewRequest(method, target, nil)
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	for _, p := range routes {
		if code := do("GET", p, vc); code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", p, code)
		}
		if code := do("POST", p, vc); code != http.StatusForbidden {
			t.Errorf("viewer POST %s = %d, want 403", p, code)
		}
		if code := do("GET", p, nil); code == http.StatusOK {
			t.Errorf("anonymous GET %s reached the handler", p)
		}
	}
	if calls != 0 {
		t.Fatalf("a floating IP handler ran %d times for a viewer or anonymous caller", calls)
	}
	for _, p := range routes {
		if code := do("GET", p, ac); code != http.StatusOK {
			t.Errorf("admin GET %s = %d, want 200", p, code)
		}
	}
	if calls != len(routes) {
		t.Fatalf("admin reached %d of %d handlers", calls, len(routes))
	}
}
