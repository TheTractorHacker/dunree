package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/utils"
)

// A GET (which skips the CSRF token check and is open to viewer accounts) must not be able to
// drive a state change: neither through a handler that reads its input with utils.PostPara, nor
// through an endpoint that changes state without any form field.
func TestGetCannotChangeState(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	a.CreateUser("view", "password-2", RoleViewer)
	vc := login(t, a, "view", "password-2")
	ac := login(t, a, "root", "password-1")
	a.LoginRedirectionHandler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "login", http.StatusTemporaryRedirect) }

	deleted := []string{}
	started := 0
	mux := http.NewServeMux()
	rt := NewManagedHTTPRouter(RouterOption{AuthAgent: a, RequireAuth: true, TargetMux: mux})
	//Same shape as DeleteProxyEndpoint: no method check, input read through utils.PostPara
	rt.HandleFunc("/api/proxy/del", func(w http.ResponseWriter, r *http.Request) {
		ep, err := utils.PostPara(r, "ep")
		if err != nil {
			utils.SendErrorResponse(w, "Invalid ep given")
			return
		}
		deleted = append(deleted, ep)
		utils.SendOK(w)
	})
	//Same shape as the static web server start: changes state without reading anything
	rt.HandleFunc("/api/webserv/start", func(w http.ResponseWriter, r *http.Request) {
		started++
		utils.SendOK(w)
	})

	do := func(c *http.Cookie, method, path string, form url.Values) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, reqWith(c, method, path, form))
		return w.Code
	}

	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		for name, c := range map[string]*http.Cookie{"admin": ac, "viewer": vc} {
			do(c, method, "/api/proxy/del?ep=victim.example", nil)
			if len(deleted) != 0 {
				t.Fatalf("%s %s with a query string deleted %v", name, method, deleted)
			}
			if code := do(c, method, "/api/webserv/start", nil); code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s /api/webserv/start = %d, want 405", name, method, code)
			}
			if started != 0 {
				t.Fatalf("%s %s reached the state changing handler", name, method)
			}
		}
	}

	//Viewer: the mutating methods stay refused by the role gate
	if code := do(vc, "POST", "/api/proxy/del", url.Values{"ep": {"victim.example"}}); code != http.StatusForbidden {
		t.Fatalf("viewer POST = %d, want 403", code)
	}
	if code := do(vc, "POST", "/api/webserv/start", nil); code != http.StatusForbidden {
		t.Fatalf("viewer POST start = %d, want 403", code)
	}
	if len(deleted) != 0 || started != 0 {
		t.Fatal("viewer changed state")
	}

	//Admin: POST works as before
	if code := do(ac, "POST", "/api/proxy/del", url.Values{"ep": {"a.example"}}); code != 200 || len(deleted) != 1 || deleted[0] != "a.example" {
		t.Fatalf("admin POST = %d, deleted %v", code, deleted)
	}
	if code := do(ac, "POST", "/api/webserv/start", nil); code != 200 || started != 1 {
		t.Fatalf("admin POST start = %d, started %d", code, started)
	}

	//The endpoints named in the report stay on the list
	for _, p := range []string{"/api/trustedproxy/reset", "/api/acme/autoRenew/renewNow", "/api/acme/autoRenew/setEAB",
		"/api/cert/selfsign", "/api/webserv/start", "/api/webserv/stop", "/api/webserv/webdav/start",
		"/api/webserv/webdav/stop", "/api/log/rotate/trigger"} {
		if !WriteMethodRequired(p) {
			t.Errorf("%s must require a state changing method", p)
		}
	}
}
