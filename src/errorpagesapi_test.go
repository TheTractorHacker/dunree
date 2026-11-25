package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/auth"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy"
	"github.com/TheTractorHacker/dunree/mod/errorpages"
)

func errorPagesSetup(t *testing.T) string {
	t.Helper()
	oldConf, oldMgr := CONF_FOLDER, errorPageMgr
	CONF_FOLDER = t.TempDir()
	initErrorPages()
	t.Cleanup(func() {
		CONF_FOLDER, errorPageMgr = oldConf, oldMgr
		dynamicproxy.SetCustomErrorPages(oldMgr)
	})
	return filepath.Join(CONF_FOLDER, errorpages.FileName)
}

func epCall(h http.HandlerFunc, method, target string, form url.Values) *httptest.ResponseRecorder {
	var r *http.Request
	if method == http.MethodPost {
		r = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.RemoteAddr = "192.168.5.5:4000"
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func epError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var v struct {
		Error string `json:"error"`
	}
	if strings.TrimSpace(w.Body.String()) == `"OK"` {
		return ""
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("answer is not JSON: %v: %s", err, w.Body.String())
	}
	return v.Error
}

func epGet(t *testing.T) errorPagesView {
	t.Helper()
	w := epCall(HandleErrorPagesGet, http.MethodGet, "/api/errorpages/get", nil)
	v := errorPagesView{}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return v
}

func TestErrorPagesAPI_ClassesAndDefaultOff(t *testing.T) {
	file := errorPagesSetup(t)
	w := epCall(HandleErrorPageClasses, http.MethodGet, "/api/errorpages/classes", nil)
	var v struct {
		Classes   []errorpages.ClassInfo `json:"classes"`
		Variables []errorpages.Variable  `json:"variables"`
		Starters  []errorpages.Starter   `json:"starters"`
		Limits    map[string]int         `json:"limits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, c := range v.Classes {
		ids = append(ids, string(c.ID))
	}
	if strings.Join(ids, ",") != "403,404,429,5xx,nohost,maintenance" || len(v.Starters) != 3 || len(v.Variables) < 8 || v.Limits["templateBytes"] != 256*1024 {
		t.Fatalf("classes answer: %v, %d starters, %d variables, limits %v", ids, len(v.Starters), len(v.Variables), v.Limits)
	}
	got := epGet(t)
	if got.Enabled || got.Active || len(got.Pages) != 0 || len(got.Hosts) != 0 || got.Theme.ApplyToBuiltin || got.Theme.ShowClientIP {
		t.Fatalf("a fresh install must have everything off: %+v", got.Config)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("reading must not create the file")
	}
	// the test link shows the built-in page with its real status while nothing is customised
	w = epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=403", nil)
	builtin, _ := dynamicproxy.BuiltinErrorPage(errorpages.ClassForbidden)
	if w.Code != 403 || w.Header().Get("X-Zoraxy-Error-Page") != "built-in" || w.Body.String() != string(builtin) || w.Header().Get("Content-Security-Policy") != "" {
		t.Fatalf("test of the built-in 403: %d %v", w.Code, w.Header())
	}
	if w := epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=nope", nil); w.Code != 400 {
		t.Fatalf("unknown class: %d", w.Code)
	}
}

func TestErrorPagesAPI_SavePreviewTestReset(t *testing.T) {
	file := errorPagesSetup(t)

	// a preview renders unsaved values and saves nothing
	page, _ := json.Marshal(errorpages.Page{Template: `<b>{{.Status}} {{.Title}} {{.Host}} {{.Theme.LogoText}}</b>`})
	theme, _ := json.Marshal(errorpages.Theme{LogoText: "Acme", AccentColor: "#112233", ShowRequestID: true})
	w := epCall(HandleErrorPagePreview, http.MethodPost, "/api/errorpages/preview", url.Values{"class": {"429"}, "page": {string(page)}, "theme": {string(theme)}})
	var pv struct {
		HTML  string `json:"html"`
		Error string `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &pv)
	if pv.HTML != "<b>429 Too many requests app.example.com Acme</b>" {
		t.Fatalf("preview: %s", w.Body.String())
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("a preview must not save")
	}
	// a broken template: an error that is valid JSON although the message quotes the template
	bad, _ := json.Marshal(errorpages.Page{Template: `<b>{{.Nope "x"}}</b>`})
	w = epCall(HandleErrorPagePreview, http.MethodPost, "/api/errorpages/preview", url.Values{"class": {"429"}, "page": {string(bad)}})
	if msg := epError(t, w); !strings.Contains(msg, "Nope") {
		t.Fatalf("preview of a broken template: %q", msg)
	}

	// save (one request: pages of the scope, switch, theme)
	pages, _ := json.Marshal(map[string]errorpages.Page{"403": {Title: "Stop", Message: "Not for you"}, "429": {Template: `<b>{{.Status}}</b>`}})
	w = epCall(HandleErrorPagesSave, http.MethodPost, "/api/errorpages/save", url.Values{"pages": {string(pages)}, "enabled": {"true"}, "theme": {string(theme)}})
	if msg := epError(t, w); msg != "" {
		t.Fatal(msg)
	}
	got := epGet(t)
	if !got.Enabled || !got.Active || got.Pages["403"].Title != "Stop" || got.Pages["429"].Template != "<b>{{.Status}}</b>" || got.Theme.LogoText != "Acme" {
		t.Fatalf("not saved: %+v", got.Config)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("file: %v", err)
	}
	// a refused save keeps the old state
	badPages, _ := json.Marshal(map[string]errorpages.Page{"403": {Template: strings.Repeat("x", errorpages.MaxTemplateBytes+1)}})
	w = epCall(HandleErrorPagesSave, http.MethodPost, "/api/errorpages/save", url.Values{"pages": {string(badPages)}})
	if msg := epError(t, w); !strings.Contains(msg, "256 KiB") {
		t.Fatalf("oversized template: %q", msg)
	}
	if w := epCall(HandleErrorPagesSave, http.MethodPost, "/api/errorpages/save", url.Values{"theme": {`{"LogoURL":"javascript:alert(1)"}`}}); epError(t, w) == "" {
		t.Fatal("a javascript: logo was accepted")
	}
	if w := epCall(HandleErrorPagesSave, http.MethodPost, "/api/errorpages/save", url.Values{"theme": {`{"Unknown":1}`}}); epError(t, w) == "" {
		t.Fatal("an unknown theme field was accepted")
	}
	if got := epGet(t); got.Pages["403"].Title != "Stop" || got.Theme.LogoText != "Acme" {
		t.Fatalf("a refused save changed the state: %+v", got.Config)
	}

	// the test link now answers like the proxy does: the page, its status and its headers
	w = epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=403", nil)
	if w.Code != 403 || w.Header().Get("X-Zoraxy-Error-Page") != "custom" || w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("Content-Security-Policy") != errorpages.ContentSecurityPolicy || !strings.Contains(w.Body.String(), "<h1>Stop</h1>") || !strings.Contains(w.Body.String(), "ZX-TEST-TEST") {
		t.Fatalf("test of the customised 403: %d %v\n%s", w.Code, w.Header(), w.Body.String())
	}
	if strings.Contains(w.Body.String(), "192.168.5.5") {
		t.Fatal("the client address is shown without the opt-in")
	}
	// a class that was not touched stays built-in
	if w := epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=5xx", nil); w.Code != 521 || w.Header().Get("X-Zoraxy-Error-Page") != "built-in" {
		t.Fatalf("untouched class: %d %v", w.Code, w.Header())
	}

	// one page of one host, and back
	w = epCall(HandleErrorPageTemplateSet, http.MethodPost, "/api/errorpages/template/set", url.Values{"class": {"403"}, "host": {"Shop.Example.com"}, "template": {"shop {{.Host}}"}})
	if msg := epError(t, w); msg != "" {
		t.Fatal(msg)
	}
	if w := epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=403&host=shop.example.com", nil); w.Body.String() != "shop shop.example.com" {
		t.Fatalf("host page: %q", w.Body.String())
	}
	if w := epCall(HandleErrorPageTemplateSet, http.MethodPost, "/api/errorpages/template/set", url.Values{"class": {"403"}, "host": {"not a host"}, "template": {"x"}}); epError(t, w) == "" {
		t.Fatal("an invalid host was accepted")
	}
	w = epCall(HandleErrorPageTemplateDelete, http.MethodPost, "/api/errorpages/template/delete", url.Values{"class": {"403"}, "host": {"shop.example.com"}})
	if msg := epError(t, w); msg != "" || len(epGet(t).Hosts) != 0 {
		t.Fatalf("delete of the host page: %q %+v", msg, epGet(t).Hosts)
	}
	w = epCall(HandleErrorPageTemplateDelete, http.MethodPost, "/api/errorpages/template/delete", url.Values{"class": {"429"}})
	if msg := epError(t, w); msg != "" || epGet(t).Pages["429"] != nil || epGet(t).Pages["403"] == nil {
		t.Fatalf("delete of one page: %q", msg)
	}

	// theme only
	w = epCall(HandleErrorPagesTheme, http.MethodPost, "/api/errorpages/theme", url.Values{"enabled": {"false"}})
	if msg := epError(t, w); msg != "" || epGet(t).Active || epGet(t).Pages["403"] == nil {
		t.Fatalf("switching off must keep the saved pages: %q", msg)
	}
	if w := epCall(HandleErrorPageTest, http.MethodGet, "/api/errorpages/test?class=403", nil); w.Header().Get("X-Zoraxy-Error-Page") != "built-in" {
		t.Fatal("switched off, the built-in page must answer")
	}

	// reset: file gone, everything built-in
	if msg := epError(t, epCall(HandleErrorPagesReset, http.MethodPost, "/api/errorpages/reset", nil)); msg != "" {
		t.Fatal(msg)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("reset must remove the file")
	}
	if got := epGet(t); got.Enabled || len(got.Pages) != 0 {
		t.Fatalf("after reset: %+v", got.Config)
	}
}

func TestErrorPagesAPI_MethodsAndRoles(t *testing.T) {
	errorPagesSetup(t)
	for name, h := range map[string]http.HandlerFunc{"save": HandleErrorPagesSave, "theme": HandleErrorPagesTheme, "template/set": HandleErrorPageTemplateSet,
		"template/delete": HandleErrorPageTemplateDelete, "preview": HandleErrorPagePreview, "reset": HandleErrorPagesReset} {
		if w := epCall(h, http.MethodGet, "/api/errorpages/"+name, nil); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s answered %d: a link must not be able to change anything", name, w.Code)
		}
		if auth.ViewerAllowed(http.MethodPost, "/api/errorpages/"+name) {
			t.Errorf("a viewer account may POST %s", name)
		}
	}
	if w := epCall(HandleErrorPagesGet, http.MethodPost, "/api/errorpages/get", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST get answered %d", w.Code)
	}
}
