package utils

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A GET (or any other method the CSRF middleware does not validate) must never
// hand a query string value to a handler through the Post* helpers.
func TestPostHelpersIgnoreQueryOnReadOnlyMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		r := httptest.NewRequest(method, "/api/proxy/del?ep=victim.example&enable=true&n=5&d=3s", nil)
		if v, err := PostPara(r, "ep"); err == nil || v != "" {
			t.Errorf("%s: PostPara returned %q, %v; want an error", method, v, err)
		}
		if v, err := PostBool(r, "enable"); err == nil || v {
			t.Errorf("%s: PostBool returned %v, %v; want an error", method, v, err)
		}
		if v, err := PostInt(r, "n"); err == nil || v != 0 {
			t.Errorf("%s: PostInt returned %v, %v; want an error", method, v, err)
		}
		if v, err := PostDuration(r, "d"); err == nil || v != nil {
			t.Errorf("%s: PostDuration returned %v, %v; want an error", method, v, err)
		}
	}

	//A GET with a form body is refused as well
	r := httptest.NewRequest(http.MethodGet, "/api/proxy/del", strings.NewReader("ep=victim.example"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v, err := PostPara(r, "ep"); err == nil || v != "" {
		t.Errorf("GET with body: PostPara returned %q, %v; want an error", v, err)
	}
}

// State changing methods keep working as before: form body first, query string as well.
func TestPostHelpersOnStateChangingMethods(t *testing.T) {
	body := url.Values{"ep": {"a.example"}, "enable": {"true"}, "n": {"5"}, "d": {"3s"}}.Encode()
	r := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v, err := PostPara(r, "ep"); err != nil || v != "a.example" {
		t.Errorf("PostPara = %q, %v", v, err)
	}
	if v, err := PostBool(r, "enable"); err != nil || !v {
		t.Errorf("PostBool = %v, %v", v, err)
	}
	if v, err := PostInt(r, "n"); err != nil || v != 5 {
		t.Errorf("PostInt = %v, %v", v, err)
	}
	if v, err := PostDuration(r, "d"); err != nil || v == nil || v.Seconds() != 3 {
		t.Errorf("PostDuration = %v, %v", v, err)
	}

	//DELETE has no parsed body in net/http, callers pass the value in the query string
	r = httptest.NewRequest(http.MethodDelete, "/api/x?ep=b.example", nil)
	if v, err := PostPara(r, "ep"); err != nil || v != "b.example" {
		t.Errorf("DELETE PostPara = %q, %v", v, err)
	}
}

// ReadPara is for handlers that only read: it takes the query string on GET and the body on POST.
func TestReadPara(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/proxy/list?type=host", nil)
	if v, err := ReadPara(r, "type"); err != nil || v != "host" {
		t.Errorf("GET ReadPara = %q, %v", v, err)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/proxy/list", strings.NewReader("type=root"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v, err := ReadPara(r, "type"); err != nil || v != "root" {
		t.Errorf("POST ReadPara = %q, %v", v, err)
	}
	if _, err := ReadPara(r, "missing"); err == nil {
		t.Error("ReadPara of a missing key must fail")
	}
}
