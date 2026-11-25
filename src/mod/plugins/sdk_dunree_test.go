package plugins

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	zp "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
)

/*
	Dunree SDK (dunree_plugin 2.x): the names it reads.

	It reads the Dunree names and falls back to the names of Zoraxy, so a plugin built // legacy-compat
	with it also understands a host that only speaks the old names.
	(The tests of the SDK live here and not in its folder: the folder is copied into
	plugins as it is.)
*/

func TestDunreeSDKReadsConfigureFromDunreeAndFromZoraxyHosts(t *testing.T) { // legacy-compat
	// A Zoraxy host: only the old names // legacy-compat
	var old zp.ConfigureSpec
	if err := json.Unmarshal([]byte(`{"port":5001,"runtime_const":{"zoraxy_version":"3.3.6","zoraxy_uuid":"u-1","development_build":true},"api_key":"k","zoraxy_port":8000,"invoke_token":"t"}`), &old); err != nil { // legacy-compat
		t.Fatal(err)
	}
	if old.Port != 5001 || old.DunreePort != 8000 || old.ZoraxyPort != 8000 || old.RuntimeConst.DunreeVersion != "3.3.6" || old.RuntimeConst.DunreeUUID != "u-1" || // legacy-compat
		!old.RuntimeConst.DevelopmentBuild || old.APIKey != "k" || old.InvokeToken != "t" {
		t.Fatalf("payload of a Zoraxy host: %+v", old) // legacy-compat
	}
	if old.APIURL("/plugin/api/x") != "http://127.0.0.1:8000/plugin/api/x" {
		t.Fatalf("the API client does not find a Zoraxy host: %q", old.APIURL("/plugin/api/x")) // legacy-compat
	}

	// A Dunree host: both sets, the Dunree names win
	var cur zp.ConfigureSpec
	if err := json.Unmarshal([]byte(`{"port":5002,"runtime_const":{"dunree_version":"1.0.0-beta.1","dunree_uuid":"u-2","zoraxy_version":"3.3.6","zoraxy_uuid":"u-2","development_build":false},"dunree_port":8001,"zoraxy_port":8001,"api_version_min":0,"api_version_max":1}`), &cur); err != nil { // legacy-compat
		t.Fatal(err)
	}
	if cur.DunreePort != 8001 || cur.RuntimeConst.DunreeVersion != "1.0.0-beta.1" || cur.RuntimeConst.ZoraxyVersion != "3.3.6" || cur.RuntimeConst.DunreeUUID != "u-2" || !cur.ContractSupported() { // legacy-compat
		t.Fatalf("payload of a Dunree host: %+v", cur)
	}

	// No port at all (a plugin without API permissions): stays 0
	var none zp.ConfigureSpec
	if err := json.Unmarshal([]byte(`{"port":5003,"runtime_const":{"zoraxy_version":"3.3.6","zoraxy_uuid":"u","development_build":false}}`), &none); err != nil || none.DunreePort != 0 { // legacy-compat
		t.Fatalf("%v %+v", err, none)
	}
	if err := json.Unmarshal([]byte(`{"port":`), &none); err == nil {
		t.Fatal("broken JSON must be an error")
	}

	// What the host writes for a Zoraxy plugin has no Dunree key, and the field order Zoraxy used // legacy-compat
	raw, _ := json.Marshal(zp.ConfigureSpec{Port: 1, RuntimeConst: zp.RuntimeConstantValue{ZoraxyVersion: "3.3.6", ZoraxyUUID: "u"}, APIKey: "k", ZoraxyPort: 2, InvokeToken: "t"}) // legacy-compat
	if string(raw) != `{"port":1,"runtime_const":{"zoraxy_version":"3.3.6","zoraxy_uuid":"u","development_build":false},"api_key":"k","zoraxy_port":2,"invoke_token":"t"}` {        // legacy-compat
		t.Fatalf("the legacy configure payload changed: %s", raw)
	}
}

func TestDunreeSDKReadsHostHeadersUnderBothNames(t *testing.T) {
	if zp.InvokeTokenHeader != "X-Dunree-Plugin-Token" || zp.RequestIDHeader != "X-Dunree-RequestID" ||
		zp.LegacyInvokeTokenHeader != "X-Zoraxy-Plugin-Token" || zp.LegacyRequestIDHeader != "X-Zoraxy-RequestID" { // legacy-compat
		t.Fatal("header names of the SDK changed")
	}
	req := func(kv ...string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/filter", strings.NewReader("{}"))
		for i := 0; i+1 < len(kv); i += 2 {
			r.Header.Set(kv[i], kv[i+1])
		}
		return r
	}
	for name, c := range map[string]struct {
		r    *http.Request
		want bool
	}{
		"dunree header":                {req("X-Dunree-Plugin-Token", "sekret"), true},
		"zoraxy header (Zoraxy host)":  {req("X-Zoraxy-Plugin-Token", "sekret"), true}, // legacy-compat
		"both (Dunree 1.x host)":       {req("X-Dunree-Plugin-Token", "sekret", "X-Zoraxy-Plugin-Token", "sekret"), true},
		"no header":                    {req(), false},
		"wrong in both":                {req("X-Dunree-Plugin-Token", "nope", "X-Zoraxy-Plugin-Token", "nope"), false},
		"prefix of the token":          {req("X-Dunree-Plugin-Token", "sekre"), false},
		"token in an unrelated header": {req("X-Plugin-Token", "sekret"), false},
	} {
		if got := zp.VerifyInvokeToken("sekret", c.r); got != c.want {
			t.Errorf("%s: VerifyInvokeToken = %v, want %v", name, got, c.want)
		}
	}
	if !zp.VerifyInvokeToken("", req()) {
		t.Error("no token configured (a host that sends none): every call is accepted, as before")
	}
	// The filter handler of the SDK answers a Zoraxy host and refuses a caller without the token // legacy-compat
	h := zp.NewFilterHandler("sekret", func(fr *zp.FilterRequest) *zp.FilterVerdict { return zp.Allow() })
	for header, want := range map[string]int{"X-Zoraxy-Plugin-Token": 200, "X-Dunree-Plugin-Token": 200, "X-Other": 403} { // legacy-compat
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(header, "sekret", "Content-Type", "application/json"))
		if w.Code != want {
			t.Errorf("filter handler with %s: %d, want %d", header, w.Code, want)
		}
	}

	if zp.HostHeader(req("X-Zoraxy-RequestID", "old"), "RequestID") != "old" || // legacy-compat
		zp.HostHeader(req("X-Dunree-RequestID", "new"), "RequestID") != "new" ||
		zp.HostHeader(req("X-Zoraxy-RequestID", "same", "X-Dunree-RequestID", "same"), "RequestID") != "same" ||
		zp.HostHeader(req(), "RequestID") != "" || zp.HostHeader(nil, "RequestID") != "" {
		t.Fatal("HostHeader")
	}
	// An upstream Zoraxy host sets only X-Zoraxy-* and forwards an X-Dunree-* header the client // legacy-compat
	// sent: the pair differs, and the value the host set must win (a client must not pick the
	// capture path or the request ID a plugin sees)
	if got := zp.HostHeader(req("X-Zoraxy-RequestID", "host-set", "X-Dunree-RequestID", "client-forged"), "RequestID"); got != "host-set" { // legacy-compat
		t.Fatalf("HostHeader with a forged X-Dunree-RequestID on a Zoraxy host: %q", got) // legacy-compat
	}
	{
		router := zp.NewPathRouter()
		var gotPath string
		router.RegisterPathHandler("/cap", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotPath = r.URL.Path; w.WriteHeader(218) }))
		router.RegisterPathHandler("/admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotPath = "forged:" + r.URL.Path; w.WriteHeader(219) }))
		mux := http.NewServeMux()
		router.RegisterStaticCaptureHandle("/ingress", mux)
		w := httptest.NewRecorder()
		cr := httptest.NewRequest(http.MethodGet, "/ingress/thing", nil)
		cr.Header.Set("X-Zoraxy-Capture", "/cap")   // legacy-compat
		cr.Header.Set("X-Zoraxy-Uri", "/cap/thing") // legacy-compat
		cr.Header.Set("X-Dunree-Capture", "/admin")
		cr.Header.Set("X-Dunree-Uri", "/admin/thing")
		mux.ServeHTTP(w, cr)
		if w.Code != 218 || gotPath != "/cap/thing" {
			t.Errorf("static capture with forged X-Dunree-* headers on a Zoraxy host: %d %q", w.Code, gotPath) // legacy-compat
		}
	}

	// Static capture router: dispatch by the capture header of either host
	for _, prefix := range []string{"X-Dunree-", "X-Zoraxy-"} { // legacy-compat
		router := zp.NewPathRouter()
		var gotPath string
		router.RegisterPathHandler("/cap", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotPath = r.URL.Path; w.WriteHeader(218) }))
		mux := http.NewServeMux()
		router.RegisterStaticCaptureHandle("/ingress", mux)
		w := httptest.NewRecorder()
		cr := httptest.NewRequest(http.MethodGet, "/ingress/thing", nil)
		cr.Header.Set(prefix+"Capture", "/cap")
		cr.Header.Set(prefix+"Uri", "/cap/thing")
		mux.ServeHTTP(w, cr)
		if w.Code != 218 || gotPath != "/cap/thing" {
			t.Errorf("static capture with %s headers: %d %q", prefix, w.Code, gotPath)
		}
	}
}
