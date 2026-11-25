package dynamicproxy

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/loadbalance"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/rewrite"
)

func hhValue(list [][]string, key string) (string, bool) {
	for _, kv := range list {
		if strings.EqualFold(kv[0], key) {
			return kv[1], true
		}
	}
	return "", false
}

func TestHardenedHeadersOffByDefault(t *testing.T) {
	// an existing rule JSON without the field loads with the preset off and sends nothing
	var hr HeaderRewriteRules
	if err := json.Unmarshal([]byte(`{"UserDefinedHeaders":[],"HSTSMaxAge":0,"EnablePermissionPolicyHeader":false}`), &hr); err != nil {
		t.Fatal(err)
	}
	if hr.HardenedHeaders != nil {
		t.Fatal("preset present in a config that never had it")
	}
	r := httptest.NewRequest("GET", "https://a.example/", nil)
	if l, _ := hardenedForRequest(&hr, r); l != nil {
		t.Errorf("headers planned with the preset off: %v", l)
	}
	if l, _ := hardenedForRequest(GetDefaultHeaderRewriteRules(), r); l != nil {
		t.Error("default rules plan headers")
	}
	// nothing is serialised for a site that does not use it
	js, _ := json.Marshal(GetDefaultHeaderRewriteRules())
	if strings.Contains(string(js), "HardenedHeaders") {
		t.Errorf("default config grew a HardenedHeaders key: %s", js)
	}
	// enabled=false keeps the choices but sends nothing
	if l, _ := hardenedForRequest(&HeaderRewriteRules{HardenedHeaders: &HardenedHeaders{Enabled: false, NoSniff: true}}, r); l != nil {
		t.Error("disabled preset sent headers")
	}
}

func TestHardenedHeadersPlanAndHSTSOptions(t *testing.T) {
	hh := DefaultHardenedHeaders()
	if err := hh.Validate(); err != nil {
		t.Fatal(err)
	}
	l := hh.Active(&HeaderRewriteRules{}, true)
	if v, _ := hhValue(l, "Strict-Transport-Security"); v != "max-age=31536000" {
		t.Errorf("HSTS = %q (includeSubDomains and preload must not be implied)", v)
	}
	if v, _ := hhValue(l, "X-Content-Type-Options"); v != "nosniff" {
		t.Error("nosniff missing")
	}
	if v, _ := hhValue(l, "X-Frame-Options"); v != "SAMEORIGIN" {
		t.Error("X-Frame-Options missing")
	}
	if v, _ := hhValue(l, "Permissions-Policy"); !strings.Contains(v, "camera=()") || !strings.Contains(v, "microphone=()") || !strings.Contains(v, "fullscreen=*") {
		t.Errorf("Permissions-Policy = %q", v)
	}
	// HSTS never goes out over plain HTTP
	if _, ok := hhValue(hh.Active(&HeaderRewriteRules{}, false), "Strict-Transport-Security"); ok {
		t.Error("HSTS planned for a plain HTTP request")
	}
	// options only when chosen
	hh.HSTSIncludeSubdomains, hh.HSTSPreload = true, true
	if err := hh.Validate(); err != nil {
		t.Fatal(err)
	}
	if v, _ := hhValue(hh.Active(&HeaderRewriteRules{}, true), "Strict-Transport-Security"); v != "max-age=31536000; includeSubDomains; preload" {
		t.Errorf("HSTS = %q", v)
	}
	// CSP framing option
	hh2 := &HardenedHeaders{Enabled: true, FrameProtection: "csp-none"}
	if v, _ := hhValue(hh2.Active(nil, true), "Content-Security-Policy"); v != "frame-ancestors 'none'" {
		t.Errorf("CSP = %q", v)
	}
	if _, ok := hhValue(hh2.Active(nil, true), "X-Frame-Options"); ok {
		t.Error("csp mode also sent X-Frame-Options")
	}
}

func TestHardenedHeadersValidationRejects(t *testing.T) {
	bad := map[string]HardenedHeaders{
		"preload without subdomains": {HSTS: true, HSTSPreload: true, HSTSMaxAge: 31536000},
		"preload short age":          {HSTS: true, HSTSPreload: true, HSTSIncludeSubdomains: true, HSTSMaxAge: 86400},
		"preload without hsts":       {HSTSPreload: true, HSTSIncludeSubdomains: true},
		"subdomains without hsts":    {HSTSIncludeSubdomains: true},
		"age too small":              {HSTS: true, HSTSMaxAge: 5},
		"age too large":              {HSTS: true, HSTSMaxAge: 999999999},
		"negative age":               {HSTS: true, HSTSMaxAge: -1},
		"bad referrer":               {ReferrerPolicy: "unsafe-url"},
		"header injection referrer":  {ReferrerPolicy: "no-referrer\r\nSet-Cookie: x=1"},
		"bad frame":                  {FrameProtection: "allow-from https://evil.example"},
	}
	for name, hh := range bad {
		hh := hh
		if err := hh.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := HardenedHeaders{ReferrerPolicy: " No-Referrer ", FrameProtection: "DENY"}
	if err := ok.Validate(); err != nil || ok.ReferrerPolicy != "no-referrer" || ok.FrameProtection != "deny" {
		t.Errorf("normalisation failed: %v %+v", err, ok)
	}
}

func TestHardenedHeadersAdminHeadersWin(t *testing.T) {
	hr := &HeaderRewriteRules{
		UserDefinedHeaders: []*rewrite.UserDefinedHeader{
			{Direction: rewrite.HeaderDirection_DunreeToDownstream, Key: "x-frame-options", Value: "ALLOWALL"},
			{Direction: rewrite.HeaderDirection_DunreeToDownstream, Key: "Referrer-Policy", IsRemove: true},
			{Direction: rewrite.HeaderDirection_DunreeToUpstream, Key: "X-Content-Type-Options", Value: "irrelevant"}, //upstream direction: does not count
		},
		HSTSMaxAge:                   63072000,
		EnablePermissionPolicyHeader: true,
		HardenedHeaders:              &HardenedHeaders{Enabled: true, OverrideExisting: true},
	}
	*hr.HardenedHeaders = *DefaultHardenedHeaders()
	hr.HardenedHeaders.OverrideExisting = true
	plan := hr.HardenedHeaders.Plan(hr, true)
	skipped := map[string]bool{}
	for _, e := range plan {
		if e.Mode == "skipped" {
			skipped[e.Key] = true
		}
	}
	for _, k := range []string{"Strict-Transport-Security", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
		if !skipped[k] {
			t.Errorf("%s is set by the admin but the preset did not skip it (even with override)", k)
		}
	}
	if skipped["X-Content-Type-Options"] {
		t.Error("an upstream direction rule wrongly blocks the downstream preset header")
	}
	active := hr.HardenedHeaders.Active(hr, true)
	if _, ok := hhValue(active, "X-Frame-Options"); ok {
		t.Error("skipped header handed to the rewriter")
	}
	if v, ok := hhValue(active, "X-Content-Type-Options"); !ok || v != "nosniff" {
		t.Error("nosniff should still be sent")
	}
}

// End to end through the real proxy path: upstream headers are kept unless override is chosen, admin headers always win.
func TestHardenedHeadersEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "ALLOWALL") //an upstream choice the preset must respect
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Admin-Wins", "from-upstream")
		w.WriteHeader(200)
	}))
	defer backend.Close()

	tlsOn := false
	fetch := func(hh *HardenedHeaders, admin []*rewrite.UserDefinedHeader) http.Header {
		router, sep, _ := newNonTLSTestRouter(t)
		router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: router.Option.Logger})
		sep.ProxyType = ProxyTypeHost
		sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(backend.URL, "http://"), Weight: 1}}
		sep.HeaderRewriteRules = &HeaderRewriteRules{UserDefinedHeaders: admin, HardenedHeaders: hh}
		prepared, err := router.PrepareProxyRoute(sep)
		if err != nil {
			t.Fatal(err)
		}
		prepared.parent = router
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tlsOn {
				r.TLS = &tls.ConnectionState{} //the request arrived over TLS
			}
			router.mux.(*ProxyHandler).hostRequest(w, r, prepared)
		}))
		t.Cleanup(proxy.Close)
		resp, err := http.Get(proxy.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header
	}
	// off: untouched
	h := fetch(nil, nil)
	if h.Get("X-Content-Type-Options") != "" || h.Get("Referrer-Policy") != "" || h.Get("Permissions-Policy") != "" {
		t.Errorf("preset off but headers appeared: %v", h)
	}

	// on, no override: fills gaps, keeps upstream values
	hh := DefaultHardenedHeaders()
	hh.FrameProtection = "csp-self"
	h = fetch(hh, nil)
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("gaps not filled: %v", h)
	}
	if h.Get("X-Frame-Options") != "ALLOWALL" {
		t.Errorf("upstream X-Frame-Options was overridden without the override option: %q", h.Get("X-Frame-Options"))
	}
	if got := h.Values("Content-Security-Policy"); len(got) != 1 || got[0] != "default-src 'self'" {
		t.Errorf("upstream CSP changed: %v", got)
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain HTTP")
	}
	tlsOn = true
	if got := fetch(hh, nil).Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS over TLS = %q", got)
	}
	tlsOn = false

	// override: replaces X-Frame-Options, adds frame-ancestors as a separate policy, never edits the upstream CSP
	hh = DefaultHardenedHeaders()
	hh.FrameProtection, hh.OverrideExisting = "deny", true
	h = fetch(hh, nil)
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("override did not replace the upstream X-Frame-Options: %q", h.Get("X-Frame-Options"))
	}
	hh.FrameProtection = "csp-none"
	h = fetch(hh, nil)
	csp := h.Values("Content-Security-Policy")
	if len(csp) != 2 || csp[0] != "default-src 'self'" || csp[1] != "frame-ancestors 'none'" {
		t.Errorf("CSP handling with override: %v", csp)
	}

	// admin header rule beats both upstream and override
	admin := []*rewrite.UserDefinedHeader{{Direction: rewrite.HeaderDirection_DunreeToDownstream, Key: "X-Frame-Options", Value: "SAMEORIGIN"}}
	hh = DefaultHardenedHeaders()
	hh.FrameProtection, hh.OverrideExisting = "deny", true
	h = fetch(hh, admin)
	if h.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("admin header lost to the preset: %q", h.Get("X-Frame-Options"))
	}
}
