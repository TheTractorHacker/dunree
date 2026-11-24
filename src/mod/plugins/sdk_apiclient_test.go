package plugins

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	SDK 1.2.0: the API client helpers of the SDK against the real API key manager
	and the real plugin API middleware (issue #149).
*/

func TestSDKAPIClientHelpersSetTheBearerHeader(t *testing.T) {
	keys := auth.NewAPIKeyManager()
	mux := http.NewServeMux()
	mw := auth.NewPluginAuthMiddleware(auth.PluginMiddlewareOptions{
		DeniedHandler: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
		},
		ApiKeyManager: keys,
		TargetMux:     mux,
	})
	var sawAuth, sawBody, sawQuery string
	handler := func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		sawBody, sawQuery = string(raw), r.URL.RawQuery
		w.Write([]byte("granted"))
	}
	for _, ep := range []string{"/plugin/api/access/list", "/plugin/api/blacklist/ip/add", "/plugin/api/proxy/list"} {
		if err := mw.HandleFunc(ep, handler); err != nil {
			t.Fatal(err)
		}
	}
	mux.HandleFunc("/plugin/api/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/plugin/api/access/list", http.StatusFound)
	})
	srv := httptest.NewServer(mux) //listens on 127.0.0.1, where the helpers call
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	key, err := keys.GenerateAPIKey("test.sdk.apiclient", []zp.PermittedAPIEndpoint{
		{Method: http.MethodGet, Endpoint: "/plugin/api/access/list"},
		{Method: http.MethodPost, Endpoint: "/plugin/api/blacklist/ip/add"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &zp.ConfigureSpec{APIKey: key.APIKey, ZoraxyPort: port}
	read := func(resp *http.Response, err error) (int, string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	//DoAPIRequest: granted endpoint, with a query string
	if code, body := read(cfg.DoAPIRequest(http.MethodGet, "/plugin/api/access/list?x=1", nil)); code != http.StatusOK || body != "granted" {
		t.Fatalf("granted GET: %d %q", code, body)
	}
	if sawAuth != "Bearer "+key.APIKey || sawQuery != "x=1" {
		t.Fatalf("Zoraxy saw Authorization %q and query %q", sawAuth, sawQuery)
	}

	//A body, through NewAPIRequest and a client of the plugin's own
	req, err := cfg.NewAPIRequest(http.MethodPost, "/plugin/api/blacklist/ip/add", strings.NewReader("ip=192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.String() != cfg.APIURL("/plugin/api/blacklist/ip/add") || req.URL.Host != "127.0.0.1:"+u.Port() {
		t.Fatalf("address of the request: %s", req.URL)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if code, _ := read(http.DefaultClient.Do(req)); code != http.StatusOK || sawBody != "ip=192.0.2.1" {
		t.Fatalf("granted POST: %d, body %q", code, sawBody)
	}

	//SetAPIAuth on a request the plugin built itself
	own, _ := http.NewRequest(http.MethodGet, cfg.APIURL("/plugin/api/access/list"), nil)
	if code, _ := read(http.DefaultClient.Do(own)); code != http.StatusUnauthorized {
		t.Fatalf("without the header Zoraxy must refuse: %d", code)
	}
	cfg.SetAPIAuth(own)
	if code, _ := read(http.DefaultClient.Do(own)); code != http.StatusOK {
		t.Fatalf("with SetAPIAuth: %d", code)
	}

	//Not granted, wrong method, unknown key: a status, not an error
	if code, _ := read(cfg.DoAPIRequest(http.MethodGet, "/plugin/api/proxy/list", nil)); code != http.StatusUnauthorized {
		t.Fatalf("endpoint that is not granted: %d", code)
	}
	if code, _ := read(cfg.DoAPIRequest(http.MethodPost, "/plugin/api/access/list", nil)); code != http.StatusUnauthorized {
		t.Fatalf("method that is not granted: %d", code)
	}
	stranger := &zp.ConfigureSpec{APIKey: strings.Repeat("0", 64), ZoraxyPort: port}
	if code, _ := read(stranger.DoAPIRequest(http.MethodGet, "/plugin/api/access/list", nil)); code != http.StatusUnauthorized {
		t.Fatalf("unknown key: %d", code)
	}

	//A redirect is handed back, not followed (the key is not sent on)
	sawAuth = ""
	if code, _ := read(cfg.DoAPIRequest(http.MethodGet, "/plugin/api/moved", nil)); code != http.StatusFound || sawAuth != "" {
		t.Fatalf("redirect: status %d, key sent on: %v", code, sawAuth != "")
	}

	//No key, no port, or something that is not a path: an error and no request
	for _, bad := range []*zp.ConfigureSpec{nil, {ZoraxyPort: port}, {APIKey: key.APIKey}} {
		if _, err := bad.NewAPIRequest(http.MethodGet, "/plugin/api/access/list", nil); !errors.Is(err, zp.ErrNoAPIKey) {
			t.Fatalf("configuration %+v: %v", bad, err)
		}
		if _, err := bad.DoAPIRequest(http.MethodGet, "/plugin/api/access/list", nil); !errors.Is(err, zp.ErrNoAPIKey) {
			t.Fatalf("configuration %+v: %v", bad, err)
		}
	}
	for _, ep := range []string{"", "plugin/api/access/list", "http://example.invalid/plugin/api/access/list", "//example.invalid/x", "@example.invalid/x"} {
		if _, err := cfg.NewAPIRequest(http.MethodGet, ep, nil); !errors.Is(err, zp.ErrAPIEndpoint) {
			t.Fatalf("endpoint %q must be refused: %v", ep, err)
		}
	}

	//APIURL refuses the same endpoints (an empty address: a request built from it cannot be
	//sent, so the key cannot go to another host), and no helper panics without a configuration
	for _, ep := range []string{"", "plugin/api/access/list", "//example.invalid/x", "@example.invalid/x", ".example.invalid/x", ":1@example.invalid/x"} {
		if got := cfg.APIURL(ep); got != "" {
			t.Fatalf("APIURL(%q) = %q, want an empty address", ep, got)
		}
	}
	if u, err := url.Parse(cfg.APIURL("/plugin/api/access/list?x=@example.invalid")); err != nil || u.Host != "127.0.0.1:"+strconv.Itoa(port) || u.User != nil {
		t.Fatalf("APIURL of a path must stay on Zoraxy: %v %v", u, err)
	}
	var none *zp.ConfigureSpec
	if got := none.APIURL("/plugin/api/access/list"); got != "" {
		t.Fatalf("APIURL without a configuration = %q", got)
	}
	if got := (&zp.ConfigureSpec{APIKey: key.APIKey}).APIURL("/plugin/api/access/list"); got != "" {
		t.Fatalf("APIURL without a port = %q", got)
	}
	bare, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	none.SetAPIAuth(bare)
	(&zp.ConfigureSpec{}).SetAPIAuth(bare)
	cfg.SetAPIAuth(nil)
	if bare.Header.Get("Authorization") != "" {
		t.Fatalf("SetAPIAuth without a key must set no header: %q", bare.Header.Get("Authorization"))
	}

	//The key stops working when the plugin is stopped, as before
	keys.RevokeAPIKeysForPlugin("test.sdk.apiclient")
	if code, _ := read(cfg.DoAPIRequest(http.MethodGet, "/plugin/api/access/list", nil)); code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d", code)
	}
}
