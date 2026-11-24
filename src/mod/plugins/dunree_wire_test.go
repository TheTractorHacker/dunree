package plugins

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/foleyit/dunree/mod/dynamicproxy/dpcore"
	zp "github.com/foleyit/dunree/mod/plugins/dunree_plugin"
	"github.com/foleyit/dunree/mod/plugins/dunree_plugin/events"
	"github.com/foleyit/dunree/mod/wirecompat"
)

/*
	Dunree rebrand: the plugin wire.

	A plugin built with the Zoraxy SDK (package zoraxy_plugin: zoraxy_port, zoraxy_version, // legacy-compat
	zoraxy_uuid, X-Zoraxy-* headers) must be discovered, started and work exactly as before.
	A plugin built with the Dunree SDK (package dunree_plugin) gets the Dunree names as well.

	The Zoraxy side is tested three ways: // legacy-compat
	  - testdata/sdk-1.2.0: the SDK as it was in the last revision before the rebrand, frozen
	    there by `git show <rev>:src/mod/plugins/zoraxy_plugin/...`; the fixture plugin is // legacy-compat
	    built against it and run through the whole suite (and against 1.0.0 and 1.1.0)
	  - testdata/chaosplugin: a hand-written plugin that speaks the old JSON and reads the
	    old headers without any SDK, and records the payload as it arrived
	  - a fake plugin (httptest) that records the raw headers of every kind of call
*/

// The last Zoraxy SDK passes the whole suite on this Dunree // legacy-compat
func TestSDKCompatBinaryBuiltWithZoraxySDK12StillPasses(t *testing.T) { sdkSuite(t, sdk12) } // legacy-compat

// And it does so with "Also send legacy X-Zoraxy-* headers" switched off: the plugin channel
// does not follow that setting, or the plugin would refuse every call of the host
func TestSDKCompatZoraxySDKPluginWorksWithLegacyNamesOff(t *testing.T) { // legacy-compat
	wirecompat.SetEmitLegacy(false)
	defer wirecompat.SetEmitLegacy(true)
	sdkSuite(t, sdk12)
}

// The frozen 1.2.0 is the Zoraxy SDK: old package name, old field names, old headers, nothing of Dunree // legacy-compat
func TestSDKFrozen12IsThePreRebrandSDK(t *testing.T) {
	dir := filepath.Join("testdata", "sdk-"+sdk12, "zoraxy_plugin") // legacy-compat: frozen old-SDK fixture keeps the old directory name
	var all strings.Builder
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		raw, err := os.ReadFile(path)
		all.Write(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	src := all.String()
	for _, want := range []string{
		"package zoraxy_plugin", `SDKVersion = "` + sdk12 + `"`, // legacy-compat
		"`json:\"zoraxy_port,omitempty\"`", "`json:\"zoraxy_version\"`", "`json:\"zoraxy_uuid\"`",
		`"X-Zoraxy-Plugin-Token"`, `"X-Zoraxy-RequestID"`, `"X-Zoraxy-Capture"`, `"X-Zoraxy-Csrf"`,
	} { // legacy-compat
		if !strings.Contains(src, want) {
			t.Errorf("the frozen SDK %s lacks %s: it was overwritten", sdk12, want)
		}
	}
	if strings.Contains(strings.ToLower(src), "dunree") {
		t.Fatalf("the frozen SDK %s mentions Dunree: it was renamed, it must stay as plugins in the field were built", sdk12)
	}
}

// What each kind of plugin is handed at its start
func TestConfigurePayloadZoraxyNamesAlwaysDunreeNamesForDunreePlugins(t *testing.T) { // legacy-compat
	m := newFaultManager(t)
	m.Options.DunreePort = 18123
	m.Options.SystemConst = &zp.RuntimeConstantValue{DunreeVersion: "1.0.0-beta.1", DunreeUUID: "node-uuid", ZoraxyVersion: "3.3.6", ZoraxyUUID: "node-uuid"} // legacy-compat

	// 1. No SDK at all, old JSON: the payload as it arrived, key by key
	legacy := startChaos(t, m, "oldjson", "mode=ok\nfeatures=hooks,api\n", "t")
	waitHealth(t, legacy, HealthOK)
	if legacy.Spec.SDKFlavor != "" {
		t.Fatalf("the chaos plugin declares no SDK flavour, got %q", legacy.Spec.SDKFlavor)
	}
	raw, err := os.ReadFile(filepath.Join(legacy.RootDir, "last-configure.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "dunree") {
		t.Fatalf("a plugin built for Zoraxy got a Dunree name in its configure payload: %s", raw) // legacy-compat
	}
	var got struct {
		ZoraxyPort   int                        `json:"zoraxy_port"` // legacy-compat
		RuntimeConst map[string]json.RawMessage `json:"runtime_const"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ZoraxyPort != 18123 || jsonString(got.RuntimeConst["zoraxy_version"]) != "3.3.6" || jsonString(got.RuntimeConst["zoraxy_uuid"]) != "node-uuid" || len(got.RuntimeConst) != 3 { // legacy-compat
		t.Fatalf("legacy payload: %s", raw)
	}
	if _, has := got.RuntimeConst["development_build"]; !has {
		t.Fatalf("legacy payload: %s", raw)
	}
	// byte for byte what Zoraxy sent: field order included // legacy-compat
	if i, j, k := strings.Index(string(raw), `"port"`), strings.Index(string(raw), `"runtime_const":{"zoraxy_version":"3.3.6","zoraxy_uuid":"node-uuid","development_build":false}`), strings.Index(string(raw), `"zoraxy_port"`); i < 0 || j < i || k < j { // legacy-compat
		t.Fatalf("the legacy payload changed its shape: %s", raw)
	}

	// 2. Zoraxy SDK 1.0.0 (configured on the command line): no Dunree name there either // legacy-compat
	old := loadSDKPlugin(t, m, sdkOld, "sdkold", "t")
	mustStart(t, m, old)
	waitHealth(t, old, HealthOK)
	if cl := procCmdline(t, old); !strings.Contains(cl, `"zoraxy_port":18123`) || !strings.Contains(cl, `"zoraxy_version":"3.3.6"`) || strings.Contains(strings.ToLower(cl), "dunree_") { // legacy-compat
		t.Fatalf("command line of a Zoraxy SDK 1.0.0 plugin: %q", cl) // legacy-compat
	}

	// 3. Zoraxy SDK 1.2.0: what the plugin understood (the SDK decodes into its own struct) // legacy-compat
	z12 := loadSDKPlugin(t, m, sdk12, "sdk12", "t")
	mustStart(t, m, z12)
	waitHealth(t, z12, HealthOK)
	if z12.Spec.SDKFlavor != "" {
		t.Fatalf("a Zoraxy SDK plugin declares no flavour, got %q", z12.Spec.SDKFlavor) // legacy-compat
	}
	seen := startedWith(t, z12.RootDir)
	var rc map[string]json.RawMessage
	json.Unmarshal(seen["runtime_const"], &rc)
	if string(seen["zoraxy_port"]) != "18123" || jsonString(rc["zoraxy_version"]) != "3.3.6" || jsonString(rc["zoraxy_uuid"]) != "node-uuid" { // legacy-compat
		t.Fatalf("a Zoraxy SDK 1.2.0 plugin did not read its port, version and UUID: %v", seen) // legacy-compat
	}

	// 4. Dunree SDK: declares the flavour and gets both sets of names
	cur := loadSDKPlugin(t, m, sdkCurrent, "sdkdunree", "t")
	mustStart(t, m, cur)
	waitHealth(t, cur, HealthOK)
	if cur.Spec.SDKFlavor != zp.SDKFlavorDunree {
		t.Fatalf("a plugin built with the Dunree SDK must declare sdk_flavor %q, got %q", zp.SDKFlavorDunree, cur.Spec.SDKFlavor)
	}
	seen = startedWith(t, cur.RootDir)
	rc = nil
	json.Unmarshal(seen["runtime_const"], &rc)
	// dunree_version differs from zoraxy_version here, so it cannot be the fallback of the SDK
	if string(seen["dunree_port"]) != "18123" || string(seen["zoraxy_port"]) != "18123" || // legacy-compat
		jsonString(rc["dunree_version"]) != "1.0.0-beta.1" || jsonString(rc["dunree_uuid"]) != "node-uuid" ||
		jsonString(rc["zoraxy_version"]) != "3.3.6" || jsonString(rc["zoraxy_uuid"]) != "node-uuid" { // legacy-compat
		t.Fatalf("configure payload of a Dunree SDK plugin: %v", seen)
	}
}

// Every header Dunree sets on a call to a plugin is there under both names, with the same value,
// whatever the legacy switch says: filter, static capture, UI, event, health check
func TestHostHeadersToPluginsHaveBothNames(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		name := "legacy names on"
		if !legacy {
			name = "legacy names off"
		}
		t.Run(name, func(t *testing.T) {
			wirecompat.SetEmitLegacy(legacy)
			defer wirecompat.SetEmitLegacy(true)
			m := newHookTestManager(t)
			m.Options.CSRFTokenGen = func(*http.Request) string { return "csrf-of-the-session" }
			var mu sync.Mutex
			seen := map[string]http.Header{}
			hooks := &zp.HookSettings{Stages: []zp.HookStage{zp.HookStagePreAuth}, FilterRequestPath: "/filter"}
			p := addFakePlugin(t, m, "both", hooks, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen[r.URL.Path] = r.Header.Clone()
				mu.Unlock()
				if r.URL.Path == "/filter" {
					json.NewEncoder(w).Encode(zp.Allow())
				}
			}, "t")
			p.hook.token = "sekret"
			p.proc = &pluginProc{ctx: context.Background()} //events are bound to the process
			p.Spec.StaticCapturePaths = []zp.StaticCaptureRule{{CapturePath: "/cap"}}
			p.Spec.StaticCaptureIngress = "/ingress"
			p.Spec.UIPath = "/ui"
			p.Spec.SubscriptionPath = "/events"
			p.Spec.HealthPath = "/health"

			//filter
			r := newReq("GET", "http://app.example.com/x", "")
			r.Header.Set("X-Dunree-RequestID", "client-supplied")
			r.Header.Set("X-Zoraxy-RequestID", "client-supplied") // legacy-compat
			if res := m.RunRequestStage(httptest.NewRecorder(), r, []string{"t"}, "203.0.113.7", zp.HookStagePreAuth); res.Handled {
				t.Fatal("allow must continue")
			}
			//health check
			if err := m.probeHealth(r.Context(), p, p.AssignedPort); err != nil {
				t.Fatal(err)
			}
			//event
			if err := p.sendEvent(events.Event{Name: events.EventName("blacklistedIpBlocked")}); err != nil {
				t.Fatal(err)
			}

			check := func(path string, names ...string) {
				t.Helper()
				mu.Lock()
				h := seen[path]
				mu.Unlock()
				if h == nil {
					t.Fatalf("the plugin was not called at %s (called: %v)", path, len(seen))
				}
				for _, n := range names {
					a, b := h.Get("X-Dunree-"+n), h.Get("X-Zoraxy-"+n) // legacy-compat
					if a == "" || a != b || a == "client-supplied" {
						t.Errorf("%s: X-Dunree-%s=%q X-Zoraxy-%s=%q", path, n, a, n, b)
					}
				}
			}
			//static capture
			p.staticRouteProxy = map[string]*dpcore.ReverseProxy{}
			p.StartAllStaticPathRouters()
			cr := newReq(http.MethodGet, "http://app.example.com/cap/thing?a=1", "")
			cr.RequestURI = "/cap/thing?a=1"
			for _, n := range []string{"Capture", "Uri", "RequestID", "Plugin-Token"} {
				cr.Header.Set("X-Dunree-"+n, "client-supplied")
				cr.Header.Set("X-Zoraxy-"+n, "client-supplied") // legacy-compat
			}
			p.HandleStaticRoute(httptest.NewRecorder(), cr, "/cap")
			//UI under the admin origin, and from the isolated listener
			if err := m.StartUIHandlerForPlugin(p, p.AssignedPort); err != nil {
				t.Fatal(err)
			}
			for _, isolated := range []bool{false, true} {
				page := "/admin-origin"
				if isolated {
					page = "/isolated"
				}
				ur := httptest.NewRequest(http.MethodGet, "/plugin.ui/both"+page, nil)
				ur.RequestURI = "/plugin.ui/both" + page
				ur.Header.Set("X-Dunree-Csrf", "client-supplied")
				ur.Header.Set("X-Zoraxy-Csrf", "client-supplied") // legacy-compat
				m.servePluginUI(p, httptest.NewRecorder(), ur, "/plugin.ui/both", isolated)
			}

			check("/filter", "RequestID", "Plugin-Token")
			check("/ingress/thing", "Capture", "Uri", "RequestID", "Plugin-Token")
			check("/ui/admin-origin", "Csrf")
			check("/ui/isolated", "Ui-Isolated")
			mu.Lock()
			if h := seen["/ui/isolated"]; h.Get("X-Dunree-Csrf") != "" || h.Get("X-Zoraxy-Csrf") != "" { // legacy-compat
				t.Errorf("an isolated plugin page got a CSRF header: %v", h)
			}
			if h := seen["/ingress/thing"]; h.Get("X-Dunree-Capture") != "/cap" || h.Get("X-Dunree-Uri") != "/cap/thing?a=1" {
				t.Errorf("static capture headers: %v", h)
			}
			mu.Unlock()
			check("/health", "Plugin-Token")
			check("/events/blacklistedIpBlocked", "Event-Type", "Plugin-Token")
		})
	}
}
