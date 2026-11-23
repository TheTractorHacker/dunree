// SDK fixture plugin: a small plugin written against the public API of the
// zoraxy_plugin package, used by the SDK compatibility tests (sdk_compat_test.go).
//
// The test copies this folder into a throw-away module, puts one version of the
// SDK next to it as mod/zoraxy_plugin (the frozen copy in testdata/sdk-1.0.0, or
// the current one) and builds it. The same source has to compile against every
// 1.x version of the SDK: what only a newer SDK has lives in declare_sdk11.go
// behind the build tag "sdk11".
//
// It behaves well on purpose (the chaos plugin is the one that misbehaves):
// UI with the terminate handler of the SDK, a pre_auth filter, a static capture
// path, an event subscription and one permitted API endpoint. It writes what it
// was started with to last-configure.json and last-args.json next to the binary.
//
// Never install this on a real proxy.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	plugin "example.com/zoraxy/sdkplugin/mod/zoraxy_plugin"
)

var eventsSeen, eventsWithToken atomic.Int64

func main() {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	folder := strings.TrimSuffix(filepath.Base(exe), ".exe")

	spec := &plugin.IntroSpect{
		ID:            "test.sdk." + strings.ToLower(folder),
		Name:          "SDK fixture " + folder,
		Author:        "Zoraxy fork test suite",
		AuthorContact: "https://example.invalid/sdk",
		Description:   "SDK compatibility test plugin. Not for production.",
		URL:           "https://example.invalid/sdk",
		Type:          plugin.PluginType_Router,
		VersionMajor:  1,

		StaticCapturePaths:   []plugin.StaticCaptureRule{{CapturePath: "/sdk-static"}},
		StaticCaptureIngress: "/static",
		UIPath:               "/ui",

		SubscriptionPath:    "/events",
		SubscriptionsEvents: map[string]string{"blacklistedIpBlocked": "sdk fixture subscription"},

		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{Method: http.MethodGet, Endpoint: "/plugin/api/access/list", Reason: "sdk fixture permission"},
		},

		Hooks: &plugin.HookSettings{
			Version:           plugin.HookAPIVersion,
			Stages:            []plugin.HookStage{plugin.HookStagePreAuth},
			FilterRequestPath: "/filter",
			TimeoutMs:         500,
			FailurePolicy:     plugin.FailureOpen,
		},
	}
	declare(spec) //what only a newer SDK can say (declare_*.go)

	conf, err := plugin.ServeAndRecvSpec(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdkplugin: no configuration:", err)
		os.Exit(64)
	}
	//Tests read what Zoraxy handed over from these files
	if raw, err := json.Marshal(conf); err == nil {
		os.WriteFile("last-configure.json", raw, 0o600)
	}
	if raw, err := json.Marshal(os.Args); err == nil {
		os.WriteFile("last-args.json", raw, 0o600)
	}

	mux := http.NewServeMux()

	ui := plugin.NewPluginFileSystemUIRouter(spec.ID, "./www", spec.UIPath)
	ui.RegisterTerminateHandler(func() { fmt.Println("sdkplugin: asked to stop") }, mux)
	mux.HandleFunc(spec.UIPath+"/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"events":%d,"events_with_token":%d}`, eventsSeen.Load(), eventsWithToken.Load())
	})
	mux.Handle(spec.UIPath+"/", ui.Handler())

	mux.Handle("/filter", plugin.NewFilterHandler(conf.InvokeToken, func(fr *plugin.FilterRequest) *plugin.FilterVerdict {
		if fr.HeaderValue("X-Sdk-Deny") != "" {
			return plugin.Deny(http.StatusForbidden, "denied by the sdk fixture")
		}
		return plugin.ModifyRequestHeaders(plugin.HeaderOps{Set: map[string]string{"X-Sdk-Fixture": "seen"}})
	}))

	router := plugin.NewPathRouter()
	router.RegisterPathHandler("/sdk-static", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "captured by the sdk fixture")
	}))
	router.RegisterStaticCaptureHandle(spec.StaticCaptureIngress, mux)

	mux.HandleFunc("/events/", func(w http.ResponseWriter, r *http.Request) {
		eventsSeen.Add(1)
		if conf.InvokeToken != "" && plugin.VerifyInvokeToken(conf.InvokeToken, r) {
			eventsWithToken.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})
	serveExtras(mux)

	addr := "127.0.0.1:" + strconv.Itoa(conf.Port)
	fmt.Println("sdkplugin: ready on " + addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "sdkplugin: server stopped:", err)
		os.Exit(66)
	}
}
