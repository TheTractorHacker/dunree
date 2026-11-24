package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	plugin "example.com/dunree/fork-ref-filter/mod/dunree_plugin"
)

/*
	Fork reference plugin: filter

	The smallest plugin that uses the whole filter part of the plugin contract
	(docs/plugins/contract.md) the way the fork recommends. It is a reference and a
	test fixture (the conformance kit tools/plugin-check and the fault suite run
	against it), not a feature:

	- pre_auth stage:  a request whose path starts with /fork-ref-filter/deny is
	                   answered 403; every other request gets the request header
	                   X-Fork-Ref-Filter: pre_auth
	- response stage:  every response gets the header X-Fork-Ref-Filter: response

	What it shows
	- start configuration on standard input (no secret on the command line)
	- the invoke token is required on the filter path
	- a health path
	- failure policy fail_closed is DECLARED. Dunree only honours it after the
	  administrator ticked the consent for this plugin; without it the plugin fails open
	- it ends on the terminate request and on SIGTERM
	- it writes two log lines per start and none per request

	It only acts on proxy rules it is attached to (a tag of its plugin group, or
	"Apply to all HTTP proxy rules").
*/

const (
	uiPath     = "/ui"
	healthPath = "/health"
	filterPath = "/filter"
	denyPrefix = "/fork-ref-filter/deny"
	markHeader = "X-Fork-Ref-Filter"
)

var calls, denied atomic.Int64

func requestPath(fr *plugin.FilterRequest) string {
	raw := fr.Request.RequestURI
	if raw == "" {
		raw = fr.Request.URL
	}
	if u, err := url.ParseRequestURI(raw); err == nil {
		return u.Path
	}
	return raw
}

func filter(fr *plugin.FilterRequest) *plugin.FilterVerdict {
	calls.Add(1)
	switch fr.Stage {
	case plugin.HookStagePreAuth:
		if strings.HasPrefix(requestPath(fr), denyPrefix) {
			denied.Add(1)
			return plugin.Deny(http.StatusForbidden, "Forbidden by the fork reference filter\n").WithReason("path under " + denyPrefix)
		}
		return plugin.ModifyRequestHeaders(plugin.HeaderOps{Set: map[string]string{markHeader: "pre_auth"}})
	case plugin.HookStageResponse:
		return plugin.ModifyResponseHeaders(plugin.HeaderOps{Set: map[string]string{markHeader: "response"}})
	}
	return plugin.Allow()
}

func main() {
	cfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            "fork.zoraxy.ref.filter",
		Name:          "Fork Reference Filter",
		Author:        "Dunree fork",
		AuthorContact: "see the repository of the fork",
		Description:   "Reference filter plugin and test fixture: marks requests and responses with a header and denies one fixed path. Not a feature.",
		Type:          plugin.PluginType_Router,
		VersionMajor:  1,
		UIPath:        uiPath,
		HealthPath:    healthPath,
		ConfigureVia:  plugin.ConfigureViaStdin,
		Hooks: &plugin.HookSettings{
			Version:           plugin.HookAPIVersion,
			Stages:            []plugin.HookStage{plugin.HookStagePreAuth, plugin.HookStageResponse},
			FilterRequestPath: filterPath,
			Priority:          100,
			TimeoutMs:         250,
			FailurePolicy:     plugin.FailureClosed, //only honoured with the consent of the administrator
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-filter: no start configuration:", err)
		os.Exit(64)
	}

	stop := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.Handle(filterPath, plugin.NewFilterHandler(cfg.InvokeToken, filter))
	mux.Handle(healthPath, plugin.HealthHandler(nil))
	mux.HandleFunc(uiPath+"/term", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case stop <- struct{}{}:
		default:
		}
	})
	mux.HandleFunc(uiPath+"/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"calls":%d,"denied":%d}`, calls.Load(), denied.Load())
	})
	mux.HandleFunc(uiPath+"/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Fork Reference Filter</title>
<body style="font-family:sans-serif;max-width:40em;margin:2em">
<h3>Fork Reference Filter</h3>
<p>Reference plugin and test fixture. Attached rules get the header <code>%s</code> on requests and responses;
requests under <code>%s</code> are answered 403.</p>
<p>Filter calls since start: <b>%d</b>, denied: <b>%d</b>.</p></body>`, markHeader, denyPrefix, calls.Load(), denied.Load())
	})

	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(cfg.Port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fork-ref-filter: cannot listen:", err)
		os.Exit(65)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		select {
		case <-sig:
		case <-stop:
		}
		fmt.Println("fork-ref-filter: stopping")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	fmt.Println("fork-ref-filter: listening on " + ln.Addr().String())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "fork-ref-filter: server stopped:", err)
		os.Exit(66)
	}
}
