//go:build !sdk11

package main

import (
	"net/http"

	plugin "example.com/zoraxy/sdkplugin/mod/zoraxy_plugin"
)

// SDK 1.0: nothing more to declare
func declare(spec *plugin.IntroSpect) {}

func serveExtras(mux *http.ServeMux) {}
