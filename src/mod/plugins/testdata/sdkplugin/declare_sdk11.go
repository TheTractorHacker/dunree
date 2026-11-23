//go:build sdk11

package main

import (
	"net/http"
	"os"

	plugin "example.com/zoraxy/sdkplugin/mod/zoraxy_plugin"
)

// SDK 1.1: secrets on standard input and a health address. api_version is filled
// in by ServeIntroSpect.
func declare(spec *plugin.IntroSpect) {
	spec.ConfigureVia = plugin.ConfigureViaStdin
	spec.HealthPath = "/health"
}

func serveExtras(mux *http.ServeMux) {
	mux.Handle("/health", plugin.HealthHandler(func() error {
		//A file named "sick" next to the binary makes the plugin unhealthy
		if _, err := os.Stat("sick"); err == nil {
			return os.ErrInvalid
		}
		return nil
	}))
}
