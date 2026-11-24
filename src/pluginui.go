package main

import (
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/foleyit/dunree/mod/updater"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	pluginui.go

	Glue for the isolated plugin pages (opt-in, see mod/plugins/ui_isolation.go):
	the default listen address, the allow-list of the admin listener in front of
	them, and the public style and script files plugin pages load by absolute path.
	Nothing here runs unless "isolated plugin pages" is turned on in the plugin
	safety settings.
*/

// isolatedPluginUIDefaultListen returns the host of the admin listener with the
// next port, e.g. ":8000" -> ":8001". Empty when the admin address has no usable port.
func isolatedPluginUIDefaultListen(adminAddr string) string {
	host, port, err := net.SplitHostPort(adminAddr)
	if err != nil {
		return ""
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n >= 65535 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(n+1))
}

// pluginUIAllowList puts the allow-list of the admin listener in front of the
// isolated plugin pages. The list is looked up per request: it is created after
// the plugin manager.
func pluginUIAllowList(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminAllowMgr == nil {
			h.ServeHTTP(w, r)
			return
		}
		adminAllowMgr.Middleware(h).ServeHTTP(w, r)
	})
}

// pluginUIStaticAssets serves the files of the admin UI. The plugin manager only
// passes requests for the public style and script files to it (isolatedStaticPath).
func pluginUIStaticAssets() http.Handler {
	var once sync.Once
	var files http.Handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if *development_build && utils.FileExists("web") {
				files = http.FileServer(http.Dir("web/"))
				return
			}
			if subFS, err := fs.Sub(webres, "web"); err == nil {
				files = http.FileServer(http.FS(subFS))
			}
		})
		if files == nil {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// releasePublicKeyBytes is the public key Dunree releases are verified with. The
// plugin manager refuses it as the plugin index key: the index has a key of its own.
func releasePublicKeyBytes() []byte {
	pk, err := updater.EmbeddedPublicKey()
	if err != nil {
		return nil
	}
	return []byte(pk)
}
