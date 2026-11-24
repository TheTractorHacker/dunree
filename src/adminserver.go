package main

import (
	"net/http"
	"time"
)

/*
	adminserver.go

	Builds the http.Server used by the management interface listeners (plain
	HTTP, HTTPS and the plugin loopback). A bare http.Serve has no timeouts at
	all, so a client that can reach the admin port could hold connections open
	forever by stalling in the TLS handshake or trickling request headers
	(slowloris), before the allow-list or any authentication runs.
*/

const (
	//Time allowed to send the complete request headers. net/http also applies
	//it to the TLS handshake of a connection accepted as a *tls.Conn.
	adminReadHeaderTimeout = 10 * time.Second
	//Time an idle keep-alive connection is kept open between requests
	adminIdleTimeout = 120 * time.Second
	//Upper bound of the request line plus headers
	adminMaxHeaderBytes = 1 << 20
)

// newAdminHTTPServer returns a http.Server for the management interface with
// header, handshake and idle timeouts set.
//
// ReadTimeout and WriteTimeout are deliberately left unset: they cover the
// whole request body and response, and would cut off large uploads (config
// restore, update packages) and long lived responses (log streaming, SSE).
// Hijacked connections (websocket) have their deadlines cleared by net/http.
func newAdminHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: adminReadHeaderTimeout,
		IdleTimeout:       adminIdleTimeout,
		MaxHeaderBytes:    adminMaxHeaderBytes,
	}
}
