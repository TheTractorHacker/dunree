package dynamicproxy

import (
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"imuslab.com/zoraxy/mod/deployrole"
	"imuslab.com/zoraxy/mod/netutils"
)

/*
	deployrole_hook.go

	Glue between the deployment role (mod/deployrole) and the proxy listeners.
	Nothing here runs in the standalone role unless the admin switched the header hardening on:
	deployRoleEntry returns at once for a nil manager or a standalone role with no opt-in.

	Entry points (all listeners that carry proxied traffic): withHealth (TLS, plain HTTP, HTTP/3),
	handlePort80Request and the secondary listeners.
*/

var (
	peerGateRejected atomic.Uint64 //connections refused by the internal role peer gate since start
	peerGateLastLog  atomic.Int64  //unix seconds of the last log line (rate limit)
)

// PeerGateRejected is the number of requests refused by the internal role peer gate since start
func PeerGateRejected() uint64 { return peerGateRejected.Load() }

func (router *Router) trustedProxyFn() func(string) bool {
	if router == nil || router.Option == nil || router.Option.AccessController == nil {
		return nil
	}
	return router.Option.AccessController.IsTrustedProxy
}

// deployRoleEntry applies the deployment role to a request before any routing. It
// returns true when the request was rejected (response written).
func (router *Router) deployRoleEntry(w http.ResponseWriter, r *http.Request) bool {
	if router == nil || router.Option == nil || router.Option.DeployRole == nil {
		return false
	}
	dr := router.Option.DeployRole
	if dr.PeerGateActive() {
		peer := netutils.GetRequesterIPUntrusted(r)
		if !dr.PeerAllowed(peer, router.trustedProxyFn()) {
			peerGateRejected.Add(1)
			now := time.Now().Unix()
			if last := peerGateLastLog.Load(); now-last >= 30 && peerGateLastLog.CompareAndSwap(last, now) && router.Option.Logger != nil {
				router.Option.Logger.PrintAndLog("deployrole", "Internal role: refused a connection from "+peer+" (not a trusted proxy and not in the direct-access networks). Further refusals are counted, logged at most every 30 s", nil)
			}
			http.Error(w, "403 - Forbidden", http.StatusForbidden)
			return true
		}
	}
	if dr.HardenActive() {
		deployrole.Harden(r, router.trustedProxyFn())
	}
	return false
}

// trustedRequesterIP is netutils.GetRequesterIP for the auth exception rules that opted in to
// trusting proxy headers (UseTrustedProxy). With the header hardening on, the headers are only
// believed when the TCP peer is a trusted proxy, whatever the rule says.
func (router *Router) trustedRequesterIP(r *http.Request) string {
	if router != nil && router.Option != nil && router.Option.DeployRole.HardenActive() {
		peer := netutils.GetRequesterIPUntrusted(r)
		isTrusted := router.trustedProxyFn()
		if isTrusted == nil || peer == "" || !(isTrusted(peer) || isTrusted(net.ParseIP(peer).String())) {
			return peer
		}
	}
	return netutils.GetRequesterIP(r)
}

// TrustedRequesterIP is the client address for consumers outside the request chain (GeoIP locale
// of the admin UI): proxy headers are believed unless the header hardening is on and the peer is not trusted.
func (router *Router) TrustedRequesterIP(r *http.Request) string { return router.trustedRequesterIP(r) }
