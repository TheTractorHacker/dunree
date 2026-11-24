// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package dpcore

import (
	"github.com/foleyit/dunree/mod/brand"
	"github.com/foleyit/dunree/mod/wirecompat"
)

/*
	Values that name the proxy to upstreams (plan row 12 of docs/rebrand/plan.md).

	A value cannot be sent twice, so each one is chosen by how an upstream is likely to use it:

	  - User-Agent (only when the client sent none) and x-proxy-by (development mode only): the
	    Dunree token; while the legacy names are on the inherited token is appended, so a substring
	    match on "zoraxy" keeps working. // legacy-compat
	  - X-Forwarded-Server: an identifier that is compared as a whole or by prefix, so while the
	    legacy names are on it stays "zoraxy-<uuid>" and only with them off it becomes "dunree-<uuid>". // legacy-compat
*/

// IdentityUserAgent is the User-Agent set on a proxied request whose client sent none.
// compatVersion is the version of the inherited code base (3.3.6).
func IdentityUserAgent(compatVersion string) string {
	ua := "Dunree/" + brand.Version
	if wirecompat.EmitLegacy() {
		ua += " Zoraxy/" + compatVersion // legacy-compat
	}
	return ua
}

// IdentityProxyBy is the debug x-proxy-by response header of development mode.
func IdentityProxyBy() string {
	v := "dunree/" + brand.Version
	if wirecompat.EmitLegacy() {
		v += " (zoraxy-compatible)" // legacy-compat
	}
	return v
}

// ForwardedServer is the X-Forwarded-Server value sent to upstreams.
func ForwardedServer(hostUUID string) string {
	if wirecompat.EmitLegacy() {
		return "zoraxy-" + hostUUID // legacy-compat: upstreams compare the whole value or its prefix
	}
	return "dunree-" + hostUUID
}
