package plugins

import (
	"net/http"

	dunreePlugin "github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

/*
	wire.go

	Names on the wire between Dunree and a plugin.

	Dunree keeps the plugin contract of Zoraxy (contract version 1). A plugin built with the // legacy-compat
	Zoraxy SDK is a binary: it reads X-Zoraxy-* headers and the zoraxy_* fields of the // legacy-compat
	configure payload, and nothing can change that after it was built. So, for the whole 1.x line:

	  - every header Dunree sets on a call to a plugin is sent twice, as X-Dunree-<name> and
	    as X-Zoraxy-<name>, with the same value. This does NOT follow the setting "Also send
	    legacy X-Zoraxy-* headers": without the old names a Zoraxy-SDK plugin could not verify // legacy-compat
	    its invoke token, would refuse every call, and a fail-open filter would then let
	    traffic pass without anyone being told.
	  - the configure payload always has zoraxy_port, runtime_const.zoraxy_version and
	    runtime_const.zoraxy_uuid. zoraxy_version is the Zoraxy release Dunree is based on, so // legacy-compat
	    a plugin that checks for "3.x or newer" keeps working.
	  - dunree_port, runtime_const.dunree_version and runtime_const.dunree_uuid are added for
	    a plugin whose introspection says sdk_flavor "dunree". A plugin without that field
	    gets byte for byte the payload it got from Zoraxy. // legacy-compat
*/

// hostHeaders returns a header of the host under both names, in the form the reverse proxy takes
func hostHeaders(name string, value string) [][]string {
	return wirecompat.HeaderPairs(name, value)
}

// setHostHeader sets a header of the host under both names on a request Dunree builds itself
func setHostHeader(h http.Header, name string, value string) {
	wirecompat.SetHeaderAlways(h, name, value)
}

// runtimeConstFor returns the runtime_const object for a plugin
func (m *Manager) runtimeConstFor(speaksDunree bool) dunreePlugin.RuntimeConstantValue {
	var rc dunreePlugin.RuntimeConstantValue
	if m.Options.SystemConst != nil {
		rc = *m.Options.SystemConst
	}
	// What a Zoraxy plugin reads. A caller that only filled the Dunree fields (tests, an // legacy-compat
	// embedding program) still gives such a plugin a version and a UUID.
	if rc.ZoraxyVersion == "" { // legacy-compat
		rc.ZoraxyVersion = rc.DunreeVersion // legacy-compat
	}
	if rc.ZoraxyUUID == "" { // legacy-compat
		rc.ZoraxyUUID = rc.DunreeUUID // legacy-compat
	}
	if !speaksDunree {
		rc.DunreeVersion, rc.DunreeUUID = "", ""
	}
	return rc
}
