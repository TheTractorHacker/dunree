// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package main

import "strings"

// mdnsInstanceNames returns the mDNS instance name this node announces and the further names it
// announces as well. Default: dunree_<uuid>, plus zoraxy_<uuid> (the name of existing installs,
// plan row 41) while the legacy names are on. A name set with -mdnsname is used alone.
func mdnsInstanceNames(custom string, nodeUUID string, legacy bool) (string, []string) {
	if custom != "" {
		return strings.TrimSuffix(custom, ".local"), nil
	}
	if legacy {
		return MDNS_HOSTNAME_PREFIX + nodeUUID, []string{MDNS_LEGACY_HOSTNAME_PREFIX + nodeUUID}
	}
	return MDNS_HOSTNAME_PREFIX + nodeUUID, nil
}
