// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package main

import (
	"reflect"
	"testing"
)

func TestMDNSInstanceNames(t *testing.T) {
	if p, a := mdnsInstanceNames("", "u1", true); p != "dunree_u1" || !reflect.DeepEqual(a, []string{"zoraxy_u1"}) { // legacy-compat
		t.Errorf("legacy on: %q %v", p, a)
	}
	if p, a := mdnsInstanceNames("", "u1", false); p != "dunree_u1" || a != nil {
		t.Errorf("legacy off: %q %v", p, a)
	}
	if p, a := mdnsInstanceNames("gw.local", "u1", true); p != "gw" || a != nil {
		t.Errorf("custom name: %q %v", p, a)
	}
	// the TXT identity names Dunree's publisher, not the authors of the code it is based on
	if MDNS_IDENTIFY_VENDOR != "Foley IT" || MDNS_IDENTIFY_DOMAIN != "dunree.local" {
		t.Errorf("identity %q / %q", MDNS_IDENTIFY_VENDOR, MDNS_IDENTIFY_DOMAIN)
	}
}
