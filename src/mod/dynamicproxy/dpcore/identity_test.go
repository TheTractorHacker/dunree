// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package dpcore

import (
	"testing"

	"github.com/foleyit/dunree/mod/brand"
	"github.com/foleyit/dunree/mod/wirecompat"
)

func TestIdentityValuesFollowTheLegacySwitch(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	wirecompat.SetEmitLegacy(true)
	if g := IdentityUserAgent("3.3.6"); g != "Dunree/"+brand.Version+" Zoraxy/3.3.6" { // legacy-compat
		t.Errorf("UA on: %q", g)
	}
	if g := IdentityProxyBy(); g != "dunree/"+brand.Version+" (zoraxy-compatible)" { // legacy-compat
		t.Errorf("proxy-by on: %q", g)
	}
	if g := ForwardedServer("u1"); g != "zoraxy-u1" { // legacy-compat
		t.Errorf("forwarded server on: %q", g)
	}
	wirecompat.SetEmitLegacy(false)
	if g := IdentityUserAgent("3.3.6"); g != "Dunree/"+brand.Version {
		t.Errorf("UA off: %q", g)
	}
	if g := IdentityProxyBy(); g != "dunree/"+brand.Version {
		t.Errorf("proxy-by off: %q", g)
	}
	if g := ForwardedServer("u1"); g != "dunree-u1" {
		t.Errorf("forwarded server off: %q", g)
	}
}
