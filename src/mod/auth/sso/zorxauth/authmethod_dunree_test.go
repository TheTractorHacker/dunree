// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package zorxauth

import (
	"testing"

	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

func TestAuthMethodFollowsTheLegacySwitch(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	if g := AuthMethodValue(); g != "zoraxy_sso" { // legacy-compat: default, upstreams compare exactly
		t.Errorf("on: %q", g)
	}
	wirecompat.SetEmitLegacy(false)
	if g := AuthMethodValue(); g != "dunree_sso" {
		t.Errorf("off: %q", g)
	}
}
