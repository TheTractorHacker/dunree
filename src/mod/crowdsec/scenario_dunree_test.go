// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package crowdsec

import (
	"strings"
	"testing"
)

// New manual bans are recorded as dunree/manual-ban. Bans made before the rename keep their scenario and
// are still found by the "manual" filter (TestAdminReadsAndRelogin lists one) and lifted by address.
func TestManualScenarioNames(t *testing.T) {
	if ManualScenario != "dunree/manual-ban" || LegacyManualScenario != "zoraxy/manual-ban" { // legacy-compat
		t.Fatalf("%q / %q", ManualScenario, LegacyManualScenario)
	}
	for _, s := range []string{ManualScenario, LegacyManualScenario} {
		if !strings.Contains(strings.ToLower(s), "manual") {
			t.Errorf("%q is not found by the manual filter", s)
		}
	}
	if !strings.HasPrefix(UserAgent(), "dunree-crowdsec-bouncer/") {
		t.Errorf("user agent %q", UserAgent())
	}
}
