// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package statistic

import "testing"

// Requests of other Dunree instances (and of older Zoraxy ones) count as programs, not browsers. // legacy-compat
func TestProductUserAgentsAreNotBrowsers(t *testing.T) {
	for _, ua := range []string{"dunree-cluster/1.0.0 (zoraxy-cluster/1.0.0)", "dunree-updater", "zoraxy-updater"} { // legacy-compat
		if !IsNonBrowserUserAgent(ua) {
			t.Errorf("%q taken for a browser", ua)
		}
	}
}
