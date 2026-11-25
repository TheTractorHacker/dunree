package updater

import "testing"

// Upstream #969: pre-releases must be marked as early access in the updater, also when the
// pre-release flag of the release was not ticked.
func TestMarkEarlyAccess(t *testing.T) {
	cases := []struct {
		tag  string
		pre  bool
		want bool
	}{
		{"v1.0.0-rc.1", false, true}, // rc tag without the GitHub pre-release flag
		{"v1.0.0-beta.2", false, true},
		{"v1.0.0-beta.2", true, true},
		{"v1.0.0", true, true}, // GitHub flag on a final tag
		{"v1.0.0", false, false},
		{"v1.2.3", false, false},
	}
	for _, c := range cases {
		r := Release{Tag: c.tag, Prerelease: c.pre}
		r.MarkEarlyAccess()
		if r.EarlyAccess != c.want {
			t.Errorf("%s (prerelease=%v): EarlyAccess=%v, want %v", c.tag, c.pre, r.EarlyAccess, c.want)
		}
	}
}
