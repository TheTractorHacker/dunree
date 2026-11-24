package auth

import (
	"regexp"
	"testing"
)

// Review of the plugin API key generation (issue #149, docs/plugins/contract.md
// section 6): a key is 64 lower-case hex characters made from 32 bytes of
// crypto/rand. This pins the format (so a later change is a decision, not an
// accident) and checks the obvious failures: repeats, a constant part, the plugin ID.
func TestPluginAPIKeyFormatAndUniqueness(t *testing.T) {
	m := NewAPIKeyManager()
	format := regexp.MustCompile(`^[0-9a-f]{64}$`)
	const n = 2000
	seen := make(map[string]bool, n)
	var counts [64][16]int
	for i := 0; i < n; i++ {
		k, err := m.GenerateAPIKey("plugin.same", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !format.MatchString(k.APIKey) {
			t.Fatalf("key %q is not 64 lower-case hex characters", k.APIKey)
		}
		if seen[k.APIKey] {
			t.Fatal("the same key was generated twice")
		}
		seen[k.APIKey] = true
		for pos, c := range k.APIKey {
			v := int(c - '0')
			if c >= 'a' {
				v = int(c-'a') + 10
			}
			counts[pos][v]++
		}
	}
	//No position is constant or nearly so (expected 125 per value; 4 standard deviations is about 43)
	for pos := range counts {
		for v, c := range counts[pos] {
			if c < 60 || c > 190 {
				t.Fatalf("position %d has value %x in %d of %d keys: not random", pos, v, c, n)
			}
		}
	}
	//Every key generated stays valid until it is revoked (a new key does not replace older ones)
	for k := range seen {
		if _, err := m.ValidateAPIKey(k); err != nil {
			t.Fatal("an earlier key stopped working")
		}
	}
	for _, bad := range []string{"", "plugin.same", "0000000000000000000000000000000000000000000000000000000000000000"} {
		if _, err := m.ValidateAPIKey(bad); err == nil {
			t.Fatalf("%q was accepted as a key", bad)
		}
	}
}
