// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package dynamicproxy

import "testing"

// The WAF and rule challenge cookies are set under the Dunree names; the names an earlier build set are
// still read (wirecompat.Cookie, tested in mod/wirecompat) until those cookies expire.
func TestChallengeCookieNames(t *testing.T) {
	if wafChallengeCookie != "dunree_waf_challenge" || legacyWafChallengeCookie != "zoraxy_waf_challenge" || // legacy-compat
		ruleChallengeCookie != "dunree_rule_challenge" || legacyRuleChallengeCookie != "zoraxy_rule_challenge" { // legacy-compat
		t.Fatal("challenge cookie names changed")
	}
}
