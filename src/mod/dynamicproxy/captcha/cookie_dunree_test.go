// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package captcha

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A CAPTCHA session cookie set by an earlier build (zoraxy_captcha_session) is honoured until it expires;
// new sessions are set as dunree_captcha_session (plan row 21).
func TestLegacySessionCookieIsHonoured(t *testing.T) {
	if CookieName != "dunree_captcha_session" || LegacyCookieName != "zoraxy_captcha_session" { // legacy-compat
		t.Fatalf("%q / %q", CookieName, LegacyCookieName)
	}
	s := NewSessionStoreWithSecret("secret")
	tok, _ := s.Issue("a.example.com", 3600)
	r := httptest.NewRequest("GET", "http://a.example.com/", nil)
	r.AddCookie(&http.Cookie{Name: LegacyCookieName, Value: tok})
	if ok, why := CheckSessionReason(r, s); !ok {
		t.Fatalf("legacy cookie rejected: %s", why)
	}
}
