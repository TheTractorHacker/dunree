// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package legacycompat

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

// csrfTokenLength and csrfDefaultMaxAge mirror gorilla/csrf (tokenLength, defaultAge).
const (
	csrfTokenLength   = 32
	csrfDefaultMaxAge = 3600 * 12
)

// CSRFCookie describes the CSRF cookie of the admin interface as gorilla/csrf writes it, plus the name an
// older build used. The cookie name is part of the signature, so a cookie cannot simply be read under a
// second name: Adopt verifies the legacy cookie and signs the same token again under the new name.
type CSRFCookie struct {
	Key        []byte // the key given to csrf.Protect
	Name       string // current cookie name
	LegacyName string // name written by the older build ("" = nothing to adopt)
	MaxAge     int    // seconds, 0 = the gorilla/csrf default (12 hours)
	Secure     bool
	Path       string
	SameSite   http.SameSite
}

func (c CSRFCookie) codec() *securecookie.SecureCookie {
	sc := securecookie.New(c.Key, nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	sc.MaxAge(c.maxAge())
	return sc
}

func (c CSRFCookie) maxAge() int {
	if c.MaxAge == 0 {
		return csrfDefaultMaxAge
	}
	return c.MaxAge
}

// Adopt makes a request that only carries a valid legacy CSRF cookie look as if it carried the current
// one: the token is added to the request under the current name and the current cookie is set on the
// response. A page that was open during the upgrade therefore keeps working, because its token still
// matches. The legacy cookie is neither changed nor written again; it runs out by itself.
// It reports whether a legacy cookie was adopted. A request that already has the current cookie, or
// whose legacy cookie is forged or too old, is left alone.
func (c CSRFCookie) Adopt(w http.ResponseWriter, r *http.Request) bool {
	if c.LegacyName == "" || c.LegacyName == c.Name {
		return false
	}
	if cur, err := r.Cookie(c.Name); err == nil && cur.Value != "" {
		return false
	}
	old, err := r.Cookie(c.LegacyName)
	if err != nil || old.Value == "" {
		return false
	}
	sc := c.codec()
	token := make([]byte, csrfTokenLength)
	if err := sc.Decode(c.LegacyName, old.Value, &token); err != nil || len(token) != csrfTokenLength {
		return false
	}
	enc, err := sc.Encode(c.Name, token)
	if err != nil {
		return false
	}
	r.AddCookie(&http.Cookie{Name: c.Name, Value: enc})
	ck := &http.Cookie{Name: c.Name, Value: enc, MaxAge: c.maxAge(), HttpOnly: true, Secure: c.Secure,
		SameSite: c.SameSite, Path: c.Path}
	if ck.MaxAge > 0 {
		ck.Expires = time.Now().Add(time.Duration(ck.MaxAge) * time.Second)
	}
	http.SetCookie(w, ck)
	return true
}

// Wrap returns next with Adopt run first. Put it in front of csrf.Protect.
func (c CSRFCookie) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Adopt(w, r)
		next.ServeHTTP(w, r)
	})
}
