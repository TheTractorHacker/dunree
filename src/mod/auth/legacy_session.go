// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package auth

import (
	"net/http"

	"github.com/gorilla/securecookie"
)

/*
	Session cookies issued under an earlier cookie name

	The cookie name is part of what gorilla/securecookie signs, so a session cookie cannot be read under a
	second name. When the admin session cookie is renamed, the names it had before go into
	LegacySessionNames and AdoptLegacySession runs in front of every handler that reads the session
	(see LegacySessionMiddleware). A request that carries only a valid cookie under an old name is then
	served as if it carried the current one, so nobody is logged out by the rename:

	  - a session with a server side expiry ("exp") is signed again under the current name and sent to the
	    browser with the time it has left; the old cookie is removed from the browser.
	  - a session from before "exp" existed is only translated for this one request and never written
	    again, so its 30 day limit keeps counting from the day it was issued.

	Nothing is accepted that the old name would not have accepted: same keys, same expiry rules, same
	account checks (they run afterwards on the translated session, exactly as for a current cookie).
	Logout removes the cookies under the old names too.
*/

// AdoptLegacySession reports whether a cookie under one of LegacySessionNames was taken over for r.
func (a *AuthAgent) AdoptLegacySession(w http.ResponseWriter, r *http.Request) bool {
	if len(a.LegacySessionNames) == 0 {
		return false
	}
	hasCurrent := false
	if c, err := r.Cookie(a.SessionName); err == nil && c.Value != "" {
		hasCurrent = true
	}
	for _, name := range a.LegacySessionNames {
		if name == "" || name == a.SessionName {
			continue
		}
		c, err := r.Cookie(name)
		if err != nil || c.Value == "" {
			continue
		}
		if hasCurrent {
			//both are present (the current one was issued later): the old one is of no use any more
			expireCookie(w, r, name)
			continue
		}
		values := map[interface{}]interface{}{}
		if securecookie.DecodeMulti(name, c.Value, &values, a.SessionStore.Codecs...) != nil {
			continue //forged, damaged or signed with another key: not ours to remove either
		}
		if ok, _ := values["authenticated"].(bool); !ok {
			expireCookie(w, r, name)
			continue
		}
		_, stamped := values["exp"].(int64)
		if stamped && a.sessionExpired(values) {
			expireCookie(w, r, name)
			continue
		}
		if !stamped && len(a.legacyCodecs) > 0 {
			var dst map[interface{}]interface{}
			if securecookie.DecodeMulti(name, c.Value, &dst, a.legacyCodecs...) != nil {
				expireCookie(w, r, name) //older than the 30 days such a session was ever good for
				continue
			}
		}
		enc, err := securecookie.EncodeMulti(a.SessionName, values, a.SessionStore.Codecs...)
		if err != nil {
			continue
		}
		r.AddCookie(&http.Cookie{Name: a.SessionName, Value: enc})
		if stamped {
			left := int(values["exp"].(int64) - a.timeNow().Unix())
			if left < 1 {
				left = 1
			}
			opt := newSessionOptions(r, left)
			http.SetCookie(w, &http.Cookie{Name: a.SessionName, Value: enc, Path: opt.Path, MaxAge: opt.MaxAge,
				HttpOnly: opt.HttpOnly, Secure: opt.Secure, SameSite: opt.SameSite})
			expireCookie(w, r, name)
		}
		return true
	}
	return false
}

// LegacySessionMiddleware runs AdoptLegacySession before next. Without LegacySessionNames it is a pass-through.
func (a *AuthAgent) LegacySessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.AdoptLegacySession(w, r)
		next.ServeHTTP(w, r)
	})
}

// expireLegacySessions removes the cookies under the old names from the browser (logout).
func (a *AuthAgent) expireLegacySessions(w http.ResponseWriter, r *http.Request) {
	for _, name := range a.LegacySessionNames {
		if name == "" || name == a.SessionName {
			continue
		}
		if _, err := r.Cookie(name); err == nil {
			expireCookie(w, r, name)
		}
	}
}

func expireCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
}
