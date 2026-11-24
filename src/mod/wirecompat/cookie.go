// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package wirecompat

import "net/http"

// Cookie reads the cookie name and falls back to legacyName: a cookie set by an earlier build is honoured
// until it expires, and is not set again under the old name (plan row 21).
func Cookie(r *http.Request, name string, legacyName string) (*http.Cookie, error) {
	c, err := r.Cookie(name)
	if err == nil || legacyName == "" {
		return c, err
	}
	return r.Cookie(legacyName)
}
