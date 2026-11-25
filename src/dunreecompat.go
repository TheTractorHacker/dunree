// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package main

import (
	"log"
	"net/http"

	"github.com/TheTractorHacker/dunree/mod/baseline"
	"github.com/TheTractorHacker/dunree/mod/legacycompat"
	"github.com/gorilla/csrf"
)

/*
	Upgrade of an existing install to Dunree (see docs/migrating-from-zoraxy.md)

	  - cookie names of the admin interface: the Dunree names are written, the names an existing install
	    has in its browsers are still accepted (mod/auth/legacy_session.go, mod/legacycompat/csrfcookie.go)
	  - first Dunree start on an existing configuration folder: one copy aside, one marker file, one log
	    notice (mod/legacycompat/firststart.go)
*/

const (
	// ADMIN_SESSION_COOKIE is the session cookie of the admin interface. It is deliberately not
	// SYSTEM_NAME: the product name may change, the cookie name must not change with it.
	ADMIN_SESSION_COOKIE = "dunree_session"
	// LEGACY_ADMIN_SESSION_COOKIE is the name installs upgraded from the base program have in their browsers.
	LEGACY_ADMIN_SESSION_COOKIE = "Zoraxy" // legacy-compat
	// LEGACY_CSRF_COOKIENAME is the CSRF cookie name of those installs (the current one is CSRF_COOKIENAME).
	LEGACY_CSRF_COOKIENAME = "zoraxy_csrf" // legacy-compat
)

// adminCSRFCookie describes the CSRF cookie exactly as newAdminCSRF configures gorilla/csrf.
func adminCSRFCookie(key []byte, secure bool) legacycompat.CSRFCookie {
	return legacycompat.CSRFCookie{Key: key, Name: CSRF_COOKIENAME, LegacyName: LEGACY_CSRF_COOKIENAME,
		Secure: secure, Path: "/", SameSite: http.SameSiteLaxMode}
}

// newAdminCSRF is the CSRF middleware of the admin interface. A browser that still holds the CSRF cookie
// under the old name keeps its token (an admin page that was open during the upgrade keeps working).
func newAdminCSRF(key []byte, secure bool) func(http.Handler) http.Handler {
	policy := adminCSRFPolicy() //admincsrf.go: where a request may come from (plain HTTP, HTTPS, behind a reverse proxy)
	protect := csrf.Protect(
		key,
		append([]csrf.Option{
			csrf.CookieName(CSRF_COOKIENAME),
			csrf.Secure(secure),
			csrf.Path("/"),
			csrf.SameSite(csrf.SameSiteLaxMode),
		}, policy.Options()...)...,
	)
	compat := adminCSRFCookie(key, secure)
	return func(next http.Handler) http.Handler { return compat.Wrap(policy.Wrap(protect, next)) }
}

// runDunreeFirstStart runs once per configuration folder, before anything else writes to it: an install
// that existed before gets a copy of its configuration folder and database next to the originals and a
// notice in the log. Nothing in the folder is converted. A failure is logged and the start goes on.
func runDunreeFirstStart(confDir string, dbPath string, probe baseline.Probe) *legacycompat.FirstStartResult {
	fresh, _ := baseline.IsFresh(probe)
	res, err := legacycompat.FirstStart(legacycompat.FirstStartOptions{ConfDir: confDir, DBPath: dbPath,
		Fresh: fresh, Version: PRODUCT_VERSION, BasedOn: COMPAT_VERSION})
	if err != nil {
		log.Printf("WARNING: first Dunree start: %v. Nothing in %s was changed; the copy will be tried again at the next start.", err, confDir)
		return res
	}
	switch res.Action {
	case legacycompat.ActionMigrated:
		log.Printf("NOTICE: first Dunree start on an existing configuration. Everything is used as it is: rules, certificates, accounts, API tokens and plugins are unchanged.")
		if res.Marker.ConfBackup != "" {
			log.Printf("NOTICE: a copy of %s as it was is in %s (%d files). Delete it once you are sure you will not go back.", confDir, res.Marker.ConfBackup, res.Files)
		}
		if res.Marker.DBBackup != "" {
			log.Printf("NOTICE: a copy of the database is in %s", res.Marker.DBBackup)
		}
		for _, n := range res.Marker.Notes {
			log.Printf("NOTICE: %s", n)
		}
		log.Printf("NOTICE: see docs/migrating-from-zoraxy.md for cookies, environment variables, the systemd unit and Docker.") // legacy-compat
	case legacycompat.ActionAdopted:
		log.Printf("NOTICE: %s has no Dunree marker but the copy from the first Dunree start exists (%s); no second copy was taken.", confDir, res.Marker.ConfBackup)
	}
	return res
}
