// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/foleyit/dunree/mod/csrfguard"
)

/*
	Origin check of the admin interface (gorilla/csrf v1.7.3, advisory GO-2025-3607)

	A request that changes something must come from a page of the admin interface itself. The library
	compares the Origin (or Referer) header with the address the request arrived for; mod/csrfguard tells
	it per request whether that address is http or https and whether a reverse proxy stands in front.
	Nothing has to be set for an admin interface that is opened directly (plain HTTP or -webui_tls), or
	through a reverse proxy that passes the Host header on or sends X-Forwarded-Host.
*/

var (
	csrfTrustedOrigins = flag.String("csrf_trusted_origins", "", "Comma separated extra addresses (host, host:port or https://host[:port], as shown in the browser) from which the management web interface may be used, for a reverse proxy in front of it that changes the Host header and sends no X-Forwarded-Host. Empty (default): only the address the request arrives for")
	csrfStrict         = flag.Bool("csrf_strict", false, "Management web interface: also require an Origin or Referer header from scripts over HTTPS and ignore X-Forwarded-Host when checking where a request comes from (off by default so that existing scripts and reverse proxy setups keep working)")
)

// adminCSRFPolicy builds the origin policy of the admin interface from the two switches. A list that
// cannot be read stops the start: a silently ignored entry would lock the administrator out later.
func adminCSRFPolicy() *csrfguard.Policy {
	trusted, err := csrfguard.ParseTrustedOrigins(*csrfTrustedOrigins)
	if err != nil {
		log.Fatalf("-csrf_trusted_origins: %v", err)
	}
	if len(trusted) > 0 || *csrfStrict {
		adminCSRFLog("admin interface: requests are also accepted from pages at %v (-csrf_trusted_origins); strict origin check: %v", trusted, *csrfStrict)
	}
	return &csrfguard.Policy{TrustedOrigins: trusted, Strict: *csrfStrict, FlagName: "csrf_trusted_origins", Logf: adminCSRFLog}
}

func adminCSRFLog(format string, a ...any) {
	if SystemWideLogger != nil {
		SystemWideLogger.PrintAndLog("csrf", fmt.Sprintf(format, a...), nil)
		return
	}
	log.Printf(format, a...)
}
