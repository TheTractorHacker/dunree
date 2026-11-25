// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package main

import (
	"github.com/TheTractorHacker/dunree/mod/brand"
	"github.com/TheTractorHacker/dunree/mod/update"
)

/*
	Two version numbers (def.go):

	PRODUCT_VERSION  the Dunree version. Everything a person or a client reads as "the version"
	                 uses it: -version, the start-up log, the About and Update pages, the API
	                 (/api/info/x, /api/v1/health), the metrics label, the fleet and cluster
	                 status, mDNS, and the comparison with Dunree releases in the updater.
	COMPAT_VERSION   the version of the code base Dunree is derived from. It feeds only what was
	                 written for that number line: update.RunConfigUpdateInDir (conf/version),
	                 the version field of configuration backups, the version plugins built with
	                 the earlier SDK are told, and the second token of the proxy's default
	                 User-Agent while the legacy names are on.
*/

// versionLine is what -version prints (one line). The in-app updater runs a downloaded program
// with -version and looks for the version of the release as a whole word in it, and
// tools/build_release_test.sh does the same, so the form "<name> - Version <version>" stays.
func versionLine() string {
	return SYSTEM_NAME + " - Version " + PRODUCT_VERSION + " (based on " + brand.BasedOnName + " " + COMPAT_VERSION + ")"
}

// startupLine is the first line of the log of a normal start.
func startupLine() string {
	return SYSTEM_NAME + " " + PRODUCT_VERSION + " starting (" + brand.PublishedBy() + "; based on " + brand.BasedOnName + " " + COMPAT_VERSION + " by " + brand.BasedOnAuthors + ", " + brand.License + ")"
}

// configVersionInt is the number update.RunConfigUpdateInDir compares with the conf/version file
// (336 for 3.3.6). It comes from COMPAT_VERSION and must never follow PRODUCT_VERSION: 1.0.0
// would read as 100, below every version file an existing install has.
func configVersionInt() int {
	return update.GetVersionIntFromVersionNumber(COMPAT_VERSION)
}
