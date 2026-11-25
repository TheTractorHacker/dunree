package main

import "github.com/TheTractorHacker/dunree/mod/baseline"

// pluginStoreExistingInstall says whether this installation existed before this start, by the probe
// main() took before anything was created (the one the enterprise baseline uses). Conservative: when
// in doubt it is an existing installation, which keeps the add-on store source it had
// (mod/plugins/store_sources.go, migrateStoreSources). A new installation starts without a source.
func pluginStoreExistingInstall() bool {
	fresh, _ := baseline.IsFresh(baselineProbe)
	return !fresh
}
