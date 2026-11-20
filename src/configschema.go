package main

import (
	"log"
	"time"

	"imuslab.com/zoraxy/mod/confpack"
)

// runConfigSchemaMigration stamps the config folder with the schema version of this build and runs
// the registered migrations (mod/confpack/migrate.go) before any module reads the files. It is
// idempotent: at the current version it does nothing. A folder stamped by a newer build is left alone.
func runConfigSchemaMigration() {
	res, err := confpack.Migrate(CONF_FOLDER, confpack.Migrations, SYSTEM_NAME+" "+SYSTEM_VERSION, time.Now())
	switch {
	case err != nil:
		log.Printf("WARNING: config schema migration: %v", err)
	case res.Newer:
		log.Printf("WARNING: %s was written by a newer Zoraxy (config schema %d, this build writes %d). It was not changed.", CONF_FOLDER, res.From, res.To)
	case len(res.Ran) > 0:
		log.Printf("Config migrated from schema %d to %d (%v). A copy of the previous config is in %s", res.From, res.To, res.Ran, res.Backup)
	}
}
