// Package upstreamguard holds one test: it scans the Go and web sources that
// are shipped in the Dunree binary for the hosts of the project Dunree is
// derived from (Zoraxy by tobychui and imuslab) and fails when one of them
// appears somewhere Dunree could contact it by default.
//
// Dunree credits Zoraxy by name, and those credits stay. What must not happen // legacy-compat
// is that the product calls a service of the upstream project on its own: the
// add-on store, an update check, a documentation fetch. See guard_test.go for
// the rules and docs/plugins/addon-store.md for the store.
package upstreamguard
