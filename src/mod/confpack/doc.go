// Package confpack builds, verifies and applies configuration archives (the zip files behind
// Utilities > Config Tools), and owns the config schema version and migration registry.
//
// Archive layout (unchanged from older builds): every file of the config folder is stored as
// "conf/<relative path>", the optional system database as "sys.db". New in schema 1: a
// "manifest.json" at the root with the schema version, Zoraxy version, mode (full or shareable),
// creation time and the size and SHA-256 of every other entry.
//
// Two modes:
//
//	full       the historic backup. Contains everything the old export did (TLS private keys, cluster
//	           secret, Fleet keys, notify secrets, basic auth hashes ...), so treat it as a secret.
//	shareable  an allow-listed subset of non secret configuration, with credential-looking JSON fields
//	           replaced by the marker "[REDACTED]". A shareable archive never replaces the secrets a
//	           running install already has (see MergeRedacted and Plan.Kept).
//
// Nothing here touches the running process: callers pass folders and hooks.
package confpack
