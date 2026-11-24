// Package legacycompat keeps an install that was created by Zoraxy working after it is upgraded to Dunree: // legacy-compat
// environment variables under the old prefix, cookies under the old names and the one-time backup of the
// configuration folder at the first Dunree start.
//
// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.
package legacycompat

import (
	"log"
	"os"
	"strings"
	"sync"
)

const (
	// EnvPrefix is the prefix of every environment variable Dunree reads.
	EnvPrefix = "DUNREE_"
	// LegacyEnvPrefix is still read when the variable with EnvPrefix is not set.
	LegacyEnvPrefix = "ZORAXY_" // legacy-compat
)

// Logf receives the deprecation lines. Tests replace it.
var Logf = log.Printf

var (
	envWarnMu sync.Mutex
	envWarned = map[string]bool{}
)

// LookupEnv returns the value of the variable DUNREE_<name>. When that is unset or blank it returns the
// value of the legacy variable with the old prefix and logs one deprecation line per variable and
// process. source is the full name of the variable the value came from ("" when neither is set).
// Surrounding white space is removed.
func LookupEnv(name string) (value string, source string) {
	if v := strings.TrimSpace(os.Getenv(EnvPrefix + name)); v != "" {
		return v, EnvPrefix + name
	}
	if v := strings.TrimSpace(os.Getenv(LegacyEnvPrefix + name)); v != "" {
		warnLegacyEnv(name)
		return v, LegacyEnvPrefix + name
	}
	return "", ""
}

// Getenv is LookupEnv without the source.
func Getenv(name string) string {
	v, _ := LookupEnv(name)
	return v
}

func warnLegacyEnv(name string) {
	envWarnMu.Lock()
	first := !envWarned[name]
	envWarned[name] = true
	envWarnMu.Unlock()
	if first {
		Logf("DEPRECATED: environment variable %s%s is still read because %s%s is not set. Rename it: the old name stops working in Dunree v2.",
			LegacyEnvPrefix, name, EnvPrefix, name)
	}
}

// resetEnvWarnings is for tests.
func resetEnvWarnings() {
	envWarnMu.Lock()
	envWarned = map[string]bool{}
	envWarnMu.Unlock()
}
