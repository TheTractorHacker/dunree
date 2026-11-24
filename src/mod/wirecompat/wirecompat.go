// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

/*
Package wirecompat holds the names Dunree uses on the wire and the names it
inherited from Zoraxy, and the one switch that decides whether the inherited // legacy-compat
names are still sent.

Dunree is a derivative of Zoraxy. Monitors, dashboards, webhook receivers, // legacy-compat
custom captcha templates and plugins built for Zoraxy know the old names, so: // legacy-compat

  - input: the old name is always accepted (header, URL path)
  - output: the Dunree name is always sent. The old name is sent as well while
    EmitLegacy is on (the setting "Also send legacy X-Zoraxy-* headers", on by
    default)
  - plugin and cluster channel: both names are always sent (SetHeaderAlways,
    HeaderPairs), whatever the switch says. A plugin built with the Zoraxy SDK // legacy-compat
    only reads the old names: without them it rejects every call of the host,
    and a fail-open filter would then let traffic through without a word.

The package has no dependency inside the module so that every other package
can use it.
*/
package wirecompat

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	HeaderPrefix       = "X-Dunree-"
	LegacyHeaderPrefix = "X-Zoraxy-" // legacy-compat

	PathPrefix       = "/.dunree"
	LegacyPathPrefix = "/.zoraxy" // legacy-compat

	MetricPrefix       = "dunree_"
	LegacyMetricPrefix = "zoraxy_" // legacy-compat
)

// legacyOff is inverted so that the zero value means "send the legacy names" (the default)
var legacyOff atomic.Bool

// EmitLegacy reports whether the legacy names are sent next to the Dunree names. Default true.
func EmitLegacy() bool { return !legacyOff.Load() }

// SetEmitLegacy switches the legacy names on output on or off. Input is not affected.
func SetEmitLegacy(on bool) { legacyOff.Store(!on) }

// Header returns the Dunree header name for a suffix: Header("Ref") = "X-Dunree-Ref"
func Header(suffix string) string { return HeaderPrefix + suffix }

// LegacyHeader returns the inherited header name for a suffix: LegacyHeader("Ref") = "X-Zoraxy-Ref"
func LegacyHeader(suffix string) string { return LegacyHeaderPrefix + suffix }

// SetHeader sets X-Dunree-<suffix> and, while EmitLegacy is on, X-Zoraxy-<suffix> to the same value.
// With the switch off a legacy header that is already in h is removed, so the two never disagree.
func SetHeader(h http.Header, suffix string, value string) {
	h.Set(HeaderPrefix+suffix, value)
	if EmitLegacy() {
		h.Set(LegacyHeaderPrefix+suffix, value)
	} else {
		h.Del(LegacyHeaderPrefix + suffix)
	}
}

// SetHeaderAlways sets both names whatever the switch says (plugin and cluster channel).
func SetHeaderAlways(h http.Header, suffix string, value string) {
	h.Set(HeaderPrefix+suffix, value)
	h.Set(LegacyHeaderPrefix+suffix, value)
}

// HeaderPairs returns both names with the value, as name/value pairs (the form
// dpcore.ResponseRewriteRuleSet.UpstreamHeaders takes). Always both names.
func HeaderPairs(suffix string, value string) [][]string {
	return [][]string{{HeaderPrefix + suffix, value}, {LegacyHeaderPrefix + suffix, value}}
}

// GetHeader reads X-Dunree-<suffix> and falls back to X-Zoraxy-<suffix>.
func GetHeader(h http.Header, suffix string) string {
	if v := h.Get(HeaderPrefix + suffix); v != "" {
		return v
	}
	return h.Get(LegacyHeaderPrefix + suffix)
}

// DelHeader removes both names.
func DelHeader(h http.Header, suffix string) {
	h.Del(HeaderPrefix + suffix)
	h.Del(LegacyHeaderPrefix + suffix)
}

// IsReservedHeader reports whether a header name belongs to the host (either prefix, any case).
func IsReservedHeader(name string) bool {
	return hasPrefixFold(name, HeaderPrefix) || hasPrefixFold(name, LegacyHeaderPrefix)
}

func hasPrefixFold(s string, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// LegacyPath returns the inherited form of a public path: "/.dunree/health" gives "/.zoraxy/health".
// A path outside /.dunree/ is returned unchanged.
func LegacyPath(p string) string {
	if strings.HasPrefix(p, PathPrefix+"/") {
		return LegacyPathPrefix + p[len(PathPrefix):]
	}
	return p
}

// IsPath reports whether the request path is the public path canonical ("/.dunree/...") or its
// inherited form ("/.zoraxy/..."). The match is exact, as it always was. A hit on the inherited
// form is counted (LegacyPathHits) and reported to the logger at most once a day per path.
func IsPath(requestPath string, canonical string) bool {
	if requestPath == canonical {
		return true
	}
	if !strings.HasPrefix(requestPath, LegacyPathPrefix+"/") || requestPath != LegacyPath(canonical) {
		return false
	}
	noteLegacy(requestPath)
	return true
}

/* Use of the inherited paths: counted, and logged once a day per path */

var legacyUse struct {
	mu     sync.Mutex
	hits   map[string]uint64
	logged map[string]time.Time
	logger func(path string, hits uint64)
}

const legacyLogInterval = 24 * time.Hour

// SetLegacyPathLogger sets the function that is told about the use of an inherited path, at most
// once a day per path. nil switches the report off (the count goes on).
func SetLegacyPathLogger(f func(path string, hits uint64)) {
	legacyUse.mu.Lock()
	legacyUse.logger = f
	legacyUse.mu.Unlock()
}

// LegacyPathHits returns how often each inherited path was requested since the process started.
func LegacyPathHits() map[string]uint64 {
	legacyUse.mu.Lock()
	defer legacyUse.mu.Unlock()
	out := make(map[string]uint64, len(legacyUse.hits))
	for k, v := range legacyUse.hits {
		out[k] = v
	}
	return out
}

// noteLegacy is only called with a path that equals a known constant, so the maps cannot grow
// with what clients send.
func noteLegacy(path string) {
	legacyUse.mu.Lock()
	if legacyUse.hits == nil {
		legacyUse.hits = map[string]uint64{}
		legacyUse.logged = map[string]time.Time{}
	}
	legacyUse.hits[path]++
	n := legacyUse.hits[path]
	f := legacyUse.logger
	due := f != nil && time.Since(legacyUse.logged[path]) >= legacyLogInterval
	if due {
		legacyUse.logged[path] = time.Now()
	}
	legacyUse.mu.Unlock()
	if due {
		f(path, n)
	}
}
