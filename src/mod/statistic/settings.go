package statistic

import (
	"errors"
	"log"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TheTractorHacker/dunree/mod/blocklog"
)

/*
	Statistic collection filters (all opt-in, the zero value records everything
	exactly like before):

	  - ExcludeNetworks: requests whose client IP is inside one of these CIDRs /
	    addresses are not recorded at all (e.g. the admin's own IP)
	  - ExcludeBlocked: requests that were rejected by Dunree itself (access
	    list, rate limit, WAF, CAPTCHA, ...) are not recorded
	  - QueryMode: how the URL query string is stored in "Top requested paths"
*/

// Query string handling modes for the recorded request URL
const (
	QueryModeStrip = "strip" // default: path only, no query string
	QueryModeMask  = "mask"  // keep parameter names, replace values with "*"
	QueryModeFull  = "full"  // keep the whole query string
)

// MaxExcludeEntries bounds the exclusion list
const MaxExcludeEntries = 256

// Settings is the user visible configuration of the collector filters
type Settings struct {
	ExcludeNetworks []string // CIDRs or single IPs
	ExcludeBlocked  bool
	QueryMode       string
	// RetentionDays deletes the daily records older than this many days (0 = keep everything, the default).
	// Valid values: 0 or MinRetentionDays..MaxRetentionDays. Today and yesterday are never deleted.
	RetentionDays int
}

// Bounds of the retention setting
const (
	MinRetentionDays = 7
	MaxRetentionDays = 3650
)

type compiledSettings struct {
	Settings
	prefixes []netip.Prefix
}

// DefaultSettings returns the upstream compatible behaviour
func DefaultSettings() Settings {
	return Settings{QueryMode: QueryModeStrip}
}

// NormalizeNetwork validates one exclusion entry and returns it in canonical
// CIDR form (a bare IP becomes /32 or /128).
func NormalizeNetwork(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty entry")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", errors.New("invalid CIDR: " + s)
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", errors.New("invalid IP address: " + s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

func compileSettings(s Settings) (*compiledSettings, error) {
	if len(s.ExcludeNetworks) > MaxExcludeEntries {
		return nil, errors.New("too many exclusion entries")
	}
	switch s.QueryMode {
	case "":
		s.QueryMode = QueryModeStrip
	case QueryModeStrip, QueryModeMask, QueryModeFull:
	default:
		return nil, errors.New("invalid query mode")
	}
	if s.RetentionDays != 0 && (s.RetentionDays < MinRetentionDays || s.RetentionDays > MaxRetentionDays) {
		return nil, errors.New("retention must be 0 (keep everything) or between 7 and 3650 days")
	}
	cs := &compiledSettings{}
	seen := map[string]bool{}
	for _, n := range s.ExcludeNetworks {
		norm, err := NormalizeNetwork(n)
		if err != nil {
			return nil, err
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		cs.Settings.ExcludeNetworks = append(cs.Settings.ExcludeNetworks, norm)
		cs.prefixes = append(cs.prefixes, netip.MustParsePrefix(norm))
	}
	cs.ExcludeBlocked = s.ExcludeBlocked
	cs.QueryMode = s.QueryMode
	cs.RetentionDays = s.RetentionDays
	return cs, nil
}

// settingsHolder is embedded in Collector
type settingsHolder struct {
	v atomic.Pointer[compiledSettings]
}

// SetSettings validates and applies new filter settings
func (c *Collector) SetSettings(s Settings) error {
	cs, err := compileSettings(s)
	if err != nil {
		return err
	}
	c.settings.v.Store(cs)
	c.PruneOldDays()
	return nil
}

// RetentionDays returns the configured retention (0 = keep everything)
func (c *Collector) RetentionDays() int {
	if cs := c.settings.v.Load(); cs != nil {
		return cs.RetentionDays
	}
	return 0
}

// pruneLookback bounds how far back PruneOldDays looks for records (ten years)
const pruneLookback = 3660

// PruneOldDays deletes the daily records older than the retention setting and returns how many were deleted.
// It probes the day keys one by one (a few thousand cheap lookups) instead of reading the table, whose values
// can be hundreds of MB. Nothing happens while retention is 0. The file does not shrink by itself: freed pages are
// reused, and "dunree -compact-db" returns them to the disk.
func (c *Collector) PruneOldDays() int {
	days := c.RetentionDays()
	if days == 0 || c.Option.Database == nil {
		return 0
	}
	deleted := 0
	cutoff := time.Now().AddDate(0, 0, -days) // records of this day and later are kept
	for i := 1; i <= pruneLookback; i++ {
		key := summaryKeyOf(cutoff.AddDate(0, 0, -i))
		if c.Option.Database.KeyExists("stats", key) {
			if err := c.Option.Database.Delete("stats", key); err == nil {
				deleted++
			}
		}
	}
	if deleted > 0 {
		log.Printf("[Statistic] Retention of %d days: deleted %d old daily records\n", days, deleted)
	}
	return deleted
}

// GetSettings returns the active filter settings
func (c *Collector) GetSettings() Settings {
	cs := c.settings.v.Load()
	if cs == nil {
		return DefaultSettings()
	}
	out := cs.Settings
	out.ExcludeNetworks = append([]string{}, cs.ExcludeNetworks...)
	return out
}

// QueryMode returns the active query handling mode
func (c *Collector) QueryMode() string {
	if cs := c.settings.v.Load(); cs != nil && cs.QueryMode != "" {
		return cs.QueryMode
	}
	return QueryModeStrip
}

// ExcludesBlocked reports whether requests rejected by Dunree itself are left out of the statistics
func (c *Collector) ExcludesBlocked() bool {
	cs := c.settings.v.Load()
	return cs != nil && cs.ExcludeBlocked
}

// ExcludesIP reports whether ip (possibly a "a,b" forwarded list, an
// IPv4-mapped IPv6 address or "[v6]") is inside the exclusion list
func (c *Collector) ExcludesIP(ip string) bool {
	cs := c.settings.v.Load()
	if cs == nil || len(cs.prefixes) == 0 {
		return false
	}
	return prefixesContain(cs.prefixes, ip)
}

func prefixesContain(prefixes []netip.Prefix, ip string) bool {
	if i := strings.Index(ip, ","); i >= 0 {
		ip = ip[:i]
	}
	ip = strings.Trim(strings.TrimSpace(ip), "[]")
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// shouldRecord applies the exclusion filters to a request
func (c *Collector) shouldRecord(ri *RequestInfo) bool {
	cs := c.settings.v.Load()
	if cs == nil {
		return true
	}
	if cs.ExcludeBlocked && ri.Blocked {
		return false
	}
	if len(cs.prefixes) > 0 && prefixesContain(cs.prefixes, ri.IpAddr) {
		return false
	}
	return true
}

// IsBlockedForwardType reports whether a request class (the "forwardType"
// given to the router log) means Dunree itself rejected the request:
// access list, rate limit, WAF, CAPTCHA, exploit detection, path rules,
// plugin or peer / client certificate denial. The classification lives in
// mod/blocklog so the blocked-request log and these counters always agree.
func IsBlockedForwardType(ft string) bool {
	return blocklog.IsBlocked(ft)
}

// BuildStatURL assembles the string recorded as "request URL": host + escaped
// path, plus the query string depending on mode.
func BuildStatURL(host, escapedPath, rawQuery, mode string) string {
	base := host + escapedPath
	if rawQuery == "" || mode == "" || mode == QueryModeStrip {
		return base
	}
	if mode == QueryModeFull {
		return base + "?" + rawQuery
	}
	// mask: keep the parameter names only
	parts := strings.Split(rawQuery, "&")
	for i, p := range parts {
		if eq := strings.Index(p, "="); eq >= 0 {
			parts[i] = p[:eq+1] + "*"
		}
	}
	return base + "?" + strings.Join(parts, "&")
}
