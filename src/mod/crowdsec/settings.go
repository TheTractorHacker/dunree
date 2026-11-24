package crowdsec

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls"
)

const (
	// DBTable and DBKey: where Settings live (sys.db). The API key is NOT here, see vault.go.
	DBTable = "settings"
	DBKey   = "crowdsec"

	ModeLog     = "log"     // default: match and count, never block
	ModeEnforce = "enforce" // block

	BanPage = "page" // 403 page (default)
	BanDrop = "drop" // close the connection without an answer

	CaptchaLog       = "log"       // default: captcha decisions are only logged
	CaptchaChallenge = "challenge" // serve the site's CAPTCHA challenge (when the site has one)

	DefaultPoll       = 10 // seconds, a conservative default (the LAPI is a local service; lower values only add load)
	MinPoll           = 5
	MaxPoll           = 3600
	DefaultMaxEntries = 100000
	HardMaxEntries    = 500000 // ceiling of the cache size setting
	DefaultMaxTTL     = 7 * 24 * 3600
	HardMaxTTL        = 30 * 24 * 3600
	DefaultGrace      = 300
	MinGrace          = 10
	MaxGrace          = 24 * 3600
	maxExempt         = 256

	// Policy values of Settings.OriginPolicy. A missing key (or "follow") means: act as the mode says.
	PolicyLog    = "log"    // decisions of this origin are never enforced, only counted and listed as "would block"
	PolicyIgnore = "ignore" // decisions of this origin are not acted on and not listed (counted as ignored by policy)

	// Origin classes (keys of Settings.OriginPolicy). The LAPI sends the origin as text; see OriginClass.
	OriginCrowdSec = "crowdsec" // a scenario of your own CrowdSec fired
	OriginCscli    = "cscli"    // added by hand (cscli decisions add, the Manage panel)
	OriginCAPI     = "capi"     // the community blocklist
	OriginLists    = "lists"    // subscribed third party blocklists ("lists:<name>")
	OriginOther    = "other"    // anything else (console, a custom origin)

	// Values of Settings.SiteOverrides
	SiteExempt  = "exempt"  // the site never acts on CrowdSec decisions (matches are listed as skipped)
	SiteLog     = "log"     // log only on this site, whatever the mode
	SiteEnforce = "enforce" // enforce on this site, even when the mode is log only

	CaptchaFallbackLog = "log" // default: a captcha decision on a site without CAPTCHA is only logged
	CaptchaFallbackBan = "ban" // ... is treated as a ban

	maxScenarioLog   = 64
	maxAllowlist     = 256
	maxSiteOverrides = 256
)

// OriginClasses lists the keys Settings.OriginPolicy accepts, in display order
var OriginClasses = []string{OriginCrowdSec, OriginCscli, OriginCAPI, OriginLists, OriginOther}

// OriginClass maps the origin text of a decision to its class. The values are the documented ones (crowdsec, cscli,
// cscli-import, CAPI, lists:<name>); anything else is "other".
func OriginClass(origin string) string {
	o := strings.ToLower(strings.TrimSpace(origin))
	switch {
	case o == "crowdsec":
		return OriginCrowdSec
	case o == "cscli" || o == "cscli-import":
		return OriginCscli
	case o == "capi":
		return OriginCAPI
	case strings.HasPrefix(o, "lists"):
		return OriginLists
	}
	return OriginOther
}

// Settings is the persisted configuration. The zero value is "off".
type Settings struct {
	Enabled bool   `json:"enabled"`
	LAPIURL string `json:"lapiUrl"` // base URL of the Local API, e.g. http://127.0.0.1:8080
	Mode    string `json:"mode"`    // "" is read as log

	// Trust of an https LAPI. Skip-verify is deliberately not offered.
	CABundlePEM string   `json:"caBundlePem"`
	PinsSHA256  []string `json:"pinsSha256"`

	PollSeconds   int `json:"pollSeconds"`   // 0 = 10
	MaxEntries    int `json:"maxEntries"`    // 0 = 100000, hard ceiling 500000
	MaxTTLSeconds int `json:"maxTtlSeconds"` // 0 = 7 days; a decision never lives longer than this, whatever its duration says
	GraceSeconds  int `json:"graceSeconds"`  // 0 = 300: LAPI unreachable for longer than this counts as down

	FailClosed bool `json:"failClosed"` // LAPI down beyond the grace period: refuse everyone (enforce mode only). Needs confirmation.

	BanResponse   string   `json:"banResponse"`   // "" = page
	CaptchaAction string   `json:"captchaAction"` // "" = log
	ExemptSites   []string `json:"exemptSites"`   // proxy rules (host names) that never consult CrowdSec (older form of SiteOverrides "exempt", still honoured)

	// Policy (all optional; empty = the behaviour before these existed). They can only lower what the mode does,
	// except a site override "enforce", which the administrator sets per site.
	OriginPolicy    map[string]string `json:"originPolicy"`    // origin class -> log | ignore
	ScenarioLogOnly []string          `json:"scenarioLogOnly"` // a decision whose scenario contains one of these (case-insensitive) is never enforced
	Allowlist       []string          `json:"allowlist"`       // addresses and ranges Dunree never acts on, whatever CrowdSec says
	SiteOverrides   map[string]string `json:"siteOverrides"`   // proxy rule host name -> exempt | log | enforce
	CaptchaFallback string            `json:"captchaFallback"` // "" = log: captcha decision on a site without CAPTCHA (captchaAction=challenge)
}

// SiteMode returns the override of a proxy rule (SiteOverrides first, then the older ExemptSites), "" when there is none
func (s Settings) SiteMode(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if v, ok := s.SiteOverrides[host]; ok {
		return v
	}
	for _, h := range s.ExemptSites {
		if h == host {
			return SiteExempt
		}
	}
	return ""
}

// AllowPrefixes parses the (already normalised) allowlist
func (s Settings) AllowPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s.Allowlist))
	for _, a := range s.Allowlist {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func parseAllow(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return p, fmt.Errorf("invalid allowlist range %q", raw)
		}
		a := p.Addr().WithZone("")
		bits := p.Bits()
		if a.Is4In6() {
			if bits < 96 {
				return p, fmt.Errorf("invalid allowlist range %q", raw)
			}
			a, bits = a.Unmap(), bits-96
		}
		if bits == 0 {
			return p, fmt.Errorf("the allowlist range %q would cover every address", raw)
		}
		return netip.PrefixFrom(a, bits).Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid allowlist address %q", raw)
	}
	a = a.WithZone("").Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func validHostKey(h string) bool {
	return h != "" && len(h) <= 253 && !strings.ContainsAny(h, " \t\r\n\x00")
}

// normalizePolicy validates the policy fields (part of Normalize)
func (s *Settings) normalizePolicy() error {
	pol := map[string]string{}
	for k, v := range s.OriginPolicy {
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.ToLower(strings.TrimSpace(v))
		known := false
		for _, c := range OriginClasses {
			known = known || c == k
		}
		if !known {
			return fmt.Errorf("unknown decision origin %q (use crowdsec, cscli, capi, lists or other)", k)
		}
		switch v {
		case "", "follow":
		case PolicyLog, PolicyIgnore:
			pol[k] = v
		default:
			return fmt.Errorf("unknown policy %q for origin %s (use follow, log or ignore)", v, k)
		}
	}
	s.OriginPolicy = pol
	if len(s.ScenarioLogOnly) > maxScenarioLog {
		return fmt.Errorf("at most %d log-only scenarios", maxScenarioLog)
	}
	seen := map[string]bool{}
	scen := make([]string, 0, len(s.ScenarioLogOnly))
	for _, x := range s.ScenarioLogOnly {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" || seen[x] {
			continue
		}
		if len(x) < 3 || len(x) > 128 || clean(x, 128) != x {
			return fmt.Errorf("invalid log-only scenario %q (3 to 128 characters)", x)
		}
		seen[x] = true
		scen = append(scen, x)
	}
	s.ScenarioLogOnly = scen
	if len(s.Allowlist) > maxAllowlist {
		return fmt.Errorf("at most %d allowlist entries", maxAllowlist)
	}
	seen = map[string]bool{}
	allow := make([]string, 0, len(s.Allowlist))
	for _, x := range s.Allowlist {
		if strings.TrimSpace(x) == "" {
			continue
		}
		p, err := parseAllow(x)
		if err != nil {
			return err
		}
		txt := p.String()
		if p.IsSingleIP() {
			txt = p.Addr().String()
		}
		if !seen[txt] {
			seen[txt] = true
			allow = append(allow, txt)
		}
	}
	s.Allowlist = allow
	if len(s.SiteOverrides) > maxSiteOverrides {
		return fmt.Errorf("at most %d site overrides", maxSiteOverrides)
	}
	sites := map[string]string{}
	for h, v := range s.SiteOverrides {
		h, v = strings.ToLower(strings.TrimSpace(h)), strings.ToLower(strings.TrimSpace(v))
		if !validHostKey(h) {
			return fmt.Errorf("invalid site %q in the site overrides", h)
		}
		switch v {
		case "":
		case SiteExempt, SiteLog, SiteEnforce:
			sites[h] = v
		default:
			return fmt.Errorf("unknown override %q for site %s (use exempt, log or enforce)", v, h)
		}
	}
	s.SiteOverrides = sites
	if len(sites) > 0 { // an override replaces the older exempt entry of the same site
		kept := s.ExemptSites[:0]
		for _, h := range s.ExemptSites {
			if _, ok := sites[h]; !ok {
				kept = append(kept, h)
			}
		}
		s.ExemptSites = kept
	}
	s.CaptchaFallback = strings.ToLower(strings.TrimSpace(s.CaptchaFallback))
	switch s.CaptchaFallback {
	case "":
		s.CaptchaFallback = CaptchaFallbackLog
	case CaptchaFallbackLog, CaptchaFallbackBan:
	default:
		return fmt.Errorf("unknown captcha fallback %q (use log or ban)", s.CaptchaFallback)
	}
	return nil
}

// EnforcedSites lists the sites with the override "enforce", sorted
func (s Settings) EnforcedSites() []string {
	var out []string
	for h, v := range s.SiteOverrides {
		if v == SiteEnforce {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// Normalize applies defaults and validates. It changes s in place; on error s is unusable.
func (s *Settings) Normalize() error {
	s.LAPIURL = strings.TrimSpace(s.LAPIURL)
	s.Mode = strings.ToLower(strings.TrimSpace(s.Mode))
	switch s.Mode {
	case "":
		s.Mode = ModeLog
	case ModeLog, ModeEnforce:
	default:
		return fmt.Errorf("unknown mode %q (use log or enforce)", s.Mode)
	}
	s.BanResponse = strings.ToLower(strings.TrimSpace(s.BanResponse))
	switch s.BanResponse {
	case "":
		s.BanResponse = BanPage
	case BanPage, BanDrop:
	default:
		return fmt.Errorf("unknown ban response %q (use page or drop)", s.BanResponse)
	}
	s.CaptchaAction = strings.ToLower(strings.TrimSpace(s.CaptchaAction))
	switch s.CaptchaAction {
	case "":
		s.CaptchaAction = CaptchaLog
	case CaptchaLog, CaptchaChallenge:
	default:
		return fmt.Errorf("unknown captcha action %q (use log or challenge)", s.CaptchaAction)
	}
	if s.PollSeconds == 0 {
		s.PollSeconds = DefaultPoll
	}
	if s.PollSeconds < MinPoll || s.PollSeconds > MaxPoll {
		return fmt.Errorf("poll interval must be %d to %d seconds", MinPoll, MaxPoll)
	}
	if s.MaxEntries == 0 {
		s.MaxEntries = DefaultMaxEntries
	}
	if s.MaxEntries < 100 || s.MaxEntries > HardMaxEntries {
		return fmt.Errorf("cache size must be 100 to %d decisions", HardMaxEntries)
	}
	if s.MaxTTLSeconds == 0 {
		s.MaxTTLSeconds = DefaultMaxTTL
	}
	if s.MaxTTLSeconds < 60 || s.MaxTTLSeconds > HardMaxTTL {
		return fmt.Errorf("maximum decision lifetime must be 60 seconds to %d seconds", HardMaxTTL)
	}
	if s.GraceSeconds == 0 {
		s.GraceSeconds = DefaultGrace
	}
	if s.GraceSeconds < MinGrace || s.GraceSeconds > MaxGrace {
		return fmt.Errorf("grace period must be %d to %d seconds", MinGrace, MaxGrace)
	}
	if len(s.ExemptSites) > maxExempt {
		return fmt.Errorf("at most %d exempt sites", maxExempt)
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(s.ExemptSites))
	for _, h := range s.ExemptSites {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		if len(h) > 253 || strings.ContainsAny(h, " \t\r\n\x00") {
			return fmt.Errorf("invalid exempt site %q", h)
		}
		seen[h] = true
		clean = append(clean, h)
	}
	s.ExemptSites = clean
	if err := s.normalizePolicy(); err != nil {
		return err
	}
	pol, err := upstreamtls.Policy{CABundlePEM: s.CABundlePEM, PinsSHA256: s.PinsSHA256}.Normalized()
	if err != nil {
		return err
	}
	if err := pol.Validate(); err != nil {
		return err
	}
	s.CABundlePEM, s.PinsSHA256 = pol.CABundlePEM, pol.PinsSHA256
	if s.LAPIURL != "" {
		u, err := ParseLAPIURL(s.LAPIURL)
		if err != nil {
			return err
		}
		if u.Scheme != "https" && pol.Active() {
			return errors.New("a CA bundle or pin only applies to an https LAPI address")
		}
		s.LAPIURL = strings.TrimRight(u.String(), "/")
	}
	if s.Enabled && s.LAPIURL == "" {
		return errors.New("the LAPI address is required")
	}
	return nil
}

// ParseLAPIURL checks the address of the Local API: http or https, a host, no credentials, query or fragment
func ParseLAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("invalid LAPI address")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("the LAPI address must start with http:// or https://")
	}
	if u.Hostname() == "" {
		return nil, errors.New("the LAPI address has no host")
	}
	if u.User != nil {
		return nil, errors.New("the LAPI address must not contain a user name or password (the API key is entered separately)")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("the LAPI address must not contain a query or fragment")
	}
	if len(raw) > 512 {
		return nil, errors.New("the LAPI address is too long")
	}
	return u, nil
}

// Policy is the TLS trust policy of the settings
func (s Settings) Policy() upstreamtls.Policy {
	return upstreamtls.Policy{CABundlePEM: s.CABundlePEM, PinsSHA256: s.PinsSHA256}
}
