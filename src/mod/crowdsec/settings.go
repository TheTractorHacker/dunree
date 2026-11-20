package crowdsec

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/upstreamtls"
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
)

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
	ExemptSites   []string `json:"exemptSites"`   // proxy rules (host names) that never consult CrowdSec
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
