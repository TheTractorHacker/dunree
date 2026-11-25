package dynamicproxy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/permissionpolicy"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/rewrite"
)

/*
	Hardened security headers preset (opt-in, off by default)

	A per site switch (HeaderRewriteRules.HardenedHeaders, nil = off, so every existing config loads unchanged)
	that adds a small, fixed set of browser hardening response headers:

	  Strict-Transport-Security   only over TLS; includeSubDomains / preload only when chosen
	  X-Content-Type-Options      nosniff
	  Referrer-Policy             one of a short list
	  X-Frame-Options or CSP frame-ancestors   framing control
	  Permissions-Policy          sensors / camera / microphone / payment... denied, built with mod/dynamicproxy/permissionpolicy

	Precedence (highest first): headers the admin set on the site (custom header rules, the HSTS and Permission
	Policy switches), then what the upstream sent, then this preset. With OverrideExisting the preset also replaces
	values the upstream sent, but never an admin header and never an existing Content-Security-Policy (frame-ancestors
	is added as a further policy header only when the upstream policy has none).

	Not covered: responses Dunree generates itself (block pages, error pages) and WebSocket upgrade responses.
*/

const (
	HardenedHSTSDefaultAge = 31536000
	hardenedHSTSMinAge     = 300
	hardenedHSTSMaxAge     = 63072000
	hardenedPreloadMinAge  = 31536000
)

// Allowed Referrer-Policy and framing values
var hardenedReferrerPolicies = map[string]bool{
	"no-referrer": true, "same-origin": true, "strict-origin": true, "strict-origin-when-cross-origin": true,
}
var hardenedFrameModes = map[string]string{
	"deny":       "X-Frame-Options: DENY",
	"sameorigin": "X-Frame-Options: SAMEORIGIN",
	"csp-none":   "Content-Security-Policy: frame-ancestors 'none'",
	"csp-self":   "Content-Security-Policy: frame-ancestors 'self'",
}

// HardenedHeaders is the preset of one site. A nil pointer or Enabled=false sends nothing.
type HardenedHeaders struct {
	Enabled               bool
	HSTS                  bool   //Send Strict-Transport-Security (only on TLS requests)
	HSTSMaxAge            int64  //Seconds, 0 = 31536000
	HSTSIncludeSubdomains bool   //Add includeSubDomains (never implied)
	HSTSPreload           bool   //Add preload (needs includeSubDomains and a max age of at least one year)
	NoSniff               bool   //X-Content-Type-Options: nosniff
	ReferrerPolicy        string //"" = not sent
	FrameProtection       string //"" (off), deny, sameorigin, csp-none, csp-self
	PermissionsPolicy     bool   //Restrictive Permissions-Policy
	OverrideExisting      bool   //Replace values the upstream sent (admin headers still win)
}

// DefaultHardenedHeaders is what the GUI pre-fills when the admin turns the preset on. It is never applied on its own.
func DefaultHardenedHeaders() *HardenedHeaders {
	return &HardenedHeaders{
		Enabled: true, HSTS: true, HSTSMaxAge: HardenedHSTSDefaultAge, NoSniff: true,
		ReferrerPolicy: "strict-origin-when-cross-origin", FrameProtection: "sameorigin", PermissionsPolicy: true,
	}
}

// Validate normalises (trims, fills the default HSTS age) and checks the values
func (hh *HardenedHeaders) Validate() error {
	if hh == nil {
		return nil
	}
	hh.ReferrerPolicy = strings.ToLower(strings.TrimSpace(hh.ReferrerPolicy))
	hh.FrameProtection = strings.ToLower(strings.TrimSpace(hh.FrameProtection))
	if hh.ReferrerPolicy != "" && !hardenedReferrerPolicies[hh.ReferrerPolicy] {
		return errors.New("unsupported Referrer-Policy value")
	}
	if hh.FrameProtection != "" {
		if _, ok := hardenedFrameModes[hh.FrameProtection]; !ok {
			return errors.New("unsupported frame protection value")
		}
	}
	if hh.HSTSMaxAge == 0 {
		hh.HSTSMaxAge = HardenedHSTSDefaultAge
	}
	if hh.HSTSMaxAge < hardenedHSTSMinAge || hh.HSTSMaxAge > hardenedHSTSMaxAge {
		return fmt.Errorf("HSTS max age must be between %d and %d seconds", hardenedHSTSMinAge, hardenedHSTSMaxAge)
	}
	if hh.HSTSPreload && !hh.HSTS {
		return errors.New("HSTS preload needs HSTS to be on")
	}
	if hh.HSTSPreload && !hh.HSTSIncludeSubdomains {
		return errors.New("HSTS preload requires includeSubDomains")
	}
	if hh.HSTSPreload && hh.HSTSMaxAge < hardenedPreloadMinAge {
		return errors.New("HSTS preload requires a max age of at least 31536000 seconds")
	}
	if hh.HSTSIncludeSubdomains && !hh.HSTS {
		return errors.New("includeSubDomains needs HSTS to be on")
	}
	return nil
}

// hardenedPermissionPolicy is the default policy (every feature allowed, so nothing breaks that is not named) with the
// sensor, capture and device features switched off
func hardenedPermissionPolicy() *permissionpolicy.PermissionsPolicy {
	p := permissionpolicy.GetDefaultPermissionPolicy()
	none := func() []string { return []string{} }
	p.Accelerometer, p.Gyroscope, p.Magnetometer, p.Camera, p.Microphone, p.Geolocation = none(), none(), none(), none(), none(), none()
	p.Payment, p.USB, p.Midi, p.Serial, p.HID, p.DisplayCapture, p.InterestCohort = none(), none(), none(), none(), none(), none(), none()
	return p
}

// HardenedHeaderEntry is one line of the plan (and of the preview shown in the GUI)
type HardenedHeaderEntry struct {
	Key     string
	Value   string
	Mode    string //"add" (only when the upstream sent none), "replace" (OverrideExisting), "skipped"
	Reason  string `json:",omitempty"` //Why a header is skipped
	skipped bool
}

// adminDownstreamKeys are the response headers the admin controls on this site (lower case)
func adminDownstreamKeys(hr *HeaderRewriteRules) map[string]string {
	m := map[string]string{}
	if hr == nil {
		return m
	}
	for _, h := range hr.UserDefinedHeaders {
		if h != nil && h.Direction == rewrite.HeaderDirection_DunreeToDownstream {
			m[strings.ToLower(h.Key)] = "a custom header rule sets it"
		}
	}
	if hr.HSTSMaxAge > 0 {
		m["strict-transport-security"] = "the site's own HSTS switch is on"
	}
	if hr.EnablePermissionPolicyHeader {
		m["permissions-policy"] = "the site's own Permission Policy is on"
	}
	return m
}

// Plan lists what the preset does for a request. isTLS: HSTS is only meaningful (and only sent) over TLS.
func (hh *HardenedHeaders) Plan(hr *HeaderRewriteRules, isTLS bool) []HardenedHeaderEntry {
	if hh == nil || !hh.Enabled {
		return nil
	}
	mode := "add"
	if hh.OverrideExisting {
		mode = "replace"
	}
	admin := adminDownstreamKeys(hr)
	var out []HardenedHeaderEntry
	add := func(k, v string) {
		e := HardenedHeaderEntry{Key: k, Value: v, Mode: mode}
		if why, ok := admin[strings.ToLower(k)]; ok {
			e.Mode, e.Reason, e.skipped = "skipped", why, true
		}
		out = append(out, e)
	}
	if hh.HSTS {
		age := hh.HSTSMaxAge
		if age == 0 {
			age = HardenedHSTSDefaultAge
		}
		v := fmt.Sprintf("max-age=%d", age)
		if hh.HSTSIncludeSubdomains {
			v += "; includeSubDomains"
		}
		if hh.HSTSPreload {
			v += "; preload"
		}
		if isTLS {
			add("Strict-Transport-Security", v)
		} else {
			out = append(out, HardenedHeaderEntry{Key: "Strict-Transport-Security", Value: v, Mode: "skipped", Reason: "only sent on HTTPS requests", skipped: true})
		}
	}
	if hh.NoSniff {
		add("X-Content-Type-Options", "nosniff")
	}
	if hh.ReferrerPolicy != "" {
		add("Referrer-Policy", hh.ReferrerPolicy)
	}
	if kv, ok := hardenedFrameModes[hh.FrameProtection]; ok {
		parts := strings.SplitN(kv, ": ", 2)
		add(parts[0], parts[1])
	}
	if hh.PermissionsPolicy {
		kv := hardenedPermissionPolicy().ToKeyValueHeader()
		add(kv[0], kv[1])
	}
	return out
}

// Active returns the key/value pairs to hand to the response rewriter (skipped entries removed)
func (hh *HardenedHeaders) Active(hr *HeaderRewriteRules, isTLS bool) [][]string {
	plan := hh.Plan(hr, isTLS)
	if len(plan) == 0 {
		return nil
	}
	out := make([][]string, 0, len(plan))
	for _, e := range plan {
		if !e.skipped {
			out = append(out, []string{e.Key, e.Value})
		}
	}
	return out
}

// hardenedForRequest is the request path helper. It costs a nil check when the preset is off.
func hardenedForRequest(hr *HeaderRewriteRules, r *http.Request) ([][]string, bool) {
	if hr == nil || hr.HardenedHeaders == nil || !hr.HardenedHeaders.Enabled {
		return nil, false
	}
	return hr.HardenedHeaders.Active(hr, r.TLS != nil), hr.HardenedHeaders.OverrideExisting
}
