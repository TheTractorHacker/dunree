//go:build unix

package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

/*
	The manifest a plugin prints for -introspect, and the checks on it.

	The field list and the rules are those of docs/plugins/contract.md section 2
	and of the loader of Zoraxy (src/mod/plugins: validatePluginSpec,
	sanitizeHookSpec, sanitizeSupervisionSpec, sanitizeContractSpec). The kit is a
	program of its own and does not import Zoraxy.
*/

const (
	contractMax         = 1 //highest plugin contract version this kit knows
	hookAPIVersion      = 1
	defaultHookTimeout  = 2000
	maxHookTimeoutMs    = 10000
	maxBodyPreviewBytes = 64 * 1024
)

type permittedEndpoint struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
}

type hookSettings struct {
	Version            int      `json:"version"`
	Stages             []string `json:"stages"`
	FilterRequestPath  string   `json:"filter_request_path"`
	FilterResponsePath string   `json:"filter_response_path"`
	Priority           int      `json:"priority"`
	TimeoutMs          int      `json:"timeout_ms"`
	FailurePolicy      string   `json:"failure_policy"`
	BodyPreviewBytes   int      `json:"body_preview_bytes"`
	BodyContentTypes   []string `json:"body_content_types"`
}

type manifest struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Author        string `json:"author"`
	AuthorContact string `json:"author_contact"`
	Description   string `json:"description"`
	URL           string `json:"url"`
	Type          int    `json:"type"`
	VersionMajor  int    `json:"version_major"`
	VersionMinor  int    `json:"version_minor"`
	VersionPatch  int    `json:"version_patch"`

	StaticCapturePaths []struct {
		CapturePath string `json:"capture_path"`
	} `json:"static_capture_paths"`
	StaticCaptureIngress  string `json:"static_capture_ingress"`
	DynamicCaptureSniff   string `json:"dynamic_capture_sniff"`
	DynamicCaptureIngress string `json:"dynamic_capture_ingress"`

	UIPath string `json:"ui_path"`

	SubscriptionPath    string            `json:"subscription_path"`
	SubscriptionsEvents map[string]string `json:"subscriptions_events"`

	PermittedAPIEndpoints []permittedEndpoint `json:"permitted_api_endpoints"`

	Hooks        *hookSettings `json:"hooks"`
	HealthPath   string        `json:"health_path"`
	ConfigureVia string        `json:"configure_via"`
	APIVersion   int           `json:"api_version"`
}

func (m *manifest) version() string {
	return fmt.Sprintf("%d.%d.%d", m.VersionMajor, m.VersionMinor, m.VersionPatch)
}

// hookTimeoutMs is the per call timeout Zoraxy uses for this plugin (default and cap applied)
func (m *manifest) hookTimeoutMs() int {
	ms := defaultHookTimeout
	if m.Hooks != nil && m.Hooks.TimeoutMs > 0 {
		ms = m.Hooks.TimeoutMs
	}
	if ms > maxHookTimeoutMs {
		ms = maxHookTimeoutMs
	}
	return ms
}

func (m *manifest) hasStage(stage string) bool {
	if m.Hooks == nil {
		return false
	}
	for _, s := range m.Hooks.Stages {
		if s == stage {
			return true
		}
	}
	return false
}

func (m *manifest) filterPath(stage string) string {
	if m.Hooks == nil {
		return ""
	}
	if stage == "response" && m.Hooks.FilterResponsePath != "" {
		return m.Hooks.FilterResponsePath
	}
	return m.Hooks.FilterRequestPath
}

func (m *manifest) hasSniff() bool {
	return m.DynamicCaptureSniff != "" && m.DynamicCaptureIngress != ""
}

func (m *manifest) wantsBody() bool {
	return m.Hooks != nil && m.Hooks.BodyPreviewBytes > 0 && len(m.Hooks.BodyContentTypes) > 0
}

func normalizeEndpoint(s string) string {
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return strings.TrimSuffix(s, "/")
}

// cleanEndpointPath is the rule of Zoraxy for a filter path ("" = unusable)
func cleanEndpointPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.ContainsAny(p, "?#\\ ") || strings.Contains(p, "..") || strings.HasPrefix(p, "//") {
		return ""
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return ""
		}
	}
	return p
}

func validHealthPath(hp string) bool {
	if len(hp) > 256 || !strings.HasPrefix(hp, "/") || strings.Contains(hp, "//") {
		return false
	}
	for _, r := range hp {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/-_.~", r)) {
			return false
		}
	}
	return true
}

var knownEvents = map[string]bool{
	"blacklistedIpBlocked": true, "blacklistToggled": true, "accessRuleCreated": true, "customEvent": true, "dummy": true,
}

// decodeManifest reads the output of -introspect as Zoraxy does. An api_version of
// another type than a whole number is dropped (the plugin is then a legacy
// plugin) and reported as a note; every other type error refuses the manifest.
func decodeManifest(out []byte) (*manifest, []string, error) {
	var m manifest
	err := json.Unmarshal(out, &m)
	if err == nil {
		return &m, nil, nil
	}
	typeErr, ok := err.(*json.UnmarshalTypeError)
	if !ok || !strings.EqualFold(typeErr.Field, "api_version") {
		return nil, nil, err
	}
	raw := map[string]json.RawMessage{}
	if json.Unmarshal(out, &raw) != nil {
		return nil, nil, err
	}
	for key := range raw {
		if strings.EqualFold(key, "api_version") {
			delete(raw, key)
		}
	}
	rest, _ := json.Marshal(raw)
	m = manifest{}
	if err := json.Unmarshal(rest, &m); err != nil {
		return nil, nil, err
	}
	return &m, []string{"api_version is not a whole number: Zoraxy drops it and treats the plugin as a legacy plugin"}, nil
}

// checkManifest returns what Zoraxy refuses (fails) and what it drops, ignores or
// what an administrator should know (warns). It also normalises the manifest the
// way Zoraxy does, so the later checks call what Zoraxy would call.
func checkManifest(m *manifest) (fails []string, warns []string) {
	for name, v := range map[string]string{"id": m.ID, "name": m.Name, "author": m.Author, "description": m.Description, "ui_path": m.UIPath} {
		if v == "" {
			fails = append(fails, name+" is empty: Zoraxy does not load the plugin")
		}
	}
	if len(m.ID) > 128 || strings.ContainsAny(m.ID, "/\\ \t\r\n<>\"'") || strings.Contains(m.ID, "..") {
		warns = append(warns, "id should be a short dotted name without spaces, slashes or quotes (it is used in addresses and folder names)")
	}
	if m.UIPath != "" && !strings.HasPrefix(m.UIPath, "/") {
		warns = append(warns, "ui_path should start with /")
	}
	if m.Type != 0 && m.Type != 1 {
		warns = append(warns, fmt.Sprintf("type %d is not 0 (router) or 1 (utility)", m.Type))
	}
	if m.VersionMajor < 0 || m.VersionMinor < 0 || m.VersionPatch < 0 {
		warns = append(warns, "the version has a negative part")
	}
	if len(m.Description) > 2000 || len(m.Name) > 128 {
		warns = append(warns, "name or description is very long")
	}
	if len(m.StaticCapturePaths) > 0 && m.StaticCaptureIngress == "" {
		warns = append(warns, "static_capture_paths without static_capture_ingress")
	}
	for _, cp := range m.StaticCapturePaths {
		if !strings.HasPrefix(cp.CapturePath, "/") {
			warns = append(warns, fmt.Sprintf("static capture path %q does not start with /", cp.CapturePath))
		}
	}
	if (m.DynamicCaptureSniff == "") != (m.DynamicCaptureIngress == "") {
		warns = append(warns, "dynamic capture needs both dynamic_capture_sniff and dynamic_capture_ingress: Zoraxy ignores one without the other")
	}
	if len(m.SubscriptionsEvents) > 0 && m.SubscriptionPath == "" {
		fails = append(fails, "subscriptions_events without subscription_path: no event can be delivered")
	}
	for name := range m.SubscriptionsEvents {
		if !knownEvents[name] {
			warns = append(warns, fmt.Sprintf("event %q is not an event this kit knows", name))
		}
	}
	for _, ep := range m.PermittedAPIEndpoints {
		if ep.Method == "" || ep.Method != strings.ToUpper(ep.Method) {
			warns = append(warns, fmt.Sprintf("permitted endpoint %q: the method %q should be an upper case HTTP method (it is compared as text)", ep.Endpoint, ep.Method))
		}
		if !strings.HasPrefix(ep.Endpoint, "/plugin/api/") {
			warns = append(warns, fmt.Sprintf("permitted endpoint %q is not below /plugin/api/", ep.Endpoint))
		}
		if strings.TrimSpace(ep.Reason) == "" {
			warns = append(warns, fmt.Sprintf("permitted endpoint %q has no reason: the administrator is asked to approve it without being told why", ep.Endpoint))
		}
	}
	if h := m.Hooks; h != nil {
		if h.Version == 0 {
			h.Version = 1
		}
		if h.Version > hookAPIVersion {
			warns = append(warns, fmt.Sprintf("hooks version %d is newer than %d: Zoraxy ignores the hooks", h.Version, hookAPIVersion))
			m.Hooks = nil
		} else {
			stages, seen := []string{}, map[string]bool{}
			for _, s := range h.Stages {
				switch s {
				case "pre_auth", "post_auth", "response":
					if !seen[s] {
						seen[s] = true
						stages = append(stages, s)
					}
				default:
					warns = append(warns, fmt.Sprintf("unknown hook stage %q: ignored by Zoraxy", s))
				}
			}
			h.Stages = stages
			h.FilterRequestPath, h.FilterResponsePath = cleanEndpointPath(h.FilterRequestPath), cleanEndpointPath(h.FilterResponsePath)
			if len(stages) > 0 && h.FilterRequestPath == "" {
				fails = append(fails, "hooks declared without a valid filter_request_path: Zoraxy ignores the hooks")
				h.Stages = nil
			}
			switch h.FailurePolicy {
			case "", "fail_open", "fail_closed":
			default:
				warns = append(warns, fmt.Sprintf("unknown failure policy %q: Zoraxy uses fail_open", h.FailurePolicy))
			}
			if h.TimeoutMs < 0 || h.TimeoutMs > maxHookTimeoutMs {
				warns = append(warns, fmt.Sprintf("hooks timeout_ms %d is outside 0 to %d: Zoraxy clamps it", h.TimeoutMs, maxHookTimeoutMs))
			}
			if h.BodyPreviewBytes < 0 || h.BodyPreviewBytes > maxBodyPreviewBytes {
				warns = append(warns, fmt.Sprintf("hooks body_preview_bytes %d is outside 0 to %d: Zoraxy clamps it", h.BodyPreviewBytes, maxBodyPreviewBytes))
				if h.BodyPreviewBytes < 0 {
					h.BodyPreviewBytes = 0
				} else {
					h.BodyPreviewBytes = maxBodyPreviewBytes
				}
			}
		}
	}
	if m.HealthPath != "" && !validHealthPath(m.HealthPath) {
		warns = append(warns, "health_path is not a plain absolute path: Zoraxy drops it and uses a TCP connect")
		m.HealthPath = ""
	}
	switch m.ConfigureVia {
	case "", "stdin":
	default:
		warns = append(warns, fmt.Sprintf("configure_via %q is unknown: Zoraxy passes the configuration on the command line", m.ConfigureVia))
		m.ConfigureVia = ""
	}
	switch {
	case m.APIVersion < 0 || m.APIVersion > 1000000:
		warns = append(warns, fmt.Sprintf("api_version %d is not a version: Zoraxy drops it and treats the plugin as a legacy plugin", m.APIVersion))
		m.APIVersion = 0
	case m.APIVersion > contractMax:
		warns = append(warns, fmt.Sprintf("api_version %d is newer than the contract version %d this kit checks against: Zoraxy warns about it, and refuses the plugin when the administrator asked for that", m.APIVersion, contractMax))
	}
	return fails, warns
}
