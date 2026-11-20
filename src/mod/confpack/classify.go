package confpack

import (
	"path"
	"strings"
)

// shareableRoots are the only conf locations a shareable export may take files from (an allow-list:
// a file Zoraxy adds later stays out until it is listed here on purpose). Each still goes through
// the never-export list and the redaction.
var shareableRoots = []string{
	"proxy", "redirect", "access", "streamproxy", "rules", "ruleset", "abuse", "trusted_proxies.json", "acme_conf.json",
	"waf_central.json", "plugin_groups.json", "log_conf.json", "blocklist_sources.json", "botrules.json",
	"sitelog.json", "certs", "version", SchemaFile,
}

// neverExport is the explicit never-export list: path prefix or exact name -> reason. It wins over the
// allow-list. Checked on the conf relative path, slash separated.
var neverExport = []struct{ p, why string }{
	{"cluster.json", "cluster secret"},
	{".cluster/", "Fleet keys and cluster state"},
	{"notify.json", "notification channel secrets"},
	{"waf_challenge.key", "WAF challenge signing key"},
	{"crowdsec/", "CrowdSec API key vault"},
	{"aiassist/", "AI assistant key vault"},
	{"ech.json", "Encrypted Client Hello private keys"},
	{"zrok.json", "tunnel credentials"},
	{"webui/", "management interface TLS key"},
	{"sso/", "single sign-on secrets and sessions"},
	{"basicauth_lists.json", "basic auth credential hashes"},
	{".history/", "per install change history"},
	{"security_audit.log", "per install audit log"},
	{"auth_audit.log", "per install audit log"},
}

// secretFileNameParts: any file whose base name contains one of these is never exported.
var secretFileNameParts = []string{"secret", "token", "session", "password", "credential", "vault", "private", "apikey", "api_key"}

// NeverExported reports whether a conf relative path is on the explicit never-export list or looks
// like a key / credential store by name. The reason is meant for the manifest.
func NeverExported(rel string) (bool, string) {
	rel = strings.TrimPrefix(rel, "./")
	for _, n := range neverExport {
		switch {
		case strings.HasSuffix(n.p, "/"):
			if strings.HasPrefix(rel, n.p) {
				return true, n.why
			}
		case rel == n.p || strings.HasPrefix(rel, n.p+"."): //rotated copies such as security_audit.log.1
			return true, n.why
		}
	}
	base := strings.ToLower(path.Base(rel))
	if strings.HasSuffix(base, ".key") {
		return true, "private key"
	}
	if nameCheckExempt(rel) {
		return false, ""
	}
	for _, p := range secretFileNameParts {
		if strings.Contains(base, p) {
			return true, "credential or key store (by name)"
		}
	}
	return false, ""
}

// nameCheckExempt: a rule file is named after the host it serves (proxy/token.example.com.config), so the by-name
// secret filter does not apply there: the JSON content is redacted by field instead. A certificate file is checked by
// content (a private key in it excludes it), not by name.
func nameCheckExempt(rel string) bool {
	for _, r := range []string{"proxy/", "redirect/", "access/", "streamproxy/", "rules/", "ruleset/"} {
		if strings.HasPrefix(rel, r) && isJSONName(rel) {
			return true
		}
	}
	if strings.HasPrefix(rel, "certs/") {
		switch strings.ToLower(path.Ext(rel)) {
		case ".pem", ".crt", ".cer", ".crl":
			return true
		}
	}
	return false
}

// KeepLiveAlways: files that describe this install and are never taken from an archive on a shareable import.
func KeepLiveAlways(rel string) bool { return rel == "version" || rel == SchemaFile }

func inShareableRoot(rel string) bool {
	for _, r := range shareableRoots {
		if rel == r || strings.HasPrefix(rel, r+"/") {
			return true
		}
	}
	return false
}

func isJSONName(rel string) bool {
	e := strings.ToLower(path.Ext(rel))
	return e == ".json" || e == ".config"
}

// ShareableKind classifies a conf relative path for the shareable export without reading it:
// "json" (include after redaction), "raw" (include as is, content checked by the caller) or
// "" with a reason when it is excluded.
func ShareableKind(rel string) (kind string, reason string) {
	if bad, why := NeverExported(rel); bad {
		return "", why
	}
	if !inShareableRoot(rel) {
		return "", "not a known configuration file"
	}
	if isJSONName(rel) {
		return "json", ""
	}
	if rel == "version" {
		return "raw", ""
	}
	if strings.HasPrefix(rel, "certs/") {
		switch strings.ToLower(path.Ext(rel)) {
		case ".pem", ".crt", ".cer", ".crl":
			return "raw", "" //public part only: the caller drops it when it holds a private key
		}
	}
	return "", "cannot be checked for secrets"
}

// KeptOnShareableImport reports whether a live conf file must survive the import of a shareable
// archive: everything a shareable export can never carry (so importing it cannot erase secrets).
func KeptOnShareableImport(rel string) bool {
	kind, _ := ShareableKind(rel)
	return kind == ""
}
