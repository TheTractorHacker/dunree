package confpack

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// RedactedMarker replaces the value of a credential field in a shareable export.
const RedactedMarker = "[REDACTED]"

// neverExportKeys are normalised field names (lower case letters and digits only) that are always
// redacted, whatever they hold. This is the explicit list; secretNameParts below is the rule set.
var neverExportKeys = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true, "passwordhash": true, "passhash": true,
	"secret": true, "clientsecret": true, "sharedsecret": true, "clustersecret": true, "hmacsecret": true,
	"apikey": true, "accesstoken": true, "refreshtoken": true, "token": true, "bearertoken": true, "authtoken": true,
	"privatekey": true, "privkey": true, "psk": true, "presharedkey": true,
	"authorization": true, "proxyauthorization": true, "cookie": true, "setcookie": true,
	"basicauthcredentials": true, "credentials": true, "credential": true, "creds": true,
	"dnscredentials": true, "webhooksecret": true, "signingsecret": true, "totpsecret": true,
}

// secretNameParts: a normalised field name containing one of these is redacted too.
var secretNameParts = []string{
	"secret", "password", "passwd", "passphrase", "apikey", "privatekey", "privkey", "credential",
	"accesstoken", "refreshtoken", "authtoken", "sessionkey", "sessiontoken", "secretkey", "accesskey",
	"signingkey", "encryptionkey", "masterkey", "authkey", "bearer",
	//review fix: apiToken, botToken, webhookToken, RemoteTokenHash, HmacKey (acme EAB) and webhook / DSN urls
	"token", "hmac", "webhook", "dsn",
}

// benignNumberParts: a number under a sensitive looking name is still redacted (a numeric PIN or secret exists)
// unless the name says it is a size, a time or a switch
var benignNumberParts = []string{"ttl", "expire", "expiry", "timeout", "count", "len", "max", "min", "size", "limit", "interval", "duration", "age", "port", "enabled", "use", "rate", "retry", "lifetime"}

// sensitiveHeaderNames mark a {name, value} pair (custom header rules) whose value is a secret.
var sensitiveHeaderNames = []string{"authorization", "cookie", "api-key", "apikey", "x-auth", "token", "secret", "password", "passwd"}

var (
	//everything between "scheme://" and the last "@" of the authority: user:pass@, a bare TOKEN@ and a password that contains "@"
	urlUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]*@`)
	//query parameters whose name looks like a credential (?token=..., &api_key=..., &sig=...)
	urlSecretQuery = regexp.MustCompile(`(?i)([?&;][^=&\s#]*(?:token|secret|key|pass|pwd|auth|sig|credential|hmac)[^=&\s#]*=)[^&\s#]+`)
	hashLike       = regexp.MustCompile(`^\$(2[abxy]?|argon2(id|i|d)?|pbkdf2[-a-z0-9]*|scrypt)\$`)
)

func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SensitiveKey reports whether a JSON field name is treated as a credential.
func SensitiveKey(k string) bool {
	n := normName(k)
	if n == "" {
		return false
	}
	if neverExportKeys[n] {
		return true
	}
	for _, p := range secretNameParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// SecretString reports whether a string value looks like a credential no matter what its field is called.
func SecretString(s string) bool {
	return strings.Contains(s, "PRIVATE KEY-----") || hashLike.MatchString(s)
}

func sensitiveHeaderPair(m map[string]any) bool {
	for k, v := range m {
		switch normName(k) {
		case "key", "name", "header", "headername":
			if s, ok := v.(string); ok {
				l := strings.ToLower(s)
				for _, p := range sensitiveHeaderNames {
					if strings.Contains(l, p) {
						return true
					}
				}
			}
		}
	}
	return false
}

// redactable: only non-empty strings, objects and arrays carry a secret; booleans, numbers and
// empty values stay (so "UseToken": false survives and the shape of the file is kept)
func redactable(v any) bool {
	switch x := v.(type) {
	case string:
		return x != "" && x != RedactedMarker
	case json.Number:
		return true
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	}
	return false
}

func redactValue(v any, n *int) any {
	switch x := v.(type) {
	case map[string]any:
		pair := sensitiveHeaderPair(x)
		for k, val := range x {
			nk := normName(k)
			if SensitiveKey(k) || (pair && (nk == "value" || nk == "headervalue")) {
				if _, isNum := val.(json.Number); isNum && benignNumberKey(nk) {
					continue
				}
				if redactable(val) {
					x[k] = RedactedMarker
					*n++
					continue
				}
			}
			x[k] = redactValue(val, n)
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactValue(x[i], n)
		}
		return x
	case string:
		if x == RedactedMarker {
			return v
		}
		if SecretString(x) {
			*n++
			return RedactedMarker
		}
		out := x
		if urlUserinfo.MatchString(out) {
			out = urlUserinfo.ReplaceAllString(out, "${1}"+RedactedMarker+"@")
		}
		if urlSecretQuery.MatchString(out) {
			out = urlSecretQuery.ReplaceAllString(out, "${1}"+RedactedMarker)
		}
		if out != x {
			*n++
			return out
		}
	}
	return v
}

func benignNumberKey(nk string) bool {
	for _, p := range benignNumberParts {
		if strings.Contains(nk, p) {
			return true
		}
	}
	return false
}

var bearerText = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`)

// ScrubText removes credentials from free text that is about to be shown (an error message, a monitor URL):
// userinfo in URLs, secret looking query parameters and "Bearer <token>". It is not a general redactor, only the
// shapes an HTTP client error or a configured URL can carry.
func ScrubText(s string) string {
	s = urlUserinfo.ReplaceAllString(s, "${1}"+RedactedMarker+"@")
	s = urlSecretQuery.ReplaceAllString(s, "${1}"+RedactedMarker)
	return bearerText.ReplaceAllString(s, "${1} "+RedactedMarker)
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errTrailing
	}
	return v, nil
}

type confError string

func (e confError) Error() string { return string(e) }

const errTrailing = confError("trailing data after the JSON value")

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RedactJSON returns the document with every credential field replaced by RedactedMarker and the
// number of fields it replaced. The output is re-encoded (sorted keys, 2 space indent).
func RedactJSON(b []byte) ([]byte, int, error) {
	v, err := decodeJSON(b)
	if err != nil {
		return nil, 0, err
	}
	n := 0
	v = redactValue(v, &n)
	out, err := encodeJSON(v)
	return out, n, err
}

// CanonicalNonSecret is the material fleet drift detection compares: the JSON document with
// credentials redacted and keys sorted, compact. Non JSON input is returned as is.
func CanonicalNonSecret(b []byte) []byte {
	v, err := decodeJSON(b)
	if err != nil {
		return b
	}
	n := 0
	v = redactValue(v, &n)
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

// MergeRedacted restores the fields an export redacted: wherever incoming holds the marker, the
// value of the same path in existing is kept; when existing has none the field is dropped, so the
// marker itself never reaches a live configuration. It returns the merged document and how many
// markers were resolved from existing (kept) and dropped. Input that is not JSON is returned unchanged.
//
// It trusts the incoming document: a credential field that holds a real value is taken as it is. Use
// MergeShareable for archives that come from outside.
func MergeRedacted(incoming, existing []byte) (out []byte, kept, dropped int, err error) {
	return mergeRedacted(incoming, existing)
}

// MergeShareable is MergeRedacted for a shareable archive, which is not trusted to carry credentials: every field
// that the redactor would have replaced (by name or by content) is first forced back to the marker, so the live
// value is kept (or the field dropped) even when the archive holds a real looking value there. ignored counts the
// fields where the archive offered a value that was refused.
func MergeShareable(incoming, existing []byte) (out []byte, kept, dropped, ignored int, err error) {
	in, err := decodeJSON(incoming)
	if err != nil {
		return incoming, 0, 0, 0, err
	}
	in = redactValue(in, &ignored)
	raw, err := encodeJSON(in)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	out, kept, dropped, err = mergeRedacted(raw, existing)
	return out, kept, dropped, ignored, err
}

func mergeRedacted(incoming, existing []byte) (out []byte, kept, dropped int, err error) {
	in, err := decodeJSON(incoming)
	if err != nil {
		return incoming, 0, 0, err
	}
	var ex any
	hasEx := false
	if len(existing) > 0 {
		if v, e := decodeJSON(existing); e == nil {
			ex, hasEx = v, true
		}
	}
	merged, keep := mergeValue(in, ex, hasEx, &kept, &dropped)
	if !keep {
		merged = nil
	}
	out, err = encodeJSON(merged)
	return out, kept, dropped, err
}

// identityKeys name the field that identifies an element of an array of objects (a rule, a user, a host).
var identityKeys = []string{"id", "uuid", "name", "username", "user", "rootormatchingdomain", "domain", "hostname", "host", "alias", "key", "path", "rulename", "matchingdomain", "origin", "url"}

// matchExisting finds the element of the live array that the incoming element stands for. Elements are matched by
// an identifying field, never by position when they have one: a reordered array must not put one element's
// secret into another element's slot. An element with an identifying field but no counterpart gets no live value.
func matchExisting(in any, exa []any, idx int) (any, bool) {
	im, ok := in.(map[string]any)
	if !ok {
		if idx < len(exa) {
			return exa[idx], true
		}
		return nil, false
	}
	for _, want := range identityKeys {
		for k, v := range im {
			if normName(k) != want {
				continue
			}
			sv, isStr := v.(string)
			if !isStr || sv == "" || sv == RedactedMarker {
				continue
			}
			for _, e := range exa {
				if em, ok := e.(map[string]any); ok {
					for ek, ev := range em {
						if normName(ek) == want {
							if es, ok := ev.(string); ok && es == sv {
								return e, true
							}
						}
					}
				}
			}
			return nil, false
		}
	}
	if idx < len(exa) {
		return exa[idx], true
	}
	return nil, false
}

func mergeValue(in, ex any, hasEx bool, kept, dropped *int) (any, bool) {
	switch x := in.(type) {
	case string:
		if x == RedactedMarker {
			if hasEx {
				*kept++
				return ex, true
			}
			*dropped++
			return nil, false
		}
		if strings.Contains(x, RedactedMarker) { //a URL whose password, userinfo or secret query value was removed
			if s, ok := ex.(string); ok && hasEx {
				*kept++
				return s, true
			}
			*dropped++
			x = strings.Replace(x, RedactedMarker+"@", "", 1)
			return strings.Replace(x, RedactedMarker, "", 1), true
		}
	case map[string]any:
		exm, _ := ex.(map[string]any)
		for k, v := range x {
			ev, ok := exm[k]
			nv, keep := mergeValue(v, ev, ok, kept, dropped)
			if keep {
				x[k] = nv
			} else {
				delete(x, k)
			}
		}
		return x, true
	case []any:
		exa, _ := ex.([]any)
		out := make([]any, 0, len(x))
		for i, v := range x {
			ev, ok := matchExisting(v, exa, i)
			if nv, keep := mergeValue(v, ev, ok, kept, dropped); keep {
				out = append(out, nv)
			}
		}
		return out, true
	}
	return in, true
}
