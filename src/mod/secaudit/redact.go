package secaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

/*
	Redaction. Two layers, both decided by the NAME of a field, never by its value alone:

	  - never-log fields (neverLog): dropped completely, not even the key is stored.
	    Passwords, tokens, cookies, CSRF values, one-time codes, private keys.
	  - secret-looking names (secretNameParts): the key is kept so the log shows that the
	    setting was touched, the value is replaced by "[redacted]".

	On top of that values are shortened, control characters are removed (log injection),
	PEM blocks are summarised (a private key is never kept, a certificate bundle becomes a
	count and a fingerprint), URLs lose their password and JSON values are redacted key by key.
*/

// neverLog are normalised field names (lower case, letters and digits only) that are
// dropped entirely from the detail.
var neverLog = map[string]bool{
	"password": true, "newpassword": true, "oldpassword": true, "currentpassword": true,
	"confirmpassword": true, "passwd": true, "pass": true, "pwd": true,
	"token": true, "accesstoken": true, "refreshtoken": true, "csrf": true, "csrftoken": true,
	"cookie": true, "setcookie": true, "authorization": true, "proxyauthorization": true,
	"secret": true, "clientsecret": true, "privatekey": true, "privkey": true, "otp": true,
	"totp": true, "recoverycode": true, "apikey": true, "sessionkey": true,
	"cred": true, "creds": true, "credentials": true,
}

// secretNameParts: a field whose normalised name contains one of these has its value redacted.
var secretNameParts = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey", "privatekey", "privkey",
	"credential", "authorization", "cookie", "sessionid", "bearer", "totp", "psk", "hmac", "signature",
	"sitekey", "license",
}

// NeverLogFields lists the normalised names that are never stored (documentation, tests).
func NeverLogFields() []string {
	out := make([]string, 0, len(neverLog))
	for k := range neverLog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normName(k string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// IsNeverLog reports whether a field is dropped entirely.
func IsNeverLog(key string) bool {
	n := normName(key)
	return neverLog[n] || strings.Contains(n, "csrf")
}

// IsSecretName reports whether a field's value must not be stored. Names ending in "key"
// are treated as secrets on purpose (API keys, key material); a harmless one is over-redacted.
func IsSecretName(key string) bool {
	n := normName(key)
	if strings.HasSuffix(n, "key") {
		return true
	}
	for _, p := range secretNameParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

const maxValue = 200

var (
	urlUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]*:[^/@\s]*@`)
	bearerRe    = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	pemBlock    = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]+)-----`)
)

func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { //do not cut a multi byte rune
		n--
	}
	return s[:n] + fmt.Sprintf("... (%d bytes)", len(s))
}

// RedactValue returns the storable form of a value of the named field.
func RedactValue(key, v string) string {
	if v == "" {
		return ""
	}
	if IsSecretName(key) {
		return "[redacted]"
	}
	t := strings.TrimSpace(v)
	if len(t) > 1 && (t[0] == '{' || t[0] == '[') {
		var j interface{}
		if json.Unmarshal([]byte(t), &j) == nil {
			out, _ := json.Marshal(redactJSON(j))
			return clip(cleanText(string(out)), 600)
		}
	}
	if strings.Contains(v, "-----BEGIN") {
		return summarisePEM(v)
	}
	v = urlUserinfo.ReplaceAllString(v, "${1}[redacted]@")
	v = bearerRe.ReplaceAllString(v, "$1 [redacted]")
	return clip(cleanText(v), maxValue)
}

func redactJSON(j interface{}) interface{} {
	switch t := j.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, v := range t {
			if IsNeverLog(k) {
				continue
			}
			if IsSecretName(k) {
				out[k] = "[redacted]"
				continue
			}
			out[k] = redactJSON(v)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, v := range t {
			out[i] = redactJSON(v)
		}
		return out
	case string:
		return RedactValue("value", t)
	}
	return j
}

// summarisePEM never keeps key material: a private key block is "[redacted]", certificates
// become a count and a short fingerprint of the text so a change is visible.
func summarisePEM(v string) string {
	certs := 0
	for _, k := range pemBlock.FindAllStringSubmatch(v, -1) {
		if strings.Contains(k[1], "PRIVATE") || strings.Contains(k[1], "ENCRYPTED") || strings.Contains(k[1], "SECRET") {
			return "[redacted: private key material]"
		}
		if k[1] == "CERTIFICATE" {
			certs++
		}
	}
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("[PEM %d certificate(s), %d bytes, sha256 %s]", certs, len(v), hex.EncodeToString(sum[:])[:16])
}

const maxDetailKeys = 32

// RedactMap applies the field rules to a whole detail map.
func RedactMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		if !IsNeverLog(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxDetailKeys {
		keys = keys[:maxDetailKeys]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[clip(cleanText(k), 64)] = RedactValue(k, in[k])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
