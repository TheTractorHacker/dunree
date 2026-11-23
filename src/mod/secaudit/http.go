package secaudit

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

/*
	HTTP glue: classify an admin API request into a security event and record it after the
	handler ran. One middleware in front of the admin mux (and one in front of the REST API)
	covers every handler, the same way the change history does; nothing here edits a handler.
*/

type route struct {
	Prefix   string
	Category string
}

// routes: the longest prefix wins. The event name is <category>.<rest of the path>, for
// example /api/trustedproxy/add -> trustedproxy.add, /api/blacklist/ip/add -> blacklist.ip.add.
// Accounts and sessions (/api/auth/, /api/users/) are audited by mod/auth in auth_audit.log.
var routes = []route{
	{"/api/deployrole/", "deployrole"},
	{"/api/crowdsec/", "crowdsec"},
	{"/api/trustedproxy/", "trustedproxy"},
	{"/api/access/", "access"},
	{"/api/blacklist/", "blacklist"},
	{"/api/whitelist/", "whitelist"},
	{"/api/quickban/", "quickban"},
	{"/api/adminallow/", "adminallow"},
	{"/api/destguard/", "destguard"},
	{"/api/netplan/", "netplan"},
	{"/api/proxy/", "proxy"},
	{"/api/securityheaders/", "securityheaders"},
	{"/api/errorpages/", "errorpages"},
	{"/api/waf/", "waf"},
	{"/api/abuse/", "abuse"},
	{"/api/botrules/", "botrules"},
	{"/api/headerrules/", "headerrules"},
	{"/api/basicauth/", "basicauth"},
	{"/api/sso/", "sso"},
	{"/api/apitoken/", "apitoken"},
	{"/api/conf/", "config"},
	{"/api/history/", "config.history"},
	{"/api/security/posture/", "posture"},
	{"/api/cluster/", "cluster"},
	{"/api/fleet/", "fleet"},
	{"/api/cert/", "cert"},
	{"/api/acme/", "acme"},
	{"/api/ech/", "ech"},
	{"/api/plugins/", "plugins"},
	{"/api/updater/start", "updater"},
	{"/api/tools/fwdproxy", "forwardproxy"},
	{"/api/webserv/", "webserv"},
	{"/api/streamprox/", "streamprox"},
	{"/api/redirect/", "redirect"},
	{"/api/pathrule/", "pathrule"},
	{"/api/zrok/", "tunnel"},
	{"/api/v1/", "restapi"},
}

// skip are read-only helpers that happen to use POST: they change nothing.
var skip = []string{
	"/api/proxy/testupstream", "/api/proxy/tlscheck", "/api/proxy/upstream/tlsinspect", "/api/proxy/script/test",
	"/api/proxy/sablier/test", "/api/proxy/templates/preview", "/api/proxy/ops/errorpreview", "/api/proxy/captcha/preview",
	"/api/waf/validate", "/api/security/posture/preview", "/api/cert/download", "/api/history/list", "/api/history/get",
	"/api/history/diff", "/api/abuse/remote/", "/api/cluster/status", "/api/cluster/nodes", "/api/fleet/node/info",
	"/api/fleet/node/probe", "/api/sso/zorxauth/customization/preview", "/api/conf/importcheck",
	"/api/errorpages/preview",
}

// always are recorded for any method: reading them hands out secrets.
var always = []string{"/api/conf/export"}

func hasPrefixAny(p string, list []string) bool {
	for _, s := range list {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

func mutating(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete || method == http.MethodPatch
}

var tlsTrustKeys = []string{"cabundle", "tlscabundlepem", "pins", "tlspinssha256", "tlsval", "skipcertvalidations"}
var rateKeys = []string{"ratenum", "ratelimit"}

// Classify returns the event name for a request, or false when the request is not recorded.
// params are the raw (not yet redacted) request parameters; they only decide the sub-event.
func Classify(method, path string, params map[string]string) (string, bool) {
	if !hasPrefixAny(path, always) && (!mutating(method) || hasPrefixAny(path, skip)) {
		return "", false
	}
	best := route{}
	for _, r := range routes {
		if strings.HasPrefix(path, r.Prefix) && len(r.Prefix) > len(best.Prefix) {
			best = r
		}
	}
	if best.Prefix == "" {
		return "", false
	}
	rest := strings.Trim(strings.TrimPrefix(path, best.Prefix), "/")
	if !strings.HasSuffix(best.Prefix, "/") { //exact style prefix such as /api/updater/start
		rest = ""
	}
	if best.Category == "restapi" {
		rest = strings.SplitN(rest, "/", 2)[0]
	}
	ev := best.Category
	if rest != "" {
		ev += "." + strings.ToLower(strings.ReplaceAll(rest, "/", "."))
	} else if best.Category == "adminallow" || best.Category == "deployrole" {
		ev += ".set"
	}
	if strings.HasPrefix(path, "/api/proxy/") {
		if paramMentions(params, tlsTrustKeys) {
			return "upstream.tls.change", true
		}
		if paramMentions(params, rateKeys) {
			return "ratelimit.change", true
		}
	}
	return ev, true
}

// paramMentions is true when a parameter name, or a JSON key inside a parameter value, is one of keys.
func paramMentions(params map[string]string, keys []string) bool {
	for k, v := range params {
		nk := normName(k)
		for _, w := range keys {
			if nk == w && v != "" {
				return true
			}
			if strings.HasPrefix(strings.TrimSpace(v), "{") && strings.Contains(strings.ToLower(v), "\""+w+"\"") {
				return true
			}
		}
	}
	return false
}

var targetFields = []string{"rootname", "ep", "domain", "host", "hostname", "name", "id", "uuid", "username", "ip", "cidr", "filename", "origin", "profile", "role"}

// Target picks the object a request is about.
func Target(params map[string]string) string {
	low := map[string]string{}
	for k, v := range params {
		low[strings.ToLower(k)] = v
	}
	for _, f := range targetFields {
		if v := strings.TrimSpace(low[f]); v != "" && !IsSecretName(f) {
			return v
		}
	}
	return ""
}

// ActorFunc resolves who is calling. false = not an authenticated admin request, nothing is recorded.
type ActorFunc func(r *http.Request) (string, bool)

type recorder struct {
	http.ResponseWriter
	status int
	head   bytes.Buffer
}

func (s *recorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *recorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.head.Len() < 256 {
		s.head.Write(b[:min(len(b), 256-s.head.Len())])
	}
	return s.ResponseWriter.Write(b)
}

func (s *recorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *recorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// the admin API reports most errors as 200 with {"error": "..."}
var errBody = regexp.MustCompile(`^\s*\{\s*"error"\s*:`)

// PeerIP is the TCP peer of the request. Forwarded headers are deliberately not used: the
// admin port is reached directly, and a header is something the caller controls.
func PeerIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

const maxBody = 64 << 10

// requestParams reads query, a small urlencoded form and a small JSON object body (top level
// keys). The body is put back for the handler. Multipart bodies (uploads) are never read.
func requestParams(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	ct := r.Header.Get("Content-Type")
	isForm := strings.HasPrefix(ct, "application/x-www-form-urlencoded")
	isJSON := strings.HasPrefix(ct, "application/json")
	if (isForm || isJSON) && r.Body != nil && r.ContentLength >= 0 && r.ContentLength <= maxBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		if err == nil && len(b) <= maxBody {
			if isForm {
				if vals, err := url.ParseQuery(string(b)); err == nil {
					for k, v := range vals {
						if len(v) > 0 {
							out[k] = v[0]
						}
					}
				}
			} else {
				var m map[string]json.RawMessage
				if json.Unmarshal(b, &m) == nil {
					for k, raw := range m {
						var s string
						if json.Unmarshal(raw, &s) == nil {
							out[k] = s
						} else {
							out[k] = string(raw)
						}
					}
				}
			}
		}
	}
	return out
}

// Middleware records classified requests after the handler ran. The outcome is "ok",
// "error" (status >= 400 or an {"error":...} body) or "denied" (401 / 403).
func (l *Logger) Middleware(actor ActorFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l == nil || !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := Classify(r.Method, r.URL.Path, nil); !ok && !(hasPrefixAny(r.URL.Path, always)) {
				next.ServeHTTP(w, r)
				return
			}
			who, ok := actor(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			params := requestParams(r)
			event, ok := Classify(r.Method, r.URL.Path, params)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			rec := &recorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			outcome := "ok"
			switch {
			case rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden:
				outcome = "denied"
			case rec.status >= 400 || errBody.Match(rec.head.Bytes()):
				outcome = "error"
			}
			detail := map[string]string{}
			for k, v := range params { //raw names: the never-log rules match on the field name itself
				detail[k] = v
			}
			detail["@method"], detail["@path"] = r.Method, r.URL.Path
			l.Record(Event{Actor: who, IP: PeerIP(r), Event: event, Target: Target(params), Outcome: outcome, Detail: detail})
		})
	}
}
