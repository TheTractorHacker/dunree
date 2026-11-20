package deployrole

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

/*
	Forwarded header hardening.

	Applied once per request, at the entry of every proxy listener, when HardenActive():

	Peer is NOT a trusted proxy: every header that names a client, a protocol or a host
	on behalf of someone else is removed (a direct client can only speak for itself),
	X-Client-Cert-* identity headers included, and a fresh RFC 7239 Forwarded header
	describing this hop is set. Zoraxy then builds X-Forwarded-For / X-Real-Ip from the
	real TCP peer.

	Peer IS a trusted proxy: the client address is the right-most X-Forwarded-For entry that
	is not itself a trusted proxy (walking from the right), not the left-most entry which any
	client can write. Entries left of it are dropped, X-Real-Ip is set to the result (so every
	later consumer, access rules, rate limits, GeoIP, auth exceptions, sees the same address),
	the CDN headers are kept only when they hold a single IP address, and Forwarded is
	rebuilt from that verified chain plus this hop (an incoming Forwarded value is never kept).
*/

// clientIPHeaders name a client address
var clientIPHeaders = []string{
	"X-Forwarded-For", "Forwarded", "X-Real-Ip",
	"CF-Connecting-IP", "CF-Connecting-IPv6", "Fastly-Client-IP", "True-Client-IP", "X-Client-IP",
}

// singleIPHeaders hold exactly one address and are validated when they come from a trusted peer
var singleIPHeaders = []string{
	"X-Real-Ip", "CF-Connecting-IP", "CF-Connecting-IPv6", "Fastly-Client-IP", "True-Client-IP", "X-Client-IP",
}

// forwardedHostProtoPort are the de-facto standard "on behalf of" headers
var forwardedHostProtoPort = []string{"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port"}

const clientCertPrefix = "x-client-cert-"

// Result describes what Harden did
type Result struct {
	PeerTrusted bool
	PeerIP      string
	ClientIP    string // the resolved client address ("" for an unparsable peer)
	Stripped    bool   // client supplied headers were removed from an untrusted peer
}

// Harden applies the header policy to r. The caller decides whether it runs
// (Manager.HardenActive); isTrusted is the trusted proxy list lookup.
func Harden(r *http.Request, isTrusted func(string) bool) Result {
	if isTrusted == nil {
		isTrusted = func(string) bool { return false }
	}
	res := Result{}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		res.PeerIP = host
	} else {
		res.PeerIP = r.RemoteAddr
	}
	pip := net.ParseIP(res.PeerIP)
	if pip == nil {
		res.PeerIP = ""
	} else {
		res.PeerTrusted = isTrusted(res.PeerIP) || isTrusted(pip.String())
	}
	if r.Header == nil {
		r.Header = http.Header{}
	}
	trustedFn := func(ip string) bool { return isTrusted(ip) }

	if !res.PeerTrusted {
		res.Stripped = stripUntrusted(r)
		res.ClientIP = res.PeerIP
		if res.PeerIP != "" {
			r.Header.Set("Forwarded", forwardedElement(res.PeerIP, r))
		}
		return res
	}

	//Trusted peer. Keep what it sent, but only well formed values. Spellings it would not use
	//(underscore or non canonical names of the identity headers) can only come from a client behind it.
	stripUnderscoreVariants(r.Header)
	for _, h := range singleIPHeaders {
		if v := r.Header.Get(h); v != "" {
			if _, ok := parseHopIP(v); !ok {
				r.Header.Del(h)
			}
		}
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" && v != "http" && v != "https" {
		r.Header.Del("X-Forwarded-Proto")
	}
	if v := r.Header.Get("X-Forwarded-Port"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			r.Header.Del("X-Forwarded-Port")
		}
	}
	if v := r.Header.Get("X-Forwarded-Host"); v != "" && !plausibleHost(v) {
		r.Header.Del("X-Forwarded-Host")
	}

	//Client address: right-most untrusted X-Forwarded-For hop, then CDN headers, then X-Real-Ip, then the peer
	chain := []string{}
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for _, e := range strings.Split(line, ",") {
			if e = strings.TrimSpace(e); e != "" {
				chain = append(chain, e)
			}
		}
	}
	client, from := "", -1
	if i, ip := rightmostUntrusted(chain, trustedFn); i >= 0 {
		client, from = ip, i
	}
	if client == "" {
		for _, h := range []string{"CF-Connecting-IP", "CF-Connecting-IPv6", "Fastly-Client-IP", "X-Real-Ip"} {
			if ip, ok := parseHopIP(r.Header.Get(h)); ok {
				client = ip
				break
			}
		}
	}
	if client == "" {
		client = res.PeerIP
	}
	res.ClientIP = client

	switch {
	case from >= 0:
		r.Header.Set("X-Forwarded-For", strings.Join(chain[from:], ", "))
	case client == res.PeerIP:
		r.Header.Del("X-Forwarded-For")
	default:
		r.Header.Set("X-Forwarded-For", client)
	}
	if client != "" {
		r.Header.Set("X-Real-Ip", client)
	}

	var verified []string
	if from >= 0 {
		for _, e := range chain[from:] {
			if ip, ok := parseHopIP(e); ok {
				verified = append(verified, ip)
			}
		}
	}
	rebuildForwarded(r, verified, client, res.PeerIP)
	return res
}

// identityHeaderSet is every header name (lower case, "-" form) that speaks for a client, a protocol or a host
var identityHeaderSet = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range [][]string{clientIPHeaders, forwardedHostProtoPort} {
		for _, h := range l {
			m[strings.ToLower(h)] = true
		}
	}
	return m
}()

// isIdentityHeaderName reports whether a raw header key is one of the identity headers or an X-Client-Cert-*
// header, after folding case and treating "_" as "-". Many backends (CGI, WSGI, PHP, nginx with
// underscores_in_headers) map "X_Forwarded_For" onto the same variable as "X-Forwarded-For".
func isIdentityHeaderName(k string) bool {
	lk := strings.ToLower(strings.ReplaceAll(k, "_", "-"))
	return identityHeaderSet[lk] || strings.HasPrefix(lk, clientCertPrefix) || lk == "x-client-cert"
}

// stripUnderscoreVariants removes the spellings a trusted peer would never write: a header named like an
// identity header but with "_" in it, or a key that is not in canonical form. Returns whether any went.
func stripUnderscoreVariants(h http.Header) bool {
	stripped := false
	for k := range h {
		if (strings.Contains(k, "_") || k != http.CanonicalHeaderKey(k)) && isIdentityHeaderName(k) {
			delete(h, k)
			stripped = true
		}
	}
	return stripped
}

func stripUntrusted(r *http.Request) bool {
	stripped := false
	for k := range r.Header {
		if isIdentityHeaderName(k) {
			delete(r.Header, k) //every spelling: case variants and X_Forwarded_For style names too
			stripped = true
		}
	}
	return stripped
}

// rightmostUntrusted walks chain from the right and returns the index and address of
// the first entry that is not a trusted proxy. When every entry is trusted the left-most
// one is the client. An entry that is not an IP address ends the walk without a result:
// a trusted hop vouched for something we cannot interpret.
func rightmostUntrusted(chain []string, isTrusted func(string) bool) (int, string) {
	for i := len(chain) - 1; i >= 0; i-- {
		ip, ok := parseHopIP(chain[i])
		if !ok {
			return -1, ""
		}
		if !isTrusted(ip) {
			return i, ip
		}
		if i == 0 {
			return 0, ip
		}
	}
	return -1, ""
}

// parseHopIP reads one address as written in X-Forwarded-For style headers (optionally with
// port or IPv6 brackets). Lists, names, zones and anything else are rejected.
func parseHopIP(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, ", \t%\"") {
		return "", false
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

func plausibleHost(v string) bool {
	if len(v) > 255 {
		return false
	}
	for _, c := range v {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune(",;\"'\\<>/@", c) {
			return false
		}
	}
	return true
}

/* ---- RFC 7239 Forwarded ---- */

// rebuildForwarded replaces the Forwarded header with one built only from what was verified:
// one for= element per verified chain address (ending at the resolved client), then this hop.
// Whatever Forwarded value came in is discarded, a trusted peer may speak for X-Forwarded-For
// but is not trusted to write RFC 7239 elements (a client could have put them there).
func rebuildForwarded(r *http.Request, chain []string, client, peer string) {
	var parts []string
	for _, ip := range chain {
		if ip != "" {
			parts = append(parts, "for="+quoteForwarded(forValue(ip)))
		}
	}
	if len(parts) == 0 && client != "" && client != peer {
		parts = append(parts, "for="+quoteForwarded(forValue(client)))
	}
	if peer != "" {
		parts = append(parts, forwardedElement(peer, r))
	}
	if len(parts) == 0 {
		r.Header.Del("Forwarded")
		return
	}
	r.Header.Set("Forwarded", strings.Join(parts, ", "))
}

// forwardedElement describes the hop client -> this proxy: for=<peer>;proto=..;host=..
func forwardedElement(peer string, r *http.Request) string {
	f := "for=" + quoteForwarded(forValue(peer))
	if r.TLS != nil {
		f += ";proto=https"
	} else {
		f += ";proto=http"
	}
	if h := r.Host; h != "" && plausibleHost(h) {
		f += ";host=" + quoteForwarded(h)
	}
	return f
}

func forValue(ip string) string {
	if p := net.ParseIP(ip); p != nil && p.To4() == nil {
		return "[" + p.String() + "]"
	}
	return ip
}

const tokenChars = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func quoteForwarded(v string) string {
	for _, c := range v {
		if !strings.ContainsRune(tokenChars, c) {
			return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
		}
	}
	return v
}
