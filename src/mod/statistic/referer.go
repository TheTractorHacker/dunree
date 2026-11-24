package statistic

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

/*
	Referring site classification

	A request with a Referer header is recorded under that header, as before.
	A request WITHOUT one used to land under the empty key, shown as one line
	"Unknown or hidden". Dunree cannot invent a header the client never sent,
	but the other headers of the same request say why it is missing. They are
	read here and the request is counted under a sentinel key instead.

	Sentinel keys start with "~". A Referer header is a URL (or garbage). Markup
	is removed from it before it is stored, so the check that keeps a client
	value out of the sentinel namespace runs on the value AFTER that removal
	(StoredRefererKey, called by RecordRequest): a stored key that starts with
	"~" is kept only when it is exactly a key ClassifyReferer can produce and
	the markup removal changed nothing. Anything else gets the "~" escaped as
	"%7E". "<b></b>~direct" is therefore stored as "%7Edirect", not counted as
	a direct visit.

	What is stored: only the key below. For "~origin:" that is the scheme and
	host of the Origin header (never a path, a query string or a client address).
*/

const (
	RefererDirect       = "~direct"        //Sec-Fetch-Site: none (typed address, bookmark, link opened from an app)
	RefererHiddenPolicy = "~hidden-policy" //cross-site navigation or fetch whose Referer was withheld
	RefererSameSite     = "~same-site"     //same-origin / same-site request without a Referer
	RefererNonBrowser   = "~non-browser"   //no browser fetch metadata and a bot / library / empty User-Agent
	RefererUnknown      = "~unknown"       //nothing in the request explains it
	RefererInvalid      = "~invalid"       //a Referer header was sent, but nothing is left of it once markup is removed
	RefererOriginPrefix = "~origin:"       //Referer missing, Origin header named the source

	//Longest Origin value kept. A host name is at most 253 bytes; anything longer is not a real origin
	maxOriginKeyLength = 120
)

// RefererSource is what ClassifyReferer reads from a request. Capture it with
// RefererSourceFromRequest before any rule or script can change the headers.
type RefererSource struct {
	Referer      string
	Origin       string
	SecFetchSite string
	HasFetchMeta bool   //any Sec-Fetch-* header was sent
	UserAgent    string //as sent
	Host         string //host the client asked for (to tell same site from another site)
}

// RefererSourceFromRequest copies the headers the classification needs
func RefererSourceFromRequest(r *http.Request) RefererSource {
	if r == nil {
		return RefererSource{}
	}
	h := r.Header
	return RefererSource{
		Referer:      h.Get("Referer"),
		Origin:       h.Get("Origin"),
		SecFetchSite: h.Get("Sec-Fetch-Site"),
		HasFetchMeta: h.Get("Sec-Fetch-Site") != "" || h.Get("Sec-Fetch-Mode") != "" || h.Get("Sec-Fetch-Dest") != "" || h.Get("Sec-Fetch-User") != "",
		UserAgent:    h.Get("User-Agent"),
		Host:         r.Host,
	}
}

// ClassifyReferer returns the key a request is counted under in the Referer
// statistics: the Referer header when one was sent, otherwise a sentinel that
// says why there is none. It never returns "".
func ClassifyReferer(s RefererSource) string {
	if ref := strings.TrimSpace(s.Referer); ref != "" {
		if strings.TrimSpace(stripMarkup(ref)) == "" {
			//A header was sent, so this is not "no referrer"; it just holds no address
			return RefererInvalid
		}
		if strings.HasPrefix(ref, "~") {
			//Not a URL. Keep what was sent, but out of the sentinel namespace.
			//A "~" that only appears once markup is removed is caught by StoredRefererKey
			return "%7E" + ref[1:]
		}
		return ref
	}

	site := strings.ToLower(strings.TrimSpace(s.SecFetchSite))

	//The Origin header names the source of POSTs and cross-origin fetches even when the Referer is withheld
	if origin, host, ok := cleanOrigin(s.Origin); ok {
		if sameHost(host, s.Host) || site == "same-origin" {
			return RefererSameSite
		}
		return RefererOriginPrefix + origin
	}

	switch site {
	case "none":
		return RefererDirect
	case "same-origin", "same-site":
		return RefererSameSite
	case "cross-site":
		return RefererHiddenPolicy
	}

	if !s.HasFetchMeta && IsNonBrowserUserAgent(s.UserAgent) {
		return RefererNonBrowser
	}
	return RefererUnknown
}

// Markup is removed from every Referer before it is stored. The policy is built once; it is safe for concurrent use
var refererMarkupPolicy = bluemonday.StripTagsPolicy()

func stripMarkup(s string) string {
	return refererMarkupPolicy.Sanitize(s)
}

// StoredRefererKey turns RequestInfo.Referer (a Referer header, or a key from
// ClassifyReferer) into the key that is stored. Markup is removed first, then
// the sentinel check runs on the result, so no header value can pose as a
// classification key:
//
//   - "" (the caller knows nothing about the request) is stored as RefererUnknown
//   - a value that is only markup is stored as RefererInvalid
//   - a value that starts with "~" after the removal is kept only when the
//     removal changed nothing and it is a key ClassifyReferer produces (for
//     "~origin:" that means the rest passes the same checks as an Origin
//     header); otherwise the "~" is escaped as "%7E"
//
// It never returns "".
func StoredRefererKey(value string) string {
	if strings.TrimSpace(value) == "" {
		return RefererUnknown
	}
	key := strings.TrimSpace(stripMarkup(value))
	if key == "" {
		return RefererInvalid
	}
	if strings.HasPrefix(key, "~") && (key != value || !isClassifierKey(key)) {
		return "%7E" + key[1:]
	}
	return key
}

// isClassifierKey reports whether key is exactly one of the keys ClassifyReferer can return for a request without a usable Referer
func isClassifierKey(key string) bool {
	switch key {
	case RefererDirect, RefererHiddenPolicy, RefererSameSite, RefererNonBrowser, RefererUnknown, RefererInvalid:
		return true
	}
	if rest, found := strings.CutPrefix(key, RefererOriginPrefix); found {
		origin, _, ok := cleanOrigin(rest)
		return ok && origin == rest
	}
	return false
}

// IsRefererSentinel reports whether a stored Referer key is one of the
// classification keys rather than a header a client sent
func IsRefererSentinel(key string) bool {
	return strings.HasPrefix(key, "~")
}

// RefererLabel is the readable name of a stored Referer key, for exports. A
// real referrer is returned unchanged; the empty key is data recorded before
// the classification existed. The names hold no comma: the CSV export joins
// the referrers of a day with "," in one cell.
func RefererLabel(key string) string {
	switch {
	case key == "":
		return "Unknown (recorded before this version)"
	case key == RefererDirect:
		return "Direct visit (typed / bookmark / app)"
	case key == RefererHiddenPolicy:
		return "Hidden by the referring site's policy"
	case key == RefererSameSite:
		return "Same site"
	case key == RefererNonBrowser:
		return "Non-browser client (bot / API / script)"
	case key == RefererUnknown:
		return "Not sent (reason unknown)"
	case key == RefererInvalid:
		return "Unreadable referrer (markup only)"
	case strings.HasPrefix(key, RefererOriginPrefix):
		return strings.TrimPrefix(key, RefererOriginPrefix) + " (from the Origin header)"
	}
	return key
}

// cleanOrigin validates an Origin header value and returns it as scheme://host[:port]
// in lower case, plus the bare host. The value is client supplied: anything that is
// not a plain http(s) origin made of host name characters is refused, so the key
// can neither carry markup nor grow without bound.
func cleanOrigin(raw string) (origin string, host string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxOriginKeyLength || strings.EqualFold(raw, "null") {
		return "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	hostport := strings.ToLower(u.Host)
	for i := 0; i < len(hostport); i++ {
		c := hostport[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '[' || c == ']' || c == '_') {
			return "", "", false
		}
	}
	host = strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", false
	}
	return scheme + "://" + hostport, host, true
}

// sameHost compares an origin host with the Host header of the request (port ignored)
func sameHost(originHost string, requestHost string) bool {
	requestHost = strings.ToLower(strings.TrimSpace(requestHost))
	if requestHost == "" {
		return false
	}
	if u, err := url.Parse("//" + requestHost); err == nil && u.Hostname() != "" {
		requestHost = u.Hostname()
	}
	return strings.TrimSuffix(originHost, ".") == strings.TrimSuffix(requestHost, ".")
}

// Words that mark a User-Agent as a program rather than a browser a person drives.
// "bot" is not in this list: it is matched as the end of a word (hasBotToken), so
// that a phone of the brand CUBOT ("Android 10; CUBOT_X30") is not taken for a bot.
var nonBrowserUAMarks = []string{
	"crawl", "spider", "slurp", "scan", "curl", "wget", "python", "go-http-client", "java/", "okhttp",
	"axios", "node", "libwww", "httpclient", "http-client", "scrapy", "postman", "insomnia", "headless",
	"monitor", "uptime", "healthcheck", "health-check", "probe", "pingdom", "feed", "fetch", "ruby", "perl", "php",
	"powershell", "aiohttp", "httpx", "restsharp", "dart", "dunree", "zoraxy", "facebookexternalhit", "preview",
}

// IsNonBrowserUserAgent reports whether a User-Agent looks like a bot, a library, a
// script or an app rather than a web browser. Only used for requests that carry
// neither a Referer nor any Sec-Fetch-* header.
func IsNonBrowserUserAgent(ua string) bool {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" || !strings.HasPrefix(ua, "mozilla/") {
		//Every mainstream browser starts its User-Agent with "Mozilla/"
		return true
	}
	if hasBotToken(ua) {
		return true
	}
	for _, m := range nonBrowserUAMarks {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}

// Device brands whose name ends in "bot". Removed before the bot check
var botLikeDeviceNames = []string{"cubot"}

// hasBotToken reports whether a lower case User-Agent holds "bot" at the end of a
// word: "Googlebot/2.1", "bingbot;", "AhrefsBot)", "Slackbot-LinkExpanding",
// "my bot", ".../bot.html". "bot" followed by a letter, a digit or "_" is part of
// another word ("both", "bottle", "CUBOT_X30") and does not count.
func hasBotToken(ua string) bool {
	for _, name := range botLikeDeviceNames {
		ua = strings.ReplaceAll(ua, name, "")
	}
	for from := 0; ; {
		i := strings.Index(ua[from:], "bot")
		if i < 0 {
			return false
		}
		end := from + i + 3
		if end >= len(ua) {
			return true
		}
		c := ua[end]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return true
		}
		from = end
	}
}
