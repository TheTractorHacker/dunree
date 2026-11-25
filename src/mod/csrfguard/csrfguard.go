// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.

// Package csrfguard tells gorilla/csrf (v1.7.3 and later) how the browser reached the admin interface.
//
// Since the fix for GO-2025-3607 the library compares the Origin (or, without one, the Referer) of every
// request that changes something with the address it believes it is served at. It cannot know that
// address by itself: it assumes HTTPS unless told otherwise, and it only knows the Host header. This
// package gives it the facts per request, so that the installs that worked before keep working:
//
//   - plain HTTP admin interface (-webui_tls off): the request is marked with csrf.PlaintextHTTPRequest
//   - HTTPS admin interface: nothing is marked, the library checks as designed
//   - TLS ended by a reverse proxy in front of a plain HTTP admin interface: the browser says "https",
//     so the request is not marked and the library compares an https origin with the Host header
//   - the same proxy saying so itself (X-Forwarded-Proto: https): an http page is then refused
//   - a reverse proxy that replaces the Host header but sends X-Forwarded-Host: an Origin that is that
//     forwarded host counts as the own address
//   - a client that is not a browser (no Origin, no Referer, no Sec-Fetch-Site) over HTTPS: the Referer
//     requirement is not applied; cookie and token are still required
//
// The last two can be switched off (Strict). Hosts that are neither are listed by the administrator
// (TrustedOrigins). The decision itself stays in the library; this package never accepts a request.
//
// The library's own csrf.TrustedOrigins option is not used: it compares the host only and so accepts an
// http page of a listed host for an https admin interface (GO-2025-3884, no fixed version). A listed
// origin is handed to the library as the own address instead, so the scheme is compared as well.
package csrfguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
)

// Policy is how the admin interface may be reached.
type Policy struct {
	// TrustedOrigins are origins other than the one in the Host header from which the admin interface may
	// be used: "host", "host:port" (as the browser shows them, lower case), or with a scheme in front
	// ("https://host"), which then has to match too. Use ParseTrustedOrigins.
	TrustedOrigins []string
	// Strict applies the library's rules without the two allowances for existing installs: a request
	// over HTTPS without Origin needs a Referer, also from a script, and X-Forwarded-Host is ignored.
	Strict bool
	// FlagName is the name of the command line switch for TrustedOrigins, used in the refusal text.
	FlagName string
	// Logf receives one line per refused origin (at most one per origin and minute). May be nil.
	Logf func(format string, a ...any)

	mu      sync.Mutex
	lastLog map[string]time.Time
}

type ctxKey int

const originalURLKey ctxKey = iota

// original is what Describe changed on its copy of the request, given back before the handler runs.
type original struct {
	url  *url.URL
	host string
}

var safeMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true, http.MethodTrace: true}

// ParseTrustedOrigins reads a comma separated list of origins. Each entry is a host name or address,
// with a port when the browser shows one ("admin.example.com", "10.0.0.5:8443", "[::1]:8443"), or a full
// origin ("https://admin.example.com"): the scheme is kept and must match, the default port of the scheme
// is dropped, because a browser does not send it. Wildcards, paths and user names are errors.
func ParseTrustedOrigins(list string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(list, ",") {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		scheme := ""
		if i := strings.Index(entry, "://"); i >= 0 {
			scheme, entry = entry[:i], entry[i+3:]
			if scheme != "http" && scheme != "https" {
				return nil, fmt.Errorf("trusted origin %q: only http and https origins exist for the admin interface", strings.TrimSpace(raw))
			}
		}
		entry = strings.TrimSuffix(entry, "/")
		if entry == "" || strings.ContainsAny(entry, "/*?#@ \t\\") {
			return nil, fmt.Errorf("trusted origin %q: give a host name or address, with a port if the browser shows one (no path, no wildcard)", strings.TrimSpace(raw))
		}
		u, err := url.Parse("//" + entry)
		if err != nil || u.Host != entry || u.Hostname() == "" || (strings.Count(entry, ":") > 1 && !strings.HasPrefix(entry, "[")) {
			return nil, fmt.Errorf("trusted origin %q is not a host or host:port", strings.TrimSpace(raw))
		}
		if p := u.Port(); p != "" {
			if _, err := net.LookupPort("tcp", p); err != nil {
				return nil, fmt.Errorf("trusted origin %q: %q is not a port", strings.TrimSpace(raw), p)
			}
			if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
				entry = strings.TrimSuffix(entry, ":"+p)
			}
		} else if strings.HasSuffix(entry, ":") {
			return nil, fmt.Errorf("trusted origin %q: the port is missing", strings.TrimSpace(raw))
		}
		if scheme != "" {
			entry = scheme + "://" + entry
		}
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	return out, nil
}

// Options are the gorilla/csrf options that belong to the policy. Add them to csrf.Protect.
func (p *Policy) Options() []csrf.Option {
	return []csrf.Option{csrf.ErrorHandler(http.HandlerFunc(p.refuse))}
}

// Wrap returns next behind protect (the result of csrf.Protect with Options), with every request
// described to the library first. next receives the request unchanged apart from the context.
func (p *Policy) Wrap(protect func(http.Handler) http.Handler, next http.Handler) http.Handler {
	guarded := protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if orig, ok := r.Context().Value(originalURLKey).(original); ok {
			r = r.WithContext(r.Context())
			r.URL, r.Host = orig.url, orig.host
		}
		next.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guarded.ServeHTTP(w, p.Describe(r))
	})
}

// Describe returns r marked the way gorilla/csrf needs it (see the package comment). The request the
// caller holds is not changed.
func (p *Policy) Describe(r *http.Request) *http.Request {
	if safeMethods[r.Method] {
		return r
	}
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")
	var originURL *url.URL
	if origin != "" {
		originURL, _ = url.Parse(origin) // a broken Origin is refused by the library
	}

	plaintext := r.TLS == nil
	if plaintext {
		// The connection to us is plain HTTP. If the browser nevertheless says https, a proxy in front of
		// us ended TLS: let the library compare an https origin with the Host header.
		browserScheme := ""
		if originURL != nil {
			browserScheme = originURL.Scheme
		} else if origin == "" {
			if ref, err := url.Parse(referer); err == nil {
				browserScheme = ref.Scheme
			}
		}
		if browserScheme == "https" || strings.EqualFold(firstValue(r.Header.Get("X-Forwarded-Proto")), "https") {
			plaintext = false
		}
	}
	if !plaintext && !p.Strict && origin == "" && referer == "" && r.Header.Get("Sec-Fetch-Site") == "" {
		// Not a browser (a browser sends Origin with every request that is not GET or HEAD, and
		// Sec-Fetch-Site on top). A script has no Referer to give; cookie and token are still checked.
		plaintext = true
	}
	if plaintext {
		r = csrf.PlaintextHTTPRequest(r)
	}

	// An origin other than the Host header is handed to the library as the own address (so that it still
	// compares the scheme) in three cases: it is the Host header written differently (upper case, or with
	// the default port of the page's scheme, as "proxy_set_header Host $host:$server_port" sends it), the
	// administrator listed it, or a proxy that replaces the Host header says in X-Forwarded-Host that this
	// is the address the browser used. A page of another site cannot make a browser send that header to us.
	if originURL != nil && originURL.Host != "" && originURL.Host != r.Host {
		own := sameHost(originURL.Scheme, originURL.Host, r.Host) || p.trusted(originURL)
		if !own && !p.Strict {
			fwd := firstValue(r.Header.Get("X-Forwarded-Host"))
			own = fwd != "" && sameHost(originURL.Scheme, originURL.Host, fwd)
		}
		if own {
			u := *r.URL
			u.Host = originURL.Host
			r = r.WithContext(context.WithValue(r.Context(), originalURLKey, original{url: r.URL, host: r.Host}))
			r.URL = &u
		}
	} else if origin == "" && referer != "" {
		// Without Origin the library compares the Referer's host with the Host header, exactly. The same
		// host written differently is handed over as written in the Referer; the scheme is still checked.
		if ref, err := url.Parse(referer); err == nil && ref.Host != "" && ref.Host != r.Host && sameHost(ref.Scheme, ref.Host, r.Host) {
			r = r.WithContext(context.WithValue(r.Context(), originalURLKey, original{url: r.URL, host: r.Host}))
			r.Host = ref.Host
		}
	}
	return r
}

// sameHost says whether host (as a browser of a page with this scheme shows it) and other (a Host or
// X-Forwarded-Host header) name the same address: case is ignored, and so is the default port of the
// scheme, which a browser never writes but some proxies do.
func sameHost(scheme, host, other string) bool {
	return normalHost(scheme, host) == normalHost(scheme, other)
}

func normalHost(scheme, host string) string {
	host = strings.ToLower(host)
	switch strings.ToLower(scheme) {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	return host
}

// trusted says whether an origin is on the administrator's list.
func (p *Policy) trusted(origin *url.URL) bool {
	host := strings.ToLower(origin.Host)
	for _, entry := range p.TrustedOrigins {
		if i := strings.Index(entry, "://"); i >= 0 {
			if entry[:i] == strings.ToLower(origin.Scheme) && entry[i+3:] == host {
				return true
			}
		} else if entry == host {
			return true
		}
	}
	return false
}

// firstValue is the first entry of a forwarding header (the one the outermost proxy wrote).
func firstValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// refuse is the error handler given to the library. The first line is the library's own text
// ("Forbidden - <reason>"); for a refused origin a second line says what to do.
func (p *Policy) refuse(w http.ResponseWriter, r *http.Request) {
	reason := csrf.FailureReason(r)
	msg := fmt.Sprintf("%s - %v", http.StatusText(http.StatusForbidden), reason)
	if reason == csrf.ErrBadOrigin || reason == csrf.ErrBadReferer || reason == csrf.ErrNoReferer {
		from := r.Header.Get("Origin")
		if from == "" {
			from = r.Header.Get("Referer")
		}
		host, scheme := "", ""
		if u, err := url.Parse(from); err == nil {
			host, scheme = u.Host, u.Scheme
		}
		flagName := p.FlagName
		if flagName == "" {
			flagName = "csrf_trusted_origins"
		}
		switch {
		case reason == csrf.ErrNoReferer:
			msg += "\nThe request has neither an Origin nor a Referer header. A browser must send one of them to change settings over HTTPS."
		case host == "":
			msg += "\nThe request does not come from a page of this admin interface."
		case scheme == "http" && (r.TLS != nil || strings.EqualFold(firstValue(r.Header.Get("X-Forwarded-Proto")), "https")) &&
			(sameHost("https", host, r.Host) || p.trusted(&url.URL{Scheme: "https", Host: host}) ||
				(!p.Strict && strings.EqualFold(host, firstValue(r.Header.Get("X-Forwarded-Host"))))):
			msg += fmt.Sprintf("\nThe request comes from an http page of %q, but this admin interface is reached over https (its own listener, or the reverse proxy in front says so in X-Forwarded-Proto). Open the admin interface with https://", host)
		default:
			msg += fmt.Sprintf("\nThe request comes from a page at %q, but it arrived for %q. If %q is an address of this admin interface (for example behind a reverse proxy that changes the Host header), start the program with -%s=%s", host, r.Host, host, flagName, host)
		}
		p.logRefusal(host, r, reason)
	}
	http.Error(w, msg, http.StatusForbidden)
}

func (p *Policy) logRefusal(host string, r *http.Request, reason error) {
	if p.Logf == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	if p.lastLog == nil {
		p.lastLog = map[string]time.Time{}
	}
	if len(p.lastLog) > 256 {
		for k, t := range p.lastLog {
			if now.Sub(t) > time.Minute {
				delete(p.lastLog, k)
			}
		}
	}
	last, seen := p.lastLog[host]
	quiet := (seen && now.Sub(last) < time.Minute) || (!seen && len(p.lastLog) > 256)
	if !quiet {
		p.lastLog[host] = now
	}
	p.mu.Unlock()
	if quiet {
		return
	}
	flagName := p.FlagName
	if flagName == "" {
		flagName = "csrf_trusted_origins"
	}
	p.Logf("admin interface: refused %s %q from %s, page origin %q, Host %q (%v). If that origin is an address of this admin interface, add it with -%s",
		r.Method, r.URL.Path, r.RemoteAddr, host, r.Host, reason, flagName)
}
