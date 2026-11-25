package dynamicproxy

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/TheTractorHacker/dunree/mod/crowdsec"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/captcha"
	"github.com/TheTractorHacker/dunree/mod/metrics"
	"github.com/TheTractorHacker/dunree/mod/netutils"
	"github.com/TheTractorHacker/dunree/mod/pathmatch"
)

// forwardedCandidates lists the resolved client address and every address the forwarding headers carry (at most 24)
func forwardedCandidates(r *http.Request, resolved string) []netip.Addr {
	out := make([]netip.Addr, 0, 8)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || len(out) >= 24 {
			return
		}
		if ap, err := netip.ParseAddrPort(raw); err == nil {
			out = append(out, ap.Addr())
			return
		}
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, a)
		}
	}
	add(resolved)
	for _, h := range []string{"X-Real-Ip", "CF-Connecting-IP", "Fastly-Client-IP"} {
		add(r.Header.Get(h))
	}
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(v, ",") {
			add(part)
		}
	}
	return out
}

/*
	CrowdSec bouncer glue (mod/crowdsec). Runs first in abuseBegin, so it covers every entry the auto-ban check covers
	(TLS path, plain HTTP path, secondary listeners and the default site). Off unless Option.CrowdSec is set and enabled:
	then it costs one nil check and one atomic load.

	The address that is looked up is GetClientIPForEndpoint, the same trusted-proxy aware resolution rate limits, ACLs
	and the auto-ban use: a forwarded header from a peer that is not trusted cannot change which decision applies.

	Log only mode never touches the request. Enforce mode: ban = 403 page or dropped connection (setting), captcha =
	the site's CAPTCHA challenge when the setting says so and the site has one (otherwise only logged, or a ban when the
	captcha fallback says so), fail-closed = same refusal as a ban. The block is recorded in the blocked-request log with
	the reason "crowdsec".

	The manager only decides (Check*). What really happened is known here, so this is where it is reported
	(Manager.Report): the counters and the activity feed of the CrowdSec page show the real outcome, not the intended one.
	The country lookup runs only for a request whose address has a decision.
*/

// crowdsecEvent describes the request for the activity feed (no headers, no query string)
func (router *Router) crowdsecEvent(r *http.Request, v crowdsec.Verdict) crowdsec.Event {
	ev := crowdsec.Event{Host: r.Host, Method: r.Method}
	if r.URL != nil {
		ev.Path = r.URL.Path
	}
	if v.IP.IsValid() && router.Option.GeodbStore != nil {
		if info, err := router.Option.GeodbStore.ResolveCountryCodeFromIP(v.IP.String()); err == nil && info != nil {
			ev.Country = info.CountryIsoCode
		}
	}
	return ev
}

// crowdsecCaptchaServed says why a request with an enforced captcha decision was served although the site has a
// CAPTCHA: the same conditions, in the same order, as captchaChallengeFor. "" = part of the challenge flow, not reported.
func (router *Router) crowdsecCaptchaServed(r *http.Request, sep *ProxyEndpoint) crowdsec.Outcome {
	cfg := sep.EffectiveCaptchaConfig()
	if !cfg.ChallengeAllowedOnPath(pathmatch.RequestTarget(r)) {
		return crowdsec.OutSkipped //outside the protected paths of this site
	}
	if ok, _ := captcha.CheckSessionReason(r, router.captchaSessionStore); ok {
		return crowdsec.OutPassed //the visitor solved the CAPTCHA earlier
	}
	return crowdsec.OutSkipped //a CAPTCHA exception of the site matches
}

// crowdsecBegin returns true when the request was answered here
func (router *Router) crowdsecBegin(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	cs := router.Option.CrowdSec
	if !cs.Active() {
		return false
	}
	var v crowdsec.Verdict
	peer := netutils.GetRequesterIPUntrusted(r)
	resolved := router.GetClientIPForEndpoint(r, sep)
	switch {
	case resolved == "":
		v = cs.CheckUnknown(abuseScope(sep))
	case resolved == peer:
		addr, err := netip.ParseAddr(resolved)
		if err != nil {
			v = cs.CheckUnknown(abuseScope(sep))
		} else {
			v = cs.Check(addr, abuseScope(sep))
		}
	default:
		//the address came from forwarded headers of a trusted proxy. Such a proxy does not strip what the client sent
		//(X-Real-Ip survives behind Cloudflare), so every address the request claims is looked up and the loopback and
		//protected-address exemptions do not apply to them.
		v = cs.CheckForwarded(forwardedCandidates(r, resolved), abuseScope(sep))
	}
	if !v.Matched {
		if v.Skip != "" { //a decision applies but the address is allowlisted or the site exempt: served, and shown as such
			cs.Report(v, v.DefaultOutcome(), router.crowdsecEvent(r, v))
		}
		return false
	}
	if !v.Enforce {
		cs.Report(v, crowdsec.OutLogOnly, router.crowdsecEvent(r, v))
		return false
	}
	detail := v.Detail()
	if v.Action == crowdsec.ActionCaptcha {
		if sep == nil || sep.EffectiveCaptchaConfig() == nil || !sep.EffectiveCaptchaConfig().IsConfigured() || router.captchaSessionStore == nil {
			if !v.Fallback {
				//no CAPTCHA on this site: a captcha decision is only logged, never turned into a block (unless the fallback says ban)
				cs.Report(v, crowdsec.OutNoCaptcha, router.crowdsecEvent(r, v))
				return false
			}
			detail += " (no CAPTCHA on this site, treated as a ban)"
		} else {
			flow := r.URL != nil && (captcha.IsVerifyPath(r.URL.Path) || captcha.IsAltchaChallengePath(r.URL.Path))
			if router.captchaChallengeFor(w, r, sep, "crowdsec", detail, "crowdsec") {
				if !flow { //the verification and the proof-of-work request belong to a challenge already counted
					cs.Report(v, crowdsec.OutChallenged, router.crowdsecEvent(r, v))
				}
				return true
			}
			cs.Report(v, router.crowdsecCaptchaServed(r, sep), router.crowdsecEvent(r, v))
			return false
		}
	}
	out := crowdsec.OutBlocked
	if v.Action == crowdsec.ActionClosed {
		out = crowdsec.OutFailClosed
	} else if v.Drop {
		out = crowdsec.OutDropped
	}
	cs.Report(v, out, router.crowdsecEvent(r, v))
	router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "crowdsec")
	if v.Drop {
		router.logRequestRule(r, false, 444, "crowdsec-dropped", r.Host, "", sep, detail, "crowdsec")
		dropConnection(w)
		return true
	}
	router.logRequestRule(r, false, http.StatusForbidden, "crowdsec", r.Host, "", sep, detail, "crowdsec")
	router.writeForbiddenPage(w, r, http.StatusForbidden, localizedPage(r, page_forbidden), false)
	return true
}
