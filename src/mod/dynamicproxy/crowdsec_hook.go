package dynamicproxy

import (
	"net/http"
	"net/netip"
	"strings"

	"imuslab.com/zoraxy/mod/crowdsec"
	"imuslab.com/zoraxy/mod/metrics"
	"imuslab.com/zoraxy/mod/netutils"
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
	the site's CAPTCHA challenge when the setting says so and the site has one (otherwise only logged), fail-closed =
	same refusal as a ban. The block is recorded in the blocked-request log with the reason "crowdsec".
*/

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
	if !v.Matched || !v.Enforce {
		return false
	}
	detail := v.Detail()
	switch v.Action {
	case crowdsec.ActionCaptcha:
		if sep == nil || sep.EffectiveCaptchaConfig() == nil || !sep.EffectiveCaptchaConfig().IsConfigured() || router.captchaSessionStore == nil {
			return false //no CAPTCHA on this site: a captcha decision is only logged, never turned into a block
		}
		return router.captchaChallengeFor(w, r, sep, "crowdsec", detail, "crowdsec")
	}
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
