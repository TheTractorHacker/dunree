package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/foleyit/dunree/mod/auth"
	"github.com/foleyit/dunree/mod/blocklog"
	"github.com/foleyit/dunree/mod/confpack"
	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/offline"
	"github.com/foleyit/dunree/mod/posture"
	"github.com/foleyit/dunree/mod/secaudit"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	secdashboard.go

	GET /api/security/overview: one request for the Security Center > Overview tab. Everything comes from data that is
	already in memory or a local file (uptime records, the live counters, the blocked request log, the security audit
	log, the cached posture evaluation, the certificate expiry cache of the Status page); there are no network calls,
	no DNS lookups of its own and every list is bounded. The answer is cached for 5 seconds (all viewers of the page
	share it). A section that fails is reported in "errors" and left out, the rest is still served.
	Closed for viewer accounts: it holds listener addresses, host names and client addresses.
*/

const (
	overviewCacheTTL  = 5 * time.Second
	ovMaxBackends     = 12
	ovMaxCerts        = 8
	ovMaxRoutes       = 5
	ovMaxRateRules    = 6
	ovMaxAudit        = 8
	ovMaxBlocked      = 8
	ovMaxTrusted      = 8
	ovMaxWarnings     = 25
	ovMaxReasons      = 6
	ovEvidenceChars   = 240
	ovMaxCrowdsecMsgs = 3
)

var ovCache struct {
	mu   sync.Mutex
	at   time.Time
	body []byte
}

func invalidateSecurityOverview() {
	ovCache.mu.Lock()
	ovCache.at = time.Time{}
	ovCache.body = nil
	ovCache.mu.Unlock()
}

// RegisterSecurityOverviewAPIs registers GET /api/security/overview on the admin router
func RegisterSecurityOverviewAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/security/overview", HandleSecurityOverview)
}

// HandleSecurityOverview serves the aggregated dashboard data
func HandleSecurityOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(securityOverviewJSON(time.Now())))
}

// securityOverviewJSON returns the cached body, building it when it is older than the TTL. Concurrent requests
// wait for one build instead of each building their own.
func securityOverviewJSON(now time.Time) []byte {
	ovCache.mu.Lock()
	defer ovCache.mu.Unlock()
	if ovCache.body != nil && now.Sub(ovCache.at) < overviewCacheTTL && now.After(ovCache.at.Add(-overviewCacheTTL)) {
		return ovCache.body
	}
	js, err := json.Marshal(buildSecurityOverview(now))
	if err != nil {
		js = []byte(`{"error":"could not build the overview"}`)
	}
	ovCache.body, ovCache.at = js, now
	return js
}

func clip(s string, n int) string {
	s = confpack.ScrubText(s) //a monitor URL or an HTTP error can carry user:pass@, ?token= or a bearer token
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

type ovWarning struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Fix      string `json:"fix"`
	Page     string `json:"page,omitempty"`
	Anchor   string `json:"anchor,omitempty"`
	Href     string `json:"href,omitempty"`
	Weight   int    `json:"weight"`
}

func statusRank(s posture.Status) int {
	switch s {
	case posture.StatusFail:
		return 0
	case posture.StatusWarn:
		return 1
	}
	return 2
}

func buildSecurityOverview(now time.Time) map[string]interface{} {
	out := map[string]interface{}{"generated": now.Unix(), "ttlSeconds": int(overviewCacheTTL / time.Second)}
	var failed []string
	sect := func(name string, fn func()) {
		defer func() {
			if rec := recover(); rec != nil {
				failed = append(failed, name)
				if SystemWideLogger != nil {
					SystemWideLogger.Println("[security overview] section " + name + " failed")
				}
			}
		}()
		fn()
	}

	glance := buildGlance(now) //uptime records, certificate expiries, traffic rates: all cached or in memory
	var report posture.Overview
	havePosture := false
	sect("posture", func() {
		//Own evaluation (no actions, no host name lookups) instead of the posture page's cached one, which resolves names
		e := getPostureEngine()
		report = posture.Overview{Report: e.Checks.Evaluate(collectPostureFactsDNS(false)), Disclaimer: posture.Disclaimer}
		havePosture = true
	})

	sect("status", func() {
		st := map[string]interface{}{"version": PRODUCT_VERSION, "uptimeSeconds": now.Unix() - bootTime, "offline": offline.Enabled()}
		listeners := []map[string]interface{}{}
		if dynamicProxyRouter != nil {
			st["proxyRunning"] = dynamicProxyRouter.Running
			o := dynamicProxyRouter.Option
			listeners = append(listeners, map[string]interface{}{"name": "Reverse proxy", "addr": ":" + strconv.Itoa(o.Port), "tls": o.UseTls})
			if o.ListenOnPort80 {
				addr := o.HttpListenAddr
				if addr == "" {
					addr = ":80"
				}
				listeners = append(listeners, map[string]interface{}{"name": "HTTP redirect", "addr": addr, "tls": false})
			}
		} else {
			st["proxyRunning"] = false
		}
		listeners = append(listeners, map[string]interface{}{"name": "Admin panel", "addr": *webUIPort, "tls": *webUITLSMode != "off" && *webUITLSMode != ""})
		st["listeners"] = listeners
		if clusterMgr != nil {
			st["clusterRole"] = clusterMgr.Role()
		}
		out["status"] = st
	})

	sect("role", func() {
		v := deployRoleStatus()
		w := v.Warnings
		if len(w) > 3 {
			w = w[:3]
		}
		for i := range w {
			w[i] = clip(w[i], ovEvidenceChars)
		}
		out["role"] = map[string]interface{}{"role": string(v.Role), "hardenActive": v.HardenActive, "peerGateActive": v.PeerGateActive,
			"trustedProxies": v.TrustedProxies, "gateRejected": v.GateRejected, "warnings": w}
	})

	sect("backends", func() { out["backends"] = ovBackends(glance, uptimeMonitor != nil) })

	sect("routes", func() {
		r := map[string]interface{}{}
		total, enabled, auths, limited := 0, 0, 0, 0
		waf := map[string]int{}
		if dynamicProxyRouter != nil {
			dynamicProxyRouter.ProxyEndpoints.Range(func(_, v interface{}) bool {
				ep, ok := v.(*dynamicproxy.ProxyEndpoint)
				if !ok || ep == nil || ep == dynamicProxyRouter.Root || ep.ProxyType == dynamicproxy.ProxyTypeRoot {
					return true
				}
				total++
				if !ep.Disabled {
					enabled++
					if authMethodName(ep) != "none" {
						auths++
					}
					if ep.RequireRateLimit {
						limited++
					}
				}
				return true
			})
			for _, c := range dynamicProxyRouter.WAFCoverage() {
				if !c.IsRoot {
					waf[c.Mode]++
				}
			}
			if root := dynamicProxyRouter.Root; root != nil {
				r["defaultSite"], _ = defaultSiteName(root.DefaultSiteOption)
			}
		}
		r["total"], r["enabled"], r["disabled"], r["withAuth"], r["rateLimited"], r["waf"] = total, enabled, total-enabled, auths, limited, waf
		top := []map[string]interface{}{}
		for _, ru := range liveTune.query(now, "5m").Rules {
			if len(top) >= ovMaxRoutes || ru.Stats.Avg <= 0 {
				break
			}
			top = append(top, map[string]interface{}{"domain": clip(ru.Domain, 120), "avgRps": round2(ru.Stats.Avg), "peakRps": round2(ru.Stats.Peak)})
		}
		r["busiest"] = top
		out["routes"] = r
	})

	sect("certs", func() {
		list := glanceCerts.get()
		expired, soon := 0, 0
		items := []map[string]interface{}{}
		for i, c := range list {
			days := int(c.NotAfter.Sub(now).Hours() / 24)
			if c.NotAfter.Before(now) {
				expired++
			} else if days <= 30 {
				soon++
			}
			if i < ovMaxCerts {
				items = append(items, map[string]interface{}{"name": clip(c.Name, 120), "daysLeft": days, "expired": c.NotAfter.Before(now)})
			}
		}
		issues := []string{}
		if havePosture {
			for _, c := range report.Checks {
				if (strings.HasPrefix(c.ID, "cert.") || c.ID == "ech.config") && (c.Status == posture.StatusFail || c.Status == posture.StatusWarn) && len(c.Evidence) > 0 {
					issues = append(issues, clip(c.Evidence[0], ovEvidenceChars))
				}
			}
		}
		if len(issues) > 5 {
			issues = issues[:5]
		}
		out["certs"] = map[string]interface{}{"total": len(list), "expired": expired, "expiringSoon": soon, "items": items, "issues": issues}
	})

	sect("crowdsec", func() {
		if crowdsecMgr == nil {
			out["crowdsec"] = map[string]interface{}{"enabled": false, "state": "off"}
			return
		}
		s := crowdsecMgr.Status()
		warns := []string{}
		for _, x := range s.Warnings {
			if len(warns) < ovMaxCrowdsecMsgs {
				warns = append(warns, clip(x, ovEvidenceChars))
			}
		}
		c := map[string]interface{}{"enabled": s.Enabled, "mode": s.Mode, "state": s.State, "keySet": s.KeySet, "cacheSize": s.CacheSize,
			"enforced": s.Enforced, "logOnly": s.LogOnly, "consecutiveErrors": s.ConsecutiveErrors, "totalErrors": s.TotalErrors,
			"failClosedActive": s.FailClosedActive, "lastError": clip(s.LastError, ovEvidenceChars), "warnings": warns}
		if s.LastSuccess != nil {
			c["lastSuccess"] = s.LastSuccess.Unix()
		}
		out["crowdsec"] = c
	})

	sect("ratelimit", func() {
		res := liveTune.query(now, "5m")
		limited, dry, enforced := 0, 0, 0
		var deniedEnforced, wouldDeny uint64
		items := []map[string]interface{}{}
		type row struct {
			domain string
			lim    TuneLimiter
		}
		rows := []row{}
		for _, ru := range res.Rules {
			if !ru.Limiter.Enabled {
				continue
			}
			limited++
			if ru.Limiter.DryRun {
				dry++
				wouldDeny += ru.Limiter.Denied
			} else {
				enforced++
				deniedEnforced += ru.Limiter.Denied
			}
			rows = append(rows, row{ru.Domain, ru.Limiter})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].lim.Denied > rows[j].lim.Denied })
		for i, rw := range rows {
			if i >= ovMaxRateRules {
				break
			}
			items = append(items, map[string]interface{}{"domain": clip(rw.domain, 120), "rate": rw.lim.Rate, "dryRun": rw.lim.DryRun, "denied": rw.lim.Denied})
		}
		out["ratelimit"] = map[string]interface{}{"window": res.Window, "stale": res.Stale, "limitedRules": limited, "dryRunRules": dry, "enforcedRules": enforced,
			"deniedEnforced": deniedEnforced, "wouldDeny": wouldDeny, "items": items}
	})

	sect("traffic", func() {
		t := map[string]interface{}{"requestsPerMin": round2(glance.Rates.RequestsPerMin), "blockedPerMin": round2(glance.Rates.BlockedPerMin),
			"errorsPerMin": round2(glance.Rates.ErrorsPerMin), "series": fixedSeries(glance.Rates.Series, 30), "blockedSeries": fixedSeries(glance.Rates.BlockedSeries, 30), "blockedToday": glance.BlockedToday}
		if statisticCollector != nil {
			total := statisticCollector.GetCurrentDailySummary().TotalRequest
			t["totalToday"] = total
			allowed := total - glance.BlockedToday
			if allowed < 0 {
				allowed = 0
			}
			t["allowedToday"] = allowed
		}
		if blockLog != nil {
			sm := blockLog.Summarize(blocklog.Filter{}, now)
			reasons := sm.Reasons
			if len(reasons) > ovMaxReasons {
				reasons = reasons[:ovMaxReasons]
			}
			hourly := make([]int, len(sm.Hourly))
			for i, b := range sm.Hourly {
				hourly[i] = b.N
			}
			t["blockLog"] = map[string]interface{}{"enabled": sm.Enabled, "kept": sm.Kept, "reasons": reasons, "hourly": hourly, "truncated": sm.Truncated}
		}
		out["traffic"] = t
	})

	sect("events", func() {
		ev := map[string]interface{}{"auditAvailable": secAudit != nil}
		audit := []map[string]interface{}{}
		if secAudit != nil {
			if page, err := secAudit.List(secaudit.Query{Limit: ovMaxAudit}); err == nil {
				for _, e := range page.Entries {
					audit = append(audit, map[string]interface{}{"time": e.Unix, "actor": clip(e.Actor, 60), "event": clip(e.Event, 80), "target": clip(e.Target, 100), "outcome": e.Outcome})
				}
			}
		}
		ev["audit"] = audit
		blocked := []map[string]interface{}{}
		if blockLog != nil {
			for _, e := range blockLog.List(blocklog.Filter{}, 0, ovMaxBlocked).Items {
				blocked = append(blocked, map[string]interface{}{"time": e.Time, "ip": clip(e.IP, 64), "host": clip(e.Host, 120), "reason": e.Reason, "status": e.Status})
			}
		}
		ev["blocked"] = blocked
		out["events"] = ev
	})

	sect("trusted", func() {
		t := map[string]interface{}{"count": 0, "entries": []map[string]string{}}
		if accessController != nil {
			list := accessController.ListTrustedProxies()
			sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
			entries := []map[string]string{}
			trustAll, broad := false, 0
			for _, tp := range list {
				if p, ok := parsePrefixAny(tp.IP); ok {
					if p.Bits() == 0 {
						trustAll = true
					} else if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
						broad++
					}
				}
				if len(entries) < ovMaxTrusted {
					entries = append(entries, map[string]string{"ip": clip(tp.IP, 64), "desc": clip(tp.Desc, 80)})
				}
			}
			t["count"], t["entries"], t["trustAll"], t["broad"] = len(list), entries, trustAll, broad
			if ar, err := accessController.GetGlobalAccessRule(); err == nil {
				t["gating"] = ar.TrustProxyHeadersOnly
			}
		}
		if dynamicProxyRouter != nil {
			t["sanitiseClientIP"] = dynamicProxyRouter.Option.SanitiseClientIPHeaders
		}
		t["hardenActive"] = deployRoleMgr != nil && deployRoleMgr.HardenActive()
		out["trusted"] = t
	})

	sect("warnings", func() {
		warns := []ovWarning{}
		counts := map[posture.Status]int{}
		if havePosture {
			for _, c := range report.Checks {
				counts[c.Status]++
				if c.Status != posture.StatusFail && c.Status != posture.StatusWarn && c.Status != posture.StatusUnknown {
					continue
				}
				ev := ""
				if len(c.Evidence) > 0 {
					ev = c.Evidence[0]
				}
				fix := c.Remediation.Label
				if fix == "" {
					fix = c.Remediation.Hint
				}
				warns = append(warns, ovWarning{ID: c.ID, Title: clip(c.Title, 160), Status: string(c.Status), Severity: c.Severity, Evidence: clip(ev, ovEvidenceChars),
					Fix: clip(fix, 160), Page: c.Remediation.Page, Anchor: c.Remediation.Anchor, Href: c.Remediation.Href, Weight: c.Weight})
			}
			sort.SliceStable(warns, func(i, j int) bool {
				a, b := warns[i], warns[j]
				if ra, rb := statusRank(posture.Status(a.Status)), statusRank(posture.Status(b.Status)); ra != rb {
					return ra < rb
				}
				if a.Weight != b.Weight {
					return a.Weight > b.Weight
				}
				return a.ID < b.ID
			})
			out["score"] = map[string]interface{}{"value": report.Score.Value, "grade": report.Score.Grade, "label": report.Score.Label, "provisional": report.Score.Provisional}
		}
		more := 0
		if len(warns) > ovMaxWarnings {
			more = len(warns) - ovMaxWarnings
			warns = warns[:ovMaxWarnings]
		}
		out["warnings"] = map[string]interface{}{"items": warns, "more": more, "checked": len(report.Checks), "ok": counts[posture.StatusOK],
			"notApplicable": counts[posture.StatusNA], "available": havePosture}
	})

	sort.Strings(failed)
	out["errors"] = append([]string{}, failed...)
	return out
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// ovBackends is the backend health card: down ones first, then the slowest, at most ovMaxBackends
func ovBackends(g GlanceData, monitored bool) map[string]interface{} {
	down := 0
	list := append([]glanceUp{}, g.Upstreams...)
	for _, u := range g.Upstreams {
		if !u.Online {
			down++
		}
	}
	if len(g.UpstreamsDown) > down {
		down = len(g.UpstreamsDown)
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Online != list[j].Online {
			return !list[i].Online
		}
		return list[i].LatencyMs > list[j].LatencyMs
	})
	if len(list) > ovMaxBackends {
		list = list[:ovMaxBackends]
	}
	items := []map[string]interface{}{}
	for _, u := range list {
		items = append(items, map[string]interface{}{"name": clip(u.Name, 120), "url": clip(u.URL, 160), "online": u.Online, "status": u.StatusCode, "latencyMs": u.LatencyMs})
	}
	return map[string]interface{}{"monitored": monitored, "total": g.UpstreamsTotal, "down": down, "items": items}
}

// fixedSeries gives a chart series a fixed length (zeros when the collector is not running)
func fixedSeries(in []int64, n int) []int64 {
	out := make([]int64, n)
	copy(out, in)
	return out
}
