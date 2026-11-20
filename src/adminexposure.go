package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/adminallow"
	"imuslab.com/zoraxy/mod/destguard"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/secaudit"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	adminexposure.go

	Dual proxy plan, Phase 2 slice C: the destination guard for diagnostic tools and proxy rule targets
	(mod/destguard) and the optional admin listener allow-list (mod/adminallow). Everything is off until
	configured; both settings live in sys.db (settings table) so the change history records them.
*/

var (
	destGuardMgr  *destguard.Guard
	adminAllowMgr *adminallow.Manager
)

// initAdminExposure loads both settings. Must run after sysdb is open and before the admin listener serves.
func initAdminExposure() {
	g, err := destguard.New(sysdb)
	if err != nil {
		SystemWideLogger.PrintAndLog("destguard", "Destination restriction", err)
	}
	destGuardMgr = g
	destguard.SetDefault(g)
	if g.Restricting() {
		SystemWideLogger.Println("Destination restriction for diagnostic tools is on")
	}

	a, err := adminallow.New(sysdb)
	if err != nil {
		SystemWideLogger.PrintAndLog("adminallow", "Admin allow-list", err)
	}
	a.Logf = func(s string) { SystemWideLogger.PrintAndLog("adminallow", s, nil) }
	adminAllowMgr = a
	adminallow.InstallDialGuard(a, *webUIPort) //proxy rules may not dial the admin listener while the list is on
	if *resetAdminAllowList {
		if a.Active() {
			if err := a.Reset(); err != nil {
				SystemWideLogger.PrintAndLog("adminallow", "-reset_admin_allowlist could not clear the allow-list", err)
			} else {
				SystemWideLogger.PrintAndLog("adminallow", "-reset_admin_allowlist: the admin allow-list was cleared. Remove the flag from the start command", nil)
				secAudit.Record(secaudit.Event{Actor: "command line", Event: "adminallow.reset", Detail: map[string]string{"flag": "-reset_admin_allowlist"}})
			}
		} else {
			SystemWideLogger.Println("-reset_admin_allowlist: no admin allow-list is set, nothing to clear")
		}
	} else if a.Active() {
		SystemWideLogger.Println("Admin listener allow-list is on: " + strconv.Itoa(len(a.Settings().CIDRs)) + " entries")
	}
}

// adminHandlerWithAllowList puts the allow-list in front of the whole admin listener
func adminHandlerWithAllowList(h http.Handler) http.Handler {
	return adminAllowMgr.Middleware(h)
}

// validateBackendTarget refuses an upstream target outside the allowed backend list (no list = no check)
func validateBackendTarget(target string, requireTLS bool) error {
	if destGuardMgr == nil || !destGuardMgr.HasAllowList() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return destGuardMgr.ValidateBackendTLS(ctx, target, requireTLS)
}

type destGuardView struct {
	destguard.Settings
	Warnings []string `json:"warnings"`
}

// destGuardWarnings lists what the current settings would refuse among the rules that exist now,
// so turning the restriction on never silently takes an upstream offline.
func destGuardWarnings() []string { return destGuardFindings(true, true) }

// backendViolations lists the existing upstreams, virtual directories and stream proxy targets that the
// allowed backend list refuses (config import and history restore bypass the save-time check)
func backendViolations() []string { return destGuardFindings(true, false) }

func destGuardFindings(allowList, tools bool) []string {
	return destGuardFindingsDNS(allowList, tools, true)
}

// destGuardFindingsDNS is destGuardFindings; with dns false a target written as a host name is skipped instead of
// resolved (the security overview makes no network calls)
func destGuardFindingsDNS(allowList, tools, dns bool) []string {
	out := []string{}
	if destGuardMgr == nil || !((allowList && destGuardMgr.HasAllowList()) || (tools && destGuardMgr.Restricting())) {
		return out
	}
	deadline := time.Now().Add(4 * time.Second)
	check := func(rule, origin string, tls bool) {
		if len(out) >= 20 || time.Now().After(deadline) {
			return
		}
		host, port, ok := destguard.SplitTarget(origin)
		if !ok || host == "" {
			return
		}
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil && !dns {
			return
		}
		port = destguard.EffectivePort(port, tls)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if allowList && destGuardMgr.HasAllowList() {
			if _, err := destGuardMgr.Resolve(ctx, host, port, false); err != nil {
				out = append(out, rule+" -> "+origin+": not accepted as a proxy rule upstream ("+err.Error()+")")
				return
			}
		}
		if tools && destGuardMgr.Restricting() {
			if _, err := destGuardMgr.Resolve(ctx, host, port, true); err != nil {
				out = append(out, rule+" -> "+origin+": the uptime monitor and diagnostic tools will refuse it ("+err.Error()+")")
			}
		}
	}
	if dynamicProxyRouter != nil {
		dynamicProxyRouter.ProxyEndpoints.Range(func(_, v interface{}) bool {
			ep, ok := v.(*dynamicproxy.ProxyEndpoint)
			if !ok || ep == nil {
				return true
			}
			for _, u := range append(append([]*loadbalance.Upstream{}, ep.ActiveOrigins...), ep.InactiveOrigins...) {
				check(ep.RootOrMatchingDomain, u.OriginIpOrDomain, u.RequireTLS)
			}
			for _, vd := range ep.VirtualDirectories {
				check(ep.RootOrMatchingDomain+vd.MatchingPath, vd.Domain, vd.RequireTLS)
			}
			return true
		})
	}
	if streamProxyManager != nil {
		for _, sp := range streamProxyManager.Configs {
			if sp != nil {
				check("stream proxy "+sp.Name, sp.ProxyTargetAddr, false)
			}
		}
	}
	return out
}

// HandleDestGuardGet returns the destination restriction settings and what they would refuse now
func HandleDestGuardGet(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(destGuardView{Settings: destGuardMgr.Settings(), Warnings: destGuardWarnings()})
	utils.SendJSONResponse(w, string(js))
}

// HandleDestGuardSet (POST) replaces the settings: field "config" holds the JSON of destguard.Settings
func HandleDestGuardSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	var next destguard.Settings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	old := destGuardMgr.Settings()
	if err := destGuardMgr.Set(next); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	actor, _ := historyActor(r)
	cur := destGuardMgr.Settings()
	SystemWideLogger.PrintAndLog("destguard", "Destination restriction changed by "+actor+": tools restricted "+boolWord(old.RestrictTools)+" -> "+boolWord(cur.RestrictTools)+
		", allowed backends "+strconv.Itoa(len(old.AllowedBackends))+" -> "+strconv.Itoa(len(cur.AllowedBackends)), nil)
	utils.SendOK(w)
}

type adminAllowView struct {
	adminallow.Settings
	Active   bool   `json:"active"`
	Denied   uint64 `json:"denied"`
	YourAddr string `json:"yourAddr"`
	Listen   string `json:"listen"`
}

// HandleAdminAllowGet returns the allow-list, how often it refused since start, and the caller's own address
func HandleAdminAllowGet(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(adminAllowView{Settings: adminAllowMgr.Settings(), Active: adminAllowMgr.Active(), Denied: adminAllowMgr.Denied(),
		YourAddr: netutils.GetRequesterIPUntrusted(r), Listen: *webUIPort})
	utils.SendJSONResponse(w, string(js))
}

// HandleAdminAllowSet (POST) replaces the allow-list: field "config" holds the JSON of adminallow.Settings.
// A non-empty list that does not contain the caller's own address is refused (lock-out protection).
func HandleAdminAllowSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	var next adminallow.Settings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	//The address the allow-list middleware will see is the TCP peer, never a forwarded header
	if err := adminAllowMgr.Set(next, netutils.GetRequesterIPUntrusted(r)); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	actor, _ := historyActor(r)
	SystemWideLogger.PrintAndLog("adminallow", "Admin allow-list changed by "+actor+": "+strconv.Itoa(len(adminAllowMgr.Settings().CIDRs))+" entries", nil)
	utils.SendOK(w)
}

// ruleTargetsAdminListener reports whether any upstream or virtual directory of ep would reach the admin listener
func ruleTargetsAdminListener(ep *dynamicproxy.ProxyEndpoint) bool {
	return ruleTargetsAdminListenerDNS(ep, true)
}

// ruleTargetsAdminListenerDNS is ruleTargetsAdminListener; with dns false host names are not resolved
func ruleTargetsAdminListenerDNS(ep *dynamicproxy.ProxyEndpoint, dns bool) bool {
	local := localInterfaceAddrs()
	resolve := func(host string) []netip.Addr {
		if !dns {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		return ips
	}
	hit := func(origin string, tls bool) bool {
		host, port, ok := destguard.SplitTarget(origin)
		if !ok || host == "" {
			return false
		}
		if port == 0 {
			port = 80
			if tls {
				port = 443
			}
		}
		return adminallow.TargetsListener(*webUIPort, host, port, local, resolve)
	}
	for _, u := range append(append([]*loadbalance.Upstream{}, ep.ActiveOrigins...), ep.InactiveOrigins...) {
		if hit(u.OriginIpOrDomain, u.RequireTLS) {
			return true
		}
	}
	for _, vd := range ep.VirtualDirectories {
		if hit(vd.Domain, vd.RequireTLS) {
			return true
		}
	}
	return false
}

func localInterfaceAddrs() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}
