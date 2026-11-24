package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/foleyit/dunree/mod/auth"
	"github.com/foleyit/dunree/mod/deployrole"
	"github.com/foleyit/dunree/mod/destguard"
	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/dynamicproxy/loadbalance"
	"github.com/foleyit/dunree/mod/netplan"
	"github.com/foleyit/dunree/mod/posture"
	"github.com/foleyit/dunree/mod/secaudit"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	netplanapi.go

	Security Center > Network plan (mod/netplan, docs/enterprise-dual-proxy-plan.md phase 4). The plan is a document the
	administrator writes down (proxy, management and application networks, expected upstream proxies, permitted
	backends and ports, who may administer). Dunree compares the real configuration with it through the posture checks
	netplan.* (mod/posture/checks_netplan.go) and can export firewall recommendations. It applies nothing to any firewall.

	GET  /api/netplan/get      the plan, and what the posture checks find against it
	POST /api/netplan/set      config (JSON of netplan.Settings), replaces the plan; empty plan clears it
	GET  /api/netplan/policy   the recommendations as JSON {markdown}; ?download=1 as a .md attachment

	All closed for viewer accounts (internal topology), POST needs the CSRF token like every admin POST, changes are
	recorded by the security audit log (netplan.set) and the change history (settings table, key "netplan").
*/

var (
	netplanMgr *netplan.Manager
	netplanMu  sync.Mutex
)

// getNetPlan returns the plan manager, loading it from sys.db on first use
func getNetPlan() *netplan.Manager {
	netplanMu.Lock()
	defer netplanMu.Unlock()
	if netplanMgr == nil {
		if sysdb != nil {
			sysdb.NewTable(netplan.DBTable)
		}
		m, err := netplan.New(sysdb)
		if err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("netplan", "Network plan", err)
		}
		netplanMgr = m
	}
	return netplanMgr
}

// RegisterNetPlanAPIs registers the network plan APIs on the admin router
func RegisterNetPlanAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/netplan/get", HandleNetPlanGet)
	authRouter.HandleFunc("/api/netplan/set", HandleNetPlanSet)
	authRouter.HandleFunc("/api/netplan/policy", HandleNetPlanPolicy)
}

func parsePrefixAny(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		a = a.WithZone("")
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func deployRoleName() string {
	if deployRoleMgr != nil {
		if r := deployRoleMgr.Settings().Role; r != "" {
			return string(r)
		}
	}
	return string(deployrole.RoleStandalone)
}

// collectBackends lists the backend destinations of every enabled proxy rule, virtual directory, the default
// site and the stream proxies. Names are never resolved. Bounded.
func collectBackends() (out []posture.BackendFact, unresolved int) {
	const maxBackends = 1000
	add := func(rule, origin string, tls bool) {
		if len(out) >= maxBackends {
			return
		}
		host, port, ok := destguard.SplitTarget(origin)
		if !ok || host == "" { //unreadable or a unix socket: not a network destination
			return
		}
		b := posture.BackendFact{Rule: rule, Host: host, Port: destguard.EffectivePort(port, tls)}
		if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			b.Addr = a.WithZone("").Unmap()
		} else {
			unresolved++
		}
		out = append(out, b)
	}
	addEndpoint := func(ep *dynamicproxy.ProxyEndpoint) {
		if ep == nil || ep.Disabled {
			return
		}
		for _, u := range append(append([]*loadbalance.Upstream{}, ep.ActiveOrigins...), ep.InactiveOrigins...) {
			if u != nil {
				add(ep.RootOrMatchingDomain, u.OriginIpOrDomain, u.RequireTLS)
			}
		}
		for _, vd := range ep.VirtualDirectories {
			if vd != nil {
				add(ep.RootOrMatchingDomain+vd.MatchingPath, vd.Domain, vd.RequireTLS)
			}
		}
	}
	if dynamicProxyRouter != nil {
		root := dynamicProxyRouter.Root
		dynamicProxyRouter.ProxyEndpoints.Range(func(_, v interface{}) bool {
			if ep, ok := v.(*dynamicproxy.ProxyEndpoint); ok && ep != root {
				addEndpoint(ep)
			}
			return true
		})
		if root != nil && root.DefaultSiteOption == dynamicproxy.DefaultSite_ReverseProxy {
			addEndpoint(root)
		}
	}
	if streamProxyManager != nil {
		for _, sp := range streamProxyManager.Configs {
			if sp != nil {
				add("stream proxy "+sp.Name, sp.ProxyTargetAddr, false)
			}
		}
	}
	return out, unresolved
}

// collectNetPlanFacts gathers the facts of the network plan checks: the saved plan and the real configuration
// it is compared with. No network access.
func collectNetPlanFacts() *posture.NetPlanFacts {
	s := getNetPlan().Settings()
	n := &posture.NetPlanFacts{Declared: s.Declared(), Role: deployRoleName()}
	n.ProxyCIDRs = netplan.ParsePrefixes(s.ProxyVLAN.CIDRs)
	n.MgmtCIDRs = netplan.ParsePrefixes(s.ManagementVLAN.CIDRs)
	n.AppCIDRs = netplan.ParsePrefixes(s.ApplicationVLAN.CIDRs)
	n.TrustedUpstream = netplan.ParsePrefixes(s.TrustedProxies)
	n.AdminAccess = netplan.ParsePrefixes(s.AdminAccess)
	for _, p := range netplan.ParsePorts(s.AppPorts) {
		n.AppPorts = append(n.AppPorts, posture.PlanPorts{Lo: p.Lo, Hi: p.Hi})
	}
	for _, d := range netplan.ParseDests(s.AllowedBackends) {
		pd := posture.PlanDest{Prefix: d.Prefix}
		for _, p := range d.Ports {
			pd.Ports = append(pd.Ports, posture.PlanPorts{Lo: p.Lo, Hi: p.Hi})
		}
		n.AllowedDecl = append(n.AllowedDecl, pd)
	}
	if accessController != nil {
		for _, tp := range accessController.ListTrustedProxies() {
			if p, ok := parsePrefixAny(tp.IP); ok {
				n.ActualTrusted = append(n.ActualTrusted, p)
			}
		}
	}
	if adminAllowMgr != nil {
		for _, c := range adminAllowMgr.Settings().CIDRs {
			if p, ok := parsePrefixAny(c); ok {
				n.AdminAllow = append(n.AdminAllow, p)
			}
		}
	}
	if destGuardMgr != nil {
		n.GuardHasList = destGuardMgr.HasAllowList()
		for _, e := range destGuardMgr.Settings().AllowedBackends {
			if p, _, err := destguard.EntryParts(e); err == nil {
				n.GuardEntries = append(n.GuardEntries, p)
			}
		}
	}
	n.Backends, n.Unresolved = collectBackends()
	return n
}

func adminPortNumber() int {
	addr := strings.TrimSpace(*webUIPort)
	if _, p, err := net.SplitHostPort(addr); err == nil {
		addr = p
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(addr, ":"))
	return n
}

// netplanContext is what the export needs from the running instance
func netplanContext() netplan.Context {
	c := netplan.Context{Role: deployRoleName(), AdminPort: adminPortNumber(), AdminListen: *webUIPort, Now: time.Now()}
	if dynamicProxyRouter != nil {
		if p := dynamicProxyRouter.Option.Port; p > 0 {
			c.ProxyPorts = append(c.ProxyPorts, p)
		}
		if dynamicProxyRouter.Option.ListenOnPort80 {
			c.ProxyPorts = append(c.ProxyPorts, 80)
		}
	}
	backends, _ := collectBackends()
	seen := map[string]bool{}
	for _, b := range backends {
		key := b.Rule + "|" + b.Host + "|" + strconv.Itoa(b.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		c.Backends = append(c.Backends, netplan.Backend{Rule: b.Rule, Host: b.Host, Port: b.Port})
	}
	return c
}

type netplanFinding struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Status      posture.Status      `json:"status"`
	Severity    string              `json:"severity"`
	Evidence    []string            `json:"evidence"`
	Why         string              `json:"why"`
	Remediation posture.Remediation `json:"remediation"`
}

type netplanView struct {
	Settings    netplan.Settings `json:"settings"`
	Declared    bool             `json:"declared"`
	Disclaimer  string           `json:"disclaimer"`
	Role        string           `json:"role"`
	AdminListen string           `json:"adminListen"`
	Findings    []netplanFinding `json:"findings"` // the netplan.* checks (every status, so the page can say what did not apply)
	Related     []netplanFinding `json:"related"`  // existing checks that bear on segmentation, shown for context, not repeated
}

// the existing posture checks that the validation list points to instead of repeating them
var netplanRelatedChecks = []string{"upstream.tls_verify", "admin.rule_target", "exposure.backend_allowlist", "exposure.dest_restrict", "admin.bind", "access.trusted_proxy_gating"}

func buildNetPlanView() netplanView {
	v := netplanView{Settings: getNetPlan().Settings(), Disclaimer: netplan.Disclaimer, Role: deployRoleName(), AdminListen: *webUIPort,
		Findings: []netplanFinding{}, Related: []netplanFinding{}}
	v.Declared = v.Settings.Declared()
	rep := getPostureEngine().Checks.Evaluate(collectPostureFacts())
	rel := map[string]bool{}
	for _, id := range netplanRelatedChecks {
		rel[id] = true
	}
	for _, c := range rep.Checks {
		f := netplanFinding{ID: c.ID, Title: c.Title, Status: c.Status, Severity: c.Severity, Evidence: c.Evidence, Why: c.Why, Remediation: c.Remediation}
		switch {
		case strings.HasPrefix(c.ID, "netplan."):
			v.Findings = append(v.Findings, f)
		case rel[c.ID]:
			v.Related = append(v.Related, f)
		}
	}
	return v
}

// HandleNetPlanGet returns the plan and the findings. It never changes anything.
func HandleNetPlanGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	js, _ := json.Marshal(buildNetPlanView())
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}

// HandleNetPlanSet (POST) replaces the plan: field "config" holds the JSON of netplan.Settings
func HandleNetPlanSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	var next netplan.Settings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	mgr := getNetPlan()
	old := mgr.Settings()
	if err := mgr.Set(next); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	cur := mgr.Settings()
	actor, _ := historyActor(r)
	SystemWideLogger.PrintAndLog("netplan", "Network plan changed by "+actor+": declared "+boolWord(old.Declared())+" -> "+boolWord(cur.Declared())+
		", application networks "+strconv.Itoa(len(old.ApplicationVLAN.CIDRs))+" -> "+strconv.Itoa(len(cur.ApplicationVLAN.CIDRs)), nil)
	getPostureEngine().Invalidate()
	invalidateSecurityOverview()
	utils.SendOK(w)
}

const netplanPolicyFile = "dunree-firewall-recommendations.md"

// HandleNetPlanPolicy returns the firewall recommendations. Nothing is applied anywhere.
func HandleNetPlanPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	md := netplan.Recommendations(getNetPlan().Settings(), netplanContext())
	actor, _ := historyActor(r)
	secAudit.Record(secaudit.Event{Actor: actor, IP: callerIP(r), Event: "netplan.export", Target: netplanPolicyFile, Detail: map[string]string{"bytes": strconv.Itoa(len(md))}})
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+netplanPolicyFile+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write([]byte(md))
		return
	}
	js, _ := json.Marshal(map[string]string{"markdown": md, "filename": netplanPolicyFile, "disclaimer": netplan.Disclaimer})
	utils.SendJSONResponse(w, string(js))
}
