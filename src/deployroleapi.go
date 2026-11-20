package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/deployrole"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	deployroleapi.go

	Deployment role (standalone / external / internal) of this instance, see mod/deployrole and
	docs/enterprise-dual-proxy-plan.md. Settings live in sys.db (settings/deployrole), the change
	history records changes to them like any other setting (route label in mod/confhistory).
*/

var deployRoleMgr *deployrole.Manager

// initDeployRole loads the role settings. A stored value that no longer validates falls back to standalone.
func initDeployRole() {
	m, err := deployrole.New(sysdb)
	if err != nil {
		SystemWideLogger.PrintAndLog("deployrole", "Deployment role", err)
	}
	deployRoleMgr = m
	if r := m.Role(); r != deployrole.RoleStandalone {
		SystemWideLogger.Println("Deployment role: " + string(r))
	}
}

// requesterIPForGeoDB is the GeoIP store's client address resolver (set before the router exists)
func requesterIPForGeoDB(r *http.Request) string {
	if dynamicProxyRouter != nil {
		return dynamicProxyRouter.TrustedRequesterIP(r)
	}
	return netutils.GetRequesterIP(r)
}

type deployRoleView struct {
	deployrole.Settings
	HardenActive   bool     `json:"hardenActive"`
	PeerGateActive bool     `json:"peerGateActive"`
	TrustedProxies int      `json:"trustedProxies"`
	GateRejected   uint64   `json:"gateRejected"`
	Warnings       []string `json:"warnings"`
}

func deployRoleStatus() deployRoleView {
	s := deployRoleMgr.Settings()
	if s.DirectCIDRs == nil {
		s.DirectCIDRs = []string{}
	}
	v := deployRoleView{Settings: s, HardenActive: deployRoleMgr.HardenActive(), PeerGateActive: deployRoleMgr.PeerGateActive(), Warnings: []string{}}
	if accessController != nil {
		v.TrustedProxies = len(accessController.ListTrustedProxies())
	}
	v.GateRejected = dynamicproxy.PeerGateRejected()
	switch s.Role {
	case deployrole.RoleInternal:
		if !s.PeerGate {
			v.Warnings = append(v.Warnings, "Internal role without the peer gate: any host that can reach this proxy directly skips the external proxy. Enable the gate once the external proxy is listed under Trusted Proxies, and keep the firewall rule too.")
		}
		if v.TrustedProxies == 0 {
			v.Warnings = append(v.Warnings, "The trusted proxy list is empty: the external proxy is not trusted, so every request looks like a direct client and its forwarded client address is ignored.")
		}
	case deployrole.RoleExternal:
		if v.TrustedProxies == 0 {
			v.Warnings = append(v.Warnings, "The trusted proxy list is empty. If a CDN such as Cloudflare is in front of this proxy, its client address headers are ignored until the CDN ranges are listed under Trusted Proxies.")
		}
	case deployrole.RoleStandalone:
		if s.HardenHeaders && v.TrustedProxies == 0 {
			v.Warnings = append(v.Warnings, "Header hardening is on and the trusted proxy list is empty: all forwarded client address headers are dropped.")
		}
	}
	return v
}

// HandleDeployRoleGet returns the settings, what is active and warnings
func HandleDeployRoleGet(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(deployRoleStatus())
	utils.SendJSONResponse(w, string(js))
}

// HandleDeployRoleSet (POST) replaces the settings: field "config" holds the JSON of deployrole.Settings
func HandleDeployRoleSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	var next deployrole.Settings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	//A gate that would refuse every peer is a mistake, not a configuration
	if next.PeerGate && next.Role == deployrole.RoleInternal && len(next.DirectCIDRs) == 0 && (accessController == nil || len(accessController.ListTrustedProxies()) == 0) {
		utils.SendErrorResponse(w, "the peer gate would refuse every connection: add the external proxy under Trusted Proxies or list a direct-access network first")
		return
	}
	old := deployRoleMgr.Settings()
	if err := deployRoleMgr.Set(next); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	actor, _ := historyActor(r)
	cur := deployRoleMgr.Settings()
	SystemWideLogger.PrintAndLog("deployrole", "Deployment settings changed by "+actor+": role "+string(old.Role)+" -> "+string(cur.Role)+
		", header hardening "+boolWord(old.HardenHeaders)+" -> "+boolWord(cur.HardenHeaders)+", peer gate "+boolWord(old.PeerGate)+" -> "+boolWord(cur.PeerGate), nil)
	utils.SendOK(w)
}

func boolWord(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
