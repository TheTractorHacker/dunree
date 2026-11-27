// Package vip implements the floating IP (keepalived / VRRP) part of Cluster / HA.
//
// Dunree applies nothing outside itself: this package validates settings,
// GENERATES keepalived.conf and copy-paste commands, and READS status from
// the network interfaces and a few files. It never runs ip, systemctl,
// sysctl, apt or keepalived, and never writes under /etc.
//
// Design: docs/cluster/vip-plan.md. All addresses in tests and docs are
// placeholders (192.0.2.0/24, 2001:db8::/32).
package vip

import (
	"net/netip"
)

// Transport and auth modes.
const (
	TransportUnicast   = "unicast"
	TransportMulticast = "multicast"

	AuthCluster  = "cluster"
	AuthPassword = "password"
	AuthNone     = "none"
)

// MaxConfigBytes bounds a settings JSON document.
const MaxConfigBytes = 16 << 10

// Member is one keepalived node. Label is display only and is never part of a
// config line except inside the header comment (it is validated).
type Member struct {
	Label         string `json:"label"`
	Address       string `json:"address"`
	Priority      int    `json:"priority"`
	InterfaceHint string `json:"interfaceHint,omitempty"`
}

// Health is the vrrp_script tuning (same on every node).
type Health struct {
	Interval int `json:"interval"`
	Timeout  int `json:"timeout"`
	Fall     int `json:"fall"`
	Rise     int `json:"rise"`
}

// Shared is the part of the configuration that must match on all nodes. It is
// stored in conf/ha/vip.json and travels with the cluster snapshot.
type Shared struct {
	Enabled   bool     `json:"enabled"`
	VIP       string   `json:"vip"`
	Prefix    int      `json:"prefix"`
	VRID      int      `json:"vrid"`
	AdvertInt int      `json:"advertInt"`
	Transport string   `json:"transport"`
	Members   []Member `json:"members"`
	Auth      string   `json:"auth"`
	Password  string   `json:"password,omitempty"`
	// ClusterPass is the random VRRP password of auth=cluster. The primary
	// generates it once (crypto/rand); it travels in the encrypted snapshot
	// and is derived from nothing, so a sniffed advert says nothing about the
	// cluster secret.
	ClusterPass  string `json:"clusterPass,omitempty"`
	Preempt      bool   `json:"preempt"`
	PreemptDelay int    `json:"preemptDelay"`
	Health       Health `json:"health"`
	NotifyLog    bool   `json:"notifyLog"`
	GarpRefresh  int    `json:"garpRefresh"`
}

// Local holds the node-local overrides (conf/cluster.json, "vipLocal").
type Local struct {
	Interface        string `json:"interface,omitempty"`
	SourceAddress    string `json:"sourceAddress,omitempty"`
	PriorityOverride int    `json:"priorityOverride,omitempty"`
	HealthTarget     string `json:"healthTarget,omitempty"` // "" or "auto" = automatic
}

// Defaults returns the defaults of section 1.2. haveSecret selects the
// default auth mode.
func Defaults(haveSecret bool) Shared {
	auth := AuthPassword
	if haveSecret {
		auth = AuthCluster
	}
	return Shared{
		VRID: 51, AdvertInt: 1, Transport: TransportUnicast, Auth: auth,
		Preempt: true, PreemptDelay: 60,
		Health: Health{Interval: 2, Timeout: 3, Fall: 3, Rise: 2},
	}
}

// IfaceInfo is one network interface as the code sees it. Tests provide fakes.
type IfaceInfo struct {
	Name  string
	Up    bool
	Addrs []netip.Prefix // address with the configured prefix length
}

// InterfaceLister abstracts net.Interfaces so tests need no root and no
// particular host network.
type InterfaceLister interface {
	Interfaces() ([]IfaceInfo, error)
}

// ListenerFacts are what only the running process knows about its listeners.
type ListenerFacts struct {
	HealthPort     string   // value of -health_port ("", ":8081", "192.0.2.11:8081")
	Port80         bool     // plain HTTP listener is running (it only runs next to a TLS listener)
	HTTPPort       int      // its port (0 = 80)
	InboundPort    int      // proxy listener port
	TLS            bool     // proxy listener serves TLS
	BoundAddr      string   // address the proxy listener binds ("" = all addresses)
	HealthDisabled bool     // cluster health endpoint switched off
	HealthAllow    []string // health allow-list entries (IPs or CIDRs)
	// RejectUnknownSNI: the TLS listener turns down a client that sends no
	// (or an unknown) server name, which the probe to an IP literal does.
	RejectUnknownSNI bool
}

// Env is everything Generate needs beyond the settings. It makes the
// generator a pure function.
type Env struct {
	Version    string
	Interfaces []IfaceInfo
	Listener   ListenerFacts
	UFWEnabled bool
}
