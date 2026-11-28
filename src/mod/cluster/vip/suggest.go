package vip

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SuggestMaxProbes bounds how many candidate addresses are probed per call.
const (
	SuggestMaxProbes = 12
	SuggestParallel  = 4
	SuggestWant      = 3
)

// Candidate is one suggested floating IP.
type Candidate struct {
	Address string `json:"address"`
	Reason  string `json:"reason"` // i18n key
}

// SuggestResult is the answer of the suggestion call.
type SuggestResult struct {
	Network struct {
		CIDR  string `json:"cidr"`
		First string `json:"first"`
		Last  string `json:"last"`
	} `json:"network"`
	Gateway    string      `json:"gateway,omitempty"`
	Candidates []Candidate `json:"candidates"`
}

// SuggestInput holds what Suggest reads. Everything that touches the host is
// injectable. Dunree only looks: ARP table, route table, and a few TCP dials
// to addresses inside the user's own /24.
type SuggestInput struct {
	Base    netip.Addr // an address of this network (this server, or "near")
	Members []string   // member addresses to leave out
	Lister  InterfaceLister
	Paths   Paths
	Dial    func(addr string, timeout time.Duration) (connected bool, refused bool)
}

// Suggest picks up to three spare addresses in the /24 around Base. Absence
// of an answer proves nothing (switched-off devices, blocked probes): the
// result is a suggestion, never a guarantee.
func Suggest(in SuggestInput) (*SuggestResult, error) {
	base := in.Base.Unmap()
	if !base.Is4() {
		return nil, fmt.Errorf("address suggestions are for IPv4 networks")
	}
	netw := netip.PrefixFrom(base, 24).Masked()
	b4 := netw.Addr().As4()
	at := func(last int) netip.Addr { return netip.AddrFrom4([4]byte{b4[0], b4[1], b4[2], byte(last)}) }
	skip := map[netip.Addr]bool{}
	for _, m := range in.Members {
		if a, err := netip.ParseAddr(m); err == nil {
			skip[a] = true
		}
	}
	if in.Lister != nil {
		if ifs, err := in.Lister.Interfaces(); err == nil {
			for _, i := range ifs {
				for _, p := range i.Addrs {
					skip[p.Addr()] = true
				}
			}
		}
	}
	res := &SuggestResult{Candidates: []Candidate{}}
	res.Network.CIDR, res.Network.First, res.Network.Last = netw.String(), at(1).String(), at(254).String()
	if gw := readGateway(in.Paths.RouteFile); gw.IsValid() {
		skip[gw] = true
		if netw.Contains(gw) {
			res.Gateway = gw.String()
		}
	}
	for a := range readARP(in.Paths.ARPFile) {
		skip[a] = true
	}
	var order []int
	for i := 10; i <= 29; i++ {
		order = append(order, i)
	}
	for i := 240; i <= 250; i++ {
		order = append(order, i)
	}
	for i := 2; i <= 9; i++ {
		order = append(order, i)
	}
	var pool []netip.Addr
	for _, n := range order {
		a := at(n)
		if !skip[a] && len(pool) < SuggestMaxProbes {
			pool = append(pool, a)
		}
	}
	answered := make([]bool, len(pool))
	var wg sync.WaitGroup
	sem := make(chan struct{}, SuggestParallel)
	pe := &PreflightEnv{Paths: Paths{}, Dial: in.Dial} // ARP already handled above
	for i, a := range pool {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			answered[i], _ = vipInUse(a, pe)
		}(i, a)
	}
	wg.Wait()
	for i, a := range pool {
		if !answered[i] && len(res.Candidates) < SuggestWant {
			res.Candidates = append(res.Candidates, Candidate{Address: a.String(), Reason: "suggest.unanswered"})
		}
	}
	return res, nil
}

// readARP returns the addresses with a complete ARP entry (flags 0x2).
func readARP(path string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	if path == "" {
		return out
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) >= 4 && f[2] == "0x2" && f[3] != "00:00:00:00:00:00" {
			if a, err := netip.ParseAddr(f[0]); err == nil {
				out[a] = true
			}
		}
	}
	return out
}

// readGateway returns the default gateway from /proc/net/route format
// (little-endian hex), or an invalid address.
func readGateway(path string) netip.Addr {
	if path == "" {
		return netip.Addr{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return netip.Addr{}
	}
	type route struct {
		gw     netip.Addr
		metric int
	}
	var rs []route
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		m, _ := strconv.Atoi(f[6])
		rs = append(rs, route{netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}), m})
	}
	if len(rs) == 0 {
		return netip.Addr{}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].metric < rs[j].metric })
	return rs[0].gw
}

// SuggestBase picks the address whose /24 is searched: "near" if given, else
// a member address that is on this host, else the first up IPv4 address.
func SuggestBase(near string, members []string, ifs []IfaceInfo) (netip.Addr, error) {
	if near != "" {
		a, err := netip.ParseAddr(near)
		if err != nil || !a.Is4() {
			return netip.Addr{}, fmt.Errorf("near must be an IPv4 address")
		}
		return a, nil
	}
	own := map[netip.Addr]bool{}
	for _, i := range ifs {
		for _, p := range i.Addrs {
			own[p.Addr()] = true
		}
	}
	for _, m := range members {
		if a, err := netip.ParseAddr(m); err == nil && own[a] && a.Is4() {
			return a, nil
		}
	}
	for _, i := range ifs {
		if !i.Up {
			continue
		}
		for _, p := range i.Addrs {
			a := p.Addr()
			if a.Is4() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
				return a, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("this server has no IPv4 address to base a suggestion on")
}
