package vip

import (
	"fmt"
	"net/netip"
)

// Self describes how this host appears in the member list.
type Self struct {
	Index     int    // index in Shared.Members
	Interface string // interface carrying the VIP
	Prefix    int    // prefix configured on the detected interface (0 = unknown)
	Priority  int    // effective priority (override applied)
	Source    string // member address
	Peers     []string
	// Sources say where each value came from: detected, local override, member hint
	IfaceSource string
	PrioSource  string
}

// Resolve finds this node in the member list (section 1.1). It returns an
// error when no member address is configured on this host and no
// sourceAddress override names one.
func Resolve(s *Shared, l *Local, ifs []IfaceInfo) (*Self, error) {
	if len(s.Members) == 0 {
		return nil, fmt.Errorf("no members configured")
	}
	idx := -1
	var ifc IfaceInfo
	var pfx int
	want := ""
	if l != nil {
		want = l.SourceAddress
	}
	for i, m := range s.Members {
		if want != "" && m.Address != want {
			continue
		}
		a, err := netip.ParseAddr(m.Address)
		if err != nil {
			continue
		}
		for _, in := range ifs {
			for _, p := range in.Addrs {
				if p.Addr() == a {
					if idx < 0 || (l != nil && l.Interface == in.Name) {
						idx, ifc, pfx = i, in, p.Bits()
					}
				}
			}
		}
	}
	if idx < 0 {
		if want != "" {
			return nil, fmt.Errorf("the source address %s is not configured on any interface of this host", want)
		}
		return nil, fmt.Errorf("none of the member addresses is configured on this host: this node is not a member")
	}
	self := &Self{Index: idx, Interface: ifc.Name, Prefix: pfx, Priority: s.Members[idx].Priority,
		Source: s.Members[idx].Address, IfaceSource: "detected", PrioSource: "shared"}
	if l != nil && l.Interface != "" {
		self.Interface, self.IfaceSource = l.Interface, "local override"
	}
	if l != nil && l.PriorityOverride != 0 {
		self.Priority, self.PrioSource = l.PriorityOverride, "local override"
	}
	for i, m := range s.Members {
		if i != idx {
			self.Peers = append(self.Peers, m.Address)
		}
	}
	return self, nil
}
