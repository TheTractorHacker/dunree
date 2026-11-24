package ruleset

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

/*
	lists.go

	Named lists: sets of networks (ip), exact strings (string) or country codes (country) that rules
	reference as $name. They are edited in one place (lists.json) and used by any number of rules.

	An entry of an ip or string list may be a variable reference, written {{name}} (upstream #370):
	the built-in {{external_ip}} or a user defined variable. References are resolved when the
	snapshot is built (see Engine.SetVarResolver / RefreshVars), never per request. A reference
	that does not resolve matches nothing in an ip list; in a string list it stays the literal
	text it always was, so lists written before variables existed behave as before.
*/

const (
	ListIP      = "ip"
	ListString  = "string"
	ListCountry = "country"

	MaxLists       = 100
	MaxListItems   = 10000
	MaxListItemLen = 256
	MaxListDescLen = 200
)

// List is a named list
type List struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // ip | string | country
	Description string   `json:"description,omitempty"`
	Items       []string `json:"items"`

	set  map[string]struct{}
	nets *ipSet
	refs []string  // variable names of the {{name}} entries, in order of first use
	vars []ListVar // how the references resolved (only on the resolved copy held by a snapshot)
}

// ListVar reports how one {{name}} entry of a list resolved
type ListVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// varRef returns the variable name when a list entry is exactly one {{name}} reference
func varRef(item string) (string, bool) {
	if !strings.HasPrefix(item, "{{") || !strings.HasSuffix(item, "}}") {
		return "", false
	}
	name := strings.TrimSpace(item[2 : len(item)-2])
	if name == "" || len(name) > maxListName {
		return "", false
	}
	for i, c := range name {
		if !(c >= 'a' && c <= 'z' || c == '_' && i > 0 || c >= '0' && c <= '9' && i > 0) {
			return "", false
		}
	}
	return name, true
}

// splitRefs separates the literal entries from the variable references
func splitRefs(items []string) (literal []string, refs []string) {
	seen := map[string]bool{}
	for _, it := range items {
		if name, ok := varRef(strings.TrimSpace(it)); ok {
			if !seen[name] {
				seen[name] = true
				refs = append(refs, name)
			}
			continue
		}
		literal = append(literal, it)
	}
	return literal, refs
}

// resolve returns the list a snapshot evaluates: l itself when it has no variable references,
// else a compiled copy with the references replaced by their current values. l is never modified
// (older snapshots may still be reading it).
func (l *List) resolve(vars func(name string) (string, bool)) *List {
	if len(l.refs) == 0 {
		return l
	}
	c := &List{Name: l.Name, Type: l.Type, Description: l.Description, Items: l.Items, refs: l.refs}
	literal, _ := splitRefs(l.Items)
	items := append([]string(nil), literal...)
	for _, name := range l.refs {
		v := ListVar{Name: name}
		if vars != nil {
			v.Value, v.OK = vars(name)
		}
		v.Value = strings.TrimSpace(v.Value)
		switch {
		case !v.OK || v.Value == "":
			v.OK = false
			v.Error = "not defined or no value right now"
			if l.Type == ListString {
				items = append(items, "{{"+name+"}}") // unchanged meaning: the literal text
			}
		case l.Type == ListIP:
			// a variable may hold several addresses or networks, separated by commas or spaces
			parts := strings.FieldsFunc(v.Value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
			// the access lists accept IPv4 wildcards (10.0.*.*), so the same variable has to work here
			wildErr := ""
			for i, p := range parts {
				if strings.Contains(p, "*") {
					if parts[i], wildErr = wildcardCIDR(p); wildErr != "" {
						break
					}
				}
			}
			if wildErr != "" {
				v.OK = false
				v.Error = wildErr
				break
			}
			if _, err := newIPSet(parts); err != nil || len(parts) == 0 {
				v.OK = false
				v.Error = "the value is not an address or network"
				break
			}
			items = append(items, parts...)
		default:
			if len(v.Value) > MaxListItemLen {
				v.OK = false
				v.Error = "the value is too long"
				break
			}
			items = append(items, v.Value)
		}
		c.vars = append(c.vars, v)
	}
	if l.Type == ListIP {
		c.nets, _ = newIPSet(items) // every part was checked above
	} else {
		c.set = make(map[string]struct{}, len(items))
		for _, it := range items {
			c.set[it] = struct{}{}
		}
	}
	return c
}

// wildcardCIDR turns an IPv4 wildcard as the access lists write it (10.0.*.*) into the network it
// stands for (10.0.0.0/16). Only whole trailing octets can be wildcards: 10.*.0.1 is not a
// network and is reported instead of being matched approximately.
func wildcardCIDR(s string) (cidr string, problem string) {
	oct := strings.Split(s, ".")
	if len(oct) != 4 {
		return "", "the wildcard " + s + " is not an IPv4 wildcard such as 10.0.*.*"
	}
	fixed := 0
	for fixed < 4 && oct[fixed] != "*" {
		fixed++
	}
	for i := fixed; i < 4; i++ {
		if oct[i] != "*" {
			return "", "the wildcard " + s + " cannot be used in a list: only trailing parts can be * (10.0.*.*)"
		}
		oct[i] = "0"
	}
	p, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", strings.Join(oct, "."), fixed*8))
	if err != nil || !p.Addr().Is4() {
		return "", "the wildcard " + s + " is not an IPv4 wildcard such as 10.0.*.*"
	}
	return p.String(), ""
}

// parseAddr reads an IP address (a port or zone is not accepted)
func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ipSet matches addresses against a set of networks in at most one map lookup per distinct prefix length
type ipSet struct {
	m     map[netip.Prefix]struct{}
	bits4 []int
	bits6 []int
}

func newIPSet(items []string) (*ipSet, error) {
	s := &ipSet{m: make(map[netip.Prefix]struct{}, len(items))}
	have4, have6 := map[int]bool{}, map[int]bool{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		var p netip.Prefix
		if strings.Contains(it, "/") {
			pp, err := netip.ParsePrefix(it)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid network (use 10.0.0.0/8 or 2001:db8::/32)", it)
			}
			p = pp
		} else {
			a, err := netip.ParseAddr(it)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid address or network", it)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		// v4-mapped networks are treated as the IPv4 network
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		s.m[p] = struct{}{}
		if p.Addr().Is4() {
			have4[p.Bits()] = true
		} else {
			have6[p.Bits()] = true
		}
	}
	for b := range have4 {
		s.bits4 = append(s.bits4, b)
	}
	for b := range have6 {
		s.bits6 = append(s.bits6, b)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.bits4)))
	sort.Sort(sort.Reverse(sort.IntSlice(s.bits6)))
	return s, nil
}

func (s *ipSet) contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	bits := s.bits6
	if a.Is4() {
		bits = s.bits4
	}
	for _, b := range bits {
		p, err := a.Prefix(b)
		if err != nil {
			continue
		}
		if _, ok := s.m[p]; ok {
			return true
		}
	}
	return false
}

// Validate checks and compiles a list
func (l *List) Validate() error {
	if !validListName(l.Name) {
		return fmt.Errorf("list names are lower case letters, digits and _, starting with a letter, at most %d characters", maxListName)
	}
	if len(l.Description) > MaxListDescLen {
		return fmt.Errorf("the description is longer than %d characters", MaxListDescLen)
	}
	if len(l.Items) > MaxListItems {
		return fmt.Errorf("a list holds at most %d entries", MaxListItems)
	}
	l.refs = nil
	switch l.Type {
	case ListIP:
		literal, refs := splitRefs(l.Items)
		set, err := newIPSet(literal)
		if err != nil {
			return err
		}
		l.nets, l.set, l.refs = set, nil, refs
	case ListString, ListCountry:
		if l.Type == ListString {
			_, l.refs = splitRefs(l.Items)
		}
		l.set = make(map[string]struct{}, len(l.Items))
		for _, it := range l.Items {
			if it == "" || len(it) > MaxListItemLen || strings.ContainsAny(it, "\x00\r\n") {
				return fmt.Errorf("invalid entry %q (1-%d characters, no line breaks)", it, MaxListItemLen)
			}
			if l.Type == ListCountry && !countryRe.MatchString(it) {
				return fmt.Errorf("%q is not a country code (two upper case letters such as US)", it)
			}
			l.set[it] = struct{}{}
		}
		l.nets = nil
	default:
		return fmt.Errorf("the list type must be ip, string or country")
	}
	return nil
}

// link resolves $name references against the lists, checking the list type fits the field
func (x *Expr) link(lists map[string]*List) *Error {
	var walk func(n *Node) *Error
	walk = func(n *Node) *Error {
		if n.Kind != NCond {
			for _, k := range n.Kids {
				if err := walk(k); err != nil {
					return err
				}
			}
			return nil
		}
		c := n.C
		if c.Val.Kind != VRef {
			return nil
		}
		l := lists[c.Val.Ref]
		if l == nil {
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "unknown list $%s (create it under Lists first)", c.Val.Ref)
		}
		switch {
		case c.Field.Type == TIP && l.Type != ListIP:
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "$%s is a %s list, %s needs an ip list", l.Name, l.Type, c.Field.Name)
		case c.Field.Type == TString && l.Type == ListIP:
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "$%s is an ip list and cannot be compared with the text field %s", l.Name, c.Field.Name)
		case c.Field.Type == TString && l.Type == ListCountry && !c.Field.Country:
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "$%s is a country list and can only be used with ip.country", l.Name)
		}
		c.ref = l
		return nil
	}
	return walk(x.Root)
}

// Link resolves the named lists of the expression. The expression is usable for evaluation afterwards.
func (x *Expr) Link(lists map[string]*List) *Error { return x.link(lists) }
