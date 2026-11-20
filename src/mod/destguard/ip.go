// Package destguard is the shared destination guard of the admin tools that dial a host the admin
// (or a stolen session) names: upstream test, port and IP scan, uptime checks, web SSH, the forward
// proxy, and the validation of proxy rule targets. It generalises the logic of the AI assistant SSRF
// guard, which now uses CheckIP from here.
//
// Everything is opt-in. With no Guard, or a Guard whose settings are all zero, every dial is exactly
// the plain net dial of before (see Guard.DialContext) and nothing is validated.
package destguard

import (
	"errors"
	"net/netip"
)

var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, OpenStack, DigitalOcean
	netip.MustParseAddr("169.254.170.2"),   // AWS ECS task metadata
	netip.MustParseAddr("100.100.100.200"), // Alibaba
	netip.MustParseAddr("192.0.0.192"),     // Oracle
	netip.MustParseAddr("168.63.129.16"),   // Azure wire server
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	zeroNet   = netip.MustParsePrefix("0.0.0.0/8")
	reserved  = netip.MustParsePrefix("240.0.0.0/4")
	nat64WK   = netip.MustParsePrefix("64:ff9b::/96")
	nat64Loc  = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour = netip.MustParsePrefix("2002::/16")
	teredo    = netip.MustParsePrefix("2001::/32")
	v4Compat  = netip.MustParsePrefix("::/96")
)

// Class is what kind of address an allowed destination is
type Class int

const (
	ClassPublic   Class = iota // routable, not private
	ClassPrivate               // RFC 1918, ULA, CGNAT
	ClassLoopback              // 127/8, ::1
)

// Classify returns the class of ip, or an error when the address must never be contacted:
// cloud metadata, link-local, multicast, unspecified, reserved, and the IPv6 transition forms
// (IPv4-mapped, NAT64, 6to4, IPv4-compatible, Teredo) that carry such an address. A transition
// form that carries an ordinary address is classified by the address it carries.
func Classify(ip netip.Addr) (Class, error) {
	ip = ip.Unmap()
	if ip.Is6() {
		if emb, refuse, ok := embeddedIPv4(ip); ok {
			if refuse {
				return 0, errors.New("IPv6 transition addresses (Teredo, NAT64 local-use) are refused")
			}
			return Classify(emb)
		}
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return 0, errors.New("the endpoint address is a cloud metadata address and is always refused")
		}
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return 0, errors.New("link-local, multicast and unspecified endpoint addresses are always refused")
	}
	if zeroNet.Contains(ip) || reserved.Contains(ip) {
		return 0, errors.New("reserved endpoint addresses are refused")
	}
	if ip.IsLoopback() {
		return ClassLoopback, nil
	}
	if ip.IsPrivate() || cgnat.Contains(ip) {
		return ClassPrivate, nil
	}
	return ClassPublic, nil
}

// CheckIP returns an error when ip must not be contacted. Loopback, private and CGNAT addresses
// are refused unless allowLocal. Same rules as the AI assistant endpoint check.
func CheckIP(ip netip.Addr, allowLocal bool) error {
	c, err := Classify(ip)
	if err != nil {
		return err
	}
	if c != ClassPublic && !allowLocal {
		return errors.New("loopback and private endpoint addresses need the OpenAI-compatible provider with the local model box ticked")
	}
	return nil
}

// embeddedIPv4 extracts the IPv4 address carried by an IPv6 transition address. ok is false for
// ordinary IPv6. refuse is true for prefixes that are refused outright (Teredo, local-use NAT64).
// The IPv4-compatible form ::a.b.c.d is decoded as well; ::, ::1 and the v4-compat space below
// 0.0.0.2 stay with the normal unspecified/loopback checks.
func embeddedIPv4(ip netip.Addr) (v4 netip.Addr, refuse, ok bool) {
	b := ip.As16()
	switch {
	case nat64WK.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), false, true
	case nat64Loc.Contains(ip), teredo.Contains(ip):
		return netip.Addr{}, true, true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), false, true
	case v4Compat.Contains(ip):
		if ip == netip.IPv6Unspecified() || ip == netip.IPv6Loopback() {
			return netip.Addr{}, false, false
		}
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), false, true
	}
	return netip.Addr{}, false, false
}
