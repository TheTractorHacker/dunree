package tlscert

/*
	rejectsni.go

	Optional "reject handshakes for unknown names" (upstream #1319, like nginx ssl_reject_handshake). Off by default.

	Without it a client that asks for a name nothing matches (a scanner, access by IP address, no SNI at all) is
	answered with the fallback certificate. When that is a real certificate (for example a wildcard), the client learns
	the domain without knowing any host name. With the option on such a handshake is refused before any certificate is
	sent.

	A name is unknown when the certificate lookup ended at the fallback (the configured fallback certificate or the
	built-in localhost one), that certificate is not valid for the name, and IsKnownHost does not claim the name for a
	proxy rule. A proxy rule without a certificate of its own therefore keeps working exactly as before.
*/

import (
	"crypto/tls"
	"net"
	"strings"
)

// rejectUnknown decides for a handshake that reached the fallback certificate, counts and reports a refusal.
//
// A client that connects to an IP address sends no server name (RFC 6066 forbids an IP address in SNI), so a proxy
// rule keyed on an IP address can only be recognised by the address the connection arrived on. A hello without SNI
// is therefore checked against the local IP address of its connection before it is refused.
func (m *Manager) rejectUnknown(helloInfo *tls.ClientHelloInfo) bool {
	if !m.RejectUnknownSNI.Load() {
		return false
	}
	serverName := helloInfo.ServerName
	if m.IsKnownHost != nil {
		if serverName != "" {
			if m.IsKnownHost(serverName) {
				return false
			}
		} else if ip := localIPOf(helloInfo); ip != "" && m.IsKnownHost(ip) {
			return false
		}
	}
	m.rejectedUnknown.Add(1)
	if m.OnUnknownRejected != nil {
		m.OnUnknownRejected(serverName)
	}
	return true
}

// localIPOf is the IP address a handshake arrived on ("" when unknown), without zone, IPv4-mapped as IPv4
func localIPOf(helloInfo *tls.ClientHelloInfo) string {
	if helloInfo == nil || helloInfo.Conn == nil || helloInfo.Conn.LocalAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(helloInfo.Conn.LocalAddr().String())
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// RejectedUnknownCount is the number of handshakes refused by RejectUnknownSNI since start
func (m *Manager) RejectedUnknownCount() uint64 {
	return m.rejectedUnknown.Load()
}
