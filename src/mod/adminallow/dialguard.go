package adminallow

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The admin listener allow-list is meant to keep the admin panel on the management network. A proxy
// rule whose upstream is the admin port would reach it from this very machine (usually an allowed
// address), so the proxy must never dial it while the list is on.
//
// The check is made at dial time on the resolved address (net.Dialer.Control), by the router's own
// outbound dialers (HTTP, h2c, WebSocket, CONNECT tunnels, virtual directories). It does not depend
// on any request header, so a client cannot make it disappear, and DNS names are judged by the
// address actually connected to (no rebinding gap between check and use).

// ErrAdminPortDial is returned by DialControl for a refused dial
var ErrAdminPortDial = errors.New("refused: upstream is the Zoraxy admin listener and the admin allow-list is on")

type dialGuardState struct {
	m      *Manager
	listen string
}

var dialGuard atomic.Pointer[dialGuardState]

// InstallDialGuard arms the dial guard: while m has an allow-list, dials to the admin listener bound at
// listen (the -port value) are refused. Pass a nil manager to disarm.
func InstallDialGuard(m *Manager, listen string) {
	if m == nil {
		dialGuard.Store(nil)
		return
	}
	dialGuard.Store(&dialGuardState{m: m, listen: listen})
}

var (
	localMu    sync.Mutex
	localAt    time.Time
	localAddrs []netip.Addr
)

func localInterfaceAddrs() []netip.Addr {
	localMu.Lock()
	defer localMu.Unlock()
	if time.Since(localAt) < 10*time.Second && localAddrs != nil {
		return localAddrs
	}
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	localAddrs, localAt = out, time.Now()
	return out
}

// DialBlocked reports whether a dial to the resolved "ip:port" must be refused
func DialBlocked(network, address string) bool {
	g := dialGuard.Load()
	if g == nil || !g.m.Active() {
		return false
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return false
	}
	host, ps, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	port, err := net.LookupPort("tcp", ps)
	if err != nil {
		return false
	}
	return TargetsListener(g.listen, host, port, localInterfaceAddrs(), nil)
}

// DialControl is a net.Dialer.Control function; install it on every outbound dialer of the proxy
func DialControl(network, address string, _ syscall.RawConn) error {
	if DialBlocked(network, address) {
		return ErrAdminPortDial
	}
	return nil
}

// Dialer returns a net.Dialer with the guard installed
func Dialer(timeout, keepAlive time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive, Control: DialControl}
}

// DialContext is the guarded dial with default settings, for transports that only need a dial function
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return Dialer(0, 0).DialContext(ctx, network, addr)
}
