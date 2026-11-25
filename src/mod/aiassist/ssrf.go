package aiassist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/TheTractorHacker/dunree/mod/destguard"
)

/*
	SSRF guard. The configured endpoint is admin supplied, but a stolen session or a CSRF slip
	must not turn the proxy into a scanner of the cloud metadata service or the internal network.

	Rules:
	  - link-local (169.254/16, fe80::/10), cloud metadata addresses, multicast, unspecified: always refused
	  - loopback, private (RFC 1918, ULA), CGNAT: refused unless provider is openai_compatible AND the
	    admin ticked "local model"
	  - the check runs on the address that is actually dialled (after DNS), so DNS names that resolve to a
	    private range and DNS rebinding are covered; every redirect is refused
	  - environment proxies are ignored (they would bypass the check)
*/

// checkIP returns an error when ip must not be contacted (shared logic in mod/destguard).
func checkIP(ip netip.Addr, allowLocal bool) error {
	return destguard.CheckIP(ip, allowLocal)
}

// checkLiteralHost rejects IP literal hosts at settings time (names are checked when dialled).
func checkLiteralHost(host string, allowLocal bool) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkIP(ip, allowLocal)
	}
	return nil
}

// lookupIP is replaced in tests.
var lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newGuardedClient builds an HTTP client that only connects to allowed addresses and never follows redirects.
func newGuardedClient(allowLocal bool, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var ips []netip.Addr
			if ip, perr := netip.ParseAddr(host); perr == nil {
				ips = []netip.Addr{ip}
			} else if ips, err = lookupIP(ctx, host); err != nil {
				return nil, fmt.Errorf("cannot resolve the endpoint host: %w", err)
			}
			if len(ips) == 0 {
				return nil, errors.New("the endpoint host has no address")
			}
			for _, ip := range ips { // every address must be allowed, so a mixed answer cannot be used to slip through
				if err := checkIP(ip, allowLocal); err != nil {
					return nil, err
				}
			}
			var last error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
