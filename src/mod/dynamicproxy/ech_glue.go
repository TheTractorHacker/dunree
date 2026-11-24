package dynamicproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

/*
	ech_glue.go

	Encrypted Client Hello wiring. Key management lives in mod/ech; the router only gets a callback
	(RouterOption.EchKeys) that crypto/tls calls per handshake, so enabling / rotating keys needs no restart.

	The callback is installed on the listener config before the per-SNI clones (client certificates) are made;
	tls.Config.Clone copies GetEncryptedClientHelloKeys, and ECH is decrypted before GetConfigForClient runs
	anyway, so mTLS endpoints see the inner SNI. HTTP/3 clones the same config.

	Per request result (EchResultOf): crypto/tls reports ECHAccepted and the server name it routed on (the inner
	name when ECH was accepted). What it does not report is whether the client offered ECH at all, nor the outer
	name of an accepted hello. Both are visible in the keys callback: crypto/tls calls it only for a ClientHello
	that carries the ECH extension, first with the OUTER hello. The TCP listeners therefore put a small note in the
	connection context (echConnContext) that the callback fills and the request handlers read. Nothing is kept
	outside the connection, so there is nothing to clean up.
*/

// ECH outcomes of a TLS request
const (
	EchAccepted = "accepted" // the inner ClientHello was decrypted
	EchOffered  = "offered"  // the client sent an ECH extension that was not decrypted: GREASE, or a config this server has no key for
	EchPlain    = "plain"    // no ECH: the server name travelled in clear text
)

type echCtxKey struct{}

// echConnNote is what the keys callback saw on one connection
type echConnNote struct {
	offered atomic.Bool
	outer   atomic.Pointer[string]
}

// echConnContext is the http.Server.ConnContext of the TLS listeners
func (router *Router) echConnContext(ctx context.Context, _ net.Conn) context.Context {
	if router.Option.EchKeys == nil {
		return ctx
	}
	return context.WithValue(ctx, echCtxKey{}, &echConnNote{})
}

func (router *Router) applyEch(cfg *tls.Config) {
	keys := router.Option.EchKeys
	if keys == nil {
		return
	}
	cfg.GetEncryptedClientHelloKeys = func(hello *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		if hello != nil && hello.Context() != nil {
			if note, _ := hello.Context().Value(echCtxKey{}).(*echConnNote); note != nil {
				note.offered.Store(true)
				//crypto/tls may ask a second time with the inner hello: only the first name is the outer one
				name := hello.ServerName
				note.outer.CompareAndSwap(nil, &name)
			}
		}
		return keys(hello)
	}
}

// EchResultOf returns the ECH outcome of a request and the outer SNI: the server name that was readable on the
// network. ok is false for a request that did not arrive over TLS. outer is "" when the client sent no SNI, and
// for an accepted hello on a listener that cannot see the outer hello (HTTP/3).
func EchResultOf(r *http.Request) (outcome, outer string, ok bool) {
	if r == nil || r.TLS == nil {
		return "", "", false
	}
	note, _ := r.Context().Value(echCtxKey{}).(*echConnNote)
	if r.TLS.ECHAccepted {
		if note != nil {
			if p := note.outer.Load(); p != nil {
				outer = *p
			}
		}
		return EchAccepted, cleanSNI(outer), true
	}
	if note != nil && note.offered.Load() {
		return EchOffered, cleanSNI(r.TLS.ServerName), true
	}
	return EchPlain, cleanSNI(r.TLS.ServerName), true
}

// cleanSNI makes a server name from the network safe for a log line: host name characters only, bounded
func cleanSNI(name string) string {
	if len(name) > 253 {
		name = name[:253]
	}
	return strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_', c == '*':
			return c
		case c >= 'A' && c <= 'Z':
			return c + ('a' - 'A')
		}
		return '?'
	}, name)
}

func (router *Router) echObserve(r *http.Request) {
	if router.Option.EchObserve == nil || r.TLS == nil {
		return
	}
	outcome, _, _ := EchResultOf(r)
	router.Option.EchObserve(outcome == EchAccepted, outcome == EchOffered)
}
