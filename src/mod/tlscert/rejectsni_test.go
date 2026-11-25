package tlscert

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/info/logger"
)

// Real handshakes against a listener that uses Manager.GetCert the way the proxy does (no static certificates).
func TestRejectUnknownSNI(t *testing.T) {
	lg, _ := logger.NewFmtLogger()
	m, err := NewManagerWithTmp(t.TempDir(), t.TempDir(), lg)
	if err != nil {
		t.Fatal(err)
	}
	m.SetHostSpecificTlsBehavior(defaultHostSpecificTlsBehavior)
	c, k := selfPair(t, "app.example.com", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m.CertStore, "app.example.com.pem"), c)
	put(t, filepath.Join(m.CertStore, "app.example.com.key"), k)
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatal(err)
	}
	m.IsKnownHost = func(n string) bool { return n == "rule-without-cert.example.com" }
	var rejected, fallback []string
	m.OnUnknownRejected = func(n string) { rejected = append(rejected, n) }
	m.OnFallbackServed = func(n string) { fallback = append(fallback, n) }

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: m.GetCert})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				c.(*tls.Conn).Handshake()
				c.Close()
			}(conn)
		}
	}()
	dial := func(sni string) (string, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
	}

	// default (off): every name is answered, unknown ones with the fallback certificate
	for _, n := range []string{"app.example.com", "scanner.test", "", "rule-without-cert.example.com"} {
		if _, err := dial(n); err != nil {
			t.Fatalf("option off: handshake for %q must succeed: %v", n, err)
		}
	}
	if len(rejected) != 0 || m.RejectedUnknownCount() != 0 {
		t.Fatalf("option off: nothing may be rejected, got %q", rejected)
	}
	if len(fallback) != 3 {
		t.Fatalf("option off: fallback hook = %q", fallback)
	}

	m.RejectUnknownSNI.Store(true)
	fallback = nil
	if cn, err := dial("app.example.com"); err != nil || cn != "app.example.com" {
		t.Fatalf("a name with a certificate must keep working: %q %v", cn, err)
	}
	if _, err := dial("rule-without-cert.example.com"); err != nil {
		t.Fatalf("a proxy rule without its own certificate must keep the fallback certificate: %v", err)
	}
	for _, n := range []string{"scanner.test", ""} {
		_, err := dial(n)
		if err == nil {
			t.Fatalf("handshake for unknown name %q must be rejected", n)
		}
		if !strings.Contains(err.Error(), "unrecognized name") {
			t.Fatalf("want the unrecognized_name alert for %q, got: %v", n, err)
		}
	}
	if len(rejected) != 2 || rejected[0] != "scanner.test" || rejected[1] != "" || m.RejectedUnknownCount() != 2 {
		t.Fatalf("rejected = %q, count %d", rejected, m.RejectedUnknownCount())
	}
	if len(fallback) != 1 || fallback[0] != "rule-without-cert.example.com" {
		t.Fatalf("a rejected handshake must not be reported as served: %q", fallback)
	}

	// a proxy rule keyed on the IP address of the listener: clients send no SNI for an IP address, so the address
	// the connection arrived on decides. Only the hello without SNI is let through, other unknown names are not.
	m.IsKnownHost = func(n string) bool { return n == "rule-without-cert.example.com" || n == "127.0.0.1" }
	if _, err := dial(""); err != nil {
		t.Fatalf("a rule for the IP address of the listener must keep working without SNI: %v", err)
	}
	if _, err := dial("scanner.test"); err == nil {
		t.Fatal("an IP address rule must not let other unknown names through")
	}
	if len(fallback) != 2 || fallback[1] != "" || m.RejectedUnknownCount() != 3 {
		t.Fatalf("IP address rule: fallback %q, rejected count %d", fallback, m.RejectedUnknownCount())
	}
	m.IsKnownHost = func(n string) bool { return n == "rule-without-cert.example.com" }

	// a configured fallback certificate that covers the name is a match, not an unknown name
	fc, fk := selfPair(t, "*.wild.example", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m.CertStore, "fb.pem"), fc)
	put(t, filepath.Join(m.CertStore, "fb.key"), fk)
	m.FallbackCert = "fb"
	if _, err := dial("other.unknown.test"); err == nil {
		t.Fatal("a name the fallback certificate does not cover must still be rejected")
	}

	// without IsKnownHost every unmatched name is unknown
	m.IsKnownHost = nil
	if _, err := dial("rule-without-cert.example.com"); err == nil {
		t.Fatal("without a rule lookup the name is unknown")
	}

	// switching off restores the old behaviour at once
	m.RejectUnknownSNI.Store(false)
	if _, err := dial("scanner.test"); err != nil {
		t.Fatalf("option off again: %v", err)
	}
}

type addrConn struct {
	net.Conn
	local net.Addr
}

func (c addrConn) LocalAddr() net.Addr { return c.local }

func TestLocalIPOf(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.7:443":         "192.0.2.7",
		"[2001:db8::1]:443":     "2001:db8::1",
		"[fe80::1%eth0]:443":    "fe80::1",
		"[::ffff:192.0.2.7]:80": "192.0.2.7",
	} {
		tcp, err := net.ResolveTCPAddr("tcp", strings.Replace(addr, "%eth0", "", 1))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(addr, "%eth0") {
			tcp.Zone = "eth0"
		}
		if got := localIPOf(&tls.ClientHelloInfo{Conn: addrConn{local: tcp}}); got != want {
			t.Errorf("%s: got %q, want %q", addr, got, want)
		}
	}
	if got := localIPOf(&tls.ClientHelloInfo{}); got != "" {
		t.Errorf("no connection: %q", got)
	}
	if got := localIPOf(&tls.ClientHelloInfo{Conn: addrConn{local: &net.UnixAddr{Name: "/run/x.sock", Net: "unix"}}}); got != "" {
		t.Errorf("unix socket: %q", got)
	}
}
