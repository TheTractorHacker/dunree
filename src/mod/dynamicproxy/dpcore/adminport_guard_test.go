package dpcore

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/adminallow"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/upstreamtls/tlstest"
)

type memKV map[string]interface{}

func (memKV) Read(string, string, interface{}) error  { return nil }
func (memKV) Write(string, string, interface{}) error { return nil }

// armAdminGuard makes the test server's port "the admin port" and turns the allow-list on
func armAdminGuard(t *testing.T, listener net.Addr) {
	t.Helper()
	m, _ := adminallow.New(memKV{})
	if err := m.Set(adminallow.Settings{CIDRs: []string{"127.0.0.1"}}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.String())
	adminallow.InstallDialGuard(m, "0.0.0.0:"+port)
	t.Cleanup(func() { adminallow.InstallDialGuard(nil, "") })
}

// Attack: a proxy rule whose upstream is the admin port. The old defence was the X-Forwarded-Server marker that
// the proxy adds and that hop-by-hop handling can drop; the dial itself is refused now, whatever the headers are.
func TestProxyCannotDialAdminPortWhileAllowListIsOn(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ADMIN-PANEL")) }))
	defer admin.Close()
	target, _ := url.Parse(admin.URL)

	do := func(opts *DpcoreOptions, hdr map[string]string) (int, string) {
		p := NewDynamicProxyCore(target, "", opts)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		code, err := p.ProxyHTTP(rec, req, &ResponseRewriteRuleSet{ProxyDomain: target.Host, OriginalHost: "front.example.com"})
		if err != nil {
			return code, ""
		}
		return code, rec.Body.String()
	}
	// guard off (default): reachable, as before
	if _, body := do(&DpcoreOptions{}, nil); body != "ADMIN-PANEL" {
		t.Fatalf("baseline proxying broken: %q", body)
	}
	armAdminGuard(t, admin.Listener.Addr())
	//Connection header naming the marker, and a request that never carried one: neither changes anything
	for _, h := range []map[string]string{nil, {"Connection": "X-Forwarded-Server", "X-Forwarded-Server": "x"}} {
		if _, body := do(&DpcoreOptions{}, h); body == "ADMIN-PANEL" {
			t.Errorf("HTTP proxy reached the admin port (headers %v)", h)
		}
		if _, body := do(&DpcoreOptions{H2C: true}, h); body == "ADMIN-PANEL" {
			t.Errorf("h2c proxy reached the admin port (headers %v)", h)
		}
	}
}

// The CONNECT / upgrade tunnel dials on its own
func TestConnectTunnelCannotDialAdminPort(t *testing.T) {
	ca := tlstest.NewCA("c")
	target := startTLSUpstream(t, ca.Issue(tlstest.Options{IPs: []net.IP{net.ParseIP("127.0.0.1")}}))
	armAdminGuard(t, mustAddr(t, target.Host))
	p := NewDynamicProxyCore(target, "", &DpcoreOptions{IgnoreTLSVerification: true})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r, &ResponseRewriteRuleSet{ProxyDomain: target.Host, UseTLS: true, AllowConnect: true})
	}))
	defer front.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("CONNECT " + target.Host + " HTTP/1.1\r\nHost: " + target.Host + "\r\n\r\n"))
	status, _ := bufio.NewReader(c).ReadString('\n')
	if strings.Contains(status, " 200") {
		t.Fatalf("CONNECT tunnel to the admin port was established: %q", status)
	}
}

func mustAddr(t *testing.T, hostport string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", hostport)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
