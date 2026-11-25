package dpcore

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/upstreamtls"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/upstreamtls/tlstest"
)

func startTLSUpstream(t *testing.T, cert tls.Certificate) *url.URL {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("upstream-ok")) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	return u
}

func proxyOnce(p *ReverseProxy, target *url.URL) (int, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
	code, err := p.ProxyHTTP(rec, req, &ResponseRewriteRuleSet{ProxyDomain: target.Host, OriginalHost: "front.example.com", UseTLS: true})
	if err != nil {
		return code, ""
	}
	return code, rec.Body.String()
}

func TestNewDynamicProxyCoreUpstreamTLSPolicy(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	cert := ca.Issue(tlstest.Options{DNS: []string{"front.example.com", "app.internal"}, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	target := startTLSUpstream(t, cert)

	if code, _ := proxyOnce(NewDynamicProxyCore(target, "", &DpcoreOptions{}), target); code == http.StatusOK {
		t.Fatal("without a policy the private CA must not be trusted")
	}
	if code, body := proxyOnce(NewDynamicProxyCore(target, "", &DpcoreOptions{UpstreamTLS: upstreamtls.Policy{CABundlePEM: ca.PEM()}}), target); code != 200 || body != "upstream-ok" {
		t.Fatalf("private CA must be accepted, got %d %q", code, body)
	}
	if code, _ := proxyOnce(NewDynamicProxyCore(target, "", &DpcoreOptions{UpstreamTLS: upstreamtls.Policy{CABundlePEM: other.PEM()}}), target); code == http.StatusOK {
		t.Fatal("wrong CA must be rejected")
	}
	//skip verify keeps working exactly as before when no policy is set
	if code, _ := proxyOnce(NewDynamicProxyCore(target, "", &DpcoreOptions{IgnoreTLSVerification: true}), target); code != http.StatusOK {
		t.Fatal("skip verify without a policy must still work")
	}
	//a policy replaces skip verify
	if code, _ := proxyOnce(NewDynamicProxyCore(target, "", &DpcoreOptions{IgnoreTLSVerification: true, UpstreamTLS: upstreamtls.Policy{CABundlePEM: other.PEM()}}), target); code == http.StatusOK {
		t.Fatal("a CA bundle must replace skip verify, not add to it")
	}
}

// The CONNECT / upgrade tunnel dials the upstream itself: it must use the same policy
func TestConnectTunnelHonorsUpstreamTLSPolicy(t *testing.T) {
	ca, other := tlstest.NewCA("good"), tlstest.NewCA("other")
	cert := ca.Issue(tlstest.Options{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	target := startTLSUpstream(t, cert)

	tunnel := func(pol upstreamtls.Policy) (reply string) {
		p := NewDynamicProxyCore(target, "", &DpcoreOptions{UpstreamTLS: pol})
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
		br := bufio.NewReader(c)
		status, _ := br.ReadString('\n')
		if !strings.Contains(status, "200") {
			return "refused"
		}
		br.ReadString('\n') //end of the CONNECT reply headers
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			sb.WriteString(line)
			if err != nil {
				break
			}
		}
		return sb.String()
	}

	if got := tunnel(upstreamtls.Policy{CABundlePEM: ca.PEM()}); !strings.Contains(got, "upstream-ok") {
		t.Fatalf("tunnel with the private CA must reach the upstream, got %q", got)
	}
	if got := tunnel(upstreamtls.Policy{CABundlePEM: other.PEM()}); strings.Contains(got, "upstream-ok") {
		t.Fatalf("tunnel with the wrong CA must not reach the upstream, got %q", got)
	}
	//historical behavior (no policy): the tunnel verifies with the system roots, a private CA is not trusted
	if got := tunnel(upstreamtls.Policy{}); strings.Contains(got, "upstream-ok") {
		t.Fatalf("tunnel without a policy must keep verifying with system roots, got %q", got)
	}
}
