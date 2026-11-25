package loadbalance

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/dpcore"
	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/upstreamtls"
)

// StartProxy create and start a HTTP proxy using dpcore
// Example of webProxyEndpoint: https://example.com:443 or http://192.168.1.100:8080
// tlsServerName, if not empty, overrides the TLS SNI and certificate verification
// hostname used when connecting to a HTTPS upstream. Pass an empty string to derive
// it from the upstream address.
func (u *Upstream) StartProxy(tlsServerName string) error {
	//Filter the tailing slash if any
	domain := u.OriginIpOrDomain
	if len(domain) == 0 {
		return errors.New("invalid endpoint config")
	}
	if domain[len(domain)-1:] == "/" {
		domain = domain[:len(domain)-1]
	}

	unixSock := ""
	if sock, ok := UnixSocketPath(domain); ok {
		if err := ValidateUnixSocketPath(sock); err != nil {
			return err
		}
		unixSock = sock
		domain = "unix.socket" //placeholder host, the dialer ignores it
	}

	if !strings.HasPrefix("http://", domain) && !strings.HasPrefix("https://", domain) {
		//TLS is not hardcoded in proxy target domain
		if u.RequireTLS {
			domain = "https://" + domain
		} else {
			domain = "http://" + domain
		}
	}

	//Create a new proxy agent for this upstream
	path, err := url.Parse(domain)
	if err != nil {
		return err
	}

	proxyProto := 0
	if u.ProxyProtocol == 1 || u.ProxyProtocol == 2 {
		proxyProto = u.ProxyProtocol
	}

	proxy := dpcore.NewDynamicProxyCore(path, "", &dpcore.DpcoreOptions{
		IgnoreTLSVerification:   u.SkipCertValidations,
		FlushInterval:           100 * time.Millisecond,
		ResponseHeaderTimeout:   u.RespTimeout,
		MaxConcurrentConnection: u.MaxConn,
		UpstreamTLSServerName:   tlsServerName,
		DisableKeepAlive:        u.DisableKeepAlive,
		H2C:                     u.H2C && !u.RequireTLS && proxyProto == 0 && unixSock == "",
		UnixSocket:              unixSock,
		ProxyProtocolVersion:    proxyProto,
		ClientCertificate:       u.clientCertCallback(),
		UpstreamTLS:             u.TLSPolicy(),
	})

	u.proxy = proxy
	u.tlsServerName = tlsServerName
	return nil
}

// IsReady return the proxy ready state of the upstream server
// Return false if StartProxy() is not called on this upstream before
func (u *Upstream) IsReady() bool {
	return u.proxy != nil
}

// Clone return a new deep copy object of the identical upstream
func (u *Upstream) Clone() *Upstream {
	newUpstream := Upstream{}
	js, _ := json.Marshal(u)
	json.Unmarshal(js, &newUpstream)
	return &newUpstream
}

// ServeHTTP uses this upstream proxy router to route the current request, return the status code and error if any
func (u *Upstream) ServeHTTP(w http.ResponseWriter, r *http.Request, rrr *dpcore.ResponseRewriteRuleSet) (int, error) {
	//Auto rewrite to upstream origin if not set
	if rrr.ProxyDomain == "" {
		rrr.ProxyDomain = u.OriginIpOrDomain
	}

	return u.proxy.ServeHTTP(w, r, rrr)
}

// String return the string representations of endpoints in this upstream
func (u *Upstream) String() string {
	return u.OriginIpOrDomain
}

// TLSPolicy returns the custom CA / pin policy of this upstream (zero value when none is set or TLS is off)
func (u *Upstream) TLSPolicy() upstreamtls.Policy {
	if !u.RequireTLS {
		return upstreamtls.Policy{}
	}
	return upstreamtls.Policy{CABundlePEM: u.TLSCABundlePEM, PinsSHA256: u.TLSPinsSHA256}
}

// ClientCertificateCallback returns the upstream mTLS client certificate callback (nil when none), for the WebSocket path
func (u *Upstream) ClientCertificateCallback() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return u.clientCertCallback()
}

// UpstreamClientCertLoader loads the named client certificate pair of the certificate store.
// Set by the main package at start up; nil disables upstream mTLS.
var UpstreamClientCertLoader func(name string) (*tls.Certificate, error)

// clientCertCallback returns the callback that presents the configured client certificate, or nil.
// The pair is read again on every handshake, so a renewed certificate is picked up without a restart.
func (u *Upstream) clientCertCallback() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	name := u.ClientCertName
	if name == "" || !u.RequireTLS {
		return nil
	}
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if UpstreamClientCertLoader == nil {
			return nil, errors.New("upstream client certificates are not available")
		}
		return UpstreamClientCertLoader(name)
	}
}

var upstreamCertNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// ValidateTransportOptions checks the optional PROXY protocol and client certificate settings of an upstream
func (u *Upstream) ValidateTransportOptions() error {
	if err := u.validateUnix(); err != nil {
		return err
	}
	if u.ProxyProtocol < 0 || u.ProxyProtocol > 2 {
		return errors.New("PROXY protocol version must be 0 (off), 1 or 2")
	}
	if u.TLSCABundlePEM != "" || len(u.TLSPinsSHA256) > 0 {
		if !u.RequireTLS {
			return errors.New("a CA bundle or pin can only be used with an upstream that requires TLS")
		}
		norm, err := (upstreamtls.Policy{CABundlePEM: u.TLSCABundlePEM, PinsSHA256: u.TLSPinsSHA256}).Normalized()
		if err != nil {
			return err
		}
		if err := norm.Validate(); err != nil {
			return err
		}
		u.TLSCABundlePEM, u.TLSPinsSHA256 = norm.CABundlePEM, norm.PinsSHA256
	}
	if u.ClientCertName != "" {
		if !upstreamCertNamePattern.MatchString(u.ClientCertName) || strings.Contains(u.ClientCertName, "..") {
			return errors.New("invalid client certificate name")
		}
		if !u.RequireTLS {
			return errors.New("a client certificate can only be used with an upstream that requires TLS")
		}
	}
	return nil
}
