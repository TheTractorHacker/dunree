package zorxauth

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/foleyit/dunree/mod/utils"
)

/*
	Where a one-time validation code may be sent

	The SSO portal hands the browser a one-time validation code and sends it to
	<target host>/<SSOSessionSetURL>, where it is turned into a session cookie.
	The target host comes from the "redirect" parameter, which anyone can put in
	a link. Three rules keep the code where it belongs:

	  1. the target must be a host this proxy protects with ZorxAuth
	     (SessionTargetPolicy). The per user allowed-host list is not enough: it
	     is empty by default, which means "every host".
	  2. the code is bound to the target host when it is minted and
	     handleSessionSetCallback refuses it on any other host.
	  3. the code is not sent over plain http to a host that is only served
	     over https.
*/

var (
	errSessionTargetInvalid      = errors.New("redirect target is not an absolute http(s) URL")
	errSessionTargetNotProtected = errors.New("redirect target is not a host protected by this SSO")
	errSessionTargetNeedsHTTPS   = errors.New("redirect target is only served over https")
)

// sessionTarget is a redirect target that passed resolveSessionTarget.
type sessionTarget struct {
	Scheme   string //http or https
	Hostname string //normalized, without port: what the validation code is bound to
	Port     string //as given in the redirect target, may be empty
}

// HostWithPort is the authority of the session-set URL on the target.
func (t *sessionTarget) HostWithPort() string {
	host := t.Hostname
	if strings.Contains(host, ":") {
		host = "[" + host + "]" //IPv6 literal
	}
	if t.Port != "" {
		return host + ":" + t.Port
	}
	return host
}

// normalizeTargetHost reduces a Host header or URL host to the lower case
// hostname without port, brackets or trailing dot, so the host a validation
// code was minted for compares equal to the host that receives it.
func normalizeTargetHost(hostport string) string {
	host := strings.TrimSpace(hostport)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return utils.NormalizeHostname(host)
}

// resolveSessionTarget checks that a one-time validation code may be sent to
// the host of redirectTarget and returns where the session-set URL goes.
// Without a SessionTargetPolicy every target is refused.
func (ar *AuthRouter) resolveSessionTarget(redirectTarget string) (*sessionTarget, error) {
	if strings.ContainsAny(redirectTarget, "\\\r\n\t") {
		//browsers read "\" as "/", url.Parse does not
		return nil, errSessionTargetInvalid
	}
	u, err := url.Parse(strings.TrimSpace(redirectTarget))
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errSessionTargetInvalid
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errSessionTargetInvalid
	}
	hostname := normalizeTargetHost(u.Hostname())
	if hostname == "" {
		return nil, errSessionTargetInvalid
	}
	if ar.SessionTargetPolicy == nil {
		return nil, errSessionTargetNotProtected
	}
	protected, httpsOnly := ar.SessionTargetPolicy(hostname)
	if !protected {
		return nil, errSessionTargetNotProtected
	}
	if httpsOnly && scheme != "https" {
		return nil, errSessionTargetNeedsHTTPS
	}
	return &sessionTarget{Scheme: scheme, Hostname: hostname, Port: u.Port()}, nil
}

// sameHostRedirect returns where handleSessionSetCallback may send the browser
// after the cookie is set: a path on this host, or an absolute http(s) URL of
// this host. Anything else becomes "/".
func sameHostRedirect(redirectURL, requestHost string) string {
	redirectURL = strings.TrimSpace(redirectURL)
	if redirectURL == "" || strings.ContainsAny(redirectURL, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(redirectURL)
	if err != nil || u.User != nil {
		return "/"
	}
	if u.Scheme == "" && u.Host == "" {
		if strings.HasPrefix(redirectURL, "/") && !strings.HasPrefix(redirectURL, "//") {
			return redirectURL
		}
		return "/"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "/"
	}
	host := normalizeTargetHost(u.Hostname())
	if host == "" || host != normalizeTargetHost(requestHost) {
		return "/"
	}
	return redirectURL
}
