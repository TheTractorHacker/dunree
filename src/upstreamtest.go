package main

/*
	upstreamtest.go

	Read only connection test used by the "New proxy rule" dialog.

	GET /api/proxy/testupstream?url=HOST[:PORT][/path]   (an http:// or https:// prefix is accepted and used as a hint)
	  -> {"ok":bool,"protocol":"http|https|","status":int,"selfsign":bool,"latencyMs":int,"address":"host:port","error":"..."}

	It dials the address, works out whether the upstream speaks TLS, whether its certificate verifies, and what a plain
	GET answers. Nothing is stored. A unix: socket address is only checked for existence and connectability.
*/

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/foleyit/dunree/mod/destguard"
	"github.com/foleyit/dunree/mod/dynamicproxy/upstreamtls"
	"github.com/foleyit/dunree/mod/utils"
)

type upstreamTestResult struct {
	OK        bool   `json:"ok"`
	Protocol  string `json:"protocol"`
	Status    int    `json:"status"`
	SelfSign  bool   `json:"selfsign"`
	LatencyMs int64  `json:"latencyMs"`
	Address   string `json:"address"`
	Error     string `json:"error,omitempty"`
	//Only set when a CA bundle or pin was given: whether the certificate was accepted by that policy
	TrustChecked bool   `json:"trustChecked,omitempty"`
	TrustOK      bool   `json:"trustOK,omitempty"`
	TrustError   string `json:"trustError,omitempty"`
}

const upstreamTestTimeout = 4 * time.Second

// splitUpstreamTarget splits user input into a dial address (host:port), a request path and a protocol hint
func splitUpstreamTarget(raw string) (addr string, path string, hint string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", errors.New("no address given")
	}
	switch {
	case strings.HasPrefix(strings.ToLower(raw), "https://"):
		hint, raw = "https", raw[len("https://"):]
	case strings.HasPrefix(strings.ToLower(raw), "http://"):
		hint, raw = "http", raw[len("http://"):]
	}
	u, perr := url.Parse("//" + raw)
	if perr != nil || u.Hostname() == "" {
		return "", "", "", errors.New("invalid address")
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		if hint == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path = u.RequestURI()
	if path == "" {
		path = "/"
	}
	return net.JoinHostPort(host, port), path, hint, nil
}

// testUpstream probes one upstream address
func testUpstream(raw string) upstreamTestResult {
	return testUpstreamWith(raw, upstreamtls.Policy{}, "")
}

// testUpstreamWith probes one upstream address. When pol is active, an HTTPS upstream is verified with the same policy
// the proxy uses (custom CA replaces the system roots, pins, host name check against serverName or the host) and a
// certificate that does not pass is a failed test, not a note.
func testUpstreamWith(raw string, pol upstreamtls.Policy, serverName string) upstreamTestResult {
	start := time.Now()
	res := upstreamTestResult{}

	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "unix:") {
		sock := strings.TrimSpace(raw)[len("unix:"):]
		res.Address = "unix:" + sock
		if destguard.Restricting() {
			res.Error = "unix sockets cannot be tested while the destination restriction is on"
			return res
		}
		c, err := net.DialTimeout("unix", sock, upstreamTestTimeout)
		res.LatencyMs = time.Since(start).Milliseconds()
		if err != nil {
			res.Error = "cannot connect to the socket: " + err.Error()
			return res
		}
		c.Close()
		res.OK, res.Protocol = true, "http"
		return res
	}

	addr, path, hint, err := splitUpstreamTarget(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Address = addr

	// 1. can we connect at all
	c, err := destguard.DialTimeout("tcp", addr, upstreamTestTimeout)
	if err != nil {
		res.LatencyMs = time.Since(start).Milliseconds()
		res.Error = "cannot connect: " + shortNetErr(err)
		return res
	}
	c.Close()
	res.LatencyMs = time.Since(start).Milliseconds()

	host, _, _ := net.SplitHostPort(addr)
	// 2. does it speak TLS (unless the user said plain http)
	if hint != "http" {
		d := &net.Dialer{Timeout: upstreamTestTimeout}
		tc, terr := testTLSDial(d, addr, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if terr == nil {
			tc.Close()
			res.Protocol = "https"
			// does the certificate verify
			vc, verr := testTLSDial(d, addr, &tls.Config{ServerName: host})
			if verr != nil {
				res.SelfSign = true
			} else {
				vc.Close()
			}
			if pol.Active() {
				res.TrustChecked = true
				pc, perr := testTLSDial(d, addr, policyTLSConfig(pol, host, serverName))
				if perr != nil {
					res.TrustError = shortNetErr(perr)
					res.Error = "TLS verification with the configured CA / pin failed: " + res.TrustError
					return res
				}
				pc.Close()
				res.TrustOK = true
			}
		} else if pol.Active() && hint == "https" {
			res.Error = "the address does not speak TLS"
			return res
		}
	}
	if res.Protocol == "" {
		res.Protocol = "http"
	}

	// 3. what does a GET answer (certificate errors are not an issue for a reachability test)
	client := &http.Client{
		Timeout:       upstreamTestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true},
	}
	if res.TrustChecked {
		//Verified earlier with the policy; the request itself uses it too so it cannot talk to a different certificate
		client.Transport = &http.Transport{TLSClientConfig: policyTLSConfig(pol, host, serverName), DisableKeepAlives: true}
	}
	if destguard.Restricting() {
		//Destination restriction (opt-in): the request dials through the guard, which resolves once and checks
		client.Transport.(*http.Transport).DialContext = destguard.DialContext
	}
	t0 := time.Now()
	resp, err := client.Get(res.Protocol + "://" + addr + path)
	if err != nil {
		if res.Protocol == "http" {
			res.OK = true // the port accepts connections; it may just not speak HTTP the way a browser does
			res.Error = "connected, but the HTTP request failed: " + shortNetErr(err)
		} else {
			res.Error = "TLS connected, but the HTTPS request failed: " + shortNetErr(err)
		}
		return res
	}
	resp.Body.Close()
	res.OK = true
	res.Status = resp.StatusCode
	res.LatencyMs = time.Since(t0).Milliseconds()
	return res
}

// policyTLSConfig is the tls.Config the proxy would use for this upstream: host name verification stays on
func policyTLSConfig(pol upstreamtls.Policy, host, serverName string) *tls.Config {
	cfg := &tls.Config{ServerName: host}
	if sn := strings.TrimSpace(serverName); sn != "" {
		if h, _, err := net.SplitHostPort(sn); err == nil {
			sn = h
		}
		if net.ParseIP(sn) == nil {
			cfg.ServerName = sn
		}
	}
	pol.Apply(cfg)
	return cfg
}

// testTLSDial is tls.DialWithDialer; with the destination restriction on the TCP connection goes through the guard
func testTLSDial(d *net.Dialer, addr string, cfg *tls.Config) (*tls.Conn, error) {
	if !destguard.Restricting() {
		return tls.DialWithDialer(d, "tcp", addr, cfg)
	}
	raw, err := destguard.DialTimeout("tcp", addr, d.Timeout)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	raw.SetDeadline(time.Now().Add(d.Timeout))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return tc, nil
}

func shortNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func HandleTestUpstream(w http.ResponseWriter, r *http.Request) {
	target, err := utils.GetPara(r, "url")
	if err != nil && r.Method == http.MethodPost {
		target, err = utils.PostPara(r, "url")
	}
	if err != nil {
		utils.SendErrorResponse(w, "url is required")
		return
	}
	//Optional trust policy (POST, because a CA bundle does not fit a query string)
	pol := upstreamtls.Policy{}
	serverName := ""
	if r.Method == http.MethodPost {
		pol.CABundlePEM, _ = utils.PostPara(r, "cabundle")
		if pins, _ := utils.PostPara(r, "pins"); pins != "" {
			pol.PinsSHA256 = splitPins(pins)
		}
		serverName, _ = utils.PostPara(r, "servername")
		if ep, perr := utils.PostPara(r, "ep"); perr == nil && serverName == "" && dynamicProxyRouter != nil {
			//Same host name the proxy verifies with: the rule's "overwrite host header" value
			if rule, lerr := dynamicProxyRouter.LoadProxy(ep); lerr == nil && rule != nil && rule.HeaderRewriteRules != nil {
				serverName = rule.HeaderRewriteRules.RequestHostOverwrite
			}
		}
		norm, err := pol.Normalized()
		if err == nil {
			err = norm.Validate()
		}
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		pol = norm
	}
	js, _ := json.Marshal(testUpstreamWith(target, pol, serverName))
	utils.SendJSONResponse(w, string(js))
}

// splitPins splits a pin list typed one per line, or separated by commas or spaces
func splitPins(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';' })
}

// HandleUpstreamTLSInspect lists the certificates of a pasted CA bundle with their fingerprints and SPKI pins, and
// normalizes a pin list, so the admin can check what is about to be saved. POST cabundle, pins (optional)
func HandleUpstreamTLSInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	bundle, _ := utils.PostPara(r, "cabundle")
	pinsRaw, _ := utils.PostPara(r, "pins")
	out := struct {
		Certs []upstreamtls.CertInfo
		Pins  []string
	}{Certs: []upstreamtls.CertInfo{}, Pins: []string{}}
	if strings.TrimSpace(bundle) != "" {
		_, infos, err := upstreamtls.ParseBundle(bundle, time.Now())
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		out.Certs = infos
	}
	pins, err := upstreamtls.NormalizePins(splitPins(pinsRaw))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	out.Pins = pins
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}
