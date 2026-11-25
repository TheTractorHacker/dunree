package crowdsec

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TheTractorHacker/dunree/mod/destguard"
	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

// UserAgent identifies this bouncer to the LAPI: "dunree-crowdsec-bouncer/1.0", with the inherited token
// appended while the legacy names are on (plan row 13)
func UserAgent() string {
	return wirecompat.UserAgent("dunree-crowdsec-bouncer/1.0", "zoraxy-crowdsec-bouncer/1.0")
}

const (
	maxStreamBytes   = 128 << 20 // a full answer larger than this is refused (the cache is bounded anyway)
	maxLookupBytes   = 1 << 20
	lookupTimeout    = 10 * time.Second
	maxDeletedPerRun = 2_000_000
)

// Timeouts of a full and of a delta pull (variables so tests can shorten them)
var (
	startupTimeout = 90 * time.Second
	deltaTimeout   = 20 * time.Second
)

// ErrAuth is returned when the LAPI answers 403 (documented answer for a missing or wrong API key) or 401
var ErrAuth = errors.New("the LAPI rejected the API key (HTTP 403 or 401)")

// apiDecision is the decision object of the LAPI answer. Documented fields only.
type apiDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// CheckLAPIAddr resolves host once and refuses cloud metadata, link-local, multicast, unspecified and reserved
// addresses. The LAPI is defined by the administrator and usually sits on the same host or LAN, so loopback and
// private ranges are allowed (that is the difference to the diagnostic tools guard).
func CheckLAPIAddr(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if _, cerr := destguard.Classify(a); cerr != nil {
			return nil, cerr
		}
		return []netip.Addr{a.WithZone("").Unmap()}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the LAPI host name: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("the LAPI host name has no address")
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, a := range ips {
		if _, cerr := destguard.Classify(a); cerr != nil { // a mixed answer is refused as a whole
			return nil, cerr
		}
		out = append(out, a.WithZone("").Unmap())
	}
	return out, nil
}

// guardedDial resolves and checks the destination once and dials a checked address (DNS rebinding between check and connect is not possible)
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := CheckLAPIAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var last error
	for _, ip := range ips {
		c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return c, nil
		}
		last = derr
	}
	return nil, last
}

// Client talks to one LAPI. It never follows redirects (the API key must not be sent anywhere else) and never uses
// the environment proxy.
type Client struct {
	base *url.URL
	key  string
	http *http.Client
}

// NewClient builds a client for the settings. key is the plain API key.
func NewClient(s Settings, key string, timeout time.Duration) (*Client, error) {
	u, err := ParseLAPIURL(s.LAPIURL)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           guardedDial,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       60 * time.Second,
		DisableCompression:    false,
	}
	if u.Scheme == "https" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		s.Policy().Apply(cfg) // custom CA and pins, never skip-verify
		tr.TLSClientConfig = cfg
	}
	return &Client{base: u, key: key, http: &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close releases idle connections
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.key)
	req.Header.Set("User-Agent", UserAgent())
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.scrub(err)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, ErrAuth
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("the LAPI answered HTTP %d", resp.StatusCode) //the body is never quoted
	}
	return resp, nil
}

// scrub makes sure a transport error cannot carry the key
func (c *Client) scrub(err error) error {
	msg := err.Error()
	if c.key != "" {
		msg = strings.ReplaceAll(msg, c.key, "[key]")
	}
	return errors.New(msg)
}

// Lookup is GET /v1/decisions?ip=<ip>: one authenticated call. It returns the decisions that apply (none = JSON null).
func (c *Client) Lookup(ctx context.Context, ip string) ([]apiDecision, error) {
	resp, err := c.get(ctx, "/v1/decisions", url.Values{"ip": {ip}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []apiDecision
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxLookupBytes)).Decode(&out); err != nil {
		return nil, errors.New("the LAPI answer is not valid JSON")
	}
	return out, nil
}

// Stream is GET /v1/decisions/stream[?startup=true]. The answer {"new":[...],"deleted":[...]} is decoded element
// by element (memory stays bounded whatever the size of the answer); fn is called for every decision with
// deleted=false for "new" and true for "deleted". An error from fn aborts the call.
func (c *Client) Stream(ctx context.Context, startup bool, fn func(d apiDecision, deleted bool) error) error {
	q := url.Values{"scopes": {"Ip,Range"}} //the only scopes enforced; others are not downloaded (the answer is still checked per decision)
	if startup {
		q.Set("startup", "true")
	}
	resp, err := c.get(ctx, "/v1/decisions/stream", q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxStreamBytes))
	bad := errors.New("the LAPI answer is not the documented {\"new\":[...],\"deleted\":[...]} JSON")
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return bad
	}
	deleted := 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return bad
		}
		key, _ := kt.(string)
		switch key {
		case "new", "deleted":
			t, err := dec.Token()
			if err != nil {
				return bad
			}
			if t == nil { // null = nothing
				continue
			}
			if t != json.Delim('[') {
				return bad
			}
			for dec.More() {
				var d apiDecision
				if err := dec.Decode(&d); err != nil {
					return bad
				}
				if key == "deleted" {
					if deleted++; deleted > maxDeletedPerRun {
						return errors.New("the LAPI answer holds too many deleted decisions")
					}
				}
				if err := fn(d, key == "deleted"); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing ]
				return bad
			}
		default:
			var skip json.RawMessage // unknown member (future LAPI versions): ignored
			if err := dec.Decode(&skip); err != nil {
				return bad
			}
		}
	}
	if _, err := dec.Token(); err != nil { // closing }
		return bad
	}
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("no duration")
	}
	return time.ParseDuration(s)
}

func itoa(i int) string { return strconv.Itoa(i) }
