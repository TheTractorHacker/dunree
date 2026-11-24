package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
	Management of CrowdSec from the admin UI (docs/guides/crowdsec.md, "Manage CrowdSec").

	The bouncer key can only READ decisions. Adding or removing a ban, and reading alerts, needs a LAPI machine
	("watcher") login, which is a separate, optional credential:

	  - it is created by the administrator on the CrowdSec host (cscli machines add), pasted here once, sealed in
	    conf/crowdsec/ like the API key, never returned by any endpoint, never logged and never exported;
	  - it is bound to the LAPI address it was entered for and is never sent anywhere else;
	  - every write is limited (a few per minute), validated (no loopback, no server or trusted proxy address, no huge
	    ranges, bounded duration) and recorded by the security audit log with the actor.

	CrowdSec stays the single source of truth: Dunree keeps no copy of the bans it creates; the bouncer pull picks
	them up like any other decision.
*/

const (
	adminTimeout   = 15 * time.Second
	maxAdminBody   = 8 << 20
	MaxBanDuration = 30 * 24 * time.Hour
	MinBanDuration = time.Minute
	maxReason      = 200
	writesPerMin   = 20
	// ManualScenario marks the decisions created from this panel. Decisions made before the rename
	// carry LegacyManualScenario; they are listed and lifted like any other (nothing matches on it).
	ManualScenario       = "dunree/manual-ban"
	LegacyManualScenario = "zoraxy/manual-ban" // legacy-compat
)

// ErrNoMachine is returned when no machine login is stored
var ErrNoMachine = errors.New("no CrowdSec machine login is stored (see \"Manage CrowdSec\" to add one)")

// Alert is one alert of the LAPI, reduced to what the panel shows
type Alert struct {
	ID        int64     `json:"id"`
	Time      string    `json:"time"`
	Scenario  string    `json:"scenario"`
	Message   string    `json:"message"`
	Events    int       `json:"events"`
	Scope     string    `json:"scope"`
	Value     string    `json:"value"`
	Country   string    `json:"country"`
	AS        string    `json:"as"`
	Simulated bool      `json:"simulated"`
	Decisions []Decided `json:"decisions"`
}

// Decided is a decision attached to an alert
type Decided struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
}

type apiAlert struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	StartAt   string `json:"start_at"`
	Scenario  string `json:"scenario"`
	Message   string `json:"message"`
	Events    int    `json:"events_count"`
	Simulated bool   `json:"simulated"`
	Source    struct {
		Scope string `json:"scope"`
		Value string `json:"value"`
		CN    string `json:"cn"`
		AS    string `json:"as_name"`
	} `json:"source"`
	Decisions []struct {
		ID       int64  `json:"id"`
		Type     string `json:"type"`
		Scope    string `json:"scope"`
		Value    string `json:"value"`
		Duration string `json:"duration"`
		Origin   string `json:"origin"`
		Scenario string `json:"scenario"`
	} `json:"decisions"`
}

// adminSession is the cached JWT of the machine login
type adminSession struct {
	mu     sync.Mutex
	token  string
	expire time.Time
	bind   string
}

// adminState is kept by the Manager
type adminState struct {
	sess   adminSession
	wmu    sync.Mutex
	writes []time.Time
}

// MachineSet reports whether a machine login is stored
func (m *Manager) MachineSet() bool { return m.vault != nil && m.vault.MachineSet() }

// SetMachine stores a machine login for the current LAPI address. The login is tested before it is kept.
func (m *Manager) SetMachine(ctx context.Context, id, pw string) error {
	id, pw = strings.TrimSpace(id), strings.TrimSpace(pw)
	if err := ValidMachine(id, pw); err != nil {
		return err
	}
	s := m.Settings()
	if s.LAPIURL == "" {
		return errors.New("save the LAPI address first")
	}
	if err := s.Normalize(); err != nil {
		return err
	}
	cl, err := NewClient(s, "", adminTimeout)
	if err != nil {
		return err
	}
	defer cl.Close()
	if _, _, err := cl.login(ctx, id, pw); err != nil {
		return err
	}
	if err := m.vault.SetMachine(MachineCreds{ID: id, Password: pw}); err != nil {
		return err
	}
	if err := m.vault.SetMachineBinding(BindingOf(s.LAPIURL)); err != nil {
		_ = m.vault.ClearMachine()
		return err
	}
	m.adm.sess.reset()
	return nil
}

// ClearMachine removes the machine login
func (m *Manager) ClearMachine() error {
	m.adm.sess.reset()
	return m.vault.ClearMachine()
}

func (a *adminSession) reset() {
	a.mu.Lock()
	a.token, a.expire, a.bind = "", time.Time{}, ""
	a.mu.Unlock()
}

// MachineID returns the stored machine id (not the password), for display
func (m *Manager) MachineID() string {
	c, ok, err := m.vault.Machine()
	if err != nil || !ok {
		return ""
	}
	return c.ID
}

// statusError is a non-success answer of the LAPI (the body is never quoted)
type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("the LAPI answered HTTP %d", e.code) }

// rawJSON sends one JSON request with an optional bearer token and decodes the answer into out (nil = ignore)
func (c *Client) rawJSON(ctx context.Context, method, path string, q url.Values, body []byte, bearer string, out interface{}) error {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return c.scrub(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return statusError{resp.StatusCode}
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAdminBody)).Decode(out); err != nil {
		return errors.New("the LAPI answer is not valid JSON")
	}
	return nil
}

// login is POST /v1/watchers/login
func (c *Client) login(ctx context.Context, id, pw string) (string, time.Time, error) {
	body, _ := json.Marshal(map[string]interface{}{"machine_id": id, "password": pw, "scenarios": []string{}})
	var out struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := c.rawJSON(ctx, http.MethodPost, "/v1/watchers/login", nil, body, "", &out); err != nil {
		var se statusError
		if errors.As(err, &se) && (se.code == 401 || se.code == 403) {
			return "", time.Time{}, errors.New("the LAPI rejected the machine login (wrong id or password, or the machine is not validated yet: cscli machines validate)")
		}
		return "", time.Time{}, errors.New(strings.NewReplacer(pw, "[password]", id, "[machine]").Replace(err.Error()))
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("the LAPI login answer holds no token")
	}
	exp, err := time.Parse(time.RFC3339, out.Expire)
	if err != nil || exp.Before(time.Now()) {
		exp = time.Now().Add(10 * time.Minute) // unknown lifetime: short, a new login is cheap
	}
	return out.Token, exp, nil
}

// adminCall runs one authenticated request with the stored machine login (one retry after a fresh login on 401)
func (m *Manager) adminCall(ctx context.Context, method, path string, q url.Values, body []byte, out interface{}) error {
	if m.vault == nil {
		return ErrNoMachine
	}
	creds, ok, err := m.vault.Machine()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoMachine
	}
	s := m.Settings()
	if s.LAPIURL == "" {
		return errors.New("the LAPI address is not set")
	}
	if b, has := m.vault.MachineBinding(); !has || b != BindingOf(s.LAPIURL) {
		return errors.New("the machine login was entered for another LAPI address; enter it again")
	}
	if err := s.Normalize(); err != nil {
		return err
	}
	cl, err := NewClient(s, "", adminTimeout)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := m.adminToken(ctx, cl, creds)
		if err != nil {
			return err
		}
		err = cl.rawJSON(ctx, method, path, q, body, tok, out)
		var se statusError
		if errors.As(err, &se) && se.code == 401 && attempt == 0 {
			m.adm.sess.reset()
			continue
		}
		if errors.As(err, &se) && se.code == 403 {
			return errors.New("the LAPI refused this action for the machine login")
		}
		return err
	}
	return errors.New("the LAPI keeps rejecting the machine login")
}

func (m *Manager) adminToken(ctx context.Context, cl *Client, c MachineCreds) (string, error) {
	ss := &m.adm.sess
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.token != "" && time.Until(ss.expire) > 30*time.Second {
		return ss.token, nil
	}
	tok, exp, err := cl.login(ctx, c.ID, c.Password)
	if err != nil {
		return "", err
	}
	ss.token, ss.expire = tok, exp
	return tok, nil
}

// TestMachine logs in with the stored machine login (a fresh login, not the cached token)
func (m *Manager) TestMachine(ctx context.Context) error {
	m.adm.sess.reset()
	return m.adminCall(ctx, http.MethodGet, "/v1/alerts", url.Values{"limit": {"1"}}, nil, nil)
}

func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

func toAlerts(in []apiAlert) []Alert {
	out := make([]Alert, 0, len(in))
	for _, a := range in {
		al := Alert{ID: a.ID, Time: cleanText(firstNonEmpty(a.StartAt, a.CreatedAt), 40), Scenario: cleanText(a.Scenario, 120), Message: cleanText(a.Message, 300),
			Events: a.Events, Scope: cleanText(a.Source.Scope, 20), Value: cleanText(a.Source.Value, 64), Country: cleanText(a.Source.CN, 8),
			AS: cleanText(a.Source.AS, 80), Simulated: a.Simulated, Decisions: []Decided{}}
		for _, d := range a.Decisions {
			al.Decisions = append(al.Decisions, Decided{ID: d.ID, Type: cleanText(d.Type, 20), Scope: cleanText(d.Scope, 20), Value: cleanText(d.Value, 64),
				Duration: cleanText(d.Duration, 40), Origin: cleanText(d.Origin, 40), Scenario: cleanText(d.Scenario, 120)})
		}
		out = append(out, al)
	}
	return out
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// Alerts returns the newest alerts (limit 1..200); ip, when not empty, filters on one address
func (m *Manager) Alerts(ctx context.Context, ip string, limit int) ([]Alert, error) {
	q := url.Values{"limit": {strconv.Itoa(clampInt(limit, 1, 200, 50))}}
	if ip = strings.TrimSpace(ip); ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, errors.New("not an IP address")
		}
		q.Set("ip", a.String())
	}
	var raw []apiAlert
	if err := m.adminCall(ctx, http.MethodGet, "/v1/alerts", q, nil, &raw); err != nil {
		return nil, err
	}
	return toAlerts(raw), nil
}

// ActiveDecisions lists the decisions that are active now (the way "cscli decisions list" does: alerts that still
// have an active decision). filter keeps rows whose value, scenario or origin contains it.
func (m *Manager) ActiveDecisions(ctx context.Context, filter string, limit int) ([]Decided, error) {
	q := url.Values{"has_active_decision": {"true"}, "limit": {strconv.Itoa(clampInt(limit, 1, 500, 200))}}
	var raw []apiAlert
	if err := m.adminCall(ctx, http.MethodGet, "/v1/alerts", q, nil, &raw); err != nil {
		return nil, err
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	out := []Decided{}
	seen := map[int64]bool{}
	for _, al := range toAlerts(raw) {
		for _, d := range al.Decisions {
			if seen[d.ID] || strings.HasPrefix(d.Duration, "-") {
				continue
			}
			seen[d.ID] = true
			if filter != "" && !strings.Contains(strings.ToLower(d.Value+" "+d.Scenario+" "+d.Origin), filter) {
				continue
			}
			out = append(out, d)
		}
	}
	return out, nil
}

func clampInt(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ParseBanTarget validates what an administrator may ban from the panel: one address or a range no wider than
// /16 (IPv4) or /48 (IPv6). Loopback, unspecified and multicast addresses are refused.
func ParseBanTarget(s string) (scope, value string, pfx netip.Prefix, err error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			return "", "", pfx, errors.New("not an IP address or range")
		}
		p = p.Masked()
		min := 16
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			min = 48
		}
		if p.Bits() < min {
			return "", "", pfx, fmt.Errorf("the range is too wide (at most /%d)", min)
		}
		if bad := badBanAddr(p.Addr()); bad != "" {
			return "", "", pfx, errors.New(bad)
		}
		if p.IsSingleIP() {
			return "Ip", p.Addr().String(), p, nil
		}
		return "Range", p.String(), p, nil
	}
	a, perr := netip.ParseAddr(s)
	if perr != nil {
		return "", "", pfx, errors.New("not an IP address or range")
	}
	a = a.Unmap()
	if bad := badBanAddr(a); bad != "" {
		return "", "", pfx, errors.New(bad)
	}
	return "Ip", a.String(), netip.PrefixFrom(a, a.BitLen()), nil
}

func badBanAddr(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "a loopback address cannot be banned"
	case a.IsUnspecified():
		return "the unspecified address cannot be banned"
	case a.IsMulticast():
		return "a multicast address cannot be banned"
	}
	return ""
}

// ParseBanDuration reads 30m, 4h, 7d (a bare number is hours) and bounds it to 1 minute .. 30 days
func ParseBanDuration(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, errors.New("a duration is required")
	}
	var d time.Duration
	if n, err := strconv.Atoi(s); err == nil {
		d = time.Duration(n) * time.Hour
	} else if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, errors.New("invalid duration (examples: 30m, 4h, 7d)")
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, errors.New("invalid duration (examples: 30m, 4h, 7d)")
		}
	}
	if d < MinBanDuration || d > MaxBanDuration {
		return 0, errors.New("the duration must be between 1 minute and 30 days")
	}
	return d, nil
}

func (m *Manager) allowWrite() bool {
	a := &m.adm
	a.wmu.Lock()
	defer a.wmu.Unlock()
	now := m.now()
	keep := a.writes[:0]
	for _, t := range a.writes {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	a.writes = keep
	if len(a.writes) >= writesPerMin {
		return false
	}
	a.writes = append(a.writes, now)
	return true
}

// Ban adds a ban decision. requester is the address of the administrator; a target that contains it, the server's
// own address or a trusted proxy (Manager.Protect) is refused so the panel cannot lock its own user out.
func (m *Manager) Ban(ctx context.Context, target string, dur time.Duration, reason, actor string, requester netip.Addr) (scope, value string, err error) {
	scope, value, pfx, err := ParseBanTarget(target)
	if err != nil {
		return "", "", err
	}
	if dur < MinBanDuration || dur > MaxBanDuration {
		return "", "", errors.New("the duration must be between 1 minute and 30 days")
	}
	if requester.IsValid() && pfx.Contains(requester.Unmap()) {
		return "", "", errors.New("this would ban the address you are using right now")
	}
	if pfx.IsSingleIP() && m.Protect != nil && m.Protect(pfx.Addr()) {
		return "", "", errors.New("this address is the server itself or a trusted proxy and cannot be banned")
	}
	if !m.allowWrite() {
		return "", "", errors.New("too many changes in a minute, wait and try again")
	}
	reason = cleanText(reason, maxReason)
	if reason == "" {
		reason = "manual ban from Dunree"
	}
	msg := reason + " (by " + cleanText(actor, 64) + ")"
	now := m.now().UTC().Format(time.RFC3339)
	alert := []map[string]interface{}{{
		"scenario": ManualScenario, "scenario_hash": "", "scenario_version": "", "message": msg, "events_count": 1,
		"start_at": now, "stop_at": now, "capacity": 0, "leakspeed": "0", "simulated": false, "events": []interface{}{},
		"source": map[string]string{"scope": scope, "value": value},
		"decisions": []map[string]interface{}{{"duration": dur.String(), "origin": "cscli", "scenario": ManualScenario,
			"scope": scope, "type": "ban", "value": value, "simulated": false}},
	}}
	body, _ := json.Marshal(alert)
	if err := m.adminCall(ctx, http.MethodPost, "/v1/alerts", nil, body, nil); err != nil {
		return "", "", err
	}
	return scope, value, nil
}

// Unban removes one decision by its id
func (m *Manager) Unban(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid decision id")
	}
	if !m.allowWrite() {
		return errors.New("too many changes in a minute, wait and try again")
	}
	return m.adminCall(ctx, http.MethodDelete, "/v1/decisions/"+strconv.FormatInt(id, 10), nil, nil, nil)
}
