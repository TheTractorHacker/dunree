package crowdsec

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// KV is the part of the sys.db API the manager needs (database.Database satisfies it)
type KV interface {
	Read(table, key string, assignee interface{}) error
	Write(table, key string, value interface{}) error
}

// Action is what the request path should do with a verdict
type Action string

const (
	ActionBan     Action = "ban"
	ActionCaptcha Action = "captcha"
	ActionClosed  Action = "fail-closed" // LAPI unreachable beyond the grace period and fail-closed is on
)

// Verdict is the answer of Check. The zero value means "nothing to do".
type Verdict struct {
	Matched  bool
	Action   Action
	Enforce  bool // false: log only (or an action that is only logged); the request must not be touched
	Drop     bool // ban response: close the connection instead of the 403 page
	Decision Decision
}

// Detail is the text for the blocked-request log: never contains anything but decision fields
func (v Verdict) Detail() string {
	if v.Action == ActionClosed {
		return "LAPI unreachable (fail-closed)"
	}
	d := v.Decision
	parts := []string{d.Type}
	if d.Scenario != "" {
		parts = append(parts, d.Scenario)
	}
	if d.Origin != "" {
		parts = append(parts, "("+d.Origin+")")
	}
	return strings.Join(parts, " ")
}

// Match is one recent hit (what the request path matched), for the dashboard
type Match struct {
	Time     time.Time `json:"time"`
	IP       string    `json:"ip"`
	Site     string    `json:"site"`
	Action   Action    `json:"action"`
	Enforced bool      `json:"enforced"`
	Type     string    `json:"type"`
	Scope    string    `json:"scope"`
	Value    string    `json:"value"`
	Origin   string    `json:"origin"`
	Scenario string    `json:"scenario"`
	Count    int       `json:"count"`
}

// Recent is a decision that arrived from the LAPI, for the dashboard
type Recent struct {
	Decision
	Added time.Time `json:"added"`
}

type state struct {
	s      Settings
	exempt map[string]bool
}

type tally struct {
	scopes    map[string]uint64
	types     map[string]uint64
	malformed uint64
}

const (
	ringSize   = 100
	maxTallyKs = 16
)

// Manager keeps settings, cache and health. All methods are safe for concurrent use.
type Manager struct {
	kv    KV
	vault *Vault
	adm   adminState

	// Protect, if set, reports addresses that must never be acted on (this server, trusted proxies)
	Protect func(netip.Addr) bool
	// Log receives short operational lines (never a key, never a response body). Optional.
	Log func(msg string)
	now func() time.Time

	cur    atomic.Pointer[state]
	cache  atomic.Pointer[Cache]
	active atomic.Bool

	pullMu  sync.Mutex // serialises pulls (held for a whole LAPI stream)
	applyMu sync.Mutex // Set and the commit of a pull: a pull that ran under older settings never lands after a Set
	ctlMu   sync.Mutex // cancel/done of the loop; never held across a pull, so Stop can always cancel
	pullSeq atomic.Uint64
	resync  atomic.Bool
	wake    chan struct{}

	enforced, logOnly, closedBlocks, unknownClients atomic.Uint64

	mu          sync.Mutex
	since       time.Time // enabled (or settings changed) at
	lastOK      time.Time
	lastTry     time.Time
	lastErr     string
	consecErrs  int
	totalErrs   uint64
	resyncs     uint64
	latency     time.Duration
	authFailed  bool
	tally       tally
	matches     []Match
	recents     []Recent
	logTokens   float64
	logTokenAt  time.Time
	suppressed  int
	lastFull    time.Time // last full (startup=true) synchronisation
	clamped     uint64    // decisions seen since the last full synchronisation that were cut to the maximum lifetime
	lastLogLine string

	cancel context.CancelFunc
	done   chan struct{}
}

// New loads the settings from kv. A stored value that no longer validates is ignored (feature off); the error says so.
func New(kv KV, vault *Vault) (*Manager, error) {
	m := &Manager{kv: kv, vault: vault, now: time.Now, wake: make(chan struct{}, 1)}
	m.cur.Store(&state{s: defaultSettings(), exempt: map[string]bool{}})
	m.cache.Store(NewCache(DefaultMaxEntries))
	if kv == nil {
		return m, nil
	}
	var stored Settings
	if err := kv.Read(DBTable, DBKey, &stored); err != nil {
		return m, nil
	}
	if err := stored.Normalize(); err != nil {
		return m, errors.New("stored CrowdSec settings ignored, feature off: " + err.Error())
	}
	m.install(stored)
	return m, nil
}

func defaultSettings() Settings {
	s := Settings{}
	_ = s.Normalize()
	return s
}

func (m *Manager) install(s Settings) {
	ex := make(map[string]bool, len(s.ExemptSites))
	for _, h := range s.ExemptSites {
		ex[h] = true
	}
	m.cur.Store(&state{s: s, exempt: ex})
	m.mu.Lock()
	m.since = m.now()
	m.mu.Unlock()
	m.active.Store(s.Enabled)
}

func (m *Manager) logf(msg string) {
	if m.Log != nil {
		m.Log(msg)
	}
}

// logLimited writes an operational line, at most about 30 per minute (excess is counted and reported once)
func (m *Manager) logLimited(msg string) {
	if m.Log == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	if m.logTokenAt.IsZero() {
		m.logTokens, m.logTokenAt = 30, now
	}
	m.logTokens += now.Sub(m.logTokenAt).Seconds() * 0.5
	if m.logTokens > 30 {
		m.logTokens = 30
	}
	m.logTokenAt = now
	if m.logTokens < 1 {
		m.suppressed++
		m.mu.Unlock()
		return
	}
	m.logTokens--
	sup := m.suppressed
	m.suppressed = 0
	m.mu.Unlock()
	if sup > 0 {
		msg += " (" + itoa(sup) + " similar lines suppressed)"
	}
	m.Log(msg)
}

// Settings returns a copy of the current settings
func (m *Manager) Settings() Settings {
	s := m.cur.Load().s
	s.ExemptSites = append([]string{}, s.ExemptSites...)
	s.PinsSHA256 = append([]string{}, s.PinsSHA256...)
	return s
}

// Active reports whether the feature is enabled (one atomic load)
func (m *Manager) Active() bool { return m != nil && m.active.Load() }

// KeySet reports whether an API key is stored (never the key)
func (m *Manager) KeySet() bool { return m.vault != nil && m.vault.IsSet() }

// SetInput is a settings change. APIKey "" keeps the stored key.
type SetInput struct {
	Settings          Settings
	APIKey            string
	ClearKey          bool
	ConfirmFailClosed bool
}

// Set validates, persists and applies new settings. Nothing changes when it fails.
func (m *Manager) Set(in SetInput) error {
	next := in.Settings
	if err := next.Normalize(); err != nil {
		return err
	}
	if in.APIKey != "" {
		if err := ValidKey(strings.TrimSpace(in.APIKey)); err != nil {
			return err
		}
	}
	if in.ClearKey && in.APIKey != "" {
		return errors.New("cannot set and clear the API key in one request")
	}
	if in.ClearKey && next.Enabled {
		return errors.New("an enabled CrowdSec integration needs an API key; switch it off before removing the key")
	}
	if next.Enabled && in.APIKey == "" && !m.KeySet() {
		return errors.New("the API key is required")
	}
	newBind := BindingOf(next.LAPIURL)
	if in.APIKey == "" && !in.ClearKey && next.LAPIURL != "" && m.KeySet() && m.keyBinding() != newBind {
		return errors.New("the stored API key was entered for another LAPI address (scheme, host or port changed); enter the API key again")
	}
	if next.FailClosed && !m.cur.Load().s.FailClosed && !in.ConfirmFailClosed {
		return errors.New("fail-closed refuses every visitor when the CrowdSec LAPI is unreachable; confirm it explicitly")
	}
	if next.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		u, _ := ParseLAPIURL(next.LAPIURL)
		if _, err := CheckLAPIAddr(ctx, u.Hostname()); err != nil {
			return errors.New("LAPI address refused: " + err.Error())
		}
	}
	if m.kv == nil {
		return errors.New("no settings store")
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if in.APIKey != "" {
		if err := m.vault.Set(in.APIKey); err != nil {
			return err
		}
		if err := m.vault.SetBinding(newBind); err != nil {
			return err
		}
	}
	if in.ClearKey {
		if err := m.vault.Clear(); err != nil {
			return err
		}
	}
	if err := m.kv.Write(DBTable, DBKey, next); err != nil {
		return err
	}
	m.install(next)
	if !next.Enabled {
		m.cache.Store(NewCache(next.MaxEntries))
		m.mu.Lock()
		m.matches, m.recents, m.tally = nil, nil, tally{}
		m.consecErrs, m.lastErr, m.authFailed = 0, "", false
		m.mu.Unlock()
	} else {
		m.resync.Store(true)
		m.mu.Lock()
		m.consecErrs, m.lastErr, m.authFailed = 0, "", false
		m.mu.Unlock()
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// Start runs the pull loop until Stop
func (m *Manager) Start() {
	m.ctlMu.Lock()
	if m.cancel != nil {
		m.ctlMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.done = cancel, make(chan struct{})
	m.ctlMu.Unlock()
	go m.loop(ctx)
}

// Stop ends the pull loop
func (m *Manager) Stop() {
	m.ctlMu.Lock()
	cancel, done := m.cancel, m.done
	m.cancel = nil
	m.ctlMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Backoff is the wait after the n-th consecutive failure: 2 s doubling up to 2 minutes
func Backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := 2 * time.Second
	for i := 1; i < n && d < 120*time.Second; i++ {
		d *= 2
	}
	if d > 120*time.Second {
		d = 120 * time.Second
	}
	return d
}

func (m *Manager) loop(ctx context.Context) {
	defer close(m.done)
	for {
		st := m.cur.Load()
		wait := time.Minute
		if st.s.Enabled {
			wait = time.Duration(st.s.PollSeconds) * time.Second
			if err := m.PullOnce(ctx); err != nil && ctx.Err() == nil {
				m.mu.Lock()
				n := m.consecErrs
				m.mu.Unlock()
				wait = Backoff(n)
				wait += time.Duration(rand.Int63n(int64(wait)/5 + 1)) // jitter
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-time.After(wait):
		}
	}
}

func bumpTally(mp map[string]uint64, k string) {
	k = strings.ToLower(strings.TrimSpace(k))
	if len(k) > 32 {
		k = k[:32]
	}
	if _, ok := mp[k]; !ok && len(mp) >= maxTallyKs {
		k = "other"
	}
	mp[k]++
}

// PullOnce does one synchronisation with the LAPI: the first one and every one after an error uses startup=true
// and replaces the cache as a whole once the answer was read completely; the others apply only the changes.
func (m *Manager) PullOnce(ctx context.Context) error {
	m.pullMu.Lock()
	defer m.pullMu.Unlock()
	st := m.cur.Load()
	if !st.s.Enabled {
		return nil
	}
	now := m.now()
	m.mu.Lock()
	m.lastTry = now
	m.mu.Unlock()

	key := ""
	fail := func(err error) error {
		msg := err.Error()
		if key != "" {
			msg = strings.ReplaceAll(msg, key, "[key]")
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		m.mu.Lock()
		m.consecErrs++
		m.totalErrs++
		m.lastErr = msg
		m.authFailed = errors.Is(err, ErrAuth)
		first := m.lastLogLine != msg
		m.lastLogLine = msg
		m.mu.Unlock()
		m.resync.Store(true)
		if first {
			m.logLimited("CrowdSec: synchronisation with the LAPI failed: " + msg)
		}
		return err
	}
	k, ok, err := m.vault.Get()
	if err != nil {
		return fail(err)
	}
	if !ok {
		return fail(errors.New("no API key stored"))
	}
	key = k
	gen := m.pullSeq.Add(1)
	maxTTL := time.Duration(st.s.MaxTTLSeconds) * time.Second
	startup := m.resync.Load() || m.fullDue(now, maxTTL)
	timeout := deltaTimeout
	if startup {
		timeout = startupTimeout
	}
	client, err := NewClient(st.s, key, timeout)
	if err != nil {
		return fail(err)
	}
	defer client.Close()

	target := m.cache.Load()
	if startup {
		target = NewCache(st.s.MaxEntries)
	}
	t := tally{scopes: map[string]uint64{}, types: map[string]uint64{}}
	var fresh []Recent
	var clamped uint64
	t0 := m.now()
	var base time.Time //expiry is counted from the first decision read (after the response headers), not from before the request
	err = client.Stream(ctx, startup, func(d apiDecision, deleted bool) error {
		if deleted {
			if !startup { //a fresh cache holds nothing that could be deleted (the initial answer lists past deletions)
				target.DeleteSparing(d.Scope, d.Value, d.Type, d.ID, gen)
			}
			return nil
		}
		if !strings.EqualFold(d.Scope, ScopeIP) && !strings.EqualFold(d.Scope, ScopeRange) {
			bumpTally(t.scopes, d.Scope)
			return nil
		}
		if !strings.EqualFold(d.Type, TypeBan) && !strings.EqualFold(d.Type, TypeCaptcha) {
			bumpTally(t.types, d.Type)
			return nil
		}
		dur, derr := parseDuration(d.Duration)
		if derr != nil {
			t.malformed++
			return nil
		}
		if dur <= 0 {
			return nil //already over
		}
		if dur > maxTTL {
			dur = maxTTL
			clamped++
		}
		if base.IsZero() {
			base = m.now()
		}
		dd := Decision{ID: d.ID, Type: strings.ToLower(d.Type), Scope: strings.ToLower(d.Scope), Value: d.Value,
			Origin: clean(d.Origin, 64), Scenario: clean(d.Scenario, 128), Expires: base.Add(dur), gen: gen}
		switch target.Add(dd) {
		case addInvalid:
			t.malformed++
		case addOK:
			if len(fresh) >= ringSize {
				fresh = fresh[1:]
			}
			fresh = append(fresh, Recent{Decision: dd, Added: t0})
		}
		return nil
	})
	lat := m.now().Sub(t0)
	if err != nil {
		return fail(err)
	}
	target.Sweep(m.now())
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if m.cur.Load() != st { //the settings changed while this pull ran: its answer belongs to the old LAPI or to a disabled feature
		return nil
	}
	if startup {
		m.cache.Store(target)
	}
	m.mu.Lock()
	m.lastOK = m.now()
	m.consecErrs, m.lastErr, m.authFailed, m.lastLogLine = 0, "", false, ""
	m.latency = lat
	if startup {
		m.resyncs++
		m.tally = t
		m.lastFull, m.clamped = m.now(), clamped
	} else {
		m.clamped += clamped
		if m.tally.scopes == nil {
			m.tally = tally{scopes: map[string]uint64{}, types: map[string]uint64{}}
		}
		for k, v := range t.scopes {
			m.tally.scopes[k] += v
		}
		for k, v := range t.types {
			m.tally.types[k] += v
		}
		m.tally.malformed += t.malformed
	}
	m.recents = append(m.recents, fresh...)
	if len(m.recents) > ringSize {
		m.recents = m.recents[len(m.recents)-ringSize:]
	}
	nTypes := len(t.types)
	m.mu.Unlock()
	m.resync.Store(false)
	if startup {
		extra := ""
		if nTypes > 0 || len(t.scopes) > 0 {
			extra = ", decisions of other scopes or types are counted and not enforced"
		}
		m.logf("CrowdSec: synchronised with the LAPI, " + itoa(target.Len()) + " decisions cached" + extra)
	}
	return nil
}

// clean clips s to n bytes and drops control characters (a decision text goes into log lines)
func clean(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}

// fullDue: decisions longer than the maximum lifetime are stored cut, and the LAPI sends a decision only once. A full
// synchronisation at half the maximum lifetime refreshes them, so a long ban does not lapse while the LAPI still holds it.
func (m *Manager) fullDue(now time.Time, maxTTL time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clamped > 0 && !m.lastFull.IsZero() && now.Sub(m.lastFull) >= maxTTL/2
}

// keyBinding is the endpoint the stored key belongs to (for a key stored before bindings: the saved LAPI address)
func (m *Manager) keyBinding() string {
	if b, ok := m.vault.Binding(); ok {
		return b
	}
	return BindingOf(m.cur.Load().s.LAPIURL)
}

// down: no successful synchronisation for longer than the grace period (counted from enabling when there never was one)
func (m *Manager) down(now time.Time) bool {
	st := m.cur.Load()
	m.mu.Lock()
	ref := m.lastOK
	if ref.IsZero() || ref.Before(m.since) {
		ref = m.since
	}
	m.mu.Unlock()
	return now.Sub(ref) > time.Duration(st.s.GraceSeconds)*time.Second
}

// Check is the decision for a client address that is the TCP peer itself. Loopback, this server and the trusted
// proxies are never acted on. For an address taken from a forwarded header use CheckForwarded (those exemptions must not apply to it).
func (m *Manager) Check(ip netip.Addr, site string) Verdict {
	if !m.Active() || !ip.IsValid() {
		return Verdict{}
	}
	ip = ip.WithZone("").Unmap()
	st := m.cur.Load()
	if ip.IsLoopback() || (site != "" && st.exempt[strings.ToLower(site)]) {
		return Verdict{}
	}
	if m.Protect != nil && m.Protect(ip) {
		return Verdict{}
	}
	return m.decide(st, []netip.Addr{ip}, site)
}

// CheckForwarded is for a request that came through a trusted proxy: addrs are every address the request claims
// (the resolved client address and the forwarded headers). A trusted proxy does not strip what the client sent, so any
// of them may be the real one: the strongest decision among them applies. Loopback and the protected addresses are
// NOT exempt here, a client could otherwise choose them in a header to skip CrowdSec.
func (m *Manager) CheckForwarded(addrs []netip.Addr, site string) Verdict {
	if !m.Active() {
		return Verdict{}
	}
	st := m.cur.Load()
	if site != "" && st.exempt[strings.ToLower(site)] {
		return Verdict{}
	}
	norm := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.IsValid() {
			norm = append(norm, a.WithZone("").Unmap())
		}
	}
	if len(norm) == 0 {
		return m.CheckUnknown(site)
	}
	return m.decide(st, norm, site)
}

// CheckUnknown is for a request whose client address cannot be determined: counted, and refused only when
// fail-closed is on, enforcing and the LAPI is down (a connection without an IP address, such as a unix socket
// listener, must not be refused while CrowdSec is healthy).
func (m *Manager) CheckUnknown(site string) Verdict {
	if !m.Active() {
		return Verdict{}
	}
	m.unknownClients.Add(1)
	st := m.cur.Load()
	if site != "" && st.exempt[strings.ToLower(site)] {
		return Verdict{}
	}
	if st.s.FailClosed && st.s.Mode == ModeEnforce && m.down(m.now()) {
		m.closedBlocks.Add(1)
		v := Verdict{Matched: true, Action: ActionClosed, Enforce: true, Drop: st.s.BanResponse == BanDrop}
		m.record(netip.Addr{}, site, v)
		return v
	}
	return Verdict{}
}

func (m *Manager) decide(st *state, ips []netip.Addr, site string) Verdict {
	now := m.now()
	enforce := st.s.Mode == ModeEnforce
	c := m.cache.Load()
	var best Decision
	var bestIP netip.Addr
	found := false
	for _, ip := range ips {
		if d, ok := c.Lookup(ip, now); ok && (!found || d.rank() > best.rank()) {
			best, bestIP, found = d, ip, true
		}
	}
	if found {
		d := best
		v := Verdict{Matched: true, Decision: d, Drop: st.s.BanResponse == BanDrop}
		switch d.Type {
		case TypeBan:
			v.Action, v.Enforce = ActionBan, enforce
		case TypeCaptcha:
			v.Action, v.Enforce = ActionCaptcha, enforce && st.s.CaptchaAction == CaptchaChallenge
		default:
			return Verdict{}
		}
		if v.Enforce {
			m.enforced.Add(1)
		} else {
			m.logOnly.Add(1)
		}
		m.record(bestIP, site, v)
		return v
	}
	if st.s.FailClosed && enforce && m.down(now) {
		m.closedBlocks.Add(1)
		v := Verdict{Matched: true, Action: ActionClosed, Enforce: true, Drop: st.s.BanResponse == BanDrop}
		m.record(ips[0], site, v)
		return v
	}
	return Verdict{}
}

func (m *Manager) record(ip netip.Addr, site string, v Verdict) {
	now := m.now()
	ips := ip.String()
	m.mu.Lock()
	lo := len(m.matches) - 32
	if lo < 0 {
		lo = 0
	}
	for i := len(m.matches) - 1; i >= lo; i-- {
		e := &m.matches[i]
		if e.IP == ips && e.Site == site && e.Action == v.Action && e.Enforced == v.Enforce {
			e.Count++
			e.Time = now
			m.mu.Unlock()
			return
		}
	}
	d := v.Decision
	m.matches = append(m.matches, Match{Time: now, IP: ips, Site: site, Action: v.Action, Enforced: v.Enforce, Type: d.Type,
		Scope: d.Scope, Value: d.Value, Origin: d.Origin, Scenario: d.Scenario, Count: 1})
	if len(m.matches) > ringSize {
		m.matches = m.matches[len(m.matches)-ringSize:]
	}
	m.mu.Unlock()
	verb := "would block"
	if v.Enforce {
		verb = "blocked"
	} else if v.Action == ActionCaptcha {
		verb = "would challenge (logged only)"
	}
	m.logLimited("CrowdSec: " + verb + " " + ips + " on " + site + ": " + v.Detail())
}

// Status is the health view
type Status struct {
	Enabled           bool              `json:"enabled"`
	Mode              string            `json:"mode"`
	State             string            `json:"state"` // off, starting, ok, degraded, down
	KeySet            bool              `json:"keySet"`
	LastSuccess       *time.Time        `json:"lastSuccess"`
	LastAttempt       *time.Time        `json:"lastAttempt"`
	LastError         string            `json:"lastError"`
	ConsecutiveErrors int               `json:"consecutiveErrors"`
	TotalErrors       uint64            `json:"totalErrors"`
	Resyncs           uint64            `json:"fullSyncs"`
	LatencyMs         int64             `json:"latencyMs"`
	CacheSize         int               `json:"cacheSize"`
	CacheMax          int               `json:"cacheMax"`
	CacheRefused      uint64            `json:"cacheRefused"`
	CacheEvicted      uint64            `json:"cacheEvicted"`
	Clamped           uint64            `json:"clampedDecisions"`
	UnknownClients    uint64            `json:"unknownClients"`
	IgnoredScopes     map[string]uint64 `json:"ignoredScopes"`
	IgnoredTypes      map[string]uint64 `json:"ignoredTypes"`
	Malformed         uint64            `json:"malformed"`
	Enforced          uint64            `json:"enforced"`
	LogOnly           uint64            `json:"logOnly"`
	FailClosedBlocks  uint64            `json:"failClosedBlocks"`
	FailClosedActive  bool              `json:"failClosedActive"`
	Warnings          []string          `json:"warnings"`
}

// Status returns the health summary. It never contains the API key or response bodies.
func (m *Manager) Status() Status {
	st := m.cur.Load()
	now := m.now()
	c := m.cache.Load()
	s := Status{Enabled: st.s.Enabled, Mode: st.s.Mode, State: "off", KeySet: m.KeySet(), CacheSize: c.Len(), CacheMax: st.s.MaxEntries,
		CacheRefused: c.Dropped(), CacheEvicted: c.Evicted(), UnknownClients: m.unknownClients.Load(), Enforced: m.enforced.Load(), LogOnly: m.logOnly.Load(), FailClosedBlocks: m.closedBlocks.Load(),
		IgnoredScopes: map[string]uint64{}, IgnoredTypes: map[string]uint64{}, Warnings: []string{}}
	m.mu.Lock()
	if !m.lastOK.IsZero() {
		t := m.lastOK
		s.LastSuccess = &t
	}
	if !m.lastTry.IsZero() {
		t := m.lastTry
		s.LastAttempt = &t
	}
	s.LastError, s.ConsecutiveErrors, s.TotalErrors, s.Resyncs = m.lastErr, m.consecErrs, m.totalErrs, m.resyncs
	s.LatencyMs, s.Malformed = m.latency.Milliseconds(), m.tally.malformed
	for k, v := range m.tally.scopes {
		s.IgnoredScopes[k] = v
	}
	for k, v := range m.tally.types {
		s.IgnoredTypes[k] = v
	}
	lastOK, errs := m.lastOK, m.consecErrs
	s.Clamped = m.clamped
	m.mu.Unlock()
	if !st.s.Enabled {
		return s
	}
	isDown := m.down(now)
	poll := time.Duration(st.s.PollSeconds) * time.Second
	switch {
	case isDown:
		s.State = "down"
	case lastOK.IsZero():
		s.State = "starting"
	case errs > 0 || now.Sub(lastOK) > 3*poll+30*time.Second || s.CacheRefused > 0:
		s.State = "degraded"
	default:
		s.State = "ok"
	}
	if isDown && st.s.FailClosed && st.s.Mode == ModeEnforce {
		s.FailClosedActive = true
		s.Warnings = append(s.Warnings, "The LAPI has been unreachable longer than the grace period and fail-closed is on: every visitor is being refused.")
	} else if isDown {
		s.Warnings = append(s.Warnings, "The LAPI has been unreachable longer than the grace period. Failing open: traffic is allowed, only decisions already in the cache are applied.")
	}
	if s.Clamped > 0 {
		s.Warnings = append(s.Warnings, "Some decisions last longer than the maximum decision lifetime and are kept cut to it; a full synchronisation at half of that time refreshes them.")
	}
	if st.s.Mode == ModeLog {
		s.Warnings = append(s.Warnings, "Log only mode: matches are counted and logged, nobody is blocked.")
	}
	if st.s.FailClosed && st.s.Mode == ModeLog {
		s.Warnings = append(s.Warnings, "Fail-closed has no effect in log only mode.")
	}
	if st.s.FailClosed && st.s.Mode == ModeEnforce {
		s.Warnings = append(s.Warnings, "Fail-closed is on: if the LAPI stays unreachable beyond the grace period, every visitor is refused.")
	}
	if s.CacheRefused > 0 {
		s.Warnings = append(s.Warnings, "The decision cache is full: some decisions were not stored (community list decisions make room for local ones). Raise the cache size.")
	}
	if u, err := ParseLAPIURL(st.s.LAPIURL); err == nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		s.Warnings = append(s.Warnings, "The LAPI address is plain http on a non-loopback host: the API key travels unencrypted.")
	}
	if m.keyRejected() {
		s.Warnings = append(s.Warnings, "The LAPI rejected the API key.")
	}
	return s
}

func (m *Manager) keyRejected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authFailed
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && a.IsLoopback()
}

// Decisions returns the recent decisions received from the LAPI and the recent matches, newest first, at most limit each
func (m *Manager) Decisions(limit int) (recent []Recent, matches []Match) {
	if limit <= 0 || limit > ringSize {
		limit = ringSize
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.recents) - 1; i >= 0 && len(recent) < limit; i-- {
		recent = append(recent, m.recents[i])
	}
	for i := len(m.matches) - 1; i >= 0 && len(matches) < limit; i-- {
		matches = append(matches, m.matches[i])
	}
	if recent == nil {
		recent = []Recent{}
	}
	if matches == nil {
		matches = []Match{}
	}
	sort.SliceStable(matches, func(a, b int) bool { return matches[a].Time.After(matches[b].Time) })
	return
}

// TestResult is the answer of the connection test
type TestResult struct {
	OK        bool   `json:"ok"`
	LatencyMs int64  `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
	Note      string `json:"note,omitempty"`
}

// TestConnection makes one authenticated call (GET /v1/decisions?ip=192.0.2.1, a documentation address) to the LAPI
// of s with key. The destination passes CheckLAPIAddr. s.Enabled is not needed.
func TestConnection(ctx context.Context, s Settings, key string) TestResult {
	s.Enabled = false
	if s.LAPIURL == "" {
		return TestResult{Error: "the LAPI address is required"}
	}
	if err := s.Normalize(); err != nil {
		return TestResult{Error: err.Error()}
	}
	if err := ValidKey(key); err != nil {
		return TestResult{Error: "no API key (enter one, or save one first)"}
	}
	c, err := NewClient(s, key, lookupTimeout)
	if err != nil {
		return TestResult{Error: err.Error()}
	}
	defer c.Close()
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	_, err = c.Lookup(ctx, "192.0.2.1")
	lat := time.Since(t0).Milliseconds()
	if err != nil {
		msg := strings.ReplaceAll(err.Error(), key, "[key]")
		return TestResult{LatencyMs: lat, Error: msg}
	}
	return TestResult{OK: true, LatencyMs: lat, Note: "The LAPI accepted the API key."}
}

// Test runs TestConnection with cfg (nil = the saved settings) and key ("" = the stored key, which is never returned)
func (m *Manager) Test(ctx context.Context, cfg *Settings, key string) TestResult {
	s := m.Settings()
	if cfg != nil {
		s = *cfg
	}
	key = strings.TrimSpace(key)
	if key == "" {
		k, ok, err := m.vault.Get()
		if err != nil {
			return TestResult{Error: err.Error()}
		}
		if !ok {
			return TestResult{Error: "no API key (enter one, or save one first)"}
		}
		if BindingOf(s.LAPIURL) != m.keyBinding() { //the stored key is never sent to an address it was not entered for
			return TestResult{Error: "the stored API key was entered for another LAPI address; enter the API key to test this one"}
		}
		key = k
	}
	return TestConnection(ctx, s, key)
}

// SetClockForTest replaces the time source (grace periods and expiry can then be tested without waiting)
func (m *Manager) SetClockForTest(f func() time.Time) { m.now = f }
