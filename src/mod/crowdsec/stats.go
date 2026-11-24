package crowdsec

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
)

/*
	stats.go: what CrowdSec did, for the dashboard ("see it in action").

	Everything here is bounded and lives in memory only: 168 hourly buckets of counters (7 days), per hour the first
	32 distinct scenarios / origins / countries / sites / addresses that matched (the rest is summed under "other"),
	a feed of the last 500 matches (repeats of the same visitor on the same site with the same outcome are one entry
	with a count), the last 60 synchronisations and the last 50 health changes. It all starts again on a restart and
	when CrowdSec is switched off; enforced blocks are also in the persisted blocked-request log.

	Cost on the request path: one atomic add per checked request. Everything else happens only for a request whose
	address has a decision.
*/

// Outcome is what really happened to a request whose address had a decision (reported by the request path)
type Outcome string

const (
	OutBlocked     Outcome = "blocked"             // the 403 page
	OutDropped     Outcome = "dropped"             // connection closed without an answer
	OutChallenged  Outcome = "challenged"          // the site's CAPTCHA was shown
	OutPassed      Outcome = "challenge-passed"    // captcha decision, the visitor had already solved the CAPTCHA: served
	OutNoCaptcha   Outcome = "captcha-unavailable" // captcha decision on a site without CAPTCHA: served, only logged
	OutSkipped     Outcome = "challenge-skipped"   // captcha decision, the site's CAPTCHA does not cover this path or visitor: served
	OutLogOnly     Outcome = "log-only"            // matched, not enforced (mode, site or policy): served
	OutAllowlisted Outcome = "allowlisted"         // the address is on Dunree's CrowdSec allowlist: served
	OutExempt      Outcome = "exempt-site"         // the site is exempt: served
	OutFailClosed  Outcome = "fail-closed"         // LAPI unreachable and fail-closed: refused
)

// Outcomes lists every outcome (for filters)
var Outcomes = []Outcome{OutBlocked, OutDropped, OutChallenged, OutPassed, OutNoCaptcha, OutSkipped, OutLogOnly, OutAllowlisted, OutExempt, OutFailClosed}

// Enforced reports whether the visitor was stopped (refused or challenged)
func (o Outcome) Enforced() bool {
	return o == OutBlocked || o == OutDropped || o == OutChallenged || o == OutFailClosed
}

// Reasons a match is not enforced (Verdict.Why) or not acted on at all (Verdict.Skip)
const (
	WhyMode        = "mode"         // the mode is log only
	WhySiteLog     = "site-log"     // this site is set to log only
	WhyOriginLog   = "origin-log"   // decisions of this origin are kept log only
	WhyScenarioLog = "scenario-log" // this scenario is kept log only
	WhyCaptchaLog  = "captcha-log"  // captcha decisions are only logged
	SkipAllowlist  = "allowlist"
	SkipSiteExempt = "site-exempt"
)

// DefaultOutcome is the outcome when the request path does exactly what the verdict says (a ban is refused, a captcha
// decision is challenged). The request path reports the real one; this is for callers without a request and for tests.
func (v Verdict) DefaultOutcome() Outcome {
	switch {
	case v.Skip == SkipAllowlist:
		return OutAllowlisted
	case v.Skip == SkipSiteExempt:
		return OutExempt
	case !v.Matched:
		return ""
	case v.Action == ActionClosed:
		return OutFailClosed
	case !v.Enforce:
		return OutLogOnly
	case v.Action == ActionCaptcha:
		return OutChallenged
	case v.Drop:
		return OutDropped
	}
	return OutBlocked
}

// Event is the request a verdict was applied to (only what the dashboard shows; never headers or a body)
type Event struct {
	Host    string // Host header of the request
	Method  string
	Path    string // cut to 200 bytes, without the query
	Country string // ISO code, "" when unknown
}

// Counts are the counters of one period
type Counts struct {
	Checked       uint64 `json:"checked"`       // requests looked up
	Blocked       uint64 `json:"blocked"`       // refused: the 403 page or a dropped connection
	WouldBlock    uint64 `json:"wouldBlock"`    // matched but not enforced (log only by mode, site or policy)
	Challenged    uint64 `json:"challenged"`    // CAPTCHA shown
	Passed        uint64 `json:"passed"`        // captcha decision, CAPTCHA already solved
	NotChallenged uint64 `json:"notChallenged"` // captcha decision that could not be challenged (no CAPTCHA, path or visitor not covered)
	Allowlisted   uint64 `json:"allowlisted"`
	Exempt        uint64 `json:"exempt"`
	FailClosed    uint64 `json:"failClosed"`
	Ignored       uint64 `json:"ignored"` // only decisions of an origin set to "ignore" applied
}

func (c *Counts) add(o Counts) {
	c.Checked += o.Checked
	c.Blocked += o.Blocked
	c.WouldBlock += o.WouldBlock
	c.Challenged += o.Challenged
	c.Passed += o.Passed
	c.NotChallenged += o.NotChallenged
	c.Allowlisted += o.Allowlisted
	c.Exempt += o.Exempt
	c.FailClosed += o.FailClosed
	c.Ignored += o.Ignored
}

func (c *Counts) note(o Outcome) {
	switch o {
	case OutBlocked, OutDropped:
		c.Blocked++
	case OutChallenged:
		c.Challenged++
	case OutPassed:
		c.Passed++
	case OutNoCaptcha, OutSkipped:
		c.NotChallenged++
	case OutLogOnly:
		c.WouldBlock++
	case OutAllowlisted:
		c.Allowlisted++
	case OutExempt:
		c.Exempt++
	case OutFailClosed:
		c.FailClosed++
	}
}

const (
	statHours = 168 // 7 days of hourly buckets
	topKeys   = 32  // distinct values kept per hour and list
	feedSize  = 500
	feedDedup = 32
	pullRing  = 60
	transRing = 50
)

const (
	dimScenario = iota
	dimOrigin
	dimCountry
	dimSite
	dimIP
	nDims
)

var dimNames = [nDims]string{"scenarios", "origins", "countries", "sites", "addresses"}

type hourBucket struct {
	hour int64 // unix time / 3600; 0 = unused
	c    Counts
	tops [nDims]map[string]*[2]uint64 // [0] enforced, [1] log only
}

// FeedEntry is one line of the activity feed
type FeedEntry struct {
	ID       uint64     `json:"id"`
	Time     time.Time  `json:"time"`      // last request
	First    time.Time  `json:"firstSeen"` // first request of this entry
	IP       string     `json:"ip"`
	Country  string     `json:"country"`
	Host     string     `json:"host"` // Host header
	Rule     string     `json:"rule"` // the proxy rule (site) that handled it
	Method   string     `json:"method"`
	Path     string     `json:"path"`
	Outcome  Outcome    `json:"outcome"`
	Enforced bool       `json:"enforced"`
	Why      string     `json:"why"` // why it was not enforced, see the Why constants
	Action   Action     `json:"action"`
	Type     string     `json:"type"`
	Scope    string     `json:"scope"`
	Value    string     `json:"value"` // the address or range the decision is on
	Origin   string     `json:"origin"`
	Scenario string     `json:"scenario"`
	Expires  *time.Time `json:"expires"`
	Count    int        `json:"count"`
}

// PullRecord is one synchronisation with the LAPI
type PullRecord struct {
	Time       time.Time `json:"time"`
	Full       bool      `json:"full"`
	DurationMs int64     `json:"durationMs"`
	New        int       `json:"new"`
	Deleted    int       `json:"deleted"`
	Error      string    `json:"error,omitempty"`
}

// Transition is one change of the health state
type Transition struct {
	Time  time.Time `json:"time"`
	From  string    `json:"from"`
	To    string    `json:"to"`
	Error string    `json:"error,omitempty"`
}

// Notification events (mod/notify catalogue). Nothing is sent unless a channel subscribes to them.
const (
	NotifyDown   = "crowdsec.lapi_down"
	NotifyUp     = "crowdsec.lapi_up"
	notifyFlap   = 5 * time.Minute
	liveLookups  = 30 // "ask the CrowdSec server" calls per minute
	maxEventPath = 200
)

// stats is guarded by Manager.mu
type stats struct {
	since   time.Time
	buckets [statHours]hourBucket
	feed    []FeedEntry
	feedSeq uint64
	pulls   []PullRecord
	trans   []Transition
	comp    Composition

	foldedChecked, foldedIgnored uint64

	state        string
	downNotified bool
	lastDownSent time.Time

	liveTokens float64
	liveAt     time.Time
}

func (s *stats) bucket(hour int64) *hourBucket {
	b := &s.buckets[((hour%statHours)+statHours)%statHours]
	if b.hour != hour {
		*b = hourBucket{hour: hour}
	}
	return b
}

func bumpTop(mp *map[string]*[2]uint64, k string, enforced bool) {
	if *mp == nil {
		*mp = map[string]*[2]uint64{}
	}
	if k == "" {
		k = "(none)"
	}
	e, ok := (*mp)[k]
	if !ok {
		if len(*mp) >= topKeys {
			k = "other"
			e = (*mp)[k]
		}
		if e == nil {
			e = &[2]uint64{}
			(*mp)[k] = e
		}
	}
	if enforced {
		e[0]++
	} else {
		e[1]++
	}
}

// resetStats forgets counters, feed and history (CrowdSec switched off)
func (m *Manager) resetStats() {
	m.mu.Lock()
	m.st = stats{since: m.now(), state: m.st.state, downNotified: m.st.downNotified, lastDownSent: m.st.lastDownSent, trans: m.st.trans}
	m.st.foldedChecked, m.st.foldedIgnored = m.checked.Load(), m.ignored.Load()
	m.mu.Unlock()
}

// fold moves the per-request counters (atomics) into the bucket of the hour they belong to. Caller holds m.mu.
func (m *Manager) fold(nowHour int64) {
	h := m.statHour.Load()
	ch, ig := m.checked.Load(), m.ignored.Load()
	if h > 0 && nowHour-h < statHours && (ch != m.st.foldedChecked || ig != m.st.foldedIgnored) {
		b := m.st.bucket(h)
		b.c.Checked += ch - m.st.foldedChecked
		b.c.Ignored += ig - m.st.foldedIgnored
	}
	m.st.foldedChecked, m.st.foldedIgnored = ch, ig
	m.statHour.Store(nowHour)
}

// rollHour is called by the first checked request of a new hour
func (m *Manager) rollHour(now time.Time) {
	m.mu.Lock()
	if m.st.since.IsZero() {
		m.st.since = now
	}
	m.fold(now.Unix() / 3600)
	m.mu.Unlock()
}

func trimPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return clean(p, maxEventPath)
}

// Report records what really happened to a request that Check (or CheckForwarded, CheckUnknown) returned v for.
// The request path calls it once per matched request, after it knows the outcome. "" as outcome records nothing.
func (m *Manager) Report(v Verdict, out Outcome, ev Event) {
	if out == "" || (!v.Matched && v.Skip == "") {
		return
	}
	now := m.now()
	d := v.Decision
	ips := ""
	if v.IP.IsValid() {
		ips = v.IP.String()
	}
	enforced := out.Enforced()
	switch {
	case out == OutFailClosed:
		m.closedBlocks.Add(1)
	case enforced:
		m.enforced.Add(1)
	case out == OutLogOnly:
		m.logOnly.Add(1)
	}
	why := v.Why
	if v.Skip != "" {
		why = v.Skip
	}
	ev.Host, ev.Method, ev.Path, ev.Country = clean(ev.Host, 253), clean(ev.Method, 16), trimPath(ev.Path), strings.ToUpper(clean(ev.Country, 2))

	m.mu.Lock()
	hour := now.Unix() / 3600
	if m.statHour.Load() != hour {
		m.fold(hour)
	}
	b := m.st.bucket(hour)
	b.c.note(out)
	if out == OutLogOnly || (enforced && out != OutFailClosed) {
		bumpTop(&b.tops[dimScenario], d.Scenario, enforced)
		bumpTop(&b.tops[dimOrigin], strings.ToLower(d.Origin), enforced)
		bumpTop(&b.tops[dimCountry], ev.Country, enforced)
		bumpTop(&b.tops[dimSite], v.Site, enforced)
		bumpTop(&b.tops[dimIP], ips, enforced)
	}
	lo := len(m.st.feed) - feedDedup
	if lo < 0 {
		lo = 0
	}
	for i := len(m.st.feed) - 1; i >= lo; i-- {
		e := &m.st.feed[i]
		if e.IP == ips && e.Rule == v.Site && e.Outcome == out && e.Why == why && e.Value == d.Value {
			e.Count++
			e.Time, e.Host, e.Method, e.Path = now, ev.Host, ev.Method, ev.Path
			m.mu.Unlock()
			return
		}
	}
	m.st.feedSeq++
	fe := FeedEntry{ID: m.st.feedSeq, Time: now, First: now, IP: ips, Country: ev.Country, Host: ev.Host, Rule: v.Site, Method: ev.Method,
		Path: ev.Path, Outcome: out, Enforced: enforced, Why: why, Action: v.Action, Type: d.Type, Scope: d.Scope, Value: d.Value,
		Origin: d.Origin, Scenario: d.Scenario, Count: 1}
	if !d.Expires.IsZero() {
		t := d.Expires
		fe.Expires = &t
	}
	m.st.feed = append(m.st.feed, fe)
	if len(m.st.feed) > feedSize {
		m.st.feed = append(m.st.feed[:0], m.st.feed[len(m.st.feed)-feedSize:]...)
	}
	m.mu.Unlock()

	verb := ""
	switch out {
	case OutBlocked, OutDropped, OutFailClosed:
		verb = "blocked"
	case OutChallenged:
		verb = "challenged"
	case OutLogOnly:
		verb = "would block"
		if v.Action == ActionCaptcha {
			verb = "would challenge (logged only)"
		}
	case OutAllowlisted:
		verb = "allowlisted, not acted on:"
	case OutNoCaptcha:
		verb = "captcha decision only logged (the site has no CAPTCHA):"
	default:
		return //served without a note: exempt site, CAPTCHA already solved, path not covered
	}
	m.logLimited("CrowdSec: " + verb + " " + ips + " on " + v.Site + ": " + v.Detail())
}

// FeedQuery filters the feed. Empty fields match everything.
type FeedQuery struct {
	Outcome string // one outcome, or "enforced" / "served"
	IP      string // exact address
	Q       string // substring of address, site, host, path, scenario, origin, country
	Before  time.Time
	Limit   int // 1..200, default 25
}

// FeedPage is one page of the feed, newest first
type FeedPage struct {
	Entries []FeedEntry `json:"entries"`
	More    bool        `json:"more"`
	Total   int         `json:"total"` // entries kept (before filtering)
}

// Feed returns the activity feed, newest first
func (m *Manager) Feed(q FeedQuery) FeedPage {
	if q.Limit <= 0 {
		q.Limit = 25
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	needle := strings.ToLower(strings.TrimSpace(q.Q))
	ip := strings.TrimSpace(q.IP)
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.WithZone("").Unmap().String()
	}
	m.mu.Lock()
	all := append([]FeedEntry(nil), m.st.feed...)
	m.mu.Unlock()
	sort.SliceStable(all, func(a, b int) bool {
		if !all[a].Time.Equal(all[b].Time) {
			return all[a].Time.After(all[b].Time)
		}
		return all[a].ID > all[b].ID
	})
	out := FeedPage{Entries: []FeedEntry{}, Total: len(all)}
	for _, e := range all {
		if !q.Before.IsZero() && !e.Time.Before(q.Before) {
			continue
		}
		switch q.Outcome {
		case "":
		case "enforced":
			if !e.Enforced {
				continue
			}
		case "served":
			if e.Enforced {
				continue
			}
		default:
			if string(e.Outcome) != q.Outcome {
				continue
			}
		}
		if ip != "" && e.IP != ip {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(e.IP+" "+e.Rule+" "+e.Host+" "+e.Path+" "+e.Scenario+" "+e.Origin+" "+e.Country+" "+e.Value), needle) {
			continue
		}
		if len(out.Entries) >= q.Limit {
			out.More = true
			break
		}
		out.Entries = append(out.Entries, e)
	}
	return out
}

// Point is one bar of the timeline
type Point struct {
	T     int64 `json:"t"`     // start, unix seconds
	Hours int   `json:"hours"` // length
	Counts
}

// TopItem is one line of a top list
type TopItem struct {
	Key      string `json:"key"`
	Enforced uint64 `json:"enforced"`
	LogOnly  uint64 `json:"logOnly"`
}

// Activity is the dashboard summary
type Activity struct {
	Window      string               `json:"window"` // 24h or 7d
	Now         time.Time            `json:"now"`
	Since       time.Time            `json:"since"`    // counters started (process start, or CrowdSec switched on)
	DayStart    time.Time            `json:"dayStart"` // local midnight of the server: start of "today"
	Today       Counts               `json:"today"`
	Total       Counts               `json:"total"` // the whole window
	Series      []Point              `json:"series"`
	Tops        map[string][]TopItem `json:"tops"` // scenarios, origins, countries, sites, addresses
	Loaded      Composition          `json:"loaded"`
	Pulls       []PullRecord         `json:"pulls"`       // newest first
	Transitions []Transition         `json:"transitions"` // newest first
	LastFull    *time.Time           `json:"lastFullSync"`
	FeedSize    int                  `json:"feedSize"`
}

const topN = 8

// today sums the buckets since the local midnight of now. Caller holds m.mu and has folded.
func (m *Manager) todayLocked(now time.Time) (Counts, time.Time) {
	y, mo, d := now.Date()
	start := time.Date(y, mo, d, 0, 0, 0, 0, now.Location())
	var c Counts
	for h := start.Unix() / 3600; h <= now.Unix()/3600; h++ {
		if b := &m.st.buckets[((h%statHours)+statHours)%statHours]; b.hour == h {
			c.add(b.c)
		}
	}
	return c, start
}

// Activity returns counters, timeline, top lists, what is loaded and the synchronisation history for window ("24h" or "7d")
func (m *Manager) Activity(window string) Activity {
	now := m.now()
	nowHour := now.Unix() / 3600
	hours, step := 24, 1
	if window == "7d" {
		hours, step = statHours, 6
	} else {
		window = "24h"
	}
	out := Activity{Window: window, Now: now, Tops: map[string][]TopItem{}, Series: make([]Point, 0, hours/step)}
	var merged [nDims]map[string]*[2]uint64
	m.mu.Lock()
	m.fold(nowHour)
	out.Since = m.st.since
	out.Today, out.DayStart = m.todayLocked(now)
	first := nowHour - int64(hours) + 1
	for h := first; h <= nowHour; h += int64(step) {
		p := Point{T: h * 3600, Hours: step}
		for k := int64(0); k < int64(step); k++ {
			b := &m.st.buckets[(((h+k)%statHours)+statHours)%statHours]
			if b.hour != h+k {
				continue
			}
			p.Counts.add(b.c)
			for dim := range b.tops {
				for key, v := range b.tops[dim] {
					if merged[dim] == nil {
						merged[dim] = map[string]*[2]uint64{}
					}
					e := merged[dim][key]
					if e == nil {
						e = &[2]uint64{}
						merged[dim][key] = e
					}
					e[0] += v[0]
					e[1] += v[1]
				}
			}
		}
		out.Total.add(p.Counts)
		out.Series = append(out.Series, p)
	}
	out.Loaded = m.st.comp
	for i := len(m.st.pulls) - 1; i >= 0; i-- {
		out.Pulls = append(out.Pulls, m.st.pulls[i])
	}
	for i := len(m.st.trans) - 1; i >= 0; i-- {
		out.Transitions = append(out.Transitions, m.st.trans[i])
	}
	if !m.lastFull.IsZero() {
		t := m.lastFull
		out.LastFull = &t
	}
	out.FeedSize = len(m.st.feed)
	m.mu.Unlock()
	for dim, mp := range merged {
		items := make([]TopItem, 0, len(mp))
		for k, v := range mp {
			items = append(items, TopItem{Key: k, Enforced: v[0], LogOnly: v[1]})
		}
		sort.Slice(items, func(a, b int) bool {
			ta, tb := items[a].Enforced+items[a].LogOnly, items[b].Enforced+items[b].LogOnly
			if ta != tb {
				return ta > tb
			}
			return items[a].Key < items[b].Key
		})
		if len(items) > topN {
			items = items[:topN]
		}
		out.Tops[dimNames[dim]] = items
	}
	for _, n := range dimNames {
		if out.Tops[n] == nil {
			out.Tops[n] = []TopItem{}
		}
	}
	if out.Pulls == nil {
		out.Pulls = []PullRecord{}
	}
	if out.Transitions == nil {
		out.Transitions = []Transition{}
	}
	if out.Loaded.ByClass == nil {
		out.Loaded = Composition{ByClass: map[string]int{}, ByType: map[string]int{}, ByOrigin: []NameCount{}, Scenarios: []NameCount{}, AllScenarios: []NameCount{}}
	}
	return out
}

// Today returns the counters since the local midnight of the server
func (m *Manager) Today() Counts {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fold(now.Unix() / 3600)
	c, _ := m.todayLocked(now)
	return c
}

// countingSince is when today's counters started, when that is later than the local midnight of the server (CrowdSec
// switched on or Dunree started during the day); the zero time when they cover the whole day so far.
func (m *Manager) countingSince() time.Time {
	now := m.now()
	y, mo, d := now.Date()
	start := time.Date(y, mo, d, 0, 0, 0, 0, now.Location())
	m.mu.Lock()
	since := m.st.since
	m.mu.Unlock()
	if since.After(start) {
		return since
	}
	return time.Time{}
}

func (m *Manager) notePull(rec PullRecord) {
	m.mu.Lock()
	m.st.pulls = append(m.st.pulls, rec)
	if len(m.st.pulls) > pullRing {
		m.st.pulls = append(m.st.pulls[:0], m.st.pulls[len(m.st.pulls)-pullRing:]...)
	}
	m.mu.Unlock()
}

// noteState records a change of the health state and raises the LAPI down / back notifications (with a flap guard:
// "down" at most once in five minutes, "back" only after a "down" that was sent).
func (m *Manager) noteState() {
	state := m.stateNow()
	now := m.now()
	var send string
	m.mu.Lock()
	prev := m.st.state
	if prev == "" {
		prev = "off"
	}
	if state == prev {
		m.mu.Unlock()
		return
	}
	m.st.state = state
	errText := m.lastErr
	m.st.trans = append(m.st.trans, Transition{Time: now, From: prev, To: state, Error: errText})
	if len(m.st.trans) > transRing {
		m.st.trans = append(m.st.trans[:0], m.st.trans[len(m.st.trans)-transRing:]...)
	}
	switch {
	case state == "down" && !m.st.downNotified && (m.st.lastDownSent.IsZero() || now.Sub(m.st.lastDownSent) >= notifyFlap):
		m.st.downNotified, m.st.lastDownSent = true, now
		send = NotifyDown
	case state == "ok" && m.st.downNotified:
		m.st.downNotified = false
		send = NotifyUp
	case state == "off":
		m.st.downNotified = false
	}
	m.mu.Unlock()
	if send != "" && m.Notify != nil {
		st := m.cur.Load()
		extra := map[string]string{"mode": st.s.Mode}
		if send == NotifyDown {
			extra["error"] = errText
			extra["fail_closed"] = "no"
			if st.s.FailClosed && st.s.Mode == ModeEnforce {
				extra["fail_closed"] = "yes"
			}
		}
		m.Notify(send, st.s.LAPIURL, extra)
	}
}

// ---- Check an address ----

// ExplainDecision is one cached decision that applies to the address, with what the settings make of it
type ExplainDecision struct {
	Decision
	Class       string `json:"class"`       // origin class
	Policy      string `json:"policy"`      // act, log or ignore
	PolicyWhy   string `json:"policyWhy"`   // origin-log, scenario-log, origin-ignore, captcha-log or ""
	Allowlisted bool   `json:"allowlisted"` // the address is on the allowlist: this decision is not acted on
	Wins        bool   `json:"wins"`        // the decision that decides the result
}

// LiveDecision is a decision the LAPI answered for the address just now
type LiveDecision struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Duration string `json:"duration"`
}

// LiveAnswer is the result of asking the LAPI about one address
type LiveAnswer struct {
	Error     string         `json:"error,omitempty"`
	Decisions []LiveDecision `json:"decisions"`
	Differs   bool           `json:"differs"` // the server knows a ban or captcha decision Dunree has not loaded, or the other way round
}

// Explanation answers "what would happen to this address, and why"
type Explanation struct {
	IP        string            `json:"ip"`
	Site      string            `json:"site"`
	Enabled   bool              `json:"enabled"`
	State     string            `json:"state"`
	Mode      string            `json:"mode"`      // the mode that applies on the site (log or enforce)
	SiteMode  string            `json:"siteMode"`  // override of the site: exempt, log, enforce or ""
	Protected string            `json:"protected"` // loopback or protected ("this server or a trusted proxy"): never acted on as a direct visitor
	AllowedBy string            `json:"allowedBy"` // the allowlist entry that covers the address
	Result    string            `json:"result"`    // off, protected, none, ignored, allowlisted, exempt, would-block, would-challenge, block, drop, challenge, fail-closed
	Why       string            `json:"why"`       // for would-*: see the Why constants
	Fallback  string            `json:"fallback"`  // for challenge: what happens on a site without CAPTCHA (log or ban)
	Decisions []ExplainDecision `json:"decisions"`
	Live      *LiveAnswer       `json:"live,omitempty"`
	Recent    []FeedEntry       `json:"recent"` // the last feed entries of the address
}

// ErrLiveLimit: too many live lookups
var ErrLiveLimit = errors.New("too many live lookups, wait a minute (the loaded decisions above are still shown)")

func (m *Manager) takeLive() bool {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.liveAt.IsZero() {
		m.st.liveTokens, m.st.liveAt = liveLookups, now
	}
	m.st.liveTokens += now.Sub(m.st.liveAt).Seconds() * liveLookups / 60
	if m.st.liveTokens > liveLookups {
		m.st.liveTokens = liveLookups
	}
	m.st.liveAt = now
	if m.st.liveTokens < 1 {
		return false
	}
	m.st.liveTokens--
	return true
}

// Explain reports which cached decisions apply to ip, which one decides and what a request from it to site would get
// under the current settings. It changes nothing and counts nothing. With live it also asks the LAPI once
// (GET /v1/decisions?ip=, the bouncer key), at most 30 times a minute.
func (m *Manager) Explain(ctx context.Context, ip netip.Addr, site string, live bool) (Explanation, error) {
	if !ip.IsValid() {
		return Explanation{}, errors.New("enter an IPv4 or IPv6 address")
	}
	ip = ip.WithZone("").Unmap()
	site = strings.ToLower(strings.TrimSpace(site))
	st := m.cur.Load()
	now := m.now()
	ex := Explanation{IP: ip.String(), Site: site, Enabled: st.s.Enabled, State: m.stateNow(), Decisions: []ExplainDecision{}, Recent: []FeedEntry{}}
	ex.SiteMode = st.sites[site]
	ex.Mode = st.modeFor(site)
	if p, ok := st.allowedBy(ip); ok {
		ex.AllowedBy = p
	}
	switch {
	case ip.IsLoopback():
		ex.Protected = "loopback"
	case m.Protect != nil && m.Protect(ip):
		ex.Protected = "protected"
	}
	v := m.evaluate(st, []netip.Addr{ip}, site, false)
	for _, d := range m.cache.Load().LookupAll(ip, now) {
		if d.rank() == 0 {
			continue
		}
		disp, why := st.disposition(d)
		ed := ExplainDecision{Decision: d, Class: OriginClass(d.Origin), Policy: "act", PolicyWhy: why, Allowlisted: ex.AllowedBy != ""}
		switch disp {
		case dispLog:
			ed.Policy = "log"
		case dispIgnore:
			ed.Policy = "ignore"
		}
		if d.Type == TypeCaptcha && disp == dispAct && st.s.CaptchaAction != CaptchaChallenge {
			ed.Policy, ed.PolicyWhy = "log", WhyCaptchaLog
		}
		ed.Wins = (v.Matched || v.Skip != "") && v.Action != ActionClosed && d.ID == v.Decision.ID && d.Value == v.Decision.Value && d.Type == v.Decision.Type
		ex.Decisions = append(ex.Decisions, ed)
	}
	switch {
	case !st.s.Enabled:
		ex.Result = "off"
	case ex.Protected != "":
		ex.Result = "protected"
	case v.Skip == SkipSiteExempt:
		ex.Result = "exempt"
	case v.Skip == SkipAllowlist:
		ex.Result = "allowlisted"
	case v.Matched && v.Action == ActionClosed:
		ex.Result = "fail-closed"
	case v.Matched && !v.Enforce:
		ex.Result, ex.Why = "would-block", v.Why
		if v.Action == ActionCaptcha {
			ex.Result = "would-challenge"
		}
	case v.Matched && v.Action == ActionCaptcha:
		ex.Result, ex.Fallback = "challenge", st.s.CaptchaFallback
	case v.Matched && v.Drop:
		ex.Result = "drop"
	case v.Matched:
		ex.Result = "block"
	case len(ex.Decisions) > 0:
		ex.Result = "ignored"
	default:
		ex.Result = "none"
	}
	page := m.Feed(FeedQuery{IP: ex.IP, Limit: 10})
	ex.Recent = page.Entries
	if !live {
		return ex, nil
	}
	la := &LiveAnswer{Decisions: []LiveDecision{}}
	ex.Live = la
	if st.s.LAPIURL == "" {
		la.Error = "no CrowdSec server address is saved"
		return ex, nil
	}
	if !m.takeLive() {
		la.Error = ErrLiveLimit.Error()
		return ex, nil
	}
	key, ok, err := m.vault.Get()
	if err != nil || !ok {
		la.Error = "no API key stored"
		return ex, nil
	}
	if BindingOf(st.s.LAPIURL) != m.keyBinding() { //the stored key is never sent to an address it was not entered for
		la.Error = "the stored API key was entered for another LAPI address"
		return ex, nil
	}
	c, err := NewClient(st.s, key, lookupTimeout)
	if err != nil {
		la.Error = strings.ReplaceAll(err.Error(), key, "[key]")
		return ex, nil
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	got, err := c.Lookup(ctx, ex.IP)
	if err != nil {
		msg := strings.ReplaceAll(err.Error(), key, "[key]")
		if len(msg) > 300 {
			msg = msg[:300]
		}
		la.Error = msg
		return ex, nil
	}
	liveIDs := map[int64]bool{}
	for i, d := range got {
		if i >= 50 {
			break
		}
		la.Decisions = append(la.Decisions, LiveDecision{ID: d.ID, Type: clean(strings.ToLower(d.Type), 32), Scope: clean(strings.ToLower(d.Scope), 32),
			Value: clean(d.Value, 64), Origin: clean(d.Origin, 64), Scenario: clean(d.Scenario, 128), Duration: clean(d.Duration, 32)})
		acted := (strings.EqualFold(d.Scope, ScopeIP) || strings.EqualFold(d.Scope, ScopeRange)) && (strings.EqualFold(d.Type, TypeBan) || strings.EqualFold(d.Type, TypeCaptcha))
		if acted {
			liveIDs[d.ID] = true
		}
	}
	cached := map[int64]bool{}
	for _, d := range ex.Decisions {
		cached[d.ID] = true
		if !liveIDs[d.ID] {
			la.Differs = true
		}
	}
	for id := range liveIDs {
		if !cached[id] {
			la.Differs = true
		}
	}
	return ex, nil
}
