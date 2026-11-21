// Package baseline implements the "enterprise baseline": a short list of safe, reversible
// settings that a fresh install starts with, and that an administrator of an existing install can
// apply with a preview and undo again.
//
// The package only knows the bookkeeping (what was changed, what the previous value was, whether an
// item still holds the value the baseline wrote). What each item is and how it is read or written
// is supplied by the caller as Item values, so nothing in here touches Zoraxy settings by itself.
//
// Rules the design keeps:
//   - an item is only ever changed by an explicit Apply, never by reading the status;
//   - an item that already holds the baseline value is not recorded and never restored;
//   - Undo restores an item only while it still holds the value Apply wrote; an item the
//     administrator changed afterwards is left alone and reported;
//   - the persisted state survives restarts, and the fresh install decision is made once,
//     so a restart after an Undo never applies the baseline again.
package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DBTable = "settings"
	DBKey   = "baseline"

	SourceFresh  = "fresh"
	SourceButton = "button"
)

// KV is the part of the sys.db API used (database.Database satisfies it)
type KV interface {
	Read(table, key string, assignee interface{}) error
	Write(table, key string, value interface{}) error
}

// Info describes an item for the status card
type Info struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Why    string `json:"why"`
	Effect string `json:"effect"`           //what the baseline does to it, and the one thing to know
	Page   string `json:"page,omitempty"`   //UI page to open
	Anchor string `json:"anchor,omitempty"` //tab inside that page
	Info   bool   `json:"info"`             //true: shown only, the baseline never changes it
}

// Item is one baseline setting. Values are JSON so any setting fits.
type Item interface {
	Info() Info
	// Current is the value now, as canonical JSON
	Current() (json.RawMessage, error)
	// Target is the value the baseline sets, as canonical JSON (nil for an info item)
	Target() json.RawMessage
	// Eligible says whether the baseline may change this item now (fresh: a new install). A false
	// answer carries the reason shown to the administrator.
	Eligible(fresh bool) (bool, string)
	// Set writes a value (the baseline value on Apply, the recorded previous value on Undo)
	Set(v json.RawMessage) error
	// Display turns a JSON value into words for the preview
	Display(v json.RawMessage) string
}

// Record is what is persisted per changed item
type Record struct {
	Previous json.RawMessage `json:"previous"`
	Applied  json.RawMessage `json:"applied"`
}

// State is persisted in sys.db (settings/baseline)
type State struct {
	Decision  string            `json:"decision"` //"fresh" or "existing", made once at first start of a build with this feature
	DecidedAt int64             `json:"decidedAt"`
	AppliedAt int64             `json:"appliedAt,omitempty"` //last apply
	Source    string            `json:"source,omitempty"`    //fresh or button, of the last apply
	UndoneAt  int64             `json:"undoneAt,omitempty"`
	Items     map[string]Record `json:"items,omitempty"` //changed items still owned by the baseline
}

// Change is one line of a preview, or of an apply result
type Change struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	From   string `json:"from"`
	To     string `json:"to"`
	Status string `json:"status"` //change, already, skipped, info
	Reason string `json:"reason,omitempty"`
}

// ItemStatus is one line of the status card
type ItemStatus struct {
	Info
	On      bool   `json:"on"`
	Current string `json:"current"`
	Status  string `json:"status"` //on, off, skipped, info
	Reason  string `json:"reason,omitempty"`
	Managed bool   `json:"managed"` //recorded by an Apply and still undoable
}

// Manager keeps the state. Safe for concurrent use.
type Manager struct {
	mu    sync.Mutex
	kv    KV
	items []Item
	st    State
	have  bool
	Now   func() time.Time
}

// New loads the persisted state (none yet is fine). A state that cannot be read is treated as
// "decided: existing" so a damaged value can never switch anything on by itself.
func New(kv KV, items []Item) *Manager {
	m := &Manager{kv: kv, items: items, Now: time.Now}
	if kv != nil {
		var s State
		if err := kv.Read(DBTable, DBKey, &s); err == nil && s.Decision != "" {
			m.st, m.have = s, true
		}
	}
	return m
}

func (m *Manager) save() error {
	if m.kv == nil {
		return nil
	}
	return m.kv.Write(DBTable, DBKey, m.st)
}

func canon(v json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, v) != nil {
		return string(v)
	}
	return b.String()
}

func same(a, b json.RawMessage) bool { return canon(a) == canon(b) }

// Decided reports whether the fresh/existing decision has been recorded
func (m *Manager) Decided() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.have }

// State returns a copy of the persisted state
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.copyState()
}

func (m *Manager) copyState() State {
	s := m.st
	s.Items = make(map[string]Record, len(m.st.Items))
	for k, v := range m.st.Items {
		s.Items[k] = v
	}
	return s
}

// Preview lists, for every item, what Apply would do right now. It changes nothing.
func (m *Manager) Preview(fresh bool) []Change {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.preview(fresh)
}

func (m *Manager) preview(fresh bool) []Change {
	out := make([]Change, 0, len(m.items))
	for _, it := range m.items {
		inf := it.Info()
		c := Change{ID: inf.ID, Title: inf.Title}
		cur, err := it.Current()
		if err != nil {
			c.Status, c.Reason = "skipped", "the current value could not be read"
			out = append(out, c)
			continue
		}
		c.From = it.Display(cur)
		if inf.Info {
			c.To, c.Status = c.From, "info"
			out = append(out, c)
			continue
		}
		tgt := it.Target()
		c.To = it.Display(tgt)
		switch {
		case same(cur, tgt):
			c.To, c.Status = c.From, "already"
		default:
			if ok, why := it.Eligible(fresh); !ok {
				c.To, c.Status, c.Reason = c.From, "skipped", why
			} else {
				c.Status = "change"
			}
		}
		out = append(out, c)
	}
	return out
}

// Result of Apply and Undo
type Result struct {
	Changes []Change `json:"changes"`
	Changed int      `json:"changed"`
	Source  string   `json:"source,omitempty"`
}

// Decide records the fresh/existing decision once. A repeated call changes nothing. When fresh is
// true the baseline is applied with source "fresh". It returns the result of that apply (nil when existing).
func (m *Manager) Decide(fresh bool) (*Result, error) {
	m.mu.Lock()
	if m.have {
		m.mu.Unlock()
		return nil, nil
	}
	now := m.Now().Unix()
	m.st = State{Decision: "existing", DecidedAt: now}
	if fresh {
		m.st.Decision = "fresh"
	}
	m.have = true
	if err := m.save(); err != nil {
		m.have = false
		m.mu.Unlock()
		return nil, fmt.Errorf("could not record the baseline decision: %w", err)
	}
	m.mu.Unlock()
	if !fresh {
		return nil, nil
	}
	return m.Apply(SourceFresh)
}

// Apply sets every eligible item that is not at its baseline value yet. Items already at the value
// are left alone and not recorded. A second Apply with nothing left to do changes and writes nothing.
// A failing item is rolled back together with the ones set before it.
func (m *Manager) Apply(source string) (*Result, error) {
	if source != SourceFresh && source != SourceButton {
		return nil, errors.New("unknown source")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fresh := source == SourceFresh
	plan := m.preview(fresh)
	res := &Result{Changes: plan, Source: source}
	byID := map[string]Item{}
	for _, it := range m.items {
		byID[it.Info().ID] = it
	}
	var applied []done
	newRecs := map[string]Record{}
	for i, c := range plan {
		if c.Status != "change" {
			continue
		}
		it := byID[c.ID]
		prev, err := it.Current()
		if err == nil {
			err = it.Set(it.Target())
		}
		if err == nil {
			applied = append(applied, done{it, prev})
			var now json.RawMessage
			now, err = it.Current()
			if err == nil {
				newRecs[c.ID] = Record{Previous: prev, Applied: now}
			}
		}
		if err != nil {
			msg := m.rollback(applied)
			res.failed(plan)
			return res, fmt.Errorf("%s: %w%s", c.Title, err, msg)
		}
		plan[i].Status = "changed"
		res.Changed++
	}
	if res.Changed == 0 {
		return res, nil
	}
	if m.st.Items == nil {
		m.st.Items = map[string]Record{}
	}
	oldItems, oldApplied, oldSource, oldUndone := m.copyState().Items, m.st.AppliedAt, m.st.Source, m.st.UndoneAt
	for id, r := range newRecs {
		m.st.Items[id] = r
	}
	m.st.AppliedAt, m.st.Source, m.st.UndoneAt = m.Now().Unix(), source, 0
	if err := m.save(); err != nil {
		m.st.Items, m.st.AppliedAt, m.st.Source, m.st.UndoneAt = oldItems, oldApplied, oldSource, oldUndone
		msg := m.rollback(applied)
		res.failed(plan)
		if msg != "" {
			return res, fmt.Errorf("could not save the baseline state: %w%s", err, msg)
		}
		return res, fmt.Errorf("could not save the baseline state, nothing was changed: %w", err)
	}
	return res, nil
}

type done struct {
	it   Item
	prev json.RawMessage
}

// failed marks a failed apply: every line that was set or planned is reported as not applied
func (r *Result) failed(plan []Change) {
	for k := range plan {
		if plan[k].Status == "changed" || plan[k].Status == "change" {
			plan[k].To, plan[k].Status, plan[k].Reason = plan[k].From, "skipped", "not applied, nothing was changed"
		}
	}
	r.Changes, r.Changed = plan, 0
}

// rollback puts the items set so far back. An item that cannot be restored is recorded as owned by the
// baseline (so Undo can still revert it) and named in the returned text.
func (m *Manager) rollback(applied []done) string {
	var failed []string
	for j := len(applied) - 1; j >= 0; j-- {
		if err := applied[j].it.Set(applied[j].prev); err != nil {
			id := applied[j].it.Info().ID
			failed = append(failed, fmt.Sprintf("%s (%v)", id, err))
			if now, e := applied[j].it.Current(); e == nil {
				if m.st.Items == nil {
					m.st.Items = map[string]Record{}
				}
				m.st.Items[id] = Record{Previous: applied[j].prev, Applied: now}
			}
		}
	}
	if len(failed) == 0 {
		return ""
	}
	_ = m.save()
	return "; could not put back: " + strings.Join(failed, ", ") + " (Undo can still restore it)"
}

// Undo puts every recorded item back to its previous value, but only while it still holds the value
// Apply wrote; an item changed since is reported as skipped and left as the administrator has it.
func (m *Manager) Undo() (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := &Result{}
	if len(m.st.Items) == 0 {
		return res, errors.New("there is nothing to undo")
	}
	ids := make([]string, 0, len(m.st.Items))
	for id := range m.st.Items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	byID := map[string]Item{}
	for _, it := range m.items {
		byID[it.Info().ID] = it
	}
	var firstErr error
	for _, id := range ids {
		rec := m.st.Items[id]
		it := byID[id]
		if it == nil {
			res.Changes = append(res.Changes, Change{ID: id, Title: id, Status: "skipped", Reason: "this item no longer exists"})
			delete(m.st.Items, id)
			continue
		}
		c := Change{ID: id, Title: it.Info().Title}
		cur, err := it.Current()
		switch {
		case err != nil:
			c.Status, c.Reason = "skipped", "the current value could not be read"
		case !same(cur, rec.Applied):
			c.From, c.To, c.Status, c.Reason = it.Display(cur), it.Display(cur), "skipped", "changed since the baseline was applied, left as it is"
			delete(m.st.Items, id) //no longer ours
		default:
			c.From, c.To = it.Display(cur), it.Display(rec.Previous)
			if err := it.Set(rec.Previous); err != nil {
				c.Status, c.Reason = "skipped", "could not restore"
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", c.Title, err)
				}
			} else {
				c.Status = "restored"
				res.Changed++
				delete(m.st.Items, id)
			}
		}
		res.Changes = append(res.Changes, c)
	}
	m.st.UndoneAt = m.Now().Unix()
	if err := m.save(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("the values were restored but the state could not be saved: %w", err)
	}
	return res, firstErr
}

// Status is the card data: every item with its current state, plus the persisted state.
func (m *Manager) Status() []ItemStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	plan := m.preview(false) //same rule as the button and the preview, so the card and the drawer agree
	out := make([]ItemStatus, 0, len(m.items))
	for i, it := range m.items {
		inf := it.Info()
		s := ItemStatus{Info: inf, Current: plan[i].From, Reason: plan[i].Reason}
		_, s.Managed = m.st.Items[inf.ID]
		switch plan[i].Status {
		case "info":
			s.Status = "info"
		case "already":
			s.Status, s.On = "on", true
		case "skipped":
			s.Status = "skipped"
		default:
			s.Status = "off"
		}
		out = append(out, s)
	}
	return out
}

// Pending counts the items Apply would change right now (button source)
func (m *Manager) Pending() int {
	n := 0
	for _, c := range m.Preview(false) {
		if c.Status == "change" {
			n++
		}
	}
	return n
}
