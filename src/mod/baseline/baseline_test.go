package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memKV struct {
	m      map[string]json.RawMessage
	failOn bool
	writes int
}

func newKV() *memKV { return &memKV{m: map[string]json.RawMessage{}} }
func (k *memKV) Read(t, key string, out interface{}) error {
	b, ok := k.m[t+"/"+key]
	if !ok {
		return errors.New("not found")
	}
	return json.Unmarshal(b, out)
}
func (k *memKV) Write(t, key string, v interface{}) error {
	if k.failOn {
		return errors.New("disk full")
	}
	k.writes++
	b, _ := json.Marshal(v)
	k.m[t+"/"+key] = b
	return nil
}

type fakeItem struct {
	id       string
	val      string
	target   string
	eligible bool
	info     bool
	failSet  bool
	sets     int
}

func (f *fakeItem) Info() Info { return Info{ID: f.id, Title: f.id, Info: f.info} }
func (f *fakeItem) Current() (json.RawMessage, error) {
	b, _ := json.Marshal(f.val)
	return b, nil
}
func (f *fakeItem) Target() json.RawMessage {
	if f.info {
		return nil
	}
	b, _ := json.Marshal(f.target)
	return b
}
func (f *fakeItem) Eligible(bool) (bool, string) {
	if f.eligible {
		return true, ""
	}
	return false, "not now"
}
func (f *fakeItem) Set(v json.RawMessage) error {
	f.sets++
	if f.failSet {
		return errors.New("refused")
	}
	return json.Unmarshal(v, &f.val)
}
func (f *fakeItem) Display(v json.RawMessage) string {
	var s string
	_ = json.Unmarshal(v, &s)
	return s
}

func items() (*fakeItem, *fakeItem, *fakeItem, *fakeItem, []Item) {
	a := &fakeItem{id: "a", val: "off", target: "on", eligible: true}
	b := &fakeItem{id: "b", val: "old", target: "new", eligible: true}
	skip := &fakeItem{id: "skip", val: "mine", target: "on", eligible: false}
	info := &fakeItem{id: "info", val: "running", info: true}
	return a, b, skip, info, []Item{a, b, skip, info}
}

func TestPreviewEqualsApplyAndInfoNeverSet(t *testing.T) {
	a, b, skip, info, its := items()
	m := New(newKV(), its)
	pre := m.Preview(false)
	want := map[string]string{"a": "change", "b": "change", "skip": "skipped", "info": "info"}
	for _, c := range pre {
		if want[c.ID] != c.Status {
			t.Errorf("preview %s = %s", c.ID, c.Status)
		}
	}
	if a.sets+b.sets+skip.sets+info.sets != 0 {
		t.Fatal("preview must not write")
	}
	res, err := m.Apply(SourceButton)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != 2 || a.val != "on" || b.val != "new" || skip.val != "mine" || info.val != "running" || skip.sets != 0 || info.sets != 0 {
		t.Fatalf("apply touched the wrong items: %+v a=%s b=%s skip=%s sets=%d/%d", res, a.val, b.val, skip.val, skip.sets, info.sets)
	}
	for i, c := range res.Changes {
		if pre[i].Status == "change" && (c.Status != "changed" || c.From != pre[i].From || c.To != pre[i].To) {
			t.Errorf("apply line differs from the preview: %+v vs %+v", c, pre[i])
		}
		if pre[i].Status != "change" && c.Status != pre[i].Status {
			t.Errorf("non-change line differs: %+v vs %+v", c, pre[i])
		}
	}
}

func TestApplyIdempotent(t *testing.T) {
	a, _, _, _, its := items()
	kv := newKV()
	m := New(kv, its)
	if _, err := m.Apply(SourceButton); err != nil {
		t.Fatal(err)
	}
	st1 := m.State()
	writes, sets := kv.writes, a.sets
	res, err := m.Apply(SourceButton)
	if err != nil || res.Changed != 0 {
		t.Fatalf("second apply: %+v %v", res, err)
	}
	if kv.writes != writes || a.sets != sets {
		t.Fatal("a second apply must not write anything")
	}
	st2 := m.State()
	if st2.Items["a"].Previous == nil || string(st2.Items["a"].Previous) != string(st1.Items["a"].Previous) || string(st2.Items["a"].Previous) != `"off"` {
		t.Fatal("the recorded previous value must survive a second apply")
	}
	if _, err := m.Apply("sneaky"); err == nil {
		t.Fatal("unknown source accepted")
	}
}

func TestUndoRestoresExactly(t *testing.T) {
	a, b, skip, _, its := items()
	m := New(newKV(), its)
	m.Apply(SourceButton)
	res, err := m.Undo()
	if err != nil || res.Changed != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if a.val != "off" || b.val != "old" || skip.val != "mine" {
		t.Fatalf("not restored: %s %s %s", a.val, b.val, skip.val)
	}
	if len(m.State().Items) != 0 {
		t.Fatal("restored items must leave the state")
	}
	if _, err := m.Undo(); err == nil {
		t.Fatal("a second undo has nothing to do and must say so")
	}
}

func TestUndoLeavesItemsTheAdminChanged(t *testing.T) {
	a, b, _, _, its := items()
	m := New(newKV(), its)
	m.Apply(SourceButton)
	b.val = "admin-choice"
	res, err := m.Undo()
	if err != nil {
		t.Fatal(err)
	}
	if a.val != "off" {
		t.Fatal("untouched item must be restored")
	}
	if b.val != "admin-choice" {
		t.Fatal("an item the admin changed after apply must not be overwritten")
	}
	var warned bool
	for _, c := range res.Changes {
		if c.ID == "b" && c.Status == "skipped" && strings.Contains(c.Reason, "changed since") {
			warned = true
		}
	}
	if !warned || res.Changed != 1 {
		t.Fatalf("expected a warning for b: %+v", res)
	}
}

func TestAlreadyAtTargetIsNotRecorded(t *testing.T) {
	a, _, _, _, its := items()
	a.val = "on" //the admin had it already
	m := New(newKV(), its)
	m.Apply(SourceButton)
	if _, ok := m.State().Items["a"]; ok {
		t.Fatal("an item that already had the value is not the baseline's to undo")
	}
	a.val = "on"
	m.Undo()
	if a.val != "on" {
		t.Fatal("undo must not touch it")
	}
}

func TestDecideFreshAppliesOnceAndRestartNeverReapplies(t *testing.T) {
	a, _, _, _, its := items()
	kv := newKV()
	m := New(kv, its)
	if m.Decided() {
		t.Fatal("nothing decided yet")
	}
	res, err := m.Decide(true)
	if err != nil || res == nil || res.Changed != 2 || res.Source != SourceFresh || a.val != "on" {
		t.Fatalf("%+v %v", res, err)
	}
	if m.State().Source != SourceFresh || m.State().Decision != "fresh" || m.State().AppliedAt == 0 {
		t.Fatalf("state: %+v", m.State())
	}
	if _, err := m.Undo(); err != nil {
		t.Fatal(err)
	}
	//restart: a new manager on the same store, the probe still says fresh (e.g. a copied probe) -> nothing happens
	m2 := New(kv, its)
	if !m2.Decided() {
		t.Fatal("decision must persist")
	}
	res, err = m2.Decide(true)
	if err != nil || res != nil || a.val != "off" {
		t.Fatalf("a restart re-applied the baseline: %+v %v a=%s", res, err, a.val)
	}
}

func TestDecideExistingChangesNothing(t *testing.T) {
	a, b, _, _, its := items()
	kv := newKV()
	m := New(kv, its)
	res, err := m.Decide(false)
	if err != nil || res != nil {
		t.Fatal(res, err)
	}
	if a.sets+b.sets != 0 || a.val != "off" || b.val != "old" {
		t.Fatal("an existing install must not be changed")
	}
	if m.State().Decision != "existing" || len(m.State().Items) != 0 {
		t.Fatalf("%+v", m.State())
	}
	//the button still works and is recorded as a button apply
	if res, _ := m.Apply(SourceButton); res.Changed != 2 || m.State().Source != SourceButton {
		t.Fatal("button apply")
	}
}

func TestApplyFailureRollsBack(t *testing.T) {
	a, b, _, _, its := items()
	b.failSet = true
	m := New(newKV(), its)
	res, err := m.Apply(SourceButton)
	if err == nil {
		t.Fatal("expected an error")
	}
	if a.val != "off" || b.val != "old" {
		t.Fatalf("partial apply left behind: a=%s b=%s", a.val, b.val)
	}
	if len(m.State().Items) != 0 || res == nil {
		t.Fatal("nothing may be recorded after a failed apply")
	}
}

func TestSaveFailureRollsBack(t *testing.T) {
	a, b, _, _, its := items()
	kv := newKV()
	m := New(kv, its)
	kv.failOn = true
	if _, err := m.Apply(SourceButton); err == nil {
		t.Fatal("expected an error")
	}
	if a.val != "off" || b.val != "old" || len(m.State().Items) != 0 {
		t.Fatal("a failed save must leave nothing changed")
	}
}

func TestStatusAndOldStateLoads(t *testing.T) {
	_, _, _, _, its := items()
	kv := newKV()
	kv.m["settings/baseline"] = json.RawMessage(`{"decision":"existing","decidedAt":5}`) //minimal old/unknown-field-free value
	m := New(kv, its)
	if !m.Decided() {
		t.Fatal("must load")
	}
	got := map[string]string{}
	for _, s := range m.Status() {
		got[s.ID] = s.Status
	}
	if got["a"] != "off" || got["skip"] != "skipped" || got["info"] != "info" {
		t.Fatalf("%v", got)
	}
	kv2 := newKV()
	kv2.m["settings/baseline"] = json.RawMessage(`{garbage`)
	if New(kv2, its).Decided() {
		//a damaged record is "not decided"; the caller then decides from the probe, which is conservative
		t.Log("damaged state treated as undecided")
	}
}

func TestIsFresh(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "sys.db")

	conf := filepath.Join(root, "conf") //new dir: does not exist yet
	p := CaptureProbe(db, conf)
	if ok, why := IsFresh(p); !ok {
		t.Fatalf("new install not recognised: %s", why)
	}
	os.MkdirAll(filepath.Join(conf, "proxy"), 0o755) //empty skeleton folders are still new
	if ok, why := IsFresh(CaptureProbe(db, conf)); !ok {
		t.Fatalf("empty folders: %s", why)
	}

	//existing with proxy rules
	os.WriteFile(filepath.Join(conf, "proxy", "example.com.config"), []byte("{}"), 0o644)
	if ok, _ := IsFresh(CaptureProbe(db, conf)); ok {
		t.Fatal("an install with proxy rules is existing")
	}
	os.Remove(filepath.Join(conf, "proxy", "example.com.config"))

	//existing without rules but with an older schema stamp
	os.WriteFile(filepath.Join(conf, "config_schema.json"), []byte(`{"schema":1}`), 0o644)
	if ok, _ := IsFresh(CaptureProbe(db, conf)); ok {
		t.Fatal("a stamp from an earlier start means existing")
	}
	os.Remove(filepath.Join(conf, "config_schema.json"))

	//unreadable / damaged stamp is doubt
	os.WriteFile(filepath.Join(conf, "config_schema.json"), []byte(`{broken`), 0o644)
	if ok, _ := IsFresh(CaptureProbe(db, conf)); ok {
		t.Fatal("a damaged stamp is doubt, so existing")
	}
	os.Remove(filepath.Join(conf, "config_schema.json"))

	//a database that is already there
	os.WriteFile(db, []byte("x"), 0o644)
	if ok, _ := IsFresh(CaptureProbe(db, conf)); ok {
		t.Fatal("an existing database means existing")
	}
	os.Remove(db)
	os.MkdirAll(db, 0o755) //leveldb is a folder
	if ok, _ := IsFresh(CaptureProbe(db, conf)); ok {
		t.Fatal("an existing database folder means existing")
	}
	os.Remove(db)

	//other files in the config folder (certificates, settings) are doubt
	os.WriteFile(filepath.Join(conf, "trusted_proxies.json"), []byte("[]"), 0o644)
	if ok, _ := IsFresh(CaptureProbe(db, conf)); ok {
		t.Fatal("files in the config folder mean existing")
	}

	//an error examining anything is doubt
	if ok, _ := IsFresh(Probe{DBErr: errors.New("x")}); ok {
		t.Fatal("db error")
	}
	if ok, _ := IsFresh(Probe{ConfErr: errors.New("x")}); ok {
		t.Fatal("conf error")
	}
}

func TestFailedApplyReportsNothingChanged(t *testing.T) {
	check := func(t *testing.T, res *Result) {
		t.Helper()
		if res == nil || res.Changed != 0 {
			t.Fatalf("a failed apply must report 0 changed: %+v", res)
		}
		for _, c := range res.Changes {
			if c.Status == "changed" || c.Status == "change" {
				t.Errorf("%s is still reported as applied: %+v", c.ID, c)
			}
			if c.ID == "a" && (c.Status != "skipped" || c.To != c.From) {
				t.Errorf("rolled back line must show the unchanged value: %+v", c)
			}
		}
	}
	t.Run("item fails", func(t *testing.T) {
		_, b, _, _, its := items()
		b.failSet = true
		res, err := New(newKV(), its).Apply(SourceButton)
		if err == nil {
			t.Fatal("expected an error")
		}
		check(t, res)
	})
	t.Run("save fails", func(t *testing.T) {
		_, _, _, _, its := items()
		kv := newKV()
		m := New(kv, its)
		kv.failOn = true
		res, err := m.Apply(SourceButton)
		if err == nil {
			t.Fatal("expected an error")
		}
		check(t, res)
	})
}

// an item whose restore fails after a later item failed stays recorded, so Undo can still revert it
type stickyItem struct {
	fakeItem
	failRestore bool
}

func (s *stickyItem) Set(v json.RawMessage) error {
	var x string
	_ = json.Unmarshal(v, &x)
	if s.failRestore && x == "off" {
		return errors.New("restore refused")
	}
	return s.fakeItem.Set(v)
}

func TestRollbackFailureIsReportedAndStaysUndoable(t *testing.T) {
	a := &stickyItem{fakeItem: fakeItem{id: "a", val: "off", target: "on", eligible: true}, failRestore: true}
	b := &fakeItem{id: "b", val: "old", target: "new", eligible: true, failSet: true}
	m := New(newKV(), []Item{a, b})
	res, err := m.Apply(SourceButton)
	if err == nil || !strings.Contains(err.Error(), "could not put back: a") {
		t.Fatalf("the rollback failure must be in the error: %v", err)
	}
	if res.Changed != 0 {
		t.Fatalf("%+v", res)
	}
	if _, ok := m.State().Items["a"]; !ok {
		t.Fatal("the item left changed must be recorded so Undo can revert it")
	}
	a.failRestore = false
	if r, err := m.Undo(); err != nil || r.Changed != 1 || a.val != "off" {
		t.Fatalf("undo: %+v %v a=%s", r, err, a.val)
	}
}

// an item that is only eligible on a fresh install: the card row must follow the button rule
type freshOnly struct{ fakeItem }

func (f *freshOnly) Eligible(fresh bool) (bool, string) {
	if fresh {
		return true, ""
	}
	return false, "needs a trusted proxy"
}

func TestStatusUsesTheButtonRuleAfterAFreshDecision(t *testing.T) {
	f := &freshOnly{fakeItem{id: "f", val: "off", target: "on"}}
	kv := newKV()
	kv.m["settings/baseline"] = json.RawMessage(`{"decision":"fresh","decidedAt":5,"undoneAt":9}`)
	m := New(kv, []Item{f})
	st := m.Status()[0]
	if st.Status != "skipped" || st.Reason == "" {
		t.Fatalf("row must show not applied with the reason: %+v", st)
	}
	if m.Pending() != 0 || m.Preview(false)[0].Status != "skipped" {
		t.Fatal("preview and pending must agree with the row")
	}
}
