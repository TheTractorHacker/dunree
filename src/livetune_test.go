package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var tuneT0 = time.Unix(1_700_000_000, 0)

func tin(total, a int64) tuneInput {
	return tuneInput{Total: total, Rules: map[string]int64{"a.test": a}, Limiters: map[string]tuneLimiter{}}
}

// feed sends one tick per 5 s with the given per tick request counts
func feed(st *tuneStore, counts []int64) time.Time {
	var cum int64
	now := tuneT0
	for i, c := range counts {
		cum += c
		now = tuneT0.Add(time.Duration(i) * 5 * time.Second)
		st.tick(now, tin(cum, cum))
	}
	return now
}

func TestTuneAvgPeakShortHistory(t *testing.T) {
	st := newTuneStore()
	// tick 0 is the baseline; then 10, 50, 0, 20 requests per 5 s slot
	now := feed(st, []int64{1000, 10, 50, 0, 20})
	r := st.query(now, "1h") // the hour window is longer than the history: only the real slots count
	a := r.Rules[0].Stats
	if a.Covered != 25 { // the baseline slot + 4 slots
		t.Fatalf("covered %d s, want 25 (short history must not be diluted by an hour of zeros)", a.Covered)
	}
	if want := 80.0 / 25; a.Avg != want {
		t.Fatalf("avg %v, want %v", a.Avg, want)
	}
	if a.Peak != 10 { // 50 per 5 s
		t.Fatalf("peak %v, want 10", a.Peak)
	}
	if a.PeakAt != tuneT0.Unix()+2*5 {
		t.Fatalf("peak at %d, want slot of the 50-request tick %d", a.PeakAt, tuneT0.Unix()+10)
	}
	if a.Current != 2 { // last two slots: 0 + 20 over 10 s
		t.Fatalf("current %v, want 2", a.Current)
	}
	if r.Total.Peak != 10 {
		t.Fatalf("total peak %v", r.Total.Peak)
	}
}

func TestTuneWindows(t *testing.T) {
	st := newTuneStore()
	counts := []int64{0}
	for i := 0; i < 100; i++ { // 100 slots of 5 requests = 1 req/s, then a burst
		counts = append(counts, 5)
	}
	counts = append(counts, 500)
	now := feed(st, counts)
	for _, w := range []struct {
		name string
		n    int
	}{{"10s", 2}, {"1m", 12}, {"5m", 60}} {
		s := st.query(now, w.name).Rules[0].Stats
		if s.Covered != w.n*5 {
			t.Fatalf("%s covered %d", w.name, s.Covered)
		}
		if s.Peak != 100 {
			t.Fatalf("%s peak %v, want 100", w.name, s.Peak)
		}
		want := float64(500+(w.n-1)*5) / float64(w.n*5)
		if d := s.Avg - want; d > 1e-9 || d < -1e-9 {
			t.Fatalf("%s avg %v want %v", w.name, s.Avg, want)
		}
	}
	// the burst is out of a 10 s window after two more quiet slots
	counts2 := append(counts, 0, 0)
	st2 := newTuneStore()
	now2 := feed(st2, counts2)
	if s := st2.query(now2, "10s").Rules[0].Stats; s.Peak != 0 || s.Avg != 0 {
		t.Fatalf("burst must leave the 10 s window: %+v", s)
	}
	if s := st2.query(now2, "1m").Rules[0].Stats; s.Peak != 100 {
		t.Fatalf("burst must still be in the 1 min window: %+v", s)
	}
}

func TestTuneCounterResetIsNotASpike(t *testing.T) {
	st := newTuneStore()
	st.tick(tuneT0, tin(9000, 9000))
	st.tick(tuneT0.Add(5*time.Second), tin(9050, 9050))
	st.tick(tuneT0.Add(10*time.Second), tin(3, 3)) // midnight: counters restart
	now := tuneT0.Add(15 * time.Second)
	st.tick(now, tin(23, 23))
	s := st.query(now, "1m").Rules[0].Stats
	if s.Peak != 10 { // 50 per slot, the reset slot must not be 9000+ or 3
		t.Fatalf("peak %v after a reset, want 10 (the 50 request slot)", s.Peak)
	}
	if want := 70.0 / 20; s.Avg != want {
		t.Fatalf("avg %v, want %v: reset slot counts 0, then 20", s.Avg, want)
	}
}

func TestTuneGapIsIdleNotStretched(t *testing.T) {
	st := newTuneStore()
	st.tick(tuneT0, tin(0, 0))
	st.tick(tuneT0.Add(5*time.Second), tin(50, 50))
	// the machine was suspended for 60 s, then 10 more requests arrived
	now := tuneT0.Add(65 * time.Second)
	st.tick(now, tin(60, 60))
	s := st.query(now, "1m").Rules[0].Stats
	if s.Covered != 60 { // 12 slots in the window, history is 14 slots long
		t.Fatalf("covered %d", s.Covered)
	}
	if s.Peak != 2 { // 10 requests in the latest slot; the 50 request slot is 12 slots back, outside the window
		t.Fatalf("1m peak %v, want 2", s.Peak)
	}
	all := st.query(now, "1h").Rules[0].Stats
	if all.Covered != 70 || all.Peak != 10 {
		t.Fatalf("1h: %+v (slots skipped by the gap are idle slots, history is 14 slots)", all)
	}
}

func TestTuneRingWrap(t *testing.T) {
	st := newTuneStore()
	counts := []int64{0}
	for i := 0; i < tuneSlots+50; i++ {
		counts = append(counts, 5)
	}
	now := feed(st, counts)
	s := st.query(now, "1h").Rules[0].Stats
	if s.Covered != tuneSlots*5 || s.Avg != 1 {
		t.Fatalf("after wrapping the ring the hour must be exactly 720 slots at 1 req/s: %+v", s)
	}
}

func TestTuneBeforeFirstTick(t *testing.T) {
	st := newTuneStore()
	r := st.query(tuneT0, "10s")
	if !r.Stale || len(r.Rules) != 0 {
		t.Fatalf("no tick yet: %+v", r)
	}
	st.tick(tuneT0, tin(5, 5))
	if r := st.query(tuneT0.Add(time.Minute), "10s"); !r.Stale {
		t.Fatal("a sampler that has not ticked for a minute is stale")
	}
}

func TestTuneRuleCapAndRemoval(t *testing.T) {
	st := newTuneStore()
	in := tuneInput{Rules: map[string]int64{}, Limiters: map[string]tuneLimiter{}}
	for i := 0; i < tuneMaxRules+30; i++ {
		in.Rules[string(rune('a'+i%26))+string(rune('a'+i/26))+".test"] = 1
	}
	st.tick(tuneT0, in)
	if len(st.rules) != tuneMaxRules {
		t.Fatalf("tracked %d rules, cap is %d", len(st.rules), tuneMaxRules)
	}
	st.tick(tuneT0.Add(5*time.Second), tuneInput{Rules: map[string]int64{"a.test": 1}})
	if len(st.rules) != 1 {
		t.Fatalf("removed rules must be forgotten, have %d", len(st.rules))
	}
}

func lim(clients map[string][2]uint64) tuneInput {
	return tuneInput{Rules: map[string]int64{"a.test": 0}, Limiters: map[string]tuneLimiter{"a.test": {Rate: 10, Burst: 20, Clients: clients}}}
}

func TestTuneBusiestClientAndDenied(t *testing.T) {
	st := newTuneStore()
	st.tick(tuneT0, lim(map[string][2]uint64{"10.0.0.1": {100, 0}, "10.0.0.2": {10, 0}}))
	// 5 s later: .1 made 40 requests (5 denied), .2 made 10, .3 appeared (no baseline yet)
	now := tuneT0.Add(5 * time.Second)
	st.tick(now, lim(map[string][2]uint64{"10.0.0.1": {135, 5}, "10.0.0.2": {20, 0}, "10.0.0.3": {500, 0}}))
	l := st.query(now, "1m").Rules[0].Limiter
	if !l.Enabled || l.Rate != 10 || l.Burst != 20 {
		t.Fatalf("limiter %+v", l)
	}
	if l.Busiest == nil || l.Busiest.IP != "10.0.0.1" || l.Busiest.Rps != 8 || l.Busiest.PerMinute != 480 {
		t.Fatalf("busiest %+v, want 10.0.0.1 at 8 req/s (a client without baseline must not win)", l.Busiest)
	}
	if l.Denied != 5 {
		t.Fatalf("denied %d", l.Denied)
	}
	if l.Hint != 16 {
		t.Fatalf("suggested %v, want 2x the busiest client = 16", l.Hint)
	}
	// the bucket of .1 was swept and restarted from 0: counts went down, they are not negative traffic
	now = tuneT0.Add(10 * time.Second)
	st.tick(now, lim(map[string][2]uint64{"10.0.0.1": {5, 0}, "10.0.0.2": {20, 0}, "10.0.0.3": {500, 0}}))
	now = tuneT0.Add(15 * time.Second)
	st.tick(now, lim(map[string][2]uint64{"10.0.0.1": {10, 0}, "10.0.0.2": {20, 0}, "10.0.0.3": {500, 0}}))
	// the 10 s window now covers only the restart and the slot after it (the 8 req/s slot is outside)
	l = st.query(now, "10s").Rules[0].Limiter
	if l.Busiest == nil || l.Busiest.Rps > 1 {
		t.Fatalf("after a bucket restart: %+v (a counter that went down is not negative or huge traffic)", l.Busiest)
	}
}

func TestTuneNoLimiterNoClientNumbers(t *testing.T) {
	st := newTuneStore()
	st.tick(tuneT0, tin(0, 0))
	now := tuneT0.Add(5 * time.Second)
	st.tick(now, tin(30, 30))
	l := st.query(now, "1m").Rules[0].Limiter
	if l.Enabled || l.Busiest != nil || l.Hint != 0 || l.Denied != 0 {
		t.Fatalf("a rule without a rate limit must have no per client data: %+v", l)
	}
}

func TestTuneEndpointMethodAndWindow(t *testing.T) {
	w := httptest.NewRecorder()
	HandleLiveTune(w, httptest.NewRequest("POST", "/api/stats/livetune", nil))
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatal("handler must answer")
	}
	if n, s := tuneWindowSlots("bogus"); n != "10s" || s != 2 {
		t.Fatal("unknown window falls back to 10s")
	}
}
