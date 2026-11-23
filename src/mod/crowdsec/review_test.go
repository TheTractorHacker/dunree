package crowdsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A key the LAPI rejects before any pull worked: the state stays "starting" (the grace period is still running), and the
// status carries the fact as a flag so the page can say "key rejected" instead of "connecting".
func TestStatusFlagsRejectedKeyBeforeFirstSync(t *testing.T) {
	x := setup(t, nil)
	x.f.key = "another-key"
	if err := x.pull(t); !errors.Is(err, ErrAuth) {
		t.Fatalf("%v", err)
	}
	st := x.m.Status()
	if st.State != "starting" || !st.KeyRejected || st.LastSuccess != nil || st.ConsecutiveErrors != 1 || st.LastError == "" {
		t.Fatalf("%+v", st)
	}
	raw, _ := json.Marshal(st)
	if !strings.Contains(string(raw), `"keyRejected":true`) || strings.Contains(string(raw), testKey) {
		t.Fatalf("%s", raw)
	}
	x.f.key = testKey
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	if st = x.m.Status(); st.KeyRejected || st.State != "ok" {
		t.Fatalf("after a good pull: %+v", st)
	}
	// an unreachable server is not a rejected key
	x.f.srv.Close()
	if err := x.pull(t); err == nil {
		t.Fatal("no error from a closed server")
	}
	if st = x.m.Status(); st.KeyRejected || st.ConsecutiveErrors != 1 {
		t.Fatalf("unreachable: %+v", st)
	}
}

// Counters start again when CrowdSec is switched off and on; the status says since when they count, as long as that
// is later than local midnight.
func TestCountingSinceAfterSwitchOn(t *testing.T) {
	x := setupMixed(t, nil)
	x.check("203.0.113.1")
	if x.m.Status().Today.Blocked != 1 {
		t.Fatalf("%+v", x.m.Status().Today)
	}
	x.advance(time.Hour) //13:00
	x.set(t, func(s *Settings) { s.Enabled = false })
	if st := x.m.Status(); st.CountingSince != nil || st.Today != (Counts{}) {
		t.Fatalf("switched off: %+v", st)
	}
	x.advance(90 * time.Minute) //14:30
	x.set(t, func(s *Settings) { s.Enabled = true })
	st := x.m.Status()
	if st.Today.Blocked != 0 || st.CountingSince == nil || !st.CountingSince.Equal(*x.clock) {
		t.Fatalf("switched on at %v: since %v today %+v", *x.clock, st.CountingSince, st.Today)
	}
	if a := x.m.Activity("24h"); !a.Since.Equal(*x.clock) {
		t.Fatalf("activity since %v", a.Since)
	}
	// saving a setting while it is on does not move the start
	on := *x.clock
	x.advance(time.Hour)
	x.set(t, func(s *Settings) { s.PollSeconds = 30 })
	if st = x.m.Status(); st.CountingSince == nil || !st.CountingSince.Equal(on) {
		t.Fatalf("a save moved the start: %v", st.CountingSince)
	}
	// the next day the counters cover the whole day: no "since"
	x.advance(12 * time.Hour)
	if st = x.m.Status(); st.CountingSince != nil {
		t.Fatalf("next day: %v", st.CountingSince)
	}
}

// The reach of a "scenario kept on log only" entry is counted with the test the request path uses
func TestScenarioReachMatchesDisposition(t *testing.T) {
	x := setupMixed(t, nil)
	comp := x.m.Activity("24h").Loaded
	if len(comp.AllScenarios) != 6 || len(comp.Scenarios) != 6 {
		t.Fatalf("%+v", comp)
	}
	for entry, want := range map[string][2]int{"http": {2, 2}, " HTTP-Probing ": {1, 1}, "crowdsecurity/": {3, 3}, "firehol": {1, 1}, "nothing-like-it": {0, 0}, "": {0, 0}} {
		d, n := comp.ScenarioReach(entry)
		if d != want[0] || n != want[1] {
			t.Errorf("%q: %d decisions in %d scenarios, want %v", entry, d, n, want)
		}
	}
	// the same answer as the policy: every decision "http" reaches is log only, the others are not
	x.set(t, func(s *Settings) { s.ScenarioLogOnly = []string{"HTTP"} })
	logged := 0
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "198.18.0.9", "203.0.113.5", "203.0.113.6"} {
		if v := x.check(ip); v.Matched && v.Why == WhyScenarioLog {
			logged++
		}
	}
	if d, _ := x.m.Activity("24h").Loaded.ScenarioReach("HTTP"); d != logged || logged != 2 {
		t.Fatalf("reach %d, kept log only %d", d, logged)
	}
}

// More distinct scenario names than the list keeps: bounded, the rest is "other" and never counted as reached
func TestAllScenariosIsBounded(t *testing.T) {
	x := setup(t, func(s *Settings) { s.MaxEntries = 1000 })
	var l []string
	for i := 0; i < 400; i++ {
		l = append(l, decO(i+1, "ban", "Ip", fmt.Sprintf("203.0.%d.%d", 100+i/200, 1+i%200), "crowdsec", fmt.Sprintf("other-scenario/%03d", i)))
	}
	x.f.startup = stream(l, nil)
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	comp := x.m.Activity("24h").Loaded
	if comp.Total != 400 || len(comp.AllScenarios) != compScenarios+1 || len(comp.Scenarios) != compTopN || comp.AllScenarios[0].Name != "other" || comp.AllScenarios[0].Count != 400-compScenarios {
		t.Fatalf("total %d, %d names, top %d, first %+v", comp.Total, len(comp.AllScenarios), len(comp.Scenarios), comp.AllScenarios[0])
	}
	if d, n := comp.ScenarioReach("other"); d != compScenarios || n != compScenarios {
		t.Fatalf("reach %d in %d", d, n)
	}
}
