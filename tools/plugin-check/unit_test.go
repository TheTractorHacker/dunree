//go:build unix

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata/verdicts.json is also checked against the rules of Zoraxy itself
// (TestConformanceKitVerdictRulesMatchZoraxy in src/mod/plugins): the copy of the
// rules in verdict.go must give the same answer for every entry.
func TestVerdictFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/verdicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name    string          `json:"name"`
		Stage   string          `json:"stage"`
		Valid   bool            `json:"valid"`
		Verdict json.RawMessage `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil || len(fixtures) < 50 {
		t.Fatalf("fixtures: %v (%d)", err, len(fixtures))
	}
	for _, f := range fixtures {
		_, err := validateVerdictBody(f.Stage, f.Verdict)
		if (err == nil) != f.Valid {
			t.Errorf("%s (%s): valid=%v, want %v (%v)", f.Name, f.Stage, err == nil, f.Valid, err)
		}
	}
	if _, err := validateVerdictBody("pre_auth", []byte(`{"action":"allow","reason":"`+strings.Repeat("A", maxVerdictBytes)+`"}`)); err == nil {
		t.Error("a verdict larger than the limit was accepted")
	}
	if _, err := validateVerdictBody("pre_auth", []byte(`{"action":`)); err == nil {
		t.Error("broken JSON was accepted")
	}
}

func TestManifestChecks(t *testing.T) {
	good := `{"id":"a.b","name":"n","author":"a","description":"d","ui_path":"/ui"}`
	cases := []struct {
		name          string
		js            string
		fails, warns  string //a text the list must contain ("" = the list must be empty)
		decodeRefused bool
	}{
		{"minimal", good, "", "", false},
		{"no id", `{"name":"n","author":"a","description":"d","ui_path":"/ui"}`, "id is empty", "", false},
		{"no ui path", `{"id":"a","name":"n","author":"a","description":"d"}`, "ui_path is empty", "", false},
		{"type is text", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","type":"router"}`, "", "", true},
		{"api_version is text", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","api_version":"1"}`, "", "not a whole number", false},
		{"api_version newer", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","api_version":7}`, "", "newer than the contract version", false},
		{"bad health path", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","health_path":"/h?x=1"}`, "", "health_path", false},
		{"unknown configure_via", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","configure_via":"pipe"}`, "", "configure_via", false},
		{"hooks without path", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","hooks":{"version":1,"stages":["pre_auth"]}}`, "filter_request_path", "", false},
		{"hooks unknown stage and timeout", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","hooks":{"stages":["pre_auth","later"],"filter_request_path":"/f","timeout_ms":60000}}`, "", "unknown hook stage", false},
		{"events without path", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","subscriptions_events":{"blacklistedIpBlocked":"x"}}`, "subscription_path", "", false},
		{"endpoint without reason", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","permitted_api_endpoints":[{"method":"get","endpoint":"/api/x"}]}`, "", "upper case", false},
		{"half a dynamic capture", `{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","dynamic_capture_sniff":"/s"}`, "", "dynamic capture needs both", false},
		{"odd id", `{"id":"../x y","name":"n","author":"a","description":"d","ui_path":"/ui"}`, "", "id should be", false},
	}
	for _, tc := range cases {
		m, notes, err := decodeManifest([]byte(tc.js))
		if (err != nil) != tc.decodeRefused {
			t.Errorf("%s: decode error %v, refused want %v", tc.name, err, tc.decodeRefused)
			continue
		}
		if err != nil {
			continue
		}
		fails, warns := checkManifest(m)
		warns = append(notes, warns...)
		for what, pair := range map[string][2]string{"fails": {strings.Join(fails, "; "), tc.fails}, "warns": {strings.Join(warns, "; "), tc.warns}} {
			got, want := pair[0], pair[1]
			if (want == "" && got != "") || !strings.Contains(got, want) {
				t.Errorf("%s: %s = %q, want %q", tc.name, what, got, want)
			}
		}
	}
	m, _, _ := decodeManifest([]byte(`{"id":"a","name":"n","author":"a","description":"d","ui_path":"/ui","hooks":{"stages":["response","response"],"filter_request_path":"f","filter_response_path":"/r","timeout_ms":60000}}`))
	checkManifest(m)
	if m.hookTimeoutMs() != maxHookTimeoutMs || m.filterPath("response") != "/r" || m.filterPath("pre_auth") != "/f" || len(m.Hooks.Stages) != 1 {
		t.Errorf("hooks are not normalised the way Zoraxy does: %+v", m.Hooks)
	}
}

func TestLogCounter(t *testing.T) {
	l := &logCounter{}
	l.Write([]byte("one\ntw"))
	l.Write([]byte("o\n" + strings.Repeat("x", 100000)))
	lines, size, longest, tail := l.snapshot()
	if lines != 3 || size != 100008 || longest != 100000 || len(tail) != 3 || tail[1] != "two" || len(tail[2]) != tailLineLen {
		t.Fatalf("lines %d, bytes %d, longest %d, tail %d %q", lines, size, longest, len(tail), tail[:2])
	}
	for i := 0; i < 100; i++ {
		l.Write([]byte("\nline"))
	}
	if lines, _, _, tail := l.snapshot(); lines != 103 || len(tail) != tailLines+1 {
		t.Fatalf("lines %d, tail %d", lines, len(tail))
	}
}

func TestPercentile(t *testing.T) {
	var d []time.Duration
	for i := 1; i <= 100; i++ {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	if percentile(d, 0.5) != 50*time.Millisecond || percentile(d, 0.95) != 95*time.Millisecond || percentile(d, 0.99) != 99*time.Millisecond || percentile(nil, 0.5) != 0 || percentile(d[:1], 0.99) != time.Millisecond {
		t.Fatalf("percentiles: %v %v %v", percentile(d, 0.5), percentile(d, 0.95), percentile(d, 0.99))
	}
}
