//go:build unix

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testdata/verdicts.json is also checked against the rules of Dunree itself
// (TestConformanceKitVerdictRulesMatchDunree in src/mod/plugins): the copy of the
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
		t.Errorf("hooks are not normalised the way Dunree does: %+v", m.Hooks)
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

// The proxy rule events of SDK 1.2.0 (kit 1.2.0): known names, and sample payloads
// with the fields docs/plugins/contract.md section 4 lists.
func TestProxyRuleEventsAreKnownAndSampled(t *testing.T) {
	m, _, err := decodeManifest([]byte(`{"id":"a.b","name":"n","author":"a","description":"d","ui_path":"/ui","subscription_path":"/ev","subscriptions_events":{"proxyRuleAdded":"x","proxyRuleEdited":"x","proxyRuleRemoved":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if fails, warns := checkManifest(m); len(fails) != 0 || len(warns) != 0 {
		t.Errorf("a manifest that subscribes to the proxy rule events: fails %q, warns %q", fails, warns)
	}
	m, _, _ = decodeManifest([]byte(`{"id":"a.b","name":"n","author":"a","description":"d","ui_path":"/ui","subscription_path":"/ev","subscriptions_events":{"proxyRuleRenamed":"x"}}`))
	if _, warns := checkManifest(m); !strings.Contains(strings.Join(warns, "; "), "not an event this kit knows") {
		t.Errorf("an unknown event name must still warn: %q", warns)
	}
	want := map[string][]string{
		"proxyRuleAdded":   {"disabled", "is_root", "matching_domain_alias", "root_or_matching_domain", "tags"},
		"proxyRuleEdited":  {"disabled", "is_root", "matching_domain_alias", "root_or_matching_domain", "tags"},
		"proxyRuleRemoved": {"is_root", "root_or_matching_domain"},
	}
	for name, fields := range want {
		var ev struct {
			Name string                     `json:"name"`
			UUID string                     `json:"uuid"`
			Data map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(sampleEvent(name, "a.b", 1), &ev); err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(ev.Data))
		for f := range ev.Data {
			got = append(got, f)
		}
		sort.Strings(got)
		if ev.Name != name || ev.UUID == "" || strings.Join(got, ",") != strings.Join(fields, ",") {
			t.Errorf("sample of %s: name %q, fields %v, want %v", name, ev.Name, got, fields)
		}
		if string(ev.Data["root_or_matching_domain"]) != `"conformance.test"` || string(ev.Data["is_root"]) != "false" {
			t.Errorf("sample of %s: %s", name, ev.Data)
		}
	}
	if toolVersion == "1.1.0" {
		t.Error("the kit behaves differently from 1.1.0 (three more event names, new samples): it needs its own version")
	}
}

// Dunree rebrand: the kit speaks to a plugin as Dunree does. Every plugin gets the configure fields
// of Zoraxy; the Dunree fields are added for a plugin that declares sdk_flavor "dunree". Every // legacy-compat
// header of the host goes out under both prefixes.
func TestConfigurePayloadAndHeadersFollowTheHost(t *testing.T) {
	k := &kit{uuid: "u-1", m: &manifest{PermittedAPIEndpoints: []permittedEndpoint{{Method: "GET", Endpoint: "/plugin/api/x"}}}, stub: &stubAPI{port: 4242, keys: map[string]bool{}}}
	legacy, _ := json.Marshal(k.configurePayload(&proc{port: 5001, token: "t"}))
	if strings.Contains(string(legacy), "dunree") || !strings.Contains(string(legacy), `"zoraxy_port":4242`) || !strings.Contains(string(legacy), `"zoraxy_uuid":"u-1"`) { // legacy-compat
		t.Fatalf("payload for a plugin built for Zoraxy: %s", legacy) // legacy-compat
	}
	k.m.SDKFlavor = "dunree"
	raw, _ := json.Marshal(k.configurePayload(&proc{port: 5001, token: "t"}))
	var cur struct {
		DunreePort   int `json:"dunree_port"`
		ZoraxyPort   int `json:"zoraxy_port"` // legacy-compat
		RuntimeConst struct {
			DunreeUUID string `json:"dunree_uuid"`
			ZoraxyUUID string `json:"zoraxy_uuid"` // legacy-compat
			DunreeVer  string `json:"dunree_version"`
		} `json:"runtime_const"`
	}
	if err := json.Unmarshal(raw, &cur); err != nil || cur.DunreePort != 4242 || cur.ZoraxyPort != 4242 || cur.RuntimeConst.DunreeUUID != "u-1" || cur.RuntimeConst.ZoraxyUUID != "u-1" || cur.RuntimeConst.DunreeVer == "" { // legacy-compat
		t.Fatalf("payload for a Dunree SDK plugin: %s (%v)", raw, err)
	}

	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	k = &kit{client: srv.Client(), p: &proc{port: port, token: "sekret"}}
	hdr := k.tokenHeader("req-1")
	hdr["X-Zoraxy-Event-Type"] = "blacklistedIpBlocked" // legacy-compat: call() adds the Dunree name
	if a := k.call(http.MethodPost, "/x", []byte("{}"), hdr, 2*time.Second, 1024); a.err != nil {
		t.Fatal(a.err)
	}
	for name, want := range map[string]string{"Plugin-Token": "sekret", "RequestID": "req-1", "Event-Type": "blacklistedIpBlocked"} {
		if got.Get("X-Dunree-"+name) != want || got.Get("X-Zoraxy-"+name) != want { // legacy-compat
			t.Errorf("%s: X-Dunree=%q X-Zoraxy=%q, want %q under both", name, got.Get("X-Dunree-"+name), got.Get("X-Zoraxy-"+name), want) // legacy-compat
		}
	}
}
