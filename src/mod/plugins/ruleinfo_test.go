package plugins

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
)

func TestSniffPayloadCarriesRuleInfoAdditively(t *testing.T) {
	r := httptest.NewRequest("GET", "http://a.example/x", nil)
	if RuleInfoFromRequest(r) != nil {
		t.Fatal("rule info without context")
	}
	r = WithRuleInfo(r, "a.example", []string{"web", "prod"})
	p := dunree_plugin.EncodeForwardRequestPayload(r, "1.2.3.4")
	p.Rule = RuleInfoFromRequest(r)
	js, _ := json.Marshal(p)
	var back dunree_plugin.DynamicSniffForwardRequest
	if err := json.Unmarshal(js, &back); err != nil || back.Rule == nil || back.Rule.Name != "a.example" || len(back.Rule.Tags) != 2 || back.Rule.UUID != RuleID("a.example") {
		t.Fatalf("%s %+v", js, back.Rule)
	}
	if RuleID("a.example") == RuleID("b.example") || len(RuleID("x")) != 16 {
		t.Fatal("RuleID")
	}
	// old payloads (no rule) still decode and a nil rule is omitted
	old, _ := json.Marshal(dunree_plugin.DynamicSniffForwardRequest{Method: "GET"})
	if strings.Contains(string(old), `"rule"`) {
		t.Fatal("nil rule must be omitted")
	}
	if _, err := dunree_plugin.DecodeForwardRequestPayload([]byte(`{"method":"GET","hostname":"h"}`)); err != nil {
		t.Fatal(err)
	}
}
