package rewrite

import (
	"net/http/httptest"
	"testing"
)

// User defined variables (upstream #370) expand next to the built-ins, never shadow them, are
// sanitised like every other value and are not expanded a second time.
func TestUserVariablesInTemplates(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = "192.0.2.5:1234"

	// without a provider an unknown name keeps its old meaning: left untouched
	if got := ExpandTemplateVars(r, "x={{office_ip}}"); got != "x={{office_ip}}" {
		t.Fatalf("no provider: %q", got)
	}

	vars := map[string]string{
		"office_ip": "203.0.113.9",
		"host":      "evil.example", // must lose against the built-in
		"nested":    "{{client_ip}}",
		"dirty":     "a\r\nSet-Cookie: x=1",
	}
	SetUserVarProvider(func(name string) (string, bool) { v, ok := vars[name]; return v, ok })
	defer SetUserVarProvider(nil)

	cases := map[string]string{
		"x={{office_ip}}":             "x=203.0.113.9",
		"x={{ office_ip }}/{{nope}}":  "x=203.0.113.9/{{nope}}",
		"{{host}}":                    "app.example.com",
		"{{nested}}":                  "{{client_ip}}",
		"{{dirty}}":                   "aSet-Cookie: x=1",
		"{{client_ip}}-{{office_ip}}": "192.0.2.5-203.0.113.9",
	}
	for in, want := range cases {
		if got := ExpandTemplateVars(r, in); got != want {
			t.Errorf("ExpandTemplateVars(%q) = %q, want %q", in, got, want)
		}
	}
}
