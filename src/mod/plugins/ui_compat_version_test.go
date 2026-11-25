package plugins

import (
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/dynamicproxy/dpcore"
	zp "github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

// The User-Agent of a request to a plugin UI carries the Dunree version first and, while the
// legacy names are on, the version of the base in the "Zoraxy/" token, as on the proxy path. // legacy-compat
// The Dunree version (1.0.0-beta.1) must not end up in that token. // legacy-compat
func TestPluginUIUserAgentCompatTokenIsTheBaseVersion(t *testing.T) {
	m := newFaultManager(t)
	m.Options.SystemConst = &zp.RuntimeConstantValue{DunreeVersion: "1.0.0-beta.1", ZoraxyVersion: "3.3.6"} // legacy-compat
	if got := m.uiProxyCompatVersion(); got != "3.3.6" {
		t.Fatalf("compat version for the plugin UI proxy = %q, want the base version 3.3.6", got)
	}
	prev := wirecompat.EmitLegacy()
	defer wirecompat.SetEmitLegacy(prev)
	wirecompat.SetEmitLegacy(true)
	ua := dpcore.IdentityUserAgent(m.uiProxyCompatVersion())
	if !strings.HasSuffix(ua, " Zoraxy/3.3.6") || strings.Contains(ua, "Zoraxy/1.0.0") { // legacy-compat
		t.Fatalf("User-Agent to a plugin UI: %q", ua)
	}
	// a caller that only filled the Dunree fields still gets a value (runtimeConstFor's fallback)
	m.Options.SystemConst = &zp.RuntimeConstantValue{DunreeVersion: "1.0.0-beta.1"}
	if got := m.uiProxyCompatVersion(); got == "" {
		t.Fatal("empty compat version when only the Dunree fields are set")
	}
	// and no SystemConst at all does not panic
	m.Options.SystemConst = nil
	_ = m.uiProxyCompatVersion()
}
