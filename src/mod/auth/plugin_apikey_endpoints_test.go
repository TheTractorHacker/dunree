package auth

import (
	"testing"

	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// Approving or withdrawing a permission changes what the live key of a plugin opens,
// without a new key and without touching the keys of other plugins.
func TestSetPermittedEndpointsForPlugin(t *testing.T) {
	m := NewAPIKeyManager()
	list := zoraxy_plugin.PermittedAPIEndpoint{Method: "GET", Endpoint: "/plugin/api/access/list"}
	add := zoraxy_plugin.PermittedAPIEndpoint{Method: "POST", Endpoint: "/plugin/api/blacklist/ip/add"}
	a, err := m.GenerateAPIKey("plugin.a", []zoraxy_plugin.PermittedAPIEndpoint{list})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.GenerateAPIKey("plugin.b", []zoraxy_plugin.PermittedAPIEndpoint{list})
	if err != nil {
		t.Fatal(err)
	}
	opens := func(key string, ep zoraxy_plugin.PermittedAPIEndpoint) bool {
		_, err := m.ValidateAPIKeyForEndpoint(ep.Endpoint, ep.Method, key)
		return err == nil
	}
	if !opens(a.APIKey, list) || opens(a.APIKey, add) {
		t.Fatal("setup")
	}
	granted := []zoraxy_plugin.PermittedAPIEndpoint{list, add}
	if n := m.SetPermittedEndpointsForPlugin("plugin.a", granted); n != 1 {
		t.Fatalf("changed %d keys, want 1", n)
	}
	granted[1].Endpoint = "/changed/by/the/caller" //the manager must hold its own copy
	if !opens(a.APIKey, add) || opens(b.APIKey, add) {
		t.Fatal("the new endpoint must open for plugin.a only")
	}
	if n := m.SetPermittedEndpointsForPlugin("plugin.a", nil); n != 1 || opens(a.APIKey, list) || opens(a.APIKey, add) {
		t.Fatal("an empty list must close every endpoint")
	}
	if _, err := m.ValidateAPIKey(a.APIKey); err != nil {
		t.Fatal("the key itself must stay valid")
	}
	if !opens(b.APIKey, list) {
		t.Fatal("the key of another plugin was changed")
	}
	if n := m.SetPermittedEndpointsForPlugin("nobody", granted); n != 0 {
		t.Fatalf("changed %d keys of a plugin without keys", n)
	}
}
