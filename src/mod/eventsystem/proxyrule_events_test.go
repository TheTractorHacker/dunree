package eventsystem

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/foleyit/dunree/mod/plugins/dunree_plugin/events"
)

// The proxy rule events (SDK 1.2.0) on the wire, and read back with ParseEvent as a plugin does
func TestProxyRuleEventsDeSerialization(t *testing.T) {
	info := events.ProxyRuleInfo{RootOrMatchingDomain: "app.example.com", MatchingDomainAlias: []string{"www.example.com"}, Disabled: true, Tags: []string{"blue"}}
	cases := []struct {
		data events.EventPayload
		want string
	}{
		{&events.ProxyRuleAddedEvent{ProxyRuleInfo: info}, `{"name":"proxyRuleAdded","timestamp":7,"uuid":"u","data":{"root_or_matching_domain":"app.example.com","matching_domain_alias":["www.example.com"],"is_root":false,"disabled":true,"tags":["blue"]}}`},
		{&events.ProxyRuleEditedEvent{ProxyRuleInfo: info}, `{"name":"proxyRuleEdited","timestamp":7,"uuid":"u","data":{"root_or_matching_domain":"app.example.com","matching_domain_alias":["www.example.com"],"is_root":false,"disabled":true,"tags":["blue"]}}`},
		{&events.ProxyRuleRemovedEvent{RootOrMatchingDomain: "/", IsRoot: true}, `{"name":"proxyRuleRemoved","timestamp":7,"uuid":"u","data":{"root_or_matching_domain":"/","is_root":true}}`},
	}
	for _, c := range cases {
		name := c.data.GetName()
		if !name.IsValid() || c.data.GetEventSource() != "proxy-config" {
			t.Fatalf("%s: not a valid event of proxy-config", name)
		}
		js, err := json.Marshal(events.Event{Name: name, Timestamp: 7, UUID: "u", Data: c.data})
		if err != nil {
			t.Fatal(err)
		}
		if string(js) != c.want {
			t.Fatalf("%s on the wire:\n got %s\nwant %s", name, js, c.want)
		}
		var back events.Event
		if err := events.ParseEvent(js, &back); err != nil {
			t.Fatalf("%s: ParseEvent: %v", name, err)
		}
		if back.Name != name || back.Timestamp != 7 || back.UUID != "u" || !reflect.DeepEqual(back.Data, c.data) {
			t.Fatalf("%s read back: %+v", name, back.Data)
		}
	}
}
