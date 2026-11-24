package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/eventsystem"
	"github.com/foleyit/dunree/mod/plugins/dunree_plugin/events"
)

/*
	Proxy rule events (issue #149): proxyRuleAdded, proxyRuleEdited and
	proxyRuleRemoved are sent from the place every stored change of a proxy rule
	goes through (SaveReverseProxyConfig / RemoveReverseProxyConfig).
*/

type proxyRuleEventListener struct {
	got chan events.Event
}

func (l *proxyRuleEventListener) GetID() eventsystem.ListenerID { return "test.proxyrule.events" }
func (l *proxyRuleEventListener) Notify(e events.Event) error {
	l.got <- e
	return nil
}

// listenForProxyRuleEvents subscribes a listener to the three events for the length of the test
func listenForProxyRuleEvents(t *testing.T) *proxyRuleEventListener {
	t.Helper()
	eventsystem.InitEventSystem(SystemWideLogger)
	l := &proxyRuleEventListener{got: make(chan events.Event, 16)}
	for _, name := range []events.EventName{events.EventProxyRuleAdded, events.EventProxyRuleEdited, events.EventProxyRuleRemoved} {
		if !name.IsValid() {
			t.Fatalf("%s is not a known event name", name)
		}
		if err := eventsystem.Publisher.RegisterSubscriberToEvent(l, name); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { eventsystem.Publisher.UnregisterSubscriber(l.GetID()) })
	return l
}

func (l *proxyRuleEventListener) next(t *testing.T, want events.EventName) events.Event {
	t.Helper()
	select {
	case e := <-l.got:
		if e.Name != want {
			t.Fatalf("got event %s, want %s", e.Name, want)
		}
		if e.UUID == "" || e.Timestamp == 0 || e.Data.GetEventSource() != "proxy-config" {
			t.Fatalf("event %s is incomplete: %+v", want, e)
		}
		return e
	case <-time.After(3 * time.Second):
		t.Fatalf("no %s event", want)
	}
	return events.Event{}
}

func (l *proxyRuleEventListener) none(t *testing.T, what string) {
	t.Helper()
	select {
	case e := <-l.got:
		t.Fatalf("%s: unexpected event %s", what, e.Name)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestProxyRuleEventsAddedEditedRemoved(t *testing.T) {
	router := setupEditTest(t)
	l := listenForProxyRuleEvents(t)

	ep, err := router.LoadProxy("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ep.MatchingDomainAlias = []string{"www.example.com"}
	ep.Tags = []string{"blue"}

	//First save: the rule had no stored configuration
	if err := SaveReverseProxyConfig(ep); err != nil {
		t.Fatal(err)
	}
	added, ok := l.next(t, events.EventProxyRuleAdded).Data.(*events.ProxyRuleAddedEvent)
	if !ok || added.RootOrMatchingDomain != "app.example.com" || added.IsRoot || added.Disabled ||
		len(added.MatchingDomainAlias) != 1 || added.MatchingDomainAlias[0] != "www.example.com" || len(added.Tags) != 1 || added.Tags[0] != "blue" {
		t.Fatalf("payload of proxyRuleAdded: %+v", added)
	}

	//A change through the real edit handler of the admin interface
	if body := postEdit(t, url.Values{"rootname": {"app.example.com"}, "ratenum": {"7"}}); !strings.Contains(body, "OK") {
		t.Fatalf("edit handler: %s", body)
	}
	edited, ok := l.next(t, events.EventProxyRuleEdited).Data.(*events.ProxyRuleEditedEvent)
	if !ok || edited.RootOrMatchingDomain != "app.example.com" {
		t.Fatalf("payload of proxyRuleEdited: %+v", edited)
	}

	//Switched off: the event carries the state after the change
	ep, _ = router.LoadProxy("app.example.com")
	ep.Disabled = true
	if err := SaveReverseProxyConfig(ep); err != nil {
		t.Fatal(err)
	}
	if e := l.next(t, events.EventProxyRuleEdited).Data.(*events.ProxyRuleEditedEvent); !e.Disabled {
		t.Fatalf("proxyRuleEdited must carry the new state: %+v", e)
	}

	//A rewrite that is not a change by the administrator (hash upgrade) sends nothing
	if err := saveReverseProxyConfigQuietly(ep); err != nil {
		t.Fatal(err)
	}
	l.none(t, "quiet save")

	//What goes to the plugin: the names of the contract, and nothing about upstreams or credentials
	wire, err := json.Marshal(events.Event{Name: events.EventProxyRuleEdited, Data: &events.ProxyRuleEditedEvent{ProxyRuleInfo: edited.ProxyRuleInfo}})
	if err != nil {
		t.Fatal(err)
	}
	var onWire struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(wire, &onWire); err != nil {
		t.Fatal(err)
	}
	if len(onWire.Data) != 5 {
		t.Fatalf("the payload must hold exactly the five documented fields: %s", wire)
	}
	for _, k := range []string{"root_or_matching_domain", "matching_domain_alias", "is_root", "disabled", "tags"} {
		if _, has := onWire.Data[k]; !has {
			t.Fatalf("field %q is missing: %s", k, wire)
		}
	}

	//Removed
	if err := RemoveReverseProxyConfig("app.example.com"); err != nil {
		t.Fatal(err)
	}
	removed, ok := l.next(t, events.EventProxyRuleRemoved).Data.(*events.ProxyRuleRemovedEvent)
	if !ok || removed.RootOrMatchingDomain != "app.example.com" || removed.IsRoot {
		t.Fatalf("payload of proxyRuleRemoved: %+v", removed)
	}
	if _, err := os.Stat(filepath.Join(CONF_HTTP_PROXY, "app.example.com.config")); err == nil {
		t.Fatal("the config file is still there")
	}

	//A remove that fails (nothing stored) sends nothing
	if err := RemoveReverseProxyConfig("app.example.com"); err == nil {
		t.Fatal("removing a rule that is not stored must fail")
	}
	l.none(t, "failed remove")
}

// The default site is reported with is_root, and a failed write sends nothing
func TestProxyRuleEventsRootAndFailedWrite(t *testing.T) {
	setupEditTest(t)
	l := listenForProxyRuleEvents(t)

	root := &dynamicproxy.ProxyEndpoint{ProxyType: dynamicproxy.ProxyTypeRoot, RootOrMatchingDomain: "/"}
	if err := SaveReverseProxyConfig(root); err != nil {
		t.Fatal(err)
	}
	if e := l.next(t, events.EventProxyRuleAdded).Data.(*events.ProxyRuleAddedEvent); !e.IsRoot || e.RootOrMatchingDomain != "/" || e.Tags == nil || e.MatchingDomainAlias == nil {
		t.Fatalf("default site: %+v", e)
	}
	if err := RemoveReverseProxyConfig("/"); err != nil {
		t.Fatal(err)
	}
	if e := l.next(t, events.EventProxyRuleRemoved).Data.(*events.ProxyRuleRemovedEvent); !e.IsRoot {
		t.Fatalf("default site removed: %+v", e)
	}

	CONF_HTTP_PROXY = filepath.Join(CONF_HTTP_PROXY, "does", "not", "exist") //restored by setupEditTest
	if err := SaveReverseProxyConfig(&dynamicproxy.ProxyEndpoint{ProxyType: dynamicproxy.ProxyTypeHost, RootOrMatchingDomain: "lost.example.com"}); err == nil {
		t.Fatal("the write must fail")
	}
	l.none(t, "failed write")
}

// Without a subscriber, and before the event system exists, saving works as it always did
func TestProxyRuleEventsNeedNoEventSystem(t *testing.T) {
	setupEditTest(t)
	old := eventsystem.Publisher
	eventsystem.Publisher = nil
	t.Cleanup(func() { eventsystem.Publisher = old })
	ep := &dynamicproxy.ProxyEndpoint{ProxyType: dynamicproxy.ProxyTypeHost, RootOrMatchingDomain: "quiet.example.com"}
	if err := SaveReverseProxyConfig(ep); err != nil {
		t.Fatal(err)
	}
	if err := RemoveReverseProxyConfig("quiet.example.com"); err != nil {
		t.Fatal(err)
	}
}

// Two admin requests that store the same new rule at the same moment: one of them
// is the creation, the other one an edit. The check for the stored configuration
// and the write are one step (proxyConfigFileLock).
func TestProxyRuleEventsConcurrentSavesOfANewRuleGiveOneAdded(t *testing.T) {
	router := setupEditTest(t)
	l := listenForProxyRuleEvents(t)
	ep, err := router.LoadProxy("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	const savers = 8
	for round := 0; round < 40; round++ {
		os.Remove(filepath.Join(CONF_HTTP_PROXY, "app.example.com.config")) //no stored configuration, no event
		start, errs := make(chan struct{}), make(chan error, savers)
		for i := 0; i < savers; i++ {
			go func() {
				<-start
				errs <- SaveReverseProxyConfig(ep)
			}()
		}
		close(start)
		added := 0
		for i := 0; i < savers; i++ {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < savers; i++ {
			select {
			case e := <-l.got:
				if e.Name == events.EventProxyRuleAdded {
					added++
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("round %d: only %d of %d events", round, i, savers)
			}
		}
		if added != 1 {
			t.Fatalf("round %d: %d proxyRuleAdded events for one new rule, want 1", round, added)
		}
	}
}
