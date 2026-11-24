package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// "No event selected = all events" must keep meaning what it meant before certificate.renewing existed.
func TestRenewingIsOptInOnly(t *testing.T) {
	if !IsOptInEvent(EventCertRenewing) || IsOptInEvent(EventCertIssued) || IsOptInEvent("nope") {
		t.Fatal("only certificate.renewing is opt-in")
	}
	if !IsKnownEvent(EventCertRenewing) || SeverityOf(EventCertRenewing) != SevInfo {
		t.Fatal("certificate.renewing must be in the catalogue as info")
	}
	type wanter interface{ Wants(string) bool }
	all := map[string]wanter{
		"webhook": &WebhookSink{Cfg: WebhookConfig{Enabled: true}},
		"channel": &ChannelSink{Cfg: ChannelConfig{Enabled: true}},
		"command": &CommandSink{Cfg: CommandConfig{Enabled: true, Path: "/bin/true"}, Allowed: true},
	}
	for name, s := range all {
		if !s.Wants(EventCertIssued) {
			t.Errorf("%s with no events must still get the ordinary events", name)
		}
		if s.Wants(EventCertRenewing) {
			t.Errorf("%s with no events must NOT get certificate.renewing", name)
		}
	}
	listed := []string{EventCertRenewing}
	explicit := map[string]wanter{
		"webhook": &WebhookSink{Cfg: WebhookConfig{Enabled: true, Events: listed}},
		"channel": &ChannelSink{Cfg: ChannelConfig{Enabled: true, Events: listed}},
		"command": &CommandSink{Cfg: CommandConfig{Enabled: true, Path: "/bin/true", Events: listed}, Allowed: true},
	}
	for name, s := range explicit {
		if !s.Wants(EventCertRenewing) {
			t.Errorf("%s that lists certificate.renewing must get it", name)
		}
	}
	if (&WebhookSink{Cfg: WebhookConfig{Enabled: false, Events: listed}}).Wants(EventCertRenewing) {
		t.Error("a disabled webhook wants nothing")
	}
}

func TestAnnounceRenewalNeedsASubscriber(t *testing.T) {
	m := newTestManager(t)
	if err := m.SetRenewLead(45); err != nil {
		t.Fatal(err)
	}
	// destinations that take "all events" do not count
	if _, err := m.SaveWebhook(WebhookConfig{Name: "all", URL: "https://hooks.example.com/a", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if m.Subscribed(EventCertRenewing) {
		t.Fatal("nobody subscribed yet")
	}
	if d := m.AnnounceRenewal("a", []string{"a.example"}, "Let's Encrypt", MethodHTTP01, false); d != 0 {
		t.Fatalf("no subscriber: no wait, got %v", d)
	}
	m.Dispatcher.Wait()
	if n := len(m.Deliveries()); n != 0 {
		t.Fatalf("no subscriber: nothing may be sent, log has %d entries", n)
	}
	var nilM *Manager
	if nilM.AnnounceRenewal("a", nil, "", MethodHTTP01, false) != 0 {
		t.Fatal("nil manager must be safe")
	}
}

func TestAnnounceRenewalDeliversAndReturnsLead(t *testing.T) {
	m := newTestManager(t)
	srv, got, mu := channelReceiver(t, 200)
	testTLS = srv.Client().Transport.(*http.Transport).TLSClientConfig
	defer func() { testTLS = nil }()
	// digest and dedupe on: the announcement must still go out at once, every time
	if err := m.SaveRules(Rules{DedupeSeconds: 600, RatePerHour: 100, FailThreshold: 2, RecoverThreshold: 1, Digest: Digest{Enabled: true, IntervalMinutes: 60}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveChannel(ChannelConfig{Name: "router", Type: ChanNtfy, Enabled: true, AllowPrivate: true, Events: []string{EventCertRenewing},
		Settings: map[string]string{"server": srv.URL, "topic": "t"}}); err != nil {
		t.Fatal(err)
	}
	count := func() int { m.Dispatcher.Wait(); mu.Lock(); defer mu.Unlock(); return len(*got) }

	// default lead is 0: announced, no wait
	if d := m.AnnounceRenewal("shop", []string{"shop.example"}, "Let's Encrypt", MethodHTTP01, false); d != 0 {
		t.Fatalf("default lead must be 0, got %v", d)
	}
	if count() != 1 {
		t.Fatal("subscribed channel must get the announcement")
	}
	if err := m.SetRenewLead(30); err != nil {
		t.Fatal(err)
	}
	if d := m.AnnounceRenewal("shop", []string{"shop.example"}, "Let's Encrypt", MethodHTTP01, false); d != 30*time.Second {
		t.Fatalf("HTTP-01 must wait the lead time, got %v", d)
	}
	if d := m.AnnounceRenewal("shop", []string{"shop.example"}, "Let's Encrypt", MethodDNS01, false); d != 0 {
		t.Fatalf("DNS-01 is announced but never delayed, got %v", d)
	}
	if n := count(); n != 3 {
		t.Fatalf("held or deduplicated: %d of 3 announcements arrived", n)
	}
	mu.Lock()
	found := false // deliveries are asynchronous, so their order is not fixed
	for _, c := range *got {
		found = found || (strings.Contains(c.body, "HTTP-01") && strings.Contains(c.body, "30 seconds"))
	}
	mu.Unlock()
	if !found {
		t.Errorf("message must name the challenge and the lead time: %+v", *got)
	}

	// offline mode: nothing can be delivered, so there is nothing to wait for
	m.offline = func() bool { return true }
	if d := m.AnnounceRenewal("shop", []string{"shop.example"}, "", MethodHTTP01, false); d != 0 {
		t.Fatalf("offline: no wait, got %v", d)
	}
	m.Dispatcher.Wait()
}

func TestRenewingWebhookPayload(t *testing.T) {
	var body string
	srv, cfg := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(204)
	})
	s := &WebhookSink{Cfg: WebhookConfig{Name: "router", URL: srv.URL, Enabled: true, Events: []string{EventCertRenewing}}, AllowPrivate: true, tlsConfig: cfg, Attempts: 1}
	m := newTestManager(t)
	m.Dispatcher = NewDispatcher(func() []Sink { return []Sink{s} })
	m.cfg.Webhooks = []WebhookConfig{s.Cfg} // Subscribed() reads the configuration
	m.cfg.RenewLeadSeconds = 20
	if d := m.AnnounceRenewal("shop", []string{"shop.example", "www.shop.example"}, "Let's Encrypt", MethodHTTP01, true); d != 20*time.Second {
		t.Fatalf("lead: %v", d)
	}
	m.Dispatcher.Wait()
	var ev Event
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatalf("webhook body is not the event JSON: %v %q", err, body)
	}
	if ev.Event != EventCertRenewing || ev.Subject != "shop" || len(ev.Domains) != 2 || ev.Source != "certificate" || ev.Time.IsZero() {
		t.Fatalf("bad event: %+v", ev)
	}
	if ev.Extra["method"] != "HTTP-01" || ev.Extra["lead_seconds"] != "20" || ev.Extra["first_issue"] != "true" {
		t.Fatalf("bad extra: %v", ev.Extra)
	}
	// the command hook gets the same JSON
	if env := strings.Join(EventEnv(ev), "\n"); !strings.Contains(env, "ZORAXY_EVENT=certificate.renewing") || !strings.Contains(env, `"method":"HTTP-01"`) {
		t.Errorf("command hook environment: %s", env)
	}
}

func TestRenewLeadSettingAPI(t *testing.T) {
	m := newTestManager(t)
	if m.RenewLead() != 0 || m.View()["renewLeadSeconds"] != 0 {
		t.Fatal("lead must default to 0")
	}
	if m.SetRenewLead(-1) == nil || m.SetRenewLead(MaxRenewLeadSeconds+1) == nil {
		t.Fatal("out of range lead accepted")
	}
	post := func(form url.Values) string {
		req := httptest.NewRequest("POST", "/api/notify/hooks", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		m.HandleHooks(rec, req)
		return rec.Body.String()
	}
	if out := post(url.Values{"op": {"setOptions"}, "expiryWarnDays": {"10"}, "renewLeadSeconds": {"90"}}); strings.Contains(out, "error") {
		t.Fatalf("setOptions: %s", out)
	}
	if m.RenewLead() != 90*time.Second {
		t.Fatalf("lead not stored: %v", m.RenewLead())
	}
	// an older client that does not send the field leaves it alone
	if out := post(url.Values{"op": {"setOptions"}, "expiryWarnDays": {"12"}}); strings.Contains(out, "error") {
		t.Fatalf("setOptions: %s", out)
	}
	if m.RenewLead() != 90*time.Second || m.WarnDays() != 12 {
		t.Fatalf("lead lost by a save without the field: %v", m.RenewLead())
	}
	if out := post(url.Values{"op": {"setOptions"}, "expiryWarnDays": {"12"}, "renewLeadSeconds": {"99999"}}); !strings.Contains(out, "error") {
		t.Fatalf("too long a lead accepted: %s", out)
	}
	// a refused lead time must not save the other options of the same request
	for _, bad := range []string{"-1", "abc", "99999"} {
		if out := post(url.Values{"op": {"setOptions"}, "allowPrivateTargets": {"true"}, "expiryWarnDays": {"20"}, "renewLeadSeconds": {bad}}); !strings.Contains(out, "error") {
			t.Fatalf("lead %q accepted: %s", bad, out)
		}
		if m.WarnDays() != 12 || m.View()["allowPrivateTargets"] != false || m.RenewLead() != 90*time.Second {
			t.Fatalf("a refused lead %q still changed the options: warn %d, private %v, lead %v", bad, m.WarnDays(), m.View()["allowPrivateTargets"], m.RenewLead())
		}
	}
	// and refused warn days must not save the lead time
	if out := post(url.Values{"op": {"setOptions"}, "expiryWarnDays": {"999"}, "renewLeadSeconds": {"5"}}); !strings.Contains(out, "error") || m.RenewLead() != 90*time.Second {
		t.Fatalf("refused warn days: %s, lead %v", out, m.RenewLead())
	}
	if out := post(url.Values{"op": {"saveWebhook"}, "name": {"router"}, "url": {"https://hooks.example.com/open80"}, "events": {EventCertRenewing}, "enabled": {"true"}}); !strings.Contains(out, `"id"`) {
		t.Fatalf("a webhook must be able to subscribe: %s", out)
	}
	if !m.Subscribed(EventCertRenewing) {
		t.Fatal("saved subscription not seen")
	}
	m2, err := NewManager(m.path, false, nil, nil)
	if err != nil || m2.RenewLead() != 90*time.Second {
		t.Fatalf("lead not persisted: %v %v", m2.RenewLead(), err)
	}
	js, _ := json.Marshal(m.View())
	if !strings.Contains(string(js), `"optInEvents":["certificate.renewing"`) {
		t.Fatalf("view must tell the UI which events are opt-in: %s", js)
	}
}
