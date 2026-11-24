package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/acme"
	"github.com/foleyit/dunree/mod/notify"
)

// The bridge between the ACME handler and the notification centre (issue #178): a webhook that
// subscribed to certificate.renewing is called before the order and the issuer is told to wait.
// The receiver is an in-process HTTP server; no CA and no outside network is involved.
func TestAcmeBeforeOrderBridge(t *testing.T) {
	old := notifyManager
	defer func() { notifyManager = old }()

	notifyManager = nil
	if d := acmeBeforeOrderBridge(acme.RenewNotice{CertName: "a"}); d != 0 {
		t.Fatalf("no notification manager: no wait, got %v", d)
	}

	var mu sync.Mutex
	var bodies []notify.Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev notify.Event
		json.Unmarshal(b, &ev)
		mu.Lock()
		bodies = append(bodies, ev)
		mu.Unlock()
	}))
	defer srv.Close()

	m, err := notify.NewManager(filepath.Join(t.TempDir(), "notify.json"), false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	notifyManager = m
	if err := m.SetOptions(true, 14); err != nil { // loopback receiver
		t.Fatal(err)
	}
	if err := m.SetRenewLead(25); err != nil {
		t.Fatal(err)
	}
	notice := acme.RenewNotice{CertName: "shop", Domains: []string{"shop.example"}, CA: "Let's Encrypt"}

	// a webhook that takes "all events" is not a subscriber: nothing is sent, nothing waits
	allID, err := m.SaveWebhook(notify.WebhookConfig{Name: "all", URL: srv.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if d := acmeBeforeOrderBridge(notice); d != 0 {
		t.Fatalf("no subscriber: no wait, got %v", d)
	}
	m.Dispatcher.Wait()
	if len(bodies) != 0 {
		t.Fatalf("an 'all events' webhook must not get certificate.renewing: %+v", bodies)
	}
	m.DeleteWebhook(allID)

	if _, err := m.SaveWebhook(notify.WebhookConfig{Name: "router", URL: srv.URL, Enabled: true, Events: []string{notify.EventCertRenewing}}); err != nil {
		t.Fatal(err)
	}
	if d := acmeBeforeOrderBridge(notice); d != 25*time.Second {
		t.Fatalf("HTTP-01 order must wait the lead time, got %v", d)
	}
	notice.UseDNS = true
	if d := acmeBeforeOrderBridge(notice); d != 0 {
		t.Fatalf("DNS-01 order must not wait, got %v", d)
	}
	m.Dispatcher.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("both orders must be announced, got %+v", bodies)
	}
	methods := map[string]string{}
	for _, ev := range bodies {
		if ev.Event != notify.EventCertRenewing || ev.Subject != "shop" || len(ev.Domains) != 1 || ev.Domains[0] != "shop.example" {
			t.Fatalf("bad payload: %+v", ev)
		}
		methods[ev.Extra["method"]] = ev.Extra["lead_seconds"]
	}
	if methods["HTTP-01"] != "25" || methods["DNS-01"] != "0" {
		t.Fatalf("method / lead in payload: %v", methods)
	}
}
