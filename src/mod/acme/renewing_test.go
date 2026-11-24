package acme

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingBrokenCA is a fake ACME directory that refuses everything and counts the requests it got.
// No real CA and no real network is used: these tests cover the plumbing before the order only.
func countingBrokenCA(t *testing.T) (*httptest.Server, *int32) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "fake CA says no", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

type orderProbe struct {
	notices   []RenewNotice
	slept     []time.Duration
	hitsAtAsk []int32 // CA requests seen when BeforeOrder ran
	hitsAtNap []int32 // CA requests seen when the wait started
}

func probeOrders(a *ACMEHandler, hits *int32, lead time.Duration) *orderProbe {
	p := &orderProbe{}
	a.BeforeOrder = func(n RenewNotice) time.Duration {
		p.notices = append(p.notices, n)
		p.hitsAtAsk = append(p.hitsAtAsk, atomic.LoadInt32(hits))
		return lead
	}
	a.sleepFn = func(d time.Duration) {
		p.slept = append(p.slept, d)
		p.hitsAtNap = append(p.hitsAtNap, atomic.LoadInt32(hits))
	}
	return p
}

func TestBeforeOrderRunsAndWaitsBeforeTheCAIsContacted(t *testing.T) {
	a := newDBTestHandler(t)
	srv, hits := countingBrokenCA(t)
	p := probeOrders(a, hits, 7*time.Second)
	var after []CertEvent
	a.OnEvent = func(e CertEvent) { after = append(after, e) }

	ok, lines, err := a.ObtainCertCapture([]string{"Shop.Example", "bücher.example"}, "shop", "x@example.com", "custom", srv.URL+"/dir", true, false, 60, "", false, false, ObtainOptions{})
	if ok || err == nil {
		t.Fatal("the fake CA must refuse the order")
	}
	if len(p.notices) != 1 {
		t.Fatalf("one order, one notice, got %+v", p.notices)
	}
	n := p.notices[0]
	if n.CertName != "shop" || n.UseDNS || !n.FirstIssue || n.CA != "custom" {
		t.Fatalf("bad notice: %+v", n)
	}
	if len(n.Domains) != 2 || n.Domains[0] != "shop.example" || n.Domains[1] != "xn--bcher-kva.example" {
		t.Fatalf("domains must be the names sent to the CA: %v", n.Domains)
	}
	if len(p.slept) != 1 || p.slept[0] != 7*time.Second {
		t.Fatalf("the lead time must be waited once: %v", p.slept)
	}
	if p.hitsAtAsk[0] != 0 || p.hitsAtNap[0] != 0 {
		t.Fatalf("the CA was contacted before the notice / wait: %v %v", p.hitsAtAsk, p.hitsAtNap)
	}
	if atomic.LoadInt32(hits) == 0 {
		t.Fatal("the order must still be attempted after the wait")
	}
	if !strings.Contains(strings.Join(lines, "\n"), "waiting 7s") {
		t.Errorf("the wait must show in the operation log: %v", lines)
	}
	// the outcome event is unchanged: exactly one, after the notice
	if len(after) != 1 || after[0].Type != EventCertFailed {
		t.Fatalf("outcome events changed: %+v", after)
	}
}

func TestBeforeOrderDefaultsAndBounds(t *testing.T) {
	a := newDBTestHandler(t)
	srv, hits := countingBrokenCA(t)
	obtain := func(domains ...string) {
		a.ObtainCertWithOptions(domains, "c", "x@example.com", "custom", srv.URL+"/dir", true, false, 60, "", false, false, ObtainOptions{})
	}

	// no subscriber: nothing waits (default behaviour)
	a.sleepFn = func(time.Duration) { t.Fatal("no BeforeOrder, no wait") }
	obtain("c.example")
	if atomic.LoadInt32(hits) == 0 {
		t.Fatal("order not attempted")
	}

	// lead 0: asked, not waited
	p := probeOrders(a, hits, 0)
	obtain("c.example")
	if len(p.notices) != 1 || len(p.slept) != 0 {
		t.Fatalf("lead 0 must not wait: %+v %v", p.notices, p.slept)
	}

	// a huge lead is capped, a panicking subscriber is ignored, an invalid order is not announced
	p = probeOrders(a, hits, 48*time.Hour)
	obtain("c.example")
	if len(p.slept) != 1 || p.slept[0] != maxOrderLead {
		t.Fatalf("lead must be capped at %v: %v", maxOrderLead, p.slept)
	}
	a.BeforeOrder = func(RenewNotice) time.Duration { panic("boom") }
	before := atomic.LoadInt32(hits)
	obtain("c.example")
	if atomic.LoadInt32(hits) == before {
		t.Fatal("a panicking subscriber must not stop the order")
	}
	p = probeOrders(a, hits, time.Second)
	obtain("   ")
	if len(p.notices) != 0 || len(p.slept) != 0 {
		t.Fatalf("an order without a valid name must not be announced: %+v", p.notices)
	}
}

// Auto renew and "renew now" go through the same announcement; a stored DNS-01 certificate is reported as DNS-01.
func TestBeforeOrderFromAutoRenewAndRenewNow(t *testing.T) {
	h := newDBTestHandler(t)
	srv, hits := countingBrokenCA(t)
	r := &AutoRenewer{CertFolder: h.CertStorePath, AcmeHandler: h, EarlyRenewDays: 30, Logger: h.Logger,
		RenewerConfig: &AutoRenewConfig{Enabled: true, Email: "a@example.org", RenewAll: true}}
	writeCert(t, h.CertStorePath, "old", time.Now().Add(-time.Hour))
	if err := writeInfo(h.CertStorePath, "old", CertificateInfoJSON{AcmeName: "custom", AcmeUrl: srv.URL + "/dir", SkipTLS: true}); err != nil {
		t.Fatal(err)
	}
	p := probeOrders(h, hits, 3*time.Second)

	r.backgroundCheck() // scheduled run
	if len(p.notices) != 1 {
		t.Fatalf("auto renew must announce the order, got %+v", p.notices)
	}
	n := p.notices[0]
	if n.CertName != "old" || n.UseDNS || n.FirstIssue || len(n.Domains) != 1 || n.Domains[0] != "old.example.com" {
		t.Fatalf("bad auto renew notice: %+v", n)
	}
	if len(p.slept) != 1 || p.hitsAtNap[0] != 0 {
		t.Fatalf("auto renew must wait before the CA is contacted: %v %v", p.slept, p.hitsAtNap)
	}

	r.RenewOne("old") // the "renew now" button
	if len(p.notices) != 2 || len(p.slept) != 2 {
		t.Fatalf("renew now must announce the order too, got %+v", p.notices)
	}

	// stored DNS-01 setting wins over the argument, as in the order itself
	if err := writeInfo(h.CertStorePath, "old", CertificateInfoJSON{AcmeName: "custom", AcmeUrl: srv.URL + "/dir", SkipTLS: true, UseDNS: true}); err != nil {
		t.Fatal(err)
	}
	h.ObtainCertWithOptions([]string{"old.example.com"}, "old", "a@example.org", "custom", srv.URL+"/dir", true, false, 60, "", false, false, ObtainOptions{})
	if len(p.notices) != 3 || !p.notices[2].UseDNS || p.notices[2].FirstIssue {
		t.Fatalf("stored DNS-01 certificate must be announced as DNS-01: %+v", p.notices)
	}
}
