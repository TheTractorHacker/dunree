package notify

import (
	"errors"
	"strconv"
	"time"
)

/*
	certificate.renewing (issue #178): announce an ACME order before it starts, so that an
	automation (webhook to a router, Home Assistant, ...) can open port 80 for the HTTP-01 challenge.

	  - opt-in only: a destination gets the event only when it lists it. "No event selected = all
	    events" does not include it, so existing webhooks, channels and the command hook see no change.
	  - optional lead time (RenewLeadSeconds, default 0): the issuer waits that long after the
	    announcement before an HTTP-01 order. DNS-01 orders are announced but never delayed.
	  - nothing is sent and nothing waits unless an enabled destination subscribed.
*/

// MaxRenewLeadSeconds bounds the lead time; the issuance lock is held while waiting.
const MaxRenewLeadSeconds = 600

// Challenge method names carried in Extra["method"]
const (
	MethodHTTP01 = "HTTP-01"
	MethodDNS01  = "DNS-01"
)

// IsOptInEvent reports whether an event is only delivered to destinations that list it explicitly.
func IsOptInEvent(name string) bool {
	for _, c := range Catalog {
		if c.Name == name {
			return c.OptIn
		}
	}
	return false
}

// OptInEvents lists the opt-in only event names (for the UI).
func OptInEvents() []string {
	out := []string{}
	for _, c := range Catalog {
		if c.OptIn {
			out = append(out, c.Name)
		}
	}
	return out
}

// RenewLead is the configured lead time.
func (m *Manager) RenewLead() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Duration(m.cfg.RenewLeadSeconds) * time.Second
}

// SetRenewLead stores the lead time in seconds (0 = no wait).
func (m *Manager) SetRenewLead(seconds int) error {
	if seconds < 0 || seconds > MaxRenewLeadSeconds {
		return errors.New("lead time must be between 0 and " + strconv.Itoa(MaxRenewLeadSeconds) + " seconds")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.RenewLeadSeconds = seconds
	return m.save()
}

// setOptionsAndLead is SetOptions plus an optional lead time (nil = keep), checked together and
// stored with one save, so that a refused value leaves every option as it was.
func (m *Manager) setOptionsAndLead(allowPrivate bool, warnDays int, lead *int) error {
	if warnDays < 0 || warnDays > 365 {
		return errors.New("warning days must be between 0 and 365")
	}
	if lead != nil && (*lead < 0 || *lead > MaxRenewLeadSeconds) {
		return errors.New("lead time must be between 0 and " + strconv.Itoa(MaxRenewLeadSeconds) + " seconds")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.AllowPrivateTargets = allowPrivate
	m.cfg.ExpiryWarnDays = warnDays
	if lead != nil {
		m.cfg.RenewLeadSeconds = *lead
	}
	return m.save()
}

// Subscribed reports whether at least one enabled destination wants the event.
func (m *Manager) Subscribed(eventType string) bool {
	for _, s := range m.sinks() {
		if s.Wants(eventType) {
			return true
		}
	}
	return false
}

// AnnounceRenewal emits certificate.renewing for an order that is about to start and returns how
// long the caller should wait before it contacts the CA. It returns 0 and emits nothing when no
// destination subscribed. method is MethodHTTP01 or MethodDNS01; only HTTP-01 orders are delayed.
// The deliveries run in the background (Emit never blocks); the caller does the waiting.
func (m *Manager) AnnounceRenewal(certName string, domains []string, ca string, method string, firstIssue bool) time.Duration {
	if m == nil || !m.Subscribed(EventCertRenewing) {
		return 0
	}
	lead := time.Duration(0)
	if method == MethodHTTP01 && !(m.offline != nil && m.offline()) {
		lead = m.RenewLead()
	}
	extra := map[string]string{
		"method":       method,
		"lead_seconds": strconv.Itoa(int(lead / time.Second)),
		"first_issue":  strconv.FormatBool(firstIssue),
	}
	m.Emit(Event{Event: EventCertRenewing, Source: "certificate", Subject: certName, Domains: domains, CA: ca, Extra: extra})
	return lead
}
