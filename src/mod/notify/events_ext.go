package notify

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

/*
Event catalogue (schema) of the notification centre.

Every event is a notify.Event (see event.go). Names are "<area>.<what>". The fields
used per event are listed below; anything else goes into Event.Extra (string values only).
Sources in other packages only need:

	notify.Emit(notify.Event{Event: notify.EventAutoBan, Source: "security",
		Subject: "203.0.113.7", Extra: map[string]string{"reason": "...", "duration": "1h"}})

Emit is safe to call before the notification centre is initialised (it is a no-op) and
never blocks.

Event             Severity  Source     Subject            Extra keys
uptime.down       critical  uptime     target name        url, status_code, failures
uptime.up         info      uptime     target name        url, downtime
certificate.issued          info     certificate  store name   (see event.go)
certificate.renewal_failed  critical certificate  store name   (see event.go)
certificate.expiring        warning  certificate  store name   (see event.go)
waf.spike         warning   waf        rule / host        blocks, window_seconds
security.autoban  warning   security   banned address     reason, duration, rule
cluster.node_offline  critical  cluster  node name         node_id, last_seen
cluster.node_online   info      cluster  node name         node_id
admin.login_failed    warning   auth     user name         ip
admin.login_new_ip    warning   auth     user name         ip
updater.available     info      updater  version tag       current, channel, url
visitor.new_country   info      visitors country code      ip, host   (off by default: needs "notify on new country" in the Visitors settings)
crowdsec.lapi_down    critical  crowdsec LAPI address      error, mode, fail_closed   (unreachable longer than the grace period; at most once in five minutes)
crowdsec.lapi_up      info      crowdsec LAPI address      mode                       (only after a crowdsec.lapi_down that was sent)
*/
const (
	EventUptimeDown        = "uptime.down"
	EventUptimeUp          = "uptime.up"
	EventWAFSpike          = "waf.spike"
	EventAutoBan           = "security.autoban"
	EventNodeOffline       = "cluster.node_offline"
	EventNodeOnline        = "cluster.node_online"
	EventAdminLoginFail    = "admin.login_failed"
	EventAdminLoginNew     = "admin.login_new_ip"
	EventUpdateAvail       = "updater.available"
	EventVisitorNewCountry = "visitor.new_country"
	EventDigest            = "notify.digest"
	EventCrowdSecDown      = "crowdsec.lapi_down" // same strings as crowdsec.NotifyDown / NotifyUp (mod/crowdsec does not import this package)
	EventCrowdSecUp        = "crowdsec.lapi_up"
)

// Severity levels, ordered
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"
)

// EventInfo describes one event type for the UI
type EventInfo struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	// OptIn events are only delivered to a destination that lists them; "no event selected = all" skips them
	OptIn bool `json:"optIn,omitempty"`
}

// Catalog lists every event the notification centre knows (certificate events included)
var Catalog = []EventInfo{
	{Name: EventUptimeDown, Severity: SevCritical, Title: "Upstream is down"},
	{Name: EventUptimeUp, Severity: SevInfo, Title: "Upstream recovered"},
	{Name: EventCertIssued, Severity: SevInfo, Title: "Certificate issued / renewed"},
	{Name: EventCertRenewFailed, Severity: SevCritical, Title: "Certificate renewal failed"},
	{Name: EventCertExpiring, Severity: SevWarning, Title: "Certificate expires soon"},
	{Name: EventCertRenewing, Severity: SevInfo, Title: "Certificate renewal about to start", OptIn: true},
	{Name: EventWAFSpike, Severity: SevWarning, Title: "WAF block spike"},
	{Name: EventAutoBan, Severity: SevWarning, Title: "Address banned automatically"},
	{Name: EventNodeOffline, Severity: SevCritical, Title: "Fleet node offline"},
	{Name: EventNodeOnline, Severity: SevInfo, Title: "Fleet node back online"},
	{Name: EventAdminLoginFail, Severity: SevWarning, Title: "Admin login failed"},
	{Name: EventAdminLoginNew, Severity: SevWarning, Title: "Admin login from a new address"},
	{Name: EventUpdateAvail, Severity: SevInfo, Title: "Update available"},
	{Name: EventVisitorNewCountry, Severity: SevInfo, Title: "First visitor from a new country"},
	{Name: EventCrowdSecDown, Severity: SevCritical, Title: "CrowdSec server unreachable"},
	{Name: EventCrowdSecUp, Severity: SevInfo, Title: "CrowdSec server reachable again"},
}

// AllEvents are the event names that can be subscribed to
func AllEvents() []string {
	out := make([]string, 0, len(Catalog))
	for _, c := range Catalog {
		out = append(out, c.Name)
	}
	return out
}

// IsKnownEvent reports whether name can be used in a subscription
func IsKnownEvent(name string) bool {
	for _, c := range Catalog {
		if c.Name == name {
			return true
		}
	}
	return false
}

// SeverityOf returns the severity of an event type (info for unknown ones)
func SeverityOf(name string) string {
	for _, c := range Catalog {
		if c.Name == name {
			return c.Severity
		}
	}
	return SevInfo
}

func sevRank(s string) int {
	switch s {
	case SevCritical:
		return 2
	case SevWarning:
		return 1
	}
	return 0
}

// ---- process wide entry point ----

var defaultManager atomic.Pointer[Manager]

// SetDefault installs the manager that the package level Emit uses
func SetDefault(m *Manager) { defaultManager.Store(m) }

// Emit sends an event through the default manager; a no-op until SetDefault was called.
// This is the stable entry point for event sources in other packages.
func Emit(ev Event) {
	if m := defaultManager.Load(); m != nil {
		m.Emit(ev)
	}
}

// ---- text rendering ----

// cleanText removes control characters and bounds the length of attacker influenced strings
func cleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
		if n >= max {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}

// Describe renders a human readable title and body for an event. It never includes secrets:
// events carry none, and channel configuration is not part of it.
func Describe(ev Event) (title string, lines []string) {
	subj := cleanText(ev.Subject, 120)
	x := func(k string) string { return cleanText(ev.Extra[k], 200) }
	switch ev.Event {
	case EventUptimeDown:
		title = "DOWN: " + subj
		lines = append(lines, "Upstream "+subj+" failed "+x("failures")+" consecutive health checks.")
		if x("url") != "" {
			lines = append(lines, "URL: "+x("url"))
		}
		if x("status_code") != "" {
			lines = append(lines, "Last status code: "+x("status_code"))
		}
	case EventUptimeUp:
		title = "RECOVERED: " + subj
		lines = append(lines, "Upstream "+subj+" is reachable again.")
		if x("downtime") != "" {
			lines = append(lines, "Downtime: "+x("downtime"))
		}
	case EventCertIssued:
		title = "Certificate issued: " + subj
	case EventCertRenewFailed:
		title = "Certificate renewal FAILED: " + subj
	case EventCertRenewing:
		title = "Certificate renewal starting: " + subj
		if x("method") != "" {
			lines = append(lines, "Challenge: "+x("method"))
		}
		if x("lead_seconds") != "" && x("lead_seconds") != "0" {
			lines = append(lines, "The ACME order starts in "+x("lead_seconds")+" seconds.")
		}
	case EventCertExpiring:
		title = "Certificate expiring: " + subj
		if ev.DaysLeft != nil {
			lines = append(lines, fmt.Sprintf("%d day(s) left", *ev.DaysLeft))
		}
	case EventWAFSpike:
		title = "WAF block spike: " + subj
		lines = append(lines, x("blocks")+" blocked requests in "+x("window_seconds")+" seconds.")
	case EventAutoBan:
		title = "Address banned: " + subj
		if x("reason") != "" {
			lines = append(lines, "Reason: "+x("reason"))
		}
		if x("duration") != "" {
			lines = append(lines, "Duration: "+x("duration"))
		}
	case EventNodeOffline:
		title = "Fleet node offline: " + subj
		if x("last_seen") != "" {
			lines = append(lines, "Last seen: "+x("last_seen"))
		}
	case EventNodeOnline:
		title = "Fleet node online: " + subj
	case EventCrowdSecDown:
		title = "CrowdSec server unreachable: " + subj
		if x("fail_closed") == "yes" {
			lines = append(lines, "Fail-closed is on: every visitor is refused until it is back.")
		} else {
			lines = append(lines, "Visitors are still served; only the decisions already in memory apply.")
		}
		if x("error") != "" {
			lines = append(lines, "Last error: "+x("error"))
		}
	case EventCrowdSecUp:
		title = "CrowdSec server reachable again: " + subj
	case EventAdminLoginFail:
		title = "Admin login failed: " + subj
		lines = append(lines, "From address: "+x("ip"))
	case EventAdminLoginNew:
		title = "Admin login from a new address: " + subj
		lines = append(lines, "From address: "+x("ip"))
	case EventVisitorNewCountry:
		title = "First visitor from a new country: " + subj
		lines = append(lines, "Address: "+cleanText(x("ip"), 64))
		if x("host") != "" {
			lines = append(lines, "Site: "+cleanText(x("host"), 120))
		}
	case EventUpdateAvail:
		title = "Dunree update available: " + subj
		if x("current") != "" {
			lines = append(lines, "Running: "+x("current"))
		}
		if x("url") != "" {
			lines = append(lines, x("url"))
		}
	case EventAuthDrift:
		title = "Login tag does not match the login: " + subj
		lines = append(lines, "Tagged: "+cleanText(x("tagged"), 200), "Login enforced now: "+x("method"))
		if x("method") == "none" {
			lines = append(lines, "The site is open to everyone although its tag names a login.")
		}
	case EventPosture:
		title = subj
		if x("detail") != "" {
			lines = append(lines, x("detail"))
		}
	case EventDigest:
		title = "Dunree digest: " + x("count") + " event(s)"
		for _, l := range strings.Split(ev.Extra["lines"], "\n") {
			if l != "" {
				lines = append(lines, cleanText(l, 200))
			}
		}
	case EventTest:
		title = "Dunree test notification"
		lines = append(lines, "If you can read this, the channel works.")
	default:
		title = cleanText(ev.Event, 80)
		if subj != "" {
			title += ": " + subj
		}
	}
	if ev.Error != "" {
		lines = append(lines, "Error: "+cleanText(ev.Error, 300))
	}
	if len(ev.Domains) > 0 && ev.Event != EventDigest {
		lines = append(lines, "Domains: "+cleanText(strings.Join(ev.Domains, ", "), 300))
	}
	return title, lines
}

// plain joins title and lines for channels with a single text field
func plain(ev Event) string {
	t, l := Describe(ev)
	if len(l) == 0 {
		return t
	}
	return t + "\n" + strings.Join(l, "\n")
}

func nowOr(f func() time.Time) time.Time {
	if f != nil {
		return f()
	}
	return time.Now()
}
