package notify

import (
	"strings"
	"testing"
)

func TestAuthDriftEventIsOptInAndDescribed(t *testing.T) {
	if !IsKnownEvent(EventAuthDrift) || !IsOptInEvent(EventAuthDrift) || SeverityOf(EventAuthDrift) != SevWarning {
		t.Fatal("auth.drift must be a known, opt-in, warning event")
	}
	title, lines := Describe(Event{Event: EventAuthDrift, Subject: "app.example.com", Extra: map[string]string{"tagged": "auth:oauth2", "method": "none"}})
	all := title + "\n" + strings.Join(lines, "\n")
	for _, want := range []string{"app.example.com", "auth:oauth2", "none", "open to everyone"} {
		if !strings.Contains(all, want) {
			t.Errorf("%q missing in %q", want, all)
		}
	}
	_, lines = Describe(Event{Event: EventAuthDrift, Subject: "a", Extra: map[string]string{"tagged": "auth:basic", "method": "forward"}})
	if strings.Contains(strings.Join(lines, "\n"), "open to everyone") {
		t.Error("a rule that still has a login is not open")
	}
}
