// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

// Hook commands get DUNREE_* always and ZORAXY_* while the legacy names are on (plan row 28).
func TestEventEnvDunreeAndLegacy(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	days := 3
	ev := Event{Event: "certificate.expiring", Domains: []string{"a.example", "b.example"}, Time: time.Unix(0, 0), DaysLeft: &days}

	wirecompat.SetEmitLegacy(true)
	env := strings.Join(EventEnv(ev), "\n")
	for _, want := range []string{"DUNREE_EVENT=certificate.expiring", "DUNREE_DOMAINS=a.example,b.example", "DUNREE_DAYS_LEFT=3", "DUNREE_EXPIRY=",
		"ZORAXY_EVENT=certificate.expiring", "ZORAXY_DOMAINS=a.example,b.example", "ZORAXY_DAYS_LEFT=3", "ZORAXY_EVENT_JSON={"} { // legacy-compat
		if !strings.Contains(env, want) {
			t.Errorf("legacy on: %s missing in\n%s", want, env)
		}
	}
	wirecompat.SetEmitLegacy(false)
	env = strings.Join(EventEnv(ev), "\n")
	if !strings.Contains(env, "DUNREE_EVENT_JSON={") || strings.Contains(env, "ZORAXY_") { // legacy-compat
		t.Errorf("legacy off:\n%s", env)
	}
}
