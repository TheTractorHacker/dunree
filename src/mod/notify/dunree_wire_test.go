package notify

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

/*
	Dunree rebrand: webhook headers are X-Dunree-Event / -Timestamp / -Signature. While the
	legacy names are on (default) the same values are also sent as X-Zoraxy-*, so a receiver
	written for Zoraxy keeps verifying: the header name is not part of the signed material. // legacy-compat
*/

func TestWebhookHeadersDunreeAndLegacy(t *testing.T) {
	defer wirecompat.SetEmitLegacy(true)
	if HeaderSignature != "X-Dunree-Signature" || HeaderTimestamp != "X-Dunree-Timestamp" || HeaderEvent != "X-Dunree-Event" ||
		LegacyHeaderSignature != "X-Zoraxy-Signature" || LegacyHeaderTimestamp != "X-Zoraxy-Timestamp" || LegacyHeaderEvent != "X-Zoraxy-Event" { // legacy-compat
		t.Fatal("webhook header names changed")
	}
	var got http.Header
	var body []byte
	srv, cfg := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		got = r.Header.Clone()
		w.WriteHeader(204)
	})
	s := &WebhookSink{Cfg: WebhookConfig{Name: "t", URL: srv.URL, Secret: "k3y", Enabled: true}, AllowPrivate: true, tlsConfig: cfg, Attempts: 1}

	if err := s.Deliver(context.Background(), Event{Event: EventTest}); err != nil {
		t.Fatal(err)
	}
	//A receiver that only knows the Zoraxy names verifies // legacy-compat
	if sig := got.Get(LegacyHeaderSignature); sig == "" || sig != Sign("k3y", got.Get(LegacyHeaderTimestamp), body) || got.Get(LegacyHeaderEvent) != EventTest {
		t.Fatalf("legacy receiver cannot verify: %v", got)
	}
	//And one that knows the Dunree names sees the same values
	for _, pair := range [][2]string{{HeaderSignature, LegacyHeaderSignature}, {HeaderTimestamp, LegacyHeaderTimestamp}, {HeaderEvent, LegacyHeaderEvent}} {
		if got.Get(pair[0]) == "" || got.Get(pair[0]) != got.Get(pair[1]) {
			t.Fatalf("%s and %s differ: %v", pair[0], pair[1], got)
		}
	}

	wirecompat.SetEmitLegacy(false)
	if err := s.Deliver(context.Background(), Event{Event: EventTest}); err != nil {
		t.Fatal(err)
	}
	if got.Get(HeaderSignature) != Sign("k3y", got.Get(HeaderTimestamp), body) || got.Get(HeaderEvent) != EventTest {
		t.Fatalf("Dunree headers with the switch off: %v", got)
	}
	for _, name := range []string{LegacyHeaderSignature, LegacyHeaderTimestamp, LegacyHeaderEvent} {
		if len(got.Values(name)) != 0 {
			t.Fatalf("%s is still sent with the switch off", name)
		}
	}
}
