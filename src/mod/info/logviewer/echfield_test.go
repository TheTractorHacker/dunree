package logviewer

import "testing"

// Lines with the opt-in ECH field of the request log parse like the old ones, with the field on its own
func TestParseLineECHField(t *testing.T) {
	const head = "[2026-03-04 05:06:07.123456] [router:host-http] [origin:a.example] [client: 1.2.3.4] "
	e, ok := ParseLine(head + "[useragent: Mozilla/5.0 [odd] x] [ech: accepted outer=public.example] GET /p 200")
	if !ok || e.Agent != "Mozilla/5.0 [odd] x" || e.ECH != "accepted outer=public.example" || e.Method != "GET" || e.URI != "/p" || e.Status != 200 {
		t.Fatalf("with field: %+v ok=%v", e, ok)
	}
	e, ok = ParseLine(head + "[useragent: Mozilla/5.0 [odd] x] GET /p 404")
	if !ok || e.Agent != "Mozilla/5.0 [odd] x" || e.ECH != "" || e.Status != 404 {
		t.Fatalf("without field: %+v ok=%v", e, ok)
	}
	// a user agent that imitates the field does not replace the real one
	e, ok = ParseLine(head + "[useragent: x] [ech: accepted outer=evil] [ech: plain outer=real.example] GET /p 200")
	if !ok || e.ECH != "plain outer=real.example" || e.Agent != "x] [ech: accepted outer=evil" {
		t.Fatalf("spoofed field: %+v ok=%v", e, ok)
	}
	e, ok = ParseLine(`{"time":"2026-03-04T05:06:07Z","class":"c","site":"s","origin":"o","client":"::1","useragent":"u","method":"GET","uri":"/","status":200,"ech":"plain outer=o"}`)
	if !ok || e.ECH != "plain outer=o" {
		t.Fatalf("json: %+v", e)
	}
}
