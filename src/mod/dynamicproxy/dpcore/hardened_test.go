package dpcore

import (
	"net/http"
	"testing"
)

func TestInjectHardenedHeaders(t *testing.T) {
	list := [][]string{{"X-Content-Type-Options", "nosniff"}, {"Content-Security-Policy", "frame-ancestors 'none'"}, {"", "x"}, {"Referrer-Policy", ""}, {"Short"}}

	h := http.Header{}
	injectHardenedHeaders(h, list, false)
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Security-Policy") != "frame-ancestors 'none'" {
		t.Errorf("missing headers not added: %v", h)
	}
	if len(h) != 2 {
		t.Errorf("malformed entries were applied: %v", h)
	}

	// existing values are kept without override
	h = http.Header{"X-Content-Type-Options": {"other"}, "Content-Security-Policy": {"default-src 'self'"}}
	injectHardenedHeaders(h, list, false)
	if h.Get("X-Content-Type-Options") != "other" || len(h.Values("Content-Security-Policy")) != 1 {
		t.Errorf("existing headers changed without override: %v", h)
	}

	// override replaces plain headers, adds (never rewrites) CSP, keeps an existing frame-ancestors
	h = http.Header{"X-Content-Type-Options": {"other"}, "Content-Security-Policy": {"default-src 'self'"}}
	injectHardenedHeaders(h, list, true)
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("override did not replace")
	}
	if v := h.Values("Content-Security-Policy"); len(v) != 2 || v[0] != "default-src 'self'" {
		t.Errorf("CSP: %v", v)
	}
	h = http.Header{"Content-Security-Policy": {"frame-ancestors https://partner.example"}}
	injectHardenedHeaders(h, list, true)
	if v := h.Values("Content-Security-Policy"); len(v) != 1 || v[0] != "frame-ancestors https://partner.example" {
		t.Errorf("existing frame-ancestors was touched: %v", v)
	}
}
