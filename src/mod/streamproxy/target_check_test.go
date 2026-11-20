package streamproxy_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/streamproxy"
)

func post(h http.HandlerFunc, form url.Values) string {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w.Body.String()
}

// Attack: a stream proxy target outside the allowed backend list (a way around the list for rule upstreams).
func TestStreamTargetCheck(t *testing.T) {
	lg, _ := logger.NewFmtLogger()
	mgr, err := streamproxy.NewStreamProxy(&streamproxy.Options{DefaultTimeout: 1, ConfigStore: t.TempDir(), Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	// no check installed: today's behaviour
	if out := post(mgr.HandleAddProxyConfig, url.Values{"name": {"a"}, "listenAddr": {"127.0.0.1:40101"}, "proxyAddr": {"169.254.169.254:80"}, "useTCP": {"true"}}); strings.Contains(out, "error") {
		t.Fatalf("refused with no check: %s", out)
	}
	mgr.TargetCheck = func(target string) error {
		if !strings.HasPrefix(target, "10.20.") {
			return errors.New(target + " is not in the allowed backend destinations")
		}
		return nil
	}
	n := len(mgr.Configs)
	out := post(mgr.HandleAddProxyConfig, url.Values{"name": {"b"}, "listenAddr": {"127.0.0.1:40102"}, "proxyAddr": {"192.0.2.7:22"}, "useTCP": {"true"}})
	if !strings.Contains(out, "allowed backend") || len(mgr.Configs) != n {
		t.Fatalf("add outside the list accepted: %s", out)
	}
	if out := post(mgr.HandleAddProxyConfig, url.Values{"name": {"c"}, "listenAddr": {"127.0.0.1:40103"}, "proxyAddr": {"10.20.0.5:22"}, "useTCP": {"true"}}); strings.Contains(out, "error") {
		t.Fatalf("add inside the list refused: %s", out)
	}
	// edit: moving the target outside is refused, an unrelated edit of the old (violating) config is not
	old := mgr.Configs[0]
	if out := post(mgr.HandleEditProxyConfigs, url.Values{"uuid": {old.UUID}, "proxyAddr": {"192.0.2.9:22"}}); !strings.Contains(out, "allowed backend") {
		t.Fatalf("edit to a target outside the list accepted: %s", out)
	}
	if old.ProxyTargetAddr != "169.254.169.254:80" {
		t.Fatalf("target changed despite refusal: %s", old.ProxyTargetAddr)
	}
	if out := post(mgr.HandleEditProxyConfigs, url.Values{"uuid": {old.UUID}, "name": {"renamed"}}); strings.Contains(out, "error") {
		t.Fatalf("unrelated edit refused: %s", out)
	}
}
