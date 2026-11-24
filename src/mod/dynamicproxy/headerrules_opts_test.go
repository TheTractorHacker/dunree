package dynamicproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

/*
	Options of the header rules added for the rest of upstream #1356: ANY mode, Negate,
	own status code, Strip and the address exceptions.
*/

func serveHeaderReq(router *Router, sep *ProxyEndpoint, path, remote string, h map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
	r.RemoteAddr = remote
	for k, v := range h {
		r.Header.Set(k, v)
	}
	router.handleNonTLSRequest(w, r, sep)
	return w
}

func TestHeaderRulesDefaultsUnchanged(t *testing.T) {
	// a rule stored before these options existed serialises without them and still means "all, 403, no strip"
	js, _ := json.Marshal(&ProxyEndpoint{HeaderRules: []*HeaderRule{{Name: "X-A", Values: []string{"a"}}}})
	for _, k := range []string{"Negate", "StatusCode", "Strip", "HeaderRulesMode", "HeaderRulesExcept"} {
		if strings.Contains(string(js), k) {
			t.Errorf("default configuration must not write %s", k)
		}
	}
	router, sep := withHeaderRules(t, &HeaderRule{Name: "X-A", Values: []string{"a"}}, &HeaderRule{Name: "X-B", Match: "present"})
	if sep.headerRulesAny || len(sep.headerExcept) != 0 {
		t.Fatal("ANY mode / exceptions must be off by default")
	}
	if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", map[string]string{"X-A": "a"}); w.Code != 403 {
		t.Fatalf("default mode must require every rule, got %d", w.Code)
	}
}

func TestHeaderRulesAnyMode(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.HeaderRules = []*HeaderRule{
		{Name: "X-Edge-Key", Values: []string{"k"}, Action: "notfound"},
		{Name: "X-Internal", Match: "present"},
		{Name: "X-Admin", Values: []string{"adm"}, PathPrefix: "/admin", StatusCode: 401},
	}
	sep.HeaderRulesMode = HeaderRulesModeAny
	sep.initHeaderRules()
	if sep.headerRulesErr != nil {
		t.Fatal(sep.headerRulesErr)
	}
	for _, c := range []struct {
		path string
		h    map[string]string
		want int
	}{
		{"/", nil, 404}, //nothing passes: the action of the first rule that applies
		{"/", map[string]string{"X-Edge-Key": "wrong"}, 404},
		{"/", map[string]string{"X-Edge-Key": "k"}, 299},
		{"/", map[string]string{"X-Internal": "1"}, 299},
		{"/", map[string]string{"X-Admin": "adm"}, 404}, //the /admin rule does not count outside its path
		{"/admin/x", map[string]string{"X-Admin": "adm"}, 299},
		{"/admin/x", map[string]string{"X-Internal": "1"}, 299},
		{"/admin/x", nil, 404},
	} {
		if w := serveHeaderReq(router, sep, c.path, "198.51.100.1:1", c.h); w.Code != c.want {
			t.Errorf("%s %v: got %d, want %d", c.path, c.h, w.Code, c.want)
		}
	}
	// only scoped rules: a path none of them covers is not checked at all
	sep.HeaderRules = sep.HeaderRules[2:]
	sep.initHeaderRules()
	if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", nil); w.Code != 299 {
		t.Fatalf("no rule applies to /: got %d", w.Code)
	}
	if w := serveHeaderReq(router, sep, "/admin", "198.51.100.1:1", nil); w.Code != 401 {
		t.Fatalf("own status of the scoped rule: got %d", w.Code)
	}
	// an unknown stored mode refuses requests, it does not fall back to "any"
	sep.HeaderRulesMode = "either"
	sep.initHeaderRules()
	if w := serveHeaderReq(router, sep, "/admin", "198.51.100.1:1", map[string]string{"X-Admin": "adm"}); w.Code != 503 {
		t.Fatalf("unknown mode must fail closed, got %d", w.Code)
	}
}

func TestHeaderRuleNegate(t *testing.T) {
	router, sep := withHeaderRules(t,
		&HeaderRule{Name: "X-Debug", Match: "present", Negate: true},
		&HeaderRule{Name: "X-Client", Values: []string{"banned-tool"}, Negate: true},
		&HeaderRule{Name: "X-Agent", Match: "regex", Values: []string{`scan.*`}, Negate: true},
	)
	for _, c := range []struct {
		h    map[string]string
		want int
	}{
		{nil, 299}, //absent headers pass every negated rule
		{map[string]string{"X-Debug": "1"}, 403},
		{map[string]string{"X-Client": "banned-tool"}, 403},
		{map[string]string{"X-Client": "fine"}, 299},
		{map[string]string{"X-Agent": "scanner/1"}, 403},
		{map[string]string{"X-Agent": "a scanner"}, 299}, //patterns match the whole value
	} {
		if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", c.h); w.Code != c.want {
			t.Errorf("%v: got %d, want %d", c.h, w.Code, c.want)
		}
	}
}

func TestHeaderRuleStatusCode(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 418, 429, 499, 503} {
		router, sep := withHeaderRules(t, &HeaderRule{Name: "X-Key", Values: []string{"super-secret"}, StatusCode: code})
		w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", map[string]string{"X-Key": "guess-123"})
		if w.Code != code {
			t.Errorf("status %d: got %d", code, w.Code)
		}
		if strings.Contains(w.Body.String(), "guess-123") || strings.Contains(w.Body.String(), "super-secret") {
			t.Errorf("status %d: value reflected in the answer", code)
		}
	}
	for i, r := range []*HeaderRule{
		{Name: "X-A", Values: []string{"a"}, StatusCode: 200},
		{Name: "X-A", Values: []string{"a"}, StatusCode: 302},
		{Name: "X-A", Values: []string{"a"}, StatusCode: 399},
		{Name: "X-A", Values: []string{"a"}, StatusCode: 500},
		{Name: "X-A", Values: []string{"a"}, StatusCode: 502},
		{Name: "X-A", Values: []string{"a"}, StatusCode: -403},
		{Name: "X-A", Values: []string{"a"}, StatusCode: 401, Action: "drop"},
		{Name: "X-A", Values: []string{"a"}, StatusCode: 401, Action: "notfound"},
	} {
		if err := ValidateHeaderRules([]*HeaderRule{r}); err == nil {
			t.Errorf("bad status rule %d accepted", i)
		}
	}
	// a stored rule with a status that is not allowed refuses requests instead of answering it
	router, sep, _ := newNonTLSTestRouter(t)
	sep.HeaderRules = []*HeaderRule{{Name: "X-A", Values: []string{"a"}, StatusCode: 200}}
	sep.initHeaderRules()
	if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", nil); w.Code != 503 {
		t.Fatalf("invalid stored status must fail closed, got %d", w.Code)
	}
}

func TestHeaderRuleStrip(t *testing.T) {
	router, sep := withHeaderRules(t,
		&HeaderRule{Name: "x-edge-key", Values: []string{"k"}, Strip: true},
		&HeaderRule{Name: "X-Keep", Match: "present"},
		&HeaderRule{Name: "X-Admin", Values: []string{"adm"}, PathPrefix: "/admin", Strip: true},
	)
	var seen http.Header
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
		seen = r.Header.Clone()
		w.WriteHeader(299)
		return true
	}
	h := map[string]string{"X-Edge-Key": "k", "X-Keep": "v", "X-Admin": "adm"}
	if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", h); w.Code != 299 {
		t.Fatalf("got %d", w.Code)
	}
	if seen.Get("X-Edge-Key") != "" {
		t.Error("the stripped header reached the next stage")
	}
	if seen.Get("X-Keep") != "v" {
		t.Error("a header without Strip was removed")
	}
	if seen.Get("X-Admin") != "adm" {
		t.Error("a rule outside its path scope must not strip")
	}
	if w := serveHeaderReq(router, sep, "/admin", "198.51.100.1:1", h); w.Code != 299 || seen.Get("X-Admin") != "" || seen.Get("X-Edge-Key") != "" {
		t.Errorf("inside the scope both headers are stripped: %d %v", w.Code, seen)
	}
}

func TestHeaderRulesExceptions(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.HeaderRules = []*HeaderRule{{Name: "X-Key", Values: []string{"k"}, Strip: true}}
	sep.HeaderRulesExcept = []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32", " "}
	sep.initHeaderRules()
	if sep.headerRulesErr != nil {
		t.Fatal(sep.headerRulesErr)
	}
	var seen http.Header
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
		seen = r.Header.Clone()
		w.WriteHeader(299)
		return true
	}
	for _, c := range []struct {
		remote string
		want   int
	}{
		{"10.1.2.3:500", 299},
		{"192.0.2.7:500", 299},
		{"[2001:db8::1]:500", 299},
		{"[::ffff:10.1.2.3]:500", 299}, //IPv4 mapped
		{"192.0.2.8:500", 403},
		{"11.0.0.1:500", 403},
		{"[2001:db9::1]:500", 403},
	} {
		if w := serveHeaderReq(router, sep, "/", c.remote, nil); w.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.remote, w.Code, c.want)
		}
	}
	// the default access rule does not trust proxy headers: a client cannot claim an excepted address
	if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", map[string]string{"X-Forwarded-For": "10.1.2.3", "X-Real-Ip": "10.1.2.3"}); w.Code != 403 {
		t.Fatalf("forged client address was believed, got %d", w.Code)
	}
	// an excepted client that sends the header anyway still has it stripped
	if w := serveHeaderReq(router, sep, "/", "10.1.2.3:500", map[string]string{"X-Key": "whatever"}); w.Code != 299 || seen.Get("X-Key") != "" {
		t.Fatalf("strip must apply to excepted clients: %d %v", w.Code, seen)
	}
	for i, ex := range [][]string{{"not-an-ip"}, {"10.0.0.0/33"}, {"0.0.0.0/0"}, {"::/0"}, make([]string, maxHeaderExcept+1)} {
		if i == 4 {
			for j := range ex {
				ex[j] = "10.0.0.1"
			}
		}
		if err := ValidateHeaderRuleSet(sep.HeaderRules, "", ex); err == nil {
			t.Errorf("bad exception list %d accepted", i)
		}
	}
	if err := ValidateHeaderRuleSet(sep.HeaderRules, "sometimes", nil); err == nil {
		t.Error("unknown mode accepted")
	}
	if err := ValidateHeaderRuleSet(sep.HeaderRules, HeaderRulesModeAny, []string{"10.0.0.0/8"}); err != nil {
		t.Error(err)
	}
	// an invalid stored list refuses requests, also for addresses that would have been excepted
	sep.HeaderRulesExcept = []string{"10.0.0.0/8", "bogus"}
	sep.initHeaderRules()
	if w := serveHeaderReq(router, sep, "/", "10.1.2.3:500", map[string]string{"X-Key": "k"}); w.Code != 503 {
		t.Fatalf("invalid exception list must fail closed, got %d", w.Code)
	}
}

func TestMaskHeaderRuleSecretsKeepsOptions(t *testing.T) {
	pe := &ProxyEndpoint{HeaderRules: []*HeaderRule{{Name: "X-Key", Values: []string{"s3cret"}, Negate: true, StatusCode: 401, Strip: true}}}
	cp := CopyEndpoint(pe)
	cp.MaskHeaderRuleSecrets()
	got := cp.HeaderRules[0]
	if got.Values[0] != "" || !got.Negate || got.StatusCode != 401 || !got.Strip {
		t.Fatalf("masked copy: %+v", got)
	}
}

// "Remove before forwarding" on a "be absent" rule is not a no-op: where the request is let in although it carries
// the header (an excepted address, or another rule passed in "at least one" mode), the header is taken off.
func TestHeaderRuleStripOnAbsentRule(t *testing.T) {
	router, sep := withHeaderRules(t, &HeaderRule{Name: "X-Debug", Match: HeaderMatchPresent, Negate: true, Strip: true}, &HeaderRule{Name: "X-A", Values: []string{"a"}})
	sep.HeaderRulesMode = HeaderRulesModeAny
	sep.initHeaderRules()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.Header.Set("X-Debug", "1")
	r.Header.Set("X-A", "a")
	if (&ProxyHandler{Parent: router}).handleHeaderRules(httptest.NewRecorder(), r, sep) || r.Header.Get("X-Debug") != "" || r.Header.Get("X-A") != "a" {
		t.Fatalf("at least one rule passed: the request must go on without X-Debug, headers %v", r.Header)
	}
}

// The exception list must not switch the check off for everybody, also not in several pieces
func TestHeaderRulesExceptCoversEverything(t *testing.T) {
	rules := []*HeaderRule{{Name: "X-A", Values: []string{"a"}}}
	for _, ex := range [][]string{
		{"0.0.0.0/1", "128.0.0.0/1"},
		{"128.0.0.0/1", "0.0.0.0/2", "64.0.0.0/3", "96.0.0.0/3"},
		{"::/1", "8000::/1"},
		{"10.0.0.0/8", "::ffff:0.0.0.0/97", "128.0.0.0/1"},
	} {
		if err := ValidateHeaderRuleSet(rules, "", ex); err == nil || !strings.Contains(err.Error(), "every") {
			t.Errorf("%v covers every address and must be refused, got %v", ex, err)
		}
		// hand-edited config: refuse requests, never open the site
		router, sep := withHeaderRules(t, rules[0])
		sep.HeaderRulesExcept = ex
		sep.initHeaderRules()
		if w := serveHeaderReq(router, sep, "/", "198.51.100.1:1", nil); w.Code != 503 {
			t.Errorf("%v in a stored config must answer 503, got %d", ex, w.Code)
		}
	}
	for _, ex := range [][]string{
		{"0.0.0.0/1"},
		{"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4"}, //240.0.0.0/4 is left
		{"::/1", "8000::/2"},
		{"0.0.0.0/1", "::/1"},
	} {
		if err := ValidateHeaderRuleSet(rules, "", ex); err != nil {
			t.Errorf("%v leaves addresses out and must be accepted: %v", ex, err)
		}
	}
}
