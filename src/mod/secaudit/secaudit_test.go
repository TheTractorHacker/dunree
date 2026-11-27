package secaudit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newLog(t *testing.T, maxBytes int64, maxFiles int) (*Logger, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "conf", "security_audit.log")
	l, err := New(Options{Path: p, MaxBytes: maxBytes, MaxFiles: maxFiles})
	if err != nil {
		t.Fatal(err)
	}
	return l, p
}

func allText(t *testing.T, p string) string {
	t.Helper()
	var sb strings.Builder
	matches, _ := filepath.Glob(p + "*")
	for _, m := range matches {
		b, _ := os.ReadFile(m)
		sb.Write(b)
	}
	return sb.String()
}

func actorOf(r *http.Request) (string, bool) {
	if c, err := r.Cookie("who"); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

func post(h http.Handler, path string, form url.Values, who string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "10.9.8.7:51234"
	if who != "" {
		r.AddCookie(&http.Cookie{Name: "who", Value: who})
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestActorAttributionAndSpoofing(t *testing.T) {
	l, _ := newLog(t, 0, 0)
	h := l.Middleware(actorOf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) }))

	post(h, "/api/trustedproxy/add", url.Values{"cidr": {"10.0.0.0/8"}}, "alice", map[string]string{
		"X-Forwarded-For": "6.6.6.6", "X-Real-IP": "7.7.7.7", "Forwarded": "for=8.8.8.8", "X-Actor": "mallory",
	})
	post(h, "/api/trustedproxy/add", url.Values{"cidr": {"1.2.3.0/24"}}, "", nil) //unauthenticated: not recorded
	pg, _ := l.List(Query{})
	if len(pg.Entries) != 1 {
		t.Fatalf("want exactly the authenticated request, got %d", len(pg.Entries))
	}
	e := pg.Entries[0]
	if e.Actor != "alice" || e.IP != "10.9.8.7" || e.Event != "trustedproxy.add" || e.Target != "10.0.0.0/8" || e.Outcome != "ok" {
		t.Fatalf("bad entry %+v", e)
	}
	if strings.Contains(allTextOf(pg), "6.6.6.6") {
		t.Fatal("a forwarded header leaked into the log as the source address")
	}
}

func allTextOf(p Page) string { return fmt.Sprintf("%+v", p.Entries) }

func TestOutcomeDeniedAndErrorBody(t *testing.T) {
	l, _ := newLog(t, 0, 0)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/adminallow/set", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"error":"would lock you out"}`)) })
	mux.HandleFunc("/api/deployrole/set", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) })
	mux.HandleFunc("/api/destguard/set", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) })
	h := l.Middleware(actorOf)(mux)
	for _, p := range []string{"/api/adminallow/set", "/api/deployrole/set", "/api/destguard/set"} {
		post(h, p, url.Values{"config": {`{"x":1}`}}, "bob", nil)
	}
	pg, _ := l.List(Query{})
	got := map[string]string{}
	for _, e := range pg.Entries {
		got[e.Event] = e.Outcome
	}
	if got["adminallow.set"] != "error" || got["deployrole.set"] != "denied" || got["destguard.set"] != "ok" {
		t.Fatalf("outcomes %v", got)
	}
}

func TestReadOnlyAndUnlistedRequestsNotRecorded(t *testing.T) {
	l, _ := newLog(t, 0, 0)
	h := l.Middleware(actorOf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	post(h, "/api/proxy/testupstream", url.Values{"ep": {"x"}}, "a", nil)
	post(h, "/api/stats/settings", url.Values{"a": {"b"}}, "a", nil)
	r := httptest.NewRequest(http.MethodGet, "/api/trustedproxy/list", nil)
	r.AddCookie(&http.Cookie{Name: "who", Value: "a"})
	h.ServeHTTP(httptest.NewRecorder(), r)
	if pg, _ := l.List(Query{}); len(pg.Entries) != 0 {
		t.Fatalf("recorded %d entries for read only / unlisted requests", len(pg.Entries))
	}
	//the configuration export is recorded for GET as well (it hands out secrets)
	r = httptest.NewRequest(http.MethodGet, "/api/conf/export?includeDB=true", nil)
	r.AddCookie(&http.Cookie{Name: "who", Value: "a"})
	h.ServeHTTP(httptest.NewRecorder(), r)
	if pg, _ := l.List(Query{Event: "config.*"}); len(pg.Entries) != 1 || pg.Entries[0].Event != "config.export" {
		t.Fatalf("export not recorded: %+v", pg.Entries)
	}
	//the generated keepalived file holds the VRRP password: reading it is recorded too
	r = httptest.NewRequest(http.MethodGet, "/api/cluster/vip/generate?member=1", nil)
	r.AddCookie(&http.Cookie{Name: "who", Value: "a"})
	h.ServeHTTP(httptest.NewRecorder(), r)
	pg, _ := l.List(Query{Event: "cluster.*"})
	if len(pg.Entries) != 1 || pg.Entries[0].Event != "cluster.vip.generate" || pg.Entries[0].Detail["member"] != "1" {
		t.Fatalf("vip generate read not recorded: %+v", pg.Entries)
	}
	if ev, ok := Classify("GET", "/api/cluster/vip/generate", nil); !ok || ev != "cluster.vip.generate" {
		t.Fatalf("classify GET generate: %q %v", ev, ok)
	}
	if _, ok := Classify("GET", "/api/cluster/vip/status", nil); ok {
		t.Fatal("status reads must stay unrecorded")
	}
}

func TestClassifyEvents(t *testing.T) {
	cases := []struct {
		path   string
		params map[string]string
		want   string
	}{
		{"/api/deployrole/set", nil, "deployrole.set"},
		{"/api/securityheaders/default", nil, "securityheaders.default"},
		{"/api/proxy/header/hardened", nil, "proxy.header.hardened"},
		{"/api/trustedproxy/remove", nil, "trustedproxy.remove"},
		{"/api/trustedproxy/bulkUpdate", nil, "trustedproxy.bulkupdate"},
		{"/api/blacklist/ip/add", nil, "blacklist.ip.add"},
		{"/api/access/update", nil, "access.update"},
		{"/api/adminallow/set", nil, "adminallow.set"},
		{"/api/destguard/set", nil, "destguard.set"},
		{"/api/waf/profile/save", nil, "waf.profile.save"},
		{"/api/abuse/setConfig", nil, "abuse.setconfig"},
		{"/api/apitoken/create", nil, "apitoken.create"},
		{"/api/apitoken/revoke", nil, "apitoken.revoke"},
		{"/api/apitoken/delete", nil, "apitoken.delete"},
		{"/api/conf/import", nil, "config.import"},
		{"/api/conf/export", nil, "config.export"},
		{"/api/history/restore", nil, "config.history.restore"},
		{"/api/proxy/upstream/add", map[string]string{"cabundle": "x"}, "upstream.tls.change"},
		{"/api/proxy/upstream/add", map[string]string{"tlsval": "true"}, "upstream.tls.change"},
		{"/api/proxy/upstream/update", map[string]string{"payload": `{"TLSPinsSHA256":["aa"]}`}, "upstream.tls.change"},
		{"/api/proxy/edit", map[string]string{"ratenum": "100"}, "ratelimit.change"},
		{"/api/proxy/timeouts", nil, "proxy.timeouts"},
		{"/api/proxy/edit", map[string]string{"maxRequestBodyBytes": "1"}, "proxy.edit"},
		{"/api/v1/proxy-rules/abc", nil, "restapi.proxy-rules"},
		{"/api/security/posture/apply", nil, "posture.apply"},
		{"/api/updater/start", nil, "updater"},
	}
	for _, c := range cases {
		got, ok := Classify("POST", c.path, c.params)
		if !ok || got != c.want {
			t.Errorf("%s %v: got %q ok=%v, want %q", c.path, c.params, got, ok, c.want)
		}
	}
	for _, p := range []string{"/api/auth/login", "/api/users/action", "/api/stats/settings", "/api/proxy/testupstream", "/api/info/x"} {
		if ev, ok := Classify("POST", p, nil); ok {
			t.Errorf("%s must not be classified, got %s", p, ev)
		}
	}
}

func TestRedaction(t *testing.T) {
	l, p := newLog(t, 0, 0)
	pem := "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
	priv := "-----BEGIN PRIVATE KEY-----\nMIIEsecretbytes\n-----END PRIVATE KEY-----\n"
	l.Record(Event{Actor: "a", Event: "x.test", Target: "https://u:hunter2@host/", Detail: map[string]string{
		"password":         "hunter2-password",
		"newPassword":      "hunter2-new",
		"token":            "tok-AAAA",
		"creds":            "user:hunter2",
		"csrft":            "n/a",
		"apiKey":           "key-1234",
		"captchaSecretKey": "cap-secret",
		"clientSecret":     "cs-secret",
		"cabundle":         pem,
		"privpem":          priv,
		"url":              "https://admin:hunter2@10.0.0.1:8006/x",
		"auth":             "Bearer abcdefghijklmnop",
		"payload":          `{"TLSCABundlePEM":"` + strings.ReplaceAll(pem, "\n", `\n`) + `","origin":"10.0.0.2","password":"hunter2","nested":{"apiToken":"zzz","ok":"fine"}}`,
		"note":             "line1\nline2\x00",
		"pins":             "sha256//AbCdEf",
	}})
	txt := allText(t, p)
	for _, secret := range []string{"hunter2", "tok-AAAA", "key-1234", "cap-secret", "cs-secret", "MIIEsecretbytes", "MIIBfake", "abcdefghijklmnop", "zzz"} {
		if strings.Contains(txt, secret) {
			t.Errorf("secret %q reached the log:\n%s", secret, txt)
		}
	}
	pg, _ := l.List(Query{})
	d := pg.Entries[0].Detail
	for _, never := range []string{"password", "newPassword", "token", "creds", "csrft", "apiKey", "clientSecret"} {
		if _, ok := d[never]; ok {
			t.Errorf("never-log field %s was stored", never)
		}
	}
	if d["captchaSecretKey"] != "[redacted]" {
		t.Errorf("secret named fields must keep the key and hide the value: %v", d)
	}
	if !strings.HasPrefix(d["cabundle"], "[PEM 1 certificate(s)") || d["privpem"] != "[redacted: private key material]" {
		t.Errorf("pem handling: %q / %q", d["cabundle"], d["privpem"])
	}
	if d["pins"] != "sha256//AbCdEf" || !strings.Contains(d["payload"], "10.0.0.2") || !strings.Contains(d["payload"], `"ok":"fine"`) {
		t.Errorf("harmless values must survive: %v", d)
	}
	if strings.ContainsAny(d["note"], "\n\x00") {
		t.Errorf("control characters kept: %q", d["note"])
	}
	if strings.Contains(pg.Entries[0].Target, "hunter2") {
		t.Error("target keeps a url password")
	}
}

func TestListingRedactsLinesWrittenElsewhere(t *testing.T) {
	l, p := newLog(t, 0, 0)
	l.Record(Event{Actor: "a", Event: "x.one"})
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":99,"ts":1,"actor":"old","event":"x.old","outcome":"ok","detail":{"password":"leak-me","apiToken":"leak-token","k":"ok"},"prev":"p","hash":"h"}` + "\n")
	f.Close()
	pg, _ := l.List(Query{})
	b := fmt.Sprintf("%+v", pg)
	if strings.Contains(b, "leak-me") || strings.Contains(b, "leak-token") {
		t.Fatalf("listing exposed a secret: %s", b)
	}
	if pg.Entries[0].Prev != "" || pg.Entries[0].Hash != "" {
		t.Fatal("chain values are not for the viewer")
	}
}

func TestRotationBoundedAndNewestKept(t *testing.T) {
	l, p := newLog(t, 2048, 3)
	const n = 200
	for i := 1; i <= n; i++ {
		l.Record(Event{Actor: "a", Event: "x.fill", Target: fmt.Sprintf("t%d", i), Detail: map[string]string{"pad": strings.Repeat("p", 40)}})
		if i == 1 || i == n {
			continue
		}
	}
	files, _ := filepath.Glob(p + "*")
	if len(files) != 3 {
		t.Fatalf("want 3 files kept, have %v", files)
	}
	var total int64
	for _, f := range files {
		fi, _ := os.Stat(f)
		total += fi.Size()
		if fi.Size() > 2048 {
			t.Errorf("%s is %d bytes, over the bound", f, fi.Size())
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	pg, _ := l.List(Query{Limit: 1})
	if pg.Entries[0].Target != fmt.Sprintf("t%d", n) {
		t.Fatalf("the newest entry must be there, got %s", pg.Entries[0].Target)
	}
	if l.Stats().Rotations == 0 {
		t.Fatal("never rotated")
	}
	if v := l.Verify(); !v.OK || v.Entries == 0 {
		t.Fatalf("chain across rotated files: %+v", v)
	}
	// reopening resumes the chain
	l2, _ := New(Options{Path: p, MaxBytes: 2048, MaxFiles: 3})
	l2.Record(Event{Actor: "a", Event: "x.after"})
	if v := l2.Verify(); !v.OK {
		t.Fatalf("chain broken after reopen: %+v", v)
	}
	pg, _ = l2.List(Query{Limit: 1})
	if pg.Entries[0].Seq != n+1 {
		t.Fatalf("seq after reopen %d", pg.Entries[0].Seq)
	}
}

func TestConcurrentRecordKeepsEverythingAndChain(t *testing.T) {
	l, _ := newLog(t, 1<<20, 3)
	var wg sync.WaitGroup
	const workers, each = 16, 50
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				l.Record(Event{Actor: fmt.Sprintf("w%d", w), Event: "x.race", Target: fmt.Sprint(i)})
			}
		}(w)
	}
	wg.Wait()
	pg, _ := l.List(Query{Limit: 200})
	_ = pg
	v := l.Verify()
	if !v.OK || v.Entries != workers*each {
		t.Fatalf("verify %+v, want %d entries", v, workers*each)
	}
	seen := map[uint64]bool{}
	var next uint64
	for {
		pg, _ := l.List(Query{Limit: 200, Before: next})
		for _, e := range pg.Entries {
			if seen[e.Seq] {
				t.Fatalf("duplicate seq %d", e.Seq)
			}
			seen[e.Seq] = true
		}
		if pg.Next == 0 {
			break
		}
		next = pg.Next
	}
	if len(seen) != workers*each {
		t.Fatalf("pagination saw %d entries", len(seen))
	}
}

func TestVerifyDetectsEditAndRemoval(t *testing.T) {
	l, p := newLog(t, 0, 0)
	for i := 0; i < 5; i++ {
		l.Record(Event{Actor: "a", Event: "x.v", Target: fmt.Sprint(i)})
	}
	orig, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")
	os.WriteFile(p, []byte(strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "\n")+"\n"), 0o600)
	if v := l.Verify(); v.OK {
		t.Fatal("a removed entry went unnoticed")
	}
	edited := strings.Replace(string(orig), `"actor":"a"`, `"actor":"b"`, 1)
	os.WriteFile(p, []byte(edited), 0o600)
	if v := l.Verify(); v.OK {
		t.Fatal("an edited entry went unnoticed")
	}
	os.WriteFile(p, orig, 0o600)
	if v := l.Verify(); !v.OK {
		t.Fatalf("untouched file must verify: %+v", v)
	}
}

func TestWriteFailureQueuesInsteadOfDropping(t *testing.T) {
	l, p := newLog(t, 0, 0)
	l.Record(Event{Actor: "a", Event: "x.first"})
	os.Remove(p)
	os.Mkdir(p, 0o700) //the file path is now a directory: every write fails
	l.Record(Event{Actor: "a", Event: "x.second"})
	l.Record(Event{Actor: "a", Event: "x.third"})
	if s := l.Stats(); s.Queued != 2 || s.WriteFailures == 0 {
		t.Fatalf("stats %+v", s)
	}
	os.Remove(p)
	l.Record(Event{Actor: "a", Event: "x.fourth"})
	pg, _ := l.List(Query{})
	if len(pg.Entries) != 3 || pg.Entries[0].Event != "x.fourth" || pg.Entries[2].Event != "x.second" {
		t.Fatalf("queued entries were not written in order: %+v", pg.Entries)
	}
	if s := l.Stats(); s.Queued != 0 || s.Dropped != 0 {
		t.Fatalf("stats %+v", s)
	}
	if v := l.Verify(); !v.OK {
		t.Fatalf("the chain must stay intact over the outage: %+v", v)
	}
}

func TestFilterByEventAndActor(t *testing.T) {
	l, _ := newLog(t, 0, 0)
	l.Record(Event{Actor: "a", Event: "trustedproxy.add"})
	l.Record(Event{Actor: "b", Event: "trustedproxy.remove"})
	l.Record(Event{Actor: "a", Event: "waf.policy"})
	if pg, _ := l.List(Query{Event: "trustedproxy.*"}); len(pg.Entries) != 2 {
		t.Fatalf("prefix filter: %d", len(pg.Entries))
	}
	if pg, _ := l.List(Query{Event: "waf.policy"}); len(pg.Entries) != 1 {
		t.Fatalf("exact filter: %d", len(pg.Entries))
	}
	if pg, _ := l.List(Query{Actor: "a"}); len(pg.Entries) != 2 {
		t.Fatalf("actor filter: %d", len(pg.Entries))
	}
	pg, _ := l.List(Query{Limit: 2})
	if len(pg.Entries) != 2 || pg.Next == 0 {
		t.Fatalf("pagination %+v", pg)
	}
	pg2, _ := l.List(Query{Limit: 2, Before: pg.Next})
	if len(pg2.Entries) != 1 || pg2.Next != 0 {
		t.Fatalf("second page %+v", pg2)
	}
}

func TestTokenLifecycleEventsNeverLogTheToken(t *testing.T) {
	l, p := newLog(t, 0, 0)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/apitoken/create", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"token":"zrx_SUPERSECRETTOKEN","info":{"id":"abc"}}`))
	})
	mux.HandleFunc("/api/apitoken/revoke", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) })
	mux.HandleFunc("/api/apitoken/delete", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) })
	h := l.Middleware(actorOf)(mux)
	post(h, "/api/apitoken/create", url.Values{"name": {"ci"}, "scope": {"write"}, "cidrs": {"10.0.0.0/8"}, "token": {"zrx_SUPERSECRETTOKEN"}}, "root", nil)
	post(h, "/api/apitoken/revoke", url.Values{"id": {"abc"}}, "root", nil)
	post(h, "/api/apitoken/delete", url.Values{"id": {"abc"}}, "root", nil)
	pg, _ := l.List(Query{Event: "apitoken.*"})
	if len(pg.Entries) != 3 {
		t.Fatalf("token events: %d", len(pg.Entries))
	}
	if pg.Entries[2].Target != "ci" || pg.Entries[2].Detail["scope"] != "write" {
		t.Fatalf("create entry %+v", pg.Entries[2])
	}
	if strings.Contains(allText(t, p), "SUPERSECRET") {
		t.Fatal("the token value reached the log")
	}
}

func TestJSONBodyParamsAreRedacted(t *testing.T) {
	l, p := newLog(t, 0, 0)
	h := l.Middleware(actorOf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		if !strings.Contains(string(b[:n]), "pw-json") {
			t.Error("the handler must still see the body")
		}
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/proxy-rules/x", strings.NewReader(`{"name":"x","password":"pw-json","upstream":"10.0.0.1"}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "who", Value: "tok1"})
	h.ServeHTTP(httptest.NewRecorder(), r)
	txt := allText(t, p)
	if strings.Contains(txt, "pw-json") || !strings.Contains(txt, "10.0.0.1") {
		t.Fatalf("json handling: %s", txt)
	}
}

func TestNilLoggerIsSafe(t *testing.T) {
	var l *Logger
	l.Record(Event{Event: "x"})
	if pg, err := l.List(Query{}); err != nil || len(pg.Entries) != 0 {
		t.Fatal("nil list")
	}
	h := l.Middleware(actorOf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	post(h, "/api/deployrole/set", url.Values{}, "a", nil)
}
