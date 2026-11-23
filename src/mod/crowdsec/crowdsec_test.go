package crowdsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "SUPERSECRETBOUNCERKEY0123456789"

type memKV struct {
	mu sync.Mutex
	m  map[string]Settings
}

func (k *memKV) Read(table, key string, a interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.m[table+"/"+key]
	if !ok {
		return fmt.Errorf("not found")
	}
	*(a.(*Settings)) = s
	return nil
}
func (k *memKV) Write(table, key string, v interface{}) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]Settings{}
	}
	k.m[table+"/"+key] = v.(Settings)
	return nil
}

// fakeLAPI is a stand-in for the documented LAPI endpoints
type fakeLAPI struct {
	mu       sync.Mutex
	key      string
	startup  string // answer for ?startup=true
	delta    string // answer for the delta call
	status   int    // when not 0: answer this status with a body that contains the key (must never be echoed anywhere)
	delay    time.Duration
	calls    []string
	gotKeys  []string
	lookup   string
	redirect string
	authCode int // answer for a wrong key (0 = 403)
	srv      *httptest.Server
}

func newFake(t *testing.T) *fakeLAPI {
	f := &fakeLAPI{key: testKey, startup: `{"new":null,"deleted":null}`, delta: `{"new":null,"deleted":null}`, lookup: "null"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.RequestURI())
	f.gotKeys = append(f.gotKeys, r.Header.Get("X-Api-Key"))
	status, delay, redirect := f.status, f.delay, f.redirect
	ok := r.Header.Get("X-Api-Key") == f.key
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	if !ok {
		code := 403
		f.mu.Lock()
		if f.authCode != 0 {
			code = f.authCode
		}
		f.mu.Unlock()
		w.WriteHeader(code)
		w.Write([]byte(`{"message":"access forbidden"}`))
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		w.Write([]byte("internal error, key was " + f.key))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/decisions/stream":
		if r.URL.Query().Get("startup") == "true" {
			w.Write([]byte(f.startup))
		} else {
			w.Write([]byte(f.delta))
		}
	case "/v1/decisions":
		w.Write([]byte(f.lookup))
	default:
		w.WriteHeader(404)
	}
}

func dec(id int, typ, scope, value, dur string) string {
	return fmt.Sprintf(`{"id":%d,"origin":"cscli","type":%q,"scope":%q,"value":%q,"duration":%q,"scenario":"manual 'ban' from 'x'"}`, id, typ, scope, value, dur)
}
func stream(newD, delD []string) string {
	j := func(l []string) string {
		if len(l) == 0 {
			return "null"
		}
		return "[" + strings.Join(l, ",") + "]"
	}
	return `{"deleted":` + j(delD) + `,"new":` + j(newD) + `}`
}

type tm struct {
	m     *Manager
	f     *fakeLAPI
	logs  *[]string
	clock *time.Time
	kv    *memKV
	dir   string
	apply func(Settings)
}

func setup(t *testing.T, mutate func(*Settings)) *tm {
	t.Helper()
	f := newFake(t)
	dir := t.TempDir()
	kv := &memKV{}
	m, err := New(kv, NewVault(dir))
	if err != nil {
		t.Fatal(err)
	}
	var logs []string
	var lm sync.Mutex
	m.Log = func(s string) { lm.Lock(); logs = append(logs, s); lm.Unlock() }
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	s := Settings{Enabled: true, LAPIURL: f.srv.URL, Mode: ModeEnforce}
	if mutate != nil {
		mutate(&s)
	}
	if err := m.Set(SetInput{Settings: s, APIKey: testKey, ConfirmFailClosed: true}); err != nil {
		t.Fatal(err)
	}
	return &tm{m: m, f: f, logs: &logs, clock: &clock, kv: kv, dir: dir}
}

func (x *tm) pull(t *testing.T) error {
	t.Helper()
	return x.m.PullOnce(context.Background())
}

// check asks for a verdict and reports it the way the request path does when it does exactly what the verdict says
func (x *tm) check(ip string) Verdict { return x.checkOn(ip, "site") }
func (x *tm) checkOn(ip, site string) Verdict {
	v := x.m.Check(netip.MustParseAddr(ip), site)
	x.m.Report(v, v.DefaultOutcome(), Event{Host: site, Method: "GET", Path: "/p?secret=1"})
	return v
}
func (x *tm) advance(d time.Duration) { *x.clock = x.clock.Add(d) }

func TestStartupThenDelta(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h"), dec(2, "ban", "Range", "198.51.100.0/24", "2h")}, []string{dec(99, "ban", "Ip", "203.0.113.50", "-1h")})
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	if !x.check("203.0.113.9").Enforce || !x.check("198.51.100.77").Enforce {
		t.Fatal("startup decisions not applied")
	}
	if x.check("203.0.113.10").Matched {
		t.Fatal("unrelated address matched")
	}
	//delta: add one, delete one
	x.f.delta = stream([]string{dec(3, "ban", "Ip", "192.0.2.5", "10m")}, []string{dec(1, "ban", "Ip", "203.0.113.9", "1h")})
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	if x.check("203.0.113.9").Matched {
		t.Fatal("deleted decision still enforced")
	}
	if !x.check("192.0.2.5").Matched {
		t.Fatal("delta decision missing")
	}
	x.f.mu.Lock()
	calls, keys := append([]string{}, x.f.calls...), append([]string{}, x.f.gotKeys...)
	x.f.mu.Unlock()
	if calls[0] != "/v1/decisions/stream?scopes=Ip%2CRange&startup=true" || calls[1] != "/v1/decisions/stream?scopes=Ip%2CRange" {
		t.Fatalf("calls %v: first must be startup=true, then a plain delta", calls)
	}
	for _, k := range keys {
		if k != testKey {
			t.Fatal("X-Api-Key not sent")
		}
	}
	st := x.m.Status()
	if st.State != "ok" || st.CacheSize != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestExpiryAndMaxTTL(t *testing.T) {
	x := setup(t, func(s *Settings) { s.MaxTTLSeconds = 3600 })
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "10m"), dec(2, "ban", "Ip", "203.0.113.10", "720h"), dec(3, "ban", "Ip", "203.0.113.11", "-5m"), dec(4, "ban", "Ip", "203.0.113.12", "3h59m57.641708614s")}, nil)
	x.pull(t)
	if x.check("203.0.113.11").Matched {
		t.Fatal("an already expired decision was cached")
	}
	x.advance(11 * time.Minute)
	if x.check("203.0.113.9").Matched {
		t.Fatal("expired decision enforced")
	}
	if !x.check("203.0.113.10").Matched {
		t.Fatal("decision gone too early")
	}
	x.advance(50 * time.Minute) //past the 1h max TTL, though the LAPI said 720h
	if x.check("203.0.113.10").Matched || x.check("203.0.113.12").Matched {
		t.Fatal("max TTL not applied")
	}
	if n := x.m.cache.Load().Sweep(x.m.now()); n == 0 {
		t.Fatal("sweep removed nothing")
	}
	if x.m.Status().CacheSize != 0 {
		t.Fatal("sweep did not empty the cache")
	}
}

func TestCacheCap(t *testing.T) {
	x := setup(t, func(s *Settings) { s.MaxEntries = 100 })
	var l []string
	for i := 0; i < 250; i++ {
		l = append(l, dec(i+1, "ban", "Ip", fmt.Sprintf("10.9.%d.%d", i/200, i%200+1), "1h"))
	}
	x.f.startup = stream(l, nil)
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	st := x.m.Status()
	if st.CacheSize != 100 || st.CacheRefused != 150 || st.State != "degraded" {
		t.Fatalf("hard cap not held: %+v", st)
	}
	if len(st.Warnings) == 0 {
		t.Fatal("no warning for a full cache")
	}
	//a settings value above the ceiling is refused
	s := Settings{Enabled: true, LAPIURL: x.f.srv.URL, MaxEntries: HardMaxEntries + 1}
	if s.Normalize() == nil {
		t.Fatal("cache size above the ceiling accepted")
	}
}

func TestRangesIPv6AndScopes(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{
		dec(1, "ban", "Range", "10.1.0.0/16", "1h"),
		dec(2, "ban", "Range", "2001:db8:abcd::/48", "1h"),
		dec(3, "ban", "Ip", "2001:db8::1", "1h"),
		dec(4, "ban", "Range", "0.0.0.0/0", "1h"), //would block everyone: refused
		dec(5, "ban", "Range", "::/0", "1h"),
		dec(6, "ban", "Country", "FR", "1h"),
		dec(7, "ban", "AS", "64500", "1h"),
		dec(8, "throttle", "Ip", "192.0.2.80", "1h"),
		dec(9, "ban", "Ip", "not-an-ip", "1h"),
		dec(10, "ban", "Ip", "192.0.2.81", "garbage"),
		dec(11, "captcha", "Ip", "192.0.2.82", "1h"),
		dec(12, "ban", "Range", "10.1.2.0/24", "1h"),
		dec(13, "captcha", "Ip", "10.1.2.3", "1h"), //ban (range) beats captcha
	}, nil)
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.0.1", "10.1.255.254", "2001:db8:abcd:1::7", "2001:db8::1", "::ffff:10.1.9.9"} {
		if v := x.check(ip); !v.Matched || v.Action != ActionBan {
			t.Errorf("%s not matched: %+v", ip, v)
		}
	}
	for _, ip := range []string{"10.2.0.1", "2001:db8::2", "192.0.2.80", "8.8.8.8", "2606:4700::1"} {
		if x.check(ip).Matched {
			t.Errorf("%s matched wrongly", ip)
		}
	}
	if v := x.check("10.1.2.3"); v.Action != ActionBan {
		t.Errorf("ban must win over captcha: %+v", v)
	}
	if v := x.check("192.0.2.82"); v.Action != ActionCaptcha || v.Enforce {
		t.Errorf("captcha is only logged by default: %+v", v)
	}
	st := x.m.Status()
	if st.IgnoredScopes["country"] != 1 || st.IgnoredScopes["as"] != 1 || st.IgnoredTypes["throttle"] != 1 {
		t.Errorf("ignored decisions not counted: %+v %+v", st.IgnoredScopes, st.IgnoredTypes)
	}
	if st.Malformed != 4 { //two /0 ranges, a bad address, a bad duration
		t.Errorf("malformed = %d", st.Malformed)
	}
}

func TestRangeDeleteAndLengths(t *testing.T) {
	c := NewCache(1000)
	exp := time.Now().Add(time.Hour)
	c.Add(Decision{ID: 1, Type: "ban", Scope: "Range", Value: "10.0.0.0/8", Expires: exp})
	c.Add(Decision{ID: 2, Type: "ban", Scope: "Range", Value: "10.0.5.0/24", Expires: exp})
	if _, ok := c.Lookup(netip.MustParseAddr("10.0.5.5"), time.Now()); !ok {
		t.Fatal("no match")
	}
	c.Delete("Range", "10.0.0.0/8", "ban", 1)
	if _, ok := c.Lookup(netip.MustParseAddr("10.7.5.5"), time.Now()); ok {
		t.Fatal("deleted /8 still matches")
	}
	if _, ok := c.Lookup(netip.MustParseAddr("10.0.5.5"), time.Now()); !ok {
		t.Fatal("remaining /24 lost")
	}
	c.Delete("Range", "10.0.5.0/24", "ban", 0)
	if c.Len() != 0 || c.lens4[8] != 0 || c.lens4[24] != 0 {
		t.Fatalf("bookkeeping wrong: n=%d", c.Len())
	}
	// a delete with another id leaves the decision alone
	c.Add(Decision{ID: 5, Type: "ban", Scope: "Ip", Value: "1.2.3.4", Expires: exp})
	c.Delete("Ip", "1.2.3.4", "ban", 6)
	if c.Len() != 1 {
		t.Fatal("delete with a different id removed the decision")
	}
}

func TestAuthFailure403(t *testing.T) {
	x := setup(t, nil)
	x.f.key = "another-key"
	err := x.pull(t)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("%v", err)
	}
	st := x.m.Status()
	if st.ConsecutiveErrors != 1 || st.State == "ok" {
		t.Fatalf("%+v", st)
	}
	found := false
	for _, w := range st.Warnings {
		if strings.Contains(w, "rejected the API key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no key warning: %v", st.Warnings)
	}
	tr := TestConnection(context.Background(), x.m.Settings(), testKey)
	if tr.OK || !strings.Contains(tr.Error, "403") {
		t.Fatalf("%+v", tr)
	}
}

func TestTimeoutKeepsOldCacheAndResyncs(t *testing.T) {
	old := deltaTimeout
	oldS := startupTimeout
	deltaTimeout, startupTimeout = 150*time.Millisecond, 150*time.Millisecond
	defer func() { deltaTimeout, startupTimeout = old, oldS }()
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	x.f.mu.Lock()
	x.f.delay = 600 * time.Millisecond
	x.f.mu.Unlock()
	if err := x.pull(t); err == nil {
		t.Fatal("slow LAPI did not time out")
	}
	if !x.check("203.0.113.9").Matched {
		t.Fatal("the cache was dropped on a timeout: it must keep serving")
	}
	x.f.mu.Lock()
	x.f.delay = 0
	x.f.mu.Unlock()
	x.f.startup = stream([]string{dec(2, "ban", "Ip", "203.0.113.20", "1h")}, nil)
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	x.f.mu.Lock()
	last := x.f.calls[len(x.f.calls)-1]
	x.f.mu.Unlock()
	if last != "/v1/decisions/stream?scopes=Ip%2CRange&startup=true" {
		t.Fatalf("after an error the next pull must be a full one, got %s", last)
	}
	if x.check("203.0.113.9").Matched || !x.check("203.0.113.20").Matched {
		t.Fatal("full resync must replace the cache")
	}
}

func TestMalformedJSON(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.pull(t)
	for _, bad := range []string{`not json`, `[]`, `{"new":{"a":1}}`, `{"new":[{"id":"x"}]}`, `{"new":[{"id":1,"type":"ban"}`, ``, `{"new":[1,2]}`, `{"new":[`} {
		x.f.mu.Lock()
		x.f.startup = bad
		x.f.mu.Unlock()
		x.m.resync.Store(true)
		if err := x.pull(t); err == nil {
			t.Errorf("accepted %q", bad)
		}
		if !x.check("203.0.113.9").Matched {
			t.Errorf("%q wiped the cache", bad)
		}
	}
	if x.m.Status().ConsecutiveErrors == 0 {
		t.Fatal("errors not counted")
	}
}

func TestLAPIDownFailOpenAndClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		closed     bool
		mode       string
		wantBlock  bool
		wantActive bool
	}{
		{"fail-open", false, ModeEnforce, false, false},
		{"fail-closed", true, ModeEnforce, true, true},
		{"fail-closed but log only", true, ModeLog, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := setup(t, func(s *Settings) { s.FailClosed, s.Mode, s.GraceSeconds = tc.closed, tc.mode, 60 })
			x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "24h")}, nil)
			if err := x.pull(t); err != nil {
				t.Fatal(err)
			}
			x.f.srv.Close() //LAPI goes away
			x.advance(30 * time.Second)
			if err := x.pull(t); err == nil {
				t.Fatal("pull against a closed server succeeded")
			}
			if v := x.check("198.51.100.1"); v.Matched {
				t.Fatalf("inside the grace period nobody may be refused: %+v", v)
			}
			if st := x.m.Status(); st.State != "degraded" {
				t.Fatalf("state %s inside the grace period", st.State)
			}
			x.advance(2 * time.Minute) //beyond the grace period
			v := x.check("198.51.100.1")
			if v.Matched != tc.wantBlock || v.Enforce != tc.wantBlock {
				t.Fatalf("beyond grace: %+v", v)
			}
			if tc.wantBlock && (v.Action != ActionClosed || !strings.Contains(v.Detail(), "fail-closed")) {
				t.Fatalf("%+v", v)
			}
			st := x.m.Status()
			if st.State != "down" || st.FailClosedActive != tc.wantActive {
				t.Fatalf("%+v", st)
			}
			if len(st.Warnings) == 0 {
				t.Fatal("no visible warning while down")
			}
			//cached decisions keep working in every mode
			if !x.check("203.0.113.9").Matched {
				t.Fatal("cached ban lost while the LAPI is down")
			}
			//never refused: loopback and protected addresses
			x.m.Protect = func(a netip.Addr) bool { return a == netip.MustParseAddr("198.51.100.1") }
			if x.check("198.51.100.1").Matched || x.check("127.0.0.1").Matched || x.check("::1").Matched {
				t.Fatal("protected or loopback address refused")
			}
		})
	}
}

func TestStartingGraceBeforeFirstSync(t *testing.T) {
	x := setup(t, func(s *Settings) { s.FailClosed, s.GraceSeconds = true, 60 })
	if v := x.check("198.51.100.1"); v.Matched {
		t.Fatal("fail-closed refused traffic before the grace period of a fresh start")
	}
	if x.m.Status().State != "starting" {
		t.Fatal(x.m.Status().State)
	}
	x.advance(2 * time.Minute)
	if !x.check("198.51.100.1").Matched {
		t.Fatal("never synchronised and past grace: fail-closed must apply")
	}
}

func TestLogOnlyNeverBlocksEnforceBlocks(t *testing.T) {
	x := setup(t, func(s *Settings) { s.Mode = "" }) //default
	if x.m.Settings().Mode != ModeLog {
		t.Fatal("first enabled mode must be log only")
	}
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.pull(t)
	v := x.check("203.0.113.9")
	if !v.Matched || v.Enforce {
		t.Fatalf("log only must match but not enforce: %+v", v)
	}
	st := x.m.Status()
	if st.LogOnly != 1 || st.Enforced != 0 {
		t.Fatalf("%+v", st)
	}
	_, matches := x.m.Decisions(10)
	if len(matches) != 1 || matches[0].Enforced || matches[0].IP != "203.0.113.9" {
		t.Fatalf("%+v", matches)
	}
	if len(*x.logs) == 0 {
		t.Fatal("log only mode logged nothing")
	}
	s := x.m.Settings()
	s.Mode = ModeEnforce
	if err := x.m.Set(SetInput{Settings: s}); err != nil {
		t.Fatal(err)
	}
	x.pull(t)
	if v := x.check("203.0.113.9"); !v.Enforce || v.Action != ActionBan {
		t.Fatalf("%+v", v)
	}
	// exempt site
	s.ExemptSites = []string{"Site"}
	x.m.Set(SetInput{Settings: s})
	if x.check("203.0.113.9").Matched {
		t.Fatal("exempt site still checked")
	}
	// disabled: nothing
	s.Enabled = false
	x.m.Set(SetInput{Settings: s})
	if x.check("203.0.113.9").Matched || x.m.Active() {
		t.Fatal("disabled integration matched")
	}
}

func TestCaptchaAction(t *testing.T) {
	x := setup(t, func(s *Settings) { s.CaptchaAction = CaptchaChallenge })
	x.f.startup = stream([]string{dec(1, "captcha", "Ip", "203.0.113.9", "1h")}, nil)
	x.pull(t)
	if v := x.check("203.0.113.9"); v.Action != ActionCaptcha || !v.Enforce {
		t.Fatalf("%+v", v)
	}
}

func TestKeyNeverLeaks(t *testing.T) {
	x := setup(t, nil)
	x.f.mu.Lock()
	x.f.status = 500 //the body of this answer contains the key
	x.f.mu.Unlock()
	if err := x.pull(t); err == nil {
		t.Fatal("500 accepted")
	}
	x.f.mu.Lock()
	x.f.status = 0
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.f.mu.Unlock()
	x.pull(t)
	x.check("203.0.113.9")
	tr := TestConnection(context.Background(), x.m.Settings(), testKey)
	if !tr.OK {
		t.Fatalf("%+v", tr)
	}
	// a transport error to a closed port must not contain the key either
	s := x.m.Settings()
	s.LAPIURL = "http://127.0.0.1:1"
	tr2 := TestConnection(context.Background(), s, testKey)
	if tr2.OK {
		t.Fatal("connected to a closed port")
	}
	recent, matches := x.m.Decisions(10)
	out := map[string]interface{}{"settings": x.m.Settings(), "status": x.m.Status(), "recent": recent, "matches": matches, "test": tr, "test2": tr2, "logs": *x.logs}
	js, _ := json.Marshal(out)
	if strings.Contains(string(js), testKey) || strings.Contains(strings.ToLower(string(js)), "supersecret") {
		t.Fatalf("API key found in output: %s", js)
	}
	if !x.m.Status().KeySet {
		t.Fatal("key set indicator missing")
	}
	// on disk: sealed, not plain, and excluded from exports
	var found bool
	filepath.Walk(x.dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), testKey) {
				t.Errorf("plain key in %s", p)
			}
			if i.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v", p, i.Mode().Perm())
			}
			found = true
		}
		return nil
	})
	if !found || !IsSecretFile("crowdsec/apikey.sealed") || !IsSecretFile("crowdsec/crowdsec.key") || IsSecretFile("crowdsec/other") {
		t.Fatal("vault files / export exclusion")
	}
	// the persisted settings hold no key
	kvjs, _ := json.Marshal(x.kv.m)
	if strings.Contains(string(kvjs), testKey) {
		t.Fatal("key in persisted settings")
	}
	// tampered vault is reported, key not revealed
	os.WriteFile(filepath.Join(x.dir, "apikey.sealed"), []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0o600)
	if err := x.pull(t); err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Fatalf("%v", err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	x := setup(t, nil)
	other := newFake(t)
	x.f.mu.Lock()
	x.f.redirect = other.srv.URL + "/v1/decisions/stream"
	x.f.mu.Unlock()
	if err := x.pull(t); err == nil {
		t.Fatal("a redirect was accepted")
	}
	other.mu.Lock()
	n := len(other.calls)
	other.mu.Unlock()
	if n != 0 {
		t.Fatal("the redirect target was contacted (with the API key)")
	}
}

func TestDestinationGuard(t *testing.T) {
	ctx := context.Background()
	for _, h := range []string{"169.254.169.254", "169.254.1.1", "fe80::1", "0.0.0.0", "224.0.0.1", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"} {
		if _, err := CheckLAPIAddr(ctx, h); err == nil {
			t.Errorf("%s accepted", h)
		}
	}
	for _, h := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.2", "::1", "203.0.113.4"} {
		if _, err := CheckLAPIAddr(ctx, h); err != nil {
			t.Errorf("%s refused: %v", h, err)
		}
	}
	x := setup(t, nil)
	s := x.m.Settings()
	s.LAPIURL = "http://169.254.169.254/latest"
	if err := x.m.Set(SetInput{Settings: s, APIKey: testKey}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("metadata LAPI accepted on save: %v", err)
	}
	if r := TestConnection(ctx, s, testKey); r.OK || r.Error == "" {
		t.Fatalf("metadata address contacted by the test: %+v", r)
	}
	// the dialer itself refuses it too (e.g. a name that resolves there)
	c, _ := NewClient(Settings{LAPIURL: "http://169.254.169.254"}, testKey, time.Second)
	if _, err := c.Lookup(ctx, "1.2.3.4"); err == nil {
		t.Fatal("dial to metadata address succeeded")
	}
}

func TestSettingsValidationAndPersistence(t *testing.T) {
	f := newFake(t)
	kv := &memKV{}
	dir := t.TempDir()
	m, _ := New(kv, NewVault(dir))
	good := Settings{Enabled: true, LAPIURL: f.srv.URL}
	// enabling without a key
	if err := m.Set(SetInput{Settings: good}); err == nil {
		t.Fatal("enabled without a key")
	}
	bad := []Settings{
		{LAPIURL: "ftp://x"}, {LAPIURL: "http://user:pw@127.0.0.1"}, {LAPIURL: "http://127.0.0.1?a=b"}, {LAPIURL: "http://"},
		{LAPIURL: "http://127.0.0.1", CABundlePEM: "x"}, {LAPIURL: "http://127.0.0.1", PinsSHA256: []string{strings.Repeat("ab", 32)}},
		{LAPIURL: "http://127.0.0.1", Mode: "block"}, {LAPIURL: "http://127.0.0.1", PollSeconds: 1}, {LAPIURL: "http://127.0.0.1", MaxTTLSeconds: 5},
		{LAPIURL: "http://127.0.0.1", GraceSeconds: 1}, {LAPIURL: "http://127.0.0.1", BanResponse: "x"}, {LAPIURL: "http://127.0.0.1", CaptchaAction: "x"},
		{Enabled: true},
	}
	for i, b := range bad {
		if err := m.Set(SetInput{Settings: b, APIKey: testKey}); err == nil {
			t.Errorf("bad settings %d accepted: %+v", i, b)
		}
	}
	for _, k := range []string{"has space", "new\nline", strings.Repeat("a", 600)} {
		if err := m.Set(SetInput{Settings: good, APIKey: k}); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
	if m.Active() || m.KeySet() {
		t.Fatal("a refused change left state behind")
	}
	// fail-closed needs the explicit confirm
	fc := good
	fc.FailClosed = true
	if err := m.Set(SetInput{Settings: fc, APIKey: testKey}); err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatalf("fail-closed without confirm: %v", err)
	}
	if err := m.Set(SetInput{Settings: fc, APIKey: testKey, ConfirmFailClosed: true}); err != nil {
		t.Fatal(err)
	}
	// already on: saving again needs no new confirm, but it can be switched off without one
	if err := m.Set(SetInput{Settings: fc}); err != nil {
		t.Fatal(err)
	}
	// cannot remove the key while enabled
	if err := m.Set(SetInput{Settings: fc, ClearKey: true}); err == nil {
		t.Fatal("key removed while enabled")
	}
	// restart: settings and key persist, mode is log only
	m2, err := New(kv, NewVault(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !m2.Active() || !m2.KeySet() || m2.Settings().Mode != ModeLog || !m2.Settings().FailClosed {
		t.Fatalf("not persisted: %+v", m2.Settings())
	}
	// old install: nothing stored = off
	m3, _ := New(&memKV{}, NewVault(t.TempDir()))
	if m3.Active() || m3.Settings().Enabled {
		t.Fatal("default must be off")
	}
	// a corrupt stored value leaves the feature off
	kv.m[DBTable+"/"+DBKey] = Settings{Enabled: true, LAPIURL: "gopher://x"}
	m4, err := New(kv, NewVault(dir))
	if err == nil || m4.Active() {
		t.Fatal("corrupt stored settings must be ignored")
	}
	// switch off and remove the key
	off := fc
	off.Enabled = false
	if err := m.Set(SetInput{Settings: off, ClearKey: true}); err != nil || m.KeySet() {
		t.Fatalf("%v", err)
	}
}

func TestHTTPSWithCAAndPin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != testKey {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte("null"))
	}))
	defer srv.Close()
	cert := srv.Certificate()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	ctx := context.Background()
	base := Settings{LAPIURL: srv.URL}
	if r := TestConnection(ctx, base, testKey); r.OK {
		t.Fatal("unknown CA accepted: there is no skip-verify")
	}
	withCA := base
	withCA.CABundlePEM = caPEM
	if r := TestConnection(ctx, withCA, testKey); !r.OK {
		t.Fatalf("custom CA: %+v", r)
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	withPin := withCA
	withPin.PinsSHA256 = []string{hex.EncodeToString(pin[:])}
	if r := TestConnection(ctx, withPin, testKey); !r.OK {
		t.Fatalf("right pin: %+v", r)
	}
	wrong := sha256.Sum256([]byte("other"))
	withPin.PinsSHA256 = []string{hex.EncodeToString(wrong[:])}
	if r := TestConnection(ctx, withPin, testKey); r.OK {
		t.Fatal("wrong pin accepted")
	}
}

func TestBackoff(t *testing.T) {
	prev := time.Duration(0)
	for n := 1; n < 20; n++ {
		d := Backoff(n)
		if d < prev || d > 120*time.Second || d < 2*time.Second {
			t.Fatalf("n=%d %v", n, d)
		}
		prev = d
	}
	if Backoff(1) != 2*time.Second || Backoff(30) != 120*time.Second {
		t.Fatal("bounds")
	}
}

func TestLoopSyncsAndStops(t *testing.T) {
	x := setup(t, func(s *Settings) { s.PollSeconds = 5 })
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.m.Start()
	defer x.m.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for !x.check("203.0.113.9").Matched {
		if time.Now().After(deadline) {
			t.Fatal("the loop never synchronised")
		}
		time.Sleep(20 * time.Millisecond)
	}
	x.m.Stop()
	x.m.Stop() //idempotent
}

func TestHeaderLikeInputsAreOnlyAddresses(t *testing.T) {
	// Check takes an address, never a string from a header; an invalid address matches nothing
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.pull(t)
	if v := x.m.Check(netip.Addr{}, "site"); v.Matched {
		t.Fatal("zero address matched")
	}
	if !x.m.Check(netip.MustParseAddr("::ffff:203.0.113.9"), "site").Matched {
		t.Fatal("IPv4-mapped form of a banned address evades the ban")
	}
}

// ---- review fixes ----

func (x *tm) startupCalls() int {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	n := 0
	for _, c := range x.f.calls {
		if strings.Contains(c, "startup=true") {
			n++
		}
	}
	return n
}

// A ban longer than the maximum lifetime must not lapse locally while the LAPI still holds it: deltas never repeat it,
// so a full synchronisation refreshes it at half the maximum lifetime.
func TestLongBanSurvivesViaPeriodicFullResync(t *testing.T) {
	x := setup(t, func(s *Settings) { s.MaxTTLSeconds = 3600 })
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.10", "720h"), dec(2, "ban", "Ip", "203.0.113.11", "10m")}, nil)
	if err := x.pull(t); err != nil {
		t.Fatal(err)
	}
	if x.m.Status().Clamped != 1 || len(x.m.Status().Warnings) == 0 {
		t.Fatalf("clamped decision not reported: %+v", x.m.Status())
	}
	base := x.startupCalls()
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.10", "700h")}, nil) //what the LAPI holds later: the short ban is gone
	for i := 0; i < 5; i++ {                                                         // 2h35m in steps of 31 min, no errors
		x.advance(31 * time.Minute)
		if err := x.pull(t); err != nil {
			t.Fatal(err)
		}
	}
	if !x.check("203.0.113.10").Matched {
		t.Fatal("the long ban lapsed locally while the LAPI still holds it (fail-open)")
	}
	if x.check("203.0.113.11").Matched {
		t.Fatal("a short ban outlived its duration")
	}
	if x.startupCalls() <= base {
		t.Fatal("no periodic full synchronisation")
	}
}

func TestNoPeriodicResyncWithoutClampedDecisions(t *testing.T) {
	x := setup(t, func(s *Settings) { s.MaxTTLSeconds = 3600 })
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.10", "10m")}, nil)
	x.pull(t)
	base := x.startupCalls()
	for i := 0; i < 4; i++ {
		x.advance(31 * time.Minute)
		x.pull(t)
	}
	if x.startupCalls() != base {
		t.Fatal("full synchronisation although nothing was cut")
	}
}

// A forwarded header may claim any address: a banned client must not hide behind loopback, this server or a clean address.
func TestCheckForwardedHeaderSpoofing(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.pull(t)
	x.m.Protect = func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.1") }
	ban := netip.MustParseAddr("203.0.113.9")
	for _, fake := range []string{"127.0.0.1", "::1", "192.0.2.1", "203.0.113.200", "::ffff:127.0.0.1"} {
		v := x.m.CheckForwarded([]netip.Addr{netip.MustParseAddr(fake), ban}, "site")
		if !v.Matched || !v.Enforce {
			t.Fatalf("banned client evaded with a claimed %s", fake)
		}
	}
	if v := x.m.CheckForwarded([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, "site"); v.Matched {
		t.Fatal("clean claimed address matched")
	}
	// the TCP peer exemptions still hold
	if x.m.Check(netip.MustParseAddr("127.0.0.1"), "site").Matched {
		t.Fatal("loopback peer checked")
	}
}

func TestUnknownClient(t *testing.T) {
	x := setup(t, func(s *Settings) { s.FailClosed = true; s.GraceSeconds = 60 })
	x.pull(t)
	if x.m.CheckUnknown("site").Matched {
		t.Fatal("unknown client refused while the LAPI is healthy")
	}
	x.f.status = 500
	x.advance(5 * time.Minute)
	x.pull(t)
	if v := x.m.CheckUnknown("site"); !v.Matched || v.Action != ActionClosed {
		t.Fatalf("unknown client admitted while failing closed: %+v", v)
	}
	if x.m.Status().UnknownClients != 2 {
		t.Fatalf("not counted: %+v", x.m.Status().UnknownClients)
	}
}

// The stored key goes only to the address it was entered for.
func TestStoredKeyBoundToLAPIAddress(t *testing.T) {
	x := setup(t, nil)
	var hits int
	var mu sync.Mutex
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		if r.Header.Get("X-Api-Key") != "" {
			t.Errorf("key leaked to another LAPI address")
		}
	}))
	defer evil.Close()
	cfg := x.m.Settings()
	cfg.LAPIURL = evil.URL
	tr := x.m.Test(context.Background(), &cfg, "")
	if tr.OK || tr.Error == "" {
		t.Fatalf("test against another address with the stored key was allowed: %+v", tr)
	}
	// same host, other port is another endpoint too
	cfg.LAPIURL = strings.Replace(x.f.srv.URL, "127.0.0.1:", "127.0.0.1:1", 1)
	if tr := x.m.Test(context.Background(), &cfg, ""); tr.OK {
		t.Fatal("other port accepted")
	}
	// Set with a changed address and no key is refused, nothing changes
	next := x.m.Settings()
	next.LAPIURL = evil.URL
	if err := x.m.Set(SetInput{Settings: next}); err == nil {
		t.Fatal("address changed without re-entering the key")
	}
	if x.m.Settings().LAPIURL != x.f.srv.URL {
		t.Fatal("settings changed on a refused Set")
	}
	// with the key typed again it works, and the old address no longer takes the stored key
	if err := x.m.Set(SetInput{Settings: next, APIKey: testKey}); err != nil {
		t.Fatal(err)
	}
	back := x.m.Settings()
	back.LAPIURL = x.f.srv.URL
	if err := x.m.Set(SetInput{Settings: back}); err == nil {
		t.Fatal("moving back without the key accepted")
	}
	// the unchanged address keeps working without re-entering the key
	same := x.m.Settings()
	same.Mode = ModeLog
	if err := x.m.Set(SetInput{Settings: same}); err != nil {
		t.Fatal(err)
	}
	// a key stored before bindings existed is bound to the saved address
	os.Remove(filepath.Join(x.dir, bindFileName))
	if tr := x.m.Test(context.Background(), &cfg, ""); tr.OK {
		t.Fatal("legacy key sent to another address")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("attacker server was contacted %d times", hits)
	}
}

func TestCacheFullLocalEvictsCommunityList(t *testing.T) {
	c := NewCache(100)
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 100; i++ {
		if c.Add(Decision{ID: int64(i + 1), Type: "ban", Scope: "ip", Value: fmt.Sprintf("10.1.0.%d", i+1), Origin: "CAPI", Expires: exp}) != addOK {
			t.Fatal("fill")
		}
	}
	if c.Add(Decision{ID: 500, Type: "ban", Scope: "ip", Value: "203.0.113.9", Origin: "CAPI", Expires: exp}) != addFull {
		t.Fatal("another list decision was stored in a full cache")
	}
	if c.Add(Decision{ID: 501, Type: "ban", Scope: "ip", Value: "203.0.113.9", Origin: "cscli", Expires: exp}) != addOK {
		t.Fatal("local decision refused although list decisions occupy the cache")
	}
	if _, ok := c.Lookup(netip.MustParseAddr("203.0.113.9"), time.Now()); !ok || c.Len() != 100 || c.Evicted() != 1 {
		t.Fatalf("len %d evicted %d", c.Len(), c.Evicted())
	}
	// range decisions evict too, and a cache of only local decisions stays refused
	if c.Add(Decision{ID: 502, Type: "ban", Scope: "range", Value: "198.18.0.0/16", Origin: "crowdsec", Expires: exp}) != addOK {
		t.Fatal("local range refused")
	}
	l := NewCache(100)
	for i := 0; i < 100; i++ {
		l.Add(Decision{ID: int64(i + 1), Type: "ban", Scope: "ip", Value: fmt.Sprintf("10.2.0.%d", i+1), Origin: "cscli", Expires: exp})
	}
	if l.Add(Decision{ID: 900, Type: "ban", Scope: "ip", Value: "10.3.0.1", Origin: "cscli", Expires: exp}) != addFull || l.Len() != 100 {
		t.Fatal("local decisions must not evict each other")
	}
}

// A deleted entry without id, or one listed after its replacement, must not remove the replacement.
func TestDeletedAfterNewKeepsReplacement(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.pull(t)
	x.f.delta = `{"new":[` + dec(2, "ban", "Ip", "203.0.113.9", "2h") + `],"deleted":[` + dec(0, "ban", "Ip", "203.0.113.9", "0s") + `]}`
	x.pull(t)
	if !x.check("203.0.113.9").Matched {
		t.Fatal("extended ban removed by a deleted entry without id that follows it")
	}
	// the old decision (id 1) is gone, the new one (id 2) remains
	x.f.delta = `{"new":[` + dec(3, "ban", "Ip", "203.0.113.20", "2h") + `],"deleted":[` + dec(3, "ban", "Ip", "203.0.113.20", "0s") + `]}`
	x.pull(t)
	if !x.check("203.0.113.20").Matched {
		t.Fatal("replacement listed as deleted in the same answer was removed")
	}
	// a plain delete still works
	x.f.delta = stream(nil, []string{dec(2, "ban", "Ip", "203.0.113.9", "0s")})
	x.pull(t)
	if x.check("203.0.113.9").Matched {
		t.Fatal("delete had no effect")
	}
}

func TestStreamAsksOnlyForEnforcedScopes(t *testing.T) {
	x := setup(t, nil)
	x.pull(t)
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	if len(x.f.calls) == 0 || !strings.Contains(x.f.calls[0], "scopes=Ip%2CRange") {
		t.Fatalf("calls %v", x.f.calls)
	}
}

func TestAuthFailure401(t *testing.T) {
	x := setup(t, nil)
	x.f.authCode = 401
	x.f.key = "other"
	if err := x.pull(t); !errors.Is(err, ErrAuth) {
		t.Fatalf("401 not treated as an auth failure: %v", err)
	}
}

func TestDecisionTextHasNoControlCharacters(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = `{"new":[{"id":1,"origin":"cs\r\nFAKE","type":"ban","scope":"Ip","value":"203.0.113.9","duration":"1h","scenario":"a\nCrowdSec: blocked 1.1.1.1\u001b[2J x"}],"deleted":null}`
	x.pull(t)
	v := x.check("203.0.113.9")
	if !v.Matched {
		t.Fatal("no match")
	}
	for _, f := range []string{v.Decision.Scenario, v.Decision.Origin, v.Detail()} {
		if strings.ContainsAny(f, "\r\n\x1b ") {
			t.Fatalf("control character survived: %q", f)
		}
	}
}

// Stop must cancel a pull that is in flight, not wait for it
func TestStopCancelsInFlightPull(t *testing.T) {
	x := setup(t, nil)
	x.f.delay = 4 * time.Second
	x.m.Start()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		x.f.mu.Lock()
		n := len(x.f.calls)
		x.f.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t0 := time.Now()
	x.m.Stop()
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("Stop took %v with a pull in flight", d)
	}
}

// A pull that started before a settings change must not land after it
func TestPullDoesNotOutliveSettingsChange(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.f.delay = 400 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- x.pull(t) }()
	time.Sleep(150 * time.Millisecond)
	off := x.m.Settings()
	off.Enabled = false
	if err := x.m.Set(SetInput{Settings: off}); err != nil {
		t.Fatal(err)
	}
	<-done
	if st := x.m.Status(); st.CacheSize != 0 {
		t.Fatalf("a pull refilled the cache of a disabled feature: %+v", st)
	}
	if rec, _ := x.m.Decisions(10); len(rec) != 0 {
		t.Fatal("recent decisions repopulated while disabled")
	}
	if x.check("203.0.113.9").Matched {
		t.Fatal("match while disabled")
	}
}

func TestOldPullDoesNotClearResyncAfterSettingsChange(t *testing.T) {
	x := setup(t, nil)
	x.f.startup = stream([]string{dec(1, "ban", "Ip", "203.0.113.9", "1h")}, nil)
	x.f.delay = 400 * time.Millisecond
	other := newFake(t)
	done := make(chan error, 1)
	go func() { done <- x.pull(t) }()
	time.Sleep(150 * time.Millisecond)
	next := x.m.Settings()
	next.LAPIURL = other.srv.URL
	if err := x.m.Set(SetInput{Settings: next, APIKey: testKey}); err != nil {
		t.Fatal(err)
	}
	<-done
	if !x.m.resync.Load() {
		t.Fatal("the old pull cleared the resync flag of the new LAPI")
	}
	if x.check("203.0.113.9").Matched {
		t.Fatal("old LAPI decisions installed after the change")
	}
}
