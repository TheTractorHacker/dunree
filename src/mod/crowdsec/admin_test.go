package crowdsec

import (
	"context"
	"encoding/json"
	"io"
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

const (
	mID = "dunree-admin"
	mPW = "MACHINE-PASSWORD-0123456789"
)

// watcherLAPI is a stand-in for the documented watcher endpoints
type watcherLAPI struct {
	mu      sync.Mutex
	srv     *httptest.Server
	token   string
	logins  int
	expire  bool // answer 401 once to a bearer call
	alerts  string
	posted  []map[string]interface{}
	deleted []string
	gotAuth []string
	forbid  bool
	queries []string
}

func newWatcher(t *testing.T) *watcherLAPI {
	w := &watcherLAPI{token: "jwt-token-ABC"}
	w.alerts = `[{"id":7,"created_at":"2026-11-22T10:00:00Z","scenario":"crowdsecurity/ssh-bf","message":"ban on 203.0.113.5","events_count":6,` +
		`"source":{"scope":"Ip","value":"203.0.113.5","cn":"DE","as_name":"Example AS"},` +
		`"decisions":[{"id":41,"type":"ban","scope":"Ip","value":"203.0.113.5","duration":"3h59m","origin":"crowdsec","scenario":"crowdsecurity/ssh-bf"},` +
		`{"id":42,"type":"ban","scope":"Ip","value":"198.51.100.0/24","duration":"-5m","origin":"cscli","scenario":"old"}]},` +
		`{"id":8,"scenario":"manual","message":"x","source":{"scope":"Ip","value":"192.0.2.9"},` +
		`"decisions":[{"id":43,"type":"ban","scope":"Ip","value":"192.0.2.9","duration":"1h","origin":"cscli","scenario":"zoraxy/manual-ban"}]}]`
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.queries = append(w.queries, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/v1/watchers/login" {
			var b map[string]interface{}
			json.NewDecoder(r.Body).Decode(&b)
			if b["machine_id"] != mID || b["password"] != mPW {
				rw.WriteHeader(401)
				io.WriteString(rw, `{"message":"bad `+mPW+`"}`)
				return
			}
			w.logins++
			io.WriteString(rw, `{"code":200,"expire":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`","token":"`+w.token+`"}`)
			return
		}
		w.gotAuth = append(w.gotAuth, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer "+w.token {
			rw.WriteHeader(401)
			return
		}
		if w.expire {
			w.expire = false
			rw.WriteHeader(401)
			return
		}
		if w.forbid {
			rw.WriteHeader(403)
			return
		}
		switch {
		case r.URL.Path == "/v1/alerts" && r.Method == "GET":
			io.WriteString(rw, w.alerts)
		case r.URL.Path == "/v1/alerts" && r.Method == "POST":
			var b []map[string]interface{}
			json.NewDecoder(r.Body).Decode(&b)
			w.posted = append(w.posted, b...)
			io.WriteString(rw, `["99"]`)
		case strings.HasPrefix(r.URL.Path, "/v1/decisions/") && r.Method == "DELETE":
			w.deleted = append(w.deleted, r.URL.Path)
			io.WriteString(rw, `{"nbDeleted":"1"}`)
		default:
			rw.WriteHeader(404)
		}
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func adminMgr(t *testing.T, w *watcherLAPI) *Manager {
	t.Helper()
	m, err := New(&memKV{}, NewVault(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{LAPIURL: w.srv.URL}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	m.install(s)
	return m
}

func TestMachineLoginSealedAndBound(t *testing.T) {
	w := newWatcher(t)
	m := adminMgr(t, w)
	ctx := context.Background()
	if err := m.SetMachine(ctx, mID, "wrong"); err == nil || strings.Contains(err.Error(), mPW) || m.MachineSet() {
		t.Fatalf("wrong password accepted or leaked: %v", err)
	}
	if err := m.SetMachine(ctx, "bad id", mPW); err == nil {
		t.Fatal("id with a space accepted")
	}
	if err := m.SetMachine(ctx, mID, mPW); err != nil || !m.MachineSet() || m.MachineID() != mID {
		t.Fatalf("%v", err)
	}
	// sealed on disk: neither file holds the password
	for _, f := range []string{machineFileName, machineBindFile, keyFileName} {
		b, _ := readFile(m.vault.dir, f)
		if strings.Contains(string(b), mPW) {
			t.Fatalf("password in %s", f)
		}
	}
	if !IsSecretFile("crowdsec/" + machineFileName) {
		t.Fatal("machine file would be exported")
	}
	// bound to the address: another address is refused, nothing is sent
	other := newWatcher(t)
	s := Settings{LAPIURL: other.srv.URL}
	s.Normalize()
	m.install(s)
	if _, err := m.Alerts(ctx, "", 10); err == nil || !strings.Contains(err.Error(), "another LAPI address") {
		t.Fatalf("login sent to another address: %v", err)
	}
	if other.logins != 0 || len(other.queries) != 0 {
		t.Fatalf("other LAPI contacted: %v", other.queries)
	}
	// tampered file
	if err := writeFileAtomic(m.vault.dir+"/"+machineFileName, []byte("AAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.vault.Machine(); err != ErrTampered {
		t.Fatalf("tamper not detected: %v", err)
	}
	if err := m.ClearMachine(); err != nil || m.MachineSet() {
		t.Fatal("not cleared")
	}
	if _, err := m.Alerts(ctx, "", 10); err != ErrNoMachine {
		t.Fatalf("%v", err)
	}
}

func TestAdminReadsAndRelogin(t *testing.T) {
	w := newWatcher(t)
	m := adminMgr(t, w)
	ctx := context.Background()
	if err := m.SetMachine(ctx, mID, mPW); err != nil {
		t.Fatal(err)
	}
	dec, err := m.ActiveDecisions(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != 2 || dec[0].ID != 41 || dec[1].ID != 43 { // expired (-5m) decision dropped
		t.Fatalf("%+v", dec)
	}
	if dec, _ := m.ActiveDecisions(ctx, "MANUAL", 0); len(dec) != 1 || dec[0].ID != 43 {
		t.Fatalf("filter: %+v", dec)
	}
	logins := w.logins
	al, err := m.Alerts(ctx, "203.0.113.5", 10)
	if err != nil || len(al) != 2 || al[0].Country != "DE" || al[0].Events != 6 {
		t.Fatalf("%v %+v", err, al)
	}
	if !strings.Contains(w.queries[len(w.queries)-1], "ip=203.0.113.5") || !strings.Contains(w.queries[len(w.queries)-1], "limit=10") {
		t.Fatalf("%v", w.queries)
	}
	if _, err := m.Alerts(ctx, "not-an-ip", 10); err == nil {
		t.Fatal("bad ip accepted")
	}
	if w.logins != logins {
		t.Fatalf("token not reused: %d logins", w.logins-logins)
	}
	// token expired on the server: one new login, then success
	w.mu.Lock()
	w.expire = true
	w.mu.Unlock()
	if _, err := m.Alerts(ctx, "", 5); err != nil || w.logins != logins+1 {
		t.Fatalf("relogin: %v logins=%d", err, w.logins-logins)
	}
	// 403 never leaks anything
	w.mu.Lock()
	w.forbid = true
	w.mu.Unlock()
	if _, err := m.Alerts(ctx, "", 5); err == nil || strings.Contains(err.Error(), mPW) {
		t.Fatalf("%v", err)
	}
}

func TestBanAndUnban(t *testing.T) {
	w := newWatcher(t)
	m := adminMgr(t, w)
	ctx := context.Background()
	m.SetMachine(ctx, mID, mPW)
	admin := netip.MustParseAddr("10.1.0.99")
	m.Protect = func(a netip.Addr) bool { return a.String() == "10.1.0.25" }

	for _, tc := range []struct{ target, why string }{
		{"127.0.0.1", "loopback"}, {"0.0.0.0", "unspecified"}, {"224.0.0.1", "multicast"}, {"10.0.0.0/8", "wide v4"},
		{"2001:db8::/32", "wide v6"}, {"nonsense", "garbage"}, {"10.1.0.0/24", "contains the admin"}, {"10.1.0.99", "the admin"},
		{"10.1.0.25", "protected"},
	} {
		if _, _, err := m.Ban(ctx, tc.target, time.Hour, "", "root", admin); err == nil {
			t.Errorf("%s (%s) accepted", tc.target, tc.why)
		}
	}
	if len(w.posted) != 0 {
		t.Fatalf("a refused ban reached the LAPI: %v", w.posted)
	}
	scope, val, err := m.Ban(ctx, " 203.0.113.77 ", 4*time.Hour, "scanner\nwith newline", "alice", admin)
	if err != nil || scope != "Ip" || val != "203.0.113.77" {
		t.Fatalf("%v %s %s", err, scope, val)
	}
	if _, _, err := m.Ban(ctx, "198.51.100.0/24", 24*time.Hour, "", "alice", admin); err != nil {
		t.Fatal(err)
	}
	if len(w.posted) != 2 {
		t.Fatalf("%v", w.posted)
	}
	a := w.posted[0]
	d := a["decisions"].([]interface{})[0].(map[string]interface{})
	if a["scenario"] != ManualScenario || d["type"] != "ban" || d["value"] != "203.0.113.77" || d["scope"] != "Ip" || d["duration"] != "4h0m0s" ||
		d["origin"] != "cscli" || strings.ContainsAny(a["message"].(string), "\n") || !strings.Contains(a["message"].(string), "alice") {
		t.Fatalf("%v", a)
	}
	if d2 := w.posted[1]["decisions"].([]interface{})[0].(map[string]interface{}); d2["scope"] != "Range" || d2["value"] != "198.51.100.0/24" {
		t.Fatalf("%v", d2)
	}
	for _, h := range w.gotAuth {
		if h != "Bearer "+w.token {
			t.Fatalf("auth header %q", h)
		}
	}
	if err := m.Unban(ctx, 0); err == nil {
		t.Fatal("id 0")
	}
	if err := m.Unban(ctx, 41); err != nil || len(w.deleted) != 1 || w.deleted[0] != "/v1/decisions/41" {
		t.Fatalf("%v %v", err, w.deleted)
	}
}

func TestWriteRateLimit(t *testing.T) {
	w := newWatcher(t)
	m := adminMgr(t, w)
	ctx := context.Background()
	m.SetMachine(ctx, mID, mPW)
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	m.SetClockForTest(func() time.Time { return now })
	var refused int
	for i := 0; i < writesPerMin+5; i++ {
		if err := m.Unban(ctx, int64(100+i)); err != nil {
			refused++
		}
	}
	if refused != 5 {
		t.Fatalf("refused %d", refused)
	}
	now = now.Add(61 * time.Second)
	if err := m.Unban(ctx, 1); err != nil {
		t.Fatalf("window did not reset: %v", err)
	}
}

func TestBanDurationAndTarget(t *testing.T) {
	for in, want := range map[string]time.Duration{"30m": 30 * time.Minute, "4h": 4 * time.Hour, "7d": 168 * time.Hour, "2": 2 * time.Hour, "90M": 90 * time.Minute} {
		if d, err := ParseBanDuration(in); err != nil || d != want {
			t.Errorf("%s: %v %v", in, d, err)
		}
	}
	for _, in := range []string{"", "0", "30s", "31d", "-4h", "abc", "1d2h3", "99999999999999d"} {
		if _, err := ParseBanDuration(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if s, v, _, err := ParseBanTarget("192.0.2.0/24"); err != nil || s != "Range" || v != "192.0.2.0/24" {
		t.Fatalf("%v %s %s", err, s, v)
	}
	if s, v, _, err := ParseBanTarget("192.0.2.77/24"); err != nil || s != "Range" || v != "192.0.2.0/24" {
		t.Fatalf("not masked: %v %s %s", err, s, v)
	}
	if s, v, _, err := ParseBanTarget("::ffff:192.0.2.1"); err != nil || s != "Ip" || v != "192.0.2.1" {
		t.Fatalf("%v %s %s", err, s, v)
	}
	if s, _, _, err := ParseBanTarget("2001:db8:1::/48"); err != nil || s != "Range" {
		t.Fatalf("%v %s", err, s)
	}
}

func readFile(dir, name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) }
