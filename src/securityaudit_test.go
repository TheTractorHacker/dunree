package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/apitoken"
	"github.com/TheTractorHacker/dunree/mod/auth"
	"github.com/TheTractorHacker/dunree/mod/secaudit"
)

func useSecAudit(t *testing.T) (*secaudit.Logger, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "security_audit.log")
	l, err := secaudit.New(secaudit.Options{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	old, oldAuth := secAudit, requireAuth
	secAudit, requireAuth = l, false //-noauth: the actor is "admin"
	t.Cleanup(func() { secAudit, requireAuth = old, oldAuth })
	return l, p
}

func formPost(h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.168.5.5:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.50")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// API token create / revoke / delete went unaudited before: they are recorded with the
// token name and scope, and the clear text token (only ever in the response) never reaches
// the log nor the listing API.
func TestSecurityAuditAPITokenEvents(t *testing.T) {
	_, p := useSecAudit(t)
	tokens, err := apitoken.NewManager(&v1KV{m: map[string][]byte{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/apitoken/create", tokens.HandleCreate)
	mux.HandleFunc("/api/apitoken/revoke", tokens.HandleRevoke)
	mux.HandleFunc("/api/apitoken/delete", tokens.HandleDelete)
	h := secAuditWrap(mux)

	w := formPost(h, "/api/apitoken/create", url.Values{"name": {"ci-bot"}, "scope": {apitoken.ScopeReadWrite}, "cidrs": {"10.0.0.0/8"}})
	var created struct {
		Token string
		Info  struct{ ID string }
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	if len(created.Token) < 16 || created.Info.ID == "" {
		t.Fatalf("token not created: %s", w.Body.String())
	}
	formPost(h, "/api/apitoken/revoke", url.Values{"id": {created.Info.ID}})
	formPost(h, "/api/apitoken/delete", url.Values{"id": {created.Info.ID}})
	formPost(h, "/api/apitoken/delete", url.Values{"id": {"does-not-exist"}}) //fails: recorded as an error

	lr := httptest.NewRecorder()
	HandleSecurityAuditList(lr, httptest.NewRequest(http.MethodGet, "/api/security/audit/list?event=apitoken.*", nil))
	var out struct {
		Entries []secaudit.Entry
	}
	json.Unmarshal(lr.Body.Bytes(), &out)
	if len(out.Entries) != 4 {
		t.Fatalf("want 4 token events, got %d: %s", len(out.Entries), lr.Body.String())
	}
	got := []string{}
	for _, e := range out.Entries {
		got = append(got, e.Event+"/"+e.Outcome)
		if e.Actor != "admin" || e.IP != "192.168.5.5" {
			t.Errorf("actor/ip %q %q (the X-Forwarded-For value must not be used)", e.Actor, e.IP)
		}
	}
	want := []string{"apitoken.delete/error", "apitoken.delete/ok", "apitoken.revoke/ok", "apitoken.create/ok"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v, want %v", got, want)
	}
	if out.Entries[3].Target != "ci-bot" || out.Entries[3].Detail["scope"] != apitoken.ScopeReadWrite {
		t.Fatalf("create detail %+v", out.Entries[3])
	}
	disk, _ := os.ReadFile(p)
	for _, body := range []string{string(disk), lr.Body.String()} {
		if strings.Contains(body, created.Token) {
			t.Fatal("the token secret appears in the log or the listing")
		}
	}
	if strings.Contains(lr.Body.String(), `"hash"`) {
		t.Fatal("chain hashes are not part of the listing")
	}
}

// Changes made with a REST API token are attributed to the token.
func TestSecurityAuditRESTTokenActor(t *testing.T) {
	l, _ := useSecAudit(t)
	tokens, _ := apitoken.NewManager(&v1KV{m: map[string][]byte{}}, nil)
	stub := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) }
	read := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }
	h := newAPIv1Handler(tokens, v1Backend{ProxyList: read, ProxyAdd: stub, ProxyEdit: stub, ProxyDelete: stub, ProxyToggle: stub,
		AccessList: read, RedirectList: read, CertList: read, StatsSummary: read, WAF: read, StatsBlocked: read},
		func(next http.Handler) http.Handler { return next })
	rw, _, _ := tokens.Create("deploy-bot", apitoken.ScopeReadWrite, 0, nil)
	v1Do(h, "GET", "/api/v1/proxy-rules", rw, "")
	if rec := v1Do(h, "POST", "/api/v1/proxy-rules", rw, `{"rootname":"x.example.com","ep":"1.1.1.1:80","password":"pw-in-body"}`); rec.Code >= 400 {
		t.Fatalf("create: %d", rec.Code)
	}
	pg, _ := l.List(secaudit.Query{})
	if len(pg.Entries) != 1 || pg.Entries[0].Actor != "token deploy-bot" || pg.Entries[0].Event != "restapi.proxy-rules" || pg.Entries[0].Target != "x.example.com" {
		t.Fatalf("entries %+v", pg.Entries)
	}
	if b, _ := json.Marshal(pg); strings.Contains(string(b), "pw-in-body") {
		t.Fatal("secret from the JSON body in the listing")
	}
}

// The settings of the dual proxy plan are recorded with the changed values.
func TestSecurityAuditPhase2Settings(t *testing.T) {
	l, _ := useSecAudit(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"OK"`)) })
	h := secAuditWrap(ok)
	pem := "-----BEGIN CERTIFICATE-----\nMIIBabc\n-----END CERTIFICATE-----\n"
	formPost(h, "/api/deployrole/set", url.Values{"config": {`{"Role":"internal","PeerGate":true}`}})
	formPost(h, "/api/trustedproxy/add", url.Values{"cidr": {"10.1.0.0/16"}, "name": {"ext"}})
	formPost(h, "/api/adminallow/set", url.Values{"config": {`{"CIDRs":["10.0.5.0/24"]}`}})
	formPost(h, "/api/destguard/set", url.Values{"config": {`{"Restrict":true}`}})
	formPost(h, "/api/proxy/upstream/add", url.Values{"ep": {"site"}, "origin": {"10.0.0.2:8006"}, "tls": {"true"}, "cabundle": {pem}, "pins": {"sha256//AAAA"}})
	formPost(h, "/api/proxy/upstream/update", url.Values{"ep": {"site"}, "origin": {"10.0.0.2:8006"}, "payload": {`{"SkipCertValidations":true}`}})
	formPost(h, "/api/proxy/timeouts", url.Values{"readTimeout": {"30"}})
	formPost(h, "/api/waf/policy", url.Values{"mode": {"block"}})
	formPost(h, "/api/abuse/setConfig", url.Values{"enabled": {"true"}})
	formPost(h, "/api/blacklist/ip/add", url.Values{"ip": {"198.51.100.7"}})
	formPost(h, "/api/proxy/edit", url.Values{"rootname": {"site"}, "ratenum": {"50"}})
	formPost(h, "/api/conf/import", url.Values{})
	formPost(h, "/api/history/restore", url.Values{"id": {"abc"}})
	r := httptest.NewRequest(http.MethodGet, "/api/conf/export", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)

	have := map[string]secaudit.Entry{}
	pg, _ := l.List(secaudit.Query{Limit: 200})
	for _, e := range pg.Entries {
		have[e.Event] = e
	}
	for _, ev := range []string{"deployrole.set", "trustedproxy.add", "adminallow.set", "destguard.set", "upstream.tls.change", "proxy.timeouts",
		"waf.policy", "abuse.setconfig", "blacklist.ip.add", "ratelimit.change", "config.import", "config.history.restore", "config.export"} {
		if _, ok := have[ev]; !ok {
			t.Errorf("event %s not recorded (have %v)", ev, keys(have))
		}
	}
	if d := have["deployrole.set"].Detail["config"]; !strings.Contains(d, `"internal"`) {
		t.Errorf("role change detail %q", d)
	}
	if d := have["upstream.tls.change"].Detail; !strings.HasPrefix(d["cabundle"], "[PEM 1 certificate") || d["pins"] != "sha256//AAAA" {
		t.Errorf("tls detail %v", d)
	}
}

func keys(m map[string]secaudit.Entry) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A read-only (viewer) account cannot read the audit log, and a refused change is recorded as denied.
func TestSecurityAuditViewerAndDenied(t *testing.T) {
	if auth.ViewerAllowed("GET", "/api/security/audit/list") || auth.ViewerAllowed("GET", "/api/security/audit/verify") {
		t.Fatal("a viewer must not read the security audit log")
	}
	l, _ := useSecAudit(t)
	h := secAuditWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "403 - Read-only", http.StatusForbidden) }))
	formPost(h, "/api/trustedproxy/add", url.Values{"cidr": {"0.0.0.0/0"}})
	pg, _ := l.List(secaudit.Query{})
	if len(pg.Entries) != 1 || pg.Entries[0].Outcome != "denied" {
		t.Fatalf("%+v", pg.Entries)
	}
}

func TestSecurityAuditVerifyEndpoint(t *testing.T) {
	l, p := useSecAudit(t)
	l.Record(secaudit.Event{Actor: "a", Event: "x.one"})
	l.Record(secaudit.Event{Actor: "a", Event: "x.two"})
	get := func() map[string]any {
		w := httptest.NewRecorder()
		HandleSecurityAuditVerify(w, httptest.NewRequest(http.MethodGet, "/api/security/audit/verify", nil))
		var m map[string]any
		json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	if get()["ok"] != true {
		t.Fatal("fresh log must verify")
	}
	b, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(b, []byte("x.one"), []byte("x.uno"), 1), 0o600)
	if get()["ok"] != false {
		t.Fatal("tampering must be reported")
	}
}

// The audit log is never exported, and a configuration import neither replaces nor erases it.
func TestSecurityAuditSurvivesExportAndImport(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	logPath := filepath.Join(confDir, securityAuditFile)
	l, _ := secaudit.New(secaudit.Options{Path: logPath})
	l.Record(secaudit.Event{Actor: "root", Event: "config.export", Detail: map[string]string{"marker": "original-entry"}})
	os.WriteFile(logPath+".1", []byte("rotated-copy\n"), 0o600)

	w := httptest.NewRecorder()
	ExportConfigAsZip(w, httptest.NewRequest(http.MethodGet, "/api/conf/export", nil))
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.Contains(f.Name, securityAuditFile) {
			t.Fatalf("export contains %s", f.Name)
		}
	}

	// a hostile archive that tries to plant an audit log
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for name, body := range map[string]string{"conf/proxy/a.config": `{"RootOrMatchingDomain":"rule-new"}`, "conf/security_audit.log": `{"seq":1,"event":"forged"}` + "\n", "conf/security_audit.log.1": "forged\n"} {
		f, _ := zw.Create(name)
		f.Write([]byte(body))
	}
	zw.Close()
	if res := uploadZip(t, zb.Bytes()); res.Code != http.StatusOK {
		t.Fatalf("import: %d %s", res.Code, res.Body.String())
	}
	if b, _ := os.ReadFile(filepath.Join(confDir, "proxy", "a.config")); string(b) != `{"RootOrMatchingDomain":"rule-new"}` {
		t.Fatal("the import did not apply")
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "original-entry") || strings.Contains(string(b), "forged") {
		t.Fatalf("audit log after import: %q", b)
	}
	if b, _ := os.ReadFile(logPath + ".1"); string(b) != "rotated-copy\n" {
		t.Fatalf("rotated file after import: %q", b)
	}
	if v := l.Verify(); !v.OK {
		t.Fatalf("chain after import: %+v", v)
	}
}
