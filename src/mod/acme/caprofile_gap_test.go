package acme

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
	Issue #233 gap: registration email per CA profile, default CA profile, assigning a certificate
	without issuing it, importing the global CA settings, one ACME account per profile.

	fakeAccountCA is an in-process ACME directory that accepts account registrations and refuses
	every order. No real CA and no real network is used; what is covered is everything up to the order.
*/

type fakeAccountCA struct {
	srv *httptest.Server
	mu  sync.Mutex
	// one entry per newAccount request
	contacts [][]string
	eabKids  []string
	orders   int
}

func b64json(s string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func newFakeAccountCA(t *testing.T, eabRequired bool) *fakeAccountCA {
	f := &fakeAccountCA{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce%d", time.Now().UnixNano()))
		switch r.URL.Path {
		case "/dir":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order",
				"meta": map[string]any{"externalAccountRequired": eabRequired},
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/acct":
			body, _ := io.ReadAll(r.Body)
			var jws struct{ Payload string }
			json.Unmarshal(body, &jws)
			var payload struct {
				Contact                []string `json:"contact"`
				ExternalAccountBinding struct {
					Protected string `json:"protected"`
				} `json:"externalAccountBinding"`
			}
			b64json(jws.Payload, &payload)
			var eabHead struct {
				Kid string `json:"kid"`
			}
			if payload.ExternalAccountBinding.Protected != "" {
				b64json(payload.ExternalAccountBinding.Protected, &eabHead)
			}
			f.mu.Lock()
			f.contacts = append(f.contacts, payload.Contact)
			f.eabKids = append(f.eabKids, eabHead.Kid)
			n := len(f.contacts)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", fmt.Sprintf("%s/acct/%d", base, n))
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"status": "valid", "contact": payload.Contact})
		default:
			if r.URL.Path == "/order" {
				f.mu.Lock()
				f.orders++
				f.mu.Unlock()
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"fake CA refuses every order"}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAccountCA) dir() string { return f.srv.URL + "/dir" }

func (f *fakeAccountCA) accounts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.contacts)
}

func (f *fakeAccountCA) orderCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orders
}

func (f *fakeAccountCA) lastContact() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.contacts) == 0 {
		return ""
	}
	return strings.Join(f.contacts[len(f.contacts)-1], ",")
}

// order runs one issuance that gets as far as the (refused) order
func orderWith(t *testing.T, a *ACMEHandler, name, email, caName, caURL, profileID string) {
	t.Helper()
	ok, err := a.ObtainCertWithOptions([]string{name + ".example"}, name, email, caName, caURL, true, false, 60, "", false, false, ObtainOptions{CAProfileID: profileID})
	if ok || err == nil {
		t.Fatal("the fake CA must refuse the order")
	}
	if !strings.Contains(err.Error(), "fake CA refuses every order") {
		t.Fatalf("issuance must fail at the order, not before: %v", err)
	}
}

func mustSaveCA(t *testing.T, a *ACMEHandler, p CAProfile) string {
	t.Helper()
	id, err := a.SaveCAProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCAProfilesWithSameURLAndEmailDoNotShareAnAccount(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, false)
	idA := mustSaveCA(t, a, CAProfile{Name: "A", DirectoryURL: ca.dir(), SkipTLS: true})
	idB := mustSaveCA(t, a, CAProfile{Name: "B", DirectoryURL: ca.dir(), SkipTLS: true})

	orderWith(t, a, "one", "global@example.com", "", "", idA)
	if ca.accounts() != 1 || ca.lastContact() != "mailto:global@example.com" {
		t.Fatalf("profile A must register with the global email as fallback: %d %q", ca.accounts(), ca.lastContact())
	}
	orderWith(t, a, "one", "global@example.com", "", "", idA)
	if ca.accounts() != 1 {
		t.Fatalf("profile A must reuse its account, registrations: %d", ca.accounts())
	}
	orderWith(t, a, "two", "global@example.com", "", "", idB)
	if ca.accounts() != 2 {
		t.Fatalf("profile B has the same URL and email but must get its own account, registrations: %d", ca.accounts())
	}
	orderWith(t, a, "two", "global@example.com", "", "", idB)
	orderWith(t, a, "one", "global@example.com", "", "", idA)
	if ca.accounts() != 2 {
		t.Fatalf("both profiles must keep reusing their own account, registrations: %d", ca.accounts())
	}
}

func TestCAProfileRegistrationEmailWinsOverGlobalEmail(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, false)
	if _, err := a.SaveCAProfile(CAProfile{Name: "bad", DirectoryURL: ca.dir(), Email: "not an email"}); err == nil {
		t.Fatal("an invalid registration email must be refused")
	}
	id := mustSaveCA(t, a, CAProfile{Name: "own mail", DirectoryURL: ca.dir(), SkipTLS: true, Email: " pki@corp.example "})
	p, _ := a.GetCAProfile(id)
	if p.Email != "pki@corp.example" {
		t.Fatalf("the email must be stored trimmed: %q", p.Email)
	}
	orderWith(t, a, "one", "global@example.com", "", "", id)
	if ca.lastContact() != "mailto:pki@corp.example" {
		t.Fatalf("the profile email must be the account contact, got %q", ca.lastContact())
	}
	// without a profile the global email is used as before
	orderWith(t, a, "two", "global@example.com", "custom", ca.dir(), "")
	if ca.lastContact() != "mailto:global@example.com" {
		t.Fatalf("no profile: the global email must be used, got %q", ca.lastContact())
	}
	// an old profile record without the field still loads and falls back to the global email
	a.saveProfiles(prefCAProfiles, []map[string]any{{"id": "old1", "name": "old", "directoryURL": ca.dir(), "skipTLS": true}})
	orderWith(t, a, "three", "fallback@example.com", "", "", "old1")
	if ca.lastContact() != "mailto:fallback@example.com" {
		t.Fatalf("a profile without an email must fall back to the global one, got %q", ca.lastContact())
	}
}

func TestProfilesKeepSeparateEABBindings(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, true)
	hmac := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	idA := mustSaveCA(t, a, CAProfile{Name: "A", DirectoryURL: ca.dir(), SkipTLS: true, EABKid: "kid-A", EABHmac: hmac})
	idB := mustSaveCA(t, a, CAProfile{Name: "B", DirectoryURL: ca.dir(), SkipTLS: true, EABKid: "kid-B", EABHmac: hmac})
	orderWith(t, a, "one", "g@example.com", "", "", idA)
	orderWith(t, a, "two", "g@example.com", "", "", idB)
	ca.mu.Lock()
	kids := strings.Join(ca.eabKids, ",")
	ca.mu.Unlock()
	if kids != "kid-A,kid-B" {
		t.Fatalf("each profile must bind its own EAB key, registrations used: %q", kids)
	}
}

func TestExistingAccountGoesToExactlyOneProfile(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, false)
	// an account registered before profiles had their own: keyed by directory URL + email
	orderWith(t, a, "legacy", "g@example.com", "custom", ca.dir(), "")
	if ca.accounts() != 1 {
		t.Fatal("setup: one registration expected")
	}
	legacyKey := accountDBKey(ca.dir(), "g@example.com")
	var before json.RawMessage
	a.Database.Read(acmeAccountTable, legacyKey, &before)

	idA := mustSaveCA(t, a, CAProfile{Name: "A", DirectoryURL: ca.dir(), SkipTLS: true})
	idB := mustSaveCA(t, a, CAProfile{Name: "B", DirectoryURL: ca.dir(), SkipTLS: true})
	orderWith(t, a, "b", "g@example.com", "", "", idB)
	if ca.accounts() != 1 {
		t.Fatalf("the first profile must take over the existing account, not register again: %d", ca.accounts())
	}
	orderWith(t, a, "a", "g@example.com", "", "", idA)
	if ca.accounts() != 2 {
		t.Fatalf("the second profile must not share the account that was taken over: %d", ca.accounts())
	}
	// the historic entry is untouched and still serves issuance without a profile
	var after json.RawMessage
	a.Database.Read(acmeAccountTable, legacyKey, &after)
	if string(before) == "" || string(before) != string(after) {
		t.Fatal("the historic account entry must stay as it was")
	}
	orderWith(t, a, "legacy", "g@example.com", "custom", ca.dir(), "")
	orderWith(t, a, "b", "g@example.com", "", "", idB)
	orderWith(t, a, "a", "g@example.com", "", "", idA)
	if ca.accounts() != 2 {
		t.Fatalf("no further registration expected: %d", ca.accounts())
	}
	// the owner is deleted: a new profile may take the account over
	if err := a.DeleteCAProfile(idB); err != nil {
		t.Fatal(err)
	}
	idC := mustSaveCA(t, a, CAProfile{Name: "C", DirectoryURL: ca.dir(), SkipTLS: true})
	orderWith(t, a, "c", "g@example.com", "", "", idC)
	if ca.accounts() != 2 {
		t.Fatalf("a profile created after the owner was deleted must take the account over: %d", ca.accounts())
	}
}

func TestDefaultCAProfileIsOptInAndForNewCertificatesOnly(t *testing.T) {
	a := newDBTestHandler(t)
	idA := mustSaveCA(t, a, CAProfile{Name: "A", DirectoryURL: "https://a.example/dir"})
	idB := mustSaveCA(t, a, CAProfile{Name: "B", DirectoryURL: "https://b.example/dir"})
	if a.DefaultCAProfileID() != "" || a.resolveRequestCAProfile("", "fresh") != "" {
		t.Fatal("no default CA profile unless one is chosen")
	}
	if err := a.SetDefaultCAProfile("nope"); err == nil {
		t.Fatal("an unknown profile cannot be the default")
	}
	if err := a.SetDefaultCAProfile(idA); err != nil || a.DefaultCAProfileID() != idA {
		t.Fatalf("default not stored: %v", err)
	}
	// new certificate: default; explicit choices win
	if got := a.resolveRequestCAProfile("", "fresh"); got != idA {
		t.Fatalf("a new certificate must get the default profile, got %q", got)
	}
	if got := a.resolveRequestCAProfile(CAProfileNone, "fresh"); got != "" {
		t.Fatalf("an explicit 'none' must win over the default, got %q", got)
	}
	if got := a.resolveRequestCAProfile(idB, "fresh"); got != idB {
		t.Fatalf("an explicit profile must win over the default, got %q", got)
	}
	// existing certificates are never moved to the default
	writeCert(t, a.CertStorePath, "nometa", time.Now().Add(time.Hour))
	writeCert(t, a.CertStorePath, "le", time.Now().Add(time.Hour))
	writeInfo(a.CertStorePath, "le", CertificateInfoJSON{AcmeName: "Let's Encrypt", ManagedBy: "acme"})
	writeCert(t, a.CertStorePath, "onb", time.Now().Add(time.Hour))
	writeInfo(a.CertStorePath, "onb", CertificateInfoJSON{AcmeName: "custom", CAProfileID: idB})
	writeCert(t, a.CertStorePath, "gone", time.Now().Add(time.Hour))
	writeInfo(a.CertStorePath, "gone", CertificateInfoJSON{AcmeName: "custom", CAProfileID: "deleted"})
	for name, want := range map[string]string{"nometa": "", "le": "", "onb": idB, "gone": ""} {
		if got := a.resolveRequestCAProfile("", name); got != want {
			t.Errorf("existing certificate %s: profile %q, want %q", name, got, want)
		}
	}
	// deleting the default profile clears the setting
	if err := a.DeleteCAProfile(idA); err != nil || a.DefaultCAProfileID() != "" || a.prefGet(prefDefaultCA) != "" {
		t.Fatalf("deleting the default profile must clear the default: %v", err)
	}
	if err := a.SetDefaultCAProfile(idB); err != nil {
		t.Fatal(err)
	}
	if err := a.SetDefaultCAProfile(""); err != nil || a.DefaultCAProfileID() != "" {
		t.Fatal("the default must be clearable")
	}
}

func TestAssignCertificateToProfileWithoutReissuing(t *testing.T) {
	r, _ := newRenewer(t) // certificate "old", expired
	a := r.AcmeHandler
	a.beforeIssue = nil
	caOld, caNew := newFakeAccountCA(t, false), newFakeAccountCA(t, false)
	idOld := mustSaveCA(t, a, CAProfile{Name: "old CA", DirectoryURL: caOld.dir(), SkipTLS: true})
	idNew := mustSaveCA(t, a, CAProfile{Name: "new CA", DirectoryURL: caNew.dir(), SkipTLS: true, Email: "new@corp.example"})
	writeInfo(a.CertStorePath, "old", CertificateInfoJSON{AcmeName: "custom", AcmeUrl: caOld.dir(), SkipTLS: true, KeyType: "EC384", PropTimeout: 123, CAProfileID: idOld, ManagedBy: "acme", IssuedAt: 42})
	pemBefore, _ := os.ReadFile(filepath.Join(a.CertStorePath, "old.pem"))

	if err := a.AssignCertCAProfile("old", "missing"); err == nil {
		t.Fatal("an unknown profile must be refused")
	}
	if err := a.AssignCertCAProfile("nocert", idNew); err == nil {
		t.Fatal("an unknown certificate must be refused")
	}
	for _, bad := range []string{"", "../old", "a/b", ".hidden"} {
		if err := a.AssignCertCAProfile(bad, idNew); err == nil {
			t.Errorf("certificate name %q must be refused", bad)
		}
	}
	if err := a.AssignCertCAProfile("old", idNew); err != nil {
		t.Fatal(err)
	}
	if caOld.accounts()+caNew.accounts()+caOld.orderCount()+caNew.orderCount() != 0 {
		t.Fatal("assigning must not contact any CA")
	}
	pemAfter, _ := os.ReadFile(filepath.Join(a.CertStorePath, "old.pem"))
	if string(pemBefore) != string(pemAfter) {
		t.Fatal("assigning must not touch the certificate")
	}
	info, err := LoadCertInfoJSON(filepath.Join(a.CertStorePath, "old.json"))
	if err != nil || info.CAProfileID != idNew || info.KeyType != "EC384" || info.PropTimeout != 123 || info.IssuedAt != 42 || info.ManagedBy != "acme" {
		t.Fatalf("only the profile may change in the metadata: %+v (%v)", info, err)
	}

	// "Renew now" and the automatic renewal both go to the newly assigned profile, with its email
	if _, err := r.RenewOne("old"); err == nil {
		t.Fatal("the fake CA refuses the order")
	}
	if caNew.orderCount() != 1 || caOld.orderCount() != 0 || caNew.lastContact() != "mailto:new@corp.example" {
		t.Fatalf("Renew now must use the assigned profile: new %d old %d contact %q", caNew.orderCount(), caOld.orderCount(), caNew.lastContact())
	}
	r.CheckAndRenewCertificates()
	if caNew.orderCount() != 2 || caOld.orderCount() != 0 {
		t.Fatalf("auto renew must use the assigned profile: new %d old %d", caNew.orderCount(), caOld.orderCount())
	}

	// removing the assignment keeps the rest
	if err := a.AssignCertCAProfile("old", ""); err != nil {
		t.Fatal(err)
	}
	if info, _ := LoadCertInfoJSON(filepath.Join(a.CertStorePath, "old.json")); info.CAProfileID != "" || info.AcmeUrl != caOld.dir() {
		t.Fatalf("unassign must only clear the profile: %+v", info)
	}

	// a certificate without metadata is an upload: assigning must not turn it into an ACME certificate
	writeCert(t, a.CertStorePath, "plain", time.Now().Add(time.Hour))
	if err := a.AssignCertCAProfile("plain", idNew); !errors.Is(err, errNotIssuedByACME) {
		t.Fatalf("a certificate without metadata must be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.CertStorePath, "plain.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused assignment must not write metadata: %v", err)
	}
	writeCert(t, a.CertStorePath, "ext", time.Now().Add(time.Hour))
	writeInfo(a.CertStorePath, "ext", CertificateInfoJSON{ManagedBy: "mapdir", Source: "/x"})
	if err := a.AssignCertCAProfile("ext", idNew); !errors.Is(err, errExternallyManaged) {
		t.Fatalf("an externally managed certificate cannot be assigned, got %v", err)
	}

	// while a certificate is being issued the metadata is not rewritten
	a.issueMu.Lock()
	err = a.AssignCertCAProfile("old", idNew)
	a.issueMu.Unlock()
	if !errors.Is(err, errIssuanceRunning) {
		t.Fatalf("assigning during an issuance must be refused, got %v", err)
	}
}

func TestImportGlobalCASettingsAsProfile(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, false)
	if len(a.ListCAProfiles()) != 0 {
		t.Fatal("nothing is imported automatically")
	}
	if _, err := a.ImportGlobalCA("custom", "", false, "g@example.com"); err == nil {
		t.Fatal("a custom CA without URL cannot be imported")
	}
	if _, err := a.ImportGlobalCA("No Such CA", "", false, "g@example.com"); err == nil {
		t.Fatal("an unknown CA name cannot be imported")
	}

	// the global settings were in use: an account and EAB credentials exist for the directory
	orderWith(t, a, "legacy", "g@example.com", "custom", ca.dir(), "")
	a.Database.NewTable("acme")
	a.Database.Write("acme", ca.dir()+"_kid", "global-kid")
	a.Database.Write("acme", ca.dir()+"_hmacEncoded", "global-hmac")

	res, err := a.ImportGlobalCA("custom", ca.dir(), true, "g@example.com")
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.GetCAProfile(res.ID)
	if err != nil || p.DirectoryURL != ca.dir() || !p.SkipTLS || p.Email != "g@example.com" || p.EABKid != "global-kid" || p.EABHmac != "global-hmac" {
		t.Fatalf("imported profile is incomplete: %+v (%v)", p, err)
	}
	if !res.EABCopied || !res.AccountAdopted || res.Name != "Custom CA" {
		t.Fatalf("import result: %+v", res)
	}
	if a.DefaultCAProfileID() != "" {
		t.Fatal("the import must not make the profile the default")
	}
	// the profile reuses the existing account, another profile with the same URL and email does not
	orderWith(t, a, "viaprofile", "ignored@example.com", "", "", res.ID)
	if ca.accounts() != 1 {
		t.Fatalf("the imported profile must reuse the existing account: %d registrations", ca.accounts())
	}
	other := mustSaveCA(t, a, CAProfile{Name: "other", DirectoryURL: ca.dir(), SkipTLS: true, Email: "g@example.com"})
	orderWith(t, a, "viaother", "", "", "", other)
	if ca.accounts() != 2 {
		t.Fatalf("another profile must register its own account: %d registrations", ca.accounts())
	}
	// the global settings keep working and a second import is refused instead of duplicated
	orderWith(t, a, "legacy", "g@example.com", "custom", ca.dir(), "")
	if ca.accounts() != 2 {
		t.Fatal("the global settings must keep their account")
	}
	if _, err := a.ImportGlobalCA("custom", ca.dir(), true, "g@example.com"); err == nil || !strings.Contains(err.Error(), "already saved") {
		t.Fatalf("importing twice must be refused, got %v", err)
	}

	// a built-in CA resolves to its directory; a taken name gets a suffix
	mustSaveCA(t, a, CAProfile{Name: "Let's Encrypt", DirectoryURL: "https://taken.example/dir"})
	res2, err := a.ImportGlobalCA("", "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := loadCAApiServerFromName("Let's Encrypt", a.TestMode)
	p2, _ := a.GetCAProfile(res2.ID)
	if p2.DirectoryURL != want || res2.Name != "Let's Encrypt (2)" || p2.Email != "" || res2.AccountAdopted || res2.EABCopied {
		t.Fatalf("built-in import: %+v %+v", res2, p2)
	}
}

func postForm(h http.HandlerFunc, target string, form url.Values) map[string]any {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	out := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		out["raw"] = strings.TrimSpace(rec.Body.String())
	}
	return out
}

func TestCAProfileAPIEmailDefaultAndAssign(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, false)
	res := postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"save"}, "name": {"corp"}, "directoryURL": {ca.dir()}, "skipTLS": {"true"}, "email": {"pki@corp.example"}})
	id, _ := res["id"].(string)
	if id == "" {
		t.Fatalf("save failed: %v", res)
	}
	if r := postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"save"}, "name": {"x"}, "directoryURL": {ca.dir()}, "email": {"nope"}}); r["error"] == nil {
		t.Fatal("a bad email must be refused by the API")
	}

	list := func() map[string]any {
		rec := httptest.NewRecorder()
		a.HandleCAProfiles(rec, httptest.NewRequest(http.MethodGet, "/api/acme/profiles/ca", nil))
		out := map[string]any{}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	l := list()
	if l["default"] != "" || l["profiles"].([]any)[0].(map[string]any)["email"] != "pki@corp.example" {
		t.Fatalf("list must show the email and no default: %v", l)
	}
	if r := postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"setDefault"}, "id": {"nope"}}); r["error"] == nil {
		t.Fatal("unknown default must be refused")
	}
	postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"setDefault"}, "id": {id}})
	if list()["default"] != id {
		t.Fatal("setDefault not stored")
	}

	// a new certificate requested without email and without naming a profile: the default profile and
	// its registration email are used (the request reaches the CA and fails at the order)
	out := postForm(a.HandleRenewCertificate, "/api/acme/obtainCert", url.Values{"domains": {"new.example"}, "filename": {"new.example"}, "ca": {"Let's Encrypt"}})
	if e, _ := out["error"].(string); !strings.Contains(e, "fake CA refuses every order") {
		t.Fatalf("the default profile must be used for a new certificate: %v", out)
	}
	if ca.orderCount() != 1 || ca.lastContact() != "mailto:pki@corp.example" {
		t.Fatalf("order %d contact %q", ca.orderCount(), ca.lastContact())
	}
	// "none" keeps the CA of the request; without an email that is refused before any CA is contacted
	out = postForm(a.HandleRenewCertificate, "/api/acme/obtainCert", url.Values{"domains": {"other.example"}, "filename": {"other.example"}, "ca": {"custom"}, "caURL": {"https://127.0.0.1:1/dir"}, "caProfile": {CAProfileNone}})
	if e, _ := out["error"].(string); !strings.Contains(e, "email") || ca.orderCount() != 1 {
		t.Fatalf("explicit none without email must be refused for the missing email: %v", out)
	}
	postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"setDefault"}, "id": {""}})
	if list()["default"] != "" {
		t.Fatal("the default must be clearable through the API")
	}

	// assign through the API; a later request for that certificate that names no profile keeps it
	writeCert(t, a.CertStorePath, "site", time.Now().Add(time.Hour))
	writeInfo(a.CertStorePath, "site", CertificateInfoJSON{AcmeName: "Let's Encrypt", ManagedBy: "acme"})
	if r := postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"assign"}, "cert": {"site"}, "id": {"nope"}}); r["error"] == nil {
		t.Fatal("assign to an unknown profile must be refused")
	}
	if r := postForm(a.HandleCAProfiles, "/api/acme/profiles/ca", url.Values{"op": {"assign"}, "cert": {"site"}, "id": {id}}); r["error"] != nil {
		t.Fatalf("assign failed: %v", r)
	}
	if info, _ := LoadCertInfoJSON(filepath.Join(a.CertStorePath, "site.json")); info.CAProfileID != id {
		t.Fatalf("assignment not stored: %+v", info)
	}
	out = postForm(a.HandleRenewCertificate, "/api/acme/obtainCert", url.Values{"domains": {"site.example.com"}, "filename": {"site"}, "ca": {"Let's Encrypt"}})
	if e, _ := out["error"].(string); !strings.Contains(e, "fake CA refuses every order") || ca.orderCount() != 2 {
		t.Fatalf("a renewal request that names no profile must use the assigned one: %v (orders %d)", out, ca.orderCount())
	}
}

func TestRenewNowWithoutGlobalEmailNeedsAProfileEmail(t *testing.T) {
	r, _ := newRenewer(t)
	a := r.AcmeHandler
	a.beforeIssue = nil
	r.RenewerConfig.Email = ""
	ca := newFakeAccountCA(t, false)
	out := postForm(r.HandleRenewCertNow, "/api/acme/renewCert", url.Values{"cert": {"old"}})
	if e, _ := out["error"].(string); !strings.Contains(e, "email is not set") {
		t.Fatalf("no email anywhere must be refused: %v", out)
	}
	writeInfo(a.CertStorePath, "old", CertificateInfoJSON{AcmeName: "Let's Encrypt", ManagedBy: "acme"})
	noMail := mustSaveCA(t, a, CAProfile{Name: "no mail", DirectoryURL: ca.dir(), SkipTLS: true})
	if err := a.AssignCertCAProfile("old", noMail); err != nil {
		t.Fatal(err)
	}
	out = postForm(r.HandleRenewCertNow, "/api/acme/renewCert", url.Values{"cert": {"old"}})
	if e, _ := out["error"].(string); !strings.Contains(e, "email is not set") || ca.orderCount() != 0 {
		t.Fatalf("a profile without email does not replace the global email: %v", out)
	}
	withMail := mustSaveCA(t, a, CAProfile{Name: "mail", DirectoryURL: ca.dir(), SkipTLS: true, Email: "pki@corp.example"})
	if err := a.AssignCertCAProfile("old", withMail); err != nil {
		t.Fatal(err)
	}
	out = postForm(r.HandleRenewCertNow, "/api/acme/renewCert", url.Values{"cert": {"old"}})
	if ca.orderCount() != 1 || ca.lastContact() != "mailto:pki@corp.example" {
		t.Fatalf("the profile email must be enough for Renew now: %v (orders %d)", out, ca.orderCount())
	}
}

// Review finding: the skip-TLS flag of the previous CA stayed with the certificate after it was moved.
func TestReassignedCertificateVerifiesTLSOfTheNewProfile(t *testing.T) {
	r, _ := newRenewer(t) // certificate "old", expired
	a := r.AcmeHandler
	a.beforeIssue = nil
	private, public := newFakeAccountCA(t, false), newFakeAccountCA(t, false) // both self-signed httptest servers
	idPrivate := mustSaveCA(t, a, CAProfile{Name: "private CA", DirectoryURL: private.dir(), SkipTLS: true})
	idPublic := mustSaveCA(t, a, CAProfile{Name: "public CA", DirectoryURL: public.dir(), SkipTLS: false})
	writeInfo(a.CertStorePath, "old", CertificateInfoJSON{AcmeName: "custom", AcmeUrl: private.dir(), SkipTLS: true, CAProfileID: idPrivate, ManagedBy: "acme"})
	if err := a.AssignCertCAProfile("old", idPublic); err != nil {
		t.Fatal(err)
	}
	wantTLSFailure := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "fake CA refuses every order") {
			t.Fatalf("%s: the renewal must fail at TLS verification of the new CA, got %v", what, err)
		}
		if public.accounts() != 0 || public.orderCount() != 0 || private.orderCount() != 0 {
			t.Fatalf("%s: no CA may be talked to without verification: accounts %d orders %d / %d", what, public.accounts(), public.orderCount(), private.orderCount())
		}
	}
	_, err := r.RenewOne("old")
	wantTLSFailure("Renew now", err)
	r.CheckAndRenewCertificates()
	if public.accounts() != 0 || public.orderCount() != 0 {
		t.Fatal("auto renew talked to the new CA without verifying TLS")
	}
	// a request that names the profile cannot switch verification off either
	_, err = a.ObtainCertWithOptions([]string{"old.example"}, "old", "g@example.com", "", "", true, false, 60, "", false, false, ObtainOptions{CAProfileID: idPublic})
	wantTLSFailure("request with skipTLS", err)
	// the profile that says "ignore TLS errors" still works with a stored flag of false
	writeInfo(a.CertStorePath, "old", CertificateInfoJSON{AcmeName: "Let's Encrypt", SkipTLS: false, CAProfileID: idPrivate, ManagedBy: "acme"})
	if _, err := r.RenewOne("old"); err == nil || !strings.Contains(err.Error(), "fake CA refuses every order") {
		t.Fatalf("a profile with skip TLS must reach its CA: %v", err)
	}
}

// Review finding: the ACME "profile" name of the previous CA was sent to the new one.
func TestAssignClearsTheACMEProfileNameOfThePreviousCA(t *testing.T) {
	a := newDBTestHandler(t)
	idA := mustSaveCA(t, a, CAProfile{Name: "A", DirectoryURL: "https://a.example/dir"})
	idB := mustSaveCA(t, a, CAProfile{Name: "B", DirectoryURL: "https://b.example/dir"})
	writeCert(t, a.CertStorePath, "site", time.Now().Add(time.Hour))
	writeInfo(a.CertStorePath, "site", CertificateInfoJSON{AcmeName: "custom", AcmeProfile: "shortlived", CAProfileID: idA, ManagedBy: "acme", KeyType: "EC256"})
	load := func() *CertificateInfoJSON {
		info, err := LoadCertInfoJSON(filepath.Join(a.CertStorePath, "site.json"))
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	if err := a.AssignCertCAProfile("site", idA); err != nil || load().AcmeProfile != "shortlived" {
		t.Fatalf("assigning to the CA it already has must change nothing: %+v (%v)", load(), err)
	}
	if err := a.AssignCertCAProfile("site", idB); err != nil {
		t.Fatal(err)
	}
	if info := load(); info.CAProfileID != idB || info.AcmeProfile != "" || info.KeyType != "EC256" {
		t.Fatalf("the ACME profile name of the old CA must be cleared, the rest kept: %+v", info)
	}
}

// Review finding: a renewal that loaded the metadata before it got the issuance lock wrote the old
// CA profile back over an assignment made in between.
func TestRenewalUsesTheCAProfileAssignedWhileItWaited(t *testing.T) {
	r, _ := newRenewer(t)
	a := r.AcmeHandler
	a.beforeIssue = nil
	caOld, caNew := newFakeAccountCA(t, false), newFakeAccountCA(t, false)
	idOld := mustSaveCA(t, a, CAProfile{Name: "old CA", DirectoryURL: caOld.dir(), SkipTLS: true})
	idNew := mustSaveCA(t, a, CAProfile{Name: "new CA", DirectoryURL: caNew.dir(), SkipTLS: true})
	writeInfo(a.CertStorePath, "old", CertificateInfoJSON{AcmeName: "custom", AcmeUrl: caOld.dir(), SkipTLS: true, AcmeProfile: "shortlived", CAProfileID: idOld, ManagedBy: "acme"})
	// the renewer read the metadata here (profile idOld), then the admin assigned the certificate
	if err := a.AssignCertCAProfile("old", idNew); err != nil {
		t.Fatal(err)
	}
	stale := ObtainOptions{CAProfileID: idOld, Profile: "shortlived", FromMetadata: true}
	_, err := a.ObtainCertWithOptions([]string{"old.example"}, "old", "g@example.com", "custom", caOld.dir(), true, false, 60, "", false, false, stale)
	if err == nil || !strings.Contains(err.Error(), "fake CA refuses every order") {
		t.Fatalf("the renewal must reach a CA: %v", err)
	}
	if caNew.orderCount() != 1 || caOld.orderCount() != 0 || caOld.accounts() != 0 {
		t.Fatalf("the renewal must go to the CA assigned in the meantime: new %d old %d", caNew.orderCount(), caOld.orderCount())
	}
	// unassigned while waiting: the CA recorded for the certificate, no profile
	if err := a.AssignCertCAProfile("old", ""); err != nil {
		t.Fatal(err)
	}
	stale.CAProfileID = idNew
	a.ObtainCertWithOptions([]string{"old.example"}, "old", "g@example.com", "custom", caOld.dir(), true, false, 60, "", false, false, stale)
	if caNew.orderCount() != 1 || caOld.orderCount() != 1 {
		t.Fatalf("after unassigning the renewal must use the recorded CA: new %d old %d", caNew.orderCount(), caOld.orderCount())
	}
	// a request that names a profile itself (no FromMetadata) is not second-guessed
	a.ObtainCertWithOptions([]string{"old.example"}, "old", "g@example.com", "", "", false, false, 60, "", false, false, ObtainOptions{CAProfileID: idNew})
	if caNew.orderCount() != 2 {
		t.Fatalf("an explicit profile must be used as given: %d", caNew.orderCount())
	}
}

// Review finding: the import took the existing account away from an older saved CA that uses the
// global email (no email of its own) and has not asked for the account yet.
func TestImportGlobalLeavesTheAccountToAnExistingProfile(t *testing.T) {
	a := newDBTestHandler(t)
	ca := newFakeAccountCA(t, false)
	// before the upgrade: a saved CA without email field, its certificates issued with the account
	// keyed by directory URL + global email
	orderWith(t, a, "legacy", "g@example.com", "custom", ca.dir(), "")
	a.saveProfiles(prefCAProfiles, []map[string]any{{"id": "old1", "name": "Corp CA", "directoryURL": ca.dir(), "skipTLS": true}})

	if _, err := a.ImportGlobalCA("custom", ca.dir(), true, "G@Example.com"); err == nil || !strings.Contains(err.Error(), "already saved as the CA profile \"Corp CA\"") {
		t.Fatalf("the import must see the older saved CA as the same CA, got %v", err)
	}
	if len(a.ListCAProfiles()) != 1 || a.prefGet(accountOwnerKey(ca.dir(), "g@example.com")) != "" {
		t.Fatalf("a refused import must leave no profile and no account owner: %d %q", len(a.ListCAProfiles()), a.prefGet(accountOwnerKey(ca.dir(), "g@example.com")))
	}
	orderWith(t, a, "site", "g@example.com", "", "", "old1")
	if ca.accounts() != 1 {
		t.Fatalf("the older saved CA must keep the existing account, registrations: %d", ca.accounts())
	}
	// a saved CA with an email of its own that differs is another account: the import goes through
	// and takes the account of the global settings over
	d := newDBTestHandler(t)
	orderWith(t, d, "legacy", "g@example.com", "custom", ca.dir(), "")
	mustSaveCA(t, d, CAProfile{Name: "Own mail", DirectoryURL: ca.dir(), SkipTLS: true, Email: "own@example.com"})
	if res, err := d.ImportGlobalCA("custom", ca.dir(), true, "g@example.com"); err != nil || !res.AccountAdopted {
		t.Fatalf("a saved CA with a different email must not block the import: %+v (%v)", res, err)
	}

	// imported without a global email, then the email is set: still the same saved CA, no "(2)"
	b := newDBTestHandler(t)
	first, err := b.ImportGlobalCA("Let's Encrypt", "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ImportGlobalCA("Let's Encrypt", "", false, "late@example.com"); err == nil || !strings.Contains(err.Error(), first.Name) {
		t.Fatalf("a second import after setting the email must be refused, got %v", err)
	}
	// parallel clicks: exactly one profile
	c := newDBTestHandler(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.ImportGlobalCA("Let's Encrypt", "", false, "g@example.com") }()
	}
	wg.Wait()
	if n := len(c.ListCAProfiles()); n != 1 {
		t.Fatalf("parallel imports must create one saved CA, got %d", n)
	}
}
