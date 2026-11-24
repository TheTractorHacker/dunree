package acme

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The New proxy rule pages request a certificate with dns=true and no profile id (issue #91).
// These tests pin what that request does on the server. No real CA or DNS provider is contacted:
// the fake CA serves a directory and refuses everything after it.
func fakeDirectoryOnlyCA(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dir" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   srv.URL + "/nonce",
				"newAccount": srv.URL + "/acct",
				"newOrder":   srv.URL + "/order",
			})
			return
		}
		http.Error(w, "fake CA says no", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func obtainWithDNS(a *ACMEHandler, caURL, name string) ([]string, error) {
	_, lines, err := a.ObtainCertCapture([]string{name + ".example"}, name, "x@example.com", "custom", caURL, true, true, 60, "", false, false, ObtainOptions{})
	return lines, err
}

func TestDNSChallengeWithoutProfileIDUsesDefaultProfile(t *testing.T) {
	a := newDBTestHandler(t)
	srv := fakeDirectoryOnlyCA(t)

	// no default profile and no credentials for this certificate: refused with the configuration error, nothing is guessed
	lines, err := obtainWithDNS(a, srv.URL+"/dir", "nodefault")
	if err == nil || !strings.Contains(err.Error(), "DNS Provider and DNS Credential configuration required") {
		t.Fatalf("dns=true without any DNS configuration must be refused, got %v", err)
	}
	if strings.Contains(strings.Join(lines, "\n"), "Using DNS credential profile") {
		t.Fatal("no profile may be used when none is the default")
	}

	// a saved profile that is not the default is not picked up either
	id, err := a.SaveDNSProfile(DNSProfile{Name: "cf-main", Provider: "cloudflare", Credentials: `{"AuthToken":"tok-123"}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obtainWithDNS(a, srv.URL+"/dir", "notdefault"); err == nil || !strings.Contains(err.Error(), "configuration required") {
		t.Fatalf("a profile that is not the default must not be used, got %v", err)
	}

	// the default profile is used for a request that names no profile
	if err := a.SetDefaultDNSProfile(id); err != nil {
		t.Fatal(err)
	}
	lines, err = obtainWithDNS(a, srv.URL+"/dir", "withdefault")
	log := strings.Join(lines, "\n")
	if !strings.Contains(log, "Using DNS credential profile cf-main (cloudflare)") {
		t.Fatalf("the default profile must be used, log:\n%s", log)
	}
	if err == nil {
		t.Fatal("the fake CA refuses the account, an error is expected")
	}
	if strings.Contains(err.Error(), "configuration required") {
		t.Fatalf("with a default profile the request must get past the DNS configuration, got %v", err)
	}
	if strings.Contains(log, "tok-123") || strings.Contains(err.Error(), "tok-123") {
		t.Fatal("the credential must not appear in the log or the error")
	}
}

// A certificate keeps the DNS profile it was issued with: the id stored in its info file wins over the default,
// so changing or clearing the default later does not move its renewals to another profile.
// (The write of that id after a successful issuance needs an issuing CA and is not covered here.)
func TestCertificateKeepsItsDNSProfileWhenDefaultChanges(t *testing.T) {
	a := newDBTestHandler(t)
	srv := fakeDirectoryOnlyCA(t)
	first, err := a.SaveDNSProfile(DNSProfile{Name: "cf-first", Provider: "cloudflare", Credentials: `{"AuthToken":"tok-first"}`})
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.SaveDNSProfile(DNSProfile{Name: "cf-second", Provider: "cloudflare", Credentials: `{"AuthToken":"tok-second"}`})
	if err != nil {
		t.Fatal(err)
	}
	// as left behind by an issuance while cf-first was the default
	if err := writeInfo(a.CertStorePath, "kept", CertificateInfoJSON{UseDNS: true, DNSProfileID: first, ManagedBy: "acme"}); err != nil {
		t.Fatal(err)
	}
	used := func(name string) string {
		lines, _ := obtainWithDNS(a, srv.URL+"/dir", name)
		return strings.Join(lines, "\n")
	}
	if err := a.SetDefaultDNSProfile(second); err != nil {
		t.Fatal(err)
	}
	if log := used("kept"); !strings.Contains(log, "Using DNS credential profile cf-first (cloudflare)") || strings.Contains(log, "cf-second") {
		t.Fatalf("a changed default must not move the certificate to another profile, log:\n%s", log)
	}
	// a certificate without a stored profile follows the new default
	if log := used("fresh"); !strings.Contains(log, "Using DNS credential profile cf-second (cloudflare)") {
		t.Fatalf("a new certificate must use the current default, log:\n%s", log)
	}
	if err := a.SetDefaultDNSProfile(""); err != nil {
		t.Fatal(err)
	}
	if log := used("kept"); !strings.Contains(log, "Using DNS credential profile cf-first (cloudflare)") {
		t.Fatalf("a cleared default must not take the profile from the certificate, log:\n%s", log)
	}
}

// What the New proxy rule pages read to decide whether to offer the DNS challenge: the default id and the
// profile's name, with the secrets masked.
func TestDNSProfilesListForNewRuleOffer(t *testing.T) {
	a := newDBTestHandler(t)
	type listing struct {
		Profiles []DNSProfile `json:"profiles"`
		Default  string       `json:"default"`
	}
	get := func() listing {
		w := httptest.NewRecorder()
		a.HandleDNSProfiles(w, httptest.NewRequest(http.MethodGet, "/api/acme/profiles/dns", nil))
		var l listing
		if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
			t.Fatalf("bad listing %q: %v", w.Body.String(), err)
		}
		if strings.Contains(w.Body.String(), "tok-123") {
			t.Fatalf("the listing leaks a credential: %s", w.Body.String())
		}
		return l
	}
	if l := get(); l.Default != "" || len(l.Profiles) != 0 {
		t.Fatalf("a fresh install offers nothing, got %+v", l)
	}
	id, err := a.SaveDNSProfile(DNSProfile{Name: "cf-main", Provider: "cloudflare", Credentials: `{"AuthToken":"tok-123"}`})
	if err != nil {
		t.Fatal(err)
	}
	if l := get(); l.Default != "" || len(l.Profiles) != 1 {
		t.Fatalf("saving a profile must not make it the default, got %+v", l)
	}
	form := url.Values{"op": {"setDefault"}, "id": {id}}
	r := httptest.NewRequest(http.MethodPost, "/api/acme/profiles/dns", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.HandleDNSProfiles(w, r)
	if strings.Contains(w.Body.String(), "error") {
		t.Fatalf("setDefault failed: %s", w.Body.String())
	}
	l := get()
	if l.Default != id || len(l.Profiles) != 1 || l.Profiles[0].ID != id || l.Profiles[0].Name != "cf-main" {
		t.Fatalf("the listing must name the default profile, got %+v", l)
	}
}
