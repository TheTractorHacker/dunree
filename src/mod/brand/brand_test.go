package brand

import (
	"strings"
	"testing"
)

// The values the rest of the product reads. A change here is a change of what
// Dunree says about itself everywhere, so it is pinned.
func TestIdentity(t *testing.T) {
	if Name != "Dunree" || Slug != "dunree" || Publisher != "Foley IT" || License != "AGPL-3.0" || Tagline != "Reverse proxy and web gateway" {
		t.Fatalf("identity changed: %q %q %q %q %q", Name, Slug, Publisher, License, Tagline)
	}
	if !strings.HasPrefix(Version, "1.") {
		t.Fatalf("the Dunree version line starts at 1.0.0-beta.1, got %q", Version)
	}
	if Version == BasedOnVersion {
		t.Fatal("the Dunree version must not be the version of the Zoraxy base")
	}
}

// The credit to the work Dunree is derived from must name the project, its
// version, its authors and the licence, and must not present them as publisher.
func TestAttribution(t *testing.T) {
	if got, want := BasedOn(), "Based on Zoraxy v3.3.6 by tobychui and imuslab, AGPL-3.0"; got != want {
		t.Fatalf("BasedOn() = %q, want %q", got, want)
	}
	if got := PublishedBy(); got != "Published by Foley IT" {
		t.Fatalf("PublishedBy() = %q", got)
	}
	for _, name := range []string{"tobychui", "imuslab"} {
		if strings.Contains(Publisher, name) || strings.Contains(Name, name) {
			t.Fatalf("%s is credited as an author of the base, never as publisher or product", name)
		}
	}
	i := Get()
	if i.Product != Name || i.ProductVersion != Version || i.Publisher != Publisher || i.BasedOn != "Zoraxy" || i.BasedOnVersion != "3.3.6" || i.BasedOnAuthors != "tobychui and imuslab" || i.License != License {
		t.Fatalf("Get() does not report the constants: %+v", i)
	}
}

// The addresses are empty in the source tree: nothing points at a home that is
// not decided, and nothing points at the project Dunree is based on.
func TestAddressesAreNotSetInTheSourceTree(t *testing.T) {
	if SourceURL != "" || ProductURL != "" || SecurityContact != "" {
		t.Fatalf("addresses must be empty in the source tree and set for a release build: %q %q %q", SourceURL, ProductURL, SecurityContact)
	}
	if i := Get(); i.SourceURL != "" || i.ProductURL != "" {
		t.Fatalf("Get() reports an address although none is set: %+v", i)
	}
}

// An address set at build time ends up in a link of the admin interface and of
// the CAPTCHA page: only a plain web address is passed on.
func TestSafeURL(t *testing.T) {
	for _, ok := range []string{"https://example.org/dunree", "http://example.org", "HTTPS://Example.org/a?b=c#d"} {
		if SafeURL(ok) != ok {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "https://", "http://", "javascript:alert(1)", "data:text/html,x", "//example.org", "ftp://example.org", "example.org",
		"https://example.org/\"onclick=\"x", "https://example.org/<script>", "https://example.org/ a", "https://example.org/\n", "https://example.org/'x", " https://example.org",
		"https://example.org/" + strings.Repeat("a", 600)} {
		if got := SafeURL(bad); got != "" {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
	defer func(s, p string) { SourceURL, ProductURL = s, p }(SourceURL, ProductURL)
	SourceURL, ProductURL = "javascript:alert(1)", "https://dunree.example/"
	if i := Get(); i.SourceURL != "" || i.ProductURL != "https://dunree.example/" {
		t.Fatalf("Get() must drop an unsafe address and keep a web address: %+v", i)
	}
}
