// Package brand holds what Dunree says about itself: its name, its version,
// who publishes it and what it is based on.
//
// It is the one place for these values. The About page, the page footer and
// the visitor-facing default pages read them from here (the admin interface
// through /api/info/x), so that a later change of an address or of the version
// is one edit.
//
// Dunree is published by Foley IT under AGPL-3.0. It is a modified, independent
// derivative of Zoraxy by tobychui and imuslab and is not endorsed by them; see
// the NOTICE file. Nothing in this package is an address Dunree contacts.
package brand

const (
	// Name is the product name as it is shown to people.
	Name = "Dunree"
	// Slug is the name in lower case, for file names and identifiers.
	Slug = "dunree"
	// Tagline is the one-line description of the product.
	Tagline = "Reverse proxy and web gateway"
	// Publisher is who publishes the official releases.
	Publisher = "Foley IT"
	// License is the SPDX identifier of the licence of the whole program.
	License = "AGPL-3.0"

	// Version is the Dunree version of this source tree. The Dunree version line
	// starts at 1.0.0-beta.1; it is not the Zoraxy version the code is based on.
	Version = "1.0.0-beta.1"

	// BasedOnName, BasedOnVersion and BasedOnAuthors name the work Dunree is
	// derived from. They are attribution and must stay.
	BasedOnName    = "Zoraxy"
	BasedOnVersion = "3.3.6"
	BasedOnAuthors = "tobychui and imuslab"
)

// Addresses. They are variables on purpose: the home of the project is not
// decided yet, so they are empty in the source tree and the owner sets them for
// a release build, for example
//
//	go build -ldflags "-X github.com/TheTractorHacker/dunree/mod/brand.SourceURL=https://..."
//
// Empty means "not set": the interface then shows the text without a link.
// Dunree never fetches these addresses; they are links a person follows.
var (
	// SourceURL is where the complete source code of this build can be obtained
	// (the source offer of AGPL-3.0 section 13).
	SourceURL = ""
	// ProductURL is the website of the product.
	ProductURL = ""
	// SecurityContact is where a vulnerability is reported (an address or a URL).
	SecurityContact = ""
)

// BasedOn returns the attribution line in its short form:
// "Based on Zoraxy v3.3.6 by tobychui and imuslab, AGPL-3.0".
func BasedOn() string {
	return "Based on " + BasedOnName + " v" + BasedOnVersion + " by " + BasedOnAuthors + ", " + License
}

// PublishedBy returns "Published by Foley IT".
func PublishedBy() string {
	return "Published by " + Publisher
}

// Info is what the admin interface is told (part of the answer of /api/info/x).
type Info struct {
	Product        string // "Dunree"
	ProductVersion string // "1.0.0-beta.1"
	Tagline        string
	Publisher      string // "Foley IT"
	License        string // "AGPL-3.0"
	BasedOn        string // "Zoraxy"
	BasedOnVersion string // "3.3.6"
	BasedOnAuthors string // "tobychui and imuslab"
	SourceURL      string // "" = not set in this build
	ProductURL     string // "" = not set in this build
}

// Get returns the values of this build. Addresses that are not plain http(s)
// URLs are reported as not set, so that a build flag can never put a script
// address into a link of the admin interface.
func Get() Info {
	return Info{
		Product: Name, ProductVersion: Version, Tagline: Tagline, Publisher: Publisher, License: License,
		BasedOn: BasedOnName, BasedOnVersion: BasedOnVersion, BasedOnAuthors: BasedOnAuthors,
		SourceURL: SafeURL(SourceURL), ProductURL: SafeURL(ProductURL),
	}
}

// SafeURL returns u when it is an absolute http:// or https:// address without
// white space, quotes or angle brackets, and "" otherwise.
func SafeURL(u string) string {
	if len(u) > 512 {
		return ""
	}
	lower := toLower(u)
	if !(hasPrefix(lower, "https://") && len(u) > len("https://")) && !(hasPrefix(lower, "http://") && len(u) > len("http://")) {
		return ""
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c <= ' ' || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`' || c == '\\' || c == 0x7f {
			return ""
		}
	}
	return u
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
