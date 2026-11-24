package acme

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

/*
	caprofile_assign.go (issue #233)

	What goes beyond storing CA profiles:

	* a default CA profile for NEW certificates (none unless chosen),
	* assigning an existing certificate to a profile without issuing it again,
	* turning the global CA settings into a first profile (only when asked).

	ACME accounts per profile live in account.go.
*/

// CAProfileNone is the value of the "caProfile" request parameter that says "no saved CA profile,
// use the CA named in this request", as opposed to leaving the parameter out.
const CAProfileNone = "none"

// DefaultCAProfileID is the CA profile used for new certificates that name none ("" = none, the default).
func (a *ACMEHandler) DefaultCAProfileID() string {
	id := a.prefGet(prefDefaultCA)
	if id == "" {
		return ""
	}
	if _, err := a.GetCAProfile(id); err != nil {
		return ""
	}
	return id
}

// SetDefaultCAProfile selects the default CA profile ("" clears it).
func (a *ACMEHandler) SetDefaultCAProfile(id string) error {
	if id != "" {
		if _, err := a.GetCAProfile(id); err != nil {
			return err
		}
	}
	return a.prefSet(prefDefaultCA, id)
}

// caProfileEmail returns the registration email of a CA profile, "" when it has none or does not exist.
func (a *ACMEHandler) caProfileEmail(id string) string {
	if id == "" {
		return ""
	}
	p, err := a.GetCAProfile(id)
	if err != nil {
		return ""
	}
	return p.Email
}

// resolveRequestCAProfile decides the CA profile of a certificate request made through the HTTP API:
//
//	a profile ID    that profile
//	CAProfileNone   no profile, the CA named in the request
//	""              an existing certificate keeps the profile it is assigned to (if that still exists);
//	                a new certificate gets the default CA profile, if one is set
//
// With no profile assigned and no default set, "" comes back and the request behaves as it always did.
func (a *ACMEHandler) resolveRequestCAProfile(requested string, certName string) string {
	if requested == CAProfileNone {
		return ""
	}
	if requested != "" {
		return requested
	}
	info, err := LoadCertInfoJSON(a.certPath(certName + ".json"))
	if err == nil {
		if info.CAProfileID != "" {
			if p, perr := a.GetCAProfile(info.CAProfileID); perr == nil {
				a.Logf("Certificate "+certName+" is assigned to the CA profile "+p.Name+", using it", nil)
				return p.ID
			}
		}
		return ""
	}
	if _, serr := os.Stat(a.certPath(certName + ".pem")); serr == nil {
		return "" // an existing certificate without metadata keeps the CA of the request
	}
	if def := a.DefaultCAProfileID(); def != "" {
		a.Logf("No CA profile named for the new certificate "+certName+", using the default CA profile", nil)
		return def
	}
	return ""
}

var errIssuanceRunning = errors.New("a certificate is being issued right now, try again when it has finished")

var errNotIssuedByACME = errors.New("this certificate was not issued by ACME on this server (it was uploaded), so it cannot be assigned to a saved CA; request it once with that CA instead")

// AssignCertCAProfile assigns an existing certificate to a CA profile ("" removes the assignment)
// without issuing it again: only the metadata next to the certificate changes, the next renewal
// (automatic or "Renew now") then uses that profile. Only certificates issued by ACME here can be
// assigned; one without metadata (an upload) is refused.
func (a *ACMEHandler) AssignCertCAProfile(certName string, profileID string) error {
	certName = strings.TrimSpace(certName)
	if certName == "" || certName != filepath.Base(certName) || strings.ContainsAny(certName, `/\`) || strings.HasPrefix(certName, ".") {
		return os.ErrInvalid
	}
	if profileID != "" {
		if _, err := a.GetCAProfile(profileID); err != nil {
			return err
		}
	}
	// issuance rewrites the same file
	if !a.issueMu.TryLock() {
		return errIssuanceRunning
	}
	defer a.issueMu.Unlock()

	pemPath := a.certPath(certName + ".pem")
	if _, err := os.Stat(pemPath); err != nil {
		return errors.New("certificate not found")
	}
	jsonPath := a.certPath(certName + ".json")
	info, err := LoadCertInfoJSON(jsonPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("the metadata of this certificate cannot be read")
		}
		// No metadata: an uploaded certificate. Writing metadata here would quietly turn it into one
		// that is renewed by ACME, which is not what "assign" promises.
		return errNotIssuedByACME
	}
	if info.IsExternallyManaged() {
		return errExternallyManaged
	}
	if info.CAProfileID == profileID {
		return nil
	}
	info.CAProfileID = profileID
	// The ACME "profile" name (for example "shortlived") was remembered from the previous CA and may
	// not exist at the new one: the next renewal takes the default of the CA profile it goes to.
	info.AcmeProfile = ""
	return SaveCertInfoJSON(jsonPath, info, a.PublicFileMode)
}

// GlobalCAImport is the outcome of ImportGlobalCA.
type GlobalCAImport struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	EABCopied      bool   `json:"eabCopied"`      // EAB credentials of the global settings were copied into the profile
	AccountAdopted bool   `json:"accountAdopted"` // the ACME account registered with the global settings now belongs to the profile
}

// ImportGlobalCA creates a CA profile from the global CA settings (preferred CA, custom URL, skip
// TLS, ACME email and the EAB credentials stored for that directory). The global settings and the
// account stored for them are left as they are; the profile takes the existing account over, so no
// new registration happens. Nothing calls this automatically. It is refused while a saved CA with
// the same directory URL and the same effective email (its own, or the global one when it has none)
// exists: that profile is, or will be, the owner of the account.
func (a *ACMEHandler) ImportGlobalCA(caName string, customURL string, skipTLS bool, email string) (*GlobalCAImport, error) {
	caName, email = strings.TrimSpace(caName), strings.TrimSpace(email)
	if caName == "" {
		caName = "Let's Encrypt"
	}
	p := CAProfile{Name: caName, Email: email}
	if caName == "custom" {
		p.DirectoryURL, p.SkipTLS = strings.TrimSpace(customURL), skipTLS
		if err := validateDirectoryURL(p.DirectoryURL); err != nil {
			return nil, errors.New("the global CA is a custom ACME server without a valid directory URL")
		}
		p.Name = "Custom CA"
	} else {
		dir, err := loadCAApiServerFromName(caName, a.TestMode)
		if err != nil {
			return nil, err
		}
		p.DirectoryURL = dir
	}
	p, err := normalizeCAProfile(p)
	if err != nil {
		return nil, err
	}
	// A saved CA without an email of its own uses the global email, so it counts as the same CA and
	// the same account as these settings. Importing next to it would hand the existing account to the
	// new, certificate-less profile and leave the older one to register again.
	effective := func(e string) string {
		if e == "" {
			return email
		}
		return e
	}

	// check and save under one lock: two parallel requests must not both pass the duplicate check
	profileMu.Lock()
	existing := a.listCAProfilesLocked()
	for _, e := range existing {
		if e.DirectoryURL == p.DirectoryURL && strings.EqualFold(effective(e.Email), p.Email) {
			profileMu.Unlock()
			return nil, errors.New("the global CA settings are already saved as the CA profile \"" + e.Name + "\"")
		}
	}
	taken := func(n string) bool {
		for _, e := range existing {
			if strings.EqualFold(e.Name, n) {
				return true
			}
		}
		return false
	}
	base := p.Name
	for i := 2; taken(p.Name); i++ {
		p.Name = base + " (" + strconv.Itoa(i) + ")"
	}

	// EAB credentials of the global settings are stored per directory URL in the "acme" table
	if a.Database != nil && a.Database.TableExists("acme") {
		var kid, hmac string
		a.Database.Read("acme", p.DirectoryURL+"_kid", &kid)
		a.Database.Read("acme", p.DirectoryURL+"_hmacEncoded", &hmac)
		if kid != "" && hmac != "" {
			p.EABKid, p.EABHmac = kid, hmac
		}
	}

	id, err := a.saveCAProfileLocked(p)
	profileMu.Unlock()
	if err != nil {
		return nil, err
	}
	res := &GlobalCAImport{ID: id, Name: p.Name, EABCopied: p.EABKid != ""}
	if email != "" {
		_, res.AccountAdopted = a.adoptLegacyAccount(p.DirectoryURL, email, id)
	}
	return res, nil
}
