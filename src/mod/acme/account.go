package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"

	"github.com/go-acme/lego/v5/acme"
)

/*
	account.go

	This file persists and reuses the ACME account (account key + registration)
	across certificate requests and renewals.

	Without this, ObtainCert() generated a fresh account key and registered a
	brand new ACME account on every single call. Let's Encrypt counts each of
	those as a "new registration" and rate limits them to 10 per IP per 3h, so
	routine renewals would eventually fail with:

		urn:ietf:params:acme:error:rateLimited :: too many new registrations

	The account is stored in the system database, in the same "acme" table and
	keyed by the same CA directory URL already used for this provider's EAB
	credentials (see ObtainCert). It is keyed by the CA directory URL only (NOT
	the email): an ACME account is identified by its key pair, the email is just
	a contact address. Keying by CA URL alone means a renewal still reuses the
	account even if the renewer email differs from the email used at first
	issuance.
*/

// acmeAccountTable is the database table reusable ACME accounts are stored in.
// It is intentionally the same table used for this module's DNS and EAB
// credentials so all per-CA ACME state lives together.
const acmeAccountTable = "acmepref"

// ACMEUser represents a user in the ACME system.
type ACMEUser struct {
	Email        string
	Registration *acme.ExtendedAccount
	key          crypto.Signer
}

// GetEmail returns the email of the ACMEUser.
func (u *ACMEUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the registration resource of the ACMEUser.
func (u *ACMEUser) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}

// GetPrivateKey returns the private key of the ACMEUser.
func (u *ACMEUser) GetPrivateKey() crypto.Signer {
	return u.key
}

// MarshalJSON implements json.Marshaler for ACMEUser.
// It serializes the private key as a PEM string because
// crypto.PrivateKey cannot be marshalled directly.
func (u *ACMEUser) MarshalJSON() ([]byte, error) {
	pemData := ""
	if u.key == nil {
		return nil, errors.New("no ACME account key found")
	}
	ecKey, ok := u.key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ACME account private key is not an ECDSA key")
	}

	der, _ := x509.MarshalECPrivateKey(ecKey)
	pemData = string(pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: der,
	}))

	return json.Marshal(struct {
		Email        string                `json:"email"`
		Registration *acme.ExtendedAccount `json:"registration"`
		KeyPEM       string                `json:"key"`
	}{
		Email:        u.Email,
		Registration: u.Registration,
		KeyPEM:       pemData,
	})
}

// UnmarshalJSON implements json.Unmarshaler for ACMEUser.
// It deserializes the private key from the PEM string field
// back into a crypto.PrivateKey.
func (u *ACMEUser) UnmarshalJSON(data []byte) error {
	aux := struct {
		Email        string                `json:"email"`
		Registration *acme.ExtendedAccount `json:"registration"`
		KeyPEM       string                `json:"key"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	u.Email = aux.Email
	u.Registration = aux.Registration

	if aux.KeyPEM == "" {
		return errors.New("no ACME account key stored")
	}

	block, _ := pem.Decode([]byte(aux.KeyPEM))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return errors.New("stored ACME account key could not be decoded as EC private key")
	}

	parsedKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return errors.New("stored ACME account key could not be parsed")
	}
	u.key = parsedKey

	return nil
}

// accountDBKey returns the database key for the account of a given CA
// directory URL and email. Using both ensures unique keys per account
// even when the same CA is used with different emails.
func accountDBKey(caDirURL string, email string) string {
	h := sha256.Sum256([]byte(caDirURL + "|" + email))
	return "acme_account_" + hex.EncodeToString(h[:8])
}

// accountDBKeyFor is accountDBKey plus the identity of a saved CA profile. Issuance without a
// profile ("" = the global CA settings) keeps the historic key, so nothing stored before changes
// place. Two profiles that point at the same directory URL with the same email get separate
// accounts (and so separate EAB bindings), see issue #233.
func accountDBKeyFor(caDirURL string, email string, profileID string) string {
	if profileID == "" {
		return accountDBKey(caDirURL, email)
	}
	h := sha256.Sum256([]byte(caDirURL + "|" + email + "|profile:" + profileID))
	return "acme_account_" + hex.EncodeToString(h[:8])
}

// accountOwnerKey names the record that says which CA profile took over the account stored
// under the historic (directory URL + email) key.
func accountOwnerKey(caDirURL string, email string) string {
	return "acme_account_owner_" + accountDBKey(caDirURL, email)[len("acme_account_"):]
}

// readACMEAccount loads the account stored under dbKey; ok is false when there is none or it
// cannot be reused.
func (a *ACMEHandler) readACMEAccount(dbKey string, caDirURL string) (*ACMEUser, bool) {
	if !a.Database.TableExists(acmeAccountTable) {
		// No ACME table yet (first run) - not an error.
		return nil, false
	}
	if !a.Database.KeyExists(acmeAccountTable, dbKey) {
		// No stored account for this CA yet - not an error.
		return nil, false
	}

	var user ACMEUser
	if err := a.Database.Read(acmeAccountTable, dbKey, &user); err != nil {
		a.Logf("Stored ACME account for "+caDirURL+" is invalid, registering a new account", err)
		return nil, false
	}

	if user.Registration == nil || user.Registration.Location == "" {
		// A key without a usable registration URI cannot be reused on its own.
		return nil, false
	}

	if _, ok := user.key.(*ecdsa.PrivateKey); !ok {
		a.Logf("Stored ACME account key for "+caDirURL+" is not an ECDSA key", nil)
		return nil, false
	}
	return &user, true
}

// loadACMEAccount tries to load a previously persisted account for the given
// CA directory URL and email. It returns (key, registration, true) only when
// a complete, reusable account is found; otherwise ok is false and the caller
// should register a new account.
func (a *ACMEHandler) loadACMEAccount(caDirURL string, email string) (*ecdsa.PrivateKey, *acme.ExtendedAccount, bool) {
	return a.loadACMEAccountFor(caDirURL, email, "")
}

// loadACMEAccountFor is loadACMEAccount for a saved CA profile ("" = none). A profile first looks
// for its own account. Accounts registered before profiles had their own (they were keyed by
// directory URL + email only) are not lost: the first profile that asks for such an account takes
// it over (see adoptLegacyAccount); any other profile with the same URL and email registers anew.
func (a *ACMEHandler) loadACMEAccountFor(caDirURL string, email string, profileID string) (*ecdsa.PrivateKey, *acme.ExtendedAccount, bool) {
	user, ok := a.readACMEAccount(accountDBKeyFor(caDirURL, email, profileID), caDirURL)
	if !ok && profileID != "" {
		user, ok = a.adoptLegacyAccount(caDirURL, email, profileID)
	}
	if !ok {
		return nil, nil, false
	}
	return user.key.(*ecdsa.PrivateKey), user.Registration, true
}

// adoptLegacyAccount hands the account stored under the historic (directory URL + email) key to
// one CA profile: it is copied to the profile's own key and the owner is recorded, so exactly one
// profile reuses it. The historic entry stays where it is (issuance without a profile and older
// versions keep finding it). An owner that no longer exists gives the account up.
func (a *ACMEHandler) adoptLegacyAccount(caDirURL string, email string, profileID string) (*ACMEUser, bool) {
	accountAdoptMu.Lock()
	defer accountAdoptMu.Unlock()
	user, ok := a.readACMEAccount(accountDBKey(caDirURL, email), caDirURL)
	if !ok {
		return nil, false
	}
	ownerKey := accountOwnerKey(caDirURL, email)
	if owner := a.prefGet(ownerKey); owner != "" && owner != profileID {
		if _, err := a.GetCAProfile(owner); err == nil {
			return nil, false // taken by another profile that still exists
		}
	}
	if err := a.prefSet(ownerKey, profileID); err != nil {
		return nil, false
	}
	if err := a.Database.Write(acmeAccountTable, accountDBKeyFor(caDirURL, email, profileID), user); err != nil {
		a.Logf("Failed to copy the existing ACME account to the CA profile", err)
	}
	a.Logf("CA profile takes over the existing ACME account for "+caDirURL, nil)
	return user, true
}

var accountAdoptMu sync.Mutex

// saveACMEAccount persists the account (key + registration) so that subsequent
// certificate requests and renewals reuse it instead of registering a new
// ACME account every time.
func (a *ACMEHandler) saveACMEAccount(caDirURL string, user *ACMEUser) error {
	return a.saveACMEAccountFor(caDirURL, user, "")
}

// saveACMEAccountFor is saveACMEAccount for a saved CA profile ("" = none).
func (a *ACMEHandler) saveACMEAccountFor(caDirURL string, user *ACMEUser, profileID string) error {
	if user == nil || user.GetRegistration() == nil {
		return errors.New("no ACME registration to persist")
	}

	if !a.Database.TableExists(acmeAccountTable) {
		if err := a.Database.NewTable(acmeAccountTable); err != nil {
			return err
		}
	}

	return a.Database.Write(acmeAccountTable, accountDBKeyFor(caDirURL, user.Email, profileID), user)
}
