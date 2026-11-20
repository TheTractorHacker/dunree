// Package upstreamtls implements the optional, per-upstream TLS trust policy: a private CA bundle and/or SPKI SHA-256
// pins that are used to verify an HTTPS upstream INSTEAD of skipping verification.
//
// Rules (never weakened):
//   - the certificate chain is always verified and the host name is always checked (ServerName)
//   - a CA bundle REPLACES the system roots for that upstream (it does not add to them)
//   - pins are additional to chain verification: at least one certificate of the verified chain must match one pin
//   - an invalid policy fails closed (every handshake is refused with the error), it never falls back to skip-verify
package upstreamtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxBundleBytes = 256 * 1024
	MaxBundleCerts = 64
	MaxPins        = 16
)

// Policy is the stored form. The zero value means "no custom trust" (historical behavior).
type Policy struct {
	CABundlePEM string   //PEM encoded CA certificates (trust anchors), empty = system roots
	PinsSHA256  []string //SPKI SHA-256 pins, hex or base64, see NormalizePin
}

// Active reports whether any custom trust is configured
func (p Policy) Active() bool {
	return strings.TrimSpace(p.CABundlePEM) != "" || len(p.PinsSHA256) > 0
}

// CertInfo describes one certificate of a bundle, for display
type CertInfo struct {
	Subject     string `json:"Subject"`
	Issuer      string `json:"Issuer"`
	NotBefore   string `json:"NotBefore"`
	NotAfter    string `json:"NotAfter"`
	Expired     bool   `json:"Expired"`
	IsCA        bool   `json:"IsCA"`
	SelfSigned  bool   `json:"SelfSigned"`
	Fingerprint string `json:"Fingerprint"` //SHA-256 of the DER certificate, hex with colons
	SPKIPin     string `json:"SPKIPin"`     //SHA-256 of the SubjectPublicKeyInfo, hex (usable as a pin)
}

// SPKIHash returns the SHA-256 of the SubjectPublicKeyInfo of a certificate
func SPKIHash(c *x509.Certificate) [32]byte {
	return sha256.Sum256(c.RawSubjectPublicKeyInfo)
}

// NormalizePin accepts a SHA-256 SPKI pin as 64 hex digits (colons / spaces allowed), standard or URL safe base64
// (44 chars), optionally with a "sha256//" or "sha256/" prefix (curl style), and returns lowercase hex.
func NormalizePin(s string) (string, error) {
	s = strings.TrimSpace(s)
	l := strings.ToLower(s)
	if strings.HasPrefix(l, "sha256//") {
		s = s[len("sha256//"):]
	} else if strings.HasPrefix(l, "sha256/") {
		s = s[len("sha256/"):]
	}
	s = strings.TrimSpace(s)
	hexForm := strings.NewReplacer(":", "", " ", "").Replace(s)
	if len(hexForm) == 64 {
		if b, err := hex.DecodeString(hexForm); err == nil {
			return hex.EncodeToString(b), nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == sha256.Size {
			return hex.EncodeToString(b), nil
		}
	}
	return "", fmt.Errorf("invalid pin %q: expected a SHA-256 value as 64 hex digits or base64", truncate(s, 24))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// NormalizePins normalizes and de-duplicates a pin list
func NormalizePins(in []string) ([]string, error) {
	if len(in) > MaxPins {
		return nil, fmt.Errorf("too many pins (maximum %d)", MaxPins)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range in {
		if strings.TrimSpace(p) == "" {
			continue
		}
		n, err := NormalizePin(p)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// ParseBundle validates a PEM CA bundle and returns the pool and the certificate details.
// Only CERTIFICATE blocks are accepted: a private key (or anything else) in the paste is refused so keys are never stored.
func ParseBundle(pemText string, now time.Time) (*x509.CertPool, []CertInfo, error) {
	if len(pemText) > MaxBundleBytes {
		return nil, nil, errors.New("CA bundle is too large")
	}
	rest := []byte(strings.TrimSpace(pemText))
	pool := x509.NewCertPool()
	infos := []CertInfo{}
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, nil, errors.New("CA bundle contains data that is not PEM")
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("CA bundle may only contain CERTIFICATE blocks (found %q)", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("CA bundle contains an unparsable certificate: %v", err)
		}
		if len(infos) >= MaxBundleCerts {
			return nil, nil, fmt.Errorf("CA bundle has too many certificates (maximum %d)", MaxBundleCerts)
		}
		pool.AddCert(c)
		fp := sha256.Sum256(c.Raw)
		spki := SPKIHash(c)
		infos = append(infos, CertInfo{
			Subject: c.Subject.String(), Issuer: c.Issuer.String(),
			NotBefore: c.NotBefore.Format("2006-01-02"), NotAfter: c.NotAfter.Format("2006-01-02"),
			Expired: now.After(c.NotAfter), IsCA: c.IsCA, SelfSigned: bytes.Equal(c.RawSubject, c.RawIssuer),
			Fingerprint: colonHex(fp[:]), SPKIPin: hex.EncodeToString(spki[:]),
		})
	}
	if len(infos) == 0 {
		return nil, nil, errors.New("CA bundle contains no certificate")
	}
	return pool, infos, nil
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(b))
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Validate checks the policy as stored, returning the first problem
func (p Policy) Validate() error {
	if strings.TrimSpace(p.CABundlePEM) != "" {
		if _, _, err := ParseBundle(p.CABundlePEM, time.Now()); err != nil {
			return err
		}
	}
	_, err := NormalizePins(p.PinsSHA256)
	return err
}

// Normalized returns a copy with the pins in canonical form
func (p Policy) Normalized() (Policy, error) {
	pins, err := NormalizePins(p.PinsSHA256)
	if err != nil {
		return p, err
	}
	if len(pins) == 0 {
		pins = nil
	}
	return Policy{CABundlePEM: strings.TrimSpace(p.CABundlePEM), PinsSHA256: pins}, nil
}

// Key is a stable string of the policy, for change detection (health check config hash)
func (p Policy) Key() string {
	if !p.Active() {
		return ""
	}
	pins := append([]string(nil), p.PinsSHA256...)
	sort.Strings(pins)
	h := sha256.Sum256([]byte(strings.TrimSpace(p.CABundlePEM) + "\x00" + strings.Join(pins, ",")))
	return hex.EncodeToString(h[:8])
}

// Apply installs the policy into cfg: RootCAs (when a bundle is set) and the pin check. It clears InsecureSkipVerify,
// because a configured policy replaces skip-verify. cfg.ServerName is left to the caller and keeps being verified.
// An invalid policy makes every handshake fail (fail closed).
func (p Policy) Apply(cfg *tls.Config) {
	cfg.InsecureSkipVerify = false
	pins, err := NormalizePins(p.PinsSHA256)
	var pool *x509.CertPool
	if err == nil && strings.TrimSpace(p.CABundlePEM) != "" {
		pool, _, err = ParseBundle(p.CABundlePEM, time.Now())
	}
	if err != nil {
		cfg.VerifyConnection = func(tls.ConnectionState) error {
			return fmt.Errorf("upstream TLS trust policy is invalid, connection refused: %v", err)
		}
		return
	}
	if pool != nil {
		cfg.RootCAs = pool
	}
	if len(pins) == 0 {
		return
	}
	want := map[[32]byte]bool{}
	for _, h := range pins {
		b, _ := hex.DecodeString(h)
		var k [32]byte
		copy(k[:], b)
		want[k] = true
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		//Standard verification (chain + host name) already ran and succeeded, VerifiedChains is its result
		if len(cs.VerifiedChains) == 0 {
			return errors.New("upstream certificate chain was not verified, refusing to check pins")
		}
		for _, chain := range cs.VerifiedChains {
			for _, c := range chain {
				if want[SPKIHash(c)] {
					return nil
				}
			}
		}
		return errors.New("upstream certificate does not match any pinned public key")
	}
}
