// Package tlstest generates throwaway certificate authorities and certificates for tests of upstream TLS handling.
// It is only imported from _test files.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  []byte
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return n
}

// NewCA creates a self-signed CA
func NewCA(cn string) *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: key, DER: der}
}

// PEM returns the CA certificate, PEM encoded
func (ca *CA) PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.DER}))
}

// Pool returns a pool holding only this CA
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Options of an issued certificate
type Options struct {
	DNS       []string
	IPs       []net.IP
	NotBefore time.Time
	NotAfter  time.Time
	Client    bool //client authentication instead of server authentication
}

// Issue signs a leaf certificate. Zero validity = valid from an hour ago for a day.
func (ca *CA) Issue(o Options) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(24 * time.Hour)
	}
	eku := x509.ExtKeyUsageServerAuth
	if o.Client {
		eku = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: o.NotBefore, NotAfter: o.NotAfter,
		DNSNames: o.DNS, IPAddresses: o.IPs,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
