package crowdsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

/*
	The bouncer API key is stored the way the AI assistant key is (mod/aiassist/secret.go): AES-256-GCM sealed under a
	random per-install master key, both files mode 0600 in conf/crowdsec/, both excluded from configuration exports
	(IsSecretFile, used by confbackup.go). The key is never part of Settings, never returned by an API and never logged.
*/

const (
	DirName        = "crowdsec"
	keyFileName    = "crowdsec.key"
	sealedFileName = "apikey.sealed"
	bindFileName   = "apikey.bind"
	sealAAD        = "zoraxy-crowdsec-apikey-v1"
)

// ErrTampered is returned when the sealed key cannot be authenticated
var ErrTampered = errors.New("the stored CrowdSec API key cannot be decrypted (file modified or from another install); enter the key again")

// IsSecretFile tells the configuration backup which files under the conf folder are never exported (rel is relative to conf)
func IsSecretFile(rel string) bool {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "./")
	return rel == DirName+"/"+keyFileName || rel == DirName+"/"+sealedFileName
}

// Vault holds the sealed API key
type Vault struct {
	dir string
	mu  sync.Mutex
}

// NewVault uses dir (created 0700 when missing)
func NewVault(dir string) *Vault { return &Vault{dir: dir} }

func (v *Vault) masterKey(create bool) ([]byte, error) {
	p := filepath.Join(v.dir, keyFileName)
	if b, err := os.ReadFile(p); err == nil {
		k, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr == nil && len(k) == 32 {
			return k, nil
		}
		if !create {
			return nil, ErrTampered
		}
	} else if !create {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(p, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func gcmFor(k []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// ValidKey reports whether s is acceptable as a bouncer API key (printable, no whitespace, at most 512 bytes)
func ValidKey(s string) error {
	if s == "" || len(s) > 512 {
		return errors.New("invalid API key (empty or longer than 512 characters)")
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return errors.New("invalid API key (it must not contain spaces or control characters)")
		}
	}
	return nil
}

// Set seals and stores the key
func (v *Vault) Set(key string) error {
	key = strings.TrimSpace(key)
	if err := ValidKey(key); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	mk, err := v.masterKey(true)
	if err != nil {
		return err
	}
	g, err := gcmFor(mk)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	blob := g.Seal(nonce, nonce, []byte(key), []byte(sealAAD))
	return writeFileAtomic(filepath.Join(v.dir, sealedFileName), []byte(base64.StdEncoding.EncodeToString(blob)), 0o600)
}

// Clear removes the stored key
func (v *Vault) Clear() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_ = os.Remove(filepath.Join(v.dir, bindFileName))
	err := os.Remove(filepath.Join(v.dir, sealedFileName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Get returns the plain key; ok is false when none is stored. Callers must never log or return it.
func (v *Vault) Get() (key string, ok bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(v.dir, sealedFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", true, ErrTampered
	}
	mk, err := v.masterKey(false)
	if err != nil {
		return "", true, ErrTampered
	}
	g, err := gcmFor(mk)
	if err != nil || len(blob) < g.NonceSize()+g.Overhead() {
		return "", true, ErrTampered
	}
	pt, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], []byte(sealAAD))
	if err != nil {
		return "", true, ErrTampered
	}
	return string(pt), true, nil
}

// IsSet reports whether a key file exists (without decrypting it)
func (v *Vault) IsSet() bool {
	_, err := os.Stat(filepath.Join(v.dir, sealedFileName))
	return err == nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_ = tmp.Chmod(perm)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Binding tells for which LAPI endpoint (BindingOf) the stored key was entered. ok is false for a key stored before
// bindings existed (the caller then uses the endpoint of the saved settings).
func (v *Vault) Binding() (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(v.dir, bindFileName))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// SetBinding records the endpoint the key belongs to
func (v *Vault) SetBinding(b string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return writeFileAtomic(filepath.Join(v.dir, bindFileName), []byte(b+"\n"), 0o600)
}

// BindingOf is the identity of a LAPI endpoint for key binding: a hash of scheme, lower-case host and port. The path
// is not part of it (the key goes to the host).
func BindingOf(lapiURL string) string {
	u, err := ParseLAPIURL(lapiURL)
	if err != nil {
		return "-"
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	sum := sha256.Sum256([]byte(u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port))
	return hex.EncodeToString(sum[:])
}
