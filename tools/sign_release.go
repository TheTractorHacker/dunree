// sign_release.go - release signing helper for the in-app updater.
//
// This is a standalone program (stdlib only). It is NOT part of the Dunree
// binary and not part of the Go module; run it with `go run tools/sign_release.go`.
//
// Modes:
//
//	sign    (default)  go run tools/sign_release.go -dist DIR -key PRIVATE.pem -tag vX.Y.Z[-beta.N] -build N [-upstream X.Y.Z] [-pub PUBLIC.pem]
//	        Writes DIR/SHA256SUMS (sha256sum format, over every dunree_* file in
//	        DIR (programs, archives and packages) plus the fixed extra assets
//	        listed in extraAssets when present, preceded by the signed header line
//	        "# dunree-release product=dunree tag=<tag> build=<n> upstream=<X.Y.Z>".
//	        It names the product, binds the release tag and a monotonically
//	        increasing build number, so an old signed release cannot be replayed as
//	        a downgrade and a file signed for another product with the same key is
//	        not taken for a Dunree release; `sha256sum -c` ignores the line.
//	        upstream is the version of the code base the release is derived from
//	        (COMPAT_VERSION); it is informational.)
//	        and DIR/SHA256SUMS.sig (raw 64 byte ed25519 signature over the exact
//	        bytes of SHA256SUMS), then re-verifies its own output.
//	verify             go run tools/sign_release.go -verify -dist DIR -pub PUBLIC.pem
//	        Checks the signature, the header and every listed file's SHA-256.
//	genkey             go run tools/sign_release.go -genkey PRIVATE.pem PUBLIC.pem
//	        Creates a (throwaway or real) ed25519 key pair; refuses to overwrite.
//
// The private key path may also come from $DUNREE_RELEASE_KEY or, when that is
// not set, from the older $ZORAXY_RELEASE_KEY; the public key path from
// $DUNREE_RELEASE_PUB, then $ZORAXY_RELEASE_PUB. The key is the one the
// releases were always signed with: it does not change with the product name.
// It is read only to sign; its contents are never printed or logged.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// extraAssets are non-binary release files that are signed along with the
// binaries (CrowdSec setup helpers). The in-app updater only looks up the line
// of its own binary, so extra lines do not affect it.
var extraAssets = []string{"CROWDSEC-README.md", "crowdsec-docker-compose.yml", "crowdsec-setup.sh"}

const (
	sumsName = "SHA256SUMS"
	sigName  = "SHA256SUMS.sig"
)

func main() {
	dist := flag.String("dist", "", "directory containing the dunree_* release files")
	keyPath := flag.String("key", keyFromEnv(os.Getenv), "path to the ed25519 private key (PKCS#8 PEM); default $DUNREE_RELEASE_KEY, then $ZORAXY_RELEASE_KEY")
	pubPath := flag.String("pub", pubFromEnv(os.Getenv), "path to the ed25519 public key (SPKI PEM) used to verify; default $DUNREE_RELEASE_PUB, then $ZORAXY_RELEASE_PUB")
	tag := flag.String("tag", "", "release tag the signature is bound to, e.g. v1.0.0-beta.1 (must equal the GitHub release tag)")
	upstream := flag.String("upstream", "", "version of the code base the release is derived from, e.g. 3.3.6 (written into the header, informational)")
	build := flag.Int("build", 0, "monotonically increasing build number (must exceed the previous release's)")
	verify := flag.Bool("verify", false, "verify an existing dist directory instead of signing")
	genkey := flag.Bool("genkey", false, "generate a key pair: -genkey PRIVATE.pem PUBLIC.pem")
	flag.Parse()

	var err error
	switch {
	case *genkey:
		if flag.NArg() != 2 {
			err = errors.New("usage: -genkey PRIVATE.pem PUBLIC.pem")
		} else {
			err = generateKey(flag.Arg(0), flag.Arg(1))
		}
	case *verify:
		err = verifyDist(*dist, *pubPath)
	default:
		err = signDist(*dist, *keyPath, *pubPath, *tag, *upstream, *build)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// product is the product name signed into the header, and headerPrefix the first word of it.
// The in-app updater requires both (src/mod/updater/verify.go).
const (
	product      = "dunree"
	headerPrefix = "# dunree-release "
	assetPrefix  = "dunree_"
	// legacyAssetPrefix is how the files of the earlier fork were named. A Dunree release does
	// not carry them: no installed updater of that fork accepts a Dunree release.
	legacyAssetPrefix = "zoraxy_" // legacy-compat
)

func isReleaseAsset(name string) bool { return strings.HasPrefix(name, assetPrefix) }

// keyFromEnv returns the private key path from the environment: the Dunree name first, then the older one.
func keyFromEnv(getenv func(string) string) string {
	return envFallback(getenv, "DUNREE_RELEASE_KEY", "ZORAXY_RELEASE_KEY")
}

// pubFromEnv returns the public key path from the environment, in the same order.
func pubFromEnv(getenv func(string) string) string {
	return envFallback(getenv, "DUNREE_RELEASE_PUB", "ZORAXY_RELEASE_PUB")
}

func envFallback(getenv func(string) string, name, older string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return getenv(older)
}

func generateKey(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if err := writeNew(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}), 0o600); err != nil {
		return err
	}
	return writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadPrivate(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("no private key: pass -key or set DUNREE_RELEASE_KEY")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("private key is not a valid PKCS#8 key")
	}
	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ed25519")
	}
	return pk, nil
}

func loadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("public key is not PEM encoded")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ed25519")
	}
	return pk, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// tagRe is the tag form of a Dunree release: Semantic Versioning with an optional pre-release
// part and a leading v (the same expression as in src/mod/updater/version.go, without the
// optional v: a release tag always has it).
var tagRe = regexp.MustCompile(`^v(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$`)

var upstreamRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// headerLine renders the signed first line of SHA256SUMS (without the newline).
func headerLine(tag string, build int, upstream string) string {
	l := fmt.Sprintf("%sproduct=%s tag=%s build=%d", headerPrefix, product, tag, build)
	if upstream != "" {
		l += " upstream=" + upstream
	}
	return l
}

func signDist(dist, keyPath, pubPath, tag, upstream string, build int) error {
	if !tagRe.MatchString(tag) {
		return errors.New("-tag is required and must look like v1.0.0 or v1.0.0-beta.1")
	}
	if upstream != "" && !upstreamRe.MatchString(upstream) {
		return errors.New("-upstream must look like 3.3.6")
	}
	if build <= 0 {
		return errors.New("-build is required and must be a positive, increasing number")
	}
	if dist == "" {
		return errors.New("-dist is required")
	}
	priv, err := loadPrivate(keyPath)
	if err != nil {
		return err
	}
	ents, err := os.ReadDir(dist)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), legacyAssetPrefix) {
			return fmt.Errorf("%s in %s has the file name of the earlier fork; a Dunree release carries dunree_* files only, remove it", e.Name(), dist)
		}
		if e.Type().IsRegular() && isReleaseAsset(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no dunree_* files found in %s", dist)
	}
	for _, n := range extraAssets {
		if st, err := os.Lstat(filepath.Join(dist, n)); err == nil && st.Mode().IsRegular() {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var sums strings.Builder
	sums.WriteString(headerLine(tag, build, upstream) + "\n")
	for _, n := range names {
		h, err := fileSum(filepath.Join(dist, n))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", h, n)
	}
	sig := signBytes(priv, []byte(sums.String()))
	if err := os.WriteFile(filepath.Join(dist, sumsName), []byte(sums.String()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dist, sigName), sig, 0o644); err != nil {
		return err
	}
	// Verify our own output against the derived public key (and -pub if given).
	derived := priv.Public().(ed25519.PublicKey)
	if pubPath != "" {
		want, err := loadPublic(pubPath)
		if err != nil {
			return err
		}
		if !derived.Equal(want) {
			return errors.New("the private key does not match the expected public key (-pub); signature files were written but are NOT valid for that key")
		}
	}
	if err := verifyWith(dist, derived); err != nil {
		return fmt.Errorf("self-verification failed: %w", err)
	}
	fmt.Printf("signed %d files; wrote %s and %s\n", len(names), sumsName, sigName)
	return nil
}

func signBytes(priv ed25519.PrivateKey, b []byte) []byte { return ed25519.Sign(priv, b) }

func verifyDist(dist, pubPath string) error {
	if dist == "" || pubPath == "" {
		return errors.New("-verify needs -dist and -pub")
	}
	pub, err := loadPublic(pubPath)
	if err != nil {
		return err
	}
	if err := verifyWith(dist, pub); err != nil {
		return err
	}
	fmt.Println("OK: signature and checksums verified")
	return nil
}

func verifyWith(dist string, pub ed25519.PublicKey) error {
	sums, err := os.ReadFile(filepath.Join(dist, sumsName))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(dist, sigName))
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, sig) {
		return errors.New("bad signature over " + sumsName)
	}
	n := 0
	first := true
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if first {
			first = false
			if !validHeader(line) {
				return errors.New(sumsName + " has no signed Dunree release header")
			}
			continue
		}
		if len(f) != 2 {
			return fmt.Errorf("malformed line %q", line)
		}
		got, err := fileSum(filepath.Join(dist, f[1]))
		if err != nil {
			return err
		}
		if got != f[0] {
			return fmt.Errorf("checksum mismatch for %s", f[1])
		}
		n++
	}
	if n == 0 {
		return errors.New(sumsName + " is empty")
	}
	return nil
}

// validHeader reports whether line is the header of a Dunree release: the Dunree first word,
// product=dunree, a tag and a build number, each named once.
func validHeader(line string) bool {
	line = strings.TrimRight(line, "\r")
	if !strings.HasPrefix(line, headerPrefix) {
		return false
	}
	seen := map[string]string{}
	for _, kv := range strings.Fields(strings.TrimPrefix(line, headerPrefix)) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, dup := seen[k]; dup {
			return false
		}
		seen[k] = v
	}
	n := 0
	for _, c := range seen["build"] {
		if c < '0' || c > '9' {
			return false
		}
		n++
	}
	return seen["product"] == product && tagRe.MatchString(seen["tag"]) && n > 0
}
