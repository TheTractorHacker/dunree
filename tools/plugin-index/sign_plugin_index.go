// sign_plugin_index.go - key pair and signing helper for the signed plugin index.
//
// This is a standalone program (stdlib only). It is NOT part of the Dunree
// binary and not part of the Go module; run it with
// `go run tools/plugin-index/sign_plugin_index.go`.
//
// The plugin index is signed with a key of its own. It must never be the key
// that signs Dunree releases: whoever holds the plugin key decides which plugin
// binaries a proxy accepts, whoever holds the release key decides which Dunree
// it runs. This tool refuses a key file that is $ZORAXY_RELEASE_KEY or is named
// like the release key.
//
// Modes:
//
//	genkey   go run tools/plugin-index/sign_plugin_index.go -genkey PRIVATE.pem PUBLIC.pem
//	         Creates an ed25519 key pair (PKCS#8 / SPKI PEM, the format of
//	         tools/sign_release.go); refuses to overwrite. Give PUBLIC.pem to
//	         Dunree (Plugin Manager > Plugin safety settings, or the start flag
//	         -plugin_index_pubkey). Keep PRIVATE.pem off the proxies.
//
//	sign     go run tools/plugin-index/sign_plugin_index.go -index DRAFT.json -out index.json \
//	             -key PRIVATE.pem -serial N [-files DIR] [-fetch] [-pub PUBLIC.pem]
//	         Reads a draft index, fills in the SHA-256 and size of every download
//	         that lacks them, sets the serial number, writes index.json and
//	         index.json.sig (the raw 64 byte ed25519 signature over the exact bytes
//	         of index.json) and verifies its own output.
//	         The checksum of a download comes from, in this order: the draft (when
//	         it has both sha256 and size), a local file DIR/<plugin id>/<file name
//	         of the URL> or DIR/<file name of the URL> (-files), or the URL itself
//	         (-fetch, network access).
//	         -serial must be higher than the serial of the index that is already at
//	         -out: Dunree refuses a signed index that is older than one it has seen
//	         (replay protection).
//	         A download URL has to be https and must not point at a moving target
//	         ("/releases/latest/"); -allow-http and -allow-unpinned lift that for
//	         tests.
//
//	verify   go run tools/plugin-index/sign_plugin_index.go -verify -index index.json -pub PUBLIC.pem [-files DIR]
//	         Checks the signature, and with -files the checksum of every download
//	         that is present locally.
//
//	sign-raw go run tools/plugin-index/sign_plugin_index.go -sign-raw -index index.json -key PRIVATE.pem [-pub PUBLIC.pem]
//	         Signs a finished Dunree add-on index ("format": "dunree-addon-index",
//	         docs/plugins/addon-store.md) exactly as it is: not a byte of the index
//	         is changed, only <index>.sig is written, and the result is verified.
//	         tools/addon-store writes such an index, with the checksums and the
//	         serial number already in it, and calls this mode. -verify reads this
//	         format too.
//
// The private key path may also come from $ZORAXY_PLUGIN_INDEX_KEY. The key is
// read only to sign; its contents are never printed or logged.
//
// Draft format (also the format of the signed index):
//
//	{
//	  "format": "zoraxy-plugin-index",
//	  "version": 1,
//	  "serial": 0,
//	  "plugins": [
//	    {
//	      "IconPath": "https://example.com/icon.png",
//	      "PluginIntroSpect": { "id": "com.example.plugin", "name": "Example", "version_major": 1, ... },
//	      "Downloads": {
//	        "linux_amd64": { "url": "https://example.com/v1.0.0/plugin_linux_amd64", "sha256": "", "size": 0 }
//	      }
//	    }
//	  ]
//	}
//
// PluginIntroSpect is the output of `<plugin binary> -introspect`.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	indexFormat  = "zoraxy-plugin-index"
	indexVersion = 1
	// The Dunree add-on index (written by tools/addon-store, signed here as it is)
	addonIndexFormat  = "dunree-addon-index"
	addonIndexVersion = 1
	maxDownload       = 1 << 30
)

type download struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type entry struct {
	IconPath         string              `json:"IconPath"`
	PluginIntroSpect json.RawMessage     `json:"PluginIntroSpect"`
	Downloads        map[string]download `json:"Downloads"`
}

type index struct {
	Format    string   `json:"format"`
	Version   int      `json:"version"`
	Serial    int64    `json:"serial"`
	Generated string   `json:"generated,omitempty"`
	Plugins   []*entry `json:"plugins"`
}

func main() {
	indexPath := flag.String("index", "", "the draft index to sign, or the signed index to verify")
	outPath := flag.String("out", "", "where the signed index is written (the signature goes to <out>.sig)")
	keyPath := flag.String("key", os.Getenv("ZORAXY_PLUGIN_INDEX_KEY"), "path to the ed25519 private key of the plugin index (PKCS#8 PEM); default $ZORAXY_PLUGIN_INDEX_KEY")
	pubPath := flag.String("pub", "", "path to the ed25519 public key (SPKI PEM) used to verify")
	serial := flag.Int64("serial", 0, "serial number of this index, higher than the one before")
	filesDir := flag.String("files", "", "folder with the plugin binaries: <dir>/<plugin id>/<file name of the URL> or <dir>/<file name of the URL>")
	fetch := flag.Bool("fetch", false, "download a binary to compute its checksum when it is not found locally (network access)")
	allowHTTP := flag.Bool("allow-http", false, "accept download URLs that are not https (tests)")
	allowUnpinned := flag.Bool("allow-unpinned", false, "accept download URLs that point at a moving target such as /releases/latest/ (tests)")
	verify := flag.Bool("verify", false, "verify a signed index instead of signing")
	genkey := flag.Bool("genkey", false, "generate a key pair: -genkey PRIVATE.pem PUBLIC.pem")
	signRaw := flag.Bool("sign-raw", false, "sign a finished Dunree add-on index as it is (writes <index>.sig only): -sign-raw -index index.json -key PRIVATE.pem [-pub PUBLIC.pem]")
	flag.Parse()

	var err error
	switch {
	case *genkey:
		if flag.NArg() != 2 {
			err = errors.New("usage: -genkey PRIVATE.pem PUBLIC.pem")
		} else {
			err = generateKey(flag.Arg(0), flag.Arg(1))
		}
	case *signRaw:
		err = signRawIndex(*indexPath, *keyPath, *pubPath)
	case *verify:
		err = verifyIndex(*indexPath, *pubPath, *filesDir)
	default:
		err = signIndex(signOptions{*indexPath, *outPath, *keyPath, *pubPath, *serial, *filesDir, *fetch, *allowHTTP, *allowUnpinned})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// refuseReleaseKey keeps the plugin index key and the release key apart
func refuseReleaseKey(keyPath string) error {
	if strings.Contains(strings.ToLower(filepath.Base(keyPath)), "release-key") || strings.Contains(strings.ToLower(filepath.Base(keyPath)), "release_key") {
		return errors.New("this file is named like the release key. The plugin index has a key of its own: create one with -genkey")
	}
	if rel := os.Getenv("ZORAXY_RELEASE_KEY"); rel != "" {
		a, errA := os.Stat(keyPath)
		b, errB := os.Stat(rel)
		if errA == nil && errB == nil && os.SameFile(a, b) {
			return errors.New("this is the release key ($ZORAXY_RELEASE_KEY). The plugin index has a key of its own: create one with -genkey")
		}
	}
	return nil
}

func generateKey(privPath, pubPath string) error {
	if err := refuseReleaseKey(privPath); err != nil {
		return err
	}
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
	if err := writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (private, keep it off the proxies) and %s (public, give it to Dunree)\n", privPath, pubPath)
	return nil
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
		return nil, errors.New("no private key: pass -key or set ZORAXY_PLUGIN_INDEX_KEY")
	}
	if err := refuseReleaseKey(path); err != nil {
		return nil, err
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

func fileSum(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func fetchSum(target string) (string, int64, error) {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(target)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%s: %s", target, resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return "", 0, err
	}
	if n > maxDownload {
		return "", 0, fmt.Errorf("%s is larger than %d bytes", target, maxDownload)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func pluginID(e *entry) string {
	var spec struct {
		ID string `json:"id"`
	}
	json.Unmarshal(e.PluginIntroSpect, &spec)
	return spec.ID
}

// localFile finds the binary of a download in the -files folder
func localFile(filesDir string, id string, rawURL string) string {
	if filesDir == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	name := path.Base(u.Path)
	if name == "" || name == "." || name == "/" || strings.Contains(name, "..") {
		return ""
	}
	safeID := filepath.Base(filepath.Clean("/" + id))
	for _, candidate := range []string{filepath.Join(filesDir, safeID, name), filepath.Join(filesDir, name)} {
		if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func checkURL(rawURL string, allowHTTP, allowUnpinned bool) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a URL", rawURL)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return fmt.Errorf("%s is not an https URL", rawURL)
	}
	if !allowUnpinned && (strings.Contains(u.Path, "/releases/latest/") || strings.Contains(u.Path, "/latest/download/")) {
		return fmt.Errorf("%s points at \"latest\": what it serves changes with every release, so its checksum would stop matching. Use the URL of one release", rawURL)
	}
	return nil
}

type signOptions struct {
	indexPath, outPath, keyPath, pubPath string
	serial                               int64
	filesDir                             string
	fetch, allowHTTP, allowUnpinned      bool
}

func readIndex(p string) (*index, []byte, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}
	var idx index
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&idx); err != nil {
		return nil, nil, fmt.Errorf("%s is not a plugin index: %w", p, err)
	}
	if idx.Format != indexFormat {
		return nil, nil, fmt.Errorf("%s: \"format\" must be %q", p, indexFormat)
	}
	if idx.Version != indexVersion {
		return nil, nil, fmt.Errorf("%s: \"version\" must be %d", p, indexVersion)
	}
	return &idx, raw, nil
}

func signIndex(o signOptions) error {
	if o.indexPath == "" || o.outPath == "" {
		return errors.New("-index and -out are required")
	}
	if o.serial <= 0 {
		return errors.New("-serial is required and must be a positive number, higher than the serial of the index before")
	}
	priv, err := loadPrivate(o.keyPath)
	if err != nil {
		return err
	}
	idx, _, err := readIndex(o.indexPath)
	if err != nil {
		return err
	}
	if old, _, err := readIndex(o.outPath); err == nil && old.Serial >= o.serial {
		return fmt.Errorf("the index at %s has serial %d: -serial must be higher (Dunree refuses an index that is older than one it has seen)", o.outPath, old.Serial)
	}
	seen := map[string]bool{}
	filled := 0
	for _, e := range idx.Plugins {
		if e == nil {
			return errors.New("the index has an empty plugin entry")
		}
		id := pluginID(e)
		if id == "" {
			return errors.New("a plugin entry has no PluginIntroSpect.id")
		}
		if seen[id] {
			return fmt.Errorf("plugin %s is listed twice", id)
		}
		seen[id] = true
		if len(e.Downloads) == 0 {
			return fmt.Errorf("plugin %s has no Downloads", id)
		}
		platforms := make([]string, 0, len(e.Downloads))
		for p := range e.Downloads {
			platforms = append(platforms, p)
		}
		sort.Strings(platforms)
		for _, platform := range platforms {
			d := e.Downloads[platform]
			if err := checkURL(d.URL, o.allowHTTP, o.allowUnpinned); err != nil {
				return fmt.Errorf("plugin %s, %s: %w", id, platform, err)
			}
			d.SHA256 = strings.ToLower(strings.TrimSpace(d.SHA256))
			local := localFile(o.filesDir, id, d.URL)
			switch {
			case local != "":
				sum, size, err := fileSum(local)
				if err != nil {
					return err
				}
				if d.SHA256 != "" && (d.SHA256 != sum || (d.Size != 0 && d.Size != size)) {
					return fmt.Errorf("plugin %s, %s: the draft says sha256 %s (%d bytes), the file %s is %s (%d bytes)", id, platform, d.SHA256, d.Size, local, sum, size)
				}
				d.SHA256, d.Size = sum, size
				filled++
			case d.SHA256 != "" && d.Size > 0:
				//taken from the draft
			case o.fetch:
				sum, size, err := fetchSum(d.URL)
				if err != nil {
					return fmt.Errorf("plugin %s, %s: %w", id, platform, err)
				}
				d.SHA256, d.Size = sum, size
				filled++
			default:
				return fmt.Errorf("plugin %s, %s: no sha256 and size in the draft, no local file under -files, and -fetch is not set", id, platform)
			}
			if raw, err := hex.DecodeString(d.SHA256); err != nil || len(raw) != sha256.Size {
				return fmt.Errorf("plugin %s, %s: sha256 is not 64 hex digits", id, platform)
			}
			e.Downloads[platform] = d
		}
	}
	if len(idx.Plugins) == 0 {
		return errors.New("the index lists no plugins")
	}
	idx.Serial = o.serial
	idx.Generated = time.Now().UTC().Format(time.RFC3339)
	doc, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	sig := ed25519.Sign(priv, doc)
	derived := priv.Public().(ed25519.PublicKey)
	if o.pubPath != "" {
		want, err := loadPublic(o.pubPath)
		if err != nil {
			return err
		}
		if !derived.Equal(want) {
			return errors.New("the private key does not match the expected public key (-pub); nothing was written")
		}
	}
	if err := os.WriteFile(o.outPath, doc, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(o.outPath+".sig", sig, 0o644); err != nil {
		return err
	}
	if err := verifyWith(o.outPath, derived, ""); err != nil {
		return fmt.Errorf("self-verification failed: %w", err)
	}
	sum := sha256.Sum256(derived)
	fmt.Printf("signed %d plugins (serial %d, %d checksums computed); wrote %s and %s.sig\npublic key fingerprint: %s\n", len(idx.Plugins), idx.Serial, filled, o.outPath, o.outPath, hex.EncodeToString(sum[:8]))
	return nil
}

func verifyIndex(indexPath, pubPath, filesDir string) error {
	if indexPath == "" || pubPath == "" {
		return errors.New("-verify needs -index and -pub")
	}
	pub, err := loadPublic(pubPath)
	if err != nil {
		return err
	}
	if err := verifyWith(indexPath, pub, filesDir); err != nil {
		return err
	}
	fmt.Println("OK: signature verified")
	return nil
}

// addonIndex is what this tool needs to see of a Dunree add-on index
type addonIndex struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Serial  int64  `json:"serial"`
	Addons  []struct {
		ID        string              `json:"id"`
		Artifacts map[string]download `json:"artifacts"`
	} `json:"addons"`
}

// readAddonIndex reads a Dunree add-on index. isAddon is false (and err nil)
// when the file is some other JSON document, for example a plugin index.
func readAddonIndex(p string) (idx *addonIndex, raw []byte, isAddon bool, err error) {
	raw, err = os.ReadFile(p)
	if err != nil {
		return nil, nil, false, err
	}
	var doc addonIndex
	if json.Unmarshal(raw, &doc) != nil || doc.Format != addonIndexFormat {
		return nil, raw, false, nil
	}
	if doc.Version != addonIndexVersion {
		return nil, raw, true, fmt.Errorf("%s: \"version\" must be %d", p, addonIndexVersion)
	}
	if doc.Serial <= 0 {
		return nil, raw, true, fmt.Errorf("%s has no serial number", p)
	}
	for _, a := range doc.Addons {
		if a.ID == "" {
			return nil, raw, true, fmt.Errorf("%s: an add-on has no id", p)
		}
		if len(a.Artifacts) == 0 {
			return nil, raw, true, fmt.Errorf("%s: add-on %s has no artifacts", p, a.ID)
		}
		for platform, d := range a.Artifacts {
			if sum, err := hex.DecodeString(d.SHA256); err != nil || len(sum) != sha256.Size || d.Size <= 0 || d.URL == "" {
				return nil, raw, true, fmt.Errorf("%s: add-on %s, %s: no url, checksum or size", p, a.ID, platform)
			}
		}
	}
	return &doc, raw, true, nil
}

// signRawIndex signs a finished add-on index without rewriting it
func signRawIndex(indexPath, keyPath, pubPath string) error {
	if indexPath == "" {
		return errors.New("-sign-raw needs -index")
	}
	idx, raw, isAddon, err := readAddonIndex(indexPath)
	if err != nil {
		return err
	}
	if !isAddon {
		return fmt.Errorf("%s is not a Dunree add-on index (\"format\" must be %q). A plugin index draft is signed without -sign-raw", indexPath, addonIndexFormat)
	}
	priv, err := loadPrivate(keyPath)
	if err != nil {
		return err
	}
	derived := priv.Public().(ed25519.PublicKey)
	if pubPath != "" {
		want, err := loadPublic(pubPath)
		if err != nil {
			return err
		}
		if !derived.Equal(want) {
			return errors.New("the private key does not match the expected public key (-pub); nothing was written")
		}
	}
	if err := os.WriteFile(indexPath+".sig", ed25519.Sign(priv, raw), 0o644); err != nil {
		return err
	}
	if err := verifyWith(indexPath, derived, ""); err != nil {
		return fmt.Errorf("self-verification failed: %w", err)
	}
	sum := sha256.Sum256(derived)
	fmt.Printf("signed %d add-ons (serial %d); wrote %s.sig\npublic key fingerprint: %s\n", len(idx.Addons), idx.Serial, indexPath, hex.EncodeToString(sum[:8]))
	return nil
}

func verifyWith(indexPath string, pub ed25519.PublicKey, filesDir string) error {
	if _, raw, isAddon, err := readAddonIndex(indexPath); isAddon {
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(indexPath + ".sig")
		if err != nil {
			return err
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, raw, sig) {
			return errors.New("bad signature over " + indexPath)
		}
		return nil
	}
	idx, raw, err := readIndex(indexPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(indexPath + ".sig")
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, raw, sig) {
		return errors.New("bad signature over " + indexPath)
	}
	if idx.Serial <= 0 {
		return errors.New("the index has no serial number")
	}
	for _, e := range idx.Plugins {
		id := pluginID(e)
		for platform, d := range e.Downloads {
			if raw, err := hex.DecodeString(d.SHA256); err != nil || len(raw) != sha256.Size || d.Size <= 0 {
				return fmt.Errorf("plugin %s, %s: no checksum or size", id, platform)
			}
			if local := localFile(filesDir, id, d.URL); local != "" {
				sum, size, err := fileSum(local)
				if err != nil {
					return err
				}
				if sum != d.SHA256 || size != d.Size {
					return fmt.Errorf("checksum mismatch for %s (%s, %s)", local, id, platform)
				}
			}
		}
	}
	return nil
}
