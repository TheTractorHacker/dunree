# Publishing an add-on (how Foley IT runs the Dunree add-on store)

The store is a folder of static files: an index, its signature, a catalogue page and the program files. It is
built by `tools/addon-store` and can be served by any static web server, or read directly as a **Local folder**
source. There is no server-side code and no account system. The format of the index is in
[addon-store.md](addon-store.md).

Anyone can run a store the same way; nothing here is specific to Foley IT except the key and the address.

## 0. Once: the key

The index is signed with the **plugin index key**, a key of its own. It is not the release key.

```sh
go run tools/plugin-index/sign_plugin_index.go -genkey addon-index.pem addon-index.pub
```

* `addon-index.pem` is the private key. Keep it off every proxy and out of the repository. Whoever holds it
  decides which programs a Dunree in `enforce` mode accepts.
* `addon-index.pub` is the public key. Administrators give it to Dunree (**Plugin Manager > Plugin safety
  settings**, or the start flag `-plugin_index_pubkey`).

For the official store the owner then sets, in `src/mod/plugins/store_sources.go` and nowhere else:

```go
const (
    DunreeAddonStoreIndexURL  = "https://<the real host>/index.json"
    DunreeAddonStorePublicKey = "<contents of addon-index.pub, or the 32 bytes in base64>"
)
```

Until that is done the one-click choice "Dunree add-on store" stays disabled in every build. The test
`TestDunreeStoreAddressIsDefinedOnce` (`src/mod/upstreamguard`) fails if the address is written anywhere else.

## 1. One folder per add-on

```
addons/
  geo-block/
    addon.json
    icon.png                      optional: png, jpg, webp or gif, at most 4 MB (no svg)
    screenshots/rules.png         optional
    artifacts/
      geo-block_linux_amd64
      geo-block_linux_arm64
      geo-block_windows_amd64.exe
      geo-block_darwin_arm64
```

`addon.json`:

```json
{
  "id": "ie.foleyit.geo-block",
  "name": "Geo block",
  "publisher": "Foley IT",
  "description": "Blocks or allows visitors by country.",
  "homepage": "https://example.org/geo-block",
  "licence": "AGPL-3.0-only",
  "version": "1.2.0",
  "api_version": 1,
  "min_host_version": "1.0.0",
  "type": "router",
  "categories": ["Security"],
  "permissions": [{ "method": "GET", "endpoint": "/plugin/api/access/list", "reason": "Reads the access rules" }],
  "changelog": [{ "version": "1.2.0", "date": "2026-11-20", "notes": "IPv6 ranges" }],
  "icon": "icon.png",
  "screenshots": ["screenshots/rules.png"]
}
```

* `id`, `name`, `publisher`, `version` and `licence` are required. `id` and `version` must be what the program
  prints with `-introspect`; `name` becomes the install folder.
* Without `"artifacts"` every file in `artifacts/` named `*_<os>_<arch>` (plus `.exe` for Windows) is taken. To
  name them yourself: `"artifacts": {"linux_amd64": "artifacts/geo-block_linux_amd64"}`, or
  `{"file": "...", "sha256": "..."}` to have the tool compare the file with a checksum you got from your build.
* A field the tool does not know is an error, so a typo cannot silently drop something from the store.

Build the program files as static binaries, one per platform:

```sh
for target in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do
  os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -o "addons/geo-block/artifacts/geo-block_${os}_${arch}${ext}" .
done
```

## 2. Check

```sh
go run tools/addon-store/main.go -in addons -check
```

Nothing is written. Every add-on is verified, and one failure stops the whole run, so a store never goes out
half-checked. What is verified:

* the manifest fields (above);
* every artifact is a regular file inside the add-on folder, not empty, at most 1 GB;
* a Windows artifact ends in `.exe`, no other one does;
* every artifact is a program file **for the platform it is listed under**: ELF for Linux and the BSDs, PE for
  Windows, Mach-O for macOS, with the CPU type of the architecture (catches a file under the wrong key;
  `-skip-binary-check` turns this off for exotic targets);
* a checksum given in the manifest matches the file;
* with `-introspect`: the artifact for the machine the tool runs on is started with `-introspect`, and the ID
  and version it prints are compared with the manifest. This runs the program, so use it on the build machine.

## 3. Build and sign

```sh
go run tools/addon-store/main.go -in addons -out site \
    -key /secure/addon-index.pem -pub addon-index.pub \
    -store-name "Dunree add-on store" -publisher "Foley IT"
```

Run it from the repository root. It writes:

```
site/index.json          the add-on index, format version 1
site/index.json.sig      the detached signature
site/index.pub           the public key (only with -pub)
site/index.html          the catalogue: searchable, one file, loads nothing from another host
site/addons/<id>/<version>/<file>          the program files
site/addons/<id>/icon.png, screenshots/    pictures
```

* **Signing** is done by `tools/plugin-index/sign_plugin_index.go -sign-raw`, which `addon-store` starts. The
  generator never opens the private key; it passes the path on (or leaves it to `$ZORAXY_PLUGIN_INDEX_KEY`). The
  new index is written and signed next to the published one and moved into place only when the signature
  verifies, so a failed run leaves `index.json` and `index.json.sig` as they were. `-signer` takes an already
  built signer instead of `go run`.
* **The serial** goes up by one from the index that is already in `site/` (or pass `-serial N`). It never goes
  down: Dunree reports an older index as replayed. So **keep `site/` between runs**, or pass the next serial.
* **A published version is never replaced.** The version is part of the address of a program file, and the tool
  refuses to put other content at an address it already published: raise `"version"` instead. Older versions
  stay in `site/`, so installed copies and mirrors that still hold an older index keep working.
* **Addresses are relative** to `index.json` by default, so `site/` works at any address and as a local folder.
  `-base-url https://host/path/` writes absolute addresses instead.
* `-unsigned` writes no signature. Dunree shows such an index as `missing` and refuses it under `enforce`. For
  tests and private folders only.

Verify what was written at any time:

```sh
go run tools/plugin-index/sign_plugin_index.go -verify -index site/index.json -pub addon-index.pub
```

## 4. Publish

Copy `site/` to the web server (`rsync -a site/ host:/var/www/addons/`). Order matters when files are copied one
by one: program files first, `index.json` and `index.json.sig` last and together. Serve it over https, with no
rewriting of the files: the signature is over the exact bytes of `index.json`.

Then check it from a Dunree: **System > Add-ons > Sources > Custom index URL**, with signature checking set to
`enforce`. The source must show **Signed**.

To try a build without a web server, add `site/` as a **Local folder** source.

## 5. Withdraw an add-on or a version

Remove the add-on folder from `addons/` and build again (to withdraw one version only, publish a fixed version with a higher number instead). The
new index, with a higher serial, no longer lists it, and Dunree in `enforce` mode refuses the older index. Then
delete its files from `site/addons/`. An installed copy is not removed from proxies: say so in the changelog of
the store, and publish a fixed version under the same `id` so that the update reaches them.

If the private key is lost or exposed: create a new pair, sign with it, and give administrators the new public
key. Replacing the key in Dunree revokes everything the old key signed.

## Known limits

* One version per add-on in the index; no channels (stable / beta).
* The tool does not build, scan or sandbox anything: it publishes the files it is given. Review is a human step
  before `-key` is used.
* The binary check reads the file header only. It does not prove that a program is a Dunree add-on, unless
  `-introspect` is used for the platform of the build machine.
* Replacing `index.json` and `index.json.sig` on the web server is two file operations. A Dunree that syncs
  between them sees `bad_signature` once and keeps the add-ons of the last valid index (under `enforce`).
* No download statistics, ratings or accounts: the store is static files.
* The key and environment variable of the signer still carry the old name (`$ZORAXY_PLUGIN_INDEX_KEY`).
