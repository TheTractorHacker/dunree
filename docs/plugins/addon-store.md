# The Dunree add-on store

An add-on (the admin interface calls it an app, the code a plugin) is a program that Dunree starts next to
itself. The add-on store is where Dunree finds add-ons to install: one or more **sources**, each of which is an
**index** that lists add-ons and where their program files are.

This page describes what Dunree does by default, the kinds of source, and the **Dunree add-on index, format
version 1**. How an index is built and published is in [publishing-addons.md](publishing-addons.md).

## What Dunree does by default: nothing

Dunree ships **without a store source**. Until an administrator adds one, the store fetches nothing and opens no
connection, and **System > App Store** shows "No add-on store configured" with the three ways to add a source:

| Choice | What it is | Network |
|---|---|---|
| **Dunree add-on store** | The store Foley IT publishes. One click. | the address in `DunreeAddonStoreIndexURL` |
| **Custom index URL** | Any `index.json` on the web: your organisation's, a community's. | the address you enter |
| **Local folder** | A folder on the server Dunree runs on that holds `index.json` and the program files. | none |

The address of the Dunree add-on store is written down in exactly one place, the constant
`DunreeAddonStoreIndexURL` in `src/mod/plugins/store_sources.go`, next to `DunreeAddonStorePublicKey` (the public
half of the key the store is signed with). **Both are placeholders that the owner sets before the store opens.**
While the address is empty or its host is a reserved placeholder name (`.example`, `.invalid`, `.test`), the
one-click choice is shown as "not open yet", cannot be chosen, and Dunree never contacts it.

Sources are stored in the database (table `plugins`, key `custom_store_urls`). Removing a source stops every
fetch from it. Add-ons that were installed from it keep running; they get no updates until the source is added
again, and the App Store page says so.

### Installations that existed before Dunree

Zoraxy, which Dunree is derived from, had the plugin store of the Zoraxy project built in. That store is a third <!-- rebrand:keep -->
party to Dunree. An installation that existed before its first Dunree start keeps it, so that nothing changes
silently: at that first start the address is written into the list of sources **once**. It is shown as
**"Zoraxy community store (third party)"**, the log says so, and it can be removed like any other source. Once <!-- rebrand:keep -->
removed it does not come back. A new installation never gets it. (The address is the constant
`LegacyZoraxyStoreIndexURL`; setting it to `""` switches the migration off.) <!-- rebrand:keep -->

## The three index formats Dunree reads

| `schema` in the source status | Format | Checksums | Signature |
|---|---|---|---|
| `dunree-addon-index/1` | **Dunree add-on index v1**, this page | required | detached, ed25519 |
| `zoraxy-plugin-index/1` | signed plugin index of the fork (`docs/plugins/reliability-plan.md`, item 2.4) | required | detached, ed25519 |
| `list` | the list of the Zoraxy plugin store (a JSON array) | none | none <!-- rebrand:keep --> |

All three end up as the same store entries, so install, update, health check and rollback are identical.

## Dunree add-on index, format version 1

One JSON document, conventionally `index.json`, UTF-8, at most 8 MB:

```json
{
  "format": "dunree-addon-index",
  "version": 1,
  "serial": 12,
  "generated": "2026-11-24T12:00:00Z",
  "store": { "name": "Dunree add-on store", "publisher": "Foley IT", "url": "https://..." },
  "addons": [
    {
      "id": "ie.foleyit.geo-block",
      "name": "Geo block",
      "publisher": "Foley IT",
      "description": "Blocks or allows visitors by country.",
      "homepage": "https://...",
      "licence": "AGPL-3.0-only",
      "version": "1.2.0",
      "api_version": 1,
      "min_host_version": "1.0.0",
      "type": "router",
      "categories": ["Security"],
      "featured": false,
      "permissions": [
        { "method": "GET", "endpoint": "/plugin/api/access/list", "reason": "Reads the access rules" }
      ],
      "changelog": [
        { "version": "1.2.0", "date": "2026-11-20", "notes": "IPv6 ranges" },
        { "version": "1.1.0", "date": "2026-10-02", "notes": "First public release" }
      ],
      "icon": "addons/ie.foleyit.geo-block/icon.png",
      "screenshots": ["addons/ie.foleyit.geo-block/screenshots/rules.png"],
      "artifacts": {
        "linux_amd64":   { "url": "addons/ie.foleyit.geo-block/1.2.0/geo-block_linux_amd64",       "sha256": "…64 hex…", "size": 9412608 },
        "linux_arm64":   { "url": "addons/ie.foleyit.geo-block/1.2.0/geo-block_linux_arm64",       "sha256": "…", "size": 9109504 },
        "windows_amd64": { "url": "addons/ie.foleyit.geo-block/1.2.0/geo-block_windows_amd64.exe", "sha256": "…", "size": 9632256 },
        "darwin_arm64":  { "url": "addons/ie.foleyit.geo-block/1.2.0/geo-block_darwin_arm64",      "sha256": "…", "size": 9245184 }
      }
    }
  ]
}
```

### Top level

| Field | Required | Meaning |
|---|---|---|
| `format` | yes | exactly `dunree-addon-index` |
| `version` | yes | exactly `1`. Dunree refuses a version it does not know instead of guessing |
| `serial` | yes | a positive number that goes up with every published index. Dunree remembers the highest serial it has seen with a valid signature per source and reports an older one as **replayed** |
| `generated` | no | RFC 3339 time, information only |
| `store` | no | name, publisher and home page of the store. Information for people: trust comes from the signature, never from these fields |
| `addons` | yes | the add-ons, at most 5000 |

### An add-on

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique ID, 1 to 128 letters, digits, `.`, `-`, `_`; starts with a letter or digit; no `..`. Use your domain in reverse. It must be the ID the program declares with `-introspect` |
| `name` | yes | display name, at most 100 characters. Also the name of the folder the add-on is installed into |
| `publisher` | yes | who publishes the add-on, at most 100 characters |
| `version` | yes | `major.minor.patch`. A pre-release suffix (`-beta.1`) is allowed and not compared |
| `artifacts` | yes | the program files, one per platform, see below |
| `api_version` | no | the plugin contract the add-on was built for (`docs/plugins/contract.md`). `0` or absent: the contract from before versions were counted |
| `min_host_version` | no | the oldest Dunree that can run it, `major.minor.patch`. An older Dunree lists the add-on and **refuses to install it, in every verification mode** |
| `licence` | no in the format, required by `tools/addon-store` | SPDX identifier of the licence the add-on is published under. `license` is accepted as a spelling |
| `description`, `homepage` | no | text (at most 4000 characters) and a web address |
| `type` | no | `router` (can handle requests of the sites it is assigned to) or `utility` (default) |
| `categories` | no | the first one is the category the App Store files the add-on under |
| `featured` | no | shown in the "Featured app" card of the App Store |
| `permissions` | no | the Dunree API endpoints the add-on asks for: `method`, `endpoint`, `reason`. Shown before the install. What the installed program declares is what the administrator approves (`docs/plugins/contract.md`), so a permission that is missing here is not granted silently |
| `changelog` | no | `version`, `date`, `notes`, newest first |
| `icon`, `screenshots` | no | pictures, loaded by the browser of the administrator. Only web addresses are shown |

An entry that breaks one of these rules is **left out** (the source status and the log say which one and why);
the rest of the index stays usable.

### Artifacts and platforms

`artifacts` maps a platform to one program file:

* The key is `<os>_<arch>` as Go names them (`GOOS`, `GOARCH`): `linux_amd64`, `linux_arm64`, `linux_arm`,
  `linux_riscv64`, `windows_amd64`, `windows_arm64`, `darwin_amd64`, `darwin_arm64`, `freebsd_amd64`, ...
  Dunree also accepts `/` or `-` as the separator and the common aliases `x86_64`, `aarch64`, `macos`.
* `url`: where the file is. **Absolute** (`https://...`) or **relative to the address of the index**. Relative
  addresses are what `tools/addon-store` writes by default: the whole folder can then be served from any address,
  mirrored, or read from a local folder, without touching the signed index.
* `sha256` (64 hex digits) and `size` (bytes) of the file. Both are required.

**Selection:** Dunree installs the artifact whose key is exactly its own `GOOS_GOARCH`, and nothing else. There
is no fallback to another architecture (no amd64 build on an arm64 machine, no emulation guesses). An add-on
without a build for the server is listed with a note and cannot be installed.

**Windows:** the artifact for a `windows_*` platform is an `.exe`, and Dunree stores the program in the plugin
folder with the extension `.exe` whatever the artifact is called.

**Where a file may be:** an index on the web may only name web addresses. It can never make Dunree read a file of
the server: a `file:` address in it is dropped, and an install refuses a `file:` address unless the entry came
from a **Local folder** source and the file is inside that source's own folder (whatever the index format; the
reading code checks again that the file is inside a configured local source). An index in a local folder may name
files inside its own folder, or web addresses, never files of another local source.

### Signature

The signature is **detached**: `index.json.sig` next to the index holds the raw 64 bytes of an ed25519 signature
over the exact bytes of `index.json`. It is the mechanism of the signed plugin index, with the same key:

* The key is the **plugin index key**, created with `go run tools/plugin-index/sign_plugin_index.go -genkey`.
  It is never the key Dunree releases are signed with; Dunree refuses the release key as an index key.
* Dunree holds only the public half: **Plugin Manager > Plugin safety settings**, or the start flag
  `-plugin_index_pubkey`. One key is configured for all sources. Choosing the Dunree add-on store configures
  `DunreeAddonStorePublicKey` when it is set and no key is configured yet.

The verification mode is the existing setting (**Plugin safety settings > Signature checking**):

| Mode | Index | Program file |
|---|---|---|
| `off` | nothing is fetched or compared; state `unchecked` | not compared |
| `warn` (default) | every problem is logged, shown in the source list and written to the audit log; nothing is refused | a file that does not match `sha256`/`size` is installed, with a warning and an audit entry |
| `enforce` | only add-ons of an index with a valid signature of the configured key, that is not older than the last one seen, are installed or updated. While a source serves something else, the add-ons of its last valid index stay on offer | a file that does not match is refused; the download is cut off at `size` |

States of a source: `signed`, `no_key`, `missing` (no `.sig`), `bad_signature`, `replayed`, `unchecked`. A Dunree
add-on index is always expected to be signed: without a signature file it is `missing`, not "unsigned".

Independent of the mode: the minimum host version, the rule that a downloaded program may not declare the ID of
another installed plugin, and the limit on the download size.

### Install, update, rollback

Unchanged, and the same for every format (`docs/plugins/reliability-plan.md`, item 2.5): the file is downloaded
into a staging folder, compared with the index, run once with `-introspect` (as the plugin user when one is
configured), and only then moved into place. A freshly installed add-on is not started until it is enabled. An
update keeps the previous program file and checks that the new one answers; a failed update can be rolled back
with one click, or automatically when that setting is on. Updates only come from the source the add-on was
installed from.

## API

| Route | |
|---|---|
| `GET /api/plugins/store/setup` | `{configured, sources, platform, dunreeStore: {url, ready, added}, orphaned: [{source, kind, plugins}]}`. Read-only, no network |
| `GET /api/plugins/store/sources` | each source now also has `kind` (`builtin`, `dunree`, `custom`, `local`, `zoraxy-community`), `label`, `folder` and `schema` |
| `POST /api/plugins/store/sources/add` | `url=...` as before, or `kind=dunree`, or `kind=local&folder=...` |
| `GET /api/plugins/store/list` | entries of an add-on index carry `Addon`: publisher, licence, categories, changelog, screenshots, platforms, `minHostVersion`, `incompatible`, `note` |

## Known limits

* **The Dunree add-on store does not exist yet.** `DunreeAddonStoreIndexURL` is a placeholder and
  `DunreeAddonStorePublicKey` is empty; the owner sets both. Until then the one-click choice is disabled.
* **One public key for all sources.** A custom source signed with another key shows as `bad_signature` (refused
  under `enforce`). Per-source keys are not implemented.
* **No key rotation inside the format.** Replacing the configured key revokes what the old key signed; there is
  no signed "next key" entry.
* **One version per add-on.** The index offers the current version of each add-on. Older program files stay in
  the store folder, but Dunree cannot install an older version from the index (rollback uses the copy it kept).
* **Exact platform match only.** No universal macOS selection, no `GOARM` or `GOAMD64` level, no libc (musl or
  glibc) distinction: build static Go binaries.
* **Pictures of a local folder are not shown.** The browser cannot load files of the server, so add-ons of a
  local folder use the default icon and show no screenshots.
* **A local folder must be readable by the Dunree process**, and it is read on the server Dunree runs on, not on
  the machine of the browser. In Docker it has to be mounted into the container.
* **The minimum host version is only compared when the host version is `major.minor.patch`.** A development
  build with another version string installs with a note instead.
* **An icon that cannot be downloaded fails the install** (as it does for every index format).
* **The page is still called "App Store"** in the navigation; "add-on" is used for the store and its index.
* **Existing installations keep contacting the Zoraxy community store** until an administrator removes that <!-- rebrand:keep -->
  source. That is deliberate (nothing changes silently) and visible; see above for how to switch the migration off.
