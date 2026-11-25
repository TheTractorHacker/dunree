# Dunree rebrand: inventory and plan

Status: plan only, nothing renamed yet. Machine-readable version: `tools/rebrand/policy.json`.
Inventory taken with `git grep` on branch `dev` at 65d9e0ac (2026-11-24). Counts are matches / files and
are approximate (one regex per class, some overlap between classes).

**Product:** Dunree (`dunree`, `DUNREE`), published by Foley IT, AGPL-3.0, "Reverse proxy and web gateway".
Based on Zoraxy v3.3.6 by tobychui and imuslab. First version: v1.0.0-beta.1.
**Module root:** `github.com/foleyit/dunree`. This is a placeholder and lives in one variable (`MODULE_ROOT` in
policy.json). Nothing is pushed or renamed on GitHub.

Totals: about 8,000 case-insensitive matches of `zoraxy|imuslab|tobychui` in 1,241 tracked files.
`imuslab` appears 1,249 times, and 1,235 of those are the Go module path `imuslab.com/zoraxy`. They are not
attribution. `tobychui` appears 276 times: copyright headers, `Author:` lines, changelog and issue links.

## 1. Decision classes

| Class | Meaning |
|---|---|
| **R — rename** | Rename fully. No legacy path. Covers internal code, docs, UI text, file names and build output. |
| **D — dual** | Dunree name is primary. The old name is still accepted on input. On output it is also sent, behind the setting **"Also send legacy Zoraxy names"** (`legacy_emit`, default ON for v1, to be removed in v2). |
| **D+ — dual, always** | Like D, but the legacy output does not depend on the setting during v1, because turning it off would break a third-party plugin built against the old SDK and nothing would show why. The setting only controls when this ends (v2). |
| **F — frozen** | The string must never change. It is a key-derivation salt, a signed-format identifier or a persisted ID. Changing it would invalidate sessions, signatures or cluster keys. The code may still get a new constant name; the bytes stay. |
| **K — keep, attribution** | Stays as it is: copyright, licence headers, NOTICE, CHANGELOG history, issue and PR references, git history. |
| **N — neutral prefix** | Short internal prefixes (`zx-`, `zr_`, `zxStore`). They are not the product name and are not visible to users. Keep them (see 3.4). |
| **C — configurable** | External URL that must become a setting, flag or build variable. It may not point to upstream by default for new installs. |

"Legacy setting" in the table below always means `legacy_emit` (one global switch, stored in the settings
table, shown under Settings > Advanced > Compatibility, logged at startup when ON).

## 2. Classification table

WP = work package (section 4). Each row needs an automated test, and each D/D+ row also needs a "known
limits" line in `docs/ux/changes.md` under the new section "Dunree rebrand".

| # | Surface | Count | Decision | Legacy behaviour | WP | Test |
|---|---|---|---|---|---|---|
| 1 | Go module path `imuslab.com/zoraxy` (src/go.mod, every import) | 1235 / 527 | R → `${MODULE_ROOT}` | none (compile-time only) | WP1 | `go build ./... && go vet ./...`; test asserts `go.mod` module == policy `MODULE_ROOT` |
| 2 | Secondary modules: `imuslab.com/zoraxy/docs`, `/benchmark`, `aroz.org/zoraxy/test_server`, `aroz.org/zoraxy/websocket-echo`, `zoraxy-plugin-check`, `tools/nt6.1_go_mod/*.go.mod` | 9 files | R → `${MODULE_ROOT}/docs`, `.../tools/<name>` | none | WP1 | build each module; nt6.1 files: a grep test that the module line matches `MODULE_ROOT` |
| 3 | Example plugin modules `example.com/zoraxy/<name>` | 15 | R → `example.com/dunree/<name>` | none | WP6 | `example/plugins/build_all.sh` builds every example |
| 4 | Go identifiers (`ZoraxyPort`, `collectZoraxyMetrics`, `IsZoraxyName`, `zoraxyPlugin` alias, ...) | ~900 | R | exported SDK identifiers: see row 22 | WP1 | compile |
| 5 | `SYSTEM_NAME = "Zoraxy"` (def.go) | 1 + 7 uses | R → `"Dunree"`, **but** it is also the admin session cookie name (start.go:144) | the admin session cookie gets its own constant `ADMIN_SESSION_COOKIE`. It stays `"Zoraxy"` on installs that already have users (D: read `Dunree`, fall back to `Zoraxy`, re-issue as `Dunree`) | WP2 | test: log in with an old `Zoraxy` cookie, request succeeds and response sets `Dunree`; renaming SYSTEM_NAME does not log anyone out |
| 6 | `SYSTEM_VERSION = "3.3.6"` | 19 uses | split: `PRODUCT_VERSION = "1.0.0-beta.1"` and `COMPAT_VERSION = "3.3.6"` (the Zoraxy base) | `COMPAT_VERSION` keeps driving `conf/version` / `update.RunConfigUpdateInDir`, the legacy plugin field `zoraxy_version`, confpack `zoraxyVersion`, and `upstream=` in the release header. Everything that is shown to users or reported as the product version uses `PRODUCT_VERSION` | WP2 | test: an existing conf with `version=336` runs no migration and is not rewritten to `100`; plugin gets `zoraxy_version=3.3.6`, `dunree_version=1.0.0-beta.1` |
| 7 | UI text "Zoraxy" (src/web, not locales) | 540 / 92 | R | none | WP4 | ui-smoke + a grep test: no `Zoraxy` in src/web outside the attribution allow-list |
| 8 | `<title>` / `document.title` (index, login, reset, apidocs; index.html:488) | 6 | R → `… \| Dunree` | none | WP4 | ui-smoke title assertion |
| 9 | i18n: en.json keys are the English text (`"…Zoraxy…": "…"`), plus other locales | 1183 / 10 | R, **keys and values renamed in the same step in every locale** | none. If only the HTML changes, every translated string with the name falls back to English without any error | WP4 | `tools/i18n` test: every key used in src/web exists in en.json; no key/value pair holds `Zoraxy` except the attribution keys |
| 10 | Attribution in UI: "© 2021 – year tobychui. Licensed under AGPL", "Zoraxy is developed by tobychui for imuslab" | 4 + locales | K + reword | becomes "Dunree © Foley IT. Based on Zoraxy © tobychui / imuslab. AGPL-3.0". tobychui and imuslab stay named, and they are not shown as authors of Dunree | WP4 | grep test: `tobychui` still present in the About and footer templates |
| 11 | Response headers to visitors: `X-Zoraxy-Ref`, `X-Zoraxy-Captcha-Reason`, `X-Zoraxy-Error-Page` | 17 | D | `X-Dunree-*` always. `X-Zoraxy-*` also sent while `legacy_emit` is ON | WP3 | header test with the setting ON (both sent) and OFF (only Dunree) |
| 12 | Headers to upstreams and identity values: `X-Forwarded-Server: zoraxy-<uuid>`, `x-proxy-by: zoraxy/<v>`, UA rewrite `Zoraxy/<v>` (dpcore.go:490) | 4 | D (value) | a value cannot be sent twice. With `legacy_emit` ON: `dunree-<uuid>`, `dunree/<v> (zoraxy-compatible)`, UA `Dunree/<v> Zoraxy/<compat>`. A substring match on `zoraxy` at the upstream keeps working. OFF: Dunree only | WP3 | dpcore test that checks both values for each setting |
| 13 | Outbound User-Agents (`Zoraxy-HealthCheck`, `-Webhook`, `-Notify`, `-Sablier`, `-HTTPTest`, `-blocklist-import`, `zoraxy-updater`, `zoraxy-cluster/`, `zoraxy-fleet/`, `zoraxy-wsproxy/1.1`, `zoraxy-aiassist/1`, `zoraxy-crowdsec-bouncer/1.0`) | ~14 | D (value) | `Dunree-HealthCheck` and so on. With `legacy_emit` ON the old token is appended (`Dunree-HealthCheck (Zoraxy-HealthCheck)`), so an allow-list at the upstream that matches it keeps working | WP3 | table test over every UA constant |
| 14 | Headers to plugins: `X-Zoraxy-Plugin-Token`, `X-Zoraxy-RequestID`, `X-Zoraxy-Capture`, `X-Zoraxy-URI`, `X-Zoraxy-Ui-Isolated`, `X-Zoraxy-Event-Type` | ~210 | **D+** | `X-Dunree-*` and `X-Zoraxy-*` are both always sent in v1, because the old SDK only reads the old names and Go's `Header.Get` is case-insensitive. The new SDK reads Dunree first, then Zoraxy | WP5 | load `testdata/sdk-1.0.0` and `sdk-1.1.0` plugins on the new host: filter, capture, sniff, UI, events and invoke-token checks pass |
| 15 | Headers from plugins / plugin UI: `X-Zoraxy-Csrf` | 39 | D (input) | host accepts `X-Dunree-Csrf` or `X-Zoraxy-Csrf` | WP5 | CSRF test with each header |
| 16 | `<meta name="zoraxy.csrf.Token">` in admin pages and in plugin UIs | 89 / 70 | D+ | admin pages render both `dunree.csrf.Token` and `zoraxy.csrf.Token`. A third-party plugin UI may read the parent page's meta tag | WP4 | ui-smoke: both meta tags present; old-SDK plugin UI test |
| 17 | Webhook headers `X-Zoraxy-Event`, `X-Zoraxy-Signature`, `X-Zoraxy-Timestamp` | 6 | D | `X-Dunree-*` always, plus legacy when ON. The signature value is the same for both: same HMAC input, and the header name is not part of the signed material | WP3 | webhook test: a receiver checking either header verifies |
| 18 | Cluster/fleet headers `X-Zoraxy-Snapshot-Version`, `X-Zoraxy-Fleet-Hash` | 4 | **D+** | both sent, both accepted. A mixed cluster (Zoraxy-fork primary, Dunree follower, or the reverse) is normal during a rolling upgrade | WP3 | cluster test: old-header primary with new follower, and the reverse |
| 19 | Internal context key `X-Zoraxy-Internal-Ref` (blockref.go:24) | 1 | R | never leaves the process | WP3 | existing blockref tests |
| 20 | Public paths `/.zoraxy/health`, `/.zoraxy/healthz`, `/.zoraxy/captcha/verify`, `/.zoraxy/captcha/altcha` | 43 / 19 | D (input) | `/.dunree/…` is served and used by the built-in pages. `/.zoraxy/…` is always served in v1 (monitors and custom captcha templates call it) and logged once per day per path as legacy use | WP3 | route test: both prefixes answer the same way; a custom template that posts to `/.zoraxy/captcha/verify` still passes |
| 21 | Cookies: `zoraxy_csrf`, `zoraxy_captcha_session`, `zoraxy_rule_challenge`, `zoraxy_waf_challenge` | 4 | D | new cookies are set as `dunree_*`. An old cookie is accepted until it expires, then dropped (not re-set). `zr_xauth_session` / `zr_sticky_session`: N (keep) | WP2 | test per cookie: an old-name cookie is honoured once and replaced by the new name |
| 22 | Plugin SDK package `zoraxy_plugin` (src/mod/plugins/zoraxy_plugin, 119 copies in example/ and docs/) | 536 / 254 | R → package `dunree_plugin` at `src/mod/plugins/dunree_plugin`. `src/mod/plugins/zoraxy_plugin` stays as a thin, deprecated copy of the last 1.x SDK for plugin authors who still need it | old plugins are binaries: the host contract matters, not the Go package (rows 14, 23, 24). `testdata/sdk-1.0.0` and `sdk-1.1.0` are **frozen fixtures, never renamed** | WP5 | contract test builds `testdata/sdkplugin` with each old SDK and with `dunree_plugin` |
| 23 | Configure payload fields `zoraxy_port`, `runtime_const.zoraxy_version`, `runtime_const.zoraxy_uuid` | ~140 | **D+** | the host sends both sets of fields: `dunree_port`/`dunree_version`/`dunree_uuid` and the `zoraxy_*` ones (unknown JSON fields are ignored by both SDKs). `zoraxy_version` = `COMPAT_VERSION` (3.3.6), so an old plugin that checks `>= 3.x` keeps working. The new SDK reads `dunree_*` first, then `zoraxy_*` | WP5 | JSON golden test of ConfigureSpec; old SDK reports port and version correctly |
| 24 | Introspect / contract (`-introspect`, `-configure=`, `-configure-stdin`, `api_version`, `api_version_min/max`) | — | unchanged | the flags have no name in them. `api_version` 1 is the contract. The Dunree SDK declares the same contract (1), with `sdk_flavor:"dunree"` added only for information | WP5 | existing phase2_contract tests |
| 25 | Plugin store index format `"zoraxy-plugin-index"`, `store_verify.go` | 4 | F (accept) + D | the verifier accepts `zoraxy-plugin-index` and `dunree-plugin-index`. `sign_plugin_index` emits `dunree-plugin-index`, or the old one with `-legacy-format` | WP5 | signed-index test for both formats; replay serials are kept per URL |
| 26 | Plugin store URL `raw.githubusercontent.com/aroz-online/zoraxy-official-plugins/.../index2.json` (start.go:480) | 1 | C | new setting `plugin_store_urls`. **Existing installs:** at the first Dunree start the current hard-coded list is written into the setting, so behaviour does not change and the source shows in the UI as "Zoraxy community store (third party)". **New installs:** `${STORE_INDEX_URL}` (Dunree add-on store, empty until it exists, so no store call is made) | WP5 | test: upgrade keeps the aroz URL; fresh install makes no request to aroz-online |
| 27 | Prometheus metrics `zoraxy_*` (35 names, metrics.go, mod/metrics, mod/dynamicproxy) | 84 / 8 | D | `dunree_*` always. Every family is also emitted as `zoraxy_*` while `legacy_emit` (or its own `metrics_legacy_names`, defaulting to the same value) is ON. Realm `zoraxy-metrics` → `dunree-metrics` | WP3 | exposition test: both families with identical values; OFF gives only `dunree_*`; scrape-size note in known limits |
| 28 | Env vars to hooks: `ZORAXY_EVENT`, `_SOURCE`, `_SUBJECT`, `_DOMAINS`, `_CA`, `_ERROR`, `_TIME`, `_EXPIRY`, `_DAYS_LEFT`, `_EVENT_JSON` | 10 | D | the hook command gets `DUNREE_*`, plus `ZORAXY_*` while `legacy_emit` is ON | WP3 | notify/command test of the env |
| 29 | Env vars read by the binary: `ZORAXY_METRICS_TOKEN` | 1 | D (input) | `DUNREE_METRICS_TOKEN` first, then `ZORAXY_METRICS_TOKEN` (a warning is logged when only the old one is set) | WP3 | env precedence test |
| 30 | Env vars in tools: `ZORAXY_RELEASE_KEY`, `_RELEASE_PUB`, `_PLUGIN_INDEX_KEY`, `ZORAXY_BIN`, `ZORAXY_URL`, `ZORAXY_LEAK_SECONDS`, `ZORAXY_TEST_*` | ~45 | D (input) for the release and index keys, R for test-only variables | the signing tools accept `DUNREE_*`, then `ZORAXY_*`. `~/.zoraxy-release-key/` is still found when `~/.dunree-release-key/` is missing. **The key itself does not change** | WP7 | sign_release_test with each variable |
| 31 | localStorage keys (`zoraxy_menu_groups`, `zoraxy_recent_tabs`, `zoraxy_pinned_tabs`, `zoraxy_trafficflow_*`, `zoraxy_status_diagram`, `zoraxy_sso_tab`, `zoraxy_site_editor_mode`, `zoraxy_palette_recent`, `zoraxy.utm.range`, `zoraxy.topbar.update`, `zoraxy.stats.refwhy`, `zoraxy.lang`) | 39 / 11 | D (input) | migrated in **one place**, `script/safestorage.js` (`zxStore`): `get(k)` for a `dunree*` key that is missing copies the matching `zoraxy*` value once and keeps the old key until v2. Callers only use the new names | WP4 | JS unit test of `zxStore` migration (run under ui-smoke) |
| 32 | Conf / DB names | 0 hits | — | no conf file, DB table or DB key contains the name (checked: NewTable list, conf/*.json). Nothing to migrate | — | — |
| 33 | Updater backup names `zoraxy-pre-update-*.zip`, temp `.zoraxy-update-*`, `.zoraxy-wtest-*` | 6 | D (input) | new backups are written as `dunree-pre-update-*`. The list, rollback and prune read both prefixes. Temp names: R | WP7 | updater backup listing test with both prefixes |
| 34 | Release assets `zoraxy_<os>_<arch>`, SHA256SUMS header `# zoraxy-release tag= build= upstream=`, updater `AssetName`, Makefile `dist/zoraxy_*`, `build_release.sh` | ~40 | D, **release bridge** | see 3.1. Dunree releases in v1 ship `dunree_<os>_<arch>` **and** byte-identical `zoraxy_<os>_<arch>`. The header keeps the prefix `# zoraxy-release` with `product=dunree` added (the old parser ignores unknown keys). The verifier accepts `# dunree-release` too | WP7 | sign/verify tests: an old updater (frozen copy of verify.go in testdata) accepts a Dunree SHA256SUMS |
| 35 | Updater default repo `TheTractorHacker/zoraxy` (source.go:21), `-update_repo` | 1 (+38 refs) | C | build variable `${REPO}`, still overridable with `-update_repo`. **Not changed until the GitHub org exists.** An installed binary whose default repo has no releases shows "no release source" instead of an error | WP7 | test: default repo comes from the build variable |
| 36 | Version ordering (`CompareReleases`, `ParseTag`) | — | change | a Dunree tag `v1.x` must sort above every Zoraxy-fork `v3.x` build. Add a product epoch (`product=dunree` from the signed header, or the `dunree_` asset) before comparing triples | WP7 | test: v1.0.0-beta.1 (dunree) > v3.3.6-rc9.40 (zoraxy) |
| 37 | Binary name `zoraxy`, `start.sh`, `-doctor`, `instance.IsZoraxyName`, systemd checks | ~60 | R + D (input) | new builds and installs are called `dunree`. An install upgraded in place keeps the file name `zoraxy`, because the updater replaces `os.Executable()`. `IsZoraxyName` → `IsProductName`, which matches `dunree*` and `zoraxy*`. start.sh and the doctor check both unit names | WP8 | proc name test; start.sh shellcheck + bats-style test with a fake systemctl |
| 38 | systemd unit `docs/deploy/zoraxy.service`, `Description`, `Documentation=` | 41 / 10 | R + D | ship `docs/deploy/dunree.service`. `zoraxy.service` stays as a documented legacy file whose comment explains how to switch. Do **not** add `Alias=zoraxy.service` (it conflicts with an existing unit file). The binary never renames a unit by itself | WP8 | test: unit file parses (`systemd-analyze verify` when available, else a key/section lint) |
| 39 | Install paths `/opt/zoraxy`, `/var/log/zoraxy`, `/usr/local/bin/zoraxy` | 47 / 16 | R for new installs | nothing in the binary is hard-coded to these paths (they are WorkingDirectory/flags). Docs show `/opt/dunree`, with a note that an existing `/opt/zoraxy` keeps working | WP8 | doc lint only (no code path) |
| 40 | Docker: image `zoraxydocker/zoraxy`, `container_name: zoraxy`, `/opt/zoraxy/config/` volume, label `com.imuslab.zoraxy.container-identifier`, workflow defaults `zoraxydocker`/`zoraxy` | 18 / 10 | R + D | the image and workflow defaults become `${DOCKER_IMAGE}` (Foley IT registry, a variable). Upstream's `zoraxydocker` namespace must never be a default. Volume: `/opt/dunree/config/`, with `/opt/zoraxy` symlinked to `/opt/dunree` in the image, and entrypoint.py using `/opt/zoraxy/config` when that is what is mounted. New label `ie.foleyit.dunree.container-identifier`; the old label is kept in v1 (dockerux detection) | WP8 | docker build in CI; entrypoint unit test for both mount points |
| 41 | mDNS: host name prefix `zoraxy_`, TXT `domain=zoraxy.aroz.org`, `vendor=imuslab.com` | 3 | R + D | `dunree_<uuid>`. While `legacy_emit` is ON, a second record `zoraxy_<uuid>` is registered so existing `.local` bookmarks still resolve. `vendor` → `Foley IT`, `domain` → `${PRODUCT_DOMAIN}`: advertising imuslab as vendor would misattribute Dunree. The scanner accepts both | WP3 | mdns test: register and scan with both names |
| 42 | External links to upstream (`zoraxy.aroz.org`, `github.com/tobychui/zoraxy` wiki/issues/readme, `aroz.org` examples) | ~390 | C / K | **Help, support, docs and "report an issue" links** → `${DOCS_URL}` / `${ISSUES_URL}`, because Dunree bugs must not be filed with upstream. **History references** (issue/PR numbers in CHANGELOG, triage, code comments such as "see tobychui/zoraxy#77", deprecated README.txt "Original implementation") → K. `aroz.org` as an **example domain** in rules.html → `example.com` | WP4/WP9 | grep test: no `zoraxy.aroz.org` and no `tobychui/zoraxy/(wiki\|blob)` outside the K allow-list |
| 43 | Captcha footer: label "Zoraxy", `DefaultFooterURL = https://zoraxy.aroz.org` | 3 | R + C | the visitor-facing default becomes "Dunree" / `${PRODUCT_URL}` (no link when empty). Branding saved explicitly by an admin is kept | WP3 | captcha page test |
| 44 | Self-signed cert `Organization: aroz.org` (tlscert/certgen.go) | 1 | R → `${PUBLISHER}` | existing certificates are not reissued | WP2 | certgen test |
| 45 | CrowdSec scenario `zoraxy/manual-ban` | 1 | D (input) | new bans use `dunree/manual-ban`. List and unban match both scenarios, because existing decisions in the LAPI carry the old one | WP3 | crowdsec admin test with both scenarios |
| 46 | netplan zone names `zoraxy-<n>`, zrok share description `zoraxy-<host>`, traceroute payload `zoraxy_trace` | 3 | R (netplan is a printed plan, nothing is applied), D (input) for zrok: existing shares found by the prefix must still be recognised. traceroute: R | WP3 | zrok test that matches both prefixes |
| 47 | Cryptographic / persisted constants: `"zoraxy-oauth2-session-v1"` (HKDF salt ×3), `"zoraxy-cluster-v1"` (cluster key HKDF), `"zoraxy-captcha-session-v1|"`, `"zoraxy-rule:"` (rule ID hash) | 6 | **F** | never change these strings. Changing one logs out every OAuth2 session, makes persisted sessions unreadable, splits a cluster from its followers and changes every rule ID | WP2 | golden test: each constant's bytes are pinned (fails when someone runs a blind sed) |
| 48 | `X-Auth-Method: zoraxy_sso` sent upstream by ZorxAuth | 1 | D (value) | `dunree_sso`. While `legacy_emit` is ON the value stays `zoraxy_sso`: an upstream compares it exactly, so appending is not possible | WP3 | header test per setting |
| 49 | ZorxAuth feature name ("Zoraxy Auth", package `zorxauth`, `ZorxAuth` identifiers) | 744 / 97 | R for UI text ("Dunree Auth"). The package name and DB table names stay (N: `zorxauth` is a feature name and the DB tables use it) | data unchanged | WP4 | UI grep; existing zorxauth tests |
| 50 | Docs site `docs/index.html`, `docs/CNAME` (= `zoraxy.aroz.org`), `nginx2zoraxy.html`, `docs/plugins/**`, guides, DEVELOPMENT, README, CAPTCHA_FEATURE, ROADMAP | ~1720 / 91 | R. `docs/CNAME` **is deleted**: GitHub Pages from this repo would otherwise claim upstream's domain. `nginx2zoraxy.html` → `nginx2dunree.html` | none | WP9 | doc grep test with allow-list; link check |
| 51 | CHANGELOG.md, `zoraxy_plugin/CHANGELOG.md`, `docs/triage/**` | 545 / 12 | K | a new Dunree CHANGELOG section is added on top. Earlier entries stay as written | WP9 | — |
| 52 | LICENSE, THIRD_PARTY_NOTICES.md, third_party/**, copyright headers (`Copyright (c) 2018-present tobychui`, `Author: tobychui` ×17) | — | K | add `NOTICE` (see 3.6) | WP9 | test: LICENSE unchanged (hash), NOTICE contains "tobychui" and "imuslab" and "not endorsed" |
| 53 | CI: `.github/workflows/*`, issue templates "Zoraxy Version", `CODEOWNERS` (`@tobychui`) | 8 / 5 | R | CODEOWNERS → Foley IT placeholder team (it is not attribution, and leaving it would ask upstream to review fork PRs) | WP8 | actionlint |
| 54 | Build: `src/Makefile` (`zoraxy_*`, `zoraxy_file_checksum.sha1`), `build_ref_plugins.sh`, `example/plugins/build_all.sh` (copies the SDK) | ~25 | R (+ D for release assets, row 34) | — | WP7 | `make -n` dry run; build_all |
| 55 | Tools and tests (`tools/e2e*`, `ui-smoke`, `plugin-check`, `plugin-index`, `i18n`) | 466 / 90 | R, except tests that **assert legacy behaviour**, which keep the old strings on purpose (mark them `// legacy-compat`) | — | WP10 | the suites themselves |
| 56 | Example plugins and their vendored SDK copies | 1754 / 170 | R by regenerating (`build_all.sh` copies `dunree_plugin`), not by sed | — | WP6 | build_all |
| 57 | Neutral prefixes `zx-` (CSS, 17,592), `zxStore` (74), `zr_` (log files `zr_*.log`, `zr_xauth_session`, `zr_sticky_session`, `zr_sid_*`), `LOG_PREFIX = "zr"`, `zx_runtime` template | ~17,700 | N (keep) | log files, cookies and session values stay readable | — | — |
| 58 | Brand assets (favicon, logos in src/web/img, img/, docs/img) | — | R → `brand/` assets (#1a56c4 / #6d9bff) | — | WP4 | ui-smoke screenshots |

## 3. Decisions that needed a closer look

### 3.1 Version reset breaks in-app upgrades unless we bridge it
`CompareReleases` compares major.minor.patch first. To a Zoraxy-fork install, `v1.0.0-beta.1` is **older** than
the `v3.3.6-…` it runs, so the update page would never offer Dunree. The old updater also requires
`zoraxy_<os>_<arch>` assets and a `# zoraxy-release` first line, and it refuses a build number that is not
higher than the last one it saw. Plan:
1. Ship one last Zoraxy-fork release (`v3.3.6-…`, next build number) whose updater knows the product epoch
   (row 36). This is the bridge.
2. Dunree v1 releases also carry the `zoraxy_*` asset names and the `# zoraxy-release … product=dunree` header,
   and they keep the fork's build counter running upwards. The build number is not reset with the version.
3. The same signing key is used. The public key embedded in the updater does not change.

Without the bridge, existing installs have to upgrade by hand. That has to be written in the release notes.

**Decision (2026-11-24, replaces steps 1 to 3 and rows 34 and 36):** no bridge. Dunree releases carry `dunree_<os>_<arch>[.exe]`
files only and the signed header `# dunree-release product=dunree tag=... build=... upstream=<COMPAT_VERSION>`, verified with
the same key. Dunree's updater compares its own `PRODUCT_VERSION` with Dunree releases by Semantic Versioning precedence
and never considers a release of the fork (other file names, the header `# zoraxy-release`, refused by name). An install <!-- rebrand:keep -->
of the fork is switched by replacing the program file; no in-app path is promised. `UPDATE_REPO` stays the policy variable.
What was built and its limits: `docs/ux/changes.md`, "Dunree rebrand: finish".

### 3.2 `SYSTEM_VERSION` has two jobs
It is shown to users, and it also drives the config migrator (`conf/version` = `336`). If it became
`1.0.0-beta.1` that would turn into `100`. Split it into `PRODUCT_VERSION` and `COMPAT_VERSION` (row 6).
`COMPAT_VERSION` also feeds `zoraxy_version` to old plugins and `upstream=` in the release header, and
"Based on Zoraxy v3.3.6" in About is generated from it.

### 3.3 `SYSTEM_NAME` is the admin session cookie name
A blind rename would log out every administrator and every API client that holds a cookie. The cookie name
gets its own constant (row 5).

### 3.4 Prefixes we deliberately keep (`zx-`, `zxStore`, `zr_`, `zorxauth`)
Policy (1) says "identifiers: rename fully". I narrow that: abbreviations that do not spell the product
name stay. Renaming `zx-` touches about 17,600 CSS and JS sites at the same moment other agents are editing
the UI. It would also change log file names (`zr_*.log`, which the log viewer finds by prefix) and cookies
(`zr_xauth_session`, `zr_sticky_session`), and gain nothing users can see.

### 3.5 Frozen strings (class F)
Five strings with "zoraxy" in them are cryptographic domain separators or persisted IDs (row 47). They are
excluded from every replacement rule and pinned by a golden test. The same holds for the signed-format
identifiers that a running install already trusts (`zoraxy-plugin-index`, `# zoraxy-release`). They are
accepted for ever, and newly written only as described in rows 25 and 34.

### 3.6 Attribution and NOTICE
`NOTICE` (new, repo root): "Dunree – Reverse proxy and web gateway. Copyright © 2026 Foley IT. Dunree is a
modified, independent derivative of Zoraxy (https://github.com/tobychui/zoraxy), © 2021–2026 tobychui and
imuslab, licensed under AGPL-3.0. Dunree is not affiliated with or endorsed by tobychui or imuslab. Parts
written for Dunree are © Foley IT. They are not the work of the Zoraxy authors." It also names the base,
"Based on Zoraxy v3.3.6". About, README and the footer say the same in short form. Copyright headers in
upstream files stay. New files get a Foley IT header.

### 3.7 Headers to plugins are D+, not D
If a user turned "Also send legacy names" off, an old-SDK plugin would stop verifying its invoke token and
reject every call. Fail-open filters would then quietly let traffic through. The plugin channel therefore
always sends both names in v1 (rows 14, 16, 18, 23).

### 3.8 Values cannot be duplicated
For headers we add a second header. For *values* (User-Agent, `X-Forwarded-Server`, `X-Auth-Method`) we
cannot. Rows 12, 13 and 48 choose per value: append the old token where substring matching is likely,
and keep the old exact value where exact comparison is likely.

### 3.9 Upstream-owned endpoints
`zoraxy.aroz.org` (docs, captcha footer, mDNS domain, `docs/CNAME`), `aroz-online/zoraxy-official-plugins`
(store), `zoraxydocker/zoraxy` (image), `github.com/tobychui/zoraxy/wiki` and `/issues` (help links). Every
one becomes a variable or setting. Existing installs keep what they had through migration (row 26). New
installs contact none of them.

## 4. Work packages (who does it)

Each WP is one agent or person. They touch only the listed areas, and they follow the order below because
WP1 rewrites every import.

| WP | Scope | Depends on |
|---|---|---|
| WP1 | Module path (rows 1–4). Done by `tools/rebrand/apply` (rule `module-path`) in one mechanical commit. Nothing else may be in that commit | — |
| WP2 | Core constants: SYSTEM_NAME/VERSION split, session cookie constant, cookies, frozen-constant golden test, certgen org (rows 5, 6, 21, 44, 47) | WP1 |
| WP3 | Wire surfaces + `legacy_emit` setting: headers, UAs, paths, metrics, env, webhooks, cluster, mDNS, crowdsec, zrok, captcha footer (rows 11–13, 17–20, 27–29, 41, 43, 45, 46, 48) | WP2 |
| WP4 | Admin UI text, titles, i18n keys and values, zxStore migration, csrf meta, attribution footer and About, brand assets (rows 7–10, 16, 31, 42 UI part, 49, 58) | WP2 (constants) |
| WP5 | Plugin SDK `dunree_plugin`, host dual fields and headers, store URL setting and migration, index format (rows 14, 15, 22–26) | WP3 (header helpers) |
| WP6 | Example plugins regenerated from `dunree_plugin` (rows 3, 56) | WP5 |
| WP7 | Release and updater: asset names, header, epoch, backup prefixes, Makefile, signing tools, repo variable (rows 30, 33–36, 54) | WP2 |
| WP8 | Install and packaging: binary name, start.sh, doctor, systemd, Docker, CI, CODEOWNERS (rows 37–40, 53) | WP7 |
| WP9 | Docs, README, NOTICE, CHANGELOG head, docs site, CNAME removal (rows 42 docs part, 50–52) | any |
| WP10 | Tools and test suites, and the rebrand lint (`tools/rebrand/check`: fails CI on a new `Zoraxy` outside the allow-list) (row 55) | last |

## 5. Known limits (to be copied into `docs/ux/changes.md` → "Dunree rebrand")

- Legacy names are emitted only while "Also send legacy Zoraxy names" is ON (default ON). It will be removed
  in v2. Plugin-channel and cluster headers are sent in both forms regardless of the setting until v2.
- Metrics: with the legacy names on, each series is exported twice, so the scrape is roughly twice as large.
- User-Agent and similar values change (the old token is appended, not kept alone). An upstream rule that
  matches the *whole* old UA exactly stops matching.
- An install updated in place keeps its binary name (`zoraxy`), its unit name (`zoraxy.service`) and its paths.
  Only new installs use `dunree`.
- Upgrading in-app from a Zoraxy-fork build needs the bridge release (3.1). An older fork build has to be
  upgraded by hand.
- Old cookies (`zoraxy_csrf`, the captcha and challenge cookies) are honoured until they expire, and are not
  re-issued under the old name.
- `/.zoraxy/*` paths keep answering in v1 and their use is logged.
- Third-party plugins built with the Zoraxy SDK keep working (contract api_version 1). They see
  `zoraxy_version = 3.3.6`, not the Dunree version.
- Frozen strings (3.5) still contain "zoraxy", and they always will.
