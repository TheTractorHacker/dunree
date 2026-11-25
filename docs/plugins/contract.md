# Dunree plugin contract

Contract version: **1**. Written 2026-11-23 for the fork (`dev` branch). Status of this document: it describes what
the code does (`src/mod/plugins`, SDK `src/mod/plugins/dunree_plugin` 2.0.0). Where the two ever disagree, that is a
bug in one of them; the tests named in section 8 are what keeps them together.

The contract is everything Dunree and a plugin say to each other. A plugin is a separate program; nothing in this
document depends on the language it is written in. The Go SDK (`dunree_plugin`) is one implementation of the plugin
side.

Dunree is based on Zoraxy and keeps its plugin contract. Some names on the wire exist twice, a Dunree name and the
name Zoraxy used; **section 10** says which, and what a plugin built for Zoraxy and a plugin built for Dunree each <!-- rebrand:keep -->
get. Where this document says "legacy name" it means the Zoraxy name. <!-- rebrand:keep -->

## 1. Versions

| Version | Meaning |
|---|---|
| 0 ("legacy") | The contract as it was before versions were counted. A plugin whose manifest has no `api_version` is version 0. Every plugin built before 2026-11-23 is version 0, including the three plugins on the owner's proxies |
| 1 | Version 0 plus: `api_version` in the manifest, `api_version_min` / `api_version_max` in the configure payload. `health_path` and `configure_via` are optional in both versions |

This Dunree supports versions **0 to 1** (`ContractVersionMin`, `ContractVersionMax` in `src/mod/plugins/contract.go`;
the admin API `GET /api/plugins/settings` returns the range).

What Dunree does with the version of a plugin:

| Plugin says | Dunree |
|---|---|
| nothing, or `0` | legacy plugin: runs exactly as before, gets exactly the configure payload it always got. Never warned about, never refused |
| a version inside the range | runs; the configure payload carries the supported range |
| a version above the range (built for a newer Dunree) | **default: started anyway**, with a log line at load and at every start, and a note in the Plugin Manager (Health column, Details). **Opt-in** ("Plugin safety settings", `contract_mode=refuse`): not started, state `failed_to_start` with the reason; a restart policy does not retry it, neither at boot nor after a crash. A plugin that is running when the setting is turned on keeps running and is refused at its next start |
| a whole number that is negative or above 1000000 | the field is dropped with a log line: legacy plugin |
| not a whole number (a string such as `"1"`, a fraction, a number too large for an integer, an object, a list, `true`) | the field is dropped with a log line: legacy plugin. The rest of the manifest is read as always, so a manifest that carried an `api_version` of another type before the field existed still loads. `null` is the same as leaving the field out |

Dunree never refuses a plugin because its version is *old*. Version 0 stays supported for as long as this major
version of the contract exists (see the stability rules).

## 2. Introspect

Dunree runs the entry point of the plugin with the single argument `-introspect`, as the user Dunree runs as, with a
10 second limit. The plugin prints **one JSON document** on standard output and exits with code 0. Anything else
(other output, non-zero exit, timeout) means the folder is listed as "could not be loaded".

Entry point: `<folder>/<folder name>` (`.exe` on Windows), else `start.sh`, else `start.bat`.

Fields (JSON names). "Required" means Dunree refuses the plugin without it.

| Field | Required | Meaning |
|---|---|---|
| `id`, `name`, `author`, `description`, `ui_path` | yes | identity and the path of the plugin's own page |
| `author_contact`, `url`, `type` (0 router, 1 utility), `version_major`, `version_minor`, `version_patch` | no | shown to the administrator; the version is compared with the store |
| `static_capture_paths` (list of `{capture_path}`), `static_capture_ingress` | no | static capture |
| `dynamic_capture_sniff`, `dynamic_capture_ingress` | no | dynamic capture |
| `subscription_path`, `subscriptions_events` (event name to comment) | no | events |
| `permitted_api_endpoints` (list of `{method, endpoint, reason}`) | no | Dunree API endpoints the plugin asks for (section 6) |
| `hooks` | no | request / response filter, own version field `hooks.version` (see "Request and Response Hooks" in the author docs) |
| `health_path` | no | plain absolute path (letters, digits, `/ - _ . ~`, at most 256 characters); an invalid value is dropped |
| `configure_via` | no | `"stdin"` or absent; an unknown value is dropped |
| `api_version` | no | contract version, section 1 |
| `sdk_flavor` | no | `"dunree"` = the plugin reads the Dunree names of the configure payload (section 10). The Dunree SDK sets it. Any other value, or none, is a plugin built for Zoraxy <!-- rebrand:keep --> |

Unknown fields are ignored. `null` and an absent field mean the same for lists and maps.

## 3. Configure (start)

Dunree starts the entry point in the folder of the plugin (working directory = that folder), in a process group of
its own, with one of:

- `-configure=<json>` (default), or
- `-configure-stdin` when the manifest says `configure_via: "stdin"`: the same JSON, followed by a newline, is written
  to standard input, which is then closed. Nothing secret is on the command line or in the environment.

The JSON:

| Field | When | Meaning |
|---|---|---|
| `port` | always | the plugin listens on `127.0.0.1:<port>` (HTTP) |
| `runtime_const` | always | `{zoraxy_version, zoraxy_uuid, development_build}`. `zoraxy_version` is the Zoraxy release this Dunree is based on (`3.3.6`), **not** the Dunree version, so a plugin that checks for a Zoraxy version keeps working. `zoraxy_uuid` is the node UUID <!-- rebrand:keep --> |
| `runtime_const.dunree_version`, `runtime_const.dunree_uuid` | only when the manifest says `sdk_flavor: "dunree"` | the Dunree version (for example `1.0.0-beta.1`) and the node UUID (the same value as `zoraxy_uuid`). They are the first two keys of `runtime_const` |
| `invoke_token` | always | secret of this start; Dunree sends it as `X-Dunree-Plugin-Token` and as `X-Zoraxy-Plugin-Token` on every call it makes to the plugin |
| `api_key`, `zoraxy_port` | only when the manifest has `permitted_api_endpoints` | key and port for calls to the Dunree plugin API |
| `dunree_port` | only with `permitted_api_endpoints` **and** `sdk_flavor: "dunree"` | the same port as `zoraxy_port` |
| `api_version_min`, `api_version_max` | only when the manifest has `api_version` of 1 or more | contract versions this Dunree supports, inclusive. `api_version_min` is left out when it is 0 |

A plugin must ignore fields it does not know. Every start issues a new invoke token and a new API key; the old key
is void as soon as the old process is gone.

Standard output and standard error are read line by line (a line is cut at 64 KiB).

## 4. Calls from Dunree to the plugin

All over HTTP to `127.0.0.1:<port>`. Capture, sniff, filter, event and health calls carry the invoke token in
`X-Dunree-Plugin-Token` and, with the same value, in `X-Zoraxy-Plugin-Token`; requests for the plugin page and the
terminate request do not. Every header Dunree sets on these calls exists under both prefixes (section 10); the table
below names the Dunree one.

**The page path and the terminate request have no authentication on the plugin port.** Dunree's admin login guards
the way through the admin address (`/plugin.ui/<id>/...`) only. The port itself is a loopback port: every user and
process on the host can call `<ui_path>/...` and `<ui_path>/term` directly, and the plugin cannot tell such a call
from one that came through the admin page (the page proxy adds no secret in contract version 1). So:

- whatever a plugin does on a request to its page path, with its own files or with its Dunree API key, any local
  process can ask for. A value embedded in the page (a nonce) only stops cross-site request forgery in the browser of
  the administrator; a local process reads the page and the value. Keep page actions harmless or bounded
  (`fork-ref-ui-api` accepts documentation addresses only and hands out a count, not the rules).
- any local process can stop a plugin with `GET <ui_path>/term`, and a logged-in administrator can reach the same
  path through the page proxy. For a filter plugin that means its rules run without it (fail-open, the default), or
  answer 503 where the administrator gave the `fail_closed` consent. Dunree reports the plugin as ended; with the
  restart policy `never` (the default) it stays down.

This is how upstream works and it is unchanged. A token on the page path and on `/term` would need a new contract
version; it is not planned yet (see the known limits of phase 3 in `reliability-plan.md`).

| Call | Request | Expected answer |
|---|---|---|
| Plugin page | any request below `ui_path` (proxied from `/plugin.ui/<id>/` of the admin interface) | whatever the page is |
| Terminate | `GET <ui_path>/term`, 3 s | `200`, then exit. Optional: `404` is understood as "not supported" |
| Static capture | the visitor's request, to `static_capture_ingress`, headers `X-Dunree-Capture` = the capture path that matched and `X-Dunree-URI` = the request URI as the visitor sent it | the response for the visitor |
| Dynamic sniff | `POST dynamic_capture_sniff/` (with the trailing slash) with the request description (JSON) | status `200` = the plugin takes the request (it is then sent to `dynamic_capture_ingress`); every other status = it does not. The answer may be at most 4096 bytes. (The SDK answers `200 OK` or `501 SKIP`. The constants 280 / 284 / 580 of the SDK are not what Dunree reads; an earlier version of this table listed them by mistake) |
| Dynamic ingress | the visitor's request, to `dynamic_capture_ingress` | the response for the visitor |
| Filter hooks | `POST` to the filter path with a `FilterRequest` | `200` with a `FilterVerdict` (JSON, at most 256 KiB) |
| Event | `POST subscription_path/<event name>` with the event (JSON) | `200`; one at a time, in order, at most 1000 waiting |
| Health | `GET health_path`, 2 s, only when the administrator turned the health check on | any `2xx` = healthy |

### Events

A plugin gets the events it names in `subscriptions_events`, and no others. A name this Dunree does not know is
logged and skipped; the plugin still starts.

| Event name | Sent when | `data` |
|---|---|---|
| `blacklistedIpBlocked` | a request was refused by a blacklist | `ip`, `comment`, `requested_url`, `hostname`, `user_agent`, `method` |
| `blacklistToggled` | the blacklist of an access rule was switched on or off | `rule_id`, `enabled` |
| `accessRuleCreated` | an access rule was created | `id`, `name`, `desc`, `blacklist_enabled`, `whitelist_enabled`, `trust_proxy_headers_only` |
| `proxyRuleAdded` (since fork.32, SDK 1.2.0) | an HTTP proxy rule was stored that had no stored configuration before | `root_or_matching_domain` (`/` for the default site), `matching_domain_alias`, `is_root`, `disabled`, `tags` |
| `proxyRuleEdited` (since fork.32, SDK 1.2.0) | a stored HTTP proxy rule was stored again: any change of it (upstreams, headers, tags, aliases, on / off, ...) | as `proxyRuleAdded`, the state after the change |
| `proxyRuleRemoved` (since fork.32, SDK 1.2.0) | the stored configuration of an HTTP proxy rule was removed | `root_or_matching_domain`, `is_root` |
| `customEvent` | another plugin sent it | `source_plugin`, `recipients`, `payload` |

The proxy rule events name the rule and nothing else: no upstream address, no credentials, no header values. A
plugin that needs the details asks the plugin API (`GET /plugin/api/proxy/list`, which is a permission). Limits of
the proxy rule events:

- They follow the stored configuration. A change of the host name of a rule arrives as `proxyRuleRemoved` (old
  name) followed by `proxyRuleAdded` (new name).
- `proxyRuleEdited` does not say what changed, and it is also sent when a save changed nothing.
- Saves and removals are handled one at a time, so two requests that store the same new rule at the same moment
  arrive as one `proxyRuleAdded` and one `proxyRuleEdited`. The two steps of a host name change are not one step
  for a subscriber: another event can arrive between its `proxyRuleRemoved` and its `proxyRuleAdded`. Events are
  sent to a plugin one request each, so do not rely on the order in which two events that follow each other
  closely arrive.
- Not sent: for rules loaded at start, for a configuration restored or imported as files (backup restore, Fleet
  sync to a follower: these replace the files and reload), and for the rewrite of a rule when a basic auth password
  hash is upgraded at login. Stream proxy, redirection and virtual directory rules of their own have no event
  (a virtual directory change is stored in its proxy rule and arrives as `proxyRuleEdited`).
- Delivery is the delivery of every event: at most 1000 waiting per plugin, no retry, no replay for a plugin that
  was not running.

**Events over UDP: will not be done.** Upstream's tracker lists "consider sending events over UDP instead of HTTP".
The fork keeps HTTP on loopback: a UDP datagram can be lost or arrive out of order without either side noticing,
is limited in size (the event payloads have no upper bound), cannot carry the invoke token check and the per plugin
ordering, back-pressure and failure counters that the HTTP delivery has, and would be a second transport every
plugin author and the conformance kit has to support. The cost it would save (one loopback HTTP request per event
on a kept-alive connection) has not been a measured problem.

## 5. Stop

1. `GET <ui_path>/term` (when the plugin has a UI path).
2. `SIGTERM` to the process group (Windows: the process is killed after 300 ms).
3. After 5 seconds without an exit: `SIGKILL` to the process group.

A plugin should exit within 5 seconds of either request. Children of the plugin are ended with it unless they left
the process group.

## 6. Calls from the plugin to Dunree, and permissions

`http://127.0.0.1:<dunree_port>/plugin/api/...` (`zoraxy_port` is the same port) with `Authorization: Bearer <api_key>`. Only method and path pairs
that are **granted** are answered.

- Default: every pair of `permitted_api_endpoints` is granted, as always. Pairs the administrator has not approved
  are reported once (log, security audit log entry `plugins.permissions.new`, Plugin Manager).
- Opt-in "Require my approval" (`require_permission_approval=true`): only approved pairs are granted. A plugin with
  nothing approved still gets a key; its calls are answered "endpoint not permitted". An approval or a withdrawal
  applies to the running process at once.
- What counts as approved: what the administrator approved in the Plugin Manager, and, for plugins that were
  installed when this Dunree version first started, what they asked for at that moment.
- An approval is for one plugin ID and one method and path. A pair the manifest stops asking for loses its
  approval.

### The API key

The SDK (since 1.2.0) sets the header for you: `cfg.DoAPIRequest(method, endpoint, body)`, or `cfg.NewAPIRequest` /
`cfg.SetAPIAuth` with your own `http.Client`. A plugin in another language sends the header itself. Only
`DoAPIRequest` and `NewAPIRequest` guarantee that the key goes to Dunree and nowhere else: `SetAPIAuth` sets the
header on whatever request it is given. `cfg.APIURL` gives an empty address for anything that is not a path
starting with one `/`.

How the key is made was reviewed for fork.32 (`src/mod/auth/plugin_apikey_manager.go`); **nothing was changed**,
because nothing was found weak:

| Question | Finding |
|---|---|
| Source of randomness | 32 bytes from `crypto/rand` (the operating system's generator), an error from it refuses the key. 256 bits: guessing is not possible |
| Encoding | the 32 bytes are put through SHA-256 and written as 64 hex characters. The hash adds nothing and takes nothing away (the output still has 256 bits of the input); it stays, so the format of the key does not change |
| Relation to the plugin | none: the plugin ID, the time and the port are not part of the key |
| Lifetime | made at every start of the plugin, kept in memory only (never written to disk or to the database), removed when the plugin stops or crashes. Keys do not survive a restart of Dunree, so there is no old key to keep valid |
| Scope | one key opens only the granted method and path pairs of its plugin; an approval or withdrawal applies to the live key |
| Comparison | the key is looked up in a map, which is not a constant-time comparison. With a random 256-bit key and Go's per-process seeded map hash this gives an attacker nothing to measure towards; noted, not changed |
| Where it can leak | on the command line of the plugin unless the manifest says `configure_via: "stdin"` (section 3); in the plugin's own logs if it prints it; the call itself is plain HTTP, on loopback only |
| Wrong keys | answered `401`; attempts are not counted or rate limited (the API is reachable on the management port, so a firewall or the loopback bind is what limits who can try) |

Held by `TestPluginAPIKeyFormatAndUniqueness` (`src/mod/auth`) and `TestSDKAPIClientHelpersSetTheBearerHeader`
(`src/mod/plugins`).

## 7. Stability rules

These are promises of the fork for contract major version "1.x" (versions 0 and 1 and what follows them).

1. **Additive only.** A new contract version may add optional manifest fields, optional configure fields, optional
   headers and new calls that a plugin opts into through its manifest. It never removes a field, never changes the
   type or meaning of one, and never makes an optional field required.
2. **Nothing new is sent to a plugin that did not ask.** A legacy plugin gets byte for byte the configure payload
   and the calls it got before. New calls and new payload fields need a manifest field or a declared `api_version`.
   (Two additions from before this rule exist and stay: `invoke_token` in the payload, and the
   `X-Zoraxy-Plugin-Token` header on every call. One addition came with the rebrand: every header of the host is
   also sent under its `X-Dunree-` name, to every plugin. A header cannot be sent to some plugins only without
   knowing what they were built with, and rule 3 makes an unknown header harmless. The configure payload does
   follow the rule: the `dunree_*` fields need `sdk_flavor`.)
3. **Both sides ignore what they do not know**: unknown JSON fields, unknown headers.
4. **A plugin is never refused for being old.** Version 0 stays supported. Dropping it would be a new major version
   of the contract and needs an owner decision and a release note one release ahead.
5. **A newer plugin is not refused by default**, only reported. Refusing is the administrator's choice.
6. **The version number goes up** only when a plugin or Dunree has to know about the change to behave correctly.
   Optional fields that are safe to ignore (as `health_path` was) do not need a new number.
7. **Every change to the contract** comes with: an entry in this file, an entry in the SDK changelog, a golden
   manifest or a test, and a "known limits" note in `reliability-plan.md`.

## 8. What keeps this true

| Claim | Test (`src/mod/plugins`) |
|---|---|
| Manifests of all example plugins and of the three installed plugins load unchanged and are legacy | `TestContractGoldenManifestsParseUnchanged` (`testdata/manifests/`) |
| Version states, warn by default, refuse on opt-in, legacy never affected | `TestContractStatesAndSanitize`, `TestContractAPIVersionThatIsNotANumberLoadsAsLegacy`, `TestFaultPluginWithOddAPIVersionIsLoadedAsLegacy`, `TestFaultContractMismatchWarnsByDefaultAndRefusesOnOptIn`, `TestFaultRefusedPluginIsNotRetriedAtBoot`, `TestFaultRefusedPluginIsNotRetriedAfterACrash` |
| The range is only sent to plugins that declare a version | `TestFaultContractRangeOnlyForPluginsThatDeclareAVersion` |
| A binary built with SDK 1.0.0 still works against this Dunree | `TestSDKCompatBinaryBuiltWithOldSDKStillPasses` |
| A binary built with SDK 1.1.0 still works against this Dunree | `TestSDKCompatBinaryBuiltWithSDK11StillPasses` (`testdata/sdk-1.1.0`) |
| A binary built with the last Zoraxy SDK (1.2.0, package `zoraxy_plugin`, taken from the revision before the rebrand) still works, also with the legacy-names setting off | `TestSDKCompatBinaryBuiltWithZoraxySDK12StillPasses`, `TestSDKCompatZoraxySDKPluginWorksWithLegacyNamesOff`, `TestSDKFrozen12IsThePreRebrandSDK` (`testdata/sdk-1.2.0`) <!-- rebrand:keep --> |
| A plugin built for Zoraxy gets the configure payload of Zoraxy, key for key; a Dunree SDK plugin gets both sets of names | `TestConfigurePayloadZoraxyNamesAlwaysDunreeNamesForDunreePlugins`, `TestFaultContractRangeOnlyForPluginsThatDeclareAVersion` <!-- rebrand:keep --> |
| Every header of the host is sent under both prefixes on every kind of call, with the same value, whatever the legacy-names setting says | `TestHostHeadersToPluginsHaveBothNames` |
| The Dunree SDK reads a Dunree host and a Zoraxy host | `TestDunreeSDKReadsConfigureFromDunreeAndFromZoraxyHosts`, `TestDunreeSDKReadsHostHeadersUnderBothNames` (`sdk_dunree_test.go`) <!-- rebrand:keep --> |
| Proxy rule events are sent, with the documented payload and nothing more | `TestProxyRuleEvents...` (`src/proxyrule_events_test.go`), `TestProxyRuleEventsDeSerialization` (`src/mod/eventsystem`) |
| Secrets on standard input | `TestFaultSDKPluginSecretsAreNotInTheProcessList`, `TestFaultSecretsOnStdinAreNotOnTheCommandLine` |
| Permissions | `phase2_permissions_test.go` |
| A plugin can be checked against this document without Dunree | the conformance kit `tools/plugin-check` (`docs/plugins/conformance.md`); its verdict rules are held to those of Dunree by `TestConformanceKitVerdictRulesMatchDunree` |
| The reference plugins keep the contract | `tools/plugin-check/check_test.go` (`TestReferencePluginsPass`), `phase3_reference_test.go` |

## 9. The SDK (`dunree_plugin`) and where it lives

**Decision (module path): the SDK stays a package inside the Dunree module**
(`github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin`, folder `src/mod/plugins/dunree_plugin`) **and is distributed by
copying the folder** into a plugin (`mod/dunree_plugin`), as upstream does. It is **not** a Go module of its own.

Why:

- Dunree itself imports the package. A `go.mod` in that folder would take it out of the main module, and the main
  module would then need a `require` plus a `replace` to its own sub-folder, which every build, the vendoring check
  and the release script would have to follow. That is a real risk for no gain to the proxy.
- A module needs an import path that resolves. `github.com/TheTractorHacker/dunree` is upstream's name and does not serve this
  fork; a separate repository under the fork's own name is an owner decision (name, who tags, who answers issues).
- Every existing plugin, upstream's documentation and all examples use the copy workflow. It needs no network at
  build time and pins the SDK version in the plugin's own tree.

What a module would have given, and how it is covered instead:

| Wanted | How |
|---|---|
| A version | constant `SDKVersion` (semantic versioning), tag `sdk/v<version>` on the commit, `CHANGELOG.md` in the folder (copied with it) |
| Knowing what changed | the changelog; minor versions only add |
| Proof that old builds keep working | the frozen copy `testdata/sdk-1.0.0` and `TestSDKCompat...`: the same fixture plugin is built against the frozen copy and against the current SDK and run through start, filter, capture, UI, events, API key, crash, automatic restart and stop |
| No outside dependency | the package only imports the standard library (the compatibility build runs with `GOPROXY=off`) |

Rules for changing the SDK: a release that adds something is a minor version; when it is released the previous
state is frozen under `testdata/sdk-<version>` and added to the compatibility test (done for 1.0.0, for 1.1.0 when
1.2.0 was made, and for 1.2.0, the last `zoraxy_plugin`, when the package became `dunree_plugin` 2.0.0). The frozen <!-- rebrand:keep -->
copies keep the folder and package name `zoraxy_plugin` and are never renamed. The tags `sdk/v1.1.0` and `sdk/v1.2.0` have **not** been created (tags are made at release <!-- rebrand:keep -->
time by the owner's release flow).

If a separate module is wanted later, the folder can be published as it is: it has no import of Dunree.

## 10. Dunree names and Zoraxy names <!-- rebrand:keep -->

Dunree is a modified, independent derivative of Zoraxy (by tobychui and imuslab) and is not endorsed by them. Its
plugin contract is the contract of the Zoraxy fork it continues, version 1, unchanged. What changed with the name is <!-- rebrand:keep -->
only this: the host now has a Dunree name for everything that had "Zoraxy" in it on the wire, and keeps the Zoraxy <!-- rebrand:keep -->
name next to it.

**A plugin is a binary.** One that was built with the Zoraxy SDK reads `zoraxy_port` and `X-Zoraxy-Plugin-Token`, and <!-- rebrand:keep -->
that cannot be changed after it was built. So the Zoraxy names are not optional for the host. <!-- rebrand:keep -->

### What the host sends

| Surface | Dunree name | Zoraxy (legacy) name | Who gets what <!-- rebrand:keep --> |
|---|---|---|---|
| Headers on calls to the plugin | `X-Dunree-Plugin-Token`, `X-Dunree-RequestID`, `X-Dunree-Capture`, `X-Dunree-URI`, `X-Dunree-Csrf`, `X-Dunree-Ui-Isolated`, `X-Dunree-Event-Type` | the same with `X-Zoraxy-` | **every plugin gets both**, same value, on every call. A value a client sent under either name is overwritten. An isolated plugin page gets neither `Csrf` header |
| Configure: port of the plugin API | `dunree_port` | `zoraxy_port` | `zoraxy_port`: every plugin with API permissions. `dunree_port`: also needs `sdk_flavor: "dunree"` |
| Configure: host version | `runtime_const.dunree_version` (Dunree version) | `runtime_const.zoraxy_version` (Zoraxy base version, `3.3.6`) | `zoraxy_version`: every plugin. `dunree_version`: needs `sdk_flavor: "dunree"` <!-- rebrand:keep --> |
| Configure: node UUID | `runtime_const.dunree_uuid` | `runtime_const.zoraxy_uuid` | as the version |
| Headers a plugin may not set in a verdict | `X-Dunree-*` | `X-Zoraxy-*` | both prefixes are reserved for every plugin |
| Manifest, flags (`-introspect`, `-configure=`, `-configure-stdin`), status codes, paths, event names and payloads, `api_version` | no product name in them | | unchanged |

The setting **"Also send legacy X-Zoraxy-* headers"** (Listeners > Compatibility) is about what visitors, monitors
and webhook receivers get. **It does not touch the plugin channel**: with it off, plugins still get both header
names and the `zoraxy_*` fields. Reason: without the old header a plugin built with the Zoraxy SDK cannot verify its <!-- rebrand:keep -->
invoke token and refuses every call; a fail-open filter (the default) then lets traffic pass and nothing shows why.

### A plugin built with the Zoraxy SDK (`zoraxy_plugin` 1.0.0 to 1.2.0), or without an SDK for Zoraxy <!-- rebrand:keep -->

Nothing to do. It is found, started and called as before:

- its manifest has no `sdk_flavor`, so its configure payload is, key for key and in the same order, what Zoraxy <!-- rebrand:keep -->
  sent: `port`, `runtime_const{zoraxy_version, zoraxy_uuid, development_build}`, `api_key`, `zoraxy_port`,
  `invoke_token` (and the contract range when it declares `api_version`);
- it finds its token, capture path, request id, CSRF token and event type in the `X-Zoraxy-*` headers;
- it sees `zoraxy_version = 3.3.6`. It cannot see the Dunree version.

You can keep building it with your copy of `mod/zoraxy_plugin`; the old package is not shipped in this tree any <!-- rebrand:keep -->
more (the last one, 1.2.0, is kept as a test fixture in `src/mod/plugins/testdata/sdk-1.2.0`).

### A plugin built with the Dunree SDK (`dunree_plugin` 2.x)

- `ServeIntroSpect` declares `sdk_flavor: "dunree"`, so the plugin gets `dunree_port`, `dunree_version` and
  `dunree_uuid` next to the legacy fields. Read `ConfigureSpec.DunreePort`, `RuntimeConst.DunreeVersion`,
  `RuntimeConst.DunreeUUID`.
- `VerifyInvokeToken`, the routers and `HostHeader(r, "<name>")` read the `X-Dunree-` header and fall back to
  `X-Zoraxy-`. When both are present with different values, `HostHeader` takes the `X-Zoraxy-` one (see the known limits).
- The same binary runs on a Zoraxy-fork host of contract version 1: that host ignores `sdk_flavor`, sends only the <!-- rebrand:keep -->
  old names, and the SDK fills the `Dunree*` fields from them (`DunreeVersion` is then the Zoraxy version). <!-- rebrand:keep -->

Moving a plugin from `zoraxy_plugin` to `dunree_plugin`: replace the folder `mod/zoraxy_plugin` with <!-- rebrand:keep -->
`mod/dunree_plugin`, change the import path and package name, rename `ZoraxyPort` / `ZoraxyVersion` / `ZoraxyUUID` <!-- rebrand:keep -->
to `DunreePort` / `DunreeVersion` / `DunreeUUID`, and replace any `r.Header.Get("X-Zoraxy-...")` of your own with
`HostHeader(r, "...")`. Keep your plugin ID: stored settings (enabled, policy, permissions, tags) belong to the ID.

### Known limits

- The Zoraxy names stay for the whole Dunree 1.x line. Removing them is a new major contract version (rule 4). <!-- rebrand:keep -->
- Every call to a plugin now carries seven more header lines at most (the `X-Dunree-` twins). A plugin that passes
  all request headers on to another server passes these on too, as it already did with the `X-Zoraxy-` ones.
- A plugin written without the SDK that wants `dunree_port` has to put `"sdk_flavor": "dunree"` in its manifest.
  `zoraxy_port` is always there and is the same port.
- On a Zoraxy host, which does not set `X-Dunree-*`, a client of the proxy can send `X-Dunree-Capture` or <!-- rebrand:keep -->
  `X-Dunree-RequestID` itself. Where that host sets the `X-Zoraxy-` twin (capture, URI, request ID), `HostHeader` <!-- rebrand:keep -->
  sees two different values and takes the `X-Zoraxy-` one, because a Dunree 1.x host always sends the pair with <!-- rebrand:keep -->
  the same value (`TestDunreeSDKReadsHostHeadersUnderBothNames`). A header that host does not set at all for the call
  can still be supplied by a client. The invoke token is not affected (it is a secret). On a Dunree host both names
  are overwritten.
- The reference plugins keep their IDs (`fork.zoraxy.ref.*`), and the page of a plugin still gets the CSRF token
  through the `{{.csrfToken}}` placeholder; the name of the meta tag a plugin page uses is the plugin's own.
- The conformance kit (`tools/plugin-check`) sends both header names and follows `sdk_flavor` for the payload, as
  Dunree does. Its report says `"tool": "dunree-plugin-check"`; reports made before say `zoraxy-plugin-check`.
