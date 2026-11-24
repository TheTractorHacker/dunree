# dunree_plugin (plugin SDK) changelog

Up to 1.2.0 this package was `zoraxy_plugin`; see the 2.0.0 entry.

The package follows [semantic versioning](https://semver.org). The version is the constant `SDKVersion`.
Releases are tagged `sdk/v<version>` in the Zoraxy repository; the tag marks the commit whose
`src/mod/plugins/zoraxy_plugin` folder is that version. The package has no dependency outside the Go
standard library and is used by copying the folder into your plugin (`mod/zoraxy_plugin`).

What the numbers mean here:

- **patch** (1.1.x): fixes, no new names.
- **minor** (1.x.0): new optional fields, constants, functions. A plugin written for an older 1.x compiles
  unchanged, and a binary built with an older 1.x keeps working with a newer Zoraxy.
- **major** (x.0.0): something was removed or changed meaning. Not planned.

`APIVersion` is separate: it is the version of the plugin contract (see `docs/plugins/contract.md`).

## 2.0.0 (2026-11-24), contract version 1 — the Dunree SDK

From this version on the package is `dunree_plugin` (`src/mod/plugins/dunree_plugin`, copied into a plugin as
`mod/dunree_plugin`). Everything above and below this entry that says `zoraxy_plugin` or Zoraxy describes the
package as it was up to 1.2.0, when it was the plugin SDK of the Zoraxy fork that Dunree continues. It is kept
as history. Dunree is a modified, independent derivative of Zoraxy (by tobychui and imuslab) and is not endorsed
by them.

The major number changes because the import path and some exported names changed, so a plugin has to be edited
to compile with it. **The plugin contract did not change** (`APIVersion` is still 1): a binary built with
`zoraxy_plugin` 1.0.0 to 1.2.0 runs on Dunree without being rebuilt, and a binary built with this package runs
on a Zoraxy-fork host that speaks contract version 1.

Changed (source level, what to edit when you move a plugin from `zoraxy_plugin`):

- Package and folder: `zoraxy_plugin` → `dunree_plugin`.
- `ConfigureSpec.ZoraxyPort` → `ConfigureSpec.DunreePort`; `RuntimeConstantValue.ZoraxyVersion` / `ZoraxyUUID` →
  `DunreeVersion` / `DunreeUUID`. The old field names still exist, as the legacy wire fields (see below); read the
  `Dunree*` ones.
- `InvokeTokenHeader` and `RequestIDHeader` are now `X-Dunree-Plugin-Token` and `X-Dunree-RequestID`. The old
  values are `LegacyInvokeTokenHeader` and `LegacyRequestIDHeader`.

Added:

- `HostHeader(r, name)` reads a header the host sets on its calls: `X-Dunree-<name>`, and `X-Zoraxy-<name>` when
  the first is absent. When both are present with different values the `X-Zoraxy-<name>` value wins: a Dunree
  1.x host always sends both with the same value, so a differing pair means an upstream Zoraxy host passed on an
  `X-Dunree-<name>` header a client put into its request. The routers of the package (static capture, dynamic
  capture, UI) use it. `compat.go` lists the names.
- `VerifyInvokeToken` (and with it `RequireInvokeToken`, `NewFilterHandler`) accepts the token in
  `X-Dunree-Plugin-Token` or `X-Zoraxy-Plugin-Token`.
- Configure payload: `dunree_port`, `runtime_const.dunree_version`, `runtime_const.dunree_uuid`. A payload that
  only has `zoraxy_port`, `zoraxy_version`, `zoraxy_uuid` (a Zoraxy host) fills `DunreePort`, `DunreeVersion` and
  `DunreeUUID` from them (`ConfigureSpec.UnmarshalJSON`).
- `IntroSpect.SDKFlavor` (`sdk_flavor`), filled with `SDKFlavorDunree` by `ServeIntroSpect`. Dunree sends the
  `dunree_*` fields of the configure payload to a plugin that declares it. A host that does not know the field
  ignores it.

Known limits: on a Dunree host `ZoraxyVersion` is the Zoraxy release Dunree is based on (for example `3.3.6`) and
`DunreeVersion` is the Dunree version; on a Zoraxy host both are the Zoraxy version, and the package cannot tell
the two hosts apart other than by `dunree_version` being absent from the payload (it does not expose that).
On a Zoraxy host a client of the proxy can still send an `X-Dunree-<name>` header that the host itself does not
set at all for that call (`HostHeader` then has nothing to compare it with), so treat host headers as hints and
rely on `VerifyInvokeToken` for who is calling (the token is a secret, its header name does not matter). A future
host that stops sending the `X-Zoraxy-*` names must remove client copies of them before calling a plugin. The `{{.csrfToken}}`
placeholder and the `zoraxy.csrf.Token` meta tag of plugin pages are unchanged in this version.

## 1.2.0 (2026-11-23), contract version 1

Added. All of it is optional; a plugin that uses none of it behaves as with 1.1.0, and the contract version is
unchanged.

- API client helpers (`api_client.go`) for the calls a plugin makes to the Zoraxy plugin API. They build the
  address and set the `Authorization: Bearer <api_key>` header:
  `ConfigureSpec.DoAPIRequest(method, endpoint, body)` (build and send; no redirects followed, 30 s limit),
  `ConfigureSpec.NewAPIRequest(method, endpoint, body)` (build only, for your own `http.Client`),
  `ConfigureSpec.SetAPIAuth(req)` (header only), `ConfigureSpec.APIURL(endpoint)`, and the errors `ErrNoAPIKey`
  (the start configuration holds no key) and `ErrAPIEndpoint` (the endpoint is not a path).
- Events `proxyRuleAdded`, `proxyRuleEdited`, `proxyRuleRemoved` (`events.EventProxyRuleAdded`, ...) with the
  payloads `events.ProxyRuleAddedEvent`, `events.ProxyRuleEditedEvent` (both carry `events.ProxyRuleInfo`: host
  name, aliases, default site or not, switched off or not, tags) and `events.ProxyRuleRemovedEvent`.
  `events.ParseEvent` reads them. Only a Zoraxy that knows these names sends them; an older Zoraxy does not
  register a subscription to a name it does not know (it logs that, and the plugin runs).

Known limits: the helpers call `http://127.0.0.1:<zoraxy_port>` as the contract says, there is no option for another
address; `DoAPIRequest` has no context parameter (use `NewAPIRequest` with `req.WithContext` and your own client
when you need to cancel); a response body is not decoded for you. `APIURL` returns an empty string for an endpoint
that is not a path starting with one `/` (for example `@other.host/x`) and when there is no port, so a request built
from it cannot be sent; `SetAPIAuth` does nothing without a key, and it does not check where the request goes: only
`NewAPIRequest` and `DoAPIRequest` guarantee that the key goes to Zoraxy and nowhere else.

## 1.1.0 (2026-11-23), contract version 1

Added. All of it is optional; a plugin that uses none of it behaves as with 1.0.0.

- `SDKVersion`, `APIVersion`.
- `IntroSpect.APIVersion` (`api_version`). `ServeIntroSpect` fills in `APIVersion` when the field is 0, so a
  plugin rebuilt with this version declares contract version 1 without a code change.
- `ConfigureSpec.APIVersionMin` / `APIVersionMax` (`api_version_min`, `api_version_max`): the contract versions
  Zoraxy supports. `ConfigureSpec.ContractKnown`, `ContractSupported`, `SupportsAPIVersion`.
  `RecvConfigureSpec` prints one warning to standard error when Zoraxy does not support `APIVersion`.
- `IntroSpect.HealthPath` (`health_path`) and `HealthHandler`.
- `IntroSpect.ConfigureVia` (`configure_via`), `ConfigureViaStdin`, `ConfigureStdinFlag`: the configure payload
  (API key, invoke token) on standard input instead of the command line. `RecvConfigureSpec` reads both.

`health_path`, `configure_via`, `ConfigureViaStdin` and `ConfigureStdinFlag` (not `HealthHandler`) were not new in the
source tree on that day: they first shipped, without a version number, in the copy of this package that
the fork release fork.30 carried. 1.1.0 is the first numbered release that contains them. The package as fork.30 shipped
it is therefore neither 1.0.0 (which is the older copy the example plugins carried) nor 1.1.0; a plugin built with
it is a legacy plugin (no `api_version`) that may use standard input and a health path, and keeps working.

Changed behaviour of a plugin that is only rebuilt: its manifest gains `"api_version": 1`, and Zoraxy then adds
`api_version_min` / `api_version_max` to its configure payload. Nothing else.

## 1.0.0, contract version 0 (legacy)

The package as it was before versions were counted: introspect, configure on the command line, UI routers,
static and dynamic capture routers, events, request / response hooks (`hooks.go`), invoke token. A frozen copy
is kept in `src/mod/plugins/testdata/sdk-1.0.0` and a plugin built with it is run against every new Zoraxy
(`TestSDKCompat...`).
