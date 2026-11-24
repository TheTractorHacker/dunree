# zoraxy_plugin (plugin SDK) changelog

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
