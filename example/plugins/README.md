# Example Plugins

This directory contains example plugins that demonstrate how to create and use plugins with the main application. Each plugin is designed to showcase different features and capabilities of the plugin system.

## Some Note-Worthy Examples

- **api-call-example**: Demonstrates how plugins can make API calls to zoraxy
- **event-subscriber-example**: Shows how to subscribe to and handle events from zoraxy within the application
- **plugin2plugin-comms-peer1**: Illustrates communication between two plugins via the event system, where this plugin acts as the first peer
- **plugin2plugin-comms-peer2**: Similar to the above, but this plugin acts as the second peer in the communication

## Reference plugins of the fork (`fork-ref-*`)

Three small plugins that the fork maintains as **reference implementations and test fixtures**. They are minimal on
purpose and are not features you need to run. Each one passes the conformance kit (`tools/plugin-check`, see
`docs/plugins/conformance.md`) without a warning and is run through the real plugin manager by the tests in
`src/mod/plugins/phase3_reference_test.go`.

- **fork-ref-filter**: `pre_auth` and `response` hooks, declares `fail_closed` (only honoured with your consent),
  health path. Marks requests and responses with the header `X-Fork-Ref-Filter` and answers 403 under
  `/fork-ref-filter/deny`.
- **fork-ref-events**: subscribes to three events, acknowledges at once and works later, with a bounded waiting list
  (256, the oldest event is dropped and counted).
- **fork-ref-ui-api**: a page plus one read (`GET /plugin/api/access/list`) and one write
  (`POST /plugin/api/blacklist/ip/add`) API permission. Its page keeps working with plugin page isolation turned
  on. **Its port has no login, like the port of every plugin: any local user or process on the host can make the
  same requests as its page.** That is why the write accepts documentation addresses only (inside `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), at most 16 per start, and the read hands out the number of
  access rules, not the rules. Do the same in a real plugin: see `docs/plugins/contract.md` section 4.

All three read their start configuration from standard input, check the invoke token, end on the terminate request
and on SIGTERM, and write no log line per request. Build them for a release with `tools/build_ref_plugins.sh`
(or `tools/build_release.sh -p`); they are not part of the signed Zoraxy release.

## SDK copy (`mod/zoraxy_plugin`)

Every example carries a copy of the plugin SDK from `src/mod/plugins/zoraxy_plugin` (`build_all.sh` refreshes the
copies). The copies here are SDK 1.1.0, plugin contract version 1; see `CHANGELOG.md` inside the folder and
`docs/plugins/contract.md`. A plugin built with it declares `"api_version": 1` without any code change.

Two examples also show the optional parts of the contract:

- **api-call-example** and **filter-example** declare `ConfigureVia: plugin.ConfigureViaStdin` (the API key and the
  invoke token are handed over on standard input, not on the command line) and `HealthPath` with
  `plugin.HealthHandler`.
