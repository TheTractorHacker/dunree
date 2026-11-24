# Plugin reliability plan

Status: **phase 0 and phase 1 are built, with gaps.** Phase 0: see "Phase 0 results and known limits". Phase 1
(supervision, every new behaviour off by default): see "Phase 1 results and known limits" at the end, which also lists
what of phase 1 was **not** built (request budget, slow-call breaker, Prometheus series, lowering a filter timeout) and
what was not tested (root, `-plugin_user` with limits, Windows). **Phase 2 is partly built:** items 2.1 (contract),
2.2 (SDK version and compatibility test), 2.3 (secrets off the command line, SDK side) and 2.6 (permission approval), see
"Phase 2 results and known limits (items 2.1, 2.2, 2.3, 2.6)" at the end. Items 2.4 (signed index), 2.5 (safe
install, update, rollback) and 2.7 (isolated plugin UI) are built too: see "Phase 2 results and known limits (items
2.4, 2.5, 2.7)". **Phase 3 is built, with gaps** (reference plugins, conformance kit, a run of the kit against the
three plugins installed on the build machine): see "Phase 3 results and known limits", the last section, which also
lists what of phase 3 was **not** done (no signed plugin index entry, no upstream issues, no "conformance passed" flag).
Sections 1 to 6 and the appendices describe the code as it was **before** phase 0. Branch `dev`, written
2026-11-22 from a read-only review of the code (no build, no test run, no Zoraxy instance started). Every claim about today's behaviour cites `file:line`. Paths
are relative to `src/` unless they start with `docs/`, `tools/` or `example/`. Where I could not check something it says
**not verified**.

The fork's rules apply to every item here: new behaviour is **off or log-only by default**, no silent default changes,
signed releases, and every item ships with an automated test and a "known limits" note.

---

## One-page summary (plain language)

**What a plugin is today.** A plugin is a separate program that Zoraxy starts when you enable it. Zoraxy talks to it over
HTTP on `127.0.0.1` (a random port between 5800 and 6000). A plugin can do four things: show its own page inside the
admin UI, sit in the visitor's request path (as a filter, or by "capturing" requests), receive events (for example "a
blacklisted IP was blocked"), and call a small list of Zoraxy admin APIs that it asks for.

**Your three plugins** (from the public plugin index, fetched 2026-11-22):

| Plugin | Kind | In the visitor's request path? | Can change Zoraxy settings? |
|---|---|---|---|
| Data-Shield Blocklist v1.4.0 | Router, "dynamic capture" (`/sniff`) | Yes, but **only** on proxy rules tagged with its plugin group, or if "Apply to all HTTP proxy rules" is ticked | No |
| Resource Monitor v1.0.3 | Utility (own page only) | No | No |
| Zoraxy Cloudflare WAF v0.4.0 (third party) | Utility + event subscriber | No, but it is sent one HTTP call **per blocked request** | Yes: it may add and remove IPs on your blacklists |

**What is wrong today (the short list).**
1. **Nobody watches the plugin process.** If a plugin crashes, Zoraxy marks it "stopped" in memory and does nothing else:
   no restart, no alert, nothing in the UI except that it disappears from the side menu (which then says "No Plugins
   Installed" even though plugins are installed). If a plugin exits *cleanly* by itself, Zoraxy does not notice at all
   and keeps sending traffic to a dead port.
2. **"Fail closed" does not mean what the checkbox says.** If you allowed a filter plugin to block traffic when it fails,
   that only happens when the plugin *hangs*. If it *crashes*, traffic flows through unfiltered.
3. **Some failure paths give visitors a blank page.** When a capture plugin dies mid-request, the visitor gets an empty
   "200 OK" instead of an error page.
4. **No limits on what a plugin may consume.** No memory, CPU or log limits; a chatty plugin writes every line into the
   main Zoraxy log, and a line without a newline grows in Zoraxy's memory forever. Events are sent with no queue limit,
   so an attack against a blacklisted range plus a slow Cloudflare WAF plugin can pile up thousands of waiting calls.
5. **Install and update are not safe.** Downloads are not checksummed or signed, the download URL is usually "latest"
   (so the version you get is not the version shown), an update deletes the old binary first and has no rollback, and a
   failed download leaves the plugin stopped.
6. **Plugins are fully trusted.** By default a plugin runs as the same user as Zoraxy (root on your servers), its secrets
   are visible to every local user in the process list, and its UI runs inside the admin page with your admin session,
   so a plugin UI can do anything you can do in the admin UI.

**What is already good** (built by the fork, with tests): the request filter API has a per-call timeout (2 s default,
10 s cap), a circuit breaker (5 failures then skip for 30 s), fail-open by default, fail-closed only with your consent,
size limits on replies, strict validation of what a plugin may change, a secret token on calls to the plugin, and an
optional unprivileged plugin user (`-plugin_user`).

**What we will do, in order.**

| Phase | What you get | Effort | Default |
|---|---|---|---|
| 0. Measure | A fault-injection test plugin and test suite; a real status per plugin (running / crashed / exit code / last error / restarts) shown in the UI; the plain bugs above fixed | 4-5 days | read-only, no behaviour change |
| 1. Supervise | Optional automatic restart with backoff, health checks, timeouts on every plugin path, bounded event queues, per-plugin log limits and memory limits, a plugin health column and crash history in the UI | 10-13 days | every new behaviour off or log-only |
| 2. Contract and safe install | A versioned SDK and API contract, signed and checksummed plugin index, install into a staging folder, keep the previous version, one-click rollback, permission approval | 12-16 days | verification in "warn" mode |
| 3. Reference plugins and certification | Two or three small first-party plugins that double as test fixtures, and a conformance checker run against your three plugins | 8-11 days | nothing changes for existing plugins |

Total: the table's day figures are what one human engineer would need. **This fork is built with AI agents, so the writing is hours, not weeks**: roughly 1-2 hours of build time per phase for phases 0 and 1, 2-3 hours for phase 2, 2 hours for phase 3. What does not shrink is verification: running the fault-injection suite, a soak on the dev proxy, and the owner's go-ahead before anything reaches the live proxy. Plan the calendar around those gates, not around typing. Each phase is still one release with tests and a 'known limits' note.

**Should we write our own plugins?** Not to replace core features. CrowdSec, WAF, CAPTCHA, rate limits and access rules
should stay in core: they sit on every request, must be fast and must not depend on a second process. First-party
plugins make sense as **reference implementations and test fixtures**, and for optional integrations that most users do
not want in core (like the Cloudflare IP list sync). For small per-request logic the fork already has a safer option:
the sandboxed Lua scripts in core. Recommendation and cost are in section 4.

**Things you can do today, with no code change** (section 1.6): run plugins as an unprivileged user (`-plugin_user`),
check whether Data-Shield is actually attached to any proxy rule, and look in the log for
`encounted a fatal error. Disabling plugin` (the message spelling is the code's) to see if a plugin has been crashing.

---

## 1. How plugins run today

### 1.1 Process model and start-up

| Question | Answer | Evidence |
|---|---|---|
| Separate process? | Yes, one OS process per enabled plugin, started with `exec.Command`. Entry point is `<dir>/<dir name>` (or `.exe`), else `start.sh`, else `start.bat` | `mod/plugins/lifecycle.go:69`, `mod/plugins/utils.go:27-53` |
| How is it discovered? | At boot every sub-folder of `./plugins` (flag `-plugin`, **relative to the working directory**) is introspected by running the binary with `-introspect` (10 s timeout) and parsing the JSON it prints | `def.go:125`, `mod/plugins/plugins.go:133-165`, `mod/plugins/introspect.go:56-77` |
| How is it configured? | Started with `-configure=<JSON>` on the **command line**: port, Zoraxy version/UUID, plugin API key, invoke token | `mod/plugins/lifecycle.go:41-69`, `mod/plugins/zoraxy_plugin/zoraxy_plugin.go` (`ConfigureSpec`) |
| Which port? | Random 5800-6000, checked free before start (race: another process can take it before the plugin binds; the loop never ends if all 200 are busy; the comment says 49152-65535, which is wrong) | `mod/plugins/utils.go:14-17`, `:60-68` |
| Is readiness checked? | No. `StartPlugin` returns right after `cmd.Start()`; routes and hooks are attached immediately | `mod/plugins/lifecycle.go:84-195` |
| Which plugins start at boot? | Those whose DB flag is true. **A missing flag counts as true**, and installing from the store never writes the flag, so a plugin installed but never enabled **starts automatically at the next boot** | `mod/plugins/plugins.go:158`, `:219-227`, `mod/plugins/store.go:113-187` |
| Boot order | Sequential, synchronous, during start-up; a hanging introspect adds up to 10 s per plugin to boot | `start.go:478`, `mod/plugins/introspect.go:58` |
| Output | stdout and stderr read **one byte at a time**, split on newline, every line written to the main Zoraxy log under `plugin-manager`. A line with no newline grows in memory without limit | `mod/plugins/lifecycle.go:92-142`, `:230-246` |
| Shutdown | `GET <ui_path>/term` (3 s), then SIGTERM, poll 5 x 1 s, then SIGKILL. Signals go to the direct child only (no process group), so children of a `start.sh` may survive. On Windows: kill after 300 ms | `mod/plugins/lifecycle.go:249-325` |
| On Zoraxy stop | `Close()` stops every enabled plugin; the reference systemd unit also uses `KillMode=control-group`, so plugins die with the service. (True for the code this audit looked at. Since phase 1 a plugin **with a memory, CPU or task limit** runs in a systemd scope of its own, outside the cgroup of the service, and `KillMode=control-group` does not reach it: see "Third review round" and the known limit "A plugin with limits is outside the cgroup of Zoraxy") | `mod/plugins/plugins.go:251-266`, `start.go:629-633`, `docs/deploy/zoraxy.service:41` |

### 1.2 What happens when a plugin misbehaves

| Event | What Zoraxy does | What the visitor sees | Evidence |
|---|---|---|---|
| **Crashes** (non-zero exit, signal) | Logs once, sets `Enabled=false` in memory, rebuilds the tag maps. **Does not** restart, unsubscribe its events, revoke its API key, or drop its UI proxy. DB flag stays true, so it starts again at the next Zoraxy restart | Filter / sniff plugins are skipped (fail **open**, even if you consented to fail-closed). Static capture paths disappear | `mod/plugins/lifecycle.go:145-158`, `mod/plugins/hooks_pipeline.go:72` |
| **Exits cleanly** (exit 0) by itself | **Nothing.** `cmd.Wait` returns nil and the code only handles errors; plugin stays `Enabled=true` and `IsRunning()` stays true | Filters: each call fails (connection refused) -> breaker opens after 5 -> skipped (fail open), or **503 forever** if fail-closed consent was given. Static capture: blank `200 OK` (next row) | `mod/plugins/lifecycle.go:146-157`, `mod/plugins/plugins.go:343-345` |
| Capture target (static or dynamic ingress) unreachable | `dpcore` returns `502, err` without writing; both callers **ignore the return value**, so nothing is written | Go sends an **empty 200 OK** (from reading the code; not verified by running) | `mod/plugins/plugins.go:330`, `mod/plugins/dynamic_forwarder.go:80`, `mod/dynamicproxy/dpcore/dpcore.go:555-560` |
| **Hangs** (alive, never answers) | Filter / sniff calls time out (2 s default, max 10 s) and feed the breaker: 5 consecutive failures -> skipped for 30 s -> one probe call | Up to 2 s extra latency on requests until the breaker opens, then fail-open (or 503 with consent). Concurrent requests in that first window all wait | `mod/plugins/hooks_runtime.go:30-33`, `:145-189`, `:226-254` |
| Hangs on a **capture** (static / dynamic ingress) or its UI | Proxied with `DpcoreOptions{}`: no response-header timeout, no breaker | Visitor waits until the client or a route timeout gives up | `mod/plugins/plugins.go:287`, `mod/plugins/dynamic_forwarder.go:24`, `mod/plugins/lifecycle.go:217-221`, `mod/dynamicproxy/dpcore/dpcore.go:392-394` |
| **Slow** (answers inside the timeout) | Counted as success; the breaker never trips on slowness. Stages add up: pre_auth + post_auth + response can each take up to the timeout, and legacy sniffs run **one plugin after another** | Added latency on every request of the attached rules, with no total budget | `mod/plugins/hooks_pipeline.go:125-146`, `mod/plugins/traffic_router.go:73-89` |
| Returns **garbage** to a filter call | Rejected: non-200, invalid JSON, oversize (>256 KiB) or invalid verdict counts as a failure; header / path / query changes are validated | Request continues untouched (fail open) | `mod/plugins/hooks_runtime.go:267-289`, `mod/plugins/hooks_validate.go:249`, tests `TestInvalidVerdictIsAFailureAndLeavesRequestUntouched`, `TestOversizedVerdictRejected` |
| Returns garbage on a capture | Passed straight to the visitor: a capturing plugin owns the whole response | Whatever the plugin sent | `mod/plugins/plugins.go:302-340` |
| Returns garbage at introspect | Not loaded, error logged; **the plugin does not appear in the UI at all** | n/a | `mod/plugins/plugins.go:143-147`, `mod/plugins/introspect.go:71-74` |
| **Floods logs** | Every line goes to the main log, no rate limit, no per-plugin file. Event delivery failures are also logged once per event | Disk fills; real Zoraxy messages are drowned | `mod/plugins/lifecycle.go:230-246`, `mod/eventsystem/event_system.go:164-168` |
| **Uses all memory / CPU** | No limit of any kind (no rlimit, no cgroup). Under systemd the plugin is in Zoraxy's cgroup, so a unit-level memory limit would hit Zoraxy too | Proxy slows or is OOM-killed | `mod/plugins/lifecycle.go:69-86` (nothing set); `docs/deploy/zoraxy.service` has no `MemoryMax` |
| Event receiver slow / down | One goroutine **per event per subscriber**, new `http.Client` each time, 10 s timeout, no queue limit. After a crash the subscription is kept, so every event logs a delivery error | Under an attack from blacklisted IPs: goroutine pile-up and log flood in Zoraxy | `mod/plugins/eventlistener.go:23-84`, `mod/eventsystem/event_system.go:145-176`, emitted per blocked request at `mod/dynamicproxy/access.go:77-86` |
| **Upgraded while running** (store update) | Stops the plugin, downloads to `.download`, **deletes the old binary**, renames, re-introspects, restarts. A failed download returns **with the plugin left stopped**. No checksum, no backup, no rollback, no health check after restart | Plugin feature gone until someone notices | `mod/plugins/store_update.go:103-206` (stop `:134-140`, failed download `:145-149`, delete `:152`) |
| Binary replaced on disk by hand | Not noticed (hot reload only in `-dev`). Next start uses the new file without any check | n/a | `start.go:455`, `mod/plugins/development.go:63-113` |
| **Fails to start at boot** | Error logged, no retry, UI shows "Start" with no reason | Plugin feature silently missing | `mod/plugins/plugins.go:158-163` |
| Stop called on a plugin that never started | `thisPlugin.process` is nil -> **nil-pointer panic** in the HTTP handler (recovered by `net/http`, so Zoraxy survives; not verified by running) | n/a | `mod/plugins/lifecycle.go:288` |

Also found while reading (correctness, not reliability features): `Plugin.Enabled` is written by the exit goroutine and
read on every request with no lock, and `StopPlugin` polls `ProcessState`, which only the other goroutine's `cmd.Wait`
sets (both are data races; not run under `-race`), `mod/plugins/lifecycle.go:152`, `:294-304`. `InstallPlugin` and
`UninstallPlugin` read `LoadedPlugins` without the lock, `mod/plugins/store.go:121`, `:193`.

### 1.3 The request path

Where plugins run (from `mod/dynamicproxy/Server.go:70`, `:328`, `:401`; `mod/dynamicproxy/plugin_hooks.go:19-30`):

```
access rules -> [pre_auth hooks] -> WAF / exploit / rate limit / CAPTCHA / auth -> [post_auth hooks] -> [legacy static capture] -> [legacy dynamic sniff, one plugin at a time] -> upstream -> [response hooks, headers only]
```

| Integration | Timeout | Breaker | Failure policy | Notes |
|---|---|---|---|---|
| Filter hooks (pre_auth, post_auth, response) | 2 s default, plugin may ask up to 10 s | yes, 5 fails / 30 s, one probe | fail-open; fail-closed only if manifest declares it **and** admin ticks it -> 503 (502 at response) | concurrent within a stage, validated verdicts. Fork addition (#83), well tested in `mod/plugins/hooks_test.go` |
| Legacy dynamic sniff (Data-Shield uses this) | 2 s default | yes | same as above | sequential across plugins, reply ignored except status, 4 KiB cap (`mod/plugins/dynamic_forwarder.go:44-65`) |
| Capture ingress (static and dynamic) | **none** | **no** | none: blank 200 on transport error | `mod/plugins/plugins.go:302-340` |
| Plugin UI | none | no | error text | `mod/plugins/ui_router.go:15-63` |
| Events | 10 s | no | logged per event | `mod/plugins/eventlistener.go:57-60` |

Plugins only apply to proxy rules whose **tags** match the plugin's group (`conf/plugin_groups.json`), or to all rules when
"Apply to all HTTP proxy rules" is ticked; a rule can opt out with the tag `no-plugin:<id>` or `no-global-plugins`
(`mod/plugins/hooks_pipeline.go:28-105`).

### 1.4 Trust and permission model

| Question | Answer | Evidence |
|---|---|---|
| Does a plugin run as root? | **By default it runs as the same user as Zoraxy** (root on your servers). Optional `-plugin_user` / `-plugin_group` drop to an unprivileged user; refuses uid/gid 0; Zoraxy must be root to use it | `def.go:126-127`, `mod/plugins/runas_unix.go:137-158` |
| Is that applied everywhere? | **No.** `-introspect` (which runs every newly downloaded binary immediately) and "Rebuild" (`make` / `go build`) always run as Zoraxy's user | `mod/plugins/introspect.go:61`, `mod/plugins/hotrebuild.go:50-78` |
| What can it read? | Everything that user can read: with the default that is `sys.db`, `conf/`, private keys. No sandbox | (no confinement code exists) |
| Secrets | API key and invoke token are in the command line, readable by **any local user** via `ps` / `/proc/<pid>/cmdline` | `mod/plugins/lifecycle.go:65-69` |
| Zoraxy API surface | Only routes registered in `plugin_api.go` under `/plugin/api/...`, on a loopback listener, Bearer API key, exact method + path match. Includes **write** routes (blacklist/whitelist add/remove, upstream add/remove, draining) | `plugin_api.go:21-133`, `mod/auth/plugin_middleware.go:36-66`, `mod/auth/plugin_apikey_manager.go:79-93` |
| How are permissions declared? | The plugin lists `permitted_api_endpoints` in its own manifest. They are **granted automatically at every start**; you are shown them (store and info dialog) but never asked to approve, and a new version can ask for more without you noticing | `mod/plugins/lifecycle.go:54-63`, `web/snippet/pluginInfo.html:158`, `web/components/appstore.html:1202` |
| Plugin UI | Proxied under the admin origin at `/plugin.ui/<id>/`, gets the admin CSRF token header and (from reading the code) the admin session cookie; shown in an iframe with `sandbox="allow-scripts allow-same-origin"`, which on the same origin is no real sandbox. **A plugin UI can call any admin API.** Viewer accounts are kept out | `mod/plugins/ui_router.go:47-57`, `web/components/plugincontext.html:26`, `router.go:47`, `:56-66` |
| Calls from Zoraxy to the plugin | Filter, sniff and capture calls carry a per-start secret (`X-Zoraxy-Plugin-Token`); **event calls do not**, so any local process can fake events to a plugin | `mod/plugins/hooks_runtime.go:238-240`, `mod/plugins/eventlistener.go:54-55` |
| Store trust | Official index is a GitHub raw URL; extra sources may be added (http allowed). If two sources offer the same plugin ID, **the higher version wins**, so an added source can take over updates of a plugin. No checksum, no signature. Install folder is built from the plugin **name** (not sanitised; a name with `../` would escape `plugins/`) | `start.go:450-453`, `mod/plugins/store_sources.go:81-103`, `mod/plugins/store_update.go:52-63`, `mod/plugins/store.go:113-187` |
| Audit | Admin changes through `/api/plugins/` are audit-logged under "plugins" | `mod/secaudit/http.go:56` |

In one sentence: **an enabled plugin is as powerful as Zoraxy's own user, and its UI is as powerful as the admin.** That is
acceptable for code you trust, but it is why reliability and supply-chain checks matter.

### 1.5 The UI today

- Plugin Manager shows an "Experimental feature" warning (`web/components/plugins.html:156`).
- Side menu shows "No Plugins Installed" when **no plugin is running** (`web/components/plugins.html:470-489`), so a crash of
  all plugins looks like "nothing installed". The Plugin Manager table instead says "No plugins installed. Browse the App
  Store" only when **none is loaded** (`:620-626`), which happens if every introspect failed or `./plugins` resolves to a
  different folder than the one the plugins were installed into (it is relative to the working directory, `def.go:125`).
  Which one you saw on Proxy2 I cannot tell from here (**not verified**).
- The only health signal is "Plugin is failing and is temporarily skipped" when a filter breaker is open
  (`web/components/plugins.html:547-549`). No running/crashed state, exit code, restart count, last error or logs.
- Author name and link from the manifest are inserted without escaping (`web/components/plugins.html:590`) - small XSS
  surface from a plugin manifest.

### 1.6 Your three plugins, and what you can do today

- **Data-Shield Blocklist** (router, legacy sniff `/sniff`, no hooks, no API rights). It only filters rules tagged with its
  plugin group or when attached globally; check Plugin Manager -> Plugin map. If it is attached nowhere it does nothing.
  If it crashes, traffic continues unfiltered with no alert. The fork's core already has scheduled blocklist import from
  an https URL (`ROADMAP.md:34-35`, `mod/access/blocklistimport`); Data-Shield's lists are published as plain text files
  on GitHub, so core can probably replace this plugin (**not verified** that its feed format matches).
- **Resource Monitor** (utility, UI only, no API rights). Cannot affect visitors. Worst case: memory/CPU use and log noise.
- **Cloudflare WAF** (third party, utility, 4 API rights incl. blacklist add/remove, subscribes `blacklistedIpBlocked`).
  Not in the request path, but every blocked request starts one goroutine and one HTTP call to it (section 1.2). It can
  change your blacklists. Its download URL is `.../releases/latest/download/...`, so what you install is whatever the
  author published last, not necessarily v0.4.0.
- **No-code actions now:** run Zoraxy with `-plugin_user=zoraxy-plugins` (create the user; `chown -R` the plugin folders as
  the error message suggests); grep the log for `encounted a fatal error. Disabling plugin` and `Failed to dispatch`;
  keep fail-closed consent **off** until phase 1 fixes its crash behaviour.

---

## 2. Failure-mode table

Severity: **S1** visitor outage or security exposure, **S2** silent loss of protection / data or misleading UI,
**S3** degraded or developer-only.

| # | Failure | Current behaviour (evidence in 1.2-1.4) | Desired behaviour | Sev |
|---|---|---|---|---|
| F1 | Plugin crashes | marked stopped in memory, no restart, no alert, subscriptions and API key kept | state `crashed` with exit code and last log lines in UI; optional restart with backoff; cleanup of events/key/UI proxy | S2 |
| F2 | Plugin exits with code 0 | not detected, traffic sent to dead port | treated as an exit like F1 | S1 |
| F3 | Fail-closed plugin crashes | traffic passes unfiltered | opt-in "block while this plugin is not running"; log-only counter of requests that would have been blocked | S2 |
| F4 | Capture target down | blank `200 OK` | 502 with the normal error page, counted, breaker | S1 |
| F5 | Capture / UI hangs | no timeout | response-header timeout and breaker on capture; UI timeout | S1 |
| F6 | Filter plugin hangs | 2 s per request until breaker opens, then skipped | same, plus health check and optional restart of a hung process | S3 |
| F7 | Slow but under timeout | no budget, stages and sequential sniffs add up | per-request plugin budget; slow-call breaker (optional) | S2 |
| F8 | Garbage verdict | rejected, fail-open | unchanged (good); add counter | S3 |
| F9 | Garbage/huge introspect | not loaded and invisible; output unbounded | listed as `failed to load` with reason; output capped | S2 |
| F10 | Log flood / no newline | every line to main log; unbounded line buffer | per-plugin ring buffer + file, line cap (always), rate limit (opt-in) | S2 |
| F11 | Memory / CPU / fd / process exhaustion | no limits | optional per-plugin limits (systemd scope or rlimits) | S1 |
| F12 | Event storm to slow subscriber | goroutine per event, no bound, log per failure | bounded per-plugin queue, drop + count, one log line per minute | S1 |
| F13 | Update fails mid-way | old binary deleted first; failed download leaves plugin stopped | staging folder, verify, atomic swap, keep previous, restart old on failure, rollback button | S2 |
| F14 | Tampered or swapped binary | no checksum or signature; "latest" URLs | sha256 + ed25519 signed index, pinned URLs; warn (default) / enforce | S1 |
| F15 | Store source hijacks a plugin ID | higher version from any source wins | updates only from the source the plugin was installed from | S1 |
| F16 | Path from plugin name | not sanitised | folder from sanitised ID | S2 |
| F17 | Plugin is root | default same user as Zoraxy; introspect and rebuild always | documented recommendation; introspect under `-plugin_user` too | S1 |
| F18 | Secrets on command line | visible via `ps` | delivered on stdin for SDKs that support it (negotiated), old way kept for old plugins | S2 |
| F19 | Permissions granted silently | auto-granted at every start | shown as a diff on install/update; approval required (opt-in, log-only default) | S2 |
| F20 | Plugin UI = admin | same origin, admin cookie, CSRF token | opt-in isolated UI origin without admin cookie | S1 |
| F21 | Events unauthenticated | no token | send invoke token on events too (additive header) | S3 |
| F22 | Not ready when attached | hooks attached before the plugin listens | wait for TCP accept (log-only measure first, then opt-in gate) | S3 |
| F23 | Start at boot fails | logged only | state `failed to start` with reason in UI; optional retry | S2 |
| F24 | Never-enabled plugin starts at next boot | missing DB flag = enabled | install writes `enabled=false` (bug fix, matches what the UI shows) | S2 |
| F25 | Stop of never-started plugin | nil-pointer panic | error "not running" | S3 |
| F26 | Data races on `Enabled` / `ProcessState` | racy | atomic state owned by a supervisor goroutine | S3 |
| F27 | `start.sh` children survive stop | signal to shell only | process group (`Setpgid`), signal the group | S3 |
| F28 | Port race / exhaustion | random 5800-6000, infinite loop if full | plugin binds port 0 and reports it, or bounded retry with error | S3 |
| F29 | Incompatible plugin (old/new SDK) | no negotiation; only hooks have a version field | contract version in introspect and configure; warn on mismatch | S2 |
| F30 | Rebuild runs `make` as root, no timeout | yes | developer-only; timeout, run as plugin user | S3 |

---

## 3. What is missing for "reliable"

| Area | Have today | Missing |
|---|---|---|
| Supervision | exit detected only on error | state machine (`stopped, starting, ready, running, exited, crashed, crash-looping, failed-to-load, failed-to-start`), restart policy `never` / `on-failure` with exponential backoff (1 s -> 5 min, jitter) and a crash-loop limit (e.g. 5 in 10 min), cleanup on every exit |
| Health checks | breaker on filter calls | readiness (TCP accept on its port), liveness (`GET /health` if the SDK serves it, else TCP), restart on N failed probes (opt-in) |
| Timeouts / breaker | filter + sniff | capture ingress and UI timeouts, breaker on capture, per-request total plugin budget, slow-call threshold, admin can lower (never raise) a plugin's timeout |
| Fail-open / closed | per plugin, consent needed | consistent across hang **and** crash (opt-in), shown clearly per plugin, counted |
| Resource limits | none | Linux: optional `systemd-run --scope` per plugin with `MemoryMax`, `CPUQuota`, `TasksMax` when systemd is available; otherwise `prlimit` for `NOFILE`, `NPROC`, `CORE`; Windows: none (known limit) |
| Crash / restart history in UI | none | per plugin: state, uptime, restarts, last exit code, last error, last 200 log lines, history of last 20 exits |
| Version / API contract | `hooks.version` only | `api_version` in introspect, supported range in configure, compatibility matrix, warn on mismatch |
| Safe install / upgrade / rollback | none | staging folder, size limit, sha256 + signature, introspect in staging as the plugin user, atomic swap, keep previous version, post-start health check, rollback |
| Signature checks | release updater only (`tools/sign_release.go`) | the same ed25519 format for a fork-curated plugin index |
| Conformance kit | none | `zoraxy-plugin-check`: runs a binary through introspect, configure, readiness, health, term, verdict schema, token check, timeouts, log and memory behaviour; JSON report |
| Fault-injection suite | `TestPluginDownDoesNotHang`, breaker / timeout tests with in-process fakes, e2e kill -9 in `tools/e2e/scenarios/s12_plugin.py` | a real "chaos" plugin binary with modes: crash at start / after N s, exit 0, panic in handler, hang, slow, bad JSON, huge body, no newline output, log flood, memory balloon, ignore SIGTERM, introspect hang / garbage, fork children |
| Stable SDK with semver | copied folder (`example/plugins/build_all.sh` copies `src/mod/plugins/zoraxy_plugin`) | a Go module with tags (`sdk/v1.x.y`), changelog, compatibility tests with binaries built against older SDKs |
| Observability | log lines | Prometheus series per plugin (calls, failures, latency, breaker state, restarts, dropped events, log lines dropped) via the existing `-metrics` endpoint (off by default), per-plugin log file, last error in the API |
| UI states | "experimental", "No Plugins Installed" | correct empty states ("3 installed, none running"), health column, banners for crashed / crash-looping / unsigned / new permissions |
| Documentation | upstream author docs in `docs/plugins/docs/` | operator guide: trust model, `-plugin_user`, failure policies, known limits; author guide: contract, health endpoint, conformance; ROADMAP section 8 is stale (lists hooks as planned, `ROADMAP.md:100-103`) |

---

## 4. Should the fork ship its own first-party plugins?

**Short answer: yes, but only as reference implementations and test fixtures, plus a few optional integrations. Do not move
core security features into plugins, and do not add more plugin hook points until the reliability work below is done.**

Reasoning:

1. **Core is the right place for anything on every request.** WAF (Coraza), CrowdSec, CAPTCHA, rate limits, access rules
   and the blocklist are in the hot path, share state with the router, have their own tests and fail-open/closed logic
   already, and are in the signed release. As a plugin each would add a JSON-over-HTTP round trip per request, a second
   process that can crash, an extra supply chain, and the trust problems in 1.4. Moving them out would make the proxy
   less reliable, not more.
2. **The fork already has a safer extension point for small per-request logic:** sandboxed Lua scripts in core
   (`mod/luascript/sandbox.go:1-20`: time, heap, size and concurrency limits, no I/O). Method filters, header rules and
   path access control (several community plugins do exactly this) are better as a Lua snippet or a core rule than as a
   process.
3. **Plugins are the right place for optional integrations with outside systems** that most users do not want in the
   binary: Cloudflare IP list sync, Docker upstream discovery, DynDNS allow-lists, niche notifiers. These are not in the
   request path, so a crash costs a feature, not an outage.
4. **First-party plugins pay for themselves as fixtures.** We cannot make "plugins reliable" without plugins we control
   to test against. Three small ones cover the whole contract:
   - `fork-ref-filter`: pre_auth + response hooks, declares fail_closed, serves `/health`; used by the fault suite.
   - `fork-ref-events`: subscribes to events with a bounded queue and acks fast; used to test event back-pressure.
   - `fork-ref-ui-api`: UI plus one read and one write permitted endpoint; used to test permissions and UI isolation.
   They live in `example/plugins/`, are built and signed with each release, and are what the conformance kit is checked
   against. They are not features you must run.
5. **A smaller, stricter plugin surface is better than more hooks.** Recommendation: freeze the surface at the three
   filter stages + events + UI + permitted API; mark static/dynamic capture as "legacy" (keep them working, steer new
   plugins to hooks, which have the breaker and validation); no new hook points before phase 3.
6. **Your three plugins:** Resource Monitor and Cloudflare WAF stay plugins (low risk / genuinely external). Data-Shield
   can probably be replaced by the core scheduled blocklist URL import, which is signed with the release, faster and has
   a dry-run; compare both on Proxy1 before deciding (decision D5).

**Cost:** about 8-11 engineer-days in phase 3 (three reference plugins about 3-4 days, conformance kit about 4-5 days,
running it against your three plugins and writing up results about 1-2 days), plus about half a day per release to
rebuild and sign them. Not doing it means phases 0-2 are tested only against fakes and third-party plugins we cannot change.

---

## 5. Phased plan

Every phase is one or more PRs into `dev`, each with tests and a "known limits" note in `docs/plugins/` and DEVELOPMENT.md.
Tests that start real plugin processes are light (tiny Go or shell binaries) but must run one suite at a time on Proxy1
(`nice`, `GOFLAGS=-p=2`) to respect the shared 4-core machine. Effort is engineer-days including tests.

### Phase 0: measure and stop the bleeding (4-5 days, no behaviour change except bug fixes)

| Item | Scope | Files / areas | Test that proves it | Known limits | Days | Risk |
|---|---|---|---|---|---|---|
| 0.1 Chaos plugin | test-only binary with modes (see section 3) selected by env var; built by the test from Go source in `testdata` | `src/mod/plugins/testdata/chaosplugin/` | used by 0.2 and every later phase | Linux/macOS only in CI; Windows skipped | 1 | low |
| 0.2 Fault suite | Go tests starting the real chaos plugin through `StartPlugin`: crash, exit 0, hang, slow, bad JSON, huge body, flood, no newline, ignore SIGTERM, introspect hang. Phase 0 asserts **today's** behaviour (documents it), later phases flip the assertions | `src/mod/plugins/fault_test.go` | itself; also run with `-race` | asserts on logs are string matches | 1-1.5 | low |
| 0.3 Read-only status | supervisor-owned state, exit code, last error, start time, exit history (last 20), last 200 log lines (ring buffer), counters per plugin (calls, failures, timeouts, breaker opens, dropped events); exposed in `/api/plugins/list` (additive fields) and Prometheus when `-metrics` is on | `mod/plugins/lifecycle.go`, `typdef.go`, new `status.go`, `mod/metrics` | unit tests on state transitions with the chaos plugin; API shape test | counters reset on restart; history in memory only | 1.5 | low |
| 0.4 UI read-only | correct empty states ("N installed, none running"), state badge, last error, log viewer, `failed to load` entries for plugins whose introspect failed | `web/components/plugins.html`, `web/snippet/pluginInfo.html`, `mod/plugins/plugins.go` (keep failed entries) | ui-smoke scenario (Chromium) with one good and one broken plugin | Chromium only | 1 | low |
| 0.5 Bug fixes | F2 (exit 0 is an exit), F4 (write 502 on capture error), F24 (install writes enabled=false), F25 (nil deref), F26 (races), cleanup on crash (unsubscribe, revoke key, drop UI proxy), line length cap (64 KiB), F16 (folder from sanitised ID for new installs only), escape author in UI | `lifecycle.go`, `plugins.go`, `dynamic_forwarder.go`, `store.go`, `plugins.html` | fault suite assertions flipped for these cases; `-race` clean | F2 changes visible behaviour (a dead plugin stops being "running") but no request-path policy; existing install folders are not renamed | 1 | low-medium |

### Phase 1: supervision, timeouts, limits, UI health (10-13 days)

| Item | Scope | Files / areas | Test that proves it | Known limits | Days | Risk |
|---|---|---|---|---|---|---|
| 1.1 Supervisor | per-plugin goroutine owns the process; restart policy `never` (default, = today) or `on-failure` with backoff 1 s -> 5 min and crash-loop stop (5 in 10 min); in `never` mode it logs "would restart in Xs" | new `mod/plugins/supervisor.go`, `lifecycle.go` | chaos crash every 1 s -> backoff timings, crash-loop state, no restart in `never` | backoff state in memory, reset on Zoraxy restart | 2.5 | medium |
| 1.2 Readiness and health | measure time-to-listen (log-only); opt-in gate that attaches hooks only after TCP accept (timeout 10 s); optional liveness probe (`/health` if declared, else TCP) with restart after N failures | `supervisor.go`, SDK `zoraxy_plugin.go` (optional `HealthPath`) | chaos "slow start" and "hang"; probe-triggered restart only when opted in | TCP probe cannot see a deadlocked handler; `/health` needs SDK support | 1.5 | medium |
| 1.3 Timeouts everywhere | capture ingress and UI proxies get a response-header timeout and the existing breaker; per-request total plugin budget (log-only: count and log requests over budget; opt-in enforce); admin can lower a plugin's timeout | `plugins.go`, `dynamic_forwarder.go`, `ui_router.go`, `hooks_pipeline.go`, `traffic_router.go` | chaos hang on static capture returns 504 within the timeout; budget counter | capture timeout default must be generous (long downloads); websockets exempt | 1.5 | medium |
| 1.4 Consistent fail-closed | opt-in per plugin "also block while this plugin is not running"; default: log-only counter "N requests passed while a fail-closed plugin was down", shown in UI | `hooks_pipeline.go`, `traffic_router.go`, `hooks_runtime.go` | chaos crash with consent: default passes + counts; opted in: 503 | only for plugins that declare fail_closed | 1 | medium (can block traffic when turned on) |
| 1.5 Bounded events | per-plugin queue (e.g. 1000), one worker, shared client, drop oldest + count, one log line per minute; invoke token sent on events (additive) | `eventlistener.go`, `mod/eventsystem/event_system.go` | 50k events at a hung subscriber: goroutines stay bounded, drops counted | dropped events are lost (by design) | 1 | low |
| 1.6 Log handling | per-plugin log file with rotation and ring buffer (always); rate limit lines/s (opt-in, default off: count only) | `lifecycle.go`, `mod/info/logger` | chaos flood: main log stays small, counter matches | per-plugin files add disk use (capped) | 1 | low |
| 1.7 Resource limits | opt-in per plugin: memory, CPU, tasks via `systemd-run --scope` when running under systemd as root; else `prlimit` (NOFILE, NPROC, CORE); process group kill (F27) | new `limits_linux.go`, `limits_other.go`, `runas_unix.go` | chaos memory balloon is killed at the limit and shows `crashed (OOM)`; Zoraxy unaffected | needs systemd + root for memory/CPU; `RLIMIT_AS` not used (breaks Go programs); none on Windows; reference unit has `ProtectControlGroups=yes`, so the scope route goes through systemd, not cgroupfs | 2 | medium-high |
| 1.8 UI health | health column, crash history, restart button, policy and limits per plugin, banners for crashed / crash-looping; drop the "experimental" label only when phase 1 is complete **and** the fault suite is green | `web/components/plugins.html`, `web/snippet/pluginInfo.html` | ui-smoke: crash shows red state and history; restart works | Chromium only | 1.5 | low |

### Phase 2: contract, SDK, signed store, safe install (12-16 days)

| Item | Scope | Files / areas | Test that proves it | Known limits | Days | Risk |
|---|---|---|---|---|---|---|
| 2.1 Contract | `api_version` in introspect (missing = 0, legacy), supported range sent in configure; warn on mismatch (default), opt-in refuse; written spec `docs/plugins/contract.md` with stability rules | `zoraxy_plugin/zoraxy_plugin.go`, `introspect.go`, `lifecycle.go` | golden manifests from every example plugin and from the three installed plugins parse unchanged; mismatch warning test | old third-party plugins stay "legacy" until their authors update | 2 | low |
| 2.2 SDK module | turn `zoraxy_plugin` into a Go module with semver tags and changelog; keep the copy workflow working; compatibility test: binaries built with SDK v1.0 still pass the fault suite against new Zoraxy | `src/mod/plugins/zoraxy_plugin/go.mod`, `example/plugins/build_all.sh`, CI | compat test job | module path decision (in-repo vs separate repo) | 2 | medium |
| 2.3 Secrets off the command line | SDK declares `config_via: stdin`; Zoraxy writes configure JSON on stdin for such plugins, `-configure` stays for others | `lifecycle.go`, SDK | `ps`-style check: cmdline of a new-SDK plugin contains no key | old plugins keep the leak until rebuilt | 1 | low |
| 2.4 Signed index | fork-curated index: per platform pinned URL + sha256 + size, signed with ed25519 in the `tools/sign_release.go` format (separate plugin key recommended); verification mode `off` / `warn` (default) / `enforce`; updates only from the source of install (F15) | `store.go`, `store_update.go`, `store_sources.go`, new `store_verify.go`, `tools/` | tampered binary, wrong hash, bad signature, replayed old index -> warn / refuse per mode | only plugins the fork curates are signed; upstream index has no hashes (shown "unsigned") | 3 | medium |
| 2.5 Safe install / update / rollback | download to `plugins/.staging/<id>/` with size cap and timeouts, verify, introspect there **as the plugin user**, atomic swap keeping `previous/`, start, health check, auto-rollback (opt-in) or manual rollback button; failed download restarts the old version | `store.go`, `store_update.go`, `introspect.go`, UI | chaos "new version crashes at start" -> rollback restores old, plugin running | one previous version kept; script plugins excluded as today | 3 | medium |
| 2.6 Permission approval | diff of `permitted_api_endpoints` on install/update; default log-only (audit entry + UI badge), opt-in "require approval" grants only approved endpoints | `lifecycle.go`, `mod/auth/plugin_apikey_manager.go`, UI | update that adds `blacklist/ip/add` is not granted until approved (opt-in) | a plugin may still misuse rights it was granted | 1.5 | low |
| 2.7 Isolated plugin UI (opt-in) | serve plugin UIs from a separate loopback-proxied origin/port, strip admin cookie and CSRF token, iframe sandbox without `allow-same-origin` | `ui_router.go`, `router.go`, `plugincontext.html` | admin API call from plugin UI fails when isolated, works when not | plugin UIs that call admin APIs break when isolated; candidate default for new installs in 4.0 only | 2-3 | medium-high |

### Phase 3: first-party reference plugins and conformance (8-11 days)

| Item | Scope | Files / areas | Test that proves it | Known limits | Days | Risk |
|---|---|---|---|---|---|---|
| 3.1 Reference plugins | `fork-ref-filter`, `fork-ref-events`, `fork-ref-ui-api` (section 4), built and signed with releases, listed in the fork index | `example/plugins/fork-ref-*`, `tools/build_release.sh` | each passes the conformance kit and the fault suite; e2e scenario extended from `tools/e2e/scenarios/s12_plugin.py` | maintained by us; minimal features on purpose | 3-4 | low |
| 3.2 Conformance kit | `zoraxy-plugin-check <binary>`: introspect validity and size, configure, readiness, health, `/term`, SIGTERM within 5 s, verdict schema, token check, latency under load, log volume, memory after 1k calls; JSON + text report | `tools/plugin-check/` | runs green on reference plugins, red on the chaos plugin in each bad mode | black-box; cannot prove absence of bugs | 4-5 | low |
| 3.3 Certify your plugins | run the kit against Data-Shield, Resource Monitor, Cloudflare WAF; publish results in `docs/plugins/`; open issues upstream with the authors; "conformance passed for API vX" flag in the fork index | docs, index | report committed | third-party fixes depend on their authors | 1-2 | low |

### Totals

| Phase | Days | Ship as |
|---|---|---|
| 0 | 4-5 | one PR, fork patch release |
| 1 | 10-13 | two or three PRs (supervisor + health, timeouts + events + logs, limits + UI) |
| 2 | 12-16 | three PRs (contract + SDK + secrets, signed store + safe install, permissions + UI isolation) |
| 3 | 8-11 | two PRs |
| **Total** | **34-45** | |

Biggest risks: 1.7 (limits need systemd and root, platform differences), 2.7 (breaks plugin UIs that use admin APIs,
opt-in for that reason), 1.4 (when switched on it can block traffic). Everything else is additive.

---

## 6. Decisions needed from you

| # | Decision | My recommendation |
|---|---|---|
| D1 | Goal of "100 % reliable": every third-party plugin, or "the plugins you run + our reference plugins, with a kit that tells you whether any other plugin is safe"? | The second. We cannot fix other people's plugins; we can make Zoraxy survive them and tell you which ones misbehave. |
| D2 | Restart policy default once phase 1 ships | Keep `never` (today's behaviour) for all installs; turn on `on-failure` per plugin yourself after a few weeks of crash history. Revisit "on for new installs" in 4.0. |
| D3 | Fail-closed when a consenting plugin is **not running** | Opt-in per plugin, default log-only counter. Keep fail-closed consent off on Proxy2 until then. |
| D4 | Signed plugin index: who curates, which key, default mode | A fork-curated index signed with a **separate** plugin key (not the release key), mode `warn` by default, `enforce` opt-in. You approve each plugin added. |
| D5 | Data-Shield Blocklist | Run the core scheduled blocklist URL import next to it on Proxy1 in dry-run, compare, then retire the plugin if equal. |
| D6 | Order and scope | Phase 0 now (small, no behaviour change); decide on 1-3 after you see the status page and the fault-suite results. Also: run plugins with `-plugin_user` on Proxy2 now (no code). |

---

## Appendix A: what I could not verify

- Nothing was built or run; all behaviour is from reading the code. In particular: the blank `200 OK` on capture errors
  (F4), the nil-pointer panic (F25), the data races (F26) and that the admin cookie reaches the plugin UI are inferred
  from code, not observed.
- I did not see Proxy2: which plugins are enabled, whether they are attached to any rule, whether they have crashed, the
  working directory and `-plugin` path, and whether `-plugin_user` is set.
- The three plugins' behaviour (their own timeouts, memory use, whether they serve `/term`, how Data-Shield decides) is not
  known; only their public manifests were read (official index, fetched 2026-11-22). The installed binaries may differ
  from the index because downloads use "latest" URLs.
- Whether Data-Shield's feed works with the core blocklist URL import is not checked.
- The day figures are human-engineer estimates, not measured; with AI-assisted builds expect hours for the code and a similar amount of time again for verification (see the total in the summary table).

## Appendix B: existing tests to build on

`mod/plugins/hooks_test.go` (timeouts, fail-open/closed consent, breaker, oversized and invalid verdicts, plugin down
does not hang, concurrency, invoke token), `mod/plugins/lifecycle_test.go` (output readers and race), `runas_test.go`,
`store_test.go`, `offline_test.go`, `ruleinfo_test.go`; end to end `tools/e2e/scenarios/s12_plugin.py` (filter example,
kill -9, fail-open) and `tools/e2e-admin/scenarios/s13_plugins_https.py`; recorded in `docs/verification/e2e-admin.md:40`.

---

## Phase 0 results and known limits

Built 2026-11-22 on `dev`. Sections 1 to 6 above describe the code before this work; this section says what changed.
Nothing here changes how a request is decided: no restart, no new timeout, no new blocking. Plugins still fail open.

### What was built

| Item | Where | Notes |
|---|---|---|
| 0.1 Chaos plugin | `src/mod/plugins/testdata/chaosplugin/main.go` | Standard library only, builds offline. Modes: `ok`, `crash`, `exit0`, `hang_start`, `never_ready`, `hang`, `slow`, `badjson`, `huge`, `logflood` (includes one 1 MiB line without newline), `ignore_sigterm`, `introspect_garbage`, `introspect_hang`. The mode comes from a `chaos.conf` file next to the binary (the plan said an environment variable; a file is needed because several chaos plugins with different modes run in one Zoraxy). `CHAOS_MODE` overrides it |
| 0.2 Fault suite | `src/mod/plugins/fault_test.go`, `fault_bugs_test.go`, `chaos_helper_test.go` | Starts the real binary through the real `StartPlugin` / `StopPlugin` / hook / capture code. 35 top-level tests (8 `TestBug...`, 27 others; 8 of them were added after the phase 0 review). Tests of a known weakness say "today" in a comment and assert today's behaviour |
| 0.3 Status model | `src/mod/plugins/status.go`, `lifecycle.go`, `typdef.go` | Per plugin: state `running`, `stopped`, `crashed`, `exited`, `failed_to_start`; while running a health hint `ok`, `not_responding`, and in the status view of the Plugin Manager (or everywhere with the start flag `-plugin_port_probe`, off by default) also `starting` and `not_listening`; PID, started-at, exited-at, last-seen, exit code and reason, last problem, start count and restart count. Additive `Status` object in `/api/plugins/list`, `/api/plugins/info` and the tag listing. New admin route `/api/plugins/status` (GET: all plugins plus folders that failed to load; POST with `plugin_id`: one plugin plus its last 40 output lines; `probe=true` on any of them: also look whether the port of each running plugin is open) |
| 0.4 UI | `src/web/components/plugins.html`, test: `tools/ui-smoke/plugins_smoke.py` (in `smoke.py`, alone with `--plugins-only`) and `plugins_run.sh` (adds real plugins) | Status column with badge, one line of context and the problem; "Details" row (process facts, last problem, last output); summary line; red notice for folders that could not be loaded; status refreshes every 10 s while the page is shown. Side menu: "No Plugins Installed" only when nothing is installed, else "N plugins installed, none running" or "N plugins stopped unexpectedly" (both open the Plugin Manager) |
| 0.5 Bug fixes | see next table | |

### Bugs fixed (each has a test that fails on the code before the fix)

The eight `TestBug...` tests of `fault_bugs_test.go` only use API that existed before. They were run, one by one, against
an export of the previous commit (`git archive HEAD src/mod src/go.mod src/go.sum` into a scratch folder, plus the two test
files and the chaos plugin). Seven failed there without the race detector and pass now. The eighth
(`TestBugNoDataRaceBetweenRequestsStopAndCrash`) only fails under `-race`: there it reported data races between
`StartPlugin` / `StopPlugin` and the request path and list API (`lifecycle.go:168`, `:222`, `hooks_pipeline.go:91`,
`handler.go:171` of the old code); it is clean now.

| # | Bug (before) | Now | Test |
|---|---|---|---|
| F2 | A plugin that exited with code 0 stayed "running" and enabled; calls kept going to a dead port | Every exit is handled. State `exited`, the plugin is detached | `TestBugCleanExitIsNoticed`, `TestFaultCleanExitIsReported` |
| F1 (clean-up part) | After a crash the UI proxy, the capture routers, the API key and the event subscriptions were kept | One `detachPlugin` path for stop, crash and clean exit removes all of them and rebuilds the tag maps | `TestBugCrashCleansUp` (UI proxy, API key), `TestFaultStaticCaptureWhileRunningAndAfterCrash` |
| new | A plugin that died during start-up could be flipped back to "enabled" by `StartPlugin` (the exit goroutine ran before the flag was set) | The running state is published before the exit watcher starts | `TestBugCrashAtStartStaysDisabled` |
| new | Starting a plugin that is already running started a second process and lost track of the first | Refused with "plugin is already running" | `TestFaultStatusRunningStoppedRestarted` |
| F25 | Stop of a plugin that never started: nil-pointer panic (observed, was "not verified" in 1.2) | `StopPlugin` returns `ErrPluginNotRunning`. `DisablePlugin` (the Stop button) stores enabled=false and answers OK, because what the administrator asked for is done | `TestBugStopNeverStartedPluginDoesNotPanic`, `TestFaultDisableOfDeadPluginSucceeds` |
| F26 | Data races on `Enabled`, `ProcessState`, the proxy fields and the static capture map (a concurrent map write can end the whole process) | Runtime fields behind `Plugin.mu`; `StopPlugin` waits on a channel closed by the one goroutine that calls `Wait`; all JSON output goes through one locked snapshot | `TestBugNoDataRaceBetweenRequestsStopAndCrash`, `TestFaultConcurrentRequestsDuringStartStopCrash` under `-race` |
| F4 | Capture target unreachable: the visitor got an **empty 200 OK** (observed, was "not verified" in 1.2) | `502` with a short text body; the failure is recorded as the last problem of the plugin. A body cut off after the headers aborts the connection, like the core proxy does | `TestBugCaptureTargetDownIs502NotEmpty200`, `TestFaultCaptureRaceWithExitGives502` |
| F24 | A plugin installed from the store and never enabled started by itself at the next Zoraxy start | Every store install writes enabled=false, also when a state is left from an earlier install of the same ID | `TestBugInstalledPluginDoesNotAutostartAtNextBoot`, `TestFaultReinstallDoesNotInheritEnabledState` |
| F16 | The install folder was the plugin name from the store index (`../` could leave the plugin directory) | Name reduced to letters, digits, space, dot, dash, underscore; no `..`, no leading dot; falls back to the ID; the result must be a direct child of the plugin directory. Normal names are unchanged. An install into a folder that already holds something is refused (two store names can map to one folder), and a failed install removes the folder it created | `TestBugInstallFolderCannotLeavePluginDir`, `TestSafePluginFolderName`, `TestFaultInstallNeverWritesIntoAnOccupiedFolder` |
| F10 (line cap part) | An output line without a newline grew in memory without limit; output was read one byte at a time | Lines are cut at 64 KiB and the rest of that line is dropped | `TestReadPluginOutputCutsLongLines`, `TestFaultLogFloodStaysBounded` |
| 1.5 | Author name and contact link, descriptions and plugin IDs were put into the Plugin Manager HTML without escaping; the output of a failed "Rebuild" was put into the error dialog as HTML | Escaped; IDs are passed to the buttons as data attributes; build output is set as text | `tools/ui-smoke/plugins_smoke.py` (hostile manifest in a real instance, headless Chromium) |
| review | The clean-up after a crash ran without the start / stop lock: a start in the same instant could lose its new API key and event subscriptions | The exit watcher takes the lock for the clean-up | `TestFaultExitDetachWaitsForStartStopLock` (deterministic), `TestFaultRestartRightAfterCrashKeepsNewKey` (5 rounds; passes with and without the fix on most runs, so it is a smoke test only) |
| review | A stop that arrived while the last output of a crashed plugin was drained (up to 300 ms) made the crash a plain "stopped", not logged as a crash | Whether the exit was asked for is read when the process ends | `TestFaultStopDuringOutputDrainKeepsCrash` |
| review | The "last problem" could quote text from a plugin answer (a header name, bytes of a non-JSON answer) | Rejected answers are shown as "invalid verdict" / "invalid verdict JSON" only; the detail goes to the log line when the breaker opens | `TestFaultRejectedVerdictTextIsNotInStatus` |
| F9 (visibility part) | A folder whose introspect failed was invisible | Listed by `/api/plugins/status` and shown as a red notice | `TestFaultIntrospectGarbageIsListedAsLoadFailure` |
| docs | `ROADMAP.md` section 8 listed the hook API as planned | Updated | n/a |

Also changed while fixing the above: the wait for a stopping plugin ends as soon as the process is gone (before: polled once
per second), and every start re-attaches the static capture paths (needed because every stop and exit now removes them;
before, a store update or "Rebuild" kept stale ones).

### What the suite showed about today's behaviour (unchanged, by design)

- **Hang** (`hang`, `never_ready`): each request waits for the plugin's call timeout (300 ms in the fixture, 2 s by
  default) until 5 calls have failed, then the breaker opens and requests pass at once. Fail-open.
- **Fail-closed with consent**: a hung plugin gives 503. A **crashed** one lets traffic pass unfiltered (F3 confirmed).
  `TestFaultFailClosedHoldsForHangButNotForCrash` will fail on purpose when phase 1 changes this.
- **Slow but inside the timeout**: counts as success, never trips the breaker, visible nowhere (F7).
- **Bad JSON, oversized verdict**: rejected, request untouched (F8 confirmed).
- **Hang at start**: the plugin is attached at once, calls fail fast with "connection refused" (F22).
- **Log flood**: Zoraxy stays responsive; every line still goes to the main log (F10, the rate limit is phase 1).
- **Ignores SIGTERM**: killed after the grace period (5 s), state `stopped`, reason `signal: killed`.
- **Static capture after a crash**: the path falls through to the upstream of the rule.

### Behaviour that changed for existing installs

1. A plugin that exits with code 0 is shown as "Exited" and is no longer called.
2. A dead capture plugin gives 502 instead of an empty 200.
3. The Stop button (`/api/plugins/disable`) on a plugin that is not running answers OK and stores "do not start at
   boot" (before: panic, or a 5 s wait and "OK"). Starting a running plugin answers "plugin is already running".
4. A store install no longer starts the plugin at the next boot unless it was enabled after that install. Plugins
   installed before this change keep their stored state (a missing state still counts as enabled, as before).
   A store install whose folder already exists and is not empty is refused (before: it overwrote the files in it), and
   a failed install leaves no folder behind (before: a partly written one).
5. After a crash the plugin's API key is revoked and its event subscriptions are removed at once.
6. **The Plugin Manager page looks at the port of running plugins while it is on screen** (owner decision 1 in
   "Second review round" below). The page reads `/api/plugins/status?probe=true` when it is opened and every 10 s
   while it is shown; for that call Zoraxy opens and closes one TCP connection to the loopback port of every running
   plugin, at most once per 2 s per plugin, to tell "Starting" and "Not listening" from "Running". No HTTP request is
   sent. Nothing else causes a connection: not the plugin list API (side menu, admin UI start, plugins that were
   granted the list endpoint), not a status call without `probe=true`, and not the page while another page or
   another browser tab is in front (`TestFaultPortProbeOnlyForTheStatusView`, `TestFaultPortProbeIsOffByDefault`,
   and the "probe" checks of `plugins_smoke.py`). The start flag `-plugin_port_probe` (off by default) still turns
   the probe on for every listing, for whoever wants the two states in the API as well.
7. Nothing else.

### Known limits

- **"Not responding" needs traffic.** It is derived from failed filter / sniff calls (breaker open, or 3 failures in
  a row). A hung plugin that only has a UI, or that gets no requests, shows "Running". A real health probe is phase 1 (1.2).
- **"Starting" and "Not listening" exist only where the port is probed**: in the Plugin Manager while it is on
  screen, and everywhere with `-plugin_port_probe`. In `/api/plugins/list`, `/api/plugins/info`, the side menu and
  the plugin info panel a plugin that never opens its port shows "Running" until calls to it fail (then "Not
  responding"), so the page and the API can disagree about such a plugin. The probe is a TCP connect only: a plugin
  that opened its port but never accepts (`never_ready`) looks healthy until calls fail. A plugin that logs or counts
  every accepted connection sees one short connection every 10 s while an administrator has the page open. The 10 s
  "Starting" grace is fixed.
- **Not done in phase 0** (planned in items 0.3 and 0.4, carried into phase 1 item 1.8 unless noted):
  - exit history (last 20 exits): only the last exit is kept;
  - counters per plugin (calls, failures, timeouts, breaker opens, dropped events);
  - Prometheus series for plugin status (`mod/metrics` was outside this change);
  - the last 200 log lines: 40 are kept (phase 1 item 1.6 adds the per-plugin log file);
  - status in the plugin info side panel (`web/snippet/pluginInfo.html`, outside this change);
  - notes in DEVELOPMENT.md (outside this change; this section is the only documentation);
  - the "No Plugins Installed" placeholder of `index.html` (outside this change): it is still shown for the moment
    before the plugin list is loaded.
- **Status is in memory.** It is lost when Zoraxy restarts and when a plugin is hot-reloaded in `-dev` mode.
- **Last output is 40 lines per plugin**, each cut at 512 bytes, memory only. It is returned only by
  `POST /api/plugins/status`. Plugins cannot reach it (it is not in `plugin_api.go`). Read-only (viewer) accounts are
  refused every POST that is not on their allow-list (`mod/auth/router.go`), and every POST under `/api/plugins/` is
  written to the security audit log (`mod/secaudit/http.go`), so opening "Details" leaves a `plugins.status` entry.
  Both follow from reading that code; neither was tested here.
  The "last problem" text in the list API is worded by Zoraxy: it contains no plugin output, no text from a
  rejected plugin answer and no text of a network or HTTP client error (such a text can quote bytes the plugin sent,
  as in `malformed HTTP response "..."`, and the address or path that was called). Failed filter calls, health checks,
  captures and UI requests show one of a few fixed wordings ("the plugin did not answer in time", "connection
  refused", "the plugin closed the connection", ...); the full error of a failed capture or UI request goes to the
  log, quoted and cut at 300 bytes, at most once a minute per plugin (`TestLastProblemNeverQuotesANetworkError`,
  `TestFaultRejectedVerdictTextIsNotInStatus`). What it can still contain: a file path and an OS error when a start
  failed, an exit status, and numbers. Read-only accounts and plugins that were granted `/plugin/api/plugins/list`
  can read it. The **load failure** text of a folder that is not a plugin is the raw error of the JSON parser or the
  OS and is only in `/api/plugins/status`, which plugins cannot call.
- **Restart count** counts starts by an administrator, a store update or a rebuild. Zoraxy still never restarts a plugin.
- **Manually copied plugins still autostart.** Only store installs write enabled=false; a folder dropped into
  `./plugins` by hand keeps the upstream rule "no stored state = start at boot" (and a state left from an earlier
  plugin with the same ID applies to it).
- **Refused installs need a manual clean-up.** When the target folder exists and is not empty (for example a folder
  that failed to load) the store install fails with a message; the folder cannot be removed from the UI.
- **A crash while a start or stop of the same plugin is under way** is cleaned up when that start or stop is done
  (they share one lock). A stop can take up to the grace period (5 s) plus 3 s.
- **A stop sent a moment before the plugin crashes by itself** is still recorded as "stopped": Zoraxy cannot tell
  whether the process ended because of the request.
- **Folder names**: Windows reserved names (`CON`, `NUL`, ...) are not handled. Existing folders are not renamed.
- **Not covered by a test**: event unsubscription after a crash (the event system cannot list subscribers; the code path
  runs in `TestBugCrashCleansUp`), `introspect_hang` (would add 10 s per run; the
  mode exists), Windows (the suite skips), `-plugin_user` together with the new pipe handling (unit tests of `runas`
  pass, no root run was done).
- **Children of `start.sh`** still survive a stop (F27). By design of the new pipe handling Zoraxy should now notice
  the exit of the script at once even if a child keeps the output pipe open; this case has no test.
- **Failed-to-load folders** are shown with the raw error text of the JSON parser or the OS. The folder cannot be
  removed from the UI.
- **UI scenario**: `tools/ui-smoke/plugins_smoke.py` is part of `smoke.py` (and of `run.sh`) with the plugin API
  answered by mocks, so it needs no installed plugin; `--plugins-only` runs it alone. The part against real plugins
  needs the instance of `tools/ui-smoke/plugins_run.sh` (three chaos plugins) and only runs there. Chromium only,
  1366 px, light theme. It does not cover the plugin info side panel or the store dialog.
- **Translations**: the new UI strings are English only until the locale files are updated (list in the build report).

### How to run

```
cd src
GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test ./mod/plugins/ -run 'TestBug|TestFault' -count=1
GOTMPDIR=$HOME/.cache/go-tmp CGO_ENABLED=1 ~/capped.sh go test -race ./mod/plugins/ -count=1     # needs gcc
cd .. && PY=<python with playwright> tools/ui-smoke/plugins_run.sh     # UI scenario with real plugins; ZORAXY_BIN=<binary> skips the build
PY=<python with playwright> tools/ui-smoke/smoke.py --url <throw-away instance> --plugins-only   # the mocked part alone
```

The suite needs the `go` command at run time (it builds the chaos plugin once, under `GOTMPDIR` when set, and removes
build folders older than 30 minutes that a crashed run left), Linux or macOS, and about 18 s (22 s with `-race`). Results after the
review fixes (2026-11-23): `go test ./mod/plugins/...` green, `go test -race ./mod/plugins/...` green (the tests added or
changed by the review also 4 times in a row under `-race`), `go vet ./mod/plugins/... .` and `go build .` clean, and
`plugins_smoke.py` green once against a throw-away instance (and red, as it should be, with the escaping and the menu
branch deliberately broken). The whole `go test ./...` and the rest of `tools/ui-smoke` were **not** run (shared
machine rule).

To look at the states by hand: build `src/mod/plugins/testdata/chaosplugin`, copy the binary to
`plugins/<name>/<name>` with a `chaos.conf` (`mode=crash`, `delay=4s`, `name=...`) in a **throw-away** instance.
Never on a real proxy.

---

## Phase 1 results and known limits

Built 2026-11-23 on `dev`. Everything in this section is **off by default**, per plugin, unless the table "Behaviour
that changed for existing installs" says otherwise. A plugin with the default policy behaves as after phase 0: no
restart, no probe, fail-open, no limit, output in the main log.

### What was built

| Item | Where | What it does | Default |
|---|---|---|---|
| 1.1 Supervisor | `src/mod/plugins/supervisor.go`, `lifecycle.go` | Restart policy per plugin: `never`, `on-failure` (non-zero exit or signal), `always` (every exit nobody asked for). Backoff 1 s, 2 s, 4 s ... capped at 5 min, each delay multiplied by a random factor 0.8 to 1.2. A process that ran 1 minute resets the backoff. 5 unexpected exits (or failed automatic starts) within 10 minutes: state `crash_loop`, no more restarts until Start is pressed. New states `restarting` and `crash_loop`. Stop, Start, an update, a rebuild and setting the policy to `never` cancel a waiting restart. A plugin that fails to start at boot is retried with the same backoff. `Manager.Close` ends all of it | `never`: one log line says what a policy would have done ("it would be started again in about 1s") |
| 1.2 Readiness | `supervisor.go` (`watchProcess`) | Opt-in "wait for the plugin": after a start the plugin joins the request path (filters, capture paths) only when its port accepts a TCP connection (poll every 100 ms; after 10 s it is shown as "Not listening" and polled every second). Time to ready is recorded | off: attached at once, nothing is measured |
| 1.2 Health check | `supervisor.go`, SDK field `health_path` | Opt-in, `report` or `restart`: every 10 s a GET on the `health_path` of the manifest (any 2xx is healthy, 2 s timeout, carries the invoke token), or a TCP connect when the plugin declares none. 3 failures in a row: health `unhealthy`. In mode `restart` the process is ended (SIGTERM, SIGKILL after 2 s) and the restart policy starts it again; the mode is refused while the restart policy is `never` | off: Zoraxy never connects to a plugin only to look at it |
| 1.3 Timeout and breaker on capture and UI | `capture_guard.go`, `ui_router.go`, `plugins.go`, `dynamic_forwarder.go` | Opt-in "answer timeout" (100 ms to 10 min): the plugin gets that long to start answering a static capture, a dynamic capture or a request for its UI. Then: **504** with a text (capture) or a small page (UI). After 5 failures in a row the following requests get **503** with `Retry-After: 30` at once; after 30 s one request probes the plugin. A visitor who goes away, or a body that breaks after the headers, does not count against the plugin | off: no timeout, every request is tried (failures are counted) |
| 1.4 Fail-closed for crashes | `hooks_pipeline.go` (`guardDown`), `traffic_router.go` | Opt-in "also block requests while this plugin is not running". Needs `fail_closed` in the manifest **and** the existing consent; withdrawing the consent switches it off for good. "Not running" = crashed, exited, failed to start, waiting for a restart, crash loop, or started but not ready (readiness gate). Not: stopped by the administrator, never started. Covers pre_auth, post_auth (503), the response stage (502, upstream response dropped) and a plugin that only has a dynamic capture. Opt-out tags are respected | off: such requests pass as before, are counted (`PassedWhileDown`), logged once per minute and shown in the UI |
| 1.5 Bounded events | `eventlistener.go` | One queue of 1000 events and one worker per plugin, one shared HTTP client. Full queue: the oldest waiting event is dropped and counted. Problems are logged at most once per minute per plugin. The invoke token is sent with events. When the process ends, the delivery in flight is cancelled and the queue is emptied | **always on** (see "changed for existing installs") |
| 1.6 Output | `pluginlog.go` | Opt-in log file per plugin (`<log folder>/plugins/<plugin id>.log`, rotated at the size limit, one old file kept, so at most about twice the limit on disk; default limit 1 MiB). Opt-in rate limit in lines per second (burst of one second); dropped lines are counted and one line per 10 s says how many. Lines are always counted. The output ring in memory is now 200 lines (was 40) | main log, no rate limit |
| 1.7 Limits | `limits_linux.go`, `limits_other.go`, `procgroup_unix.go` | Opt-in memory, CPU and task limits: the plugin is started through `systemd-run --scope` (as root a system scope, otherwise a user scope) with `MemoryMax` + `MemorySwapMax=0`, `CPUQuota`, `TasksMax`. Opt-in open file limit with `prlimit(2)`. A plugin killed while a memory limit applies is reported as "most likely the kernel ending it at that limit". When a limit cannot be arranged the plugin **still starts** and the status says that the limit is not enforced. Every plugin now runs in its own process group (see below) | no limit; no `systemd-run` in the command line |
| F18 Secrets | `lifecycle.go`, SDK (`zoraxy_plugin.go`: `ConfigureVia`, `ConfigureStdinFlag`) | A plugin whose manifest says `configure_via: "stdin"` is started with `-configure-stdin` and reads the configure JSON (API key, invoke token) from its standard input. `RecvConfigureSpec` of the SDK handles both ways. Every other plugin gets `-configure=<json>` as before | per plugin, declared by the plugin |
| 0.3 leftovers | `status.go`, `supervisor.go` | Exit history (last 20: kind, exit code, how long it ran, what the supervisor did), counters per plugin (calls, failures, timeouts, breaker opens, capture requests / failures / rejected, events sent / failed / dropped / waiting, output lines / dropped, passed and refused while down, health checks). In `/api/plugins/list` (`Status.Policy`, `Status.Counters`, additive); the history and the log file path only in `POST /api/plugins/status` | always (read-only) |
| API | `policy.go`, `api.go` | `GET /api/plugins/policy?plugin_id=`, `POST /api/plugins/policy` (any of `restart`, `health_check`, `readiness_gate`, `block_when_down`, `capture_timeout_ms`, `log_target`, `log_max_kb`, `log_rate_limit`, `memory_max_mb`, `cpu_quota_percent`, `tasks_max`, `max_open_files`), `POST /api/plugins/restart`. Stored in the database table `plugin_policy`, keyed by plugin ID. No existing route changed | |
| 1.8 UI | `src/web/components/plugins.html` | New **Health** column (check passing / failing / not checked, restart policy, automatic restarts, and the counters that mean trouble). Status badges "Restarting" (with the time of the next start), "Crash loop", "Unhealthy". Red notice when a plugin is in a crash loop, yellow notice when requests passed unfiltered while a fail-closed plugin was down. **Details** now also shows counters, the exit history and a **Supervision** form for every option above. **Restart** button; **Stop** also cancels a waiting restart. The checkbox "Also block requests while this plugin is not running" sits under the fail-closed consent | |

### Behaviour that changed for existing installs

These are the changes a plugin with the **default policy** sees. Each is a bug fix in the sense of the fork rules
(unbounded resource use, wrong status code, leaked process); they are listed so nobody has to find them by surprise.
The second review round looked at each one again: all five are **kept**, none got a switch, and the line "Kept
because" under each says why (owner decisions 2 to 6 in "Second review round" below).

1. **Events are queued.** Before: one goroutine and one 10 s wait per event and subscriber, in parallel, no limit. Now:
   in order, one at a time per plugin, at most 1000 waiting. A plugin that needs 10 s per event now receives events
   later than before and loses the oldest ones once 1000 wait. Delivery failures are no longer logged one line per
   event by the event system but at most once per minute per plugin, and the log line no longer contains the body of
   the plugin's answer. `Notify` returns as soon as the event is queued.
   *Kept because* the old way had no upper bound: one slow subscriber and one event per blocked request grew
   goroutines and connections inside the proxy until it ran out of memory, and a switch would keep that failure one
   setting away. Events are only lost where the old code piled them up without limit, and every loss is counted.
2. **Event calls carry `X-Zoraxy-Plugin-Token`** (additive header).
   *Kept because* it only adds a header that existing plugins ignore, and it is the only way a plugin can tell an
   event from Zoraxy from one faked by another local process.
3. **The plugin UI path answers with a status code and a small HTML page** when it cannot be served: 503 (not running,
   or breaker open), 502 (not reachable), 504 (answer timeout), 404 (unknown plugin, plugin without a page). Before:
   a JSON `{"error": ...}` with status 200. A plugin page that breaks after its headers were sent now aborts the
   connection, as captures do since phase 0.
   *Kept because* "200 OK" for a page that could not be served is wrong for every reader (browser, monitoring,
   cache), nothing in the admin UI read that JSON (the path is only shown in a frame), and the raw JSON was what the
   administrator saw in that frame.
4. **Every plugin runs in its own process group**, and the group is signalled on stop and killed when the plugin
   process is gone. Children of a `start.sh` no longer survive a stop (F27). A plugin that deliberately leaves a
   helper process behind in the same process group loses it. Ctrl-C in a terminal no longer reaches plugins directly;
   Zoraxy stops them as part of its own shutdown.
   *Kept because* a process that keeps running, and keeps its port, after the administrator pressed Stop is the bug
   (F27), and since phase 0 the end of the plugin process detaches its routes anyway, so a helper that outlived it
   could not serve anything. A helper that must outlive the plugin can still leave the group with `setsid`.
5. **Withdrawing the fail-closed consent** also clears "block while not running".
   *Kept because* "block while not running" is itself new and off by default, it cannot be turned on without that
   consent, and the stricter option must not outlive the consent it depends on. No install from before phase 1 has it.
6. Nothing else. In particular a crashed plugin is **not** restarted, a crashed fail-closed plugin still lets requests
   pass (now counted), captures have no timeout, output goes to the main log, and no health check or readiness
   check runs. The one connection Zoraxy makes to a plugin only to look at it is the port probe of phase 0: a TCP
   connect per running plugin while the Plugin Manager page is on screen (owner decision 1 below), and for every
   listing with the start flag `-plugin_port_probe`.

### Tests

`src/mod/plugins/fault_phase1_test.go` (36 tests) with the chaos plugin, which got the modes `crash_once`,
`slow_start`, `unhealthy`, `balloon` and the features `health`, `stdinconf`, `children`.

| Behaviour asked for | Test |
|---|---|
| Crash, then restart with backoff; crash loop stops | `TestFaultCrashRestartsWithBackoffThenCrashLoopStops` (planned delays 100 / 200 / 400 / 800 ms +/- 20 %, 4 restarts, then `crash_loop`, nothing started for a further 1.2 s, Start resets), `TestFaultBackoffDelaysAndCap` (default 1 s to 5 min, jitter range), `TestFaultCrashOnceIsRestartedAndWorksAgain` (filter, capture and a fresh API key work after the automatic restart) |
| Default is unchanged | `TestFaultRestartPolicyNeverIsTheDefaultAndOnlyLogs`, `TestFaultHungCaptureDefaultStillWaits`, `TestFaultLogDefaultIsTheMainLogWithoutLimit`, `TestFaultFailClosedHoldsForHangButNotForCrash` (now also checks the counter), `TestFaultReadinessGateAttachesOnlyWhenListening` (first half), `TestFaultOpenFileLimitIsApplied` (second half) |
| Policy switch never / on-failure / always | `TestFaultCleanExitOnFailureStaysDownAlwaysRestarts`, `TestFaultStopAndPolicyChangeCancelAPendingRestart`, `TestFaultCloseEndsSupervision` |
| Readiness and health | `TestFaultReadinessGateAttachesOnlyWhenListening`, `TestFaultHealthCheckReportsAHungPlugin`, `TestFaultHealthCheckSeesHTTP500`, `TestFaultHealthCheckRestartsAHungPlugin`, `TestFaultNeverListeningIsEndedByHealthRestart`, `TestFaultHealthCheckTCPOnlyCannotSeeAHungHandler` (documents the limit) |
| Hang triggers the breaker; empty 200 gone | `TestFaultHungCaptureTimesOutAndOpensTheBreaker` (504 x 3, then 503 at once, probe after the cooldown, UI shares it), `TestFaultCaptureTimeoutAppliesToARunningPluginAndUI`, `TestFaultSlowCaptureInsideTheTimeoutIsServed`, `TestFaultPluginUIErrorsArePagesWithAStatus`; from phase 0: `TestBugCaptureTargetDownIs502NotEmpty200`, `TestFaultCaptureRaceWithExitGives502` |
| Fail-open and fail-closed, hang and crash | `TestFaultFailClosedBlockWhenDownHoldsForCrashes` (consent needed, 503 while restarting, served again after the restart, opt-out tag, other rules, admin stop, Stop on a plugin that had crashed, consent withdrawn), `TestFaultBlockWhenDownAlsoCoversNotReadyAndResponseStage`; hang: `TestTimeoutFailOpenAndFailClosedConsent`, `TestBreakerOpenFailClosedStillBlocks` (existing) |
| Queue bounded | `TestFaultEventQueueIsBoundedForAHungSubscriber` (50 000 events from 8 goroutines at a hung subscriber: at most 1000 waiting, every other one counted as dropped, fewer than 10 extra goroutines, stop ends the worker), `TestFaultEventsAreDeliveredInOrderWithTheInvokeToken`, `TestEventQueueKeepsTheNewestInOrder` |
| Log limited | `TestFaultLogFloodIntoASizeLimitedFile` (64 KiB limit: file and one rotated file, each at most 64 KiB, nothing in the main log), `TestFaultLogRateLimitDropsAndCounts`, `TestLogRateLimiterAndLogFileRotation` |
| Limits | `TestFaultMemoryLimitEndsABalloon` (96 MB: killed, reported, can be started again; skipped when systemd scopes do not work), `TestFaultOpenFileLimitIsApplied` (`/proc/<pid>/limits`) |
| Secrets | `TestFaultSecretsOnStdinAreNotOnTheCommandLine` (`/proc/<pid>/cmdline` holds neither key nor token; a plugin without the declaration still gets `-configure=`), `TestSanitizeSupervisionSpec` |
| Process group | `TestFaultStopAlsoEndsTheChildrenOfAPlugin` (after a stop and after a crash) |
| Policy API, counters, history | `TestFaultPolicyAPIValidationAndPersistence`, `TestFaultCountersAndExitHistoryInTheStatusAPI`, `TestFaultRestartAPI`, `TestFaultBootWithTheRealDatabase` |

Five of these were checked the other way round: with the behaviour deliberately broken (capture breaker always
admits; Stop does not cancel a restart; the process group is not killed; block-when-down ignored; the event queue
does not drop the oldest) the matching test fails. The others were not checked that way.

Found by running a real instance, not by the suite: the first build crashed at boot when a plugin folder existed,
because the bolt database panics on a read from a table that was never created (the suite uses an in-memory
database). `NewPluginManager` now creates the table; `TestFaultBootWithTheRealDatabase` fails without that line.

Results (2026-11-23, shared 4-core machine, through `~/capped.sh`): `go test ./mod/plugins/...` green (about 41 s),
`go test -race ./mod/plugins/` green, and the fault suite (`-run 'TestFault|TestBug|...'`) three times in a row under `-race` green. One assertion of the first race run was flaky (a counter read while lines were still on their way) and was rewritten. `go vet ./mod/plugins/... .` clean, `go build .` clean,
`mod/plugins` cross-compiles for windows/amd64, darwin/arm64, linux/arm64, linux/riscv64 and linux/mipsle (compile only). **Not run:** the whole `go test ./...`, `tools/ui-smoke` (including the
phase 0 scenario `plugins_run.sh`, whose selectors were read again and still match), any test as root, anything on
Windows or macOS.

Real instance (throw-away, port 19510, a real proxy rule on 19511, seven chaos plugins): a fail-closed plugin with
consent was killed; requests answered 200 and were counted, with "block while not running" on they answered 503
"Service temporarily unavailable", with it off again 200. A `balloon` plugin with a 96 MB limit was killed in a
systemd user scope and reported as such. A plugin with policy `on-failure` went through four restarts into the crash
loop. The Plugin Manager was looked at in headless Chromium in each of these states, light and dark at 1366 px and
light at 390 px; saving the Supervision form, the Restart button and the block-while-not-running checkbox were clicked
through. That found two UI bugs, both fixed: the answer timeout field refused decimals, and the exit history collapsed
on phones.

### Not done in phase 1

- **Per-request total plugin budget** (item 1.3) and a **slow-call breaker**: not built. F7 is unchanged: slow answers
  inside the timeout add up and are visible nowhere.
- **Lowering the timeout of filter calls** per plugin: not built. The answer timeout only covers capture and UI.
- **Prometheus series** per plugin: not built (`mod/metrics` was outside this change). The counters exist in the API.
- **Time-to-listen measured for every plugin (log-only)**: not built, because measuring needs a connection to the
  plugin, which stays off by default. It is measured with the readiness gate or a health check.
- **Per-plugin log file "always"** (plan item 1.6): built as opt-in, because moving output out of the main log would
  be a default change.
- **Health check interval, timeout and failure count, backoff and crash-loop numbers** are fixed constants, not
  settings.
- **Status in the plugin info side panel**, the start-up placeholder of `index.html`, DEVELOPMENT.md notes, the
  author documentation in `docs/plugins/docs/` (nothing there mentions `health_path` or `configure_via` yet).
- **The SDK copies inside `example/plugins/*`** were not refreshed and no example plugin declares `health_path` or
  `configure_via`. Today only the chaos plugin uses them, so **your three plugins keep their secrets on the command
  line** until their authors rebuild them with the new SDK (the Supervision form says so per plugin).
- **The "Experimental feature" label** is still shown. Removing it is the owner's call.
- **Translations**: all new texts are English.

### Known limits

- **Supervisor state is in memory.** Backoff, crash-loop count, exit history and counters are lost when Zoraxy
  restarts; the policy itself is stored. After a Zoraxy restart a plugin in a crash loop is started again once.
- **Automatic restart is not instant.** At least 0.8 s, and while the plugin is down its filters are skipped
  (fail-open) unless block-while-not-running is on. A plugin with `always` that exits cleanly every few minutes is
  restarted for ever: the crash loop only triggers at 5 exits in 10 minutes.
- **A restart policy does not make a broken plugin work.** After the crash loop it stays down until someone presses
  Start. There is no alert outside the UI and the log.
- **Health check without `health_path` is a TCP connect.** It cannot see a plugin that accepts connections but no
  longer answers (`TestFaultHealthCheckTCPOnlyCannotSeeAHungHandler`), and the readiness gate has the same blind spot
  (`never_ready`). None of your three plugins declares a health path.
- **The health check talks to the plugin over loopback HTTP.** A plugin that is slow under load can fail three
  2 s probes and be restarted in `restart` mode; start with `report`.
- **Readiness gate, health check, log target, rate limit and limits apply at the next start** of the plugin. Restart
  policy, block-while-not-running and the answer timeout apply at once.
- **Answer timeout is a response-header timeout.** A plugin that sends headers and then stalls the body is not cut
  off. WebSocket upgrades are not timed. With the option on, 5 failed requests in a row cut off **all** captured
  requests and the UI of that plugin for 30 s, also the ones that would have worked. Filter and sniff calls keep
  their own breaker; the two do not share state. A request counts as answered when the status line arrives (also
  101), not when it ends. A visitor who goes away before the answer counts neither as success nor as failure: when
  **every** visitor gives up sooner than the answer timeout, the breaker never opens, so set the timeout below what
  clients and load balancers in front wait.
- **Block-while-not-running** does not apply while the administrator, a store update, a rebuild or a hot reload has
  the plugin stopped (those are "stopped", not "down"), and not to static capture paths (they fall through to the
  upstream when the plugin is gone, as before). It does apply when a start fails, also a start pressed by the
  administrator or done by an update after a stop, and after a Zoraxy restart when the plugin is enabled but
  fails to start. A start by the administrator, an update or a rebuild that fails is **not retried** by the restart
  policy: the caller got the error. With it on, a plugin in a crash loop means 503 on every rule it is attached to until someone acts:
  that is what was asked for, and why it is off by default.
- **Events**: delivery is in order and one at a time, so one hung subscriber call (10 s) delays the next events for
  that plugin; dropped events are lost. Events are not retried.
- **Log file**: rotation keeps one old file; the file is written by Zoraxy (as its user) and its name is the plugin ID
  with unusual characters replaced. Lines dropped by the rate limit are not in the "last output" either. The limiter
  works on lines, and a line can be up to 64 KiB.
- **Limits are Linux only and need systemd.** Memory, CPU and tasks need a working `systemd-run --scope` (probed with
  `true`; the first use waits for the probe, up to 5 s, after that the last answer is served at once and refreshed in
  the background when it is older than 5 minutes, so a bus that comes up later is noticed one start late); without it
  the plugin starts **without** those limits and the status says so.
  The scope gets the description "Zoraxy plugin <id>". For a plugin that still gets `-configure=` on its command line,
  the secrets are also in the command line of `systemd-run` (the same process, the same exposure as without limits),
  but no longer in the journal or the unit description. Journal lines written by a build before this fix stay in the
  journal; every start of a plugin issues a new API key and invoke token, so the logged ones are void after a restart.
  Only the **user scope** was tested (Zoraxy not root). As root (the reference unit) a system scope is used; with
  `-plugin_user` the user switch is handed to `systemd-run --uid/--gid`: **neither was run**. The reference unit's
  sandboxing may forbid `systemd-run`; not checked. `RLIMIT_AS` is not used (it breaks Go programs). The "killed at the
  memory limit" text is an inference (SIGKILL while a memory limit applies), not read from the cgroup. The open file
  limit is set a moment after the process started.
- **A plugin with limits is outside the cgroup of Zoraxy.** Its systemd scope is a cgroup of its own, so
  `KillMode=control-group` of the Zoraxy unit does not end it. When Zoraxy crashes, is killed (SIGKILL, OOM killer)
  or gives up on the "plugin manager" shutdown step (3 s for all plugins together; one slow plugin is enough), such a
  plugin is left running. Two things then end it (see "Third review round"):
  - *Zoraxy runs in a systemd service of the same manager* (root in a system service such as the reference unit, or
    a user service of the same user): the scope is bound to that service and systemd kills it **40 s after the
    service is gone**, not at once. Until then the orphan keeps its memory and its port. The 40 s are there because
    systemd also "stops" the scope at the same moment as a normal `systemctl stop zoraxy`, and the plugin must
    survive that until Zoraxy has drained its requests and stops the plugin itself; a stop of Zoraxy that takes
    longer than 40 s (the documented worst case is 28 s) gets its limited plugins killed under it. For the same
    reason `systemctl stop zoraxy-plugin-<...>.scope` by hand takes 40 s. `RestartMode=direct` in the unit of Zoraxy
    (not in the reference unit) may hide the crash from the binding (not tested). **Only the user manager was tested**, with a
    stand-in service; as root in the reference unit the same options are used but **were not run**. The Supervision
    form says "which systemd ends when <unit> is gone" when the binding is in use; when it says nothing, it is not.
  - *Every start of a plugin with limits* first kills (SIGKILL) what is left in older scopes of the same plugin of
    the same install. That covers the restart inside the 40 s and Zoraxy outside a service (terminal, container,
    a system service that does not run as root). "Same install" is the absolute path of the plugin directory: after
    moving the install, or when the plugin is no longer started (disabled, uninstalled, its limits removed) nothing
    kills the orphan before the 40 s, and outside a service nothing at all: look for it with
    `systemctl [--user] list-units 'zoraxy-plugin-*'`. Side effect: a child of a limited plugin that left the process
    group with `setsid` survives the stop as before, but not the next start of that plugin.
  A plugin **without** such a limit is in the cgroup of Zoraxy as before: it ends with the service under the
  reference unit, and outlives a killed Zoraxy that was started any other way (unchanged, upstream behaviour).
- **Close waits for a start that is under way.** A stop of Zoraxy during an automatic restart of a plugin waits for
  that start (up to 5 s with limits on the first use of systemd) before it can stop the plugin; the shutdown step
  has 3 s, so in that corner the step is abandoned and the cases above apply.
- **Health "Not responding" and the answer timeout.** With the answer timeout on, the Health column says "Not
  responding" for as long as the capture / UI breaker is open, also during the one request that probes the plugin.
  Without the answer timeout that breaker never refuses anything and does not change the Health column.
- **Process group**: a child that calls `setsid` leaves the group and survives. Windows has no equivalent here. On
  Linux the group is killed while the ended plugin is still a zombie, so its PID cannot have been reused; on other
  Unix systems it is killed directly after the reap, which leaves a very short window for PID reuse.
- **Secrets on stdin** only for plugins that declare it. `last-configure.json` in the tests is a chaos plugin feature,
  not something Zoraxy writes.
- **Read-only accounts** can read the policy (`GET /api/plugins/policy`) and, as before, the status with its counters.
  Not tested with a viewer account.
- **Audit log**: an open Details row loads its content again (a POST, which is audited) whenever the counters of the
  plugin change, at most every 10 s.
- **`tools/ui-smoke/plugins_smoke.py` covers of phase 1** the Details row (counters, exit history, limits note)
  and the Supervision form (shows the stored policy, disables limits the host cannot enforce, Save posts the changed
  values; with real plugins the saved policy is read back). The Health column wording, "Restarting", "Crash loop",
  the two notices, the Restart button and the block-while-not-running checkbox have no committed browser check.

- **Uninstall forgets the settings of the plugin**: its policy, global attach and fail-closed consent are deleted
  from the database. Tags and groups that name the plugin ID are not touched. A store **update** keeps everything.

### Phase 1 review fixes

Findings of the independent review of phase 1 and what was done. All are bug fixes, no default changed. The tests are
in `fault_review_test.go` and `fault_review_linux_test.go` (not all match the `TestBug|TestFault` filter below: run the
package without `-run` for all of them).

| Finding | Fix | Test |
|---|---|---|
| A systemd scope without `--description` put the whole command line, with `-configure=<secrets>` of legacy plugins, into the journal and the unit description (major) | `--description=Zoraxy plugin <sanitised id>` and `--unit=zoraxy-plugin-<sanitised id>-<8 hex digits>.scope` on every scope (the description also on the probe) | `TestLimitsScopeNeverCarriesTheCommandLineAsDescription` (no option before `--` holds `-configure=`), `TestFaultLimitsScopeDescriptionOnThisHost` (starts a real user scope and reads its name, its Description and every other property systemd shows for it) |
| A visitor abort counted as a success: it reset the failure streak and closed an open capture breaker | `captureBreaker.release()`: only the probe slot is given back | `TestCaptureBreakerClientAbortIsNotASuccess`, `TestFaultAbortedRequestsToAHungCaptureDoNotResetTheBreaker` |
| The half-open probe slot was held until the request ended (a WebSocket could hold it for hours) | The breaker gets its verdict when the plugin starts to answer (final status, 101, hijack); the end of that request no longer touches it | `TestCaptureBreakerProbeIsSettledWhenThePluginAnswers`, `TestCaptureBreakerHijackSettlesTheProbe` (unit level: no real WebSocket through the proxy core) |
| A start that failed after a stop stayed "stopped on purpose", so block-while-not-running did not apply | `StartPlugin` clears the flag before the attempt | `TestFaultFailedStartAfterAStopIsDownNotStopped` |
| The process group was killed up to 300 ms after the reap: PID reuse could hit a stranger | Linux: `waitid(WNOWAIT)`, kill the group, then reap; no signal is sent to a reaped plugin any more | `TestProcessGroupIsEndedBeforeThePIDIsFree` |
| The systemd probe ran under a lock, on the admin API path | One probe at a time, outside the lock; a known answer is served at once and refreshed in the background | `TestLimitsProbeRunsOnceAndNeverBlocksOnceKnown` |
| Uninstall left the policy row behind | Policy and hook rows are deleted | `TestFaultUninstallForgetsPolicyAndConsent` |
| "The output ring can pin 12.8 MB per plugin" | **Not a defect**: `noteOutput` cuts every ring line at `outputRingLineMax` = 512 bytes (`status.go`), so one ring (there is one per plugin, for both streams) holds about 110 KB at most; only the log target gets up to 64 KiB per line | `TestFaultLogFloodStaysBounded` already checks the ring line length |

### Second review round

Both phases were reviewed once more against the two review reports. Every finding of those reports was checked in
the code as it is now. Already fixed and still fixed (each with the test named in the tables above): the journal
leak, both capture breaker findings, block-while-not-running after a failed start, the process group kill, the
systemd probe under a lock, the crash clean-up without the start / stop lock, a crash just before a requested stop,
Stop on a dead plugin, the build error dialog, the test hygiene points and the policy row left by an uninstall.
What this round added:

| Item | Change | Test |
|---|---|---|
| systemd scope | A unit name of its own next to the description (see the table above). Checked on this host: the user journal shows `Started zoraxy-plugin-test.chaos.balloon-<id>.scope - Zoraxy plugin test.chaos.balloon.` and no `-configure=` | `TestLimitsScopeNeverCarriesTheCommandLineAsDescription`, `TestFaultLimitsScopeDescriptionOnThisHost` |
| "Last problem" | The claim "never holds plugin text" was still not true for network errors (`malformed HTTP response "<bytes of the plugin>"`, and the path a visitor asked for). Fixed wording for every failed exchange with a plugin; the error text goes to the log only, quoted, cut, once a minute | `TestLastProblemNeverQuotesANetworkError` |
| Port probe | Was: off unless `-plugin_port_probe`. Now: also for the status view of the Plugin Manager while that page is on screen, and for nothing else (owner decision 1) | `TestFaultPortProbeOnlyForTheStatusView`, `plugins_smoke.py` |
| UI test | `plugins_smoke.py` is part of `smoke.py` (mocked plugin API: one good plugin with a hostile manifest, one crashed plugin, one broken folder): status badges, Details row, escaping of author / description / ID / output / last problem / limits note, the Supervision form, the probe rule. `plugins_run.sh` runs the same file plus the part against three real chaos plugins | the scenario itself |
| Tests on Windows | `go vet` with `GOOS=windows` failed on `syscall.Kill` in two test files; they use a small helper now (`killpid_*_test.go`). The suite still does not run on Windows | `GOOS=windows go vet ./mod/plugins/` |

### Third review round

| Finding | Fix | Test |
|---|---|---|
| A plugin with a memory, CPU or task limit runs in its own systemd scope, outside the cgroup of Zoraxy: it outlived a crashed or killed Zoraxy and a shutdown step that was abandoned, kept its port and memory, and the next start added a second copy. Section 1.1 said plugins die with the service (minor) | (1) When Zoraxy runs in a service of the manager the scopes are created in (read from `/proc/self/cgroup`), the scope gets `BindsTo=<unit>`, `KillSignal=SIGCONT`, `TimeoutStopSec=40`: systemd kills it 40 s after the service is gone. No `After=` (a stop of Zoraxy would wait for the plugin) and no SIGTERM on stop (the plugin would leave the request path while Zoraxy drains). The binding is part of the systemd probe and only used when the probe with it worked, so it cannot keep a plugin from starting. (2) The scope name is now `zoraxy-plugin-<id>-<8 hex digits of the install>-<8 random hex digits>.scope`, and every start of a limited plugin first runs `systemctl kill --signal=SIGKILL` on the older scopes of that plugin of that install. Both only touch plugins with limits (opt-in); nothing changes for the others | `TestFaultLimitedPluginEndsWithTheServiceOfZoraxy` (real user scope bound to a stand-in service; the service is SIGKILLed, and in a second run stopped: the plugin is still there after 1 s and gone after the grace time), `TestFaultLeftoverScopeIsKilledAtTheNextStart` (real scopes: the orphan is killed, the new process, another plugin with a longer ID and the same plugin of another install are not), `TestSystemdUnitOfCgroup`, `TestScopePatternMatchesOnlyThePluginOfThisInstance`, `TestLimitsStartKillsLeftoverScopesAndBindsOnlyWhenTheProbeAllowsIt` |
| `Close` chose the plugins to stop with `IsRunning()` without the start / stop lock: an automatic restart in the middle of its start was skipped and its process never stopped (minor, needs a restart policy) | `Close` takes the lock of each plugin before it looks; an automatic restart holds it for the whole start and checks "closing" again under it | `TestFaultCloseWaitsForAnAutomaticRestartThatIsUnderWay` (fails without the fix) |
| Health said OK while the capture / UI breaker answered every request 503 (minor) | An open capture breaker (with the answer timeout on) is "Not responding", like the filter breaker | assertion in `TestFaultHungCaptureTimesOutAndOpensTheBreaker` |
| The help of `-plugin_port_probe`, item 6 of "Behaviour that changed" and `docs/ux/changes.md` still said nothing connects to a plugin without the flag (minor) | Reworded: the Plugin Manager page probes while it is shown, the flag extends that to every listing | text only |

**Owner decisions** (each can be reversed without touching anything else):

1. **Port probe: on for the Plugin Manager page while it is shown, off everywhere else.** Why this and not the
   start flag alone: with the flag alone the page said "Running" for a plugin whose port is closed, which is the one
   place where a person looks to find out. Why not always on: the list API is also read by the side menu on every
   admin page and by plugins with the list permission, and a status that depends on who asked last would be a
   surprise. Cost: one loopback TCP connect per running plugin every 10 s while the page is open, none otherwise. To
   go back to "never unless the flag is set", remove `?probe=true` in `loadPluginListWithStatus` and `probe: "true"`
   in `loadPluginStatusDetail` (`plugins.html`).
2. **Event queue per plugin (in order, at most 1000 waiting, oldest dropped): kept**, no switch.
3. **`X-Zoraxy-Plugin-Token` on event calls: kept.**
4. **Plugin page errors as 503 / 502 / 504 / 404 with a small HTML page instead of JSON with 200: kept.**
5. **Own process group per plugin, signalled on stop and ended with the plugin: kept.** This is the one of the five
   that can break an existing plugin: a `start.sh` that starts the real program in the background and exits loses
   that program now. Before phase 0 such a plugin kept working by accident; since phase 0 its routes are removed
   when the script exits, so it was already broken, only less visibly.
6. **Withdrawing the fail-closed consent clears "block while not running": kept.**

### How to run

```
cd src
GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test ./mod/plugins/ -run 'TestBug|TestFault' -count=1
GOTMPDIR=$HOME/.cache/go-tmp CGO_ENABLED=1 ~/capped.sh go test -race ./mod/plugins/ -count=1     # needs gcc
```

---

## Phase 2 results and known limits (items 2.1, 2.2, 2.3, 2.6)

Built 2026-11-23 on `dev`. This section covers four of the seven items of phase 2. The signed index (2.4), safe
install and rollback (2.5), the isolated plugin UI (2.7) and phase 3 are **not** part of it. Everything here is off
or log-only by default; a plugin that declares nothing and an administrator who changes nothing see the behaviour of
phase 1, with the additions listed under "Behaviour that changed for existing installs".

### What was built

| Item | Where | What it does | Default |
|---|---|---|---|
| 2.1 Contract version | `src/mod/plugins/contract.go`, `introspect.go`, `lifecycle.go`, SDK `zoraxy_plugin.go` | Manifest field `api_version` (missing = 0 = legacy). Zoraxy supports 0 to 1. A plugin that declares 1 or more gets `api_version_min` / `api_version_max` in its configure payload. A plugin built for a newer contract is reported: log line at load and at start, `Status.Contract` in the API, a line in the Health column and a row in Details | **warn**: the plugin is started anyway |
| 2.1 Opt-in refuse | `contract.go` (`ManagerSettings.ContractMode`), `GET/POST /api/plugins/settings`, "Plugin safety settings" in the Plugin Manager | `contract_mode=refuse`: a plugin of an unsupported contract version is not started (state `failed_to_start` with the reason). Legacy plugins and plugins inside the range are never affected. A restart policy does not retry such a plugin, at boot or after a crash | off |
| 2.1 Written contract | `docs/plugins/contract.md` | Versions, introspect, configure, calls in both directions, stop sequence, permissions, seven stability rules, and the tests that hold each claim | |
| 2.1 Golden manifests | `src/mod/plugins/testdata/manifests/examples` (11), `.../installed` (3) | The `-introspect` output of every example plugin as built with SDK 1.0.0, and of the three plugins installed on this machine (see known limits for how they were taken) | |
| 2.2 SDK version | `src/mod/plugins/zoraxy_plugin/zoraxy_plugin.go`, `CHANGELOG.md`, `README.txt` | `SDKVersion = "1.1.0"` (semantic versioning), `APIVersion = 1`, changelog, tag scheme `sdk/v<version>`. New in 1.1.0: `IntroSpect.APIVersion` (filled in by `ServeIntroSpect`), `ConfigureSpec.APIVersionMin/Max` with `ContractKnown`, `ContractSupported`, `SupportsAPIVersion`, a one-line warning on standard error when Zoraxy does not support the SDK's contract, `HealthHandler` | |
| 2.2 Module path decision | `docs/plugins/contract.md` section 9 | **The SDK stays a package inside the Zoraxy module and is distributed by copying the folder; it is not a Go module of its own.** Reasons and what replaces the module (version constant, changelog, tags, frozen copy, compatibility test) are written there | |
| 2.2 Compatibility test | `testdata/sdk-1.0.0/` (frozen SDK), `testdata/sdkplugin/` (fixture plugin written against the public SDK API), `phase2_helper_test.go`, `phase2_contract_test.go` | The fixture is built twice, offline: against the frozen SDK 1.0.0 and against the current SDK. Each binary goes through load, start, configure, API key, filter (modify and deny), static capture, UI, 20 events with the invoke token, crash, automatic restart, stop | |
| 2.3 Secrets off the command line | phase 1 code in `lifecycle.go` (confirmed, unchanged), SDK `RecvConfigureSpec`, examples | The lifecycle side was built in phase 1 and is confirmed by a new test with a plugin built from the real SDK. New: the reference examples `api-call-example` and `filter-example` declare `ConfigureVia: plugin.ConfigureViaStdin` (and `HealthPath` with `plugin.HealthHandler`); the test now also reads `/proc/<pid>/environ` | per plugin, declared by the plugin |
| 2.6 Permission approval | `src/mod/plugins/permissions.go`, `lifecycle.go`, `mod/auth/plugin_apikey_manager.go` (`SetPermittedEndpointsForPlugin`), `GET/POST /api/plugins/permissions` | Per plugin ID Zoraxy stores which `permitted_api_endpoints` (method + path) are approved (table `plugin_permissions`). At every load (boot, install, update, reload) the manifest is compared with it. Endpoints that are not approved: one log line, one security audit entry `plugins.permissions.new` (actor "plugin manager", with the endpoints and whether they were granted), `Status.Permissions` in the API, a line in the Health column, a notice above the list, and a "Zoraxy API permissions" block in Details with Approve / Withdraw per endpoint and "Approve the N ..." | **log-only**: every endpoint of the manifest is granted, as before |
| 2.6 Opt-in "require approval" | `ManagerSettings.RequirePermissionApproval`, "Plugin safety settings" | Only approved endpoints are granted. The plugin still gets an API key; a call to an endpoint that is not approved is answered as not permitted. Approving or withdrawing changes what the key of the **running** process opens, at once | off |
| Example plugins | `example/plugins/*/mod/zoraxy_plugin` | All eleven examples carry SDK 1.1.0 and build offline with it | |
| Author docs | `docs/plugins/docs/2. Architecture/8. Contract Version, Health and Secrets.md`, note in `3. Configure.md`, `zoraxy_plugin API.md` regenerated, `index.json` | `api_version`, `health_path`, `configure_via`, and what approval means for authors | |
| UI | `src/web/components/plugins.html` | As above, plus the disclosure "Plugin safety settings" with the two switches | |

### Behaviour that changed for existing installs

1. **Two new database tables** (`plugin_settings`, `plugin_permissions`). At the first start of this version every
   installed plugin that asks for API endpoints gets a row that records those endpoints as approved ("baseline"),
   with one log line per plugin. Nothing is asked of the administrator and no badge appears for these plugins.
2. **A plugin that is installed or copied in after that first start** shows "N API permissions you have not
   approved" in the Plugin Manager and gets one audit entry. It still receives every endpoint it asks for.
3. **`/api/plugins/list`, `/api/plugins/info` and `/api/plugins/status`** carry two more objects in `Status`:
   `Contract` and `Permissions` (additive).
4. **A plugin that is rebuilt with SDK 1.1.0** declares `"api_version": 1` without a code change, and Zoraxy then
   adds `api_version_min` / `api_version_max` to its configure payload. A plugin that is not rebuilt gets byte for
   byte what it got before (`TestFaultContractRangeOnlyForPluginsThatDeclareAVersion`,
   `TestSDKCompatBinaryBuiltWithOldSDKStillPasses`).
5. **The example plugins `api-call-example` and `filter-example`** now receive their configuration on standard
   input and serve `/health`. Both still work with a Zoraxy that passes `-configure=`.
6. **Uninstall** also forgets the approved permissions of the plugin ID.
7. Nothing else. No request is decided differently, no plugin is refused, no permission is withheld unless one of
   the two switches is turned on.

### Tests

`src/mod/plugins/phase2_contract_test.go`, `phase2_permissions_test.go`, `phase2_helper_test.go`,
`src/mod/auth/plugin_apikey_endpoints_test.go`. The chaos plugin got the settings `api_version` and `api_endpoints`.

| Behaviour asked for | Test |
|---|---|
| Golden manifests parse unchanged (every field back with the same value, nothing added, all legacy, never warned about or refused) | `TestContractGoldenManifestsParseUnchanged` |
| Version states, invalid values | `TestContractStatesAndSanitize`, `TestSDKContractHelpers` |
| Mismatch: warn by default, refuse on opt-in, setting stored, legacy and current plugins unaffected | `TestFaultContractMismatchWarnsByDefaultAndRefusesOnOptIn`, `TestFaultRefusedPluginIsNotRetriedAtBoot` |
| Range only for plugins that declare a version | `TestFaultContractRangeOnlyForPluginsThatDeclareAVersion` |
| A binary built with the old SDK passes against this Zoraxy; so does one built with the current SDK | `TestSDKCompatBinaryBuiltWithOldSDKStillPasses`, `TestSDKCompatBinaryBuiltWithCurrentSDKPasses`, `TestSDKFrozenCopyIsNotTheCurrentSDK` (the frozen copy was not overwritten; the changelog has an entry for `SDKVersion`) |
| ps-style check with the real SDK: no key, no token in the command line or the environment | `TestFaultSDKPluginSecretsAreNotInTheProcessList`; from phase 1: `TestFaultSecretsOnStdinAreNotOnTheCommandLine` |
| `HealthHandler` of the SDK with the health check | `TestFaultSDKHealthHandlerIsSeenByTheHealthCheck` |
| Baseline, new plugin pending, reported once, also after a Zoraxy restart | `TestPermissionBaselineThenNewPluginsArePending` |
| Default: an update that adds an endpoint gets it, with an audit entry and a badge | `TestFaultPermissionAddedByAnUpdateIsGrantedAndReportedByDefault` (real `UpdatePlugin` through a local store fixture) |
| Opt-in: an update that adds `blacklist/ip/add` is not granted until approved; approve one, refuse nonsense, withdraw, approve all, restart, endpoint dropped and re-added is new again, option off again | `TestFaultPermissionAddedByAnUpdateIsNotGrantedUntilApproved` |
| Opt-in: a new plugin gets a key that opens nothing; approval stored | `TestFaultNewPluginGetsNothingUntilApprovedWhenApprovalIsRequired` |
| A plugin without permissions: no record, no key, no audit entry | `TestFaultPluginWithoutPermissionsHasNoRecordAndNoKey` |
| Uninstall forgets | addition to `TestFaultUninstallForgetsPolicyAndConsent` |
| Live key narrowed and widened without a new key | `TestSetPermittedEndpointsForPlugin` (`mod/auth`) |
| UI | `tools/ui-smoke/plugins_smoke.py`: mocked part (Health line, notice, contract row, permissions block with hostile endpoint and reason texts, Approve / Approve all / Withdraw post exactly what is shown, safety settings) and, through `plugins_run.sh`, the real part (a new plugin: granted and reported; "Require my approval" ticked with the real checkbox: nothing granted; one endpoint whose name is markup approved with its button; the rest with the button below; each read back from the API) |

Results (2026-11-23, shared 4-core machine, through `~/capped.sh`): see the build report of this change for the
exact runs. `go vet ./mod/plugins/...`, `GOOS=windows go vet ./mod/plugins/...` and `go build ./...` clean;
`go test -p 1 -race ./mod/plugins/... ./mod/auth/` green; `plugins_run.sh` green on a throw-away instance (port
20710) in headless Chromium at 1366 px, light theme. **Not run:** the whole `go test ./...`, the rest of
`tools/ui-smoke`, anything as root, on Windows or macOS.

### Not done

- **2.4 signed index, 2.5 safe install / rollback, 2.7 isolated plugin UI, phase 3**: not in this change. The key
  pair tool of owner decision D4 belongs to 2.4 and was not written here.
- **The SDK is not a Go module** (decision, `contract.md` section 9). **The tag `sdk/v1.1.0` was not created**
  and **no CI job** runs the compatibility test; it runs with the package tests.
- **Start flags** for the two settings: there are none, they are in the database and the UI only.
- **Plugin info side panel and store dialog** (`web/snippet/pluginInfo.html`, `web/components/appstore.html`): not
  changed. They still list the permissions of a manifest without saying what is approved.
- **The generated HTML of the author docs** (`docs/plugins/html/`) was not rebuilt; the Markdown and `index.json`
  are updated.
- **DEVELOPMENT.md**, translations (all new texts are English), Prometheus series.
- **`plugincontext.html`** was not touched (it belongs to 2.7).

### Known limits

- **The contract version is a declaration, not a proof.** Zoraxy cannot tell whether a plugin that says
  `api_version: 1` follows the contract; that is the conformance kit of phase 3. The only mismatch that exists
  today is "newer than this Zoraxy"; there is no "too old", because version 0 is supported.
- **Warn mode warns in the log, the API and the Plugin Manager only.** No notification, no audit entry.
- **Refuse applies to starts.** Turning it on does not stop a plugin that is already running; it is refused at its
  next start. Until then the Plugin Manager says "still running, will not be started again". A restart policy that
  restarts such a plugin after a crash runs into the refusal once and stops there in the state `failed_to_start`
  (no retries, no crash loop; `TestFaultRefusedPluginIsNotRetriedAfterACrash`). Turning refuse off again does not
  start it: press Start.
- **Your three plugins are legacy plugins** and stay so until their authors rebuild them with SDK 1.1.0 or add the
  field. Nothing changes for them.
- **How the three "installed" golden manifests were taken:** by running each binary under `/home/sysadmin/plugins`
  once with `-introspect` (as the unprivileged build user, working directory in a scratch folder, 10 s limit), the
  same call Zoraxy makes at every boot. They are Data-Shield Blocklist 1.3.0, Resource Monitor 1.0.3 and Zoraxy
  Cloudflare WAF 0.3.4, which is what is installed here; section 1 of this plan quotes the public index
  (1.4.0 / 0.4.0). The plugins on the other proxy were not looked at.
- **SDK 1.0.0 is the SDK as the example plugins carried it** (identical to commit `ff33f5be`, with hooks and the
  invoke token). Plugins built with an older upstream copy (before hooks) are covered by the golden manifests
  only, not by a built binary.
- **The compatibility test runs a well-behaved plugin.** It is the part of the fault suite a correct plugin has to
  pass (start, calls, crash, restart, stop), not the chaos modes: those need a plugin that misbehaves on purpose
  and stay with the chaos plugin, which does not use the SDK.
- **Stop of an SDK plugin** ends by the terminate request or by the SIGTERM that follows it, whichever is first;
  the exit code shown can be 0 or "signal: terminated". Unchanged behaviour, noticed while writing the test.
- **Secrets on standard input** only for plugins that declare it. A `start.sh` has to pass its standard input on.
  A plugin with limits is started through `systemd-run --scope`. Checked by hand on this host
  (`echo ... | systemd-run --user --scope -q -- cat` prints the line): standard input passes through a user scope.
  There is **no automated test** of `configure_via` together with limits (the phase 1 limits tests use the command
  line way), and a system scope (Zoraxy as root) was not tried.
- **Permissions are per plugin ID, not per binary.** Whoever can replace the binary of an approved plugin, or
  install another plugin under the same ID after an uninstall was skipped, inherits its approvals. Binding
  approvals to a checksum needs the signed index (2.4).
- **The baseline approves what is there.** Every plugin present at the first start of this version, also one that
  was copied in by hand, is recorded as approved with what it asks for at that moment. Review the list once before
  turning "Require my approval" on (Details of each plugin says "installed before permissions were tracked"). The
  baseline is taken per database: a new database, or a plugin directory that could not be read at that start,
  takes it at the next successful start.
- **A plugin folder that could not be loaded at that first start** (introspect timed out on a busy machine, broken
  binary) is remembered by its folder name and gets its baseline the first time it loads. This goes by the folder
  name, not by what is in the folder: whatever loads first from that folder is recorded as approved, once. The
  name is forgotten when the folder is gone at a boot or a reload (every store install and uninstall reloads), so a
  folder that is deleted and created again between two reloads still counts as the old one. A plugin whose first
  load fails *after* the baseline was taken is a new plugin.
- **A reload does not look at the permissions of plugins that are already loaded.** A binary that was replaced by
  hand is introspected again only by an update or the next start of Zoraxy; until then the approvals, the Plugin
  Manager and the API key all describe the manifest that was loaded. The process itself is the new binary from its
  next start on (unchanged from before).
- **In the default mode an approval binds nothing.** It records that the administrator has seen the endpoint and
  clears the badge. It becomes binding when "Require my approval" is turned on.
- **A permission is a method and a path, compared as text.** `get` and `GET` are different, as they already are
  for the API key check. There is no approval "for this version only" and no expiry.
- **An endpoint a plugin stops asking for loses its approval** when that manifest is loaded, so a downgrade and a
  later upgrade need a new approval.
- **Withdrawing an approval** changes the live key at once; a request that is being answered at that moment is
  not cut off. In the default mode it only brings the badge back.
- **With "Require my approval" on, a plugin that needs an endpoint it does not have** sees its call refused and
  may log errors or stop working until the endpoint is approved. That is what was asked for, and why it is off by
  default. The HTTP status of such a refusal is the one the plugin API always gave for an endpoint outside the
  manifest; it was not checked here.
- **The audit entry is written once per change** of the set of endpoints that are not approved, not at every boot.
  Approvals and withdrawals by the administrator are recorded by the HTTP audit middleware as
  `plugins.permissions` (every POST under `/api/plugins/`), which follows from reading `mod/secaudit/http.go` and
  was not tested here. The same goes for `plugins.settings`.
- **Read-only accounts** can read `GET /api/plugins/permissions` and `GET /api/plugins/settings` like the other
  plugin GET routes. Not tested with a viewer account.
- **The reason text of an endpoint is the plugin author's.** It is shown escaped, prefixed "The plugin says:".
- **Without a database** (unit tests only) settings and approvals live in memory.
- **UI**: looked at in headless Chromium at 1366 px, light theme, once. Dark theme and phone width of the new
  blocks were not looked at. The permissions block is reloaded when the status of the plugin says its permissions
  changed, at most every 10 s.
- **A change of the plugin ID by an update** makes it a new plugin for permissions (and, as before, for policy).

### Phase 2 review fixes

Findings of the independent review of items 2.1 and 2.6 and what was done. The tests are in
`src/mod/plugins/phase2_review_test.go`. No default changed; the first row removes a change for existing installs
that the first version of this phase made without saying so.

| Finding | Fix | Test |
|---|---|---|
| An `api_version` that is not a whole number (`"1"`, `1.5`, a number too large, an object) made the whole manifest fail to decode, so the plugin could not be loaded. Before the field existed such a key was ignored, and `contract.md` said it is dropped (major) | `decodeManifest` in `introspect.go`: when the only thing wrong with the manifest is the type of `api_version`, the key is dropped (any spelling Go would match), one line is logged and the plugin is a legacy plugin. Every other field is decoded as strictly as before. `contract.md` section 1 lists the cases | `TestContractAPIVersionThatIsNotANumberLoadsAsLegacy` (string, fraction, huge, object, list, bool, other spelling, the key twice; `null` and numbers without a warning; other broken fields still fail), `TestFaultPluginWithOddAPIVersionIsLoadedAsLegacy` (a `start.sh` plugin through the real loader) |
| Two changes of the plugin safety settings at the same time both started from the same values; the later write undid the earlier one, and the database and the memory could disagree | `SetSettings` holds a lock from reading the settings to storing and swapping them; the API keys are adjusted after it is released | `TestSettingsConcurrentChangesDoNotUndoEachOther` (200 rounds, also under `-race`) |
| Every reload read the manifest of plugins that were already loaded and reviewed their permissions against it, although that manifest is thrown away: approvals could be dropped and audit entries written for a binary that is not the loaded one | `reviewPermissions` is no longer called by `LoadPluginSpec`. It is called where a manifest becomes the loaded one: at boot, for a new plugin found by a reload, and by an update after the swap (the plugin is stopped at all three, and the start that follows grants what is approved) | `TestFaultReloadDoesNotReviewPermissionsOfLoadedPlugins` |
| The Health column said "not started" for a plugin of an unsupported contract version that was still running after refuse was turned on | "not started" only in the state `failed_to_start`; a running plugin shows "still running, will not be started again", any other state "will not be started". The Details row says the same | `plugins_smoke.py` ("a running plugin of a refused contract version is not called 'not started'") |
| With refuse on and a restart policy, a crash of such a plugin led to five refused restarts and the state `crash_loop` | The automatic restart treats the refusal as the boot path does: one attempt, state `failed_to_start`, an exit history entry that says why, nothing counted towards a crash loop | `TestFaultRefusedPluginIsNotRetriedAfterACrash` |
| Known limit "standard input through `systemd-run --scope` not tested" could be narrowed; the changelog called `health_path` and `configure_via` new in 1.1.0 although the fork.30 copy of the SDK had them | Known limit reworded (checked by hand, no automated test). `CHANGELOG.md` (and its copies in the example plugins) says that these names first shipped unversioned with fork.30 and that 1.1.0 is the first numbered release with them | none (documentation) |
| The baseline did not cover a plugin that failed to load at the first start of this version; it became a "new" plugin at its next load | The folder names that failed to load at the baseline boot are stored (`permission_baseline_deferred` in `plugin_settings`); such a folder gets its baseline at its first successful load, once. Limits: see "A plugin folder that could not be loaded at that first start" above | `TestPermissionBaselineCoversPluginsThatFailedToLoadThen`, `TestPermissionBaselineIsNotExtendedByLaterLoadFailures` |

Behaviour that changed with these fixes, compared with the first version of this phase (which was never released):
a manifest with an odd `api_version` loads again; a reload no longer writes permission records or audit entries for
loaded plugins; one more key in `plugin_settings` when a plugin failed to load at the baseline boot.

Results (2026-11-23, shared 4-core machine, through `~/capped.sh`): `go vet ./mod/plugins/...`,
`GOOS=windows go vet ./mod/plugins/...` and `go build ./...` clean; `go test -p 1 -race ./mod/plugins/... ./mod/auth/`
green (plugins package 71 s); `plugins_run.sh` green on a throw-away instance (port 20710). Not run: the whole
`go test ./...`, the rest of `tools/ui-smoke`, anything as root, on Windows or macOS.

Not done: no automated test of `configure_via` with limits; the Plugin Manager texts for a refused plugin are
derived from the state in the browser, the API still reports `Contract.Refused` from the current setting (true for
a running plugin that will be refused at its next start).

### How to run

```
cd src
GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test -p 1 ./mod/plugins/ ./mod/auth/ -count=1 \
  -run 'TestContract|TestSDK|TestPermission|TestSettings|TestFaultContract|TestFaultRefused|TestFaultSDK|TestFaultPermission|TestFaultNewPlugin|TestFaultPluginWith|TestFaultReloadDoesNot|TestSetPermittedEndpoints'
GOTMPDIR=$HOME/.cache/go-tmp CGO_ENABLED=1 ~/capped.sh go test -p 1 -race ./mod/plugins/... -count=1     # everything, needs gcc
cd .. && PY=<python with playwright> PORT=20710 tools/ui-smoke/plugins_run.sh     # ZORAXY_BIN=<binary> skips the build
cd example/plugins/filter-example && GOFLAGS=-mod=mod GOPROXY=off go build -o /tmp/filter-example .     # every example builds offline
```

The SDK compatibility tests need the `go` command at run time (two small offline builds, in the folder the chaos
plugin is built in). To freeze the next SDK version: copy `src/mod/plugins/zoraxy_plugin` to
`src/mod/plugins/testdata/sdk-<version>/zoraxy_plugin` before changing it, and add that version to
`phase2_helper_test.go`.

---

## Phase 2 results and known limits (items 2.4, 2.5, 2.7)

Built 2026-11-23 on `dev`. This section covers the three items the section above left open: the signed plugin
index (2.4), safe install, update and rollback (2.5) and the isolated plugin UI (2.7). Owner decisions used: D4 (a
separate plugin key, mode warn by default, enforce opt-in, no index published or curated here). **No real key was
read, copied or created**: Zoraxy only verifies with a public key you configure, the tool creates a key pair when
you run it, and the tests use keys the tool creates in a temporary folder. Phase 3 was not built when this section was written (it is now: see the last section).

### What was built

| Item | Where | What it does | Default |
|---|---|---|---|
| 2.4 Signed index format | `src/mod/plugins/store_verify.go` | A second index format next to the upstream list: `{"format":"zoraxy-plugin-index","version":1,"serial":N,"plugins":[{IconPath, PluginIntroSpect, Downloads:{"linux_amd64":{url, sha256, size}}}]}` with a detached signature at `<index URL>.sig` (the raw 64 bytes of an ed25519 signature over the exact bytes of the index, PKCS#8 / SPKI PEM keys: the format of `tools/sign_release.go`). `serial` only goes up; Zoraxy stores the highest serial it has seen per index URL (with the checksum of that index) and treats a lower one, or the same one with other content, as a replay | |
| 2.4 Key | settings `IndexPublicKey`, start flag `-plugin_index_pubkey=<file>` (wins over the setting) | The public half of the plugin key: PEM, or 32 bytes in base64 or hex. A private key pasted there is refused with a clear error | none |
| 2.4 Verification mode | settings `VerifyMode`, "Plugin safety settings" in the Plugin Manager | `off`: no signature file is fetched, nothing compared. `warn`: every finding (no key, signature missing, signature not valid, replay, download does not match checksum or size) is logged, written to the security audit log once per change and shown; nothing is refused. `enforce`: a plugin is installed or updated only from a validly signed, not replayed index with checksum and size for the platform, and only when the download matches; the download is cut off at the size of the index; the binary must declare the ID of the index; while an index is not valid the plugins of its last valid version stay on offer | **warn** |
| 2.4 Changed binary | `checkBinaryForStart`, `checkBinaryBeforeLoad` in `store_verify.go`, `lifecycle.go`, `plugins.go` | For a plugin with an install record the SHA-256 of the program file is compared with what was installed: at every start, and **before the file is run for its manifest** at a start of Zoraxy and at every reload. For that second check the record is found by the plugin **folder** (stored in the record, table `plugin_install_folders`), not by the ID the file declares. warn: log line, one audit entry (`plugins.binary.changed`), red line in the Plugin Manager, loaded and started anyway. enforce: at a start it is not started (state `failed_to_start`, not retried by a restart policy); at a start of Zoraxy the changed file is **not run at all** and the folder is listed under "could not be loaded" with the reason; at a reload it is not run and the plugin that is loaded stays as it is. off: not looked at | warn |
| 2.4 Source of install (F15) | `InstallRecord` in table `plugin_installs`, `updateCandidate` | Every install records the index URL, the version, checksum, size, the signature state of the index and how the download was checked. Update information and updates of that plugin come from that index only. `POST /api/plugins/store/releaseSource` (button "Allow updates from any index") lifts the binding | on for new installs, see "Behaviour that changed" |
| 2.4 Tool | `tools/plugin-index/sign_plugin_index.go` (standard library only, outside the Go module) | `-genkey PRIVATE.pem PUBLIC.pem` (refuses to overwrite, private key mode 0600), sign (`-index DRAFT -out index.json -key ... -serial N [-files DIR] [-fetch] [-pub ...]`: fills in checksum and size from local files or by download, refuses a serial that is not higher than the one at `-out`, refuses http and "latest" URLs, verifies its own output), `-verify`. It refuses a key file named like the release key or equal to `$ZORAXY_RELEASE_KEY` | |
| 2.5 Staging | `src/mod/plugins/store_safe.go`, `store.go`, `store_update.go` | Install and update download to `<plugin dir>/.staging/<plugin id>/` with a size cap (256 MB, setting `MaxDownloadMB`; in enforce the size of the index) and a timeout (10 minutes per download, 30 s for an index), compare with the index, and run the binary there with `-introspect`, **as the plugin user** when `-plugin_user` is set. The staging folder is skipped by the plugin loader | always |
| 2.5 Swap and previous version | `swapIn`, `swapBack` | Only after all of that the plugin is stopped and the binary swapped by two renames inside the plugin directory; the replaced binary goes to `<plugin folder>/.zoraxy-previous/` (a name of Zoraxy's own, so a plugin that keeps data in a folder called `previous` does not lose it). A failed second rename undoes the first. An install moves the whole staged folder into place with one rename | always |
| 2.5 Health check | `waitHealthyAfterUpdate` | After an update of a plugin that was running (or waiting for an automatic restart) the new process has to answer (its `health_path`, else a TCP connect) within 15 s and then stay up, as the same process, for 2 s | always, for plugins that were running |
| 2.5 Rollback | `RollbackPlugin`, `POST /api/plugins/store/rollback`, button "Roll back to version X" in Details | Puts the binary of `.zoraxy-previous/` back, reads its manifest, starts the plugin if it was meant to run. One previous version is kept; a rollback uses it up | manual |
| 2.5 Automatic rollback | setting `AutoRollback` | A new version that fails to start or fails the health check is replaced by the previous one, which is started | **off**: the new version stays in place, the failure is reported with the way out |
| 2.7 Isolated plugin UI | `src/mod/plugins/ui_isolation.go`, `ui_router.go`, `src/pluginui.go`, `web/components/plugincontext.html` | Settings `IsolatePluginUI`, `PluginUIListen`, `PluginUIOrigin`. On: Zoraxy opens a second listener (default: the host of the admin UI, next port; TLS with the web UI certificate when the admin UI uses TLS; the admin allow-list in front). The admin page asks `POST /api/plugins/ui/ticket` and opens `<origin>/t/<ticket>/` in an iframe sandboxed without `allow-same-origin`. Requests go to the plugin without `Cookie`, `Authorization` and CSRF token (header `X-Zoraxy-Ui-Isolated: true` instead); `Set-Cookie` of the plugin is dropped; every answer carries `Content-Security-Policy: sandbox ...` and `Referrer-Policy: no-referrer`; `/plugin.ui/` under the admin origin answers 403. The public style and script files plugin pages load by absolute path (`/script/`, `/main.css`, `/darktheme.css`, `/img/public/`, `/locales/`, `/favicon.png`) are served there too | **off** |
| UI | `src/web/components/plugins.html` | Plugin safety settings: signature checking (select), public key, list of indexes with their signature state, automatic rollback, plugin page isolation with its addresses and state. Details of a plugin: block "Install and updates" (index, signature badge, download check, checksum, program file state, last change, previous version, "Roll back to version X", "Allow updates from any index"). Health column and notices for a changed program file and for an update that did not start properly | |
| API | `/api/plugins/settings` (more fields, also the index list), `Status.Install` in list / info / status, `/api/plugins/store/list` (`Downloads`, `Signature`, `IndexSerial`), `/api/plugins/store/checkUpdates` (`source`, `boundToSource`, `signature`, `blocked`), `/api/plugins/store/sources` (format, signature, serial, note), `/api/plugins/store/install` (optional `source`) | additive | |
| Chaos plugin | `src/mod/plugins/testdata/chaosplugin/main.go` | Setting `version`; settings appended to the binary after `##CHAOS-TRAILER##` (makes "version 2" of a plugin with another checksum and, say, `mode=crash`); feature `adminprobe` (its page and its process try to use the admin session); `/ui/headers` | |

### Behaviour that changed for existing installs

1. **A new database table** (`plugin_installs`) and one more key in `plugin_settings` (`index_seen`). Plugins that
   are installed now have **no** install record: nothing is checked for them at start, and any index may update
   them, as before.
2. **The first store update of such a plugin binds it** to the index that update came from, and keeps the replaced
   binary in `.zoraxy-previous/`. From then on only that index updates it. To undo: "Allow updates from any index".
3. **Plugins installed from the store from now on** are bound to their index from the start. If you run a second
   index that offers the same plugin ID with a higher version, it no longer takes over updates.
4. **Install and update run the binary once more than before**: in the staging folder, before anything is replaced
   (and, with `-plugin_user`, as that user; before, the first run of a new binary was always as Zoraxy's user).
   A download that is not a loadable plugin is now refused before the installed version is stopped.
5. **An update no longer stops the plugin before the download.** It keeps running until the new binary passed its
   checks. A failed download leaves it running (before: stopped).
6. **An update of a running plugin takes at least 2 s longer** (the health check), and an update whose new version
   does not come up now returns an error although the new binary is in place. That is on purpose: the error names
   the rollback. Before, only a start that failed outright was an error.
7. **Downloads have a size cap** (256 MB per plugin binary, 4 MB per icon, 8 MB per index) **and a timeout.** A
   larger plugin needs `max_download_mb` (`POST /api/plugins/settings`, up to 4096).
8. **A folder called `.staging` in the plugin directory is not loaded as a plugin**, and every plugin folder may
   get a sub-folder `.zoraxy-previous/`.
9. **Default mode warn:** with the upstream index (not signed) nothing is fetched or logged that was not before;
   its plugins are labelled "Unsigned". Log lines and audit entries only appear for an index in the signed format
   or a plugin with an install record.
10. **The admin page asks `/api/plugins/ui/ticket` before it opens a plugin page.** With isolation off the answer is
    the address it always used.
11. Nothing else. No plugin is refused, no update is rolled back by itself and no plugin page is isolated unless
    you turn the setting on.

### Tests

`src/mod/plugins/phase2_store_test.go` (19 tests; the "store" is a local `httptest` server, the index is signed by
the real tool, which the test builds), `tools/plugin-index/sign_plugin_index_test.go` (3 tests),
`tools/ui-smoke/plugins_smoke.py` and `plugins_run.sh`.

| Behaviour asked for | Test |
|---|---|
| Defaults: warn, no key, no automatic rollback, no isolation; invalid values refused | `TestStoreDefaultsChangeNothing` |
| Key formats; a private key is refused; the start flag wins | `TestSignedIndexKeyFormats` |
| Index signed by the tool verifies; install under enforce; record and status | `TestSignedIndexInstallUnderEnforce` |
| Tampered binary (same size / larger): enforce refuses and leaves nothing, warn installs, records and audits | `TestSignedIndexTamperedBinaryPerMode` |
| Wrong hash in a forged index, other key, broken signature file, no signature file, no key: warn / enforce | `TestSignedIndexBadSignaturePerMode` |
| Replayed older index (also after a restart), same serial with other content: warn lists it marked, enforce keeps the last valid one and refuses | `TestSignedIndexReplayPerMode` |
| Upstream index: unsigned, cannot make itself look signed; warn installs as before, enforce refuses without downloading | `TestUnsignedIndexPerMode` |
| Mode off fetches no signature and compares nothing | `TestVerificationOffChecksNothing` |
| Updates only from the source of install; error text; release | `TestUpdatesOnlyFromTheSourceOfInstall` |
| A plugin without a record updates as before and is then bound | `TestPluginWithoutRecordUpdatesAsBeforeAndIsThenBound` |
| Binary replaced on disk: warn starts and reports once, enforce does not start, off does not look | `TestBinaryChangedOnDiskPerMode` |
| Update keeps `.zoraxy-previous/`, plugin files untouched, manual rollback through the API, second rollback refused, `.staging` not loaded | `TestSafeUpdateKeepsThePreviousVersion` |
| A failed download keeps the old version **running** (same PID): HTTP 500, transfer cut off, larger than the index, wrong checksum, stalled (timeout), over the size cap with and without Content-Length, not a plugin | `TestFailedDownloadKeepsTheOldVersionRunning` |
| The staged binary is introspected through the plugin user setting | `TestStagedBinaryIsIntrospectedAsThePluginUser` (not as root, see known limits) |
| **Chaos: the new version crashes at start** (also: exits with 0, never opens its port). Default: reported, rollback button restores the old one, running. Opt-in: restored and started by itself | `TestFaultNewVersionCrashesAtStart` (6 cases) |
| The same under a restart policy `on-failure` | `TestFaultNewVersionCrashesUnderARestartPolicy` |
| A stopped plugin is updated and rolled back without being started | `TestUpdateAndRollbackOfAStoppedPlugin` |
| **An admin API call from the plugin UI works when not isolated and fails when isolated** (the plugin process calls an API that needs the admin cookie and CSRF token with what it was handed); cookie, Authorization and CSRF token stripped; `Set-Cookie` dropped; CSP sandbox; tickets per plugin; 403 under the admin origin; off again | `TestIsolatedPluginUICannotUseTheAdminSession` |
| Listener that cannot be opened is refused, origin validation, static file allow-list, allow-list wrapper, configured origin, restart | `TestIsolatedPluginUIListenerAndStaticFiles` |
| Tool: round trip, serial must rise, changed index / binary / other key noticed, "latest" and http URLs refused, release key refused | `TestSignVerifyRoundtrip`, `TestSignRefusesWhatWouldNotVerifyLater`, `TestReleaseKeyIsRefused` |
| UI, mocked: install block with hostile texts, Roll back and "any index" ask first and post the plugin ID, signature badges, Health lines, frame attributes with and without isolation, safety settings post one change each | `plugins_smoke.py` |
| UI, real instance (`plugins_run.sh`, a local signed index on PORT+3): key saved on the page turns the index from "no key" to "Signed"; install under enforce; version 1.1.0 crashes at start, the page reports it, the Roll back button restores 1.0.0; **in a real browser** the plugin page reads the plugin list and changes a safety setting when not isolated, and with isolation ticked it sees no cookie and no token, both calls are blocked, `document.cookie` is denied and the setting is unchanged | `plugins_smoke.py` live part |

Results (2026-11-23, shared 4-core machine, through `~/capped.sh`): `go vet ./mod/plugins/...`,
`GOOS=windows go vet ./mod/plugins/...` and `go build ./...` clean; `go test -p 1 -race ./mod/plugins/... ./mod/auth/`
green (plugins package about 100 s); both tool test files green; `plugins_run.sh` green on a throw-away instance
(port 20710, headless Chromium, 1366 px, light theme). **Not run:** the whole `go test ./...`, the rest of
`tools/ui-smoke`, anything as root, on Windows or macOS, with web UI TLS.

### Not done

- **No index was published or curated**, no key pair of the owner exists yet. Until you create one, sign an index
  and add its URL as a store source, every plugin is "Unsigned" and `enforce` would refuse every install and update.
- **Your three installed plugins have no install record** and are not bound to an index or checked at start until
  their next store update (or a reinstall).
- **App Store page** (`web/components/appstore.html`) and the plugin info side panel: not changed apart from the
  escaping of error texts (see "Review fixes"). The store does
  not show the signature state of a plugin or why an install is refused beyond the error text of the API. The
  signature state of each index is in the Plugin Manager.
- **Start flags** for the settings (other than the key file): none.
- **Rollback of more than one version, rollback of the icon, rollback of the plugin's own data files**: not built.
- **Script plugins** (`start.sh`) are not updated by the store, as before, so they have no rollback.
- **Hot rebuild** (developer mode) does not update the install record; a rebuilt plugin shows "changed since
  install", and under enforce it is not started and not loaded at the next start of Zoraxy.
- **DEVELOPMENT.md, `docs/plugins/contract.md`, author docs, translations** (new texts are English), Prometheus series.
- **`web/index.html`** was not touched: its theme switch calls into the plugin frame. `plugincontext.html` gives an
  isolated frame a stand-in so that call does nothing; the dark theme is not passed to an isolated page.

### Known limits

- **The signature covers the index, the checksum covers the binary.** Nothing here says a plugin is safe; it says
  the binary is the one the holder of the plugin key listed. Whoever holds the private key can sign anything.
- **Key change:** there is one key. To rotate it, sign the index with the new key and replace the public key on
  every proxy; in between the index shows "Signature not valid". The stored serial numbers are per index URL, not
  per key, and are only cleared with the database.
- **Replay protection starts at the first valid index a proxy sees** and is per URL. A fresh install can be served
  an old (validly signed) index once. An index that is withheld altogether cannot be told from one that has no news.
- **warn installs what it warns about.** That is the meaning of the default; a mismatching download is on record
  (Details, audit log), not blocked.
- **enforce and plugins without a record:** they start as before, because Zoraxy has no checksum for them. Their
  updates are refused unless the index is signed.
- **The check of the program file happens at start, at a start of Zoraxy and at a reload**, not while the plugin
  runs, and covers the entry binary only, not other files in the plugin folder (a `start.sh` next to a missing
  binary, a library the binary loads). It costs one SHA-256 of the binary per start and per reload.
- **enforce keeps a changed file from running only for a folder with an install record.** A folder that was copied
  in by hand, or a plugin installed before installs were recorded, is run for its manifest at every start and
  reload as before, as Zoraxy's user. Whoever can write into the plugin directory can also add such a folder.
  enforce is about what the store installed, not a lock on the plugin directory.
- **Under enforce a plugin whose file changed is not loaded at the next start of Zoraxy**: it is not in the plugin
  list (the folder is listed as not loadable, with the reason), so it cannot be updated or rolled back from the UI.
  Put the installed file back, or remove the folder and install again, or switch to warn and restart. That
  includes a plugin you rebuilt with hot rebuild (developer mode), which does not update the install record.
- **warn still runs a changed file**, at a start of Zoraxy and at the start of the plugin. When the file declares
  the ID of its record, the start reports it; when it declares another ID, the load reports it (audit entry with
  `declared`). A changed file of a plugin that is never started and keeps its ID is only reported when started.
- **Switching the mode or the key re-reads the indexes** when a list was loaded before. Entries read with
  verification off count as not signed under enforce until the next sync.
- **Two download timeouts:** 10 minutes for the whole transfer, and a stall timeout of 60 s (a download that
  delivers no byte for that long is ended; every byte that arrives gives it another 60 s). Neither is a setting.
  Redirects are followed as before; the checksum is what pins the content, so a "pinned URL" is a rule of the signing tool
  (it refuses "latest" URLs), not something Zoraxy can verify.
- **Introspect in staging as the plugin user needs root**, like every use of `-plugin_user`. Not root with the flag
  set: the install is refused with the same message a start gives. The run as another user was **not tested**
  (tests do not run as root); the test shows that the staging introspect goes through that setting. The boot-time
  introspect of installed plugins still runs as Zoraxy's user (F17 is only closed for new binaries).
- **The staged binary is run with `-introspect` before the administrator sees its manifest.** Verification comes
  first; in warn mode a binary that failed verification is still run.
- **The swap is two renames, not one.** Between them the plugin folder has no binary; the plugin is stopped then.
  A crash of Zoraxy in that window leaves the installed binary in `.zoraxy-previous/` (update) or in
  `.staging/.rollback-<id>/` (rollback). The **next start of Zoraxy** renames it back (see "Review fixes"); until
  then the plugin has no program file. The Roll back button cannot help in that state: it needs a loaded plugin.
  The repair only runs at a start, never at a reload, and only for a folder whose program file is named after the
  folder (script plugins are not updated by the store). After an interrupted update the version an *earlier*
  update had kept is gone (the swap clears it first), so there is nothing to roll back to.
- **The health check is "answers and stays up for 2 s".** A new version that breaks later, or answers its health
  path while filtering wrongly, passes. A plugin that needs more than 15 s to open its port fails it.
- **Without automatic rollback a failed new version stays installed and stopped** (or running without a port).
  With a restart policy the supervisor keeps restarting it until you roll back or it reaches the crash-loop limit.
- **After an automatic rollback the store still offers the bad version.** Nothing retries it, but "Update" will.
  The note about the failed update stays in Details until the next install, update or rollback.
- **A rollback restores the binary only.** A new version that converted its data files leaves them converted.
- **An update of a plugin that changes its ID** is allowed in off and warn (as before) and refused in enforce.
- **Isolated plugin pages need a second port your browser can reach.** Behind another reverse proxy or a firewall
  you have to publish that port and set "Address your browser uses". If the listener cannot be opened when you
  turn the setting on, the setting is refused. If it cannot be opened at a later start of Zoraxy, plugin pages are
  unavailable (the admin origin refuses them) until you fix the address or turn the setting off.
- **A plugin page that needs the admin API, cookies, `localStorage` or same-origin access stops working when
  isolated.** Which of your three plugins do was **not checked**. The shared script files of the admin UI are
  served, but those that use storage (theme) throw inside the sandbox.
- **The ticket is the key to a plugin page**: 8 hours, per plugin, in the address. Whoever has the address can open
  that plugin's page (not the admin UI) until it expires; a logout does not end it. Tickets live in memory and end
  when Zoraxy restarts or isolation is turned off. At most 512 are kept.
- **The isolated listener** has the admin allow-list in front but not the dial guard that keeps proxy rules from
  targeting the admin listener, and no login of its own: static files on it are the ones that are public anyway.
- **An isolated page can still open a window on the admin address.** The sandbox has `allow-popups` (links in
  plugin pages that open a new tab keep working). A window opened that way is a top-level GET navigation, and the
  browser sends the admin cookie with it (SameSite=Lax). The page cannot read the answer and cannot send a POST
  with the cookie, but an admin API that changes state on a GET request (older handlers do not check the method,
  and `utils.PostPara` also reads the query string) can be triggered blind. Any website you visit while logged in
  can do the same, so isolation is not worse than no isolation here, but "no part in the admin session" is only
  true for reading and for POST. Not fixed: closing it means method checks on every admin handler, which is outside
  the plugin work. `allow-popups` was kept; dropping it would not stop the outside website.
- **What isolation does not stop:** the plugin process itself still has its granted plugin API key and runs as
  its OS user; isolation is about the page in the administrator's browser. A path such as `/t/<ticket>/../x` is
  passed to the plugin as it always was under `/plugin.ui/`.
- **Browser behaviour** (opaque origin, blocked cross-origin calls, SameSite cookies) was observed in headless
  Chromium only. With web UI TLS the listener uses the same certificate; that combination was **not run**.
- **UI:** looked at in headless Chromium at 1366 px, light theme. Dark theme and phone width of the new blocks
  were not looked at. Texts are English only.

### Review fixes (2.4, 2.5, 2.7)

Each finding was checked against the code first. Tests: `src/mod/plugins/phase2_store_review_test.go`, and
`tools/ui-smoke/plugins_smoke.py` for the two UI rows.

| Finding | Fix | Test |
|---|---|---|
| Under enforce a program file that changed on disk was still run: every start of Zoraxy and every reload ran it with `-introspect` as Zoraxy's user before anything was compared, and a file that declared another ID had no record and was never compared (major) | The install record stores the plugin folder; `plugin_install_folders` maps folder to plugin ID. `checkBinaryBeforeLoad` hashes the entry point before `LoadPluginSpec` runs it, at boot and reload. enforce: a mismatching file is not run; at boot the folder is a load failure with the reason, at a reload the loaded plugin is left as it is; one audit entry per changed file. warn: loaded as before, and a file that declares another ID than its record is logged and audited (`declared`). A record without a folder (written before this fix) gets it at the next boot. The UI texts about enforce say what happens | `TestChangedBinaryIsNotRunBeforeItIsCompared` (the replacement leaves a marker file when run), `TestInstallRecordLearnsItsFolderAtBoot` |
| Docs and two comments said `previous/`, the code uses `.zoraxy-previous/` | Corrected everywhere in this section and in `store_safe.go`, `store_verify.go` | |
| Docs said there is no stall detection; the 60 s stall timeout had no test | Doc corrected | `TestStalledDownloadIsEndedByTheStallTimeout` (bytes keep arriving past the stall time, then stop; the overall timeout stays at 10 minutes) |
| A crash between the two renames left a folder without program file; "use Roll back" could not work, nothing cleaned `.staging/` | At a start of Zoraxy `repairPluginFolder` renames the installed file back (from `.staging/.rollback-<id>/` after an interrupted rollback, else from `.zoraxy-previous/` after an interrupted update), with a log line, and `clearStagingAtBoot` empties `.staging/`. Doc corrected | `TestInterruptedSwapIsRepairedAtBoot` |
| No badge for the signature state `downgraded` (an index that was signed and is now served unsigned showed "Unknown") | Red badge "Signature removed" | badge check in `plugins_smoke.py` |
| An index entry without icon no longer got `/img/plugin_icon.png`; the old store page showed a broken image | Default restored for both index formats | `TestIndexEntryWithoutIconGetsTheDefault` |
| Install and update errors quote the ID a downloaded binary declares; the App Store and the old store page passed them to `msgbox`, which renders HTML | Every `msgbox(data.error)` of `web/components/appstore.html` and `web/snippet/pluginstore.html` passes the text escaped (also the resync and source errors, which can quote an index) | `plugins_smoke.py`: an install error with markup in the App Store is shown as text |
| Known limits did not mention that an isolated page can open a window on the admin address | Added to the known limits above; `allow-popups` kept | |

Behaviour that changed with these fixes, all for plugins with an install record or for a state that was broken:
under enforce a changed program file is no longer run at boot or reload (before: run for its manifest, then not
started), and such a plugin is missing from the plugin list after a restart; a start of Zoraxy empties
`<plugin dir>/.staging/` and repairs a plugin folder that an interrupted swap left without program file; one more
database table (`plugin_install_folders`). Nothing changes in off or warn except one more log line and audit entry
for a changed file that declares another ID.

### How to run

```
cd src
GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test -p 1 ./mod/plugins/ -count=1 \
  -run 'TestStore|TestSignedIndex|TestUnsigned|TestVerification|TestUpdatesOnly|TestPluginWithoutRecord|TestBinaryChanged|TestSafeUpdate|TestFailedDownload|TestStagedBinary|TestFaultNewVersion|TestUpdateAndRollback|TestIsolated|TestChangedBinaryIsNotRun|TestInstallRecordLearns|TestInterruptedSwap|TestIndexEntryWithoutIcon|TestStalledDownload'
GOTMPDIR=$HOME/.cache/go-tmp CGO_ENABLED=1 ~/capped.sh go test -p 1 -race ./mod/plugins/... -count=1     # everything
cd ../tools/plugin-index && go test sign_plugin_index.go sign_plugin_index_test.go
cd ../.. && PY=<python with playwright> PORT=20710 tools/ui-smoke/plugins_run.sh     # uses PORT to PORT+3
```

For the owner, once (on a machine that is not a proxy; this is the plugin key, not the release key):

```
go run tools/plugin-index/sign_plugin_index.go -genkey ~/.zoraxy-plugin-index-key plugin-index.pub
go run tools/plugin-index/sign_plugin_index.go -index draft.json -out index.json -key ~/.zoraxy-plugin-index-key -serial 1 -files ./binaries
```

Publish `index.json` and `index.json.sig` side by side, add the URL as a store source, paste `plugin-index.pub`
into Plugin Manager > Plugin safety settings (or start Zoraxy with `-plugin_index_pubkey=<file>`), check that the
index shows "Signed", and only then consider `enforce`. The draft format is in the comment at the top of the tool.

---

## Phase 3 results and known limits (items 3.1, 3.2, 3.3)

Built 2026-11-23 on `dev`. This section covers the three items of phase 3: the reference plugins (3.1), the
conformance kit (3.2) and a run of the kit against the plugins installed on the build machine (3.3). Owner decisions
used: D1 (the goal is the plugins you run plus first-party reference plugins, with a kit that says whether any other
plugin is safe), D4 (nothing here is signed with the release key, no index is published or curated), D5
(Data-Shield is not touched: it was only run, as a copy, by the kit). **Nothing in this phase changes Zoraxy itself**:
no file under `src/` was changed except one new test file.

### What was built

| Item | Where | What it does |
|---|---|---|
| 3.1 `fork-ref-filter` | `example/plugins/fork-ref-filter` | `pre_auth` and `response` hooks, declares `fail_closed`, health path, configuration on standard input, token check. Marks requests and responses with `X-Fork-Ref-Filter`, answers 403 under `/fork-ref-filter/deny` |
| 3.1 `fork-ref-events` | `example/plugins/fork-ref-events` | Subscribes to three events, requires the invoke token, acknowledges at once and works later; its own waiting list is bounded (256, the oldest is dropped and counted). `FORK_REF_EVENTS_WORK_MS` slows its worker for the back-pressure test |
| 3.1 `fork-ref-ui-api` | `example/plugins/fork-ref-ui-api` | A page plus one read (`GET /plugin/api/access/list`) and one write (`POST /plugin/api/blacklist/ip/add`) permission. Reads once at start. **Its port has no login (no plugin port has): any local user or process on the host can make the requests its page makes, with the plugin's API key behind them.** So the write accepts documentation addresses only (inside `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`; `0.0.0.0/0` and every real address are refused by the plugin), at most 16 per start, and the read hands out the number of rules, not the rules. The value in its page only stops cross-site request forgery. The page talks to the plugin only, so it works with plugin page isolation on; the API key never reaches the browser |
| 3.1 Build | `tools/build_ref_plugins.sh`, `tools/build_release.sh -p` | Builds the three plugins for the release architectures into a folder, writes a plain `SHA256SUMS`, and with `-c` runs the conformance kit on the ones the machine can run (a failure stops the build). `build_release.sh` calls it only with the new flag `-p`, after the release is signed and verified, into `DIST_DIR/plugins` |
| 3.2 Conformance kit | `tools/plugin-check` (a Go module of its own, standard library only) | `plugin-check <binary>` (version 1.1.0 since the review fixes): 21 checks (introspect validity and size, manifest, configure, secrets, readiness, loopback only, page, health, verdict rules, sniff, events, invoke token, latency under load, memory after 1000 calls, API calls, stays up, terminate request, SIGTERM within 5 s, leftover processes, log volume). Text and JSON report, exit code 0 / 1 / 2. Method, every rule and the limits: `docs/plugins/conformance.md` |
| 3.3 Certification run | `docs/plugins/conformance.md` section 5, `docs/plugins/conformance-reports/*.json` | The kit against Data-Shield Blocklist 1.3.0, Resource Monitor 1.0.3 and Zoraxy Cloudflare WAF plugin 0.3.4 as installed under `~/plugins` on the build machine |
| e2e | `tools/e2e/scenarios/s12_plugin.py` | New scenario `plugin_reference_plugins` (real Zoraxy, the three reference plugins as real processes). The existing scenario `plugin_filter_hooks` was failing before this change and is repaired (see "Found on the way") |
| Docs | `docs/plugins/conformance.md` (new), `docs/plugins/contract.md` (sniff row corrected, two rows in section 8), `example/plugins/README.md` | |

### Behaviour that changed for existing installs

1. **Nothing in Zoraxy.** No code under `src/` changed besides the new test file `src/mod/plugins/phase3_reference_test.go`.
2. **The default release is the same.** `tools/build_release.sh` without `-p` builds, signs and verifies exactly
   what it did; `-p` adds a sub-folder after that. The reference plugins are not in `SHA256SUMS` of the release.
3. **`example/plugins/build_all.sh` now also builds the three `fork-ref-*` folders** (it builds every folder).
4. Nobody gets a reference plugin installed. They are source code and optional build output.

### Tests

| Behaviour asked for | Test |
|---|---|
| Every reference plugin passes the kit, without a warning, and the checks about what it does were run | `TestReferencePluginsPass` (`tools/plugin-check/check_test.go`) |
| The kit is red on the chaos plugin in each bad mode, at the check that mode is about (19 cases: crash and exit 0 at start and later, never opens its port, accepts nothing, never answers, slower than its timeout, slow inside it, not JSON, 1 MiB, invalid header, log flood, unhealthy, memory balloon, ignores SIGTERM, introspect garbage and hang, contract version 1 without a token check) | `TestChaosPluginFailsInEveryBadMode` |
| The chaos plugin that behaves passes (so the red comes from the mode) | `TestChaosPluginThatBehavesPasses` |
| A plugin on every address fails; calls without the key or outside the manifest fail | `TestPluginThatListensOnEveryAddressFails`, `TestStubAPIRecordsWhatIsNotAllowed` |
| Exit codes, JSON report, text report, report file | `TestCommandLine` |
| The plugin folder is not written to and the scratch folder is removed | `TestPluginFolderIsNotTouched` |
| Verdict rules of the kit = verdict rules of Zoraxy, on 64 verdicts | `TestVerdictFixtures` (kit), `TestConformanceKitVerdictRulesMatchZoraxy` (`src/mod/plugins`) |
| Manifest rules, log counter, percentiles | `TestManifestChecks`, `TestLogCounter`, `TestPercentile` |
| `fork-ref-filter` through the real pipeline: contract version 1, token not on the command line, health check, both stages, deny, token required, fail-open after a crash although it declares `fail_closed` (no consent), automatic restart, stop without kill | `TestFaultReferenceFilter` (`src/mod/plugins/phase3_reference_test.go`) |
| `fork-ref-events` under 600 events with a worker of 25 ms per event: Zoraxy drops and fails none, the plugin's list stays at 256 and counts its drops; events without or with a wrong token are refused | `TestFaultReferenceEventsBackPressure` |
| `fork-ref-ui-api` against a stand-in API that checks the key as the real middleware does: default grants both; "require my approval" grants nothing, then the read only, then both; write only with the page's value, POST and a documentation address (`0.0.0.0/0`, `::/0`, private, loopback, real and too wide ranges are refused and never reach the API), at most 16 writes per start; the read gives a count; the log line does not say "administrator"; key not in the page or the command line | `TestFaultReferenceUIAPIPermissions` |
| The SDK copies of the reference plugins are the SDK of the tree | `TestReferencePluginsCarryTheCurrentSDK` |
| End to end with a real Zoraxy | `tools/e2e/run.sh --only plugin_` (`plugin_reference_plugins`, `plugin_filter_hooks`) |

Results (2026-11-23, shared 4-core machine, through `~/capped.sh`): `go vet ./mod/plugins/...`,
`GOOS=windows go vet ./mod/plugins/...` and `go build ./...` clean; `go test -p 1 -race ./mod/plugins/...` green
(124 s); `go test -race .` in `tools/plugin-check` green (about 60 s); `tools/build_ref_plugins.sh -a "amd64 arm64" -c`
green; both e2e plugin scenarios PASS on ports from 20700. **Not run:** the whole `go test ./...`, the rest of the
e2e suite, `tools/build_release.sh -p` as a whole (it needs the release key, which was not read; `bash -n` only),
the plugin UI smoke (no UI file was changed), anything as root, on Windows or macOS.

### Results of the certification run (3.3)

All three installed binaries **pass** (no failed check). Details and how they were run are in
`docs/plugins/conformance.md` section 5.3. In short:

| Plugin | Result | What to know |
|---|---|---|
| Data-Shield Blocklist 1.3.0 | PASS, 2 warnings | Configuration on the command line. Whether its sniff path checks the invoke token could not be told. Sniff p95 about 1 ms, but measured **with an empty blocklist** (its download was blocked for the run) |
| Resource Monitor 1.0.3 | PASS, 1 warning | Configuration on the command line. Nothing else applies to it |
| Zoraxy Cloudflare WAF plugin 0.3.4 | PASS, 2 warnings | **Its API key is on the command line. Its event path accepts events without the invoke token**: any local process can feed it "blocked" addresses. One log line per event. Its API use was not exercised (it ran disabled, without its settings) |

### Found on the way

- **The e2e scenario `plugin_filter_hooks` was failing before this change** (`POST /api/plugins/enable -> plugin is
  already running`). A plugin folder that is there before the first start has no stored "enabled" flag, which
  counts as enabled, so Zoraxy starts it at boot, and enabling a running plugin is an error. The scenario now
  enables only what is not running. Since when it failed was not looked up; `docs/verification/e2e-dataplane.md`
  still shows the older PASS and was not regenerated.
- **`docs/plugins/contract.md` said a sniff answers 280 / 284 / 580.** Zoraxy reads 200 as "take it" and anything
  else as "skip" (`dynamic_forwarder.go`), and the SDK answers 200 or 501. The row is corrected. The three
  constants are still in the SDK and unused by Zoraxy; they were left alone.
- **At a start of Zoraxy, plugins are started before the plugin API listens.** A plugin that calls the API in its
  first second gets "connection refused". `fork-ref-ui-api` tries its read at start again for up to 30 s. Other
  plugins have to do the same; this is not in `contract.md` yet.

### Not done

- **"Signed with releases" and "listed in the fork index"** (plan row 3.1): the reference plugins are built, not
  signed and not listed. There is no fork index and no owner plugin key yet (D4: you create the key and approve
  each entry). `build_ref_plugins.sh` prints how to sign an index with `tools/plugin-index`.
- **Upstream issues and a "conformance passed for API vX" flag in the index** (plan row 3.3): not done, both need
  the owner. The two findings to pass on are in `conformance.md` section 5.3.
- **The plugins on the other proxy and the newer versions** (Data-Shield 1.4.0, Cloudflare WAF 0.4.0) were not run.
- **The reference plugins were not added to the golden manifests** of `testdata/manifests` (that test asserts
  "all legacy"; the reference plugins declare contract version 1).
- **The kit is not built or shipped by the release script** and has no CI job; it is built from source.
- **No UI** shows a conformance result. `DEVELOPMENT.md`, translations, the generated HTML of the author docs: not
  touched.
- **`docs/verification/e2e-dataplane.md`** was not regenerated with the new scenario.

### Known limits

- **A pass is not a proof.** The kit is a black-box run of a few seconds with sample requests (the full list of
  what it cannot tell is `conformance.md` section 4): not honesty, not correctness of what a filter decides, not
  behaviour with real settings, real lists or over days, not static capture, not what a page does when a button is
  pressed.
- **The kit does not confine the plugin it runs.** Scratch folder, loopback ports, a stand-in API and (since the
  review fixes) an environment without the variables of your shell keep it away from the plugin's own files, from
  Zoraxy and from tokens in the environment; a plugin can still open files by absolute path (your real home
  included) and use the network. `-no-egress` only works for plugins that honour the proxy variables. Do not run
  the kit as root.
- **The search for left processes is not a cgroup.** On Linux the kit finds and ends children that left the process
  group (`setsid`, `setpgid`) and daemons that still run from the scratch folder. A helper that was cut loose
  between two looks at the process tree (about 200 ms apart) and that runs another program from another directory
  is missed. On other Unix systems only the process group is looked at. When the kit is killed with SIGKILL the
  kernel ends the plugin process (Linux), not its children, and the scratch folder stays.
- **The page path and `/term` of every plugin are without authentication on the plugin port.** Any local user or
  process on the host can call them directly; Zoraxy's admin login guards the way through the admin address only,
  and the page proxy adds no secret a plugin could check. So any local process can stop any plugin with
  `GET <ui_path>/term` (a logged-in administrator can reach the same path through the page proxy): for a filter
  that is a bypass (fail-open, the default) or a 503 on its rules (with the `fail_closed` consent), and with the
  restart policy `never` it stays down. And whatever a plugin page can do with the plugin's API key, a local
  process can do. This is upstream's design, unchanged by the fork, now written down in `contract.md` section 4.
  Closing it needs a token on the page path and on `/term`, which is a new contract version: not built. The kit
  prints no warning about it.
- **Thresholds are the kit's own where Zoraxy has none** (introspect size, p95 latency of 250 ms, memory growth of
  64 MiB, log lines per call). They are options, and they are judgement, not contract.
- **The invoke token check fails only plugins that declare contract version 1.** Legacy plugins get a warning,
  and a sniff path that does not take the sample request cannot be judged at all.
- **The verdict rules in the kit are a copy** of `hooks_validate.go`, held together by a shared fixture list of 64
  verdicts. A new rule in Zoraxy needs a fixture, or the copy drifts unnoticed.
- **Latency and memory numbers come from one shared machine** and from one short run each.
- **`sigterm` on a second start**: when a plugin ends on the terminate request (most do), SIGTERM is tried on a
  second start. A plugin that cannot be started twice in a row fails there.
- **Reference plugins are minimal on purpose.** `fork-ref-filter` sets a header on every request and response of
  the rules it is attached to; do not attach it to production rules. `fork-ref-ui-api` can add to a blacklist and
  cannot remove (remove in the Zoraxy access page). **Its write is not protected against local processes:** any
  user on the host can read its page from the plugin port and post the form, without logging in to Zoraxy. The
  value in the page and the CSRF token of Zoraxy only protect the browser of the administrator. What keeps it
  harmless is that the plugin refuses everything but documentation addresses (never routed) and passes on at most
  16 writes per start; a local user can therefore add up to 16 useless entries per start to a blacklist, and learn
  how many access rules exist. Do not copy the page-value pattern into a plugin whose write matters.
- **`fork-ref-filter` declares `fail_closed`.** If you tick the consent for it, requests of attached rules are
  answered 503 while it fails. That is what the declaration is for in tests; leave the consent off.
- **`fork-ref-events` loses events by design** when its list of 256 is full, and everything it counted at a
  restart. It is a fixture, not a log.
- **The reference plugins carry a copy of the SDK** like every example (`TestReferencePluginsCarryTheCurrentSDK`
  and `build_ref_plugins.sh` refuse a stale copy). An SDK change means running `example/plugins/build_all.sh`.
- **Their pages were not looked at in a browser.** They are tested through HTTP only (with and without the admin
  proxy), not with plugin page isolation in a real browser.
- **The reference plugin binaries are about 6 to 7 MiB each** (Go, stripped) and are built for Linux only.
- **Unix only.** The kit and the reference plugin tests do not run on Windows.

### Phase 3 review fixes

Findings of the independent review of phase 3 and what was done. Each was checked against the code first (the first
one is plain in the old source: the page with the value was served to anybody who asked the port). No file of Zoraxy
under `src/` changed besides the test file; no default of Zoraxy changed.

| Finding | Fix | Test |
|---|---|---|
| `fork-ref-ui-api`: any local user could read the page value from the plugin port and make the plugin add `0.0.0.0/0` to the default blacklist with its API key (lock-out), and read the access rules. The docs suggested the admin login guards the write (major) | The proxy of the plugin page carries nothing a plugin can verify, so the reference no longer has a write that matters: documentation addresses only, at most 16 writes per start, the read returns a count. Source comment, page text, log line, README, `contract.md` section 4 and the texts above now say that any local user can trigger it | `TestFaultReferenceUIAPIPermissions` (13 refused addresses, the limit, the count, the log line) |
| An interrupted kit (Ctrl-C, timeout, SIGTERM) left the plugin under test running and the scratch folder behind | The command catches SIGINT, SIGTERM and SIGHUP, ends the process group and every process seen below the plugin, removes the scratch folder, exits 2. On Linux the plugin and the introspect child are started with `Pdeathsig=SIGKILL` | `TestInterruptedKitEndsThePluginAndCleansUp` (SIGINT, SIGTERM, SIGKILL against the built command) |
| `/term` and the page path of every plugin are without authentication on loopback; nothing said so | Written down: `contract.md` section 4, `conformance.md` section 4, known limits above. No code: a token there is a new contract version | |
| The kit handed its whole environment to the plugin it certifies | The plugin gets `PATH`, `HOME` and `TMPDIR` in the scratch folder, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ` and the `-no-egress` variables; new option `-env NAME[=VALUE]` for more | `TestPluginDoesNotGetTheEnvironmentOfTheKit` |
| The leftover check only looked at the process group: a child that called `setsid` was reported as "nothing left" and kept running | Linux: the process tree below the plugin is read about every 200 ms and before each stop step; after the stop, every process seen that still runs, and every process whose program or working directory is in the scratch folder, is reported (`cleanup` WARN, "left its process group") and ended. Also fixed on the way: the memory check missed children that a plugin started from another thread than its first | `TestChildOutsideTheProcessGroupIsFoundAndEnded` (a `setsid` child, and a daemon started by a process that ends at once) |

Behaviour that changed with these fixes: only in the kit and in `fork-ref-ui-api` (both new in this phase). A plugin
that needs a variable of the caller's environment now needs `-env` under the kit. The three installed plugins were
run again with kit 1.1.0 (see `conformance.md` section 5.3).

### How to run

```
cd tools/plugin-check && go build -o plugin-check . && ./plugin-check <plugin folder>/<plugin program>
cd tools/plugin-check && GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test -count=1 .       # kit: reference plugins green, chaos modes red
cd src && GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test -p 1 -count=1 ./mod/plugins/ \
  -run 'TestReferencePlugins|TestFaultReference|TestConformanceKit'
PLUGIN_CHECK_PORTS=20740-20799 tools/build_ref_plugins.sh -o /tmp/ref-plugins -a amd64 -c  # build + kit
E2E_PORT_BASE=20700 tools/e2e/run.sh --only plugin_ --results /tmp/e2e.json                # real Zoraxy
tools/build_release.sh -t <tag> -p                                                         # release plus DIST_DIR/plugins (optional)
```

## Issue #149 gaps (fork.32): proxy rule events, SDK 1.2.0, API key review

### What was built

| Item | Where | What |
|---|---|---|
| Events `proxyRuleAdded`, `proxyRuleEdited`, `proxyRuleRemoved` | `zoraxy_plugin/events/events.go`, `src/config.go` (`SaveReverseProxyConfig`, `RemoveReverseProxyConfig`) | Sent from the one place every stored change of an HTTP proxy rule goes through, so every admin page and API that changes a rule is covered without a call in each handler. Payload: host name, aliases, default site or not, switched off or not, tags |
| SDK 1.2.0 | `zoraxy_plugin/api_client.go`, `CHANGELOG.md` | `ConfigureSpec.DoAPIRequest`, `NewAPIRequest`, `SetAPIAuth`, `APIURL`, `ErrNoAPIKey`, `ErrAPIEndpoint`: the plugin no longer writes the `Authorization: Bearer` header itself. Contract version unchanged (1). SDK 1.1.0 frozen under `testdata/sdk-1.1.0` and added to the compatibility suite |
| Examples | `example/plugins/api-call-example` uses the helpers; `event-subscriber-example` also subscribes to the three new events; all example copies of the SDK are 1.2.0 |
| Conformance kit | `tools/plugin-check` | knows the three event names and sends sample payloads for them (kit version unchanged) |
| API key generation review | `contract.md` section 6 | reviewed, nothing changed |
| Events over UDP | `contract.md` section 4 | will not be done, with the reasons |

### Behaviour that changed for existing installs

None unless a plugin asks: the events are only sent to a plugin whose manifest subscribes to them, and the helpers
only exist in a plugin rebuilt with SDK 1.2.0. With no subscriber, storing a rule costs one extra file existence
check.

### Known limits

- The events follow the stored configuration: a host name change is `proxyRuleRemoved` plus `proxyRuleAdded`;
  `proxyRuleEdited` does not say what changed and is also sent when a save changed nothing.
- No event for rules loaded at start, for configuration restored or synced as files, or for the rewrite of a rule
  by a basic auth hash upgrade. No events for stream proxy or redirection rules.
- The payload has no upstream addresses on purpose; a plugin needs the `GET /plugin/api/proxy/list` permission for
  them.
- A plugin built with SDK 1.1.0 or older can subscribe to the new names (they are strings in the manifest) but its
  `events.ParseEvent` answers "unknown event" for them; it has to read the JSON itself or be rebuilt.
- The helpers call `http://127.0.0.1:<zoraxy_port>` only; `DoAPIRequest` has a fixed 30 s limit and no context.
- Not exercised: the three new events against a real third-party plugin (upstream's CrowdSec bouncer or the
  requester's plugin); only the fork's listener and the example build were used.
- `docs/plugins/html` (the generated site) was not rebuilt.

### Not done from the upstream tracker

- "Expose more endpoints to plugins as needed": no concrete endpoint was asked for.
- "Make the example plugin read from a config file": not built.

### How to run

```
cd src && GOTMPDIR=$HOME/.cache/go-tmp go test -p 1 -count=1 . -run TestProxyRuleEvents
cd src && GOTMPDIR=$HOME/.cache/go-tmp go test -p 1 -count=1 ./mod/eventsystem/ ./mod/auth/ ./mod/plugins/ \
  -run 'TestProxyRuleEvents|TestPluginAPIKey|TestSDK'
```
