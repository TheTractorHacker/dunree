# Plugin reliability plan

Status: **phase 0 and phase 1 are built, with gaps.** Phase 0: see "Phase 0 results and known limits". Phase 1
(supervision, every new behaviour off by default): see "Phase 1 results and known limits" at the end, which also lists
what of phase 1 was **not** built (request budget, slow-call breaker, Prometheus series, lowering a filter timeout) and
what was not tested (root, `-plugin_user` with limits, Windows). Phases 2 and 3 are a plan, nothing of them is built.
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
