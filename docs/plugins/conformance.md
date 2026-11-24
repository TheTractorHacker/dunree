# Plugin conformance kit: method and results

Written 2026-11-23 for the fork (`dev` branch), kit version 1.1.0 (1.0.0 until the review fixes of the same day:
minimal environment, interrupt handling, processes outside the process group; 1.2.0 since fork.32: the kit knows the
events `proxyRuleAdded`, `proxyRuleEdited`, `proxyRuleRemoved` and sends samples of them, the reports below were made
with 1.1.0 and were not run again; 1.3.0 since the Dunree rebrand: the kit sends every header of the host under
both names, `X-Dunree-*` and `X-Zoraxy-*`, adds the `dunree_*` configure fields for a plugin whose manifest says
`sdk_flavor: "dunree"`, and its report says `"tool": "dunree-plugin-check"` where the stored reports say
`zoraxy-plugin-check`), plugin contract version 1
(`docs/plugins/contract.md`, section 10 for the two sets of names). This is item 3.2 and 3.3 of `docs/plugins/reliability-plan.md`.

The kit answers one question about one plugin binary: **does it keep the plugin contract, and does it behave in the
ways that make a plugin safe to run next to a proxy?** It starts the binary the way Dunree does, without Dunree, and
reports per check `PASS`, `WARN`, `FAIL` or `SKIP`. The result is `FAIL` when at least one check failed; warnings do
not fail a plugin.

It is a black-box test. A pass means the plugin behaved during a run of a few seconds with sample requests. It does
not mean the plugin is free of bugs, that it is honest, or that it does something useful (see "What the kit cannot
tell").

## 1. How to run it

```
cd tools/plugin-check && go build -o plugin-check .      # standard library only, no network
./plugin-check <plugin binary>                           # text report
./plugin-check -json <plugin binary>                     # JSON report on standard output
./plugin-check -out report.json <plugin binary>          # text report, and the JSON report in a file
```

Exit code: `0` no check failed, `1` at least one check failed, `2` the kit could not run (wrong arguments, not a
file) or was interrupted (Ctrl-C, SIGTERM, SIGHUP: it ends the plugin, removes the scratch folder and prints no
report). `<plugin binary>` is the program Dunree starts: `<plugin folder>/<folder name>`.

| Option | Default | Meaning |
|---|---|---|
| `-ports first-last` | any free port | loopback ports the kit may use (plugin, stand-in API) |
| `-with-folder` | off | copy the whole plugin folder to the scratch folder, not only the program. Needed for plugins that keep files next to the program (and for a `start.sh`). The plugin then runs with its own settings |
| `-no-egress` | off | set `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` of the plugin to a dead loopback address, so a plugin that honours them (Go's default HTTP client does) cannot call out |
| `-introspect-timeout` | 10s | limit of the introspect call (Dunree: 10 s) |
| `-ready-timeout` | 10s | time the plugin has to open its port |
| `-min-run` | 3s | the plugin has to stay up at least this long |
| `-calls` | 1000 | calls made before the memory is compared |
| `-load-calls`, `-concurrency` | 300, 4 | the latency check |
| `-events` | 100 | events sent in a row |
| `-max-latency`, `-warn-latency` | 250ms, 25ms | limits of the latency check (95 of 100 calls) |
| `-mem-cap-mb`, `-mem-growth-mb` | 1024, 64 | the plugin is ended above the cap; growth over the calls that fails |
| `-env NAME=VALUE`, `-env NAME` | none | add one variable to the environment of the plugin; `NAME` alone passes on the value the kit has. May be given more than once. See section 2 |
| `-keep` | off | keep the scratch folder |

A run of a well-behaved plugin takes about 4 seconds; a plugin that hangs takes up to about 25 seconds.

## 2. What a run does to the machine

- The program file is **copied to a scratch folder** (`$TMPDIR/plugin-check-*/<folder>/`) and run there. The folder
  of the plugin is not the working directory and is not written to. Settings, logs and databases a plugin keeps
  next to its program are neither read nor changed, unless you pass `-with-folder` (then they are copied, and the
  copy is used). The scratch folder is removed afterwards.
- The plugin runs **as the user who runs the kit**, in a process group of its own, on a loopback port. Do not run
  the kit as root.
- The plugin **does not get the environment of the kit.** A shell often holds tokens and cloud credentials, and the
  plugin is somebody else's program. It gets `PATH`, a `HOME` and a `TMPDIR` inside the scratch folder, `LANG`,
  `LC_ALL`, `LC_CTYPE`, `TZ`, the proxy variables of `-no-egress`, and what you name with `-env`. (Dunree itself
  hands its whole environment to a plugin; a plugin that needs a variable from it needs `-env` here.) The files of
  your real home are still readable by path: see "cannot confine" below.
- **An interrupted kit ends the plugin.** On Ctrl-C, SIGTERM or SIGHUP the kit kills the process group of the
  plugin and every process it saw below the plugin, removes the scratch folder and exits with 2. On Linux the
  kernel also ends the plugin process when the kit itself is killed (SIGKILL, crash); the scratch folder then
  stays, and a child the plugin started stays too.
- The plugin **never talks to a real Dunree**. A plugin that asks for Dunree API endpoints gets the port of a
  stand-in that records every call and answers with an empty list or `"OK"`. The key it gets opens nothing real.
- The kit **cannot confine the plugin**. A plugin can still open files by absolute path and connect to the network.
  `-no-egress` only works for plugins that honour the proxy variables. Run a plugin you do not trust at all inside
  a container or a virtual machine.
- A plugin that uses more memory than `-mem-cap-mb` is ended by the kit.

## 3. The checks

"Dunree" in this table means the code in `src/mod/plugins`; the limits are the ones Dunree applies unless the row says
"limit of the kit".

| Check | What the kit does | FAIL | WARN |
|---|---|---|---|
| `introspect` | runs the program with `-introspect` | no JSON manifest, non-zero exit, no answer within 10 s, more than 1 MiB (limit of the kit) | slower than 2 s; output on standard error |
| `introspect_size` | size of that output | more than 1 MiB | more than 64 KiB (both limits of the kit; Dunree has none) |
| `manifest` | the fields, with the rules of the loader | `id`, `name`, `author`, `description` or `ui_path` empty; hooks without a filter path; events without a subscription path | anything Dunree drops, clamps or ignores (unknown stage, timeout over 10 s, invalid `health_path`, unknown `configure_via`, `api_version` that is not a number or newer than 1), endpoints without a reason, half a dynamic capture, an odd `id` |
| `configure` | starts the plugin with the configure payload (`-configure=<json>`, or `-configure-stdin` when declared), as Dunree builds it | the process ends before it opens its port | |
| `secrets` | how the configuration is handed over | | on the command line (readable by every local user); a plugin has to declare `configure_via: "stdin"` to pass |
| `readiness` | waits for the port to accept a connection | not within `-ready-timeout` | later than 5 s |
| `bind` | connects to the port on another IPv4 address of the machine | it answers there: the plugin listens on more than `127.0.0.1` | |
| `ui` | `GET <ui_path>/` | no answer within 2 s | status 500 or above |
| `health` | `GET <health_path>` (skipped when not declared) | no answer within 2 s, or a status outside 200 to 299 | |
| `verdict` | filter calls for every declared stage: a plain GET, a scanner, a POST with a body, a very long request; then three calls Dunree never makes (not JSON, empty, unknown stage) and one more normal call | an answer Dunree would refuse: not within the timeout the plugin declared, not HTTP 200, larger than 256 KiB, not JSON, or a verdict that breaks the verdict rules; no answer to a malformed call; the process ends | `capture` at `pre_auth`, or without a capture ingress |
| `sniff` | three sniff calls (and, when the plugin takes one, a request to its capture ingress), one malformed call | no answer within the timeout, an answer over 4096 bytes, an ingress that does not answer within 5 s | |
| `events` | one event per subscribed name, then `-events` more, one at a time as Dunree sends them | no answer within 10 s, or a status other than 200 | mean above 100 ms or one event above 1 s |
| `token` | calls the filter, sniff and event path without the invoke token and with a wrong one | the plugin answers as it answers Dunree, **and declares contract version 1** | the same for a legacy plugin; or it cannot be told (a sniff that does not take the sample request answers the same either way) |
| `load` | `-load-calls` filter calls (or sniff calls), `-concurrency` at a time | a failed call; the slowest hundredth reaches the timeout; 95 of 100 calls are not faster than `-max-latency` (limit of the kit) | 95 of 100 calls are not faster than `-warn-latency` |
| `memory` | resident memory of the process and its children before the load and after `-calls` calls (Linux) | grew by more than `-mem-growth-mb`; or passed `-mem-cap-mb` at any time (the kit ends it) | grew by more than a quarter of that |
| `api` | what the plugin called on the stand-in for the Dunree API | a call without its API key, or to an endpoint that is not in `permitted_api_endpoints` | |
| `survive` | the process is still there after `-min-run` | it ended by itself | |
| `term` | `GET <ui_path>/term`, waits 2 s | | no answer; or answered and still running (404 "not supported" passes) |
| `sigterm` | `SIGTERM` to the process group. When the plugin already ended on the terminate request it is **started a second time** for this | still running after 5 s; or the second start does not open its port | |
| `cleanup` | looks for processes left in the process group and, on Linux, for processes that left it: every process seen below the plugin during the run (the process tree is read about every 200 ms and before each stop step), and every process whose program or working directory is in the scratch folder. What is found is ended | | some are left; the text says whether inside or outside the group (Dunree ends the group only, so a process outside it survives a stop) |
| `logs` | everything written to standard output and standard error during the run | a line over 64 KiB; more than 1 MiB; more than 200 + 2 lines per call | more than 50 + one line per 10 calls |

Checks that do not apply to a plugin (no hooks, no events, ...) are `SKIP` with the reason. When a plugin stops
answering, the remaining checks that would call it are `SKIP` ("Not run: ...") and the stop checks still run.

The JSON report has one object per check (`id`, `title`, `status`, `detail`, `ms`, `data` with the numbers), the
manifest head, the SHA-256 and size of the program file, and the last lines the plugin wrote.

**Why contract version 1 is held to more.** A legacy plugin (no `api_version`) was written before the invoke token
existed; failing it for not checking the token would fail every plugin in the field. A plugin that declares
contract version 1 was built with the SDK that has `RequireInvokeToken`.

## 4. What the kit cannot tell

- **Whether the plugin is honest or correct.** A plugin that passes can still filter wrongly, leak data or call
  home. The kit sees answers, not intent.
- **Behaviour with real settings and real data.** By default the plugin runs without its settings (scratch
  folder). A blocklist plugin is measured with whatever list it has at that moment, which may be none.
- **Behaviour over time.** The run is seconds. A leak of 1 MiB per hour, a crash after a day, a slow start when a
  list has grown: not seen.
- **Static capture.** The kit does not know which requests a static capture path is meant for and does not call it.
- **The page of the plugin beyond "it answers".** No browser, no buttons. A plugin that only calls the Dunree API
  when a button is pressed shows no API call.
- **Whether a sniff path checks the token** when the plugin does not take the sample request (see `token`).
- **The verdict rules are a copy.** The kit does not import Dunree. A fixture list of 64 verdicts
  (`tools/plugin-check/testdata/verdicts.json`) is checked against both (`TestVerdictFixtures` in the kit,
  `TestConformanceKitVerdictRulesMatchDunree` in `src/mod/plugins`); a rule that is in neither list can drift.
- **Latency numbers are from one shared machine**, with the kit and the plugin competing for the same cores. They
  say "milliseconds, not seconds", not more.
- **Linux and other Unix only.** No Windows. Memory is read on Linux only. `bind` needs a second IPv4 address.
- **Limits of resources Dunree can set** (memory, CPU, tasks through `systemd-run`) are not applied by the kit.
- **A process that hides well.** The search for left processes is not a cgroup. A helper that was started and cut
  loose from the plugin (double fork) between two looks at the process tree, and that also runs another program
  from another working directory, is not found and not ended. On other Unix systems than Linux only the process
  group is looked at. For a plugin you do not trust at all: a container or a virtual machine.
- **Who may call the page path and `/term`.** Both are without authentication on the plugin port (contract
  section 4): any local process can stop any plugin with `GET <ui_path>/term`, and can ask for whatever its page
  can ask for. The kit calls `/term` as Dunree does and cannot see what the page paths of a plugin do; it prints no
  warning about either, because it is true for every plugin.

## 5. Results

All runs: 2026-11-23, kit 1.0.0, a shared 4-core machine, as an unprivileged user, ports 20740 to 20799.

**Run again with kit 1.1.0** (after the review fixes: the plugin no longer gets the environment of the kit, and
processes outside the process group are looked for): the three reference plugins and the three installed plugins of
5.3 gave the same result per check and the same counts (reference plugins 18 / 17 / 16 passed without a warning;
Data-Shield 15 passed and 2 warnings, Resource Monitor 13 and 1, Cloudflare WAF 15 and 2; `cleanup` passed for all
six, nothing was left inside or outside a process group). The numbers quoted below and the report files in
`docs/plugins/conformance-reports/` are those of the first run with kit 1.0.0; the second run was not stored.

### 5.1 Reference plugins of the fork

Built from `example/plugins/fork-ref-*` with SDK 1.1.0. Default options.

| Plugin | Result | Passed | Warnings | Not applicable | Numbers |
|---|---|---|---|---|---|
| `fork-ref-filter` 1.0.0 | **PASS** | 18 | 0 | 3 (sniff, events, api) | 300 filter calls, 4 at a time: p50 0.5 ms, p95 3.2 ms, p99 5.4 ms; 11.1 MiB after 1000 calls (6.9 before); 4 log lines |
| `fork-ref-events` 1.0.0 | **PASS** | 17 | 0 | 4 (verdict, sniff, load, api) | 103 events, mean 0.19 ms; 9.4 MiB after 1000 calls; 4 log lines |
| `fork-ref-ui-api` 1.0.0 | **PASS** | 16 | 0 | 5 (verdict, sniff, events, token, load) | 1 API call (the read at start), with its key, to a declared endpoint; 12.3 MiB after 1000 calls |

Held by `TestReferencePluginsPass` (pass, no warning, and the checks about what each plugin does were run, not
skipped) and by `tools/build_ref_plugins.sh -c`.

### 5.2 The chaos plugin: the kit fails what it should fail

The fault-injection plugin of the fault suite (`src/mod/plugins/testdata/chaosplugin`), one run per mode
(`TestChaosPluginFailsInEveryBadMode`, `TestChaosPluginThatBehavesPasses`).

| Mode | Result | Check that fails |
|---|---|---|
| `ok` (hooks, static, dynamic, events, health) | PASS, 2 warnings (`token`, `secrets`: it is a legacy plugin without a token check) | |
| `slow_start`, 400 ms | PASS | |
| `crash` at start | FAIL | `configure` |
| `crash` after 600 ms | FAIL | `survive` |
| `exit0` at start | FAIL | `configure` |
| `exit0` after 600 ms | FAIL | `survive` |
| `hang_start` (never opens its port) | FAIL | `readiness` |
| `never_ready` (port open, accepts nothing) | FAIL | `ui` |
| `hang` (accepts, never answers) | FAIL | `ui` |
| `slow` (500 ms, its own timeout is 300 ms) | FAIL | `verdict` |
| `slow` (60 ms, with `-max-latency 30ms`) | FAIL | `load` |
| `badjson` | FAIL | `verdict` |
| `huge` (1 MiB answer) | FAIL | `verdict` |
| `badheader` | FAIL | `verdict` |
| `logflood` | FAIL | `logs` |
| `unhealthy` | FAIL | `health` |
| `balloon` | FAIL | `memory` (ended by the kit at the cap) |
| `ignore_sigterm` | FAIL | `sigterm` |
| `introspect_garbage` | FAIL | `introspect` |
| `introspect_hang` | FAIL | `introspect` |
| `ok` with `api_version=1` (no token check) | FAIL | `token` |

Also tested: a plugin that listens on every address fails `bind` (`TestPluginThatListensOnEveryAddressFails`); a
call without the key and a call to an endpoint outside the manifest fail `api`
(`TestStubAPIRecordsWhatIsNotAllowed`).

### 5.3 The three plugins installed on this machine

Found under `~/plugins` on the build machine (the same three binaries the golden manifests of phase 2 were taken
from). **These are the versions installed here, not the newest ones** (the public index lists Data-Shield 1.4.0 and
Cloudflare WAF 0.4.0), and **the plugins on the other proxy were not looked at.**

How they were run: `plugin-check -ports 20740-20799 -no-egress -out <report> <binary>`, as the unprivileged build
user. Only the program file was copied to the scratch folder: **none of their settings were read** (the settings
file of the Cloudflare plugin is readable by root only and was not touched), so each ran with its built-in
defaults. They were not started through Dunree and never talked to the Dunree on this machine. The full reports are
in `docs/plugins/conformance-reports/`.

| Plugin | SHA-256 of the binary (first 12) | Result | Passed | Warnings | Not applicable |
|---|---|---|---|---|---|
| Data-Shield Blocklist 1.3.0 (`fr.madyanne.zoraxy.datashield-blocklist`), router, legacy | `8d54237d6b10` | **PASS** | 15 | 2 | 4 |
| Resource Monitor 1.0.3 (`zoraxyresourcemonitor`), utility, legacy | `c355b6c0e062` | **PASS** | 13 | 1 | 7 |
| Zoraxy Cloudflare WAF plugin 0.3.4 (`com.braedach.zoraxy.cloudflarewaf`), utility, legacy | `82427c2cde62` | **PASS** | 15 | 2 | 4 |

No check failed for any of them. What the warnings and the numbers say:

**Data-Shield Blocklist 1.3.0**
- `secrets` WARN: the invoke token is on the command line (true for every legacy plugin).
- `token` WARN, **could not be told**: its sniff path answered HTTP 501 ("not for me") to the sample request with
  the token, without it and with a wrong one. Whether it checks the token cannot be seen from outside.
- `sniff` PASS: three answers of HTTP 501, each within its timeout (2 s, the default). `load` PASS: 300 sniff
  calls, 4 at a time, p50 0.35 ms, p95 1.0 ms, p99 1.8 ms. `memory` PASS: 12.5 MiB after 1000 calls (8.6 before).
- **Read these numbers with care:** with `-no-egress` its first download of the blocklist failed (its own log line:
  `initial blocklist load failed`), so latency and memory were measured **with an empty list**. It kept running
  and kept answering without the list, which is the right behaviour, but the cost of a lookup in a full list was
  not measured.
- It ends on the terminate request (104 ms) and on SIGTERM, starts a second time, logs 5 lines.

**Resource Monitor 1.0.3**
- `secrets` WARN, as above. Nothing else: it has no filter, no sniff, no events and no API permissions, so 7
  checks do not apply. Its page answered 1000 requests; 11.4 MiB afterwards (6.6 before). Ends on the terminate
  request and on SIGTERM. 3 log lines.

**Zoraxy Cloudflare WAF plugin 0.3.4**
- `secrets` WARN: **its Dunree API key** (it may add and remove addresses on your blacklists) and the invoke token
  are on the command line, readable by every local user on the proxy. Only the author can change that
  (`configure_via: "stdin"`, SDK 1.1.0).
- `token` WARN: **it accepts events from anyone.** A `blacklistedIpBlocked` event without the invoke token, and
  one with a wrong token, were answered with 200 like the ones "from Dunree". Any local process on the proxy can
  feed it invented "blocked" addresses. What it then does with them depends on its settings; in this run it was
  disabled by its defaults and logged `action: skipped-disabled` for each.
- `events` PASS: 101 events acknowledged, mean 0.37 ms, slowest 1.6 ms. It acknowledges fast.
- `logs` PASS, but worth knowing: 113 lines during the run, **one line per event**. During an attack from
  blacklisted addresses that is one log line per blocked request (the per-plugin log limits of phase 1 apply).
- `api` PASS without evidence: it asks for 4 endpoints and called none during the run, because it was disabled by
  its defaults. Its use of the API was **not exercised**.
- It tried to read `/srv/zoraxy/log/zr_2026-11.log` (its default log folder; the file does not exist on this
  machine, so nothing was read). This is the "cannot confine" limit of section 2: a plugin can open files by
  absolute path.
- Ends on the terminate request (104 ms) and on SIGTERM, starts a second time.

**What this certifies, and what it does not.** The three binaries installed here keep the mechanical part of the
contract: valid manifest, start, port on loopback only, stop within the limits, no log flood, no memory growth
over 1000 calls, and the two that are called per event or per request answer in about a millisecond. It does not
certify their behaviour with your settings, with real traffic, over days, or the newer versions. The two findings
to pass on to the authors are the unauthenticated event path of the Cloudflare plugin and the configuration on the
command line of all three. **No issue was opened upstream and no "conformance passed" flag was added to an index**
(there is no fork index yet; both need the owner).

## 6. Reproduce

```
cd tools/plugin-check
GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test -count=1 .          # reference plugins pass, chaos modes fail (about 60 s)
cd ../../src && GOTMPDIR=$HOME/.cache/go-tmp ~/capped.sh go test -p 1 -count=1 ./mod/plugins/ \
  -run 'TestReferencePlugins|TestFaultReference|TestConformanceKit'   # reference plugins through the real plugin manager
cd .. && PLUGIN_CHECK_PORTS=20740-20799 tools/build_ref_plugins.sh -o /tmp/ref -a amd64 -c
E2E_PORT_BASE=20700 tools/e2e/run.sh --only plugin_ --results /tmp/e2e.json   # real Dunree, real plugin processes
plugin-check -ports 20740-20799 -no-egress -out report.json "$HOME/plugins/Resource Monitor/Resource Monitor"
```

The tests use the ports of `PLUGIN_CHECK_TEST_PORTS` (default `20740-20799`) and start one plugin at a time.
