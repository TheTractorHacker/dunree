# CrowdSec with Dunree

Answers upstream #648 ("does CrowdSec need live logs?"). Log format and the ban API were checked on a throw-away
instance; the CrowdSec configuration itself was **not** run (no CrowdSec here), treat the YAML as a starting point.

## Reading the logs (detection)

* Dunree appends every proxied request to `log/zr_<year>-<month>.log` as it happens (month without a leading zero, e.g. `zr_2026-9.log`; one file per month, older months
  stay in the folder). That *is* the live log: point CrowdSec at it with a glob so it follows the monthly rotation:

  ```yaml
  # /etc/crowdsec/acquis.d/dunree.yaml
  filenames:
    - /path/to/your-dunree-log-folder/zr_*.log   # default: ./log next to the program
  labels:
    type: dunree
  ```
  (`sudo mkdir -p /etc/crowdsec/acquis.d` first if it does not exist. In Docker mount the log folder read-only into the container and use the in-container path in the file.)
* Line format (verified on 19,000 lines; all matched the pattern below):

  ```
  [2026-11-08 19:28:10.569106] [router:host-http] [origin:odoo.test:18443] [client: 203.0.113.5] [useragent: curl/8.18.0] GET /foo 404
  ```
  `client` is the visitor address resolved with the rule's trusted proxy policy (see
  [real-client-ip-cloudflare.md](real-client-ip-cloudflare.md)); behind Cloudflare enable *Trusted Proxy Gating* or
  CrowdSec will see Cloudflare addresses. A Grok/regex parser for it:

  ```
  ^\[(?P<ts>[^\]]+)\] \[router:(?P<router>[^\]]+)\] \[origin:(?P<host>[^\]]*)\] \[client: (?P<ip>[^\]]+)\] \[useragent: (?P<ua>[^\]]*)\] (?P<method>[A-Z]+) (?P<uri>\S+) (?P<status>\d{3})$
  ```
  With the optional **Write the ECH result to the request log** box (Network > Encrypted Client Hello, off by default) HTTPS
  lines carry one more field after the user agent, `[ech: accepted outer=ech.example.com]`. Leave the box off, or add
  `(?: \[ech: (?P<ech>[^\]]*)\])?` after the `useragent` group of the pattern.
  A community collection for Dunree was proposed to the CrowdSec hub (see upstream discussion #338); check the hub
  before writing your own.
* Alternative: per-site log files in **JSON lines** (`time, class, site, origin, upstream, client, useragent, method,
  uri, status`), configured in the logging settings; easier to parse with CrowdSec's JSON helpers (not tested here).
  They default to *off*.

## Setting CrowdSec up (the "Set up CrowdSec" panel)

Dunree only *talks to* CrowdSec; it never installs it or runs a package manager (that would need root and is a supply-chain risk).
Security Center > CrowdSec has a collapsible **Set up CrowdSec** panel (open until a LAPI address is saved) with copy buttons for the steps:

1. Install CrowdSec on a server. Debian/Ubuntu: `curl -s https://install.crowdsec.net | sudo sh` then `sudo apt install crowdsec`. Docker: the compose
   example (image `crowdsecurity/crowdsec`, port published on `127.0.0.1:8080`, data and config volumes, `./crowdsec/acquis.yaml` mounted at `/etc/crowdsec/acquis.yaml`, Dunree's log folder mounted read-only at `/var/log/dunree`).
2. Create a key on that server: `sudo cscli bouncers add dunree-$(hostname)`. One key per Dunree instance. For Docker, run cscli inside the container
   (the Docker docs page does not show that exact command, so the panel does not either).
3. Paste address and key in the form, **Test connection**, save, stay in Log only until the matches look right. The address must be reachable from Dunree (firewall, published port).
4. Detection (optional): CrowdSec has **no built-in parser for the log type `dunree`**, so without your own parser (above) or a hub collection the lines are
   read but not understood. The community blocklist works in Dunree without this step. Package install: `sudo mkdir -p /etc/crowdsec/acquis.d`, then
   `/etc/crowdsec/acquis.d/dunree.yaml` with `filenames: [<full path of your Dunree log folder>/zr_*.log]`, `labels: {type: dunree}`, then
   `sudo crowdsec -t && sudo systemctl restart crowdsec`. Docker: mount your log folder read-only at `/var/log/dunree` and the file `./crowdsec/acquis.yaml` at
   `/etc/crowdsec/acquis.yaml` (the Docker docs' compose example); inside that file use the in-container path `/var/log/dunree/zr_*.log`.

### Setup files shipped with every release

Each release carries three extra assets (signed in `SHA256SUMS` like the binaries; the in-app updater ignores them):
`crowdsec-setup.sh` (Debian/Ubuntu helper: downloads the official repository installer to a temp file, shows its sha256 and asks before running it,
`apt install crowdsec`, optional acquis file with `--log-dir`, creates the key `dunree-<hostname>` only if that name is not registered, prints the address
and key once; `--dry-run` changes nothing and needs no root; it never calls sudo and stores no secret), `crowdsec-docker-compose.yml` (the compose file of the panel)
and `CROWDSEC-README.md`. Sources are in `contrib/crowdsec/`. Dunree itself still installs nothing. They were checked with `bash -n` and `--dry-run` only, not against a real CrowdSec install.

Official sources used: <https://docs.crowdsec.net/u/getting_started/installation/linux>, <https://docs.crowdsec.net/u/getting_started/installation/docker>,
<https://docs.crowdsec.net/docs/local_api/bouncers>, <https://docs.crowdsec.net/u/getting_started/post_installation/acquisition_new>,
<https://docs.crowdsec.net/docs/log_processor/data_sources/intro>.

Left out on purpose: a "Detect local CrowdSec" button (no unauthenticated health/version path of the Local API is documented, so there is nothing safe to call without a key),
`systemctl enable`, a docker-exec form of `cscli`, and the default Local API port as a claim (the docs' examples use 8080 and the Docker docs list a default listen address of `0.0.0.0:8080`).
The commands were taken from the documentation and were **not run** here.

## Built-in bouncer (Security Center > CrowdSec)

Dunree can act as a CrowdSec remediation component itself: it keeps your CrowdSec Local API (LAPI) ban decisions in memory
and refuses matching visitors. It is off until you enable it, and starts in **Log only** mode.

1. On the CrowdSec host: `cscli bouncers add dunree` and keep the key. The LAPI must be reachable from Dunree
   (default `http://127.0.0.1:8080`; use https when it is not on the same machine).
2. Security Center > CrowdSec: enter the LAPI address and the key, **Test connection** (one authenticated
   `GET /v1/decisions?ip=` call), switch it on, and press **Save changes** on the bar that appears at the bottom.
3. Watch **Matched requests** in log only mode (see "Seeing it in action" below), then switch the mode to **Enforce**.

How it works (CrowdSec documentation: <https://docs.crowdsec.net/docs/local_api/bouncers>):
* The key is sent in the `X-Api-Key` header. The first call is `GET /v1/decisions/stream?startup=true` (full state), then
  `GET /v1/decisions/stream` every 10 s (configurable, 5 to 3600) returns the `new` and `deleted` changes. After any error the next call is a
  full `startup=true` one, with exponential backoff (2 s up to 2 min). The cache is replaced only after a full answer was read.
* Decisions: scope `Ip` and `Range` (IPv4 and IPv6); other scopes (Country, AS ...) are counted and ignored. Type `ban` is enforced, `captcha`
  can show the site's CAPTCHA (default: only logged), every other type (throttle ...) is counted and not enforced.
  A decision expires at its `duration`, never later than the "longest decision lifetime" setting (default 7 days). The cache has a hard
  limit (default 100,000 decisions, at most 500,000); decisions beyond it are refused and the card warns.
* The visitor address is the one Dunree already trusts for rate limits and access rules (trusted proxy aware), so a forged
  `X-Forwarded-For` from an untrusted client changes nothing. This server, loopback and your trusted proxies are never refused.
* Log only: matches are logged and counted, nothing is blocked. Enforce: a banned visitor gets the 403 page (or, by setting, no answer) and the block appears in
  the blocked-request log with the reason "CrowdSec" ("Why was this blocked?" works).
* LAPI unreachable for longer than the grace period (default 5 min): **fail open** by default (traffic allowed, cached decisions still apply, the card
  turns red and a line is logged). **Fail closed** (enforce mode only, confirmation required) refuses every visitor instead.
* A site can be exempted, kept on log only or enforced on its own (see "More configuration"). An https LAPI is verified with the system roots, or with the CA bundle / key pin you paste
  (there is no skip-verify option). Redirects are not followed and the destination must not be a cloud metadata or link-local address.
* The key is stored encrypted in `conf/crowdsec/`, is never returned by an API, is left out of configuration exports and out of the security audit log.
* **Two proxies:** let both Dunree instances query the same LAPI, but create **one bouncer key per instance** (`cscli bouncers add dunree-front`,
  `cscli bouncers add dunree-back`). To my recollection (not confirmed against a CrowdSec build) the LAPI tracks what it already sent per bouncer key,
  so two instances sharing a key would each receive only part of the changes. There is no replication between the instances.
* **Long bans:** a decision longer than the "longest decision lifetime" is stored cut to it, and the LAPI sends a decision only once. So that a
  30 day ban does not lapse locally, Dunree repeats a full synchronisation at half the lifetime as long as such decisions exist (the status card
  shows how many were cut).
* **Forwarded headers:** behind a trusted proxy (Cloudflare, the front proxy) the client can send any `X-Real-Ip` / `X-Forwarded-For`; the proxy
  does not remove it. Dunree therefore looks up every address the request claims, and loopback or this server's address in a header is not an
  exemption. Only the real connection address of a peer is exempt when it is loopback, this server or a trusted proxy.
* **The key stays with its address:** the stored key is bound to the scheme, host and port it was entered for. Changing the LAPI address (or testing
  another one) requires typing the key again, so the stored key cannot be sent to another host.
* **Restart:** the decision cache is memory only. After a restart, or when the LAPI is down at boot, nothing is enforced until the first successful
  synchronisation (and with fail-closed on, everything is refused after the grace period instead). Keep the grace period short for enforce mode.
* **Full cache:** decisions of community lists (origin CAPI, lists) make room for local ones (cscli, scenarios); a cache full of local decisions refuses new ones.
* A CAPTCHA decision is satisfied by any valid CAPTCHA session of the site (shared with country challenges) and by the site's CAPTCHA exceptions.
  Treat it as advisory. Decisions of type `allow` are not honoured.
* Not done: reporting alerts back to CrowdSec (use the log acquisition above for detection), TLS client-certificate authentication to the LAPI,
  the optional origin and type stream filters (only `scopes=Ip,Range` is sent). Not tested against a real CrowdSec, only against a fake LAPI that follows the documentation.

## Seeing it in action (Security Center > CrowdSec, while it is switched on)

Everything in this part is read-only and always on while CrowdSec is enabled. It answers "what is it doing?" without a terminal.

* **Status header** in plain words: "Blocking banned addresses: 1,204 decisions loaded, synced 8 s ago, 37 requests blocked today out of 12,430 checked",
  "Watching only: nobody is blocked ... 12 requests would have been blocked today", or "Cannot reach the CrowdSec server for 6 min, failing open".
  Five counters: decisions loaded, last sync, blocked today, would block today, requests checked today ("today" is the server's local day).
* **Activity**: matched requests per hour (24 hours) or per 6 hours (7 days), stacked by blocked / CAPTCHA shown / would block, and below it, on its
  own axis, all requests that were looked up. Point at a bar for the numbers; "Show the numbers as a table" gives the same as text. Four top lists
  for the period: scenarios, sources (origins), visitor countries and sites, each split into stopped and only logged.
* **Matched requests** (the live feed): every visitor whose address had a decision, newest first, with the site, method and path (never the query
  string), country, scenario, source, the decision and its expiry, and **what Dunree really did**: Blocked, Blocked (connection closed), CAPTCHA shown,
  Served (CAPTCHA already solved), Served (site has no CAPTCHA), Would block (with the reason: mode, site, source or scenario on Log only), Served
  (allowlisted), Served (site exempt), Refused (fail closed). In **log only mode this is the list of what would have been blocked**, so you can judge
  it before enforcing. Repeats of one visitor on one site with the same outcome are one entry with a count. Filters: outcome, address, text.
  It refreshes every 5 seconds while the page is on screen (the **Live** button pauses it) and stops while the browser tab is in the background.
* **Check an address**: type an address, optionally choose a site, and read what would happen and why: every loaded decision that applies (exact
  address and every containing range), which one decides, what your settings make of it (mode, site rule, source policy, allowlist), and the last
  matched requests of that address. "Also ask the CrowdSec server" adds one live `GET /v1/decisions?ip=` call (at most 30 a minute) and says when
  Dunree and the server disagree. With a machine login the alerts CrowdSec holds for the address are listed too. Nothing is changed or counted.
  Clicking an address in the list fills this card.
* **What is loaded**: how many decisions come from each source (your own scenarios, by hand, community blocklist, subscribed lists, other), bans vs
  captcha, addresses vs ranges, the most common scenarios, what was not used (other scopes and types), and the newest decisions received.
* **Connection health**: the last 60 pulls (full or changes only, duration, added, removed, error) and the last 50 state changes.

Counting fix that came with this: a `captcha` decision used to be counted and listed as "blocked" whenever captcha decisions were set to show the
site CAPTCHA, even when the request was served (site without CAPTCHA, CAPTCHA already solved, path or visitor not covered). The request path now
reports the real outcome, so "Blocked today" and the list only count requests that were really stopped.

## More configuration (all optional; an empty setting is the behaviour of earlier versions)

* **Which decisions to act on** (per source): each of *your own CrowdSec scenarios* (origin `crowdsec`), *bans added by hand* (`cscli`,
  `cscli-import`), *community blocklist* (`CAPI`), *blocklists you subscribed to* (`lists:<name>`) and *anything else* can **follow the mode**
  (default), be kept on **Log only** (never enforced, listed as "would block") or be **ignored** (not acted on, not listed, only counted). Typical
  use: enforce your own scenarios and manual bans while you watch what the community list would do. Each row shows how many decisions of that
  source are loaded. The choice is applied when a request is checked, so a change needs no new synchronisation.
* **Rules for single sites** (replaces the typed "exempt sites" list; old entries are shown as *Exempt* and keep working): pick a proxy rule and
  choose *Exempt* (never act on CrowdSec there), *Log only*, or *Enforce*. *Enforce* on one site while the mode is Log only is the way to try
  blocking on one site first; the header then says "Watching only, enforcing on 1 site".
* **Addresses Dunree never blocks** (allowlist, up to 256 addresses or ranges, `/0` refused): served whatever CrowdSec says and listed as
  "allowlisted". It only applies to this Dunree; `cscli allowlists` on the CrowdSec server covers every bouncer.
* **Scenarios kept on Log only** (up to 64 texts, at least 3 characters): a decision whose scenario name contains the text is never enforced.
  "Contains" reaches far for a short text (`http` covers most web scenarios), so the list under the field shows, for each entry and while
  decisions are loaded, how many loaded decisions and which scenarios it matches, and marks an entry that covers half or more of them.
* **Captcha decisions on a site without CAPTCHA**: only logged (default) or treated as a ban.
* **Notifications**: two events, "CrowdSec server unreachable" (`crowdsec.lapi_down`, critical, after the grace period, at most once in five
  minutes) and "CrowdSec server reachable again" (`crowdsec.lapi_up`). Nothing is sent until you subscribe a channel to them under Notifications.

Rules of precedence: the strongest decision the settings act on wins (enforced before logged, ban before captcha); an allowlisted address is never
acted on; a site rule replaces the mode for that site; source and scenario policies can only make Dunree block **less**. Whatever raises what is
blocked (Enforce, Enforce on a site, a source back to "follow the mode" while enforcing, showing the CAPTCHA, the captcha fallback "ban", fail
closed) asks for confirmation when you save. Behind a trusted proxy every address the request claims is still looked up; an allowlisted address
among them triggers nothing, the others still do. With fail closed on and the server unreachable, a visitor whose match would only be logged is
refused like everyone else (earlier versions served that one case); exempt and log-only sites and allowlisted visitors are not refused.

Known limits of this part:
* Counters, top lists, the feed (500 entries), the pull history and the state changes live in memory only: they start again when Dunree restarts
  and when CrowdSec is switched off. Requests that were really blocked are also in the persisted blocked-request log (Statistics > Blocked).
  Log-only matches are not written there.
* Because of that, after CrowdSec was switched off and on (or Dunree restarted) during the day the three counters are labelled "since 14:20"
  instead of "today", and they can be lower than the "blocked today" number elsewhere in the admin UI, which reads the persisted log.
  The counters are not kept across a switch-off.
* The reach shown for a "scenario kept on Log only" entry is counted on the decisions loaded at that moment (refreshed with the page, at most
  256 distinct scenario names; beyond that it is a lower bound). A scenario that is not loaded right now shows as "matches none" and can
  still match later.
* Before the first successful pull the state in the API stays `starting` until the grace period ends, also when the server refuses the key;
  the page then says "rejects the API key" or "cannot reach the server yet" from the `keyRejected` and `consecutiveErrors` fields.
* Every request whose address has a decision (log-only matches included) takes one process-wide lock for its counters and the feed, after a
  GeoIP lookup. Requests without a decision only pay one atomic add. Memory is bounded, but under a flood of matched traffic (for example a
  large community list in log-only mode during an attack) that lock is shared by all of them; this path has not been load-tested beyond a
  few hundred requests in a row. Enforced blocks are cheap for the upstream anyway; per-hour sharded counters are not done.
* The top lists keep the first 32 distinct values per hour and list; the rest of that hour is summed as "Other".
* The country is looked up only for requests that matched, from the GeoIP database bundled with Dunree; it can differ from what CrowdSec shows.
* "Requests checked" counts requests that reached the lookup: requests from this server, loopback and trusted proxies as direct peers are not in it.
* The live check costs one request to the CrowdSec server each time (30 a minute at most).
* The source policies act on the origin text the server sends (`crowdsec`, `cscli`, `cscli-import`, `CAPI`, `lists:<name>`). These are the
  documented values and were **not verified against a real CrowdSec**: compare them with the "By source" list on your own server (for example
  the output of `cscli decisions list -a`) before you rely on a policy. An origin Dunree does not know is "anything else".
* A site rule is keyed by the host name of the proxy rule. Renaming or deleting the rule leaves the entry behind (marked "no such proxy rule").
* Still not done: usage metrics reported to the LAPI (`cscli metrics show bouncers` stays empty for Dunree), AppSec, Country and AS scopes,
  live mode, throttle decisions, a persisted cache, Prometheus series for these counters, and a control in the site editor itself.
* Tested with Go unit tests, a fake LAPI written from the documentation and a browser run (`tools/ui-smoke/crowdsec_smoke.py`); **not tested
  against a real CrowdSec**.

API (admin session, closed to viewer accounts): `GET /api/crowdsec/activity?window=24h|7d`, `GET /api/crowdsec/feed?outcome=&ip=&q=&limit=&before=`,
`POST /api/crowdsec/check` (`ip`, `site`, `live=true`; read-only, not audited). `/api/crowdsec/status` gained `today`, `checked`, `enforcedSites`,
`policyActive`, `keyRejected`, `countingSince` (null when the counters cover the whole day so far); `loaded.allScenarios` in the activity
answer lists every loaded scenario name with its count (at most 256, then "other"); `/api/crowdsec/get` and `/set` gained `originPolicy`, `scenarioLogOnly`, `allowlist`, `siteOverrides`, `captchaFallback`.

## Managing CrowdSec from Dunree (Security Center > CrowdSec > Manage CrowdSec)

CrowdSec has no local web interface (the old Metabase dashboard was removed in 1.6; the free Console at app.crowdsec.net is the only web UI and runs in the cloud). `cscli` on the CrowdSec host remains the full tool. Dunree adds a small panel for the daily work, so you do not need a terminal for it:

* **Active bans**: everything CrowdSec currently bans (all origins: your scenarios, the community list, manual bans), with a filter and a **Remove ban** button.
* **Ban an address or range**: duration 1 hour to 30 days, optional reason. Recorded in CrowdSec as scenario `dunree/manual-ban` (bans made before the rename carry `zoraxy/manual-ban` and are listed and lifted the same way), origin `cscli`, so every other bouncer you run (firewall, other proxies) enforces it too.
* **Alerts**: what CrowdSec detected and why (scenario, address, country, number of events), filterable by address.

It needs a **machine login**, because the bouncer key can only read decisions. Create it once on the CrowdSec host: `sudo cscli machines add dunree-admin --auto -f -` prints an id and a password once; paste them in the panel. Revoke at any time with `sudo cscli machines delete dunree-admin`.

How the login is handled: tested against the saved LAPI address before it is kept; stored encrypted in `conf/crowdsec/machine.sealed` (same scheme as the bouncer key); never returned by any endpoint, never logged, never part of a configuration export; only ever sent to the LAPI address it was entered for (changing the address asks for it again); closed for viewer accounts. Every ban, unban and login change is written to the security audit log with the actor (the password field is redacted).

Safety limits: loopback, unspecified and multicast addresses cannot be banned; ranges are limited to /16 (IPv4) and /48 (IPv6); the server's own address, a trusted proxy and **the address you are browsing from** cannot be banned; at most 20 changes per minute; every ban and unban asks for confirmation.

Known limits: the panel works on the local API only (no multi-server view; use the Console for that); decisions are listed through the alerts API like `cscli decisions list`, so very old alerts beyond the newest 200 to 500 are not shown; Dunree enforces a new ban after its next pull (default 10 seconds); tested against a stand-in for the documented API and the published OpenAPI specification, **not yet against a real CrowdSec server**.

## Other ways to enforce decisions

CrowdSec's Nginx/Traefik bouncers do not apply. Besides the built-in bouncer above:

1. **Firewall bouncer** (`crowdsec-firewall-bouncer`, iptables/nftables): blocks the IP before Dunree sees it. Works
   when Dunree sees real client addresses (no NAT in front); easiest and cheapest.
2. **Dunree remote ban API** (Security Center > Auto-ban): generate a token in the UI, switch *Auto-ban* on, then a
   custom bouncer or script can push bans:

   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" -d ip=203.0.113.9 -d seconds=3600 -d reason=crowdsec \
        http://dunree:8000/api/abuse/remote/ban
   curl -X POST -H "Authorization: Bearer $TOKEN" -d ip=203.0.113.9 http://dunree:8000/api/abuse/remote/unban
   curl -H "Authorization: Bearer $TOKEN" http://dunree:8000/api/abuse/remote/list
   ```
   *Verified:* ban and list return the ban record. Bans are only enforced while Auto-ban is enabled (the list shows
   `"Active": false` otherwise), loopback/private/trusted-proxy addresses are never banned, and the API listens on the
   management port, so keep that port off the internet. Wiring this to `crowdsec-custom-bouncer` is not tested.

Dunree's own auto-ban (401/403/404/429, WAF, bots, CAPTCHA failures) covers much of what CrowdSec scenarios
detect for HTTP and may be enough on its own.
