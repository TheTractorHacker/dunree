# CrowdSec with Zoraxy

Answers upstream #648 ("does CrowdSec need live logs?"). Log format and the ban API were checked on a throw-away
instance; the CrowdSec configuration itself was **not** run (no CrowdSec here), treat the YAML as a starting point.

## Reading the logs (detection)

* Zoraxy appends every proxied request to `log/zr_<year>-<month>.log` as it happens (month without a leading zero, e.g. `zr_2026-9.log`; one file per month, older months
  stay in the folder). That *is* the live log: point CrowdSec at it with a glob so it follows the monthly rotation:

  ```yaml
  # /etc/crowdsec/acquis.d/zoraxy.yaml
  filenames:
    - /path/to/your-zoraxy-log-folder/zr_*.log   # default: ./log next to the program
  labels:
    type: zoraxy
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
  A community collection for Zoraxy was proposed to the CrowdSec hub (see upstream discussion #338); check the hub
  before writing your own.
* Alternative: per-site log files in **JSON lines** (`time, class, site, origin, upstream, client, useragent, method,
  uri, status`), configured in the logging settings; easier to parse with CrowdSec's JSON helpers (not tested here).
  They default to *off*.

## Setting CrowdSec up (the "Set up CrowdSec" panel)

Zoraxy only *talks to* CrowdSec; it never installs it or runs a package manager (that would need root and is a supply-chain risk).
Security Center > CrowdSec has a collapsible **Set up CrowdSec** panel (open until a LAPI address is saved) with copy buttons for the steps:

1. Install CrowdSec on a server. Debian/Ubuntu: `curl -s https://install.crowdsec.net | sudo sh` then `sudo apt install crowdsec`. Docker: the compose
   example (image `crowdsecurity/crowdsec`, port published on `127.0.0.1:8080`, data and config volumes, `./crowdsec/acquis.yaml` mounted at `/etc/crowdsec/acquis.yaml`, Zoraxy's log folder mounted read-only at `/var/log/zoraxy`).
2. Create a key on that server: `sudo cscli bouncers add zoraxy-$(hostname)`. One key per Zoraxy instance. For Docker, run cscli inside the container
   (the Docker docs page does not show that exact command, so the panel does not either).
3. Paste address and key in the form, **Test connection**, save, stay in Log only until the matches look right. The address must be reachable from Zoraxy (firewall, published port).
4. Detection (optional): CrowdSec has **no built-in parser for the log type `zoraxy`**, so without your own parser (above) or a hub collection the lines are
   read but not understood. The community blocklist works in Zoraxy without this step. Package install: `sudo mkdir -p /etc/crowdsec/acquis.d`, then
   `/etc/crowdsec/acquis.d/zoraxy.yaml` with `filenames: [<full path of your Zoraxy log folder>/zr_*.log]`, `labels: {type: zoraxy}`, then
   `sudo crowdsec -t && sudo systemctl restart crowdsec`. Docker: mount your log folder read-only at `/var/log/zoraxy` and the file `./crowdsec/acquis.yaml` at
   `/etc/crowdsec/acquis.yaml` (the Docker docs' compose example); inside that file use the in-container path `/var/log/zoraxy/zr_*.log`.

### Setup files shipped with every release

Each release carries three extra assets (signed in `SHA256SUMS` like the binaries; the in-app updater ignores them):
`crowdsec-setup.sh` (Debian/Ubuntu helper: downloads the official repository installer to a temp file, shows its sha256 and asks before running it,
`apt install crowdsec`, optional acquis file with `--log-dir`, creates the key `zoraxy-<hostname>` only if that name is not registered, prints the address
and key once; `--dry-run` changes nothing and needs no root; it never calls sudo and stores no secret), `crowdsec-docker-compose.yml` (the compose file of the panel)
and `CROWDSEC-README.md`. Sources are in `contrib/crowdsec/`. Zoraxy itself still installs nothing. They were checked with `bash -n` and `--dry-run` only, not against a real CrowdSec install.

Official sources used: <https://docs.crowdsec.net/u/getting_started/installation/linux>, <https://docs.crowdsec.net/u/getting_started/installation/docker>,
<https://docs.crowdsec.net/docs/local_api/bouncers>, <https://docs.crowdsec.net/u/getting_started/post_installation/acquisition_new>,
<https://docs.crowdsec.net/docs/log_processor/data_sources/intro>.

Left out on purpose: a "Detect local CrowdSec" button (no unauthenticated health/version path of the Local API is documented, so there is nothing safe to call without a key),
`systemctl enable`, a docker-exec form of `cscli`, and the default Local API port as a claim (the docs' examples use 8080 and the Docker docs list a default listen address of `0.0.0.0:8080`).
The commands were taken from the documentation and were **not run** here.

## Built-in bouncer (Security Center > CrowdSec)

Zoraxy can act as a CrowdSec remediation component itself: it keeps your CrowdSec Local API (LAPI) ban decisions in memory
and refuses matching visitors. It is off until you enable it, and starts in **Log only** mode.

1. On the CrowdSec host: `cscli bouncers add zoraxy` and keep the key. The LAPI must be reachable from Zoraxy
   (default `http://127.0.0.1:8080`; use https when it is not on the same machine).
2. Security Center > CrowdSec: enter the LAPI address and the key, **Test connection** (one authenticated
   `GET /v1/decisions?ip=` call), switch it on, save. The status card shows the state (ok / degraded / down), the last successful pull,
   the number of decisions in memory, the LAPI latency and the errors.
3. Watch **Recent matches** in log only mode, then switch the mode to **Enforce**.

How it works (CrowdSec documentation: <https://docs.crowdsec.net/docs/local_api/bouncers>):
* The key is sent in the `X-Api-Key` header. The first call is `GET /v1/decisions/stream?startup=true` (full state), then
  `GET /v1/decisions/stream` every 10 s (configurable, 5 to 3600) returns the `new` and `deleted` changes. After any error the next call is a
  full `startup=true` one, with exponential backoff (2 s up to 2 min). The cache is replaced only after a full answer was read.
* Decisions: scope `Ip` and `Range` (IPv4 and IPv6); other scopes (Country, AS ...) are counted and ignored. Type `ban` is enforced, `captcha`
  can show the site's CAPTCHA (default: only logged), every other type (throttle ...) is counted and not enforced.
  A decision expires at its `duration`, never later than the "longest decision lifetime" setting (default 7 days). The cache has a hard
  limit (default 100,000 decisions, at most 500,000); decisions beyond it are refused and the card warns.
* The visitor address is the one Zoraxy already trusts for rate limits and access rules (trusted proxy aware), so a forged
  `X-Forwarded-For` from an untrusted client changes nothing. This server, loopback and your trusted proxies are never refused.
* Log only: matches are logged and counted, nothing is blocked. Enforce: a banned visitor gets the 403 page (or, by setting, no answer) and the block appears in
  the blocked-request log with the reason "CrowdSec" ("Why was this blocked?" works).
* LAPI unreachable for longer than the grace period (default 5 min): **fail open** by default (traffic allowed, cached decisions still apply, the card
  turns red and a line is logged). **Fail closed** (enforce mode only, confirmation required) refuses every visitor instead.
* A rule can be exempted by host name in the settings. An https LAPI is verified with the system roots, or with the CA bundle / key pin you paste
  (there is no skip-verify option). Redirects are not followed and the destination must not be a cloud metadata or link-local address.
* The key is stored encrypted in `conf/crowdsec/`, is never returned by an API, is left out of configuration exports and out of the security audit log.
* **Two proxies:** let both Zoraxy instances query the same LAPI, but create **one bouncer key per instance** (`cscli bouncers add zoraxy-front`,
  `cscli bouncers add zoraxy-back`). To my recollection (not confirmed against a CrowdSec build) the LAPI tracks what it already sent per bouncer key,
  so two instances sharing a key would each receive only part of the changes. There is no replication between the instances.
* **Long bans:** a decision longer than the "longest decision lifetime" is stored cut to it, and the LAPI sends a decision only once. So that a
  30 day ban does not lapse locally, Zoraxy repeats a full synchronisation at half the lifetime as long as such decisions exist (the status card
  shows how many were cut).
* **Forwarded headers:** behind a trusted proxy (Cloudflare, the front proxy) the client can send any `X-Real-Ip` / `X-Forwarded-For`; the proxy
  does not remove it. Zoraxy therefore looks up every address the request claims, and loopback or this server's address in a header is not an
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

## Other ways to enforce decisions

CrowdSec's Nginx/Traefik bouncers do not apply. Besides the built-in bouncer above:

1. **Firewall bouncer** (`crowdsec-firewall-bouncer`, iptables/nftables): blocks the IP before Zoraxy sees it. Works
   when Zoraxy sees real client addresses (no NAT in front); easiest and cheapest.
2. **Zoraxy remote ban API** (Security Center > Auto-ban): generate a token in the UI, switch *Auto-ban* on, then a
   custom bouncer or script can push bans:

   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" -d ip=203.0.113.9 -d seconds=3600 -d reason=crowdsec \
        http://zoraxy:8000/api/abuse/remote/ban
   curl -X POST -H "Authorization: Bearer $TOKEN" -d ip=203.0.113.9 http://zoraxy:8000/api/abuse/remote/unban
   curl -H "Authorization: Bearer $TOKEN" http://zoraxy:8000/api/abuse/remote/list
   ```
   *Verified:* ban and list return the ban record. Bans are only enforced while Auto-ban is enabled (the list shows
   `"Active": false` otherwise), loopback/private/trusted-proxy addresses are never banned, and the API listens on the
   management port, so keep that port off the internet. Wiring this to `crowdsec-custom-bouncer` is not tested.

Zoraxy's own auto-ban (401/403/404/429, WAF, bots, CAPTCHA failures) covers much of what CrowdSec scenarios
detect for HTTP and may be enough on its own.
