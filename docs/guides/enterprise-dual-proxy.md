# Two Dunree proxies in a segmented network: modes, trust, failure and recovery

Applies to every Dunree version, and to the builds `v3.3.6-fork.19` and later of the fork that became Dunree
(deployment role, peer gate, CrowdSec, audit log, hardened headers). Background and the design decisions are in [../enterprise-dual-proxy-plan.md](../enterprise-dual-proxy-plan.md).

**Status of this guide.** The Dunree side was exercised end to end on one machine with the harness
`tools/e2e/dual_proxy/run.sh enterprise` (an external and an internal Dunree, a backend app, a private CA, optional
mutual TLS, a **fake** CrowdSec LAPI, client addresses on loopback; about 2.5 min). Last run: **23 PASS, 0 FAIL, 0 NOT RUN**
(the run found a defect, SNI to IP-addressed upstreams for websockets and active probes, now fixed in this release; section 3.2).
Statements marked **(verified)** were observed in that run. **Not verified, and marked (untested)**: a real CrowdSec, a
real two-VLAN network, Cloudflare, a UDM Pro, a Proxmox host, high availability, Firefox and Safari, non-loopback source
addresses, mutual TLS combined with the spoofing check, passive ejection, expired certificates, the updater's binary rollback, websockets combined with an upstream client certificate, and several upstreams. Full list:
[../enterprise-assessment.md](../enterprise-assessment.md).

**Dunree applies nothing outside itself.** It does not configure UniFi, Proxmox, Cloudflare or CrowdSec. The firewall
sections only recommend rules for you to create.

## 0. Architecture

```
 Internet visitors
        |
   [Cloudflare / CDN]   optional; its ranges go under Trusted Proxies on the EXTERNAL proxy
        |  TCP 80/443
   [UDM Pro firewall]
        |
 +-------------------- Public DMZ --------------------+
 |  EXTERNAL Dunree   role=external, hardened headers  |   CrowdSec bouncer, rate limit, WAF, TLS termination
 |  admin port bound to the management address only    |
 +-----------------------------+-----------------------+
                               | TLS (private CA or pin, optional client cert), host overwrite = public name
 +-------------------- Servers VLAN -------------------+
 |  INTERNAL Dunree   role=internal, peer gate, trusts |   per-route body limit and timeout, same LAPI
 |  only the external proxy as a Trusted Proxy         |
 +-----------------------------+-----------------------+
                               | only the allowed IP:port pairs
                         [application servers]

 Management VLAN -> admin port of both proxies (never through a proxy rule); CrowdSec LAPI host reachable from both.
```

Two proxies in series are not redundancy: each is a single point of failure (section 3).

## 1. The three modes

Security Center > **Deployment** (left menu: Security > Security Center > Deployment tab) holds the role. The role
changes how forwarded headers are trusted and which warnings appear; it never edits your existing rules.

| | Standalone (default) | External | Internal |
|---|---|---|---|
| Typical place | one proxy at the edge or in a LAN | DMZ, faces the internet or a CDN | servers VLAN, behind the external proxy |
| Forwarded client headers | as before (opt-in hardening) | hardened | hardened |
| Peer gate | not available | not available | optional: only trusted proxies and listed networks may connect |
| Who it expects in front | anything | CDN (listed under Trusted Proxies) or nothing | the external proxy (listed under Trusted Proxies) |

"Hardened" means: a peer that is not in the trusted proxy list loses every client address header
(`X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `CF-Connecting-IP`, `X-Client-Cert-*` ...); a trusted peer's chain is read from
the right and the first hop that is not itself trusted is the visitor.

### 1.1 Standalone

One Dunree, nothing in front (or a CDN in front).

1. **Network > Trusted Proxies**: leave the Cloudflare list only if you are really behind Cloudflare, otherwise remove
   it. Details: [real-client-ip-cloudflare.md](real-client-ip-cloudflare.md).
2. **Security > Access Rules** > the rule used by your sites > **Enable Trusted Proxy Gating** (needed only behind a
   CDN or another proxy).
3. **Security > Security Center > Deployment**: role *Standalone*. Optionally tick *Harden forwarded client address
   headers* (recommended behind any proxy that appends to `X-Forwarded-For`, see 2.3).
4. **Sites > HTTP Proxy** > add a rule. In *Edit site > Security*: *Rate limit* (start with *Dry run*, then check
   Status > Tune), and, if wanted, *Hardened security headers* (section 6).
5. **Security Center > Network exposure** > *Admin panel allow-list*: your management network. Keep a way back in (section 5.4).
6. Optional: **Security Center > CrowdSec** ([crowdsec.md](crowdsec.md)); start in *Log only* mode.

### 1.2 External proxy (DMZ)

1. Start Dunree with the admin panel on the management address only, for example `-port=10.0.0.5:8000` (the flag takes
   `host:port`). Do not publish the admin port. **(untested on your layout)**
2. **Network > Listeners**: ports 80 and 443 (or yours).
3. **Security Center > Deployment**: role *External*. Read the warnings it shows.
4. **Network > Trusted Proxies**: Cloudflare ranges if you use Cloudflare; empty if visitors connect directly (the
   card warns about an empty list, that warning is only relevant behind a CDN).
5. **Security > Access Rules** > each rule > **Enable Trusted Proxy Gating** if a CDN is in front.
6. **Sites > HTTP Proxy** > add the rule for the public name. Upstream = the **internal proxy** (for example
   `internal-proxy.lan:443`) with *Require TLS*. In the upstream's *Advanced Options > Upstream certificate trust*
   paste the internal proxy's CA certificate (or its public-key pin) instead of using *Skip Verification*.
7. The internal proxy must have a rule for the public host name, so check that it receives that name in the `Host`
   header; if it does not, set the host overwrite in the rule's *Header rewrite rules*. For an IP-addressed upstream
   with a CA bundle or pin, the certificate must cover the public name (the host overwrite is no longer needed for
   websockets and health probes; see 3.2). **(verified)**
8. **Security Center > Network exposure**: *Allowed backend destinations* = only the internal proxy address and port
   (`10.20.0.10 443`); *Restrict diagnostic tools to allowed destinations* on; *Admin panel allow-list* = management network.
9. **Security Center > CrowdSec**: enabled here, where internet traffic arrives. Start in *Log only*.
10. Per site: *Edit site > Security > Rate limit* and, if wanted, *Hardened security headers*.

### 1.3 Internal proxy (servers VLAN)

1. **Security Center > Deployment**: role *Internal*.
2. **Network > Trusted Proxies**: **only** the external proxy's address (remove the Cloudflare defaults, they are not
   in front of this proxy).
3. **Security > Access Rules** > every rule your sites use > **Enable Trusted Proxy Gating**. This is required: with it
   off, rate limits, bans and access rules see the external proxy's address and every visitor shares one limit. The
   Deployment card shows a warning while a rule lacks it.
4. **Security Center > Deployment** > *Peer gate* on, and under *Networks that may connect directly* list the networks
   whose users may reach this proxy without the external one (for example the LAN) and your monitoring address. The
   API refuses to turn the gate on when it would refuse everybody.
5. Optional mutual TLS between the proxies: on the internal rule, *Edit site > TLS > Client certificates, peers and
   secondary TLS* (client certificate policy; allowed peer addresses per site), and give the external proxy's upstream a
   client certificate. **(verified in the harness, checks 4a-4c: client certificate accepted, missing and foreign-CA
   certificates refused, direct connection to the internal proxy refused; not tested with a websocket or combined with the spoofing check)**
6. **Sites > HTTP Proxy**: upstreams are the application servers. **Security Center > Network exposure** > *Allowed
   backend destinations* = exactly the application `IP port` pairs.
7. **Security Center > CrowdSec**: point it at the **same** LAPI as the external proxy (there is no replication between
   proxies; both pull from the LAPI).
8. *Admin panel allow-list* = management network.

## 2. Chain trust model

1. **Who is trusted**: only peers whose TCP address is on the *Trusted Proxies* list. The address is the one of the
   TCP connection (after PROXY protocol processing if you use it), never a header.
2. **What a trusted peer may say**: the visitor address in `X-Forwarded-For` (right-most entry that is not itself
   trusted wins; everything to its left is dropped), else the CDN headers, else `X-Real-IP`. Malformed values are removed.
   An untrusted peer's headers are removed, and Dunree writes a fresh `Forwarded: for=<peer>`.
3. **Where the visitor address is used**: access rules, rate limits, CrowdSec, auto-ban, WAF, CAPTCHA, GeoIP, logs. All
   of them take it from the same function, and only from rules with **Trusted Proxy Gating** on. Without the gating
   they use the connecting proxy's address (this is the safe direction, but one bucket for everyone).
4. **The internal proxy is only as trustworthy as its network path.** Hardening cannot tell a forged connection from
   the external proxy if an attacker can reach the internal proxy from the external proxy's address (or spoof it on the
   same L2 segment). The peer gate, mutual TLS and the firewall rules in section 7 are what close that.
5. **Known limit**: in Standalone with hardening **off**, a trusted proxy that *appends* to a client-supplied
   `X-Forwarded-For` lets that client pick its rate limit bucket (the first entry is read). Turn hardening on (any role
   other than Standalone does) or make the proxy replace the header.
6. **Rate limits** count per visitor address, not per proxy, in Internal and External roles when the rule has the
   gating on. What check 2 did: on the internal rule, a dry run (nobody limited) and then enforcement, with requests from
   several loopback addresses (127.0.0.x) sent through the external proxy, one rate bucket per address, and a forged
   `X-Forwarded-For` rotated from 127.0.0.x through the external proxy did not escape the limit. Trusted-CDN peers with
   forged headers and non-loopback addresses were not part of that check (header handling is in check 1a/1b and unit tests).
7. **Audit**: role, trusted proxy, allow-list, rate limit and header-preset changes are in Security Center > **Audit
   log** (tamper evident, not tamper proof).

## 3. Failure modes

| What fails | What visitors see | What Dunree does | What you do |
|---|---|---|---|
| **External proxy down** | public sites unreachable (connection refused or timeout from the internet or CDN) | internal proxy keeps serving whoever may reach it directly: with the peer gate on, only the *Networks that may connect directly* | restart or fail over the external proxy; internal users on the direct networks keep working. Nothing needs changing on the internal one. |
| **Internal proxy down** | external proxy answers with its upstream error page for every internal site (see [error-pages-and-521.md](error-pages-and-521.md); the exact status depends on the failure) | external marks the upstream unhealthy: active probes if the uptime monitor / health check is on, passive ejection (3 failures, 30 s; **off by default** in the load-balancer config and not tested end to end); with a second upstream configured, traffic goes there | restart the internal proxy; check *Status* and *Uptime Monitor* on the external one. A second internal proxy as a second upstream is the failover (untested here). |
| **CrowdSec LAPI down** | nothing changes by default (fail-open) | status goes degraded/down, the dashboard card warns, the last cache keeps being used until decisions expire; after the grace period nothing is blocked unless **fail-closed** is on, which then refuses every visitor in *Enforce* mode | bring the LAPI back (the cache resyncs by itself with 2 s to 2 min backoff); if you must, switch fail-closed off (Security Center > CrowdSec) or set the mode to *Log only*. |
| **DNS fails** | upstream errors for rules whose upstream is a name; certificate issuance by DNS challenge fails | names are resolved when connecting (and once when saved if a destination restriction is on); an unresolvable upstream counts as unhealthy | use fixed IPs for the proxy-to-proxy hop, or a hosts entry; fix the resolver. |
| **Certificate expires on the public side** | browsers warn | ACME renews if the ACME client is set up (*Certificates > ACME Client*); Security Overview and the certificate page show expiry | renew or re-issue; see [ssl-troubleshooting.md](ssl-troubleshooting.md). |
| **Certificate expires on the internal side, external verifies it** | external answers with an upstream error | verification **fails closed** (verified for a wrong CA, a pin mismatch and no CA, checks 3b-3d; an *expired* certificate was **not tested**, it is expected to be refused the same way by Go's verifier) | renew the internal certificate, or the CA/pin on the external rule if it was replaced. Do not switch to *Skip Verification* as a workaround without understanding it. |
| **Mutual TLS client certificate expires** (if used) | external sees a handshake error | expected: connection refused by the internal proxy (**untested**: only a missing and a foreign-CA client certificate were tested, checks 4b-4c; expiry was not) | renew the external proxy's client certificate. |

### 3.1 Observed in the integration test (loopback, one machine) (verified)

| Situation | Observed |
|---|---|
| Backend stopped | internal answers **521** and logs `connection refused`. Health shows "unhealthy" (after about 3.6 s) **only if an active health check is configured**; with none (the default) health stays "healthy" while the backend is dead. After the backend restarts the chain answers 200 at once, no proxy restart. |
| Internal proxy stopped | external answers **521** with its error page and logs the cause; health unhealthy; after the internal restarts (same ports) the external answers 200 at once, no restart. Passive ejection is off by default and was not exercised. |
| LAPI killed | state ok, then degraded, then down; fail-open keeps serving clean visitors and the cached ban still returns 403; fail-closed (needs `confirmfailclosed`) blocks clean visitors with 403; with the LAPI back the state returns to ok. |
| Wrong CA, pin mismatch, no CA and no skip | external answers **521** (not 502), the backend is not reached, and the cause is logged once per upstream and reason per 30 s. Wrong CA plus explicit skip-verify also fails (no fallback). |
| Missing or foreign client certificate (mutual TLS) | external 521; the internal rejects with a TLS alert. |
| SIGTERM with a 5 s request in flight | the response completes (200), the process exits 4.6 s after the signal with status 0, new connections are refused while draining. A second SIGTERM exits in under 0.1 s and cuts the request. |

### 3.2 Fixed: SNI for websockets and active probes to an IP-addressed https upstream

The end-to-end test found this defect and it is fixed in this release. Earlier builds sent no SNI for websocket dials
and active health probes to an IP-addressed https upstream with a CA bundle (or pin) and an empty host overwrite. The
end-to-end reproduction used a CA bundle only; the pin path uses the same code and is covered by unit tests, but a pin
was not reproduced end to end. Symptoms (websocket 503 "doesn't contain any IP SANs", probe marked unhealthy while
plain HTTP worked). Both now pick the verification name like the HTTP path: the host overwrite if set, otherwise, for an
IP literal upstream, the request Host (websocket) or the rule's primary domain (probe), otherwise the upstream host
name. Hostname verification stays on, there is no fallback to skip-verify, and hostname upstreams, skip-verify and
upstreams without CA/pin behave as before. A probe to an IP upstream with a CA/pin now needs the certificate to cover
the rule's domain (as proxied requests already did). Checks 5d and 7c prove it without a host overwrite.

Plain dependencies to remember: the external proxy needs the internal proxy's address (DNS or IP), its certificate
trust (CA/pin) and the firewall path; the internal proxy needs the external proxy's address on its Trusted Proxies list
and, with the gate on, that same address must be reachable as a *peer*.

## 4. Recovery

### 4.1 Admin allow-list locked you out

Security Center > Network exposure > *Admin panel allow-list* refuses a list that does not contain the address you save
from, but an import or a history restore can install one that locks you out. Stop Dunree, start it once with
`-reset_admin_allowlist`, sign in, correct the list, then remove the flag. The flag only clears that list. (The list refuses entries that exclude the caller, and the admin port refuses a rule that
targets it, both verified; the flag itself is read from the code and was not run in the harness.)

### 4.2 Peer gate refuses the external proxy

The gate applies to proxy listeners only, **not to the admin port**. Open the admin panel (from a network on the admin
allow-list), Security Center > Deployment, turn the *Peer gate* off or add the external proxy to *Trusted Proxies* or its
network to *Networks that may connect directly*, then turn it on again. There is no command-line flag for this one. If
the admin panel is unreachable too, restore a `sys.db` backup or use section 4.3. Health checks from a monitor that is
not listed get `403` while the gate is on; list the monitor's address.

### 4.3 Roll back a configuration change

*System > History*: every change is a version with a diff; use the dry-run preview, then restore the scope you
want. The deployment role, destination restriction and CrowdSec settings are recorded ("Deployment role changed" etc.).
The history is pruned (100 versions, 30 days, 200 MiB), so take a manual backup (*System > Utilities*) before big changes.
A restore does not repeat the admin allow-list lock-out check (section 4.1).

### 4.4 Roll back a binary

*System > Update > Rollback* **(untested: the binary rollback was not run; the harness only confirmed that the
`/api/updater/rollback` endpoint exists)** returns to the previous binary that the in-app updater saved; **configuration is not
reverted** by it. Manual updates: put back the old binary and the backed-up `conf/` and `sys.db`
([updating.md](updating.md)). Docker: use the previous image tag.

### 4.5 Forgot or lost the admin login

`-reset_ac` resets the admin account to the default and exits. Change the password right after.

### 4.6 Import failed or applied something unwanted

The import validates first: *Check file (dry run)* (`/api/conf/importcheck`) and the real import both refuse an archive
whose entry or manifest checksum does not match (HTTP 400, nothing applied) **(verified)**. A successful import keeps the
previous config as `conf.old_<time>` next to `conf/`; a failed restore puts it back. To undo a good import by hand: stop
Dunree, move `conf` aside, rename `conf.old_<time>` to `conf`, start. Restoring a *shareable* archive keeps the secrets
already on the machine. If the imported config locks you out of the admin panel, see 4.1.

## 5. Safe order of changes

1. Take a backup, note the current History version.
2. Change the **external** proxy last when moving to the dual setup, and the **internal** one first (it must trust the
   external address before the external starts sending forwarded headers).
3. Keep CrowdSec in *Log only* and rate limits in *Dry run* for a few days; read the counters.
4. Turn the peer gate on only after you have seen real traffic arrive from the external proxy.
5. Test from three places: the internet (through the external proxy), the internal LAN directly, and a host that should
   be blocked. Suggested checks (the harness ran them as checks 1a and 1b, on loopback addresses only, so run them on your own network too): from a host that is not a trusted proxy,
   `curl -H 'X-Forwarded-For: 1.2.3.4' https://internal-proxy/` must be refused by the gate or answered as *your own
   address*, never as 1.2.3.4 in the logs; repeated requests must hit the rate limit per visitor, not per proxy.

## 6. Hardened security headers (per site, optional)

Edit site > **Security** > *Hardened security headers*, default for new sites under **Network > Listeners** > *Security
headers for new sites*. Both are off by default on existing installs (a new installation starts with the conservative default from 6.1). The page shows the headers that will be sent and, per header, whether it
is added only when the upstream sent none, replaces the upstream value (an option), or is skipped because you set it
yourself. Details and limits: [../ux/changes.md](../ux/changes.md), section "Rate limit identity check and hardened
security headers". HSTS and preload are remembered by browsers for the whole max age: only use them when every use of the
name works over HTTPS.

### 6.1 Enterprise baseline (on by default for new installs)

A new installation starts with a short list of safe settings already on: the forwarded client-address header clean-up and a conservative security header default for sites created later (nosniff, Referrer-Policy, HSTS for 30 days on HTTPS). The security audit log is always on and CrowdSec is shown as "Not configured" until you add the LAPI address and key. An existing installation is not changed by an update: Security Center > Overview has an "Apply enterprise baseline" button with a preview of every change and an Undo. The baseline never enables the peer gate, the admin allow-list, enforce mode, rate-limit enforcement or any allow-list, and never touches the settings of existing sites. **Behind a proxy or CDN (for example the Proxy1/Proxy2 layout, a tunnel or a Docker first start behind a load balancer):** a new install turns the header clean-up on while Trusted Proxies is still empty, so every visitor would appear with the proxy's address, rate limits and bans would key on that one address, X-Forwarded-Proto/Host would be ignored (scheme redirects can loop behind a Flexible-SSL CDN). The first-start log, the audit entry and a warning on the Overview card say so. Add the proxy under Trusted Proxies right after the first start, or switch the clean-up off under Deployment settings (or press Undo on the card) until you have. Details: docs/ux/changes.md, "Enterprise baseline".

## 7. UniFi UDM Pro zone-based firewall and Proxmox recommendations

**Dunree applies none of this.** It is a draft from the plan (section 8) for you to review. **Untested**: not applied to
a UDM Pro, UniFi Network, or Proxmox host here; menu names differ between versions, so check them against yours.

Example layout: zones/VLANs *Public DMZ* (external proxy), *Servers* (internal proxy and applications), *Management*
(admin workstations, CrowdSec LAPI host), plus the WAN.

### 7.1 UniFi zone-based firewall (policies read as source zone -> destination zone)

| # | From | To | Allow | Notes |
|---|---|---|---|---|
| 1 | External (WAN) | Public DMZ | TCP 80, 443 to the external proxy only | everything else from WAN is blocked; if you use Cloudflare restrict the source to its published ranges and consider Authenticated Origin Pulls |
| 2 | Public DMZ | Servers | TCP 443 (or your port) to the **internal proxy address only** | no other host in Servers |
| 3 | Servers (internal proxy) | Servers / app hosts | only the `IP:port` pairs of your rules | mirrors *Allowed backend destinations* |
| 4 | Management | Public DMZ and Servers | the admin port (8000 or yours) to both proxies | mirrors the admin allow-list |
| 5 | Public DMZ | Management and any other internal zone | **block, log** | the DMZ must not reach management |
| 6 | Public DMZ | Servers (everything else) | **block, log** | explicit, below rule 2 |
| 7 | Public DMZ and Servers | CrowdSec LAPI host | the LAPI port (default 8080) from both proxies | external and internal both pull from the same LAPI |
| 8 | Public DMZ | Internet | only what the external proxy needs (DNS, ACME, updates) | optional hardening |

Return traffic is handled by connection tracking (UniFi's "return traffic" matching); do not write rules for replies.
**(untested)** Order matters: allow rules above the block rules for the same pair of zones.

### 7.2 Proxmox VE firewall (second layer)

Enable the firewall at Datacenter, node and VM/CT level (**Datacenter > Firewall > Options**, then each guest's
*Firewall > Options*), default input policy **DROP**, then per proxy guest:

* external proxy guest: allow IN TCP 80/443 from anywhere (or the Cloudflare IPSet), allow IN admin port from the
  Management IPSet, allow OUT only to the internal proxy IP:443, the LAPI, DNS and (if used) ACME;
* internal proxy guest: allow IN TCP 443 from the external proxy IP and from the direct-access networks you listed in
  Dunree, allow IN admin port from Management, allow OUT only to the application IP:ports and the LAPI.

Use IPSets and a *Security Group* per role so the rule text stays short. **(untested)**

### 7.3 Keep Dunree's settings and the firewall in step

| Dunree setting | Firewall rule that should say the same |
|---|---|
| Internal proxy: Trusted Proxies = external proxy address | row 2 (only that address reaches the internal proxy's port 443) |
| Peer gate + direct networks | the networks allowed to the internal proxy |
| Allowed backend destinations | row 3 |
| Admin panel allow-list | row 4 |
| CrowdSec LAPI address | row 7 |

Dunree's own checks are a second layer, not a replacement: the peer gate answers 403 only after a TCP connection was
accepted, and the allow-lists compare addresses that a compromised host in the same zone could still use.

## 8. Equivalent API and configuration values

Everything in the GUI is an authenticated API call (session cookie or API token). Field names below are the ones the
harness uses; treat them as examples and check against your build.

| Purpose | Call | Example values |
|---|---|---|
| Role, header hardening, peer gate | `POST /api/deployrole/set` `config=` | `{"role":"internal","hardenHeaders":true,"peerGate":true,"directCIDRs":["10.30.0.0/24"]}`; external: `{"role":"external","hardenHeaders":true,"peerGate":false,"directCIDRs":[]}` |
| Trusted proxies | `/api/trustedproxy/add`, `/list`, `/remove`; per rule `/api/whitelist/trustProxy` | external proxy address on the internal; CDN ranges on the external |
| Upstream trust (external rule) | `/api/proxy/upstream/update` | `{"RequireTLS":true,"TLSCABundlePEM":"-----BEGIN CERTIFICATE-----...","TLSPinsSHA256":[],"SkipCertValidations":false,"ClientCertName":"external-proxy"}` |
| Host overwrite | `/api/proxy/header/handleHostOverwrite` | the public name (only if the internal proxy needs that Host; no longer needed for IP upstreams, 3.2) |
| Route limits | the rule's edit call | `maxRequestBodyBytes` (413 above it), `requestTimeout` seconds (504) |
| Health check | `/api/proxy/upstream/lb/set` | interval in seconds; off by default |
| CrowdSec | `POST /api/crowdsec/set` `config=`, `apikey=`, `confirmfailclosed=true`, `clearkey=true` | `{"enabled":true,"lapiUrl":"https://lapi.mgmt:8080","mode":"log","pollSeconds":5,"graceSeconds":30}`; `/api/crowdsec/status` |
| Admin allow-list | `/api/adminallow/get`, `/set` | `{"cidrs":["10.0.0.0/24"]}`; `[]` turns it off |
| Destination guard | `/api/destguard/set` | `{"restrictTools":true,"allowedBackends":["10.20.0.10"]}` |
| Export, check, import | `/api/conf/export`, `/api/conf/importcheck`, `/api/conf/import` | shareable vs full; checksums in `manifest.json` |
| History | `/api/history/list`, `/diff`, `/snapshot`, `/restore` | dry run first, then restore a scope |
| Audit | `/api/security/audit/list`, `/verify` | |

Command-line flags that matter here: `-port=<host:port>` (admin bind), `-reset_admin_allowlist`, `-reset_ac`,
`-shutdown_drain=<s>` (default 8, cap 15, 0 = off).

## 9. Rollback: how to undo each phase

| Layer | How to undo | Notes |
|---|---|---|
| Role and hardening (phase 2) | Security Center > Deployment: role *Standalone*, untick hardening and peer gate (`/api/deployrole/set` with `standalone`) | existing rules are never edited by the role |
| Upstream trust, mTLS, host overwrite, body limit, timeout | edit the rule: clear the CA bundle/pins/client certificate, set limit and timeout to 0 | 0 = unlimited = old behaviour |
| Destination guard, admin allow-list | Network exposure: turn off / empty list; locked out: `-reset_admin_allowlist` | |
| CrowdSec (phase 3) | mode *Log only*, then disable; the decision cache is memory only | `clearkey` removes the stored key |
| Rate limit | *Dry run*, then remove | |
| Hardened security headers | untick per site and the default under Network > Listeners | |
| Any single change | System > History: diff, dry run, restore the scope **(verified: restore re-executed the process, the chain answered 200, the restore was confirmed in about 20 s)** | the restore does not repeat the lock-out check; history keeps 100 versions / 30 days / 200 MiB |
| Config import | `conf.old_<time>` folder (4.6) | pre-import backup, kept automatically |
| Binary | System > Update > Rollback, or replace the binary with the old one | configuration is **not** reverted; run the backed-up `conf/` and `sys.db` back in if the new version migrated them |
| Everything | stop Dunree, restore the `conf/` folder and `sys.db` backups taken before the change, start | take them before every phase |

## 10. UniFi and Proxmox: recommendations only

Section 7 above is the recommendation set. **Nothing was applied to any device and none of it was tested on a UDM Pro or
a Proxmox host.** Review menu names and policy order against your firmware.

## 11. Security checklist before going live

- [ ] Admin port bound to the management address (`-port=10.0.0.5:8000`), not published; admin allow-list set; a rule never targets the admin listener (verified refused when the allow-list is on).
- [ ] Role set on both proxies; the internal proxy trusts **only** the external proxy; Trusted Proxy Gating on for every rule on the internal proxy.
- [ ] Peer gate on only after real traffic from the external proxy was seen; monitoring address listed.
- [ ] External to internal uses a private CA or a pin, *Skip Verification* off; the internal certificate covers the public name when the upstream is an IP address (3.2).
- [ ] Mutual TLS considered; client certificate renewal date in your calendar.
- [ ] Rate limits and CrowdSec went through *Dry run* / *Log only* for several days; fail-closed deliberately chosen.
- [ ] Both proxies point to the same LAPI; the LAPI is reachable only from them; the API key is a bouncer key.
- [ ] Allowed backend destinations list the exact application `IP port` pairs.
- [ ] Spoof test from the internet and from the LAN (section 5, step 5) run on **your** network; the harness (checks 1a, 1b) only ran it on loopback addresses.
- [ ] Health checks enabled on the proxy-to-proxy upstream (they are off by default).
- [ ] Firewall rules from section 7 created by you and reviewed; certificate expiry on both sides monitored.
- [ ] A full backup (contains private keys; store it like a password), a note of the History version, and the rollback steps in section 9 at hand.
- [ ] Stop timeout of the service manager is 30 s or more (drain).

## Automated end-to-end test

Harness: `tools/e2e/dual_proxy/run.sh`. It builds Dunree from the checkout, starts an external and an internal instance
and a backend app in temporary directories on high ports (loopback only, a private CA, a fake CrowdSec LAPI), and
removes everything on exit. It never touches an installed Dunree. Builds and runs go through `~/capped.sh` under the
shared heavy lock.

```
tools/e2e/dual_proxy/run.sh [--mode tls|mtls|both] [--keep]     # smoke test of the chain (default: both modes)
tools/e2e/dual_proxy/run.sh enterprise [--only 1,3,7] [--keep]  # the enterprise checks, about 2.5 min
```

* `--mode tls`: CA-verified hop only. `--mode mtls`: plus client certificates. `both`: one run of each.
* `enterprise` runs the checks below; `--only` takes group numbers; `--keep` keeps the temporary directories.
* Each check prints PASS, FAIL or NOT RUN with evidence lines; the exit status is non-zero when any check failed.

What the last full `enterprise` run covered (23 PASS, 0 FAIL, 0 NOT RUN, with the host-overwrite workaround removed):

| Group | Checks | Result | What it covers |
|---|---|---|---|
| 1 Spoofing | 1a, 1b | PASS, PASS | forged forwarded headers via the external proxy and straight to the internal one; peer gate |
| 2 Rate limit | 2 | PASS | per-address buckets, dry run then enforce, forged `X-Forwarded-For` rotation |
| 3 Upstream TLS | 3a, 3b, 3c, 3d | PASS x4 | private CA ok; wrong CA, pin mismatch, no CA fail closed with 521 |
| 4 Mutual TLS | 4a, 4b, 4c | PASS x3 | client certificate accepted; missing and foreign-CA certificates refused |
| 5 Limits and websockets | 5a, 5b, 5c, 5d | PASS x4 | body limit 413, request timeout 504, websocket through both hops, websocket to an IP upstream without host overwrite |
| 6 CrowdSec | 6 | PASS | against a fake LAPI: log only, enforce, delete, LAPI down fail-open and fail-closed, recovery |
| 7 Failure and recovery | 7a, 7b, 7c | PASS x3 | backend down, internal proxy down, active health probe to an IP upstream without host overwrite |
| 8 Drain | 8a, 8b | PASS, PASS | in-flight request completes on SIGTERM; second SIGTERM forces exit |
| 9 Admin exposure | 9 | PASS | allow-list lock-out protection, 403 from outside, rule to the admin listener refused |
| 10 Config management | 10 | PASS | audit log, redacted export, checksums, tampered archive refused, `conf.old_*` kept |
| 11 History | 11 | PASS | diff, dry run, restore, process restart, chain answers 200 again |

What it does **not** cover: non-loopback source addresses and a real two-VLAN network; a real CrowdSec (only the fake
LAPI); Cloudflare; UniFi UDM Pro and Proxmox firewall rules; high availability or a second internal proxy; passive
ejection; expired certificates; the updater's binary rollback; Firefox and Safari. Mutual TLS was not combined with the
spoofing check or with websockets.

## Exporting, importing and stopping safely
- **Utilities > Config Tools** offers a *Full backup* (contains TLS private keys, the cluster secret, Fleet keys, notification secrets, basic-auth hashes: store it like a password) and a *Shareable (redacted)* export (no keys or credentials; safe to hand to someone else, review it first). The shareable export always carries `manifest.json` with checksums (the full backup only when you tick the box, because the restore code of `v3.3.6-fork.18` refuses any archive entry outside `conf/` and `sys.db`, so it would refuse an archive with `manifest.json`; read from that tag's `confbackup.go`, not run); checksums prove the file is undamaged, not who made it, and a shareable archive can never set credentials: real values in credential fields are ignored and the live ones kept. *Check file (dry run)* shows what a restore would add, replace and remove before you commit; archives from older versions import but are shown as *unverified*. The previous config is kept as `conf.old_<time>` and a failed restore puts it back. Restoring a shareable archive keeps the secrets already on that machine.
- Fleet: the *Certificates* scope, capturing certificates and the legacy "Sync certificates" send private keys to other machines and ask for confirmation. The Fleet node table shows *drifted: proxy, access* when a node's non-secret configuration differs from what the hub would send it.
- Stopping Dunree (SIGTERM, restart from Fleet, update) now lets running requests finish for up to 8 s (`-shutdown_drain`, capped at 15, 0 = old immediate stop) after saving logs, visitors and statistics; a second SIGTERM / Ctrl-C forces the exit. Keep your service manager's stop timeout at 30 s or more. Scripts that enable certificate sync must send `ackCerts=true` (Fleet hub) or `ackSyncCerts=true`.
