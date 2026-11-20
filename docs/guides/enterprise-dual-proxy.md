# Two Zoraxy proxies in a segmented network: modes, trust, failure and recovery

Applies to the fork line `v3.3.6-fork.19` and later (deployment role, peer gate, CrowdSec, audit log, hardened
headers). Background and the design decisions are in [../enterprise-dual-proxy-plan.md](../enterprise-dual-proxy-plan.md).

**Status of this guide.** Everything about what Zoraxy does was read from the code and covered by unit tests of the
single features. The complete setup below (an external and an internal Zoraxy on real machines, a real UDM Pro, a real
Proxmox host, a real CrowdSec) was **not run end to end**. Lines marked **(untested)** are my expectation from
documentation or reasoning, not an observed result. A two-instance integration test is still open work (plan, Phase 5).

**Zoraxy applies nothing outside itself.** It does not configure UniFi, Proxmox, Cloudflare or CrowdSec. The firewall
sections only recommend rules for you to create.

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

One Zoraxy, nothing in front (or a CDN in front).

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

1. Start Zoraxy with the admin panel on the management address only, for example `-port=10.0.0.5:8000` (the flag takes
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
   header; if it does not, set the host overwrite in the rule's *Header rewrite rules*. **(untested)**
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
   client certificate. **(untested together; both halves exist and are tested separately)**
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
   An untrusted peer's headers are removed, and Zoraxy writes a fresh `Forwarded: for=<peer>`.
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
   gating on (tested with forged `X-Forwarded-For` rotation, trusted and untrusted peers).
7. **Audit**: role, trusted proxy, allow-list, rate limit and header-preset changes are in Security Center > **Audit
   log** (tamper evident, not tamper proof).

## 3. Failure modes

| What fails | What visitors see | What Zoraxy does | What you do |
|---|---|---|---|
| **External proxy down** | public sites unreachable (connection refused or timeout from the internet or CDN) | internal proxy keeps serving whoever may reach it directly: with the peer gate on, only the *Networks that may connect directly* | restart or fail over the external proxy; internal users on the direct networks keep working. Nothing needs changing on the internal one. |
| **Internal proxy down** | external proxy answers with its upstream error page for every internal site (see [error-pages-and-521.md](error-pages-and-521.md); the exact status depends on the failure) | external marks the upstream unhealthy: active probes if the uptime monitor / health check is on, passive ejection after 3 failures for 30 s; with a second upstream configured, traffic goes there | restart the internal proxy; check *Status* and *Uptime Monitor* on the external one. A second internal proxy as a second upstream is the failover (untested here). |
| **CrowdSec LAPI down** | nothing changes by default (fail-open) | status goes degraded/down, the dashboard card warns, the last cache keeps being used until decisions expire; after the grace period nothing is blocked unless **fail-closed** is on, which then refuses every visitor in *Enforce* mode | bring the LAPI back (the cache resyncs by itself with 2 s to 2 min backoff); if you must, switch fail-closed off (Security Center > CrowdSec) or set the mode to *Log only*. |
| **DNS fails** | upstream errors for rules whose upstream is a name; certificate issuance by DNS challenge fails | names are resolved when connecting (and once when saved if a destination restriction is on); an unresolvable upstream counts as unhealthy | use fixed IPs for the proxy-to-proxy hop, or a hosts entry; fix the resolver. |
| **Certificate expires on the public side** | browsers warn | ACME renews if the ACME client is set up (*Certificates > ACME Client*); Security Overview and the certificate page show expiry | renew or re-issue; see [ssl-troubleshooting.md](ssl-troubleshooting.md). |
| **Certificate expires on the internal side, external verifies it** | external answers with an upstream error | verification **fails closed**: with a CA bundle or pin set, an expired or non matching certificate is refused and never falls back to skip-verify | renew the internal certificate, or the CA/pin on the external rule if it was replaced. Do not switch to *Skip Verification* as a workaround without understanding it. |
| **Mutual TLS client certificate expires** (if used) | external sees a handshake error | connection refused by the internal proxy | renew the external proxy's client certificate. |

Plain dependencies to remember: the external proxy needs the internal proxy's address (DNS or IP), its certificate
trust (CA/pin) and the firewall path; the internal proxy needs the external proxy's address on its Trusted Proxies list
and, with the gate on, that same address must be reachable as a *peer*.

## 4. Recovery

### 4.1 Admin allow-list locked you out

Security Center > Network exposure > *Admin panel allow-list* refuses a list that does not contain the address you save
from, but an import or a history restore can install one that locks you out. Stop Zoraxy, start it once with
`-reset_admin_allowlist`, sign in, correct the list, then remove the flag. The flag only clears that list.

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

*System > Update > Rollback* returns to the previous binary that the in-app updater saved; **configuration is not
reverted** by it. Manual updates: put back the old binary and the backed-up `conf/` and `sys.db`
([updating.md](updating.md)). Docker: use the previous image tag.

### 4.5 Forgot or lost the admin login

`-reset_ac` resets the admin account to the default and exits. Change the password right after.

## 5. Safe order of changes

1. Take a backup, note the current History version.
2. Change the **external** proxy last when moving to the dual setup, and the **internal** one first (it must trust the
   external address before the external starts sending forwarded headers).
3. Keep CrowdSec in *Log only* and rate limits in *Dry run* for a few days; read the counters.
4. Turn the peer gate on only after you have seen real traffic arrive from the external proxy.
5. Test from three places: the internet (through the external proxy), the internal LAN directly, and a host that should
   be blocked. Suggested checks **(not run here)**: from a host that is not a trusted proxy,
   `curl -H 'X-Forwarded-For: 1.2.3.4' https://internal-proxy/` must be refused by the gate or answered as *your own
   address*, never as 1.2.3.4 in the logs; repeated requests must hit the rate limit per visitor, not per proxy.

## 6. Hardened security headers (per site, optional)

Edit site > **Security** > *Hardened security headers*, default for new sites under **Network > Listeners** > *Security
headers for new sites*. Both are off by default. The page shows the headers that will be sent and, per header, whether it
is added only when the upstream sent none, replaces the upstream value (an option), or is skipped because you set it
yourself. Details and limits: [../ux/changes.md](../ux/changes.md), section "Rate limit identity check and hardened
security headers". HSTS and preload are remembered by browsers for the whole max age: only use them when every use of the
name works over HTTPS.

## 7. UniFi UDM Pro zone-based firewall and Proxmox recommendations

**Zoraxy applies none of this.** It is a draft from the plan (section 8) for you to review. **Untested**: not applied to
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
  Zoraxy, allow IN admin port from Management, allow OUT only to the application IP:ports and the LAPI.

Use IPSets and a *Security Group* per role so the rule text stays short. **(untested)**

### 7.3 Keep Zoraxy's settings and the firewall in step

| Zoraxy setting | Firewall rule that should say the same |
|---|---|
| Internal proxy: Trusted Proxies = external proxy address | row 2 (only that address reaches the internal proxy's port 443) |
| Peer gate + direct networks | the networks allowed to the internal proxy |
| Allowed backend destinations | row 3 |
| Admin panel allow-list | row 4 |
| CrowdSec LAPI address | row 7 |

Zoraxy's own checks are a second layer, not a replacement: the peer gate answers 403 only after a TCP connection was
accepted, and the allow-lists compare addresses that a compromised host in the same zone could still use.

## Exporting, importing and stopping safely
- **Utilities > Config Tools** offers a *Full backup* (contains TLS private keys, the cluster secret, Fleet keys, notification secrets, basic-auth hashes: store it like a password) and a *Shareable (redacted)* export (no keys or credentials; safe to hand to someone else, review it first). The shareable export always carries `manifest.json` with checksums (the full backup only when you tick the box, because an older Zoraxy cannot restore an archive that has one); checksums prove the file is undamaged, not who made it, and a shareable archive can never set credentials: real values in credential fields are ignored and the live ones kept. *Check file (dry run)* shows what a restore would add, replace and remove before you commit; archives from older versions import but are shown as *unverified*. The previous config is kept as `conf.old_<time>` and a failed restore puts it back. Restoring a shareable archive keeps the secrets already on that machine.
- Fleet: the *Certificates* scope, capturing certificates and the legacy "Sync certificates" send private keys to other machines and ask for confirmation. The Fleet node table shows *drifted: proxy, access* when a node's non-secret configuration differs from what the hub would send it.
- Stopping Zoraxy (SIGTERM, restart from Fleet, update) now lets running requests finish for up to 8 s (`-shutdown_drain`, capped at 15, 0 = old immediate stop) after saving logs, visitors and statistics; a second SIGTERM / Ctrl-C forces the exit. Keep your service manager's stop timeout at 30 s or more. Scripts that enable certificate sync must send `ackCerts=true` (Fleet hub) or `ackSyncCerts=true`.
