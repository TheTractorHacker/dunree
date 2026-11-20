# Enterprise dual-proxy and network segmentation: audit and plan

Status: **Phases 1 to 5 are built and tested on one machine; see [enterprise-assessment.md](enterprise-assessment.md)
(23 PASS, 0 FAIL in the two-instance run; the one defect it found, no SNI for websockets and active probes to IP upstreams, is fixed).**
Real CrowdSec, a real two-VLAN network, Cloudflare, UniFi, Proxmox and HA are unverified. The text below is the original
plan, kept for the design record; "Nothing in this document is built" no longer applies. Phase 1 (audit) was a read-only
survey by search and spot reading; items marked *to verify* were confirmed in later phases unless the assessment says otherwise.

Fork rules apply to every item: new behaviour is **off or log-only by default**, no silent default changes, no changes
to existing installs, signed releases, a test and a "known limits" note per feature.

## 1. Target and what Zoraxy does and does not do

```
Internet -> Cloudflare -> UDM Pro -> [Public DMZ] External Zoraxy -> [Servers/DMZ] Internal Zoraxy -> App servers
                                   Admin path: Management VLAN only (separate listener, not via the proxies)
```
UDM Pro, Nexus and Proxmox firewalls are the enforcement layer. Zoraxy adds identity, filtering and visibility on
top. It will **never claim** to configure them; it validates what the admin documents and exports recommendations.
Two proxies in series are **not** redundancy (the external proxy is a single point of failure, so is the internal one).

## 2. Architecture as found (version 3.3.6, fork line `-fork.18`)

| Area | Where | Notes |
|---|---|---|
| Routing / reverse proxy | `src/mod/dynamicproxy` (router, `dpcore`, endpoints, vdir, redirection, `loadbalance`) | one `Router`, per-rule `ProxyEndpoint` |
| TLS and certs | `mod/tlscert`, `mod/acme`, `mod/dynamicproxy/certificate.go`, `secondarytls.go`, `tlscipherprofile.go`, `ech_glue.go` | SNI selection, ACME, cipher profiles |
| Authentication | `authProviders.go`, `basicauth_*`, `oauth2providers.go`, `mod/auth`, `mod/apitoken`, SSO exceptions (`authexceptions.go`) | per-rule auth modes, admin users and roles |
| Access control | `mod/access`, `accesslist.go`, `access.go` | allow/deny lists, country, **trusted proxy list** |
| Filtering | `mod/dynamicproxy/waf`, `botrules`, `mod/abuse`, `ratelimit.go`, `exploits`, `captcha` | WAF, auto-ban, rate limit (with dry run), bots |
| Logging / events | `mod/info/logger`, `mod/blocklog`, `mod/eventsystem`, `authaudit.go`, `mod/notify` | block log, "why blocked", auth audit |
| Clustering | `mod/cluster` (Fleet hub/nodes, snapshots, staged rollout, tokens, keys) | exists: sync of config between instances |
| Config management | `confbackup.go`, `mod/confhistory` + `history.go`, `/api/conf/export` and `/import`, updater rollback | zip export, history with snapshots |
| Health / uptime | `mod/uptime`, `dynamicproxy/health.go`, `loadbalance/healthcheck.go` | upstream checks, LB |
| Admin protection | `webui_loopback.go`, `adminroles_test.go`, session settings, API tokens | web UI TLS option, plugin loopback listener |
| Admin UI | `src/web` (jQuery + Fomantic + zxui kit, `nav.js`, `topbar.js`) | embedded via go:embed |

Dependencies: Go modules already vendored in the fork; **no new module is needed for this plan** (CrowdSec LAPI is
plain HTTPS+JSON, so `net/http` is enough).

## 3. Gap analysis

Legend: **Have** (works, reuse), **Improve** (exists, needs work), **Build**.

| Requirement | Status | Evidence and gap |
|---|---|---|
| External proxy: TLS termination, allow/deny, rate limit | Have | `access`, `ratelimit.go`, WAF, abuse |
| TLS re-encryption upstream | Have | per-origin TLS flag |
| Upstream TLS verify + **private CA** | **Improve** | **verified:** only system roots or per-origin `SkipCertValidations` (which also enables TLS 1.0 and weak suites); no custom CA pool, no pinning; WebSocket upstreams ignore SNI override and client cert |
| mTLS to clients per route | Have | `dynamicproxy/clientcert.go` |
| **mTLS between proxies** (proxy presents a client cert to its upstream) | **Improve** | **verified: already exists** (per-upstream `ClientCertName`, `dpcore.go:190`, health prober too). Gaps: WebSocket path does not use it; needs a UI/doc path for proxy-to-proxy use |
| CrowdSec | **Build** | doc only: `docs/guides/crowdsec.md`; remote-ban API exists as a push path |
| Trusted-proxy list, strip untrusted XFF / X-Real-IP | Have / **Improve** | `mod/access/trustedProxy.go` (`StripUntrustedClientIPHeaders`, `GetClientIP`), per-rule policy. Gaps: RFC 7239 `Forwarded` handling (*to verify*), `dpcore/header.go` appends XFF and fills X-Real-IP from `CF-Connecting-IP` / `Fastly-Client-IP` when unset (must be gated by trust), no peer identity beyond IP |
| **Internal mode**: accept only from trusted proxies / authenticated peers | **Build** | no listener-level "only these peers" gate; would be a role setting |
| Identity preserved through chain | **Improve** | XFF chain works with trusted list; add a signed/mTLS-authenticated hop option instead of header trust alone |
| Role concept (standalone / external / internal) | **Build** | no deployment role in config; GUI posture exists (`mod/posture`) to hook warnings |
| Request size limits per route | **Build** | no body limit on proxied requests (only on admin API reads) |
| Timeouts (read header, per route response) | Have / **Improve** | global `readheadertimeout`; per-route connect/response timeouts *to verify* |
| Rate limit by verified client identity | Have | per endpoint+IP using resolved client IP; needs role-aware resolution (internal mode) |
| WebSocket forwarding | Have | `websocketproxy`; add origin check review |
| Security headers | Have | `customHeader.go`, `permissionpolicy`, header rules; add a "hardened" preset (opt-in) |
| Admin API protection | Have / **Improve** | CSRF, roles, tokens exist; add "admin only on Management interface/CIDR" bind and warning if reachable via a proxy rule |
| Audit log of security-sensitive config changes | **Improve** | `authaudit.go` covers auth; `confhistory` snapshots changes, but no append-only who/what/when security log (*to verify*) |
| Dashboard (role, health, routes, certs, CrowdSec, rate limits, events, trusted proxies, validation) | **Improve** | pieces exist (Overview, Live map, Security Center, cert inventory `certinventory.go`, posture); assemble into one page, plus new CrowdSec and validation cards |
| Network segmentation section + warnings | **Build** | `mod/posture` and `doctor.go` give the warning framework |
| Config export/import, backups, rollback, history | Have / **Improve** | exist; add schema version + validation on import, redaction of secrets in export, migrations (config schema bump is already on the 4.0 roadmap) |
| Safe sync of non-secret config between proxies | Have / **Improve** | Fleet; confirm credentials and private keys are excluded (*to verify*), add drift detection view |
| Health checks / failover | Have | uptime + LB; document failure modes |
| Graceful restart / draining | **Improve** | `Shutdown(ctx)` used on listeners; verify in-flight drain on reload (*to verify*) |
| SSRF prevention | **Build** | the admin can set any upstream; upstream test tool (`upstreamtest.go`) dials arbitrary hosts. Needs an "allowed backend destinations" policy and a check on the test tool |

## 4. Proposed design

**Deployment role** (`standalone` default = today's behaviour, byte for byte):
- `external`: refuses to serve the admin UI on the public listener; trusts Cloudflare ranges only when the admin
  turns that on; forwards only to configured *authorised internal proxies*; CrowdSec enforcement on.
- `internal`: accepts proxied traffic only from the *trusted proxy list* (and optionally a client certificate from
  the external proxy); real client identity is taken from the chain only when the hop is trusted; direct internal
  users are allowed from listed CIDRs.
- The role changes **validation and warnings and a few defaults of new settings only**, never existing rules.

**CrowdSec** (documented interface: Local API with a bouncer API key, `GET /v1/decisions/stream` for the
startup + delta stream, and `GET /v1/decisions?ip=` for single lookups; TLS with optional client certs to the LAPI):
- Stream mode with a bounded in-memory decision cache (expiry from the decision `duration`, hard cap on entries),
  resync on failure. Types honoured: `ban`; `captcha` maps to the existing CAPTCHA, other types are logged, not
  enforced. Scopes: `Ip` and `Range` only; others ignored and counted.
- API key stored like other secrets in the DB, never shown again, redacted in exports/logs.
- Fail-open by default with a visible warning on the dashboard and a log line when the LAPI is unreachable;
  fail-closed is a switch with a confirm dialog. Health = last successful pull, cache size, error count.
- Two proxies: **both query the same LAPI** (the supported coordination model); no custom decision replication.
  Alerts (reporting back to CrowdSec) are out of scope for the first cut and documented as such.
- Not run against a real CrowdSec here: tested against a fake LAPI. Real-world confirmation is on your side.

**Network segmentation**: admin documents VLAN names/CIDRs, trusted upstream proxies, allowed backend CIDRs and
ports. Zoraxy checks routes against them and warns; it generates a **text/markdown policy recommendation** for UDM
Pro zone rules and Proxmox firewall (section 8) and states clearly nothing was applied.

**Dangerous-configuration warnings** (reuse posture engine): admin UI reachable from a proxied host or public
interface; a route whose upstream is the management address; trust-all forwarding; TLS verification off on any
origin; backend ranges unrestricted; SSRF-capable upstream targets (link-local, metadata 169.254.169.254, loopback);
external role with trusted-proxy list empty.

## 5. Phases

Each phase ends with a green full UI smoke, signed release only after your go (your standing "release when green"
applies only once you approve a phase).

### Phase 1: audit and design (this document)
Acceptance: you approve scope and answer section 7. Rollback: delete this file.

### Phase 2: roles, trusted headers, upstream TLS, route security
- Files: new `src/mod/deployrole/` (config, persistence, validation), `mod/access/trustedProxy.go`,
  `dpcore/header.go`, `dynamicproxy/proxyRequestHandler.go`, `reverseproxy.go`, `wrappers.go`, `config.go`,
  `mod/dynamicproxy/typedef.go`, `networkingapi.go`.
- Work: role setting; trust-gated `Forwarded`/XFF/X-Real-IP/CF headers (sanitise by default in internal/external);
  upstream CA bundle and optional pin per origin (replaces the need for skip-verify); optional upstream client
  certificate (mTLS between proxies); per-route max request body and connect/response timeouts (default unlimited =
  today); peer gate for internal role; SSRF destination policy for upstreams and the test tool.
- Security: header spoofing, TLS downgrade, SSRF; every new setting default = current behaviour.
- Tests: header trust matrix, TLS verify with private CA, wrong CA / expired / hostname mismatch, mTLS accept/reject,
  size-limit, SSRF blocklist, backward compatibility of existing rule JSON.
- Rollback: role back to standalone; config history snapshot taken before first save; revert release.

### Phase 3: CrowdSec, rate limiting, security controls
- Files: new `src/mod/crowdsec/` (client, cache, stream, health), hook in `dynamicproxy/abuse_hook.go` /
  `blockhook.go`, `abusewire.go`, API in `securityapi*.go`, reuse `blocklog` for "blocked by CrowdSec".
- Work: as section 4; rate-limit identity uses the verified client IP; "hardened security headers" opt-in preset;
  security-config audit log (append-only, secrets redacted) with a viewer.
- Tests: fake LAPI (decisions, expiry, cache cap, auth failure, timeout, malformed JSON, LAPI down fail-open and
  fail-closed), rate-limit enforcement with spoofed headers, bypass attempts.
- Rollback: switch off; cache is memory-only; nothing persisted except settings.

### Phase 4: dashboard and configuration management
- Files: new `src/web/components/enterprise.html` (+ `enterprise.css`), menu entry in `index.html`/`nav.js`,
  `securityapi`, `confbackup.go`, `history.go`, `cluster/*`.
- Work: one "Security overview" page (role/status, backend health, routes, cert expiry, CrowdSec health, rate-limit
  activity, blocked/allowed stats, event history, trusted proxies, validation warnings); network segmentation form +
  policy export; config schema version and migrations with validation on import, secret redaction in exports and
  logs, backup before import, drift view for Fleet (selected non-secret fields only, hashes compared).
- Tests: smoke scenario for the page in light/dark and phone width; import of old exports; redaction test that greps
  export for the secrets.
- Rollback: existing history snapshots plus pre-import backup; page is additive.

### Phase 5: tests, docs, deployment validation
- Failure-mode doc (external down, internal down, CrowdSec down, DNS, cert expiry), recovery steps, examples for the
  three modes, UniFi/Proxmox recommendations, and a two-instance integration test on this machine (external +
  internal on throwaway ports, under `~/capped.sh`). Live Proxy2 untouched; you deploy.

## 6. Risks and constraints
- Changing client-IP resolution is the highest-risk change (it feeds bans, rate limits, logs). It ships gated by the
  role and covered by the header matrix before anything else is built.
- Role settings must not break the existing Cloudflare trusted-proxy setup (`docs/guides/real-client-ip-cloudflare.md`).
- Dev machine has 4 cores / 12 GB: tests run capped, one heavy job at a time.
- Things I cannot verify here: real CrowdSec, UniFi/Proxmox rules, Cloudflare behaviour, your VLAN layout. They are
  labelled as untested in the notes and docs.

## 7. Decisions needed
1. **Scope/order:** is Phase 2 then 3 right, or CrowdSec first (smaller, visible)?
2. **Mode trust between proxies:** is "trusted IP list + optional mTLS" enough, or should the first cut require mTLS in
   external/internal roles?
3. **CrowdSec:** do you already run a CrowdSec LAPI (where, which version)? One shared LAPI for both proxies is my default.
4. **Admin listener:** OK to add an optional separate admin bind address/CIDR allow-list (Management VLAN only)?
5. **Release:** one release per phase (fork.19+) or hold everything for one release?

## 8. UniFi and Proxmox recommendations (draft, to be refined in Phase 5, not applied by Zoraxy)
- Internet -> Public DMZ: allow TCP 80/443 to the external proxy only. Everything else dropped.
- Public DMZ (external proxy) -> Servers VLAN: allow only to the internal proxy IP:443 (or the chosen port). No access
  to other VLANs, no DMZ-to-Management.
- Servers VLAN (internal proxy) -> app servers: allow only the specific app IP:port pairs listed in the route table.
- Management VLAN -> both proxies: admin port (8000 or your choice) allowed from Management only; deny from all else,
  including the Public DMZ.
- Public DMZ -> anything private other than the above: deny, and log drops. Proxmox VM firewall: same rules as a
  second layer, default drop inbound, allow admin from Management and traffic from the peer proxy only.
- Cloudflare: restrict origin 443 on the UDM to Cloudflare ranges, enable Authenticated Origin Pulls if you want
  Cloudflare to present a client certificate (Zoraxy's per-route mTLS can verify it).

## 9. Verified findings (read-only deep check, 7 independent readers, static reading only)

**As of the audit, before phases 2-4.** Everything below is written in the present tense of that audit; many items
were fixed or changed by the later phases. See [enterprise-assessment.md](enterprise-assessment.md) for the current status.

Corrections to section 3 and new facts. File references are to `src/`.

1. **Upstream TLS:** no private-CA support and no pinning (`mod/dynamicproxy/dpcore/dpcore.go:169-190`); skip-verify is
   all-or-nothing and re-enables TLS 1.0 and legacy ciphers (`utils/legacytls.go`). Upstream mTLS *does* exist.
   WebSocket (`websocketproxy.go:156`) and the upgrade tunnel (`dpcore.go:710`) ignore SNI override and client cert; the
   health prober builds its own `tls.Config` (`loadbalance/healthcheck.go:170`), so any new TLS option goes in three places.
2. **Forwarded headers (highest risk):** the ACL decision uses the TCP peer unless `TrustProxyHeadersOnly` is on, which is
   good. But what is **forwarded upstream** is spoofable by default: both strip paths are opt-in and off
   (`access.go:28,32`, `trustedProxy.go:202`); a client `X-Forwarded-For` stays as the left-most entry
   (`dpcore/header.go:205-229`); `CF-Connecting-IP`/`Fastly-Client-IP` from any peer are copied into `X-Real-Ip`
   unvalidated; RFC 7239 `Forwarded` is never parsed or stripped; `CF-Connecting-IPv6` is not in the strip list;
   `GetRequesterIP` takes the **first** XFF entry, which a client controls, when the peer is trusted;
   `X-Client-Cert-*` is stripped only on endpoints with a client-cert policy (a client can forge
   `X-Client-Cert-Verified` elsewhere); `geodb.go:220` and the auth-exception `UseTrustedProxy` path trust headers from
   any peer. Phase 2 therefore starts with these, as a role-gated, opt-in hardening (no silent change for standalone).
3. **Body size and timeouts:** no limit on proxied request bodies; no `ReadTimeout` (slow-body attacks unbounded),
   `WriteTimeout` 0; dial 30 s, TLS handshake 10 s, idle 30 s hard-coded; only per-upstream response-header timeout and
   per-route WebSocket timeout are configurable. Per-route body limit and request timeout are new work.
4. **Audit log:** `mod/confhistory` records actor + summary + masked diff for allow-listed config, but is pruned (100
   versions / 30 days / 200 MiB) and not tamper-evident; `conf/auth_audit.log` is append-only JSON lines but rotates
   once at 2 MiB (older entries lost) and covers logins/users/posture only. API-token lifecycle is not audited anywhere.
   Plan: a dedicated, size-bounded security log with more generous retention and token events; hash chain is optional.
5. **Export and sync leak secrets (important for your "no credentials between proxies" rule):** `/api/conf/export` is an
   unfiltered dump of `conf/` that **includes TLS private keys, the cluster secret, Fleet keys, notify secrets and
   basic-auth hashes**; with `includeDB` also DNS-provider credentials and OAuth secrets. Import is a blind overwrite
   with no version, schema or integrity check and a possible half-restored state. Fleet is allow-list based (good) but
   its *certs* scope sends private keys by design. Phase 4 adds a **redacted export** mode (default for sharing),
   a manifest with schema version and checksums, validation and a dry run before import, atomic restore, and a warning
   on the Fleet certs scope. The existing full-backup export stays available, clearly labelled as containing secrets.
6. **Reload and draining:** config-driven listener restarts drain (10 s / 5 s); **process stop, SIGTERM and Fleet restart do
   not drain** (`ShutdownSeq` never stops the proxy service), hijacked/WebSocket connections are not drained, restart
   has a 200 ms unbound window, only the first signal is handled. Failover = active probes, passive ejection (3 failures,
   30 s), uptime flag. Plan: drain on stop with an overall deadline, documented failure modes.
7. **SSRF and admin exposure:** admin features that dial admin-named hosts without private/link-local filtering:
   upstream test, port/IP scan, web SSH, uptime checks, forward proxy (no auth). Guarded already: AI assistant, notify
   webhooks, blocklist import, Sablier (partly). The admin port binds with `-port=host:port` but has **no CIDR
   allow-list**, and **nothing stops a proxy rule pointing at the admin listener**; posture does not warn about it.
   Plan: a shared destination guard (reuse `aiassist/ssrf.go` logic), admin-listener CIDR allow-list (off by default),
   and a posture warning for rules targeting the admin port.

Not determined (checked at the start of each phase): rate-limit settings storage and history coverage, the upstream
client-cert store loader, plugin URL validation, whether Fleet proxy scope syncs upstream credentials, Windows restart path.
