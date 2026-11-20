# Enterprise dual-proxy: final gap assessment

Fork line `v3.3.6-fork.22`. Plan: [enterprise-dual-proxy-plan.md](enterprise-dual-proxy-plan.md). Guide:
[guides/enterprise-dual-proxy.md](guides/enterprise-dual-proxy.md).

Evidence conventions. **E2E** = `tools/e2e/dual_proxy/run.sh enterprise` (`enterprise.py`, check ids 1a ... 11; two
Zoraxy instances, a backend, a private CA, a fake LAPI, all on loopback). Last full run: **23 PASS, 0 FAIL, 0 NOT RUN**
(5d and 7c failed before defect D1 below was fixed; they pass with the host-overwrite workaround removed). **Unit** = Go tests under `src/`. **UI** =
`tools/ui-smoke/*`. Status words: DONE (built and observed working in the tests named), PARTIAL (built, with a stated gap or
untested part), NOT DONE.

## 1. Requirements

| Requirement (plan section 3) | Status | Evidence and what is unverified |
|---|---|---|
| External proxy: TLS termination | DONE (pre-existing) | existing feature; **not covered by the E2E** (the external listener there is plain HTTP); unit/UI tests only |
| External proxy: allow/deny | DONE (pre-existing) | `src/mod/access/*_test.go`; not covered by the E2E |
| External proxy: rate limit | DONE | `mod/dynamicproxy/ratelimit_*_test.go`; E2E 2 |
| TLS re-encryption upstream | DONE | E2E 3a (private CA, skip-verify off) |
| Upstream verify with private CA, pinning, no silent skip | DONE | E2E 3a-3d: wrong CA, pin mismatch, no CA/no skip all fail with 521 and a logged cause; wrong CA plus explicit skip also fails. Unit: `mod/dynamicproxy` TLS tests, `upstreamtest_tls_test.go`. SNI for websockets and probes to IP upstreams (D1) was found by the E2E and is fixed, with unit tests for CA bundle, CA plus pin, and failure cases. Expired certificates not tested; the E2E reproduction of D1 used a CA bundle only (pin covered by unit tests) |
| mTLS to clients per route | DONE (pre-existing) | `mod/dynamicproxy/clientcert_test.go` |
| mTLS between the proxies | DONE for HTTP; PARTIAL overall | E2E 4a-4c tested the whole chain (client cert accepted, missing and foreign-CA cert rejected, direct connection too). Never exercised end to end with a websocket (upstream client certificate plus websocket path), nor combined with the spoofing check; certificate expiry and renewal untested |
| CrowdSec | PARTIAL | built and observed against a **fake** LAPI only: E2E 6 (log only, enforce, delete decision, LAPI down fail-open and fail-closed with confirmation, recovery); Unit `mod/crowdsec/crowdsec_test.go` (`TestStartupThenDelta`, `TestExpiryAndMaxTTL`, `TestCacheCap`, `TestAuthFailure403`, `TestMalformedJSON`, `TestTimeoutKeepsOldCacheAndResyncs`), `crowdsecapi_test.go`, `dynamicproxy/crowdsec_hook_test.go`; UI `crowdsec_smoke.py`. **Never run against a real CrowdSec**; no alerts back to CrowdSec (out of scope) |
| Trusted-proxy list, strip untrusted forwarded headers | DONE | E2E 1a (forged XFF, Forwarded, X-Real-IP, CF-Connecting-IP, True-Client-IP, X-Client-Cert-* never reach the backend), 1b; Unit `deployrole_test.go` (`TestUntrustedPeerStripsEverything`), `dynamicproxy/clientip_*_test.go`, `access/trustedProxy_test.go` |
| Internal mode: accept only trusted peers (peer gate) | DONE | E2E 1b (403 and `gateRejected` counter, trusted peer 200); Unit `TestPeerGate`. Real network spoofing at L2 is not covered by software (needs firewall) |
| Identity preserved through the chain | DONE | E2E 1a (`XFF=127.0.0.55, 127.0.0.1`), 4a (cert subject header). Non-loopback addresses untested |
| Role concept | DONE | `src/mod/deployrole`, `deployroleapi_test.go`, `dynamicproxy/deployrole_hook_test.go`, UI `enterprise_smoke.py` |
| Request size limit per route | DONE | E2E 5a (413 with Content-Length and chunked, either hop); Unit `dynamicproxy/routelimits_test.go` |
| Timeouts per route | DONE | E2E 5b (504 after 2.0 s); 5c (websocket exempt) |
| Rate limit by verified client identity | DONE | E2E 2 (dry run, enforce, per-address buckets, forged XFF rotation does not escape); Unit `ratelimit_identity_test.go`. Caveat: Status > Tune shows no count for a client until the sampler has seen it once (by design) |
| WebSocket forwarding | DONE for CA-verified https | E2E 5c (both hops) and 5d (IP upstream, CA bundle, no host overwrite; was D1, fixed). Websocket combined with an upstream client certificate was never exercised end to end |
| Hardened security headers (opt-in) | DONE | Unit `hardenedheaders_test.go`, `hardenedheaders_api_test.go`. Browser behaviour (Firefox, Safari) not checked |
| Admin API protection / admin only on management network | DONE | E2E 9 (lock-out protection, allow-list 403 from outside, rule to admin listener refused, public port never serves admin); Unit `adminexposure_test.go`, `mod/adminallow` tests |
| Audit log of security changes | DONE | E2E 10 (38 entries incl. role, trusted proxy, allow-list, crowdsec, import/export, no secrets, verify ok); Unit `mod/secaudit/secaudit_test.go`, `securityaudit_test.go`. Tamper-evident, not tamper-proof |
| Dashboard (role, health, routes, certs, CrowdSec, rate limits, trusted proxies, validation) | DONE | Security Center Overview/Deployment/Network plan; `secdashboard_test.go`, UI `enterprise_smoke.py`, `phase4_smoke.py`. Only Chromium-based smoke; Firefox/Safari not run |
| Network segmentation section + recommendations | PARTIAL | Network plan and exported text exist (`netplanapi_test.go`); the **firewall recommendations were never applied or tested on a UniFi UDM Pro or Proxmox host** |
| Dangerous-configuration warnings | DONE | `mod/posture`, `posture_api_test.go`; E2E 9 (`admin.rule_target` = warn) |
| SSRF / allowed backend destinations | DONE | `mod/destguard`, `adminexposure_test.go`; E2E 9 and the destguard setting in E2E 10 |
| Config export/import, schema, redaction, checksums, dry run | DONE | E2E 10 (no TLS key or CrowdSec key in the shareable export; tampered entry or checksum gives 400 and applies nothing; `conf.old_*` kept; schema 1); Unit `confbackup_test.go`, `mod/confpack/*_test.go` |
| History and rollback | DONE | E2E 11 (diff, dry run, restore, process re-exec, 200 again, `lastRestore` confirmed, audit entry). Binary rollback (updater) **not run**; only the existence of `/api/updater/rollback` was seen |
| Safe sync between proxies (Fleet) | PARTIAL | non-secret scopes, drift view, cert-sync confirmation exist (`cluster_test.go`); not exercised between two real instances |
| Health checks / failover | PARTIAL | E2E 7a, 7b (recovery without restart), 7c (active probe to an IP upstream, was D1, fixed); health checks are **off by default**; passive ejection and multiple upstreams not exercised; no HA/failover pair tested |
| Graceful drain | DONE | E2E 8a, 8b; Unit `shutdown_test.go`, `dynamicproxy/drain_test.go`. Hijacked/websocket connections are not drained (stated in the plan) |
| Failure-mode doc, recovery, three-mode examples | DONE | guide sections 0-11; recovery flags `-reset_admin_allowlist` and `-reset_ac` read from code (`def.go`, `adminexposure.go`); the allow-list flag was not run in the harness |

## 2. Product defects found by the integration test

**D1 (fixed in this release). No SNI for websocket dials and active health probes to an IP-addressed https upstream**
(E2E 5d and 7c failed before the fix). Found by the E2E: `src/mod/websocketproxy/websocketproxy.go` (`upstreamTLSConfig`
set SNI only from the rule's host overwrite) and the load-balancer health checker sent no SNI, so the internal proxy
presented its default certificate and verification failed (`cannot validate certificate for 127.0.0.1 because it doesn't
contain any IP SANs`). The plain HTTP path (`dpcore` `useRequestHostAsSNI`) was fine. Fix: the verification name is the
host overwrite if set, else, for an IP-literal upstream with a CA bundle, pin or client certificate, the request Host
(websocket) or the rule's primary domain (probe), else the upstream host name. Verification is never skipped or relaxed;
hostname upstreams, skip-verify and upstreams without CA/pin are unchanged. Behaviour change: a probe to an IP upstream with
a CA/pin now needs a certificate that covers the rule's domain (proxied requests already needed it). The host overwrite
workaround is no longer required (guide, 3.2). The E2E reproduction used a CA bundle only; a pin was covered by unit tests
(`websocketproxy` and `loadbalance` `upstream_tls_test.go`), not reproduced end to end. No real IPv6-literal upstream was tested.

Observation, not a defect: a failed upstream is reported as **521** (documented), not 502; the reason is logged once per
upstream and reason per 30 s.

## 3. Not verified (no evidence either way)

Real CrowdSec (versions, TLS/mTLS to the LAPI, real decision formats); a real two-VLAN network and non-loopback source
addresses; Cloudflare behaviour and ranges; UniFi UDM Pro zone-based rules; Proxmox firewall rules; high availability or
a second internal proxy; Firefox and Safari for the admin UI; mTLS combined with the spoofing check; passive ejection;
the updater's binary rollback; the `-reset_admin_allowlist` flag end to end; Windows.

## 4. Deferred work

1. Atomic module saves on shutdown.
2. Persisted CrowdSec decision cache (today memory only, per the plan).
3. Per-cluster keyed drift hashes in Fleet (today plain hashes of selected non-secret fields).
4. Translations of the new UI strings and error texts.
5. mTLS from the external proxy to the CrowdSec LAPI (today TLS and an API key).
6. (done) D1, SNI for websockets and probes, fixed.
7. Turn the E2E gaps into checks: non-loopback sources, passive ejection with two upstreams, mTLS plus spoofing.
