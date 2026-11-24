# Dunree fork: version 4.0 plan

Status: **draft for discussion**. Nothing here is built unless it says so. Every item keeps the fork's rules:
new behaviour is **off or log-only by default**, no silent default changes, signed releases, and every item
ships with an automated test and a "known limits" note.

## Goal

3.x made the fork safe to run (WAF, CAPTCHA, Fleet/HA, signed updater, "Why was this blocked?") and clearer to use
(new menu, top bar, site editor). 4.0 is the release where it becomes **the proxy you can run without reading the
manual, and trust in production**: one clear picture of what is happening right now, safe changes, and no surprises.

## Pillars

### 1. See it live (finish what fork.16 starts)
- Live Traffic map with per-rule req/s, busiest client against the rate limit, hints only (**built, in fork.16**).
- Live view for the Visitors page and the Blocked list (stream instead of refresh).
- Per-rule "last 24 h" mini history (rate, errors, p50/p95 latency), small and bounded in memory, no new database growth.

### 2. Change it safely
- **Dry run for every setting that can lock people out** (rate limits, WAF block mode, country rules): show how many of the
  last N requests would have been affected before enabling. Builds on the log-only mode and "Why blocked".
- **Config history with one-click rollback** in the UI (the history store exists; the UI is thin).
- **Staged rollout across a Fleet**: apply to one node, wait for health, then the rest, with automatic rollback.
- **Unsaved-changes bar** on every editor (decision D2 in the UI audit).

### 3. Certificates that never surprise
- First-class **wildcard via ACME DNS challenge** for the common DNS providers, chosen from a list, with expiry alerts in the top bar.
- A **TLS check per host** (what a browser would get, including ECH and fallback certificate) as a button, not a terminal session.
- Plain-language ECH page: "this name is/is not affected", with the DNS fix per provider.

### 4. Operate it
- **Database retention**: day-based retention for statistics (off by default), size warning with one-click offline compaction steps.
- **Optional daily update check** for the top bar badge (off by default), signed updates unchanged.
- **Backup/restore** of `conf` + `sys.db` from the UI, with a verify step, and a documented restore drill.
- `-doctor` extended to cover the config (dangling certificates, rules with no upstream, port clashes).
- **Healthier defaults for new installs only** (never changed for existing ones): WAF in detection-only mode, sensible rate limit suggestions.

### 4b. Storage for analytics (proposal, needs a decision)
Statistics today are one JSON record per day, rewritten in full every 10 minutes. That design, not BoltDB itself, is why
`sys.db` grows and why long history and "average req/s per rule over a week" are hard.
- **Step 1, embedded (no new dependency):** replace the per-day blob with small time-bucketed rollups (per minute, then per hour/day) that are appended, not rewritten, with retention built in. Config and security data stay in BoltDB.
- **Step 2, a storage interface** for analytics only, so a backend can be chosen in settings.
- **Step 3, optional external backend: PostgreSQL, with TimescaleDB as the recommended flavour** (hypertables, compression, `drop_chunks` retention, continuous aggregates). Off by default; Dunree stays a single binary that runs with no database server. MySQL/MariaDB would add maintenance for no gain over Postgres, so only one external backend is proposed.
- Not proposed: moving config, certificates, users or the rules to an external database. They are small, must be readable at boot, and an unreachable database must never stop the proxy.

### 5. Security depth
- Rules engine v2: conditions on path, header, country, ASN, rate, bot score; actions allow / challenge / block / tag; reorderable, with a test box ("would this request match?").
- Per-site **mTLS and API-token** access modes with audit log.
- Admin: roles beyond admin/viewer (per-site editor), session list with remote sign-out, optional TOTP.

### 6. Quality and trust
- Browser coverage beyond Chromium (Firefox, WebKit) in the automated suite; screen-reader pass on the main flows.
- Real Fleet integration test (hub + 2 nodes) in CI, not mocks.
- Reviewed translations for the core UI strings (today machine translated).
- Upstream sync policy: merge upstream releases on a cadence, UI divergences documented (decision D5).

## Breaking changes allowed in 4.0 (and only here)
- Remove deprecated API routes kept for old UIs.
- Config schema version bump with an automatic, backed-up migration; **no rollback to 3.x without restoring the backup**.
- Menu and terminology changes finish (decision D4).

## Proposed order
1. **4.0-alpha.1** Live pillar finished, retention + daily check (opt-in), unsaved-changes bar.
2. **4.0-alpha.2** Dry run, config history UI, wildcard ACME DNS.
3. **4.0-beta** Rules engine v2, staged Fleet rollout, roles/TOTP.
4. **4.0** Migration, cross-browser + Fleet integration tests, release notes with a tested upgrade path from the last 3.x fork release.

## Decisions needed from you
1. Is the order right? What would you move up (the thing you hit most on Proxy2)?
2. Ok to allow the one schema bump + backed-up migration in 4.0?
3. Rules engine v2 and roles: do you want them in 4.0, or is "safe changes + certificates + operate it" enough for the first 4.0?
4. Storage: ok with step 1 (embedded rollups) first, then an optional PostgreSQL/TimescaleDB backend for analytics only?
5. Version naming: keep `-fork.N` suffix on 4.0 (e.g. `v4.0.0-fork.1`), or drop the suffix? (The updater requires the base to match `SYSTEM_VERSION`, so this also decides when that constant changes.)
