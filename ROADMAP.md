# Dunree roadmap

What is planned for Dunree, the reverse proxy and web gateway published by Foley IT. It lists open work only. What was done before the Dunree version line started is in [`docs/roadmap-history.md`](docs/roadmap-history.md); what changed in each version is in [`CHANGELOG.md`](CHANGELOG.md).

Rules for every item: existing installs keep working, new behaviour is off or log-only by default, it has an automated test, and it is described with its known limits in `docs/ux/changes.md`. The licence stays AGPL-3.0.

Nothing here is a promise or has a date.

## 1.0: from beta to release

- **Project home.** Decide the repository address, the release download location, the container image name, the documentation site and the security contact, and set them in the one place each is defined (`tools/rebrand/policy.json`, `src/mod/brand`, `SECURITY.md`, `CODEOWNERS`).
- **Releases under the Dunree name.** Signed release files named `dunree_<os>_<arch>`, an updater that knows a Dunree 1.x release is newer than every Zoraxy 3.x build, and an official container image.
- **Dunree add-on store.** A signed index run by Foley IT. Until then Dunree ships without a store.
- **Finish the rename.** The remaining old names that are shown to people (see "Known limits" in `docs/ux/changes.md`, section "Dunree rebrand"), with the legacy names kept for other programs for the whole 1.x line.
- **Screenshots and documentation** for Dunree: screenshots in `docs/img/screenshots/`, guides checked against Dunree, a documentation site.
- **Translations.** Review by native speakers; more texts in the languages other than English and Chinese.

## Verification against real services

Several features were tested only against stand-ins. Each needs one run against the real thing:

- Authentik, Keycloak, Entra, Google and GitHub logins; Authelia forward auth
- ACME issuance on a staging authority (HTTP and DNS challenge, external account binding)
- one real message per notification channel
- Encrypted Client Hello in real browsers
- Sablier and zrok
- high availability on separate hosts behind a real virtual address
- a plugin built for Zoraxy with the original SDK, on a real install

## Security

- Per-user API tokens and roles finer than administrator and viewer
- Sign-in protection for the admin interface: rate limit, lock-out, optional second factor for administrators
- Certificate revocation (CRL, OCSP) for client certificates
- WAF: response inspection, paranoia level per path, an update flow for the rule set, export of events
- Count failed SSO redirects in the automatic ban

## Sites and routing

- Sign-in provider per path, not only per site
- Rule templates that can set the sign-in provider, CORS and the access rule
- Bandwidth limit for WebSocket traffic; PROXY protocol for WebSocket and stream proxy upstreams
- Load balancing by hash of the path

## Certificates

- ACME renewal information (ARI)
- Publish the Encrypted Client Hello record through a DNS provider
- A maintained GeoIP data set

## Traffic and monitoring

- Structured (JSON) access log
- Keep the notification delivery log and undelivered messages across a restart
- City-level location and an hourly history for visitors

## High availability and Fleet

- Synchronise the remaining database settings (timeouts, PROXY protocol, HTTP/3, GeoIP, plugins)
- Shared sign-out across nodes
- A second hub for Fleet; signed bundles in place of a shared secret
- Central WAF policy as a Fleet scope

## Plugins and add-ons

- Time budget per request and metrics per plugin
- An operating-system user per plugin
- Channels and older versions in an add-on index; a key per store source

## Admin interface

- Request count per site in the sites list
- Script versions and a snippet library for Lua scripts
- Plural forms and right-to-left languages
