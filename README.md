<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/dunree-lockup-dark.svg">
    <img src="brand/dunree-lockup.svg" alt="Dunree" width="300">
  </picture>
</p>

# Dunree

**Reverse proxy and web gateway.** Published by Foley IT. Open source under [AGPL-3.0](LICENSE).

Dunree puts your web services behind one gateway: it routes host names to the right server, handles HTTPS certificates, checks who and what comes in, and shows you what happened. Everything is set up in a web interface. It is one program, written in Go, with no database server and no other service to install.

Dunree is based on Zoraxy v3.3.6 by tobychui and imuslab. It is an independent project and is not endorsed by them; see [Licence and attribution](#licence-and-attribution). The Dunree version line starts at **v1.0.0-beta.1**.

> [!NOTE]
> Dunree is in beta. The project home (repository address, release downloads, container image, security contact) is not final yet. Where this page would name such an address, it says so instead of naming one.

## Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Install](#install)
- [Migrating from Zoraxy](#migrating-from-zoraxy)
- [Plugins and add-ons](#plugins-and-add-ons)
- [Documentation](#documentation)
- [Security policy](#security-policy)
- [Contributing](#contributing)
- [Licence and attribution](#licence-and-attribution)

## Features

### Sites and routing

- HTTP reverse proxy for any number of host names, with alias and wildcard host names, HTTP/2, HTTP/3 and automatic WebSocket and gRPC support
- Path routes (send a path of a site to another server), redirection rules, a default site for unknown host names
- Load balancing: round robin, weighted, least connections, least response time, IP hash, consistent hash, by client network or country; active and passive health checks, retries, draining
- Upstreams over HTTP, HTTPS, h2c or a Unix socket; upstream client certificates and PROXY protocol
- Custom headers, CORS, static responses, variables such as `{{host}}` and `{{client_ip}}`, rule templates, bulk edit
- Stream proxy for TCP and UDP
- Static web server with WebDAV
- Customisable error pages (403, 404, 429, 502, 503, 521 and more), per site or for all sites
- Optional per-site Lua scripts, start-on-demand with Sablier, tunnels with zrok

### Certificates and TLS

- Certificates from Let's Encrypt and other ACME authorities, with automatic renewal, HTTP and DNS challenge and many DNS providers (through [lego](https://go-acme.github.io/lego/dns/))
- Saved certificate authorities (ZeroSSL, Google, a private ACME server) and reusable DNS credentials
- Upload, signing requests, certificates from a watched folder, SNI and fallback certificate
- Client certificate authentication (mTLS) per site
- Encrypted Client Hello
- Webhooks and an optional command when a certificate is renewed or about to expire

### Security

- Web application firewall: [Coraza](https://github.com/corazawaf/coraza) with the OWASP Core Rule Set, central policy with profiles and exclusions, detection-only mode
- Rules builder ("when ... then ..."): block, allow, redirect, challenge, rate limit or only log, by country, address, path, header and more
- Access rules: allow and block lists by address, network or country, bulk import and scheduled block lists
- CAPTCHA challenge pages (Cloudflare Turnstile, reCAPTCHA, Friendly Captcha, Altcha) with your own texts, colours and logo
- Single sign-on: OAuth2 and OpenID Connect with several providers, forward auth (Authelia, Authentik), and a built-in login portal with 2FA and passkeys
- CrowdSec bouncer, automatic bans, bot rules, rate limits, basic auth
- Security overview with a score and one-click fixes; "why was this blocked" by reference ID
- Admin interface: several accounts with roles, audit log, optional HTTPS, API tokens

### Traffic and monitoring

- Status page with live traffic, upstream health and certificate expiry
- Statistics per site, visitors list, blocked requests with the reason
- Access log search with live view and export; log files per site
- Uptime monitor
- Notifications: e-mail, Discord, Slack, Telegram, ntfy, Gotify, Pushover and webhooks
- Prometheus metrics

### Operations

- Every change is saved as a version: compare, undo, go back
- Backup and restore of the whole configuration, with a dry run
- Signed releases; an updater that verifies the signature, keeps the previous program and can roll back
- High availability: followers copy the configuration of a primary; central management of many nodes ("Fleet") with staged roll-out
- REST API (`/api/v1`) with an OpenAPI description
- Works offline (`-offline`); a `-doctor` check for a start that fails
- Admin interface in English with machine-assisted translations (Chinese, German, Spanish, French, Japanese, Portuguese, Russian), light and dark theme

### Extending

- Plugins: separate programs that filter requests, serve pages or react to events, supervised by Dunree
- Add-on store: none is built in; you add a signed index by address or from a local folder. See [Plugins and add-ons](#plugins-and-add-ons).

Network tools (IP and port scanner, mDNS, Wake-on-LAN, web SSH, DNS / TLS / HTTP tests) are part of the admin interface.

## Screenshots

<!-- screenshots:begin written by tools/screenshots/capture.py (--docs-only) from its SHOTS list; do not edit by hand -->

[![Status](docs/img/screenshots/status.png)](docs/img/screenshots/status.png)

Status: is the proxy running, how much traffic it handles and what needs attention.

| | |
|---|---|
| [![Status, dark theme](docs/img/screenshots/status-dark.png)](docs/img/screenshots/status-dark.png)<br>The same page in the dark theme. Every page has both. | [![HTTP Proxy](docs/img/screenshots/sites.png)](docs/img/screenshots/sites.png)<br>Sites > HTTP Proxy: every host name, where it is sent, its tags, protection and live state. |
| [![Edit site: upstreams and load balancing](docs/img/screenshots/site-editor.png)](docs/img/screenshots/site-editor.png)<br>Edit site: several upstream servers behind one host name, with weights, health and fallback. | [![Certificates](docs/img/screenshots/certificates.png)](docs/img/screenshots/certificates.png)<br>Certificates: what each certificate covers, who issued it and when it expires. |
| [![Security Overview](docs/img/screenshots/security-overview.png)](docs/img/screenshots/security-overview.png)<br>Security > Security Overview: what protects the sites, with a recommendation for each gap. | [![WAF](docs/img/screenshots/waf.png)](docs/img/screenshots/waf.png)<br>Security > WAF: the web application firewall (OWASP Core Rule Set), its mode per site and what it stopped. |
| [![Rules](docs/img/screenshots/rules.png)](docs/img/screenshots/rules.png)<br>Security > Rules: when a request matches, block it, challenge it, limit its rate or only log it. | [![CrowdSec](docs/img/screenshots/crowdsec.png)](docs/img/screenshots/crowdsec.png)<br>Security Center > CrowdSec: Dunree as a CrowdSec bouncer, with the decisions that are loaded and what they matched. |
| [![Statistics](docs/img/screenshots/statistics.png)](docs/img/screenshots/statistics.png)<br>Traffic > Statistics: requests, errors, blocked requests and visitors, in total and for each site. | [![Uptime Monitor](docs/img/screenshots/uptime.png)](docs/img/screenshots/uptime.png)<br>Traffic > Uptime Monitor: the upstream servers, checked every few minutes. |
| [![Add-ons with a local index](docs/img/screenshots/addons.png)](docs/img/screenshots/addons.png)<br>System > Add-ons with a signed index from a local folder. | [![Fleet](docs/img/screenshots/fleet.png)](docs/img/screenshots/fleet.png)<br>Fleet & HA > Fleet: one Dunree as the hub of several others, with groups and staged roll-out. |
| [![Error pages](docs/img/screenshots/error-pages.png)](docs/img/screenshots/error-pages.png)<br>Sites > Error pages: your own texts, colours and HTML for the pages Dunree shows, with a preview. | [![About Dunree](docs/img/screenshots/about.png)](docs/img/screenshots/about.png)<br>System > Utilities > About Dunree: version, publisher, licence, source code and the project Dunree is based on. |
| [![Login](docs/img/screenshots/login.png)](docs/img/screenshots/login.png)<br>The login page. | |

<img src="docs/img/screenshots/status-phone.png" alt="Status on a phone" width="260">

The Status page at 390 px. The whole interface works at phone width.

The pictures show a throw-away instance with demo data: sites under `example.com`, upstream servers on loopback addresses, generated traffic. They are made by `tools/screenshots/run.sh`. All 22 pictures, with the first-start page and more of the security and statistics pages, are in [docs/img/screenshots](docs/img/screenshots/README.md).

<!-- screenshots:end -->

## Install

Dunree is one program file. It keeps its data in the folder it is started from: `conf/` (configuration and certificates), `sys.db` (database), `log/`, `www/` and `plugins/`. Always start it from the same folder, or give the paths with `-conf`, `-dbpath` and so on.

After the start, open `http://<address of the server>:8000` and create the administrator account. From another machine you need the one-time setup token that Dunree prints to the console and the log at its first start.

Ports: `8000` for the admin interface (change with `-port`), `80` and `443` for your sites. Do not make port 8000 reachable from the internet.

### Releases

Official release files and a container image are not published yet (beta, the project home is not final). Until they are, build from source. Official releases will be signed; the updater in the admin interface only installs a release whose signature it can verify.

### Build from source (all platforms)

You need [Go](https://go.dev/dl/) 1.26 or newer and the source code of Dunree.

```bash
cd dunree/src
go build -o dunree .
./dunree -version
```

Cross-compile for another system with `GOOS` and `GOARCH`, for example `GOOS=linux GOARCH=arm64 go build -o dunree_linux_arm64 .`.

### Linux

```bash
sudo mkdir -p /opt/dunree && sudo cp dunree /opt/dunree/
cd /opt/dunree
sudo ./dunree -port=:8000
```

To run it as a service, use the systemd unit `packaging/linux/dunree.service` (or `packaging/linux/install.sh`, see [`packaging/`](packaging/README.md)) and the notes in [`docs/deploy/`](docs/deploy/README.md). An install upgraded from Zoraxy keeps its `zoraxy.service` and `/opt/zoraxy`.

Raspberry Pi and other ARM boards: build with `GOARCH=arm64` (64-bit systems) or `GOARCH=arm` (32-bit).

### Windows

Build `dunree.exe` (`GOOS=windows GOARCH=amd64 go build -o dunree.exe .`), put it in its own folder and start it from a terminal in that folder:

```
dunree.exe -port=:8000
```

Web SSH, limits for plugins and the in-app updater are for Linux only.

### macOS and FreeBSD

Build from source as above and start it the same way as on Linux. These systems are built but are tested less than Linux.

### Docker

There is no official Dunree image yet, so build it yourself from the repository root:

```bash
docker build -f packaging/container/Dockerfile -t dunree:local .
```

Keep the configuration in a volume, publish ports 80, 443 (TCP and UDP) and 8000, and read [`docker/README.md`](docker/README.md) for the options. The compose files take the image name from `DUNREE_IMAGE` (`packaging/container/compose.yaml` builds it for you).

### Start options

`./dunree -help` lists every option. The ones used most:

| Option | Meaning |
|---|---|
| `-port :8000` | address and port of the admin interface |
| `-conf ./conf`, `-dbpath ./sys.db`, `-log ./log` | where configuration, database and logs are kept |
| `-webui_tls auto` | HTTPS for the admin interface with a self-signed certificate (`custom` for your own) |
| `-csrf_trusted_origins host[:port],...` | extra addresses from which the admin interface may be used, for a reverse proxy in front of it that replaces the Host header (empty by default; see DEVELOPMENT.md) |
| `-noauth` | no login for the admin interface. Only behind another gateway that does the login. |
| `-reset_ac` | reset the administrator account and exit |
| `-doctor` | check why a start fails (ports, files, database) and exit |
| `-offline` | no outbound connections at start-up or in the background |
| `-metrics` | Prometheus metrics |
| `-version` | print the version and exit |

## Migrating from Zoraxy

An install that runs Zoraxy today (3.3.x from the Zoraxy project, or a `v3.3.6-fork.N` build) keeps working when its program file is replaced by Dunree. Nothing is converted.

1. Take a backup of `conf/`, `sys.db` and `sys.uuid`.
2. Stop the service, replace the program file with the Dunree build, start the service.
3. At its first start Dunree copies the configuration folder and the database aside, once, and says so in the log.

Sites, certificates, accounts, API tokens and plugins are used as they are. Administrators stay logged in. Names that other programs know (`X-Zoraxy-*` headers, `/.zoraxy/` paths, `zoraxy_*` metrics, `ZORAXY_*` environment variables, the service and folder names) keep working; Dunree adds its own names next to them.

The full description, including systemd, Docker and how to go back, is in [`docs/migrating-from-zoraxy.md`](docs/migrating-from-zoraxy.md). What changed and what did not is listed in [`docs/ux/changes.md`](docs/ux/changes.md), section "Dunree rebrand".

## Plugins and add-ons

A plugin is a separate program that Dunree starts and supervises. It can filter requests, capture paths, serve its own pages in the admin interface and react to events. Plugins that were built for Zoraxy run without being rebuilt.

- Write a plugin: [`docs/plugins/contract.md`](docs/plugins/contract.md) (the contract between Dunree and a plugin), the SDK in `src/mod/plugins/dunree_plugin`, examples in [`example/plugins/`](example/plugins/).
- Check a plugin: [`docs/plugins/conformance.md`](docs/plugins/conformance.md) and the tool in `tools/plugin-check`.
- Add-on store: Dunree ships **without a store** and contacts none until an administrator adds one under *System > Add-ons*: an index by address, or a local folder. The index is signed. Format and behaviour: [`docs/plugins/addon-store.md`](docs/plugins/addon-store.md). Publishing your own: [`docs/plugins/publishing-addons.md`](docs/plugins/publishing-addons.md).
- A Dunree add-on store run by Foley IT does not exist yet.

A plugin runs with the rights of the Dunree process (or of the user set with `-plugin_user`). Install only plugins you trust.

## Documentation

The documentation is in [`docs/`](docs/README.md): guides for common tasks, deployment, plugins, and the notes on the design of the admin interface. Notes for developers are in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Security policy

Please report a vulnerability privately, not in a public issue. How to report and what to expect is in [`SECURITY.md`](SECURITY.md).

Do not report Dunree vulnerabilities to the Zoraxy project. If you believe a problem is also in Zoraxy, say so in your report.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Changes are listed in [`CHANGELOG.md`](CHANGELOG.md), plans in [`ROADMAP.md`](ROADMAP.md).

## Licence and attribution

Dunree is free software under the **GNU Affero General Public License, version 3** ([`LICENSE`](LICENSE)). If you change Dunree and let other people use your version over a network, the licence requires you to offer them the source code of your version.

**Dunree is based on [Zoraxy](https://github.com/tobychui/zoraxy) v3.3.6 by tobychui and imuslab**, which is published under the same licence.

- Dunree is a modified, independent derivative of Zoraxy. It is not affiliated with or endorsed by tobychui, imuslab or the Zoraxy contributors.
- The parts written for Dunree are the work of Foley IT and its contributors. They are not the work of the Zoraxy authors.
- The copyright headers of the original authors, `LICENSE` and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) are kept. [`NOTICE`](NOTICE) says the same in full.
- Parts of Zoraxy were contributed by its community, among them forward auth (`james-d-elliott`), OAuth2 (`kjagosz`), the DNS challenge (`zen8841`), the Docker container list (`eyerrock`), Docker support (`PassiveLemon`), the stream proxy (`jemmy1794`) and the plugin and event systems (`AnthonyMichaelTDM`). The history of each release of Zoraxy is kept in [`CHANGELOG.md`](CHANGELOG.md). These people are not involved in Dunree: please do not tag them in Dunree issues.
- Third-party components and their licences: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

The name comes from Fort Dunree on Lough Swilly in County Donegal (Irish *dún*, a fort). The Dunree name and logo identify the releases of Foley IT; the licence covers the code, not the name or the logo. See [`brand/README.md`](brand/README.md).

Dunree comes without warranty. If you got it from someone other than Foley IT, that party is responsible for what they gave you.
