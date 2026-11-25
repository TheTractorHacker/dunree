# Dunree documentation

Dunree is a reverse proxy and web gateway, published by Foley IT under AGPL-3.0 and based on Zoraxy v3.3.6 by tobychui and imuslab. Start with the [README](../README.md) for what it is and how to install it. This page lists the documents in this folder.

## Install, update, migrate

| Document | What it covers |
|---|---|
| [Migrating from Zoraxy](migrating-from-zoraxy.md) | Replacing Zoraxy by Dunree on an existing install: what the first start does, cookies, environment variables, systemd, Docker, going back |
| [Running under systemd](deploy/README.md) | The reference service unit ([dunree.service](deploy/dunree.service)) and what each line is for |
| [Windows](deploy/windows.md), [macOS](deploy/macos.md) | The Windows service and the launchd job; the files are in [packaging/](../packaging/README.md) |
| [Updating](guides/updating.md) | The updater in the admin interface, manual update, rollback |
| [Docker](../docker/README.md) | Building and running the container image |
| [What is in sys.db](db-growth.md) | What the database holds, what makes it grow, how to compact it |

## Guides for common tasks

| Guide | Topic |
|---|---|
| [Certificates](guides/ssl-troubleshooting.md) | Creating certificates, DNS challenge, hosts on a private network, warnings |
| [Real client IP](guides/real-client-ip-cloudflare.md) | Cloudflare, tunnels, VPNs, TCP streams, access rules |
| [Path routes and rewriting](guides/url-rewrite-and-locations.md) | Sending a path to another server, rewriting paths |
| [WebSockets](guides/websockets-odoo-cleanslate-domoticz.md) | WebSockets, with Odoo, Hasura and Domoticz as examples |
| [Error pages and 521](guides/error-pages-and-521.md) | What the error pages mean, "521 Web server is down" |
| [Customisable error pages](errorpages.md) | Your own texts, theme and HTML for the pages Dunree shows |
| [CAPTCHA, phones and apps](guides/captcha-and-mobile-apps.md) | Challenge pages and clients that are not browsers |
| [CrowdSec](guides/crowdsec.md) | Using Dunree as a CrowdSec bouncer |
| [Performance](guides/performance-tuning.md) | High CPU under load: measure first, then tune |
| [NetBird](guides/netbird.md) | A self-hosted NetBird behind the proxy (gRPC over h2c) |
| [Two proxies in a segmented network](guides/enterprise-dual-proxy.md) | Modes, trust, failure and recovery |

## Sign-in

| Guide | Topic |
|---|---|
| [Authentik](authentik.md), [Authentik forward auth checklist](guides/authentik.md) | Forward auth and OpenID Connect with Authentik |
| [Authelia](guides/authelia.md) | Forward auth with Authelia |
| [Keycloak and groups](guides/keycloak-groups.md) | OpenID Connect with group rules |
| [Sign in with Google](guides/google-oauth2.md) | OpenID Connect with Google |
| [Pocket ID and Navidrome](guides/pocket-id-navidrome.md) | Passing the user name to an application in a header |

## Plugins and add-ons

| Document | What it covers |
|---|---|
| [Plugin contract](plugins/contract.md) | What Dunree and a plugin promise each other; Zoraxy and Dunree SDK |
| [Conformance kit](plugins/conformance.md) | Checking a plugin with `tools/plugin-check` |
| [Add-on store](plugins/addon-store.md) | Store sources, the signed index format, what Dunree checks before an install |
| [Publishing an add-on](plugins/publishing-addons.md) | Building and signing an index |
| [Reliability plan](plugins/reliability-plan.md) | How plugins are supervised, and why |
| [Plugin author pages](plugins/docs/index.md) | Introduction, architecture and examples for plugin authors |

## The admin interface

| Document | What it covers |
|---|---|
| [Screenshots](img/screenshots/README.md) | Pictures of the admin interface with captions: first start, Status, sites and the site editor, certificates, the security pages, statistics, uptime, add-ons, Fleet, error pages, About. Made from demo data by `tools/screenshots/run.sh` |
| [User-visible changes](ux/changes.md) | Every change of the interface and of behaviour, with known limits. The section "Dunree rebrand" lists what was renamed and what was kept. |
| [Design v2](ux/design-v2.md) | The design rules of the interface |
| [Component kit](ux/components.md) | The components and the navigation |
| [Terminology](ux/terminology.md) | Which word is used for what |
| [Site editor](ux/site-editor.md), [Rules builder](ux/rules-builder.md), [Why was this blocked?](ux/why-blocked.md) | Single features in detail |
| [Translating](translating.md) | How the translations work and how to add one |
| [Audit of November 2026](ux/audit-2026-11.md) | The audit the redesign started from |

## Project

| Document | What it covers |
|---|---|
| [Rebrand plan](rebrand/plan.md) | Inventory and decisions of the rename from Zoraxy to Dunree |
| [Roadmap history](roadmap-history.md), [4.0 plan (draft)](roadmap-4.0.md) | Plans from before the Dunree version line. The current roadmap is [ROADMAP.md](../ROADMAP.md). |
| [Enterprise dual-proxy plan](enterprise-dual-proxy-plan.md), [assessment](enterprise-assessment.md) | Audit and result of the work for segmented networks |
| [Verification](verification/) | Evidence of the end-to-end test runs |
| [Triage](triage/) | Review of issues of the Zoraxy project, kept as history |
| [Brand](../brand/README.md) | Logo, colours and the rules for using them |

## The index page

[index.html](index.html) is a plain static page that lists the documents above, so that this folder can be put on a web
server as it is. It is written by `tools/docs/build_index.py` (do not edit it by hand), uses copies of the logo files of
`brand/` (`img/brand/`) and of the licence files (`legal/`), loads nothing from another host and links nowhere outside
this folder. `tools/docs/test_docs.py` checks that. It is not a product website: there is none yet.

The sources of the website of the Zoraxy project that came with the code (its start page, the page about its sign-in <!-- rebrand:keep -->
portal, the nginx converter page, their scripts, styles, pictures and old screenshots) were removed, and so was
`docs/CNAME`, which named the address of that website: nothing in this folder can publish that site or claim its address.
