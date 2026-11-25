# Screenshots of Dunree

<!-- written by tools/screenshots/capture.py (--docs-only) from its SHOTS list; do not edit by hand -->

The pictures show a throw-away instance with demo data: sites under `example.com`, upstream servers on loopback addresses, generated traffic. They are made by `tools/screenshots/run.sh`. Nothing in them comes from a real installation.

Desktop pictures are 1440 x 900 at twice the pixel density (2880 x 1800 pixels), the phone picture is 390 x 844 (780 x 1688). `manifest.json` lists the files. To make them again, see [How they are made](#how-they-are-made).

## Status

![Status](status.png)

Status: is the proxy running, how much traffic it handles and what needs attention.

## Status, dark theme

![Status, dark theme](status-dark.png)

The same page in the dark theme. Every page has both.

## HTTP Proxy

![HTTP Proxy](sites.png)

Sites > HTTP Proxy: every host name, where it is sent, its tags, protection and live state.

## Edit site: upstreams and load balancing

![Edit site: upstreams and load balancing](site-editor.png)

Edit site: several upstream servers behind one host name, with weights, health and fallback.

## Certificates

![Certificates](certificates.png)

Certificates: what each certificate covers, who issued it and when it expires.

## Security Overview

![Security Overview](security-overview.png)

Security > Security Overview: what protects the sites, with a recommendation for each gap.

## Security Center

![Security Center](security-center.png)

Security Center: deployment role, network exposure, auto-ban, bots, admin accounts and the audit log.

## WAF

![WAF](waf.png)

Security > WAF: the web application firewall (OWASP Core Rule Set), its mode per site and what it stopped.

## Rules

![Rules](rules.png)

Security > Rules: when a request matches, block it, challenge it, limit its rate or only log it.

## CrowdSec

![CrowdSec](crowdsec.png)

Security Center > CrowdSec: Dunree as a CrowdSec bouncer, with the decisions that are loaded and what they matched.

## Statistics

![Statistics](statistics.png)

Traffic > Statistics: requests, errors, blocked requests and visitors, in total and for each site.

## Statistics: visitors and devices

![Statistics: visitors and devices](statistics-visitors.png)

Further down the Statistics page: countries, the most active addresses, referring sites, devices and browsers.

## Uptime Monitor

![Uptime Monitor](uptime.png)

Traffic > Uptime Monitor: the upstream servers, checked every few minutes.

## Add-ons, no source

![Add-ons, no source](addons-empty.png)

System > Add-ons on a new install: no store is built in, you add a source yourself.

## Add-ons with a local index

![Add-ons with a local index](addons.png)

System > Add-ons with a signed index from a local folder.

## Fleet

![Fleet](fleet.png)

Fleet & HA > Fleet: one Dunree as the hub of several others, with groups and staged roll-out.

## Cluster / HA

![Cluster / HA](cluster.png)

Fleet & HA > Cluster / HA: the role of this node.

## Error pages

![Error pages](error-pages.png)

Sites > Error pages: your own texts, colours and HTML for the pages Dunree shows, with a preview.

## About Dunree

![About Dunree](about.png)

System > Utilities > About Dunree: version, publisher, licence, source code and the project Dunree is based on.

## First start

![First start](setup.png)

First start: the page that creates the administrator account.

## Login

![Login](login.png)

The login page.

## Status on a phone

<img src="status-phone.png" alt="Status on a phone" width="320">

The Status page at 390 px. The whole interface works at phone width.

## How they are made

```sh
PY=/path/to/python-with-playwright PORT=25600 tools/screenshots/run.sh              # about 15 minutes
PY=... MINUTES=30 tools/screenshots/run.sh                                         # fuller charts
python3 tools/screenshots/capture.py --docs-only                                   # only rewrite this page and the README section
python3 tools/screenshots/test_screenshots.py                                      # check files, sizes and texts
```

`run.sh` builds Dunree from this checkout and starts `capture.py`, which starts throw-away instances in a temp folder, fake backends and demo traffic, takes the pictures and writes this page and the section of the top-level README. The list of pictures, their captions and the demo data are at the top of `tools/screenshots/capture.py`. Numbers, times and charts differ from run to run. What the pictures do not show is in [the notes on the user-visible changes](../../ux/changes.md) under "Screenshots".
