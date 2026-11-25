#!/usr/bin/env python3
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Write docs/index.html, the plain index page of the Dunree documentation.

    python3 tools/docs/build_index.py            write docs/index.html
    python3 tools/docs/build_index.py --check    exit 1 when docs/index.html is not what this script writes

The page is static HTML with its styles inside: no script, no font, picture or style from another
host, and every link stays inside docs/, so the folder can be put on any web server as it is.  The
logo and icons are copies of files in brand/ (docs/img/brand/), the licence files are copies of the
ones in the repository root (docs/legal/).  tools/docs/test_docs.py checks all of that.

To list a new document: add it to SECTIONS below and run this script.  A guide in docs/guides/ that
is not listed fails the test.
"""
import html
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "docs", "index.html")

# (heading, intro, [(href relative to docs/, title, what it covers)])
SECTIONS = [
    ("Install, update, migrate", "", [
        ("deploy/README.md", "Running under systemd", "The reference service unit, what each line is for, the -doctor check"),
        ("deploy/dunree.service", "dunree.service", "The reference unit itself, a comment on every line"),
        ("deploy/windows.md", "Windows", "The Windows service, install script, paths"),
        ("deploy/macos.md", "macOS", "The launchd job, the package, paths"),
        ("guides/updating.md", "Updating", "In-app update, update by hand, containers, rollback"),
        ("migrating-from-zoraxy.md", "Migrating from Zoraxy", "What the first Dunree start does on an existing install, and how to go back"),
        ("db-growth.md", "What is in sys.db", "What the database holds, what makes it grow, how to compact it"),
    ]),
    ("Guides for common tasks", "", [
        ("guides/ssl-troubleshooting.md", "Certificates", "Creating certificates, DNS challenge, hosts on a private network, warnings"),
        ("guides/real-client-ip-cloudflare.md", "Real client IP", "Cloudflare, tunnels, VPNs, TCP streams, access rules"),
        ("guides/url-rewrite-and-locations.md", "Path routes and rewriting", "Sending a path to another server, rewriting paths"),
        ("guides/websockets-odoo-cleanslate-domoticz.md", "WebSockets", "WebSockets, with Odoo, Hasura and Domoticz as examples"),
        ("guides/error-pages-and-521.md", "Error pages and 521", "What the error pages mean, \"521 Web server is down\""),
        ("errorpages.md", "Customisable error pages", "Your own texts, theme and HTML for the pages Dunree shows"),
        ("guides/captcha-and-mobile-apps.md", "CAPTCHA, phones and apps", "Challenge pages and clients that are not browsers"),
        ("guides/crowdsec.md", "CrowdSec", "Using Dunree as a CrowdSec bouncer"),
        ("guides/performance-tuning.md", "Performance", "High CPU under load: measure first, then tune"),
        ("guides/netbird.md", "NetBird", "A self-hosted NetBird behind the proxy (gRPC over h2c)"),
        ("guides/enterprise-dual-proxy.md", "Two proxies in a segmented network", "Modes, trust, failure and recovery"),
    ]),
    ("Sign-in", "", [
        ("authentik.md", "Authentik", "Forward auth and OpenID Connect with Authentik"),
        ("guides/authentik.md", "Authentik forward auth checklist", "The short path and the 404 checklist"),
        ("guides/authelia.md", "Authelia", "Forward auth with Authelia"),
        ("guides/keycloak-groups.md", "Keycloak and groups", "OpenID Connect with group rules"),
        ("guides/google-oauth2.md", "Sign in with Google", "OpenID Connect with Google"),
        ("guides/pocket-id-navidrome.md", "Pocket ID and Navidrome", "Passing the user name to an application in a header"),
    ]),
    ("Plugins and add-ons", "", [
        ("plugins/addon-store.md", "Add-on store", "Store sources, the signed index format, what Dunree checks before an install"),
        ("plugins/publishing-addons.md", "Publishing an add-on", "Building and signing an index"),
        ("plugins/contract.md", "Plugin contract", "What Dunree and a plugin promise each other"),
        ("plugins/conformance.md", "Conformance kit", "Checking a plugin before you publish it"),
    ]),
    ("The admin interface", "", [
        ("img/screenshots/README.md", "Screenshots", "Pictures of the admin interface with captions, made from demo data"),
        ("ux/changes.md", "User-visible changes", "Every change of the interface and of behaviour, with known limits"),
        ("ux/terminology.md", "Terminology", "Which word is used for what"),
        ("translating.md", "Translating", "How the translations work and how to add a language"),
    ]),
    ("Everything else", "", [
        ("README.md", "Full list of documents", "Design notes, plans, verification records and the history of the project"),
    ]),
]

CSS = """
:root { --bg:#fafafa; --surface:#fff; --text:#1c2027; --muted:#5b6472; --line:#dfe3ea; --link:#1a56c4; --accent:#1a56c4; --note:#eef3fd; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0f1217; --surface:#171b22; --text:#f2f2f4; --muted:#9aa3b2; --line:#2a303b; --link:#6d9bff; --accent:#6d9bff; --note:#18233a; }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
main, header, footer { max-width: 60rem; margin: 0 auto; padding: 0 1.25rem; }
header { padding-top: 2.5rem; }
.logo { display: block; height: 3rem; width: auto; }
.logo--dark { display: none; }
@media (prefers-color-scheme: dark) { .logo--light { display: none; } .logo--dark { display: block; } }
h1 { margin: 1.5rem 0 .25rem; font-size: 1.75rem; line-height: 1.25; }
.lead { margin: 0 0 1.5rem; color: var(--muted); font-size: 1.125rem; }
h2 { margin: 2.5rem 0 .75rem; padding-bottom: .4rem; border-bottom: 1px solid var(--line); font-size: 1.2rem; }
p { margin: 0 0 1rem; max-width: 46rem; }
a { color: var(--link); text-underline-offset: 3px; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 2px; }
code { font: .9em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--note); padding: .1em .35em; border-radius: 4px; overflow-wrap: anywhere; }
.note { margin: 0 0 1rem; padding: 1rem 1.25rem; background: var(--note); border-left: 4px solid var(--accent); border-radius: 6px; }
.note p:last-child, .note ul:last-child { margin-bottom: 0; }
.note ul { margin: 0 0 1rem; padding-left: 1.25rem; }
dl { margin: 0; display: grid; grid-template-columns: minmax(12rem, 18rem) 1fr; gap: .5rem 1.5rem; }
dt { font-weight: 600; }
dd { margin: 0; color: var(--muted); }
@media (max-width: 40rem) { dl { grid-template-columns: 1fr; gap: 0; } dd { margin-bottom: .75rem; } }
footer { margin-top: 3rem; padding-top: 1.25rem; padding-bottom: 3rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .9375rem; }
footer p { max-width: none; }
"""


def esc(s):
    return html.escape(s, quote=True)


def build():
    out = []
    w = out.append
    w("<!DOCTYPE html>")
    w("<!-- Written by tools/docs/build_index.py: change that file and run it, do not edit this page by hand. -->")
    w('<html lang="en">')
    w("<head>")
    w('<meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width, initial-scale=1">')
    w("<title>Dunree documentation</title>")
    w('<meta name="description" content="Documentation of Dunree, a reverse proxy and web gateway published by Foley IT under AGPL-3.0.">')
    w('<meta name="color-scheme" content="light dark">')
    w('<link rel="icon" href="img/brand/favicon.svg" type="image/svg+xml">')
    w('<link rel="icon" href="img/brand/favicon-32.png" sizes="32x32" type="image/png">')
    w('<link rel="apple-touch-icon" href="img/brand/apple-touch-icon-180.png">')
    w("<style>" + CSS + "</style>")
    w("</head>")
    w("<body>")
    w("<header>")
    w('<img class="logo logo--light" src="img/brand/dunree-lockup.svg" alt="Dunree" width="299" height="64">')
    w('<img class="logo logo--dark" src="img/brand/dunree-lockup-dark.svg" alt="Dunree" width="299" height="64">')
    w("<h1>Dunree documentation</h1>")
    w('<p class="lead">Reverse proxy and web gateway. Published by Foley IT under AGPL-3.0.</p>')
    w("</header>")
    w("<main>")
    w('<div class="note">')
    w("<p><strong>What this page is.</strong> A plain list of the documents that come with the Dunree source code. It is not a product website.</p>")
    w("<ul>")
    w("<li>There is no download and no published container image yet. Dunree is built from source: <code>cd src &amp;&amp; go build -o dunree</code>. The file <code>README.md</code> in the root of the repository says how to install it on each system.</li>")
    w("<li>The documents are Markdown files. A git host shows them formatted; a plain web server shows them as text.</li>")
    w("<li>Some documents link to files outside this folder (<code>README.md</code>, <code>docker/</code>, <code>packaging/</code>, the source code). Those links only work in a copy of the repository.</li>")
    w("</ul>")
    w("</div>")
    for heading, intro, items in SECTIONS:
        w("<section>")
        w("<h2>%s</h2>" % esc(heading))
        if intro:
            w("<p>%s</p>" % esc(intro))
        w("<dl>")
        for href, title, what in items:
            w('<dt><a href="%s">%s</a></dt><dd>%s</dd>' % (esc(href), esc(title), esc(what)))
        w("</dl>")
        w("</section>")
    w("<section>")
    w("<h2>Licence and attribution</h2>")
    w("<p>Dunree is free software under the GNU Affero General Public License, version 3. Copyright &copy; 2026 Foley IT.</p>")
    w("<p>Dunree is based on Zoraxy v3.3.6, copyright &copy; 2021-2026 tobychui and imuslab and the Zoraxy contributors, also under AGPL-3.0. Dunree is a modified, independent derivative. It is not affiliated with, sponsored by or endorsed by tobychui, imuslab or the Zoraxy contributors: please do not report Dunree problems to the Zoraxy project.</p>")
    w("<dl>")
    w('<dt><a href="legal/LICENSE.txt">LICENSE</a></dt><dd>The full text of the licence</dd>')
    w('<dt><a href="legal/NOTICE.txt">NOTICE</a></dt><dd>Attribution: what Dunree is based on, who wrote what, names and logos, where the source code is offered</dd>')
    w('<dt><a href="legal/THIRD_PARTY_NOTICES.txt">Third-party notices</a></dt><dd>The components Dunree contains and their licences</dd>')
    w("</dl>")
    w("</section>")
    w("</main>")
    w("<footer>")
    w("<p>Dunree &middot; Reverse proxy and web gateway &middot; Published by Foley IT. Based on Zoraxy by tobychui and imuslab. AGPL-3.0.</p>")
    w("</footer>")
    w("</body>")
    w("</html>")
    return "\n".join(out) + "\n"


def main():
    text = build()
    if "--check" in sys.argv[1:]:
        try:
            with open(OUT, encoding="utf-8") as fh:
                have = fh.read()
        except OSError:
            have = ""
        if have != text:
            print("docs/index.html is not what tools/docs/build_index.py writes: run the script", file=sys.stderr)
            return 1
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote", os.path.relpath(OUT, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
