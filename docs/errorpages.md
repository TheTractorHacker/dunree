# Customisable error pages

Admin UI: **Sites > Error pages**. Code: `src/mod/errorpages` (store, validation, rendering), `src/mod/dynamicproxy/errorpages_hook.go`
(request side), `src/errorpagesapi.go` (admin API), `src/web/components/errorpages.html` (page).

## What it does

Zoraxy answers some requests by itself: a block (403), a 404, a rate limit (429), "the server behind this site is down" (521 / 504),
the "not found" page of the Default Site and a 503 when every upstream is busy. This feature lets the owner change what the visitor sees
in those cases:

* a **theme**: name or logo, accent colour, footer, whether the reference and the visitor's own address are shown;
* per **page class**: a title and a message (shown on the themed built-in page), or a whole HTML template;
* optionally per **site**: the same, for one host name or one `*.example.com` wildcard.

## Default: off, and byte-identical

Nothing changes until the owner saves a customisation **and** switches on "Use my error pages". With the switch off, without the file,
or for a page class (or host) that was not customised, every caller writes exactly the bytes, status and headers it always wrote
(`TestErrorPages_DisabledIsByteIdentical`). Switching it off keeps what was saved. "Reset to built-in" deletes the file.

## Page classes

| Class | Status | Served when |
|---|---|---|
| `403` Access denied | 403 | access rules, countries, WAF, auto-ban, CrowdSec, bot rules, security rules (block / challenge unavailable), header rules, allowed peers, path rules, "Block common exploits" and "Block AI crawlers" with the 403 action |
| `404` Not found | 404 | the upstream host name cannot be resolved, no upstream on the plain-HTTP path, a header rule that answers 404, "Block common exploits" and "Block AI crawlers" with the 404 action |
| `429` Too many requests | 429 | rate limit of a site, of a path rule, of a security rule (built in, the first two have no body) |
| `5xx` Server error | 521, 504 | the upstream is down or refuses the connection (521), a route timeout answered by Zoraxy (504) |
| `nohost` No such host | 404 | Default Site set to "not found page" and no site matches the host name |
| `maintenance` Busy or maintenance | 503 | every upstream of the site is at its connection limit |

Resolution for a request: page of the exact host, else of the longest matching `*.wildcard`, else the page of all sites, else (only when
"Use this look for every page" is on) the themed built-in page, else the built-in answer of Zoraxy.

## Templates

`html/template`, at most 256 KiB each (8 MiB in total, 64 hosts), rendered page at most 1 MiB. Values:

`{{.Status}}` `{{.StatusText}}` `{{.Title}}` `{{.Message}}` `{{.Host}}` `{{.RequestID}}` `{{.Time}}` `{{.ClientIP}}`
`{{.Theme.LogoURL}}` `{{.Theme.LogoText}}` `{{.Theme.Accent}}` `{{.Theme.FooterText}}`

* Every value is escaped for the place it is written to (text, attribute, URL, CSS). `Host` comes from the request and is attacker
  controlled: it is only ever written through the template engine (`TestErrorPages_HostileHostIsEscaped`).
* `RequestID` is the block reference (`ZX-XXXX-XXXX`, the one in Statistics > Blocked and in the `X-Zoraxy-Ref` header) for a 403, else
  the WAF transaction ID or the request ID of the site. Empty when "Show the reference" is off.
* `ClientIP` is empty unless the owner switches on "Show the visitor's address".
* `Host` is the host name the visitor asked for, as sent, without the port (`nosuch.test:8443` is shown as `nosuch.test`).
* No functions are added and the data is a flat struct of strings: a template cannot read files, the environment or the configuration.
* **Templates are straight-line.** Available: values, `{{if}}` / `{{else}}` / `{{with}}`, variables, comments and the functions `and`, `or`,
  `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `len`. Refused when saved or previewed, before anything runs: `{{range}}` (Go templates loop
  over plain integers, so `{{range 100000}}{{range 100000}}{{end}}{{end}}` would burn a CPU for hours without writing a byte),
  `{{define}}`, `{{template}}`, `{{block}}` (recursion) and every other function (`call`, `print`, `printf`, `index`, `html` ...: they can
  build values that double with every action). Every node of a template therefore runs at most once per render, and a render costs no
  more than the template is long (`TestTemplatesAreStraightLine`).
* Title, message, logo text and footer text: at most 500 characters each (characters, not bytes).
* A template is parsed and test-rendered when it is saved; a broken one is refused with the reason. A template that still fails for a
  request (or a hand-edited file) falls back to the built-in page of Zoraxy and is logged once (`errorpages` in the system log).
* The server never fetches anything. A logo is an `https://` address, a path on the site or a small `data:image/` URL; the visitor's
  browser loads it.

Response of a customised page: the status code it always had, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
Headers the caller set before (`Retry-After`, `X-Zoraxy-Ref`, `X-Request-Id`) are kept. HEAD gets the headers only.

## API (admin session, CSRF token like every other admin API; POST only for changes; viewer accounts can read)

| | |
|---|---|
| `GET /api/errorpages/classes` | page classes, template values, the three starter templates, limits |
| `GET /api/errorpages/get` | the saved customisation |
| `POST /api/errorpages/save` | `host` (empty = all sites), `pages` (JSON `{class: {Title, Message, Template}}`), optional `enabled`, `theme` (JSON). Used by the save bar |
| `POST /api/errorpages/theme` | `enabled`, `theme` (JSON) |
| `POST /api/errorpages/template/set` | `class`, optional `host`, `title`, `message`, `template` |
| `POST /api/errorpages/template/delete` | `class`, optional `host` (`host` without `class`: all pages of that site) |
| `POST /api/errorpages/preview` | `class`, optional `host`, `page` (JSON), `theme` (JSON) -> `{"html"}`; sample values, saves nothing |
| `POST /api/errorpages/reset` | removes everything |
| `GET /api/errorpages/test?class=403[&host=]` | what a visitor gets now, with status and headers (`X-Zoraxy-Error-Page: custom` or `built-in`) |

State: `<conf>/errorpages.json` (0600, written atomically). Changes are in the security audit log (`errorpages.*`) and in System > History.

## Tests

* `src/mod/errorpages/errorpages_test.go`: default off, escaping (markup in every value), validation (oversized, syntax, unknown field or
  function, loops / sub-templates / other functions refused, runaway output, 500 characters not bytes, Host without port, logo and colour rules), broken template falls back and logs once, damaged file, hosts, preview.
* `src/mod/dynamicproxy/errorpages_hook_test.go`: disabled = identical bytes and headers on every hooked path, status and headers of
  customised pages, hostile Host, fallback, the exploit / AI crawler detector, and the whole proxy chain (dead upstream, access list block with its reference, Default Site, HEAD,
  precedence of the per site option).
* `src/errorpagesapi_test.go`: the API. `tools/ui-smoke/errorpages_smoke.py` (`smoke.py --errorpages-only`): the page.

## Known limits

* **Not every error answer is a page class.** Not covered: error statuses that come from the upstream itself (use the older
  "Default error pages" in Settings or the per site option, which replaces chosen status codes of a site and wins over this feature for
  those codes), the CAPTCHA and SSO pages, plain-text refusals (misconfigured rules, client certificate, WebSocket, request too large,
  security rules with their own body or a status other than 403 / 429), plugin errors, the stream proxy and the admin UI itself.
* **No 502 page.** A dead upstream is answered with 521 and a route timeout with 504; both are the "Server error" class. The 502 answers
  Zoraxy gives itself (failed WebSocket upgrade, unreachable virtual directory target) are plain text and are not customised.
* **"Block common exploits" / "Block AI crawlers"** are customised for the 403 and 404 actions only. "400 Bad Request" stays plain text,
  "drop the connection" sends nothing, and the CAPTCHA action shows the CAPTCHA pages.
* **No loops or helper functions in templates** (see Templates). A page that needs repeated markup has to write it out.
* **A page larger than 1 MiB is not served.** Only a large inline logo written many times can reach that; the built-in page answers
  instead and the system log says so once.
* **There is no maintenance switch.** The "Busy or maintenance" page is only served for the 503 Zoraxy answers when every upstream is at
  its connection limit. A real maintenance mode for a site would be a separate feature.
* **No scripts.** The Content-Security-Policy blocks JavaScript, frames and forms on customised pages. The built-in 403 page shows the
  local time and the address with a script; a customised page gets the UTC time from the server instead.
* **English only.** The built-in pages follow `Accept-Language`; customised text and templates are served as written, to everybody.
* **The "region" sentence** of the built-in 403 page (country blocks) has no template value.
* **Old template files** (`web/templates/forbidden.html`, `notfound.html`, `blacklist.html`, `whitelist.html` ...) keep working. For a class
  that is customised here and switched on, this feature answers first.
* **Per site pages match the Host header** (exact name or `*.wildcard`), not the proxy rule: an alias needs its own entry.
* **The logo is loaded by the visitor's browser** from wherever it points; if that is one of your own sites and the site is down, the logo
  is missing. A small file stored in the page ("Use an image file", up to 64 KB) avoids that.
* **Not synced and not in the shareable export.** `errorpages.json` is per node (cluster and Fleet do not copy it) and is not on the
  allow-list of the shareable configuration export.
* **The preview frame** allows same-origin (never scripts) so the page can size it to its content instead of scrolling inside the page.
* **"Send a test" shows the saved page** on the admin port with sample values; it does not send a request through the proxy.
