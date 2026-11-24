# exec()'d by smoke.py (shares args, fail, current, settle, check_horizontal, json, os, re): defines brand_ui(pg, ctx).
#
# Brand scenario (--brand-only, also part of the full run). Reads only; any instance works (brand_run.sh starts a throw-away one).
#   * top bar: the Dunree lockup at 1366 px and the mark alone at 390 px, the light file in the light theme and the dark file in the
#     dark theme, 32 px high, loaded (natural size > 0), named for assistive technology, no page overflow
#   * icons: every <link rel=icon / apple-touch-icon / manifest> of index.html and login.html answers 200 with an image (or JSON)
#   * page title "<page> | Dunree"
#   * footer: name, version from /api/info/x (the Dunree version, not the version of the base), "Published by Foley IT",
#     "Based on Zoraxy v3.3.6 by tobychui and imuslab, AGPL-3.0", Licence and Notice answer 200, About opens the About section
#   * About (System > Utilities > About Dunree): filled from the API, both logo variants, LICENSE / NOTICE / third-party links,
#     the source offer (text without an address; a link when the API names one; never a link for an unsafe address)
#   * Credits: the supporters are named as supporters of Zoraxy
#   * login page (opened without the session): lockup, dark file on the night card, footer with the credit, no link out
#   * no request of these pages goes to a host of the Zoraxy project
# Screenshots go to --out (brand-*.png).

BRAND_CREDIT = "Based on Zoraxy v3.3.6 by tobychui and imuslab, AGPL-3.0"
BRAND_UPSTREAM_HOSTS = re.compile(r"aroz\.org|imuslab\.com|github\.com/tobychui|githubusercontent\.com/(tobychui|aroz-online)|zoraxydocker", re.I)  # rebrand:keep


def brand_ui(pg, ctx):
    out = lambda n: os.path.join(args.out, n)
    base = args.url
    current["page"] = "brand"
    # smoke.py tolerates every message that contains the word "favicon" (browsers ask for one on their own). The icon files are
    # what this scenario checks, so its messages spell the word differently and are never swallowed.
    bfail = lambda kind, msg: fail(kind, str(msg).replace("favicon", "fav-icon"))
    before = pg.viewport_size
    offsite = []
    watch = lambda r: offsite.append(r.url) if BRAND_UPSTREAM_HOSTS.search(r.url) else None
    pg.on("request", watch)

    def fetch(path):
        """status and content type of a path of the admin interface, fetched by the page (same cookies)"""
        return pg.evaluate("""async p => { try { const r = await fetch(p, {cache: 'no-store'}); const b = await r.blob();
            return {status: r.status, type: r.headers.get('content-type') || '', size: b.size}; } catch (e) { return {status: 0, type: String(e), size: 0}; } }""", path)

    def goto(width, height, theme, hash_="#status"):
        pg.set_viewport_size({"width": width, "height": height})
        pg.goto(base + "/index.html" + hash_, wait_until="domcontentloaded", timeout=60000)
        pg.reload(wait_until="domcontentloaded", timeout=60000)
        pg.wait_for_selector(".zx-top-logo", timeout=15000)
        pg.wait_for_function("document.querySelector('#zxBrandFooter .zrversion') && document.querySelector('#zxBrandFooter .zrversion').textContent.trim() !== ''", timeout=20000)
        settle(pg, 400)
        dark = pg.evaluate("document.body.classList.contains('darkTheme')")
        if dark != (theme == "dark"):
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    LOGO = """() => [...document.querySelectorAll('.zx-top-logo img')].filter(i => getComputedStyle(i).display !== 'none' && i.getBoundingClientRect().width > 0)
        .map(i => { const r = i.getBoundingClientRect(); return {src: i.getAttribute('src'), w: Math.round(r.width), h: Math.round(r.height), nat: i.naturalWidth, done: i.complete,
                                                                  left: Math.round(r.left), right: Math.round(r.right)}; })"""

    info = None
    # ---- top bar logo: lockup on a desktop, mark on a phone; light and dark file by theme ----
    for width, height, kind in ((1366, 800, "lockup"), (390, 844, "mark")):
        for theme in ("light", "dark"):
            goto(width, height, theme)
            shown = pg.evaluate(LOGO)
            want = "img/public/brand/dunree-" + kind + ("-dark" if theme == "dark" else "") + ".svg"
            if len(shown) != 1 or shown[0]["src"] != want:
                bfail("logo", f"{width}px {theme}: exactly {want} must show in the top bar, got {shown}")
            else:
                s = shown[0]
                if not s["done"] or s["nat"] <= 0:
                    bfail("logo", f"{width}px {theme}: {want} did not load")
                if s["h"] != 32:
                    bfail("logo", f"{width}px {theme}: the logo is {s['h']}px high, 32 expected (a multiple of 16 keeps the mark on whole pixels)")
                ratio = s["w"] / max(1, s["h"])
                if kind == "lockup" and not (4.4 < ratio < 4.9) or kind == "mark" and not (0.95 < ratio < 1.05):
                    bfail("logo", f"{width}px {theme}: the {kind} is stretched ({s['w']}x{s['h']})")
                if s["left"] < 8 or s["right"] > width:
                    bfail("logo", f"{width}px {theme}: the logo touches the edge of the window ({s['left']}..{s['right']})")
            name = pg.get_attribute(".zx-top-logo", "aria-label") or ""
            if "Dunree" not in name:
                bfail("logo", f"the logo link has no name for screen readers: {name!r}")
            if "| Dunree" not in pg.title() and pg.title() != "Dunree":
                bfail("title", f"{width}px {theme}: page title {pg.title()!r} does not carry the product name")
            check_horizontal(pg, f"brand {width}px {theme}")
            pg.screenshot(path=out(f"brand-topbar-{theme}-{width}.png"), clip={"x": 0, "y": 0, "width": width, "height": 120})

    # ---- icons of the page ----
    goto(1366, 800, "light")
    links = pg.evaluate("""() => [...document.querySelectorAll('link[rel~="icon"], link[rel="apple-touch-icon"], link[rel="manifest"]')].map(l => ({rel: l.rel, href: l.getAttribute('href'), abs: l.href}))""")
    rels = sorted(l["rel"] + " " + l["href"].rsplit("/", 1)[-1] for l in links)
    for need in ("icon favicon.svg", "icon favicon-32.png", "icon favicon-16.png", "shortcut icon favicon.ico", "apple-touch-icon apple-touch-icon.png", "manifest manifest.json"):
        if need not in rels:
            bfail("icons", f"index.html has no <link> for {need}: {rels}")
    for l in links:
        r = fetch(l["abs"])
        okType = ("json" in r["type"]) if l["rel"] == "manifest" else (r["type"].startswith("image/") or "icon" in r["type"])
        if r["status"] != 200 or r["size"] < 100 or not okType:
            bfail("icons", f"{l['href']} ({l['rel']}): {r}")
    for old in ("favicon.png", "img/logo.svg", "img/logo_white.svg", "img/public/logo.svg", "img/logo.png", "img/small_icon.png"):
        r = fetch(base + "/" + old)
        if r["status"] != 200 or not r["type"].startswith("image/"):
            bfail("icons", f"the path {old} from before the rebrand no longer answers with an image: {r}")

    # ---- footer ----
    info = pg.evaluate("async () => (await fetch('./api/info/x')).json()")
    for k, v in (("Product", "Dunree"), ("Publisher", "Foley IT"), ("BasedOn", "Zoraxy"), ("BasedOnVersion", "3.3.6"), ("BasedOnAuthors", "tobychui and imuslab"), ("License", "AGPL-3.0")):
        if info.get(k) != v:
            bfail("api", f"/api/info/x {k} = {info.get(k)!r}, want {v!r}")
    pv = info.get("ProductVersion") or ""
    if not re.match(r"^1\.\d+\.\d+", pv):
        bfail("api", f"/api/info/x ProductVersion {pv!r} is not a Dunree 1.x version")
    foot = " ".join(pg.inner_text("#zxBrandFooter").split())
    for need in ("Dunree", "v" + pv, "Published by Foley IT", BRAND_CREDIT, "Licence", "Notice", "About"):
        if need not in foot:
            bfail("footer", f"the footer lacks {need!r}: {foot!r}")
    shown_version = pg.inner_text("#zxBrandFooter .zrversion").strip()
    if shown_version != "v" + pv:
        bfail("footer", f"the footer shows {shown_version!r} as the version, the Dunree version is v{pv} (the version of the base is {info.get('Version')})")
    for href in pg.eval_on_selector_all("#zxBrandFooter a[href^='legal/']", "els => els.map(e => e.href)"):
        r = fetch(href)
        if r["status"] != 200 or r["size"] < 500 or "text/plain" not in r["type"]:
            bfail("footer", f"{href}: {r}")
    outside = pg.eval_on_selector_all("#zxBrandFooter a", "els => els.map(e => e.href).filter(h => new URL(h).origin !== location.origin)")
    if outside:
        bfail("footer", f"the footer links away from the admin interface: {outside}")
    pg.locator("#zxBrandFooter").scroll_into_view_if_needed()
    pg.locator("#zxBrandFooter").screenshot(path=out("brand-footer-light.png"))

    # ---- About: the footer link opens it; filled from the API ----
    pg.click("#zxBrandFooter .zx-brand-about")
    pg.wait_for_selector("#dunreeabout", state="visible", timeout=8000)
    settle(pg, 300)
    if not pg.is_visible("#utils") or pg.evaluate("document.querySelector('#utilsPage .sy-pane[data-pane=info]').hidden"):
        bfail("about", "About in the footer did not open System > Utilities > About Dunree")
    about = " ".join(pg.inner_text("#dunreeabout").split())
    for need in ("Reverse proxy and web gateway", "Dunree v" + pv, "Published by Foley IT", BRAND_CREDIT, "AGPL-3.0", "LICENSE", "NOTICE", "Third-party notices",
                 "Source code", "not affiliated with or endorsed by tobychui, imuslab or the Zoraxy contributors"):
        if need not in about:
            bfail("about", f"the About card lacks {need!r}: {about!r}")
    for sel in ("#abLicense", "#abNotice", "#abThirdParty"):
        r = fetch(pg.eval_on_selector(sel, "e => e.href"))
        if r["status"] != 200 or r["size"] < 500:
            bfail("about", f"{sel}: {r}")
    lic = pg.evaluate("async () => (await (await fetch('legal/LICENSE.txt')).text())")
    if "GNU AFFERO GENERAL PUBLIC LICENSE" not in lic or "Version 3, 19 November 2007" not in lic:
        bfail("about", "legal/LICENSE.txt is not the AGPL-3.0")
    notice = pg.evaluate("async () => (await (await fetch('legal/NOTICE.txt')).text())")
    if "tobychui" not in notice or "imuslab" not in notice or "endorsed" not in notice or "Foley IT" not in notice:
        bfail("about", "legal/NOTICE.txt lacks the credit or the statement that Dunree is not endorsed")
    host = " ".join(pg.inner_text("#dunreeinfo").split())
    if "v" + pv not in host:
        bfail("about", f"'This host' does not show the Dunree version: {host!r}")
    # no source address in this build: text, and no link
    if not info.get("SourceURL"):
        if pg.locator("#abSource a").count() or "entitled to the complete source code" not in pg.inner_text("#abSource"):
            bfail("about", "without a source address the About card must offer the source in words, without a link: " + pg.inner_text("#abSource"))
    for theme in ("light", "dark"):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != (theme == "dark"):
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)
        logos = pg.evaluate("""() => [...document.querySelectorAll('#dunreeabout .ut-about__logo')].filter(i => getComputedStyle(i).display !== 'none')
            .map(i => ({src: i.getAttribute('src'), h: Math.round(i.getBoundingClientRect().height), nat: i.naturalWidth}))""")
        want = "img/public/brand/dunree-lockup" + ("-dark" if theme == "dark" else "") + ".svg"
        if len(logos) != 1 or logos[0]["src"] != want or logos[0]["nat"] <= 0 or logos[0]["h"] != 48:
            bfail("about", f"{theme}: the About card must show {want} at 48 px: {logos}")
        pg.locator("#dunreeabout").scroll_into_view_if_needed()
        pg.locator("#utilsPage .sy-pane[data-pane=info]").screenshot(path=out(f"brand-about-{theme}.png"))
    pg.evaluate("if (document.body.classList.contains('darkTheme')) toggleTheme()")

    # a source address from the server becomes a link; an unsafe one never does
    def with_source(url):
        doc = dict(info)
        doc["SourceURL"] = url
        pg.route("**/api/info/x", lambda rt: rt.fulfill(status=200, content_type="application/json", body=json.dumps(doc)))
        pg.goto(base + "/index.html#utils", wait_until="domcontentloaded", timeout=60000)
        pg.reload(wait_until="domcontentloaded", timeout=60000)
        pg.wait_for_function("document.querySelector('#abVersion') && document.querySelector('#abVersion').textContent.trim() !== '-'", timeout=20000)
        pg.evaluate("ZxUtils.go('info')")
        pg.wait_for_timeout(300)
        res = pg.evaluate("() => ({links: [...document.querySelectorAll('#abSource a')].map(a => ({href: a.getAttribute('href'), text: a.textContent, rel: a.rel})), text: document.querySelector('#abSource').textContent, html: document.querySelector('#abSource').innerHTML, xss: window.__brandxss || 0})")
        pg.unroute("**/api/info/x")
        return res

    good = with_source("https://source.example/dunree")
    if len(good["links"]) != 1 or good["links"][0]["href"] != "https://source.example/dunree" or "noopener" not in good["links"][0]["rel"] or "complete source code of this version" not in good["text"]:
        bfail("about", f"a source address from the server must become the source link: {good}")
    pg.locator("#dunreeabout").screenshot(path=out("brand-about-source-link.png"))
    for bad in ("javascript:window.__brandxss=1", "https://x.example/\"><img src=x onerror=window.__brandxss=2>", "data:text/html,<script>window.__brandxss=3</script>", "//evil.example/x"):
        r = with_source(bad)
        if r["links"] or r["xss"] or "<img" in r["html"]:
            bfail("about", f"the unsafe source address {bad!r} must not become a link or markup: {r}")

    # ---- Credits ----
    pg.goto(base + "/index.html#utils", wait_until="domcontentloaded", timeout=60000)
    pg.reload(wait_until="domcontentloaded", timeout=60000)
    pg.wait_for_function("typeof ZxUtils === 'object'", timeout=20000)
    pg.evaluate("ZxUtils.go('contributors')")
    try:
        pg.wait_for_selector("#supportersList .zx-badge, #supportersList .zx-help", timeout=8000)
    except Exception:
        bfail("credits", "the supporters list did not load")
    credits = " ".join(pg.inner_text("#utilsPage .sy-pane[data-pane=contributors]").split())
    for need in ("Supporters of Zoraxy", "donated to the Zoraxy project", "did not donate to Dunree"):
        if need not in credits:
            bfail("credits", f"the Credits section lacks {need!r}")
    if "supporters of Zoraxy." not in credits and "supporter of Zoraxy." not in credits:
        bfail("credits", "the count line must name them as supporters of Zoraxy")
    pg.locator("#utilsPage .sy-pane[data-pane=contributors]").screenshot(path=out("brand-credits.png"))

    # ---- login page (it is public: a context without the session sees the same page) ----
    current["page"] = "brand-login"
    lp = ctx.browser.new_context(viewport={"width": 1366, "height": 800}).new_page()
    lp.on("request", watch)
    bad_status = []
    lp.on("response", lambda r: bad_status.append(f"{r.status} {r.url}") if r.status >= 400 and "/api/" not in r.url else None)
    # on a -noauth instance everybody is "logged in" and the login page would leave for the interface at once
    lp.route("**/api/auth/checkLogin", lambda rt: rt.fulfill(status=200, content_type="application/json", body="false"))
    lp.goto(base + "/login.html", wait_until="domcontentloaded", timeout=60000)
    lp.wait_for_selector("#loginForm", timeout=15000)
    lp.wait_for_timeout(800)
    for klass, want in (("afternoon", "dunree-lockup.svg"), ("night", "dunree-lockup-dark.svg")):
        lp.evaluate("k => { document.body.className = k; }", klass)
        lp.wait_for_timeout(250)
        shown = lp.evaluate("""() => [...document.querySelectorAll('#loginForm .lg-logo')].filter(i => getComputedStyle(i).display !== 'none')
            .map(i => ({src: i.getAttribute('src'), w: Math.round(i.getBoundingClientRect().width), h: Math.round(i.getBoundingClientRect().height), nat: i.naturalWidth, filter: getComputedStyle(i).filter}))""")
        if len(shown) != 1 or not shown[0]["src"].endswith(want) or shown[0]["nat"] <= 0 or shown[0]["filter"] != "none":
            bfail("login", f"{klass}: the login card must show {want}, loaded and without a filter: {shown}")
        elif shown[0]["h"] < 20 or not (4.4 < shown[0]["w"] / max(1, shown[0]["h"]) < 4.9):
            bfail("login", f"{klass}: the lockup is under 20 px high or stretched: {shown}")
        lp.screenshot(path=out(f"brand-login-{klass}.png"))
    if lp.title() != "Login | Dunree":
        bfail("login", f"title {lp.title()!r}")
    lfoot = " ".join(lp.inner_text("#lgBrandFooter").split())
    for need in ("Dunree", "Reverse proxy and web gateway", "Published by Foley IT", BRAND_CREDIT):
        if need not in lfoot:
            bfail("login", f"the login footer lacks {need!r}: {lfoot!r}")
    if lp.locator(".wavebase a").count():
        bfail("login", "the login footer must not link anywhere")
    llinks = lp.evaluate("""() => [...document.querySelectorAll('link[rel~="icon"], link[rel="apple-touch-icon"], link[rel="manifest"]')].map(l => l.href)""")
    if len(llinks) < 6:
        bfail("login", f"the login page lacks the icon set: {llinks}")
    for href in llinks:
        resp = lp.context.request.get(href)  # this context has no session: what a browser gets before the login
        r = {"status": resp.status, "type": resp.headers.get("content-type", ""), "size": len(resp.body())}
        if r["status"] != 200 or "text/html" in r["type"] or r["size"] < 100:
            bfail("login-assets", f"{href.rsplit('/', 1)[-1]} is not readable without a login: {r}")
    lp.set_viewport_size({"width": 390, "height": 844})
    lp.wait_for_timeout(300)
    ov = lp.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    if ov > 2:
        bfail("login", f"390 px: the login page overflows by {ov}px")
    lp.screenshot(path=out("brand-login-390.png"))
    if bad_status:
        bfail("login", f"requests of the login page failed: {bad_status[:5]}")
    lp.context.close()

    current["page"] = "brand"
    pg.remove_listener("request", watch)
    if before:
        pg.set_viewport_size(before)
    pg.goto(base + "/index.html", wait_until="domcontentloaded", timeout=60000)
    settle(pg)
    # An existing installation keeps the plugin store of the Zoraxy project as a third-party source until an admin
    # removes it (docs/plugins/addon-store.md); run.sh makes this instance such an installation, so the App Store
    # shows that store's plugin icons. Those requests belong to the migrated source, not to the product.
    legacy_store = pg.evaluate("""async () => { try { const r = await fetch('/api/plugins/store/sources', {cache: 'no-store'});
        const j = await r.json(); return (j || []).some(x => x.kind === 'zoraxy-community'); } catch (e) { return false; } }""")
    if legacy_store:
        offsite = [u for u in offsite if not re.match(r"https://raw\.githubusercontent\.com/aroz-online/", u)]  # rebrand:keep
    if offsite:
        bfail("offsite", f"a page asked a host of the Zoraxy project: {sorted(set(offsite))[:5]}")
    print("brand: top bar logo (4 views), icons, footer, About, source offer, Credits, login page checked")
