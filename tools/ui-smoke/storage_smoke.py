"""Smoke scenario "blocked storage + dark text colours". exec()'d by smoke.py (namespace: fail, current, args, os, re, settle);
run alone with --storage-only. Reads only; any instance works.

Part 1, blocked storage. A browser may refuse localStorage / sessionStorage (strict privacy mode, "block site data"): every call
then throws. The admin UI must keep working, with choices held in memory until the reload (script/safestorage.js, zxStore).
Two ways of blocking are simulated in fresh browser contexts: the Storage methods throw, and the window.localStorage property
itself throws (what Chromium does when site data is blocked). In each: the shell loads, every menu page opens and is not empty,
menu groups toggle, Recent and pinned items work, the HTTP Proxy table sorts, the theme menu switches dark / light / system and a
side panel opened afterwards follows the choice, the pages that store something on their own (traffic diagram, container list,
file manager) load. No console error and no uncaught exception anywhere.

Part 2, dark theme colours (normal storage). darktheme.css must not flatten kit colours: page sub titles are muted, a span or p
without a colour of its own inside a kit component or a page block (block__element class) follows its parent (muted, danger, warn,
ok), a class wins against the legacy tag rules, inside a Semantic UI component a bare p / span keeps the legacy text colour, the
group headers of the side menu and the empty row of a table are muted."""

BLOCK_METHODS = """(() => { const boom = () => { throw new DOMException('The operation is insecure.', 'SecurityError'); };
    for (const m of ['getItem', 'setItem', 'removeItem', 'clear', 'key']) Storage.prototype[m] = boom; })()"""
BLOCK_PROPERTY = """(() => { const boom = () => { throw new DOMException('Access is denied for this document.', 'SecurityError'); };
    for (const n of ['localStorage', 'sessionStorage']) Object.defineProperty(window, n, {get: boom, configurable: true}); })()"""


def storage_ui(pg, ctx):
    browser = ctx.browser
    for mode, script in (("methods throw", BLOCK_METHODS), ("property throws", BLOCK_PROPERTY)):
        current["page"] = f"storage-blocked/{mode}"
        c = browser.new_context(viewport={"width": 1366, "height": 800})
        c.add_init_script(script)
        p = c.new_page()
        p.on("pageerror", lambda e: fail("pageerror", str(e) + " @ " + " | ".join((e.stack or "").splitlines()[1:3])))
        lenient = {"on": False}   # pages opened on their own miss their data (no web server, no docker): a refused request is not the subject here
        p.on("console", lambda m: m.type == "error" and not (lenient["on"] and "Failed to load resource" in m.text) and fail("console.error", m.text + " " + m.location.get("url", "")))
        p.goto(args.url + "/", wait_until="networkidle")
        try:
            p.wait_for_selector("#mainmenu .item", state="attached", timeout=8000)
        except Exception:
            fail("storage", "the admin page did not build its menu with storage blocked")
            c.close()
            continue
        p.wait_for_timeout(800)
        blocked = p.evaluate("(() => { try { localStorage.setItem('zx.probe', '1'); localStorage.removeItem('zx.probe'); return false; } catch (e) { return true; } })()")
        if not blocked:
            fail("storage", "test setup: storage is not blocked in this context")
        if not p.evaluate("!!window.zxStore && zxStore.set('zx.probe', 'v') === false && zxStore.get('zx.probe') === 'v' && (zxStore.remove('zx.probe'), zxStore.get('zx.probe') === null)"):
            fail("storage", "zxStore must keep a value in memory when the browser refuses it, and forget it on remove")

        # every page of the menu opens and shows something
        tabs = list(dict.fromkeys(p.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")))
        if len(tabs) < 20:
            fail("storage", f"only {len(tabs)} menu pages found")
        for t in tabs:
            current["page"] = f"storage-blocked/{mode}/{t}"
            p.evaluate("t => openTabById(t)", t)
            settle(p, 350)
            st = p.evaluate("t => { const e = document.getElementById(t); return e ? [e.offsetParent !== null, e.innerText.trim().length] : null; }", t)
            if not st or not st[0] or st[1] < 10:
                fail("storage", f"page #{t} did not open or is empty with storage blocked: {st}")
        current["page"] = f"storage-blocked/{mode}"

        # menu groups, Recent, pinned: kept in memory for the session
        p.evaluate("toggleMenuGroup('traffic')")
        p.wait_for_timeout(350)
        if not p.evaluate("(() => { const s = getMenuGroupStates(); return s.traffic === true || s.traffic === false; })()"):
            fail("storage", "the open / closed state of a menu group is not kept for the session")
        recent = p.evaluate("getRecentTabs().length")
        if recent < 3 or p.evaluate("document.querySelectorAll('#group-recent .recent-item').length") < 3:
            fail("storage", f"Recent is empty after visiting {len(tabs)} pages (kept: {recent})")
        p.evaluate("pinTab('status', 'Status', 'info circle icon')")
        if not p.evaluate("isTabPinned('status')"):
            fail("storage", "a pinned page is not kept for the session")
        p.evaluate("unpinTab('status')")

        # HTTP Proxy table: the sort choice goes to storage
        p.evaluate("openTabById('httprp')")
        settle(p, 500)
        th = p.query_selector("#httprp table thead th[data-sort], #httprp table thead th button")
        if th and th.is_visible():
            th.click()
            p.wait_for_timeout(300)

        # theme menu: dark, a side panel opened afterwards follows, light, system
        p.evaluate("openTabById('status')")
        p.click("#zxThemeBtn")
        p.click(".zx-menu [data-theme=dark]")
        p.wait_for_timeout(300)
        if not p.evaluate("document.body.classList.contains('darkTheme')"):
            fail("storage", "theme menu > Dark does not switch to the dark theme with storage blocked")
        if "Dark" not in p.inner_text("#zxThemeBtn"):
            fail("storage", f"the theme button must say Dark after choosing it: {p.inner_text('#zxThemeBtn')!r}")
        p.evaluate("showSideWrapper('snippet/acme.html')")
        try:
            p.wait_for_function("(() => { const f = document.querySelector('.sideWrapper iframe'); try { return /acme\\.html/.test(f.contentWindow.location.href) && f.contentDocument.readyState === 'complete' && !!f.contentWindow.setDarkTheme; } catch (e) { return false; } })()", timeout=8000)
            if not p.evaluate("document.querySelector('.sideWrapper iframe').contentDocument.body.classList.contains('darkTheme')"):
                fail("storage", "a side panel opened after choosing Dark is light: the frames must share the choice kept in memory")
        except Exception:
            fail("storage", "the side panel did not load with storage blocked")
        p.evaluate("hideSideWrapper()")
        p.wait_for_timeout(500)
        p.evaluate("openTabById('waf')")   # the choice holds across pages
        settle(p, 300)
        if not p.evaluate("document.body.classList.contains('darkTheme')"):
            fail("storage", "the dark theme is lost when another page opens")
        p.click("#zxThemeBtn")
        p.click(".zx-menu [data-theme=light]")
        p.wait_for_timeout(300)
        if p.evaluate("document.body.classList.contains('darkTheme')") or "Light" not in p.inner_text("#zxThemeBtn"):
            fail("storage", "theme menu > Light does not switch back with storage blocked")
        p.evaluate("toggleTheme()")
        if not p.evaluate("document.body.classList.contains('darkTheme')"):
            fail("storage", "toggleTheme() does not switch with storage blocked")
        p.click("#zxThemeBtn")
        p.click(".zx-menu [data-theme=system]")
        p.wait_for_timeout(300)
        if p.evaluate("zxStore.get('theme')") is not None:
            fail("storage", "theme menu > System must forget the stored choice")

        # the container list stores its two switches; it reports "no docker" through the admin page, so it opens in the side panel
        current["page"] = f"storage-blocked/{mode}/dockerContainersList"
        lenient["on"] = True
        p.evaluate("showSideWrapper('snippet/dockerContainersList.html')")
        try:
            p.wait_for_function("(() => { const f = document.querySelector('.sideWrapper iframe'); try { return /dockerContainersList/.test(f.contentWindow.location.href) && f.contentDocument.readyState === 'complete' && !!f.contentWindow.zxStore; } catch (e) { return false; } })()", timeout=8000)
        except Exception:
            fail("storage", "the container list did not load in the side panel with storage blocked")
        p.wait_for_timeout(600)
        p.evaluate("hideSideWrapper()")
        p.wait_for_timeout(400)
        # pages that store something themselves, opened on their own (frames, tool windows)
        for rel in ("snippet/trafficFlowDiagram.html", "tools/fs.html", "snippet/upstreams.html", "ui/kit.html"):
            current["page"] = f"storage-blocked/{mode}/{rel}"
            p.goto(args.url + "/" + rel, wait_until="networkidle")
            p.wait_for_timeout(400)
            if not p.evaluate("!!document.body && document.body.children.length > 0"):
                fail("storage", f"{rel} is empty with storage blocked")
        c.close()

    # ---- part 2: the dark theme keeps kit colours ----
    current["page"] = "dark-colours"
    was_dark = pg.evaluate("document.body.classList.contains('darkTheme')")
    if not was_dark:
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(300)
    try:
        pg.evaluate("openTabById('status')")
        settle(pg, 500)
        r = pg.evaluate("""() => {
            const col = (e) => getComputedStyle(e).color;
            const host = document.querySelector('#status');
            const box = document.createElement('div');
            box.innerHTML = '<div class="zx-card" id="zxDarkProbe">'
                + '<p class="zx-help" data-k="help">help <span data-k="helpSpan">span</span></p>'
                + '<p class="zx-danger-text" data-k="danger" style="color: var(--zx-danger-text)">danger <span data-k="dangerSpan">span</span></p>'
                + '<p data-k="plainP">plain</p><h3 class="zx-card__title" data-k="title">title</h3>'
                + '<span class="zxProbeCls" data-k="cls">class</span></div>'
                + '<style>.zxProbeCls{ color: rgb(1, 2, 3); }</style>';
            host.appendChild(box);
            const o = {};
            // the legacy probe hangs on the body: no kit class above it
            const leg = document.createElement('div');
            leg.innerHTML = '<p data-k="legacyP">p</p><span data-k="legacySpan">span</span><h3 data-k="legacyH">h</h3><a class="zxProbeCls" data-k="aCls">link</a><i data-k="legacyText" style="color: var(--text_color)">i</i>'
                // no Semantic UI component above: a span follows its parent
                + '<div style="color: rgb(7, 8, 9)"><span data-k="bareSpan">span</span></div>'
                // inside a Semantic UI component p / span get the dark text colour, whatever the component says ...
                + '<div class="ui segment" style="color: rgb(4, 5, 6)"><p data-k="uiP">p</p><span data-k="uiSpan">span</span>'
                // ... except in a block of a redesigned page (a "block__element" class above) and in a kit component
                + '<div class="xx-row__main" style="color: rgb(4, 5, 6)"><span data-k="bemSpan">span</span></div><div class="zx-row" style="color: rgb(4, 5, 6)"><p data-k="kitInUi">p</p></div>'
                + '<table class="ui table"><tbody><tr><td class="zx-empty-cell" data-k="emptyCell">none</td><td data-k="cell">cell</td></tr></tbody></table></div>';
            document.body.appendChild(leg);
            const mh = document.querySelector('#mainmenu .menugroup-header > span');
            o.menuHead = mh ? [col(mh), col(mh.parentElement), col(document.querySelector('#mainmenu .item') || mh)] : null;
            document.querySelectorAll('[data-k]').forEach(e => { o[e.getAttribute('data-k')] = col(e); });
            leg.remove();
            const sub = document.querySelector('#status .zx-page-header__sub'), ttl = document.querySelector('#status .zx-page-header__title');
            o.pageSub = sub ? col(sub) : null; o.pageTitle = ttl ? col(ttl) : null;
            box.remove();
            return o; }""")
        if r["help"] == r["title"] or r["helpSpan"] != r["help"]:
            fail("dark", f"help text must be muted in the dark theme and a span inside it must follow: {r}")
        if r["dangerSpan"] != r["danger"] or r["danger"] == r["title"]:
            fail("dark", f"a span inside danger text must stay in the danger colour: {r}")
        if r["cls"] != "rgb(1, 2, 3)" or r["aCls"] != "rgb(1, 2, 3)":
            fail("dark", f"a single class must win against the legacy tag rules of darktheme.css: {r}")
        if r["pageSub"] and r["pageSub"] == r["pageTitle"]:
            fail("dark", f"the page sub title must be muted, not the colour of the title: {r}")
        if not (r["legacyP"] == r["legacySpan"] == r["legacyH"] == r["legacyText"]):
            fail("dark", f"outside the kit, bare p / span / h3 keep the legacy text colour: {r}")
        if r["bareSpan"] != "rgb(7, 8, 9)":
            fail("dark", f"outside Semantic UI components a span without a colour of its own must follow its parent: {r}")
        if not (r["uiP"] == r["uiSpan"] == r["legacyText"]):
            fail("dark", f"inside a Semantic UI component p / span keep the dark text colour (legacy pages rely on it): {r}")
        if r["bemSpan"] != "rgb(4, 5, 6)" or r["kitInUi"] != "rgb(4, 5, 6)":
            fail("dark", f"inside a page block (block__element class) or a kit component, p / span must inherit even under a .ui wrapper: {r}")
        if r["emptyCell"] != r["help"] or r["cell"] == r["emptyCell"]:
            fail("dark", f"the empty row of a table must stay muted inside a legacy .ui.table: {r}")
        if r["menuHead"] and (r["menuHead"][0] != r["menuHead"][1] or r["menuHead"][0] == r["legacyText"]):
            fail("dark", f"the group headers of the side menu must be muted, not plain text colour: {r['menuHead']}")
        pg.screenshot(path=os.path.join(args.out, "storage-dark-status.png"), full_page=True)
    finally:
        if not was_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(200)
