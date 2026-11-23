"""Smoke scenario of Sites > Error pages (components/errorpages.html). exec()'d by smoke.py (namespace: fail, current, args, os, re,
settle, check_horizontal, allow); run alone with --errorpages-only on a THROW-AWAY instance: it saves error page settings and
resets them at the end (and at the start, so a run that was interrupted does not poison the next one).

Checks: default off (API, badge, the test link answers with the built-in page), the page opens on Theme with the sectioned
navigation and six page classes, ONE save bar and one primary button, the live preview follows the theme and the text, hostile
markup typed as a title is shown as text in the preview and in the served page, the three starter templates, a broken template is
reported in the preview and refused by Save, Save switches it on (API, badge, navigation state, served page with its status code,
no-store and the Content-Security-Policy), the pages of one site (scope), "Use the built-in page", "Reset to built-in", and the
layout (no horizontal overflow, the preview does not scroll inside the page) at 1366, 2000 and 390px, light and dark.
Screenshots are written to --out as errorpages-*.png."""

import json


def errorpages_ui(pg, ctx):
    out = lambda n: os.path.join(args.out, n)
    base = args.url.rstrip("/")
    csrf = "document.querySelector('meta[name=\"zoraxy.csrf.Token\"]').content"

    def api_get():
        return pg.evaluate("fetch('/api/errorpages/get').then(r => r.json())")

    def post(path, data):
        return pg.evaluate("""([path, data, token]) => fetch(path, {method: 'POST', headers: {'X-CSRF-Token': token, 'Content-Type': 'application/x-www-form-urlencoded'},
            body: new URLSearchParams(data).toString()}).then(r => r.text())""", [path, data, pg.evaluate(csrf)])

    def served(cls, host=""):
        """the page a visitor gets now (not through the page object: a 403 here is the expected answer, not a failed request)"""
        r = ctx.request.get(base + "/api/errorpages/test?class=" + cls + ("&host=" + host if host else ""))
        return r.status, r.headers, r.text()

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def section(name):
        pg.dispatch_event("#epNav .zx-sectionnav__item[data-ep='%s']" % name, "click")
        pg.wait_for_timeout(150)

    def preview_html():
        return pg.evaluate("document.getElementById('epPreview').srcdoc || ''")

    def wait_preview(needle, what):
        try:
            pg.wait_for_function("n => (document.getElementById('epPreview').srcdoc || '').includes(n)", arg=needle, timeout=6000)
        except Exception:
            fail("errorpages", f"{what}: the preview never showed {needle!r}")

    def bar_visible():
        return pg.evaluate("[...document.querySelectorAll('#errorpages .zx-savebar')].filter(b => !b.hidden).length")

    def save(expect_ok=True):
        pg.click("#errorpages .zx-savebar [data-zx-save]")
        if expect_ok:
            try:
                pg.wait_for_function("!document.querySelector('#errorpages .zx-savebar.is-error') && [...document.querySelectorAll('#errorpages .zx-savebar [data-zx-save]')].every(b => b.hidden || b.closest('.zx-savebar').hidden)", timeout=6000)
            except Exception:
                fail("errorpages", "Save did not finish: " + pg.inner_text("#errorpages .zx-savebar"))
        else:
            pg.wait_for_selector("#errorpages .zx-savebar.is-error", timeout=6000)

    def confirm(ok=True):
        pg.wait_for_selector(".zx-dialog [data-zx-ok]", timeout=5000)
        pg.click(".zx-dialog %s" % ("[data-zx-ok]" if ok else "[data-zx-cancel]"))
        pg.wait_for_timeout(300)

    def layout(label):
        check_horizontal(pg, label)
        bad = pg.evaluate("""() => {
            const page = document.getElementById('errorPagesPage'), pr = page.getBoundingClientRect(), msgs = [];
            page.querySelectorAll('.zx-card, .zx-callout, textarea, iframe, .zx-tabs, .ep-toolbar, select, input[type=text]').forEach(el => {
                if (el.offsetParent === null) return;
                const r = el.getBoundingClientRect();
                if (r.width && (r.left < pr.left - 1 || r.right > pr.right + 1)) msgs.push((el.id || el.className || el.tagName) + ' leaves the page column: ' + Math.round(r.left) + '..' + Math.round(r.right) + ' vs ' + Math.round(pr.left) + '..' + Math.round(pr.right));
            });
            // one scroller: the preview frame shows its whole document
            const f = document.getElementById('epPreview');
            try {
                const d = f.contentDocument;
                if (d && d.documentElement && d.documentElement.scrollHeight > f.clientHeight + 4) msgs.push('the preview scrolls inside the page: document ' + d.documentElement.scrollHeight + 'px in a ' + f.clientHeight + 'px frame');
            } catch (e) { msgs.push('the preview frame cannot be measured: ' + e); }
            // nothing with its own scroll box except the HTML editor (a textarea) and the tab strip
            page.querySelectorAll('*').forEach(el => {
                if (el.offsetParent === null || el.tagName === 'TEXTAREA' || el.classList.contains('zx-tabs')) return;
                const cs = getComputedStyle(el);
                if ((cs.overflowY === 'auto' || cs.overflowY === 'scroll') && el.scrollHeight > el.clientHeight + 4) msgs.push('scroll box inside the page: ' + (el.id || el.className || el.tagName));
            });
            return msgs;
        }""")
        for m in bad:
            fail("layout", f"{label}: {m}")

    def shots(name):
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("2000", False, 2000), ("390", False, 390)):
            theme(dark)
            pg.set_viewport_size({"width": w, "height": 900 if w > 500 else 1100})
            pg.wait_for_timeout(500)
            layout(f"{name}/{label}")
            pg.screenshot(path=out(f"errorpages-{name}-{label}.png"), full_page=True)
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)

    current["page"] = "errorpages/default"
    post("/api/errorpages/reset", {})  # a clean start, whatever an earlier run left behind
    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})
    pg.evaluate("openTabById('errorpages')")
    settle(pg, 900)
    pg.wait_for_selector("#errorPagesPage #epThemePanel:not([hidden])", timeout=8000)

    # ---- default: everything off, nothing saved ----
    cfg = api_get()
    if cfg.get("Enabled") or cfg.get("Active") or cfg.get("Pages") or cfg.get("Hosts"):
        fail("errorpages", f"not off by default: {cfg}")
    crumbs = pg.inner_text("#errorPagesPage .zx-page-header__crumbs")
    if "Sites" not in crumbs or "Error pages" not in crumbs:
        fail("errorpages", f"breadcrumb: {crumbs!r}")
    if pg.inner_text("#epStatus").strip() != "Off":
        fail("errorpages", "the page status must say Off")
    items = pg.eval_on_selector_all("#epNav .zx-sectionnav__item", "els => els.map(e => e.getAttribute('data-ep'))")
    if items != ["theme", "403", "404", "429", "5xx", "nohost", "maintenance"]:
        fail("errorpages", f"sections: {items}")
    if pg.inner_text("#epHead .zx-sectionhead__title").strip() != "Theme":
        fail("errorpages", "the page must open on Theme")
    status, headers, body = served("403")
    if status != 403 or headers.get("x-zoraxy-error-page") != "built-in" or "content-security-policy" in headers or "403 - Forbidden" not in body:
        fail("errorpages", f"with nothing saved the test link must answer with the built-in 403 page: {status} {headers}")
    if bar_visible():
        fail("errorpages", "the save bar shows without a change")
    wait_preview("Access denied", "default")
    if pg.get_attribute("#epPreview", "sandbox") != "allow-same-origin":
        fail("errorpages", "the preview frame must be sandboxed without scripts")
    shots("default")

    # ---- theme: live preview, ONE save bar ----
    current["page"] = "errorpages/theme"
    pg.fill("#epLogoText", "Smoke <b>Corp</b>")
    wait_preview("Smoke &lt;b&gt;Corp&lt;/b&gt;", "theme name")
    pg.fill("#epFooter", "Call 555-0100")
    wait_preview("Call 555-0100", "footer")
    pg.click("label[for=epEnabled]")
    pg.wait_for_timeout(300)
    if bar_visible() != 1:
        fail("errorpages", f"expected exactly one save bar, {bar_visible()} are visible")
    primaries = pg.evaluate("[...document.querySelectorAll('#errorpages .zx-btn--primary, #errorpages .ui.primary.button')].filter(b => b.offsetParent !== null).length")
    if primaries != 1:
        fail("errorpages", f"expected one primary button (Save), found {primaries}")
    if pg.evaluate("document.querySelectorAll('#errorpages .zx-savebar').length") != 1:
        fail("errorpages", "more than one save bar was created")
    if api_get().get("Enabled"):
        fail("errorpages", "the switch must not save by itself")
    # an invalid logo address is refused by Save with the reason, nothing is saved
    pg.fill("#epLogoURL", "javascript:alert(1)")
    pg.wait_for_timeout(500)
    save(expect_ok=False)
    if "logo" not in pg.inner_text("#errorpages .zx-savebar").lower() or api_get().get("Enabled"):
        fail("errorpages", "an invalid logo address must be refused with the reason: " + pg.inner_text("#errorpages .zx-savebar"))
    pg.fill("#epLogoURL", "")

    # ---- a page: text, hostile markup, HTML tab ----
    current["page"] = "errorpages/403"
    section("403")
    pg.wait_for_selector("#epClassPanel:not([hidden])", timeout=3000)
    if pg.inner_text("#epHead .zx-sectionhead__title").strip() != "Access denied":
        fail("errorpages", "section head did not follow the navigation")
    if "403" not in pg.inner_text("#epStatuses") or "Built-in page" not in pg.inner_text("#epClassState"):
        fail("errorpages", f"class state: {pg.inner_text('.ep-when')!r}")
    hostile = "Stop <img src=x onerror=window.__epx=1>"
    pg.fill("#epTitle", hostile)
    wait_preview("Stop &lt;img src=x onerror=window.__epx=1&gt;", "hostile title")
    pg.fill("#epMessage", "Ask the owner.\nSecond line.")
    wait_preview("Second line.", "message")
    if pg.evaluate("window.__epx") or pg.evaluate("document.getElementById('epPreview').contentDocument.querySelector('img[src=x]') !== null"):
        fail("errorpages", "markup typed as a title became markup in the preview")
    if "Own text" not in pg.inner_text("#epClassState"):
        fail("errorpages", "the state of the page did not follow the text")
    shots("403-text")

    if pg.is_visible("#epPanelHTML"):
        fail("errorpages", "a page without its own HTML must open on the Text tab")
    pg.click("#epTabs .zx-tab[data-zx-panel=epPanelHTML]")
    starters = pg.eval_on_selector_all("#epStarters [data-ep-starter]", "els => els.map(e => e.getAttribute('data-ep-starter'))")
    if starters != ["minimal", "branded", "friendly"]:
        fail("errorpages", f"starter templates: {starters}")
    pg.click("#epStarters [data-ep-starter=friendly]")
    pg.wait_for_function("document.getElementById('epTemplate').value.includes('What you can do')", timeout=3000)
    wait_preview("What you can do", "friendly starter")
    pg.click("#epStarters [data-ep-starter=minimal]")  # the editor is not empty: asks first
    confirm(True)
    pg.wait_for_function("!document.getElementById('epTemplate').value.includes('What you can do')", timeout=3000)
    wait_preview("&lt;img src=x onerror=window.__epx=1&gt;", "minimal starter with the hostile title")
    if not pg.is_visible("#epHTMLBadge") or "KB" not in pg.inner_text("#epSize"):
        fail("errorpages", "the HTML tab must show that it is in use and how large it is")
    pg.locator("#epVarsBox summary").click()
    vars_text = pg.inner_text("#epVars")
    for v in ("{{.Status}}", "{{.Title}}", "{{.Message}}", "{{.Host}}", "{{.RequestID}}", "{{.Time}}", "{{.ClientIP}}"):
        if v not in vars_text:
            fail("errorpages", f"variables help lacks {v}")
    shots("403-html")

    # a broken template: reported next to the preview, refused by Save
    good = pg.input_value("#epTemplate")
    pg.fill("#epTemplate", "<p>{{.Nope}}</p>")
    try:
        pg.wait_for_selector("#epPreviewError:not([hidden])", timeout=6000)
    except Exception:
        fail("errorpages", "a broken template was not reported")
    if "Nope" not in pg.inner_text("#epPreviewError"):
        fail("errorpages", "the preview error does not name the problem: " + pg.inner_text("#epPreviewError"))
    save(expect_ok=False)
    if api_get().get("Enabled") or api_get().get("Pages"):
        fail("errorpages", "a broken template was saved")
    pg.screenshot(path=out("errorpages-broken-template.png"), full_page=True)
    pg.fill("#epTemplate", good)
    pg.wait_for_selector("#epPreviewError", state="hidden", timeout=6000)

    # the test link refuses to pretend while there are unsaved changes
    href = pg.get_attribute("#epTest", "href")
    if href != "/api/errorpages/test?class=403" or pg.get_attribute("#epTest", "target") != "_blank":
        fail("errorpages", f"test link: {href!r}")
    if "Save first" not in pg.inner_text("#epTestHint"):
        fail("errorpages", "the test hint must say that the test shows the saved page")

    # ---- save: switched on, served with its status and headers ----
    current["page"] = "errorpages/save"
    save()
    cfg = api_get()
    if not cfg.get("Active") or cfg["Pages"]["403"]["Title"] != hostile or cfg["Theme"]["LogoText"] != "Smoke <b>Corp</b>" or not cfg["Pages"]["403"].get("Template"):
        fail("errorpages", f"not saved as entered: {json.dumps(cfg)[:600]}")
    pg.wait_for_function("document.getElementById('epStatus').textContent.trim() === 'On'", timeout=3000)
    if "Custom" not in pg.inner_text("#epNav .zx-sectionnav__item[data-ep='403']") or "On" not in pg.inner_text("#epNav .zx-sectionnav__item[data-ep='theme']"):
        fail("errorpages", "the navigation does not show what is on")
    status, headers, body = served("403")
    if status != 403 or headers.get("x-zoraxy-error-page") != "custom" or headers.get("cache-control") != "no-store" or "default-src 'none'" not in headers.get("content-security-policy", ""):
        fail("errorpages", f"served page: {status} {headers}")
    if "<img src=x" in body or "&lt;img src=x onerror=window.__epx=1&gt;" not in body or "ZX-TEST-TEST" not in body:
        fail("errorpages", "the served page is not the escaped custom page: " + body[:400])
    status, headers, body = served("5xx")
    if status != 521 or headers.get("x-zoraxy-error-page") != "built-in":
        fail("errorpages", "a page that was not changed must stay the built-in one")
    if bar_visible():
        pg.wait_for_timeout(2600)
    if "Save first" in pg.inner_text("#epTestHint"):
        fail("errorpages", "the test hint still asks to save")

    # "Use this look for every page": the untouched classes become themed
    section("theme")
    pg.click("label[for=epApplyBuiltin]")
    save()
    status, headers, body = served("429")
    if status != 429 or headers.get("x-zoraxy-error-page") != "custom" or "Too many requests" not in body or "Call 555-0100" not in body:
        fail("errorpages", f"themed built-in 429: {status} {headers.get('x-zoraxy-error-page')}")

    # ---- pages of one site ----
    current["page"] = "errorpages/scope"
    r = post("/api/errorpages/template/set", {"class": "404", "host": "shop.smoke.example.com", "title": "Shop page gone"})
    if "error" in r:
        fail("errorpages", f"template/set: {r}")
    pg.evaluate("openTabById('status')")
    settle(pg, 400)
    pg.evaluate("openTabById('errorpages')")
    settle(pg, 900)
    section("404")
    opts = pg.eval_on_selector_all("#epScope option", "els => els.map(e => e.value)")
    if "shop.smoke.example.com" not in opts or opts[0] != "":
        fail("errorpages", f"scope options: {opts}")
    if pg.input_value("#epTitle") != "":
        fail("errorpages", "the page of all sites shows the text of one site")
    pg.select_option("#epScope", "shop.smoke.example.com")
    pg.wait_for_function("document.getElementById('epTitle').value === 'Shop page gone'", timeout=3000)
    if pg.get_attribute("#epTest", "href") != "/api/errorpages/test?class=404&host=shop.smoke.example.com":
        fail("errorpages", "the test link does not follow the site: " + str(pg.get_attribute("#epTest", "href")))
    status, headers, body = served("404", "shop.smoke.example.com")
    if status != 404 or "Shop page gone" not in body:
        fail("errorpages", "the page of the site is not served for it")
    if "Shop page gone" in served("404", "other.smoke.example.com")[2]:
        fail("errorpages", "the page of one site is served for another")
    # leaving a site with unsaved changes asks first
    pg.fill("#epTitle", "Shop page gone!")
    pg.select_option("#epScope", "")
    confirm(False)
    if pg.input_value("#epScope") != "shop.smoke.example.com" or pg.input_value("#epTitle") != "Shop page gone!":
        fail("errorpages", "cancelling the site switch lost the edit")
    pg.evaluate("document.querySelector('#errorpages .zx-savebar [data-zx-discard]').click()")
    pg.wait_for_function("document.getElementById('epTitle').value === 'Shop page gone'", timeout=3000)
    shots("scope")
    pg.click("#epScopeRemove")
    confirm(True)
    pg.wait_for_function("document.getElementById('epScope').value === ''", timeout=5000)
    if api_get().get("Hosts"):
        fail("errorpages", "the pages of the site were not removed")

    # ---- "Use the built-in page" for one class ----
    current["page"] = "errorpages/class-reset"
    section("403")
    pg.wait_for_function("document.getElementById('epTitle').value.startsWith('Stop')", timeout=3000)
    if not pg.is_visible("#epPanelHTML"):
        fail("errorpages", "a page with its own HTML must open on the HTML tab")
    pg.click("#epClassReset")
    if pg.input_value("#epTitle") != "" or pg.input_value("#epTemplate") != "":
        fail("errorpages", "'Use the built-in page' did not clear the editor")
    save()
    if "403" in (api_get().get("Pages") or {}):
        fail("errorpages", "the 403 page is still saved")

    # ---- phone: the navigation is a select ----
    current["page"] = "errorpages/phone"
    pg.set_viewport_size({"width": 390, "height": 1100})
    pg.wait_for_timeout(400)
    if not pg.is_visible("#epNav .zx-sectionnav__picker select"):
        fail("errorpages", "the section picker is missing on a phone")
    pg.select_option("#epNav .zx-sectionnav__picker select", "5xx")
    pg.wait_for_function("document.querySelector('#epHead .zx-sectionhead__title').textContent.trim() === 'Server error'", timeout=3000)
    layout("phone/5xx")
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ---- reset everything ----
    current["page"] = "errorpages/reset"
    pg.click("#epResetAll")
    confirm(True)
    pg.wait_for_function("document.getElementById('epStatus').textContent.trim() === 'Off'", timeout=5000)
    cfg = api_get()
    if cfg.get("Enabled") or cfg.get("Pages") or cfg.get("Hosts") or cfg["Theme"].get("LogoText"):
        fail("errorpages", f"reset left something behind: {cfg}")
    status, headers, body = served("403")
    if headers.get("x-zoraxy-error-page") != "built-in" or "403 - Forbidden" not in body:
        fail("errorpages", "after the reset the built-in page must answer")
    print("errorpages scenario done")
