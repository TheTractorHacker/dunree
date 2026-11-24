"""Smoke scenario of Security Center > Auth audit: login tag drift and the optional automatic login tag (issue #216).
exec()'d by smoke.py (namespace: fail, current, args, os, check_horizontal); run alone with --authaudit-only on a throw-away
instance. It makes its own two rules and removes them, and puts the "Keep the login tag up to date" setting back.

Checks: the automatic tag is off on a fresh instance and an edit that changes the login leaves the tags alone; a rule tagged
auth:oauth2 without a login is named in the warning box, its row says so and offers "Fix tag", an untagged rule does not; Fix tag
only changes the tag (auth:none, other tags kept, login untouched) and the warning goes away; with the switch on, an edit that
carries the login refreshes the tag and an edit without it does not; auth.drift is in the notification catalogue as an opt-in
event. Screenshots (light, dark, 390px) go to --out."""

AA_OPEN = "aa-drift.smoke.test"
AA_BASIC = "aa-basic.smoke.test"


def authaudit_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def audit():
        return js("fetch('/api/authaudit/get').then(r => r.json())")

    def row(host):
        return next((r for r in audit()["Rows"] if r["Name"] == host), None)

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def add(host, tags, bauth):
        r = post("/api/proxy/add", {"type": "host", "rootname": host, "ep": "127.0.0.1:9", "tls": False, "tlsval": False, "bpwsorg": True,
                                   "bypassGlobalTLS": False, "bauth": bauth, "cred": "[]", "rate": False, "ratenum": 100, "access": "default",
                                   "stickysess": False, "tags": tags, "enableUtm": False, "utmURI": ""})
        if isinstance(r, dict) and r.get("error"):
            fail("authaudit", f"could not create {host}: {r}")

    def row_html(host):
        return js("h => { const li = [...document.querySelectorAll('#aaRows .sx-row')].find(x => x.querySelector('.sx-row__title').textContent.trim().startsWith(h)); return li ? li.innerText : null }", host)

    def has_fix(host):
        return js("h => !!document.querySelector('#aaRows .aaFix[data-ep=\"' + h + '\"]')", host)

    def reload_pane():
        pg.click("#aaRefresh")
        pg.wait_for_timeout(700)

    current["page"] = "authaudit"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    for h in (AA_OPEN, AA_BASIC):
        post("/api/proxy/del", {"ep": h})
    was_auto = bool(audit().get("AutoTag"))
    post("/api/authaudit/setAutoTag", {"enable": "false"})
    try:
        # ---- 1. off by default: nothing tags a rule on save
        add(AA_OPEN, "auth:oauth2,prod", False)   # tagged as OAuth2, but nothing asks for a login: the reporter's case
        add(AA_BASIC, "team", True)
        if audit().get("AutoTag"):
            fail("authaudit", "the automatic login tag must be off")
        if row(AA_BASIC)["Tags"] != ["team"] or row(AA_BASIC)["TagDrift"]:
            fail("authaudit", f"a new rule was tagged although the setting is off: {row(AA_BASIC)}")
        post("/api/proxy/edit", {"rootname": AA_BASIC, "authprovider": 1})
        if row(AA_BASIC)["Tags"] != ["team"]:
            fail("authaudit", f"an edit tagged the rule although the setting is off: {row(AA_BASIC)['Tags']}")

        # ---- 2. the page reports the drift
        js("openTabById('seccenter')")
        pg.wait_for_selector("#secTabs .item[data-sec='authaudit']", state="attached", timeout=10000)
        pg.dispatch_event("#secTabs .item[data-sec='authaudit']", "click", timeout=6000)
        pg.wait_for_selector("#aaRows .sx-row", timeout=10000)
        pg.wait_for_timeout(700)
        if js("document.getElementById('aaAuto').checked"):
            fail("authaudit", "the switch must show off")
        box = pg.locator("#aaDrift")
        if not box.is_visible() or AA_OPEN not in box.inner_text() or AA_BASIC in box.inner_text():
            fail("authaudit", f"the warning must name {AA_OPEN} only: {box.inner_text()!r}")
        txt = row_html(AA_OPEN) or ""
        if "auth:oauth2" not in txt or "no login" not in txt or not has_fix(AA_OPEN):
            fail("authaudit", f"the drifting row must say what is tagged and offer Fix tag: {txt!r}")
        if has_fix(AA_BASIC) or js("document.querySelectorAll('#aaRows .aa-drift').length") != 1:
            fail("authaudit", "only the drifting rule gets the mismatch line and the Fix tag button")
        if not js("document.querySelector('#aaRows .aaFix').getAttribute('aria-label').includes('auth:none')"):
            fail("a11y", "Fix tag must say which tag it sets")
        # the list can be narrowed to the mismatches
        pg.click("#aaFilter [data-value='drift']")
        pg.wait_for_timeout(300)
        shown = js("[...document.querySelectorAll('#aaRows .sx-row .sx-row__title')].map(x => x.textContent.trim())")
        if len(shown) != 1 or not shown[0].startswith(AA_OPEN) or js("document.getElementById('aaNDrift').textContent") != "1":
            fail("authaudit", f"the Tag mismatch filter must show the drifting rule only: {shown}")
        pg.click("#aaFilter [data-value='all']")
        pg.wait_for_timeout(300)
        for dark in (False, True):
            theme(dark)
            pg.screenshot(path=os.path.join(args.out, f"authaudit-drift-{'dark' if dark else 'light'}.png"), full_page=True)
        theme(False)
        pg.set_viewport_size({"width": 390, "height": 900})
        pg.wait_for_timeout(400)
        check_horizontal(pg, "authaudit drift 390px")
        tops = js("(() => { const f = document.querySelector('#aaRows .aaFix'); const s = f.parentElement.querySelector('.aaSet'); return [f.getBoundingClientRect().top, s ? s.getBoundingClientRect().top : -1] })()")
        if abs(tops[0] - tops[1]) > 2:
            fail("layout", f"authaudit 390px: Fix tag and Set login must stay on one line as a pair: {tops}")
        seg = js("(() => { const f = document.getElementById('aaFilter'); const l = f.lastElementChild.getBoundingClientRect(); return [f.scrollWidth - f.clientWidth, l.right, innerWidth] })()")
        if seg[0] > 1 or seg[1] > seg[2]:
            fail("layout", f"authaudit 390px: the filter must wrap, not scroll sideways or clip: {seg}")
        pg.locator("#aaRows .aaFix").scroll_into_view_if_needed()
        pg.screenshot(path=os.path.join(args.out, "authaudit-drift-390.png"))
        pg.set_viewport_size({"width": 1366, "height": 1000})
        pg.wait_for_timeout(300)

        # ---- 3. Fix tag changes the tag only
        pg.click("#aaRows .aaFix[data-ep='%s']" % AA_OPEN)
        pg.wait_for_function("!document.querySelector('#aaRows .aaFix')", timeout=8000)
        r = row(AA_OPEN)
        if r["Tags"] != ["prod", "auth:none"] or r["Method"] != "none" or r["TagDrift"]:
            fail("authaudit", f"Fix tag: {r}")
        if pg.locator("#aaDrift").is_visible():
            fail("authaudit", "the warning must go away once no tag drifts")
        r = post("/api/authaudit/autotag", {"ep": AA_OPEN})
        if r.get("Changed") != 0 or r.get("Tag") != "auth:none":
            fail("authaudit", f"a tag that already matches must report no change: {r}")
        if not post("/api/authaudit/autotag", {"ep": "aa-gone.smoke.test"}).get("error"):
            fail("authaudit", "Fix tag for a rule that does not exist must be an error")

        # ---- 4. opt-in: the tag follows a login chosen in the request
        pg.click("label[for=aaAuto]")
        pg.wait_for_timeout(700)
        if not audit().get("AutoTag"):
            fail("authaudit", "the switch did not store the setting")
        post("/api/proxy/edit", {"rootname": AA_BASIC, "authprovider": 1})
        if row(AA_BASIC)["Tags"] != ["team", "auth:basic"]:
            fail("authaudit", f"the tag must follow the saved login: {row(AA_BASIC)['Tags']}")
        post("/api/proxy/edit", {"rootname": AA_BASIC, "authprovider": 0})
        if row(AA_BASIC)["Tags"] != ["team", "auth:none"] or row(AA_BASIC)["TagDrift"]:
            fail("authaudit", f"the tag must follow the saved login: {row(AA_BASIC)['Tags']}")
        # an edit that does not carry the login keeps the tag: it still records what was intended
        post("/api/proxy/edit", {"rootname": AA_BASIC, "tags": "team,auth:basic"})
        r = row(AA_BASIC)
        if r["Tags"] != ["team", "auth:basic"] or not r["TagDrift"]:
            fail("authaudit", f"an edit without the login must not retag: {r}")
        reload_pane()
        if not has_fix(AA_BASIC) or not pg.locator("#aaDrift").is_visible():
            fail("authaudit", "the page must show the new drift after Check again")
        pg.screenshot(path=os.path.join(args.out, "authaudit-autotag-on.png"), full_page=True)

        # ---- 5. the notify event exists and is opt-in
        c = js("fetch('/api/notify/center').then(r => r.json())")
        ev = next((e for e in c.get("events", []) if e.get("name") == "auth.drift"), None)
        if not ev or not ev.get("optIn") or ev.get("severity") != "warning":
            fail("authaudit", "auth.drift must be in the notification catalogue as an opt-in event")
    finally:
        for h in (AA_OPEN, AA_BASIC):
            post("/api/proxy/del", {"ep": h})
        post("/api/authaudit/setAutoTag", {"enable": "true" if was_auto else "false"})
