"""Smoke scenario of Security Center > Header rules, the options added for the rest of issue #245 (upstream #1356).
exec()'d by smoke.py (namespace: fail, current, args, os, re, check_horizontal); run alone with --headerrules-only on a
throw-away instance whose proxy port is the UI port + 1. It makes its own proxy rule and removes it.

Checks: a new rule starts with the old meaning (every rule, 403, nothing removed, nobody excepted) and is stored without the new
fields; "answer another status code" shows the code box, an empty or out of range code and an unreadable exception address are
refused by the server and nothing is stored; own status code, "be absent", "at least one rule" and the exception list are saved,
shown again after a reload (the secret is not) and enforced on the proxy port; no nested scroller, nothing scrolls sideways at
390px. Screenshots (light, dark, 390px) go to --out. Removing the header before forwarding is covered by the Go tests
(TestHeaderRuleStrip): the scenario has no upstream that could report what it received."""

import ssl as _hr_ssl
import urllib.error as _hr_uerr
import urllib.request as _hr_ureq

HR_HOST = "hr-gap.smoke.test"
HR_SECRET = "s3cret-smoke-245"


def headerrules_ui(pg, ctx):
    base = int(args.url.rsplit(":", 1)[1].split("/")[0])
    proxy_port = base + 1

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def stored():
        return post("/api/proxy/detail", {"type": "host", "epname": HR_HOST})

    def meta():
        return js("h => fetch('/api/headerrules/get?meta=true&ep=' + encodeURIComponent(h)).then(r => r.json())", HR_HOST)

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    tls = _hr_ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = _hr_ssl.CERT_NONE
    scheme = {"v": None}

    def hit(headers=None):
        """one request through the proxy port, returns the status (None: no answer)"""
        hdr = {"Host": HR_HOST}
        hdr.update(headers or {})
        for sch in ([scheme["v"]] if scheme["v"] else ["http", "https"]):
            r = _hr_ureq.Request("%s://127.0.0.1:%d/" % (sch, proxy_port), headers=hdr)
            try:
                with _hr_ureq.urlopen(r, timeout=8, context=tls) as resp:
                    scheme["v"] = sch
                    return resp.status
            except _hr_uerr.HTTPError as e:
                if e.code == 400 and "HTTPS server" in e.read().decode("utf-8", "replace"):
                    continue
                scheme["v"] = sch
                return e.code
            except Exception:
                continue
        return None

    BLOCKED = (401, 403, 404, 444, 503, None)

    def expect(what, headers, want):
        got = hit(headers)
        if want == "pass":
            if got in BLOCKED:
                fail("headerrules", f"{what}: the request must be let in, got {got}")
        elif got != want:
            fail("headerrules", f"{what}: got {got}, want {want}")

    def save(expect_error=None):
        pg.click("#hrSave")
        pg.wait_for_timeout(900)
        shown = pg.locator("#hrMsg").is_visible()
        if expect_error is None and shown:
            fail("headerrules", f"save refused: {pg.locator('#hrMsg').inner_text()!r}")
        if expect_error is not None and (not shown or expect_error not in pg.locator("#hrMsg").inner_text()):
            fail("headerrules", f"the server must refuse this ({expect_error!r}), message: {pg.locator('#hrMsg').inner_text() if shown else None!r}")

    def open_pane():
        js("openTabById('seccenter')")
        pg.wait_for_selector("#secTabs .item[data-sec='headers']", state="attached", timeout=10000)
        pg.dispatch_event("#secTabs .item[data-sec='headers']", "click", timeout=6000)
        pg.wait_for_selector("#hrEp option[value='%s']" % HR_HOST, state="attached", timeout=10000)
        pg.wait_for_timeout(900)
        pg.select_option("#hrEp", HR_HOST)
        pg.wait_for_timeout(700)

    current["page"] = "headerrules"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    post("/api/proxy/del", {"ep": HR_HOST})
    r = post("/api/proxy/add", {"type": "host", "rootname": HR_HOST, "ep": "127.0.0.1:%d" % base, "tls": False, "tlsval": False, "bpwsorg": True,
                                "bypassGlobalTLS": False, "bauth": False, "cred": "[]", "rate": False, "ratenum": 100, "access": "default",
                                "stickysess": False, "tags": "", "enableUtm": False, "utmURI": ""})
    if isinstance(r, dict) and r.get("error"):
        fail("headerrules", f"could not create {HR_HOST}: {r}")
    try:
        if hit() in BLOCKED:
            fail("headerrules", f"the proxy port {proxy_port} does not serve {HR_HOST} (got {hit()}); the scenario needs proxy port = UI port + 1")
        m = meta()
        if m.get("Mode") != "all" or m.get("Except") != [] or m.get("Rules") != []:
            fail("headerrules", f"a site without rules must report all / no exceptions / no rules: {m}")
        if js("h => fetch('/api/headerrules/get?ep=' + encodeURIComponent(h)).then(r => r.json())", HR_HOST) != []:
            fail("headerrules", "the plain read must stay a list")

        # ---- 1. a new rule keeps the old meaning and is stored without the new fields
        open_pane()
        if pg.locator("#hrSet").is_visible():
            fail("headerrules", "the rule set options must not show while the site has no rule")
        pg.click("#hrAdd")
        row1 = "#hrRows .hrRow:nth-child(1) "
        d = js("""() => { const r = document.querySelector('#hrRows .hrRow'); return {m: r.querySelector('.hm').value, a: r.querySelector('.ha').value, s: r.querySelector('.hs').checked,
            code: getComputedStyle(r.querySelector('.hr-code')).display, mode: document.getElementById('hrMode').value, ex: document.getElementById('hrExcept').value}; }""")
        if d != {"m": "equals", "a": "deny", "s": False, "code": "none", "mode": "all", "ex": ""}:
            fail("headerrules", f"a new rule must start with the old meaning: {d}")
        pg.fill(row1 + ".hn", "X-Edge-Key")
        pg.fill(row1 + ".hv", HR_SECRET)
        save()
        ep = stored()
        hr = (ep.get("HeaderRules") or [{}])[0]
        if any(hr.get(k) for k in ("Negate", "StatusCode", "Strip")) or ep.get("HeaderRulesMode") or ep.get("HeaderRulesExcept"):
            fail("headerrules", f"a plain rule must be stored without the new options: {hr} {ep.get('HeaderRulesMode')!r} {ep.get('HeaderRulesExcept')!r}")
        expect("no header", None, 403)
        expect("wrong secret", {"X-Edge-Key": "nope"}, 403)
        expect("right secret", {"X-Edge-Key": HR_SECRET}, "pass")

        # ---- 2. own status code: the box appears, bad input is refused and nothing changes
        pg.select_option(row1 + ".ha", "status")
        if not pg.locator(row1 + ".hc").is_visible():
            fail("headerrules", "choosing another status code must show the code box")
        save("status code")
        pg.fill(row1 + ".hc", "200")
        save("status code")
        pg.fill(row1 + ".hc", "500")
        save("status code")
        expect("after refused saves", None, 403)
        pg.fill(row1 + ".hc", "401")
        pg.check(row1 + ".hs")
        save()
        expect("own status code", None, 401)
        expect("right secret, own status", {"X-Edge-Key": HR_SECRET}, "pass")

        # ---- 3. "be absent", then "at least one rule"
        pg.click("#hrAdd")
        row2 = "#hrRows .hrRow:nth-child(2) "
        pg.fill(row2 + ".hn", "X-Debug")
        pg.select_option(row2 + ".hm", "not-present")
        if pg.locator(row2 + ".hv").is_visible():
            fail("headerrules", "'be absent' takes no values")
        save()
        expect("every rule: secret plus forbidden header", {"X-Edge-Key": HR_SECRET, "X-Debug": "1"}, 403)
        expect("every rule: secret only", {"X-Edge-Key": HR_SECRET}, "pass")
        expect("every rule: nothing", None, 401)
        pg.select_option("#hrMode", "any")
        save()
        expect("at least one: nothing (X-Debug is absent)", None, "pass")
        expect("at least one: secret plus X-Debug", {"X-Edge-Key": HR_SECRET, "X-Debug": "1"}, "pass")
        expect("at least one: X-Debug without the secret", {"X-Debug": "1"}, 401)

        # ---- 4. exceptions: an unreadable address is refused, a valid one lets the client in
        pg.fill("#hrExcept", "10.0.0.0/8\nnot-an-address")
        save("not-an-address")
        if stored().get("HeaderRulesExcept"):
            fail("headerrules", "a refused exception list was stored")
        pg.fill("#hrExcept", "0.0.0.0/0")
        save("every address")
        pg.fill("#hrExcept", "0.0.0.0/1\n128.0.0.0/1")   # every address in two halves
        save("every IPv4 address")
        if stored().get("HeaderRulesExcept"):
            fail("headerrules", "an exception list that covers every address was stored")
        expect("after refused exceptions", {"X-Debug": "1"}, 401)
        pg.fill("#hrExcept", "10.0.0.0/8\n127.0.0.1\n::1")
        save()
        expect("excepted client", {"X-Debug": "1"}, "pass")
        pg.fill("#hrExcept", "10.0.0.0/8")
        save()
        expect("client not on the list", {"X-Debug": "1"}, 401)

        # ---- 5. after a reload the page shows what is stored, the secret is not sent back
        raw = js("h => fetch('/api/headerrules/get?meta=true&ep=' + encodeURIComponent(h)).then(r => r.text())", HR_HOST)
        if HR_SECRET in raw or HR_SECRET in json.dumps(stored()):
            fail("headerrules", "the secret is sent back to the browser")
        m = meta()
        r1, r2 = m["Rules"]
        if m["Mode"] != "any" or m["Except"] != ["10.0.0.0/8"] or r1.get("StatusCode") != 401 or not r1.get("Strip") or r1.get("Negate") or not r2.get("Negate") or r2.get("Match") != "present":
            fail("headerrules", f"stored rule set: {m}")
        js("openTabById('status')")
        pg.wait_for_timeout(500)
        open_pane()
        d = js("""() => [...document.querySelectorAll('#hrRows .hrRow')].map(r => ({m: r.querySelector('.hm').value, a: r.querySelector('.ha').value, s: r.querySelector('.hs').checked,
            c: r.querySelector('.hc').value, v: r.querySelector('.hv').value, code: getComputedStyle(r.querySelector('.hr-code')).display}))""")
        want = [{"m": "equals", "a": "status", "s": True, "c": "401", "v": "", "code": "block"}, {"m": "not-present", "a": "deny", "s": False, "c": "", "v": "", "code": "none"}]
        if d != want or pg.input_value("#hrMode") != "any" or pg.input_value("#hrExcept") != "10.0.0.0/8":
            fail("headerrules", f"the page does not show the stored options: {d} mode={pg.input_value('#hrMode')!r} except={pg.input_value('#hrExcept')!r}")
        save()   # saving the page as loaded keeps the secret and every option
        expect("secret kept by a save without retyping", {"X-Edge-Key": HR_SECRET, "X-Debug": "1"}, "pass")
        if meta() != m:
            fail("headerrules", f"saving the page as loaded changed the rule set: {meta()}")

        # ---- 6. layout: no scroller inside the card, both themes, 390px
        inner = js("""() => [...document.querySelectorAll('#hrCard *')].filter(e => e.tagName !== 'TEXTAREA' && /(auto|scroll)/.test(getComputedStyle(e).overflowY + getComputedStyle(e).overflowX) && (e.scrollHeight > e.clientHeight + 1 || e.scrollWidth > e.clientWidth + 1)).map(e => e.id || e.className)""")
        if inner:
            fail("headerrules", f"nested scroller inside the card: {inner}")
        for dark in (False, True):
            theme(dark)
            pg.locator("#hrCard").scroll_into_view_if_needed()
            pg.screenshot(path=os.path.join(args.out, f"headerrules-options-{'dark' if dark else 'light'}.png"), full_page=True)
        theme(False)
        pg.set_viewport_size({"width": 390, "height": 900})
        pg.wait_for_timeout(400)
        check_horizontal(pg, "headerrules options 390px")
        o = js("""() => { const r = document.querySelector('#hrRows .hrRow.is-status'), y = s => r.querySelector(s).getBoundingClientRect();
            return {sel: y('.ha').bottom, code: y('.hr-code').top, codeEnd: y('.hr-code').bottom, next: Math.min(y('.hrDel').top, y('.hr-path').top, y('.hr-strip').top)}; }""")
        if not (o["sel"] <= o["code"] < o["sel"] + 40 and o["codeEnd"] <= o["next"]):
            fail("headerrules", f"390px: the status code box must follow the 'Otherwise' select directly: {o}")
        pg.locator("#hrSet").scroll_into_view_if_needed()
        pg.screenshot(path=os.path.join(args.out, "headerrules-options-390.png"), full_page=True)
        pg.set_viewport_size({"width": 1366, "height": 1000})
        pg.wait_for_timeout(300)

        # ---- 7. a stored rule set the proxy refuses to run is named on the page (the answer of the read is faked here:
        #         the real case is a hand-edited config, covered by TestHeaderRulesAPIOptions)
        def _invalid(route):
            body = dict(m)
            body["Mode"], body["Invalid"] = "bogus", "mode must be all or any"
            route.fulfill(status=200, content_type="application/json", body=json.dumps(body))
        pg.route("**/api/headerrules/get?meta=true*", _invalid)
        pg.select_option("#hrEp", HR_HOST)
        pg.dispatch_event("#hrEp", "change")
        pg.wait_for_timeout(700)
        pg.unroute("**/api/headerrules/get?meta=true*")
        txt = pg.locator("#hrMsg").inner_text() if pg.locator("#hrMsg").is_visible() else ""
        if "mode must be all or any" not in txt or "503" not in txt or pg.locator("#hrRows .hrRow").count() != 2:
            fail("headerrules", f"an invalid stored rule set must be named above its rules, message: {txt!r}")
        pg.locator("#hrMsg").scroll_into_view_if_needed()
        pg.screenshot(path=os.path.join(args.out, "headerrules-invalid.png"), full_page=True)
        pg.dispatch_event("#hrEp", "change")
        pg.wait_for_timeout(700)
        if pg.locator("#hrMsg").is_visible():
            fail("headerrules", "the notice must go away when the stored rule set is valid")

        # ---- 8. removing every rule removes the (now hidden) mode and exceptions with them
        if pg.input_value("#hrMode") != "any" or pg.input_value("#hrExcept") != "10.0.0.0/8":
            fail("headerrules", "precondition of step 8: the site is in 'at least one' mode with an exception")
        while pg.locator("#hrRows .hrRow").count():
            pg.click("#hrRows .hrRow:nth-child(1) .hrDel")
        if pg.locator("#hrSet").is_visible():
            fail("headerrules", "the rule set options must hide with the last rule")
        save()
        ep = stored()
        if ep.get("HeaderRules") or ep.get("HeaderRulesMode") or ep.get("HeaderRulesExcept"):
            fail("headerrules", f"a site without rules kept options: {ep.get('HeaderRulesMode')!r} {ep.get('HeaderRulesExcept')!r}")
        expect("no rules left", {"X-Debug": "1"}, "pass")
        r = post("/api/headerrules/set", {"ep": HR_HOST, "rules": json.dumps([{"Name": "X-Debug", "Match": "present", "Negate": True}, {"Name": "X-Edge-Key", "Values": [HR_SECRET]}])})
        if isinstance(r, dict) and r.get("error"):
            fail("headerrules", f"API set without mode: {r}")
        if meta().get("Mode") != "all" or meta().get("Except") != []:
            fail("headerrules", f"rules added later without a mode must mean 'every rule': {meta()}")
        expect("every rule again: nothing sent", None, 403)
    finally:
        post("/api/proxy/del", {"ep": HR_HOST})
