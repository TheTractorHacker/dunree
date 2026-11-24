"""Smoke scenario of the "renewal about to start" notification (issue #178, event certificate.renewing). exec()'d by smoke.py
(namespace: fail, current, args, os, re, check_horizontal); run alone with --renew-notice-only on a throw-away instance.
It makes its own webhook and removes it; no webhook is delivered and no CA is contacted (the ACME side is covered by Go tests).

Checks: off by default (lead time 0, the API marks certificate.renewing as opt-in); Certificates > "CSR, certificate folder" >
Event Hooks offers "renewal about to start" (not ticked) and the lead time field; a webhook that ticks it is saved with that
event; the lead time round-trips through the form, survives reopening the drawer and a value above the limit is refused with
the stored value kept; the Notifications page marks the event "sent only when ticked" in the channel editor (with the other
opt-in events of the API, nothing else) and says that the minimum severity filters ticked events too.
Screenshots (light, dark, 390px) go to --out."""

RN_HOOK = "Smoke open port 80"
RN_EVENT = "certificate.renewing"


def renew_notice_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def view():
        return js("fetch('/api/notify/hooks').then(r => r.json())")

    def post(data):
        return js("""d => new Promise(res => $.cjax({url: '/api/notify/hooks', method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status})}))""", data)

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def toasts():
        return js("[...document.querySelectorAll('.zx-toast__msg, #messageBox')].filter(e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden').map(e => e.innerText.trim()).filter(Boolean)")

    def clear_toasts():
        js("document.querySelectorAll('.zx-toast').forEach(e => e.remove())")

    def wait_drawer(open_):
        pg.wait_for_function("o => ($('.sideWrapper').is(':visible') && !$('.sideWrapper .content').transition('is animating')) === o", arg=open_, timeout=6000)

    def open_hooks():
        pg.click("#certPage button:has-text('CSR, certificate folder')")
        wait_drawer(True)
        pg.wait_for_timeout(600)
        fr = [f for f in pg.frames if "certtools" in f.url][0]
        fr.click(".ui.tabular.menu .item[data-tab=hooks]")
        fr.wait_for_selector("#optLead", state="visible", timeout=6000)
        pg.wait_for_timeout(500)
        return fr

    def close_drawer():
        js("hideSideWrapper()")
        pg.wait_for_timeout(600)

    def cleanup():
        for h in view().get("webhooks") or []:
            if h.get("name") == RN_HOOK:
                post({"op": "deleteWebhook", "id": h["id"]})
        v = view()
        post({"op": "setOptions", "allowPrivateTargets": str(bool(v.get("allowPrivateTargets"))).lower(), "expiryWarnDays": v.get("expiryWarnDays", 14), "renewLeadSeconds": 0})

    current["page"] = "renew-notice"
    print("page", current["page"])
    cleanup()
    try:
        # ---- defaults ----
        v = view()
        if v.get("renewLeadSeconds") != 0:
            fail("renew-notice", f"the lead time must default to 0, got {v.get('renewLeadSeconds')}")
        if RN_EVENT not in (v.get("events") or []) or RN_EVENT not in (v.get("optInEvents") or []):
            fail("renew-notice", f"the API must offer {RN_EVENT} as an opt-in event: {v.get('events')} / {v.get('optInEvents')}")

        js("openTabById('cert')")
        pg.wait_for_selector("#certPage button:has-text('CSR, certificate folder')", timeout=8000)
        pg.wait_for_timeout(600)
        fr = open_hooks()
        if fr.input_value("#optLead") != "0":
            fail("renew-notice", f"the lead time field must show 0 by default, shows {fr.input_value('#optLead')!r}")
        box = f".hookEv[value='{RN_EVENT}']"
        if fr.evaluate("s => document.querySelector(s).checked", box):
            fail("renew-notice", "the 'renewal about to start' event is ticked without being asked")

        # ---- a webhook that subscribes ----
        fr.fill("#hookName", RN_HOOK)
        fr.fill("#hookURL", "https://hooks.example.com/open-port-80")
        fr.evaluate("s => document.querySelector(s).click()", box)
        clear_toasts()
        fr.click("button:has-text('Save webhook')")
        fr.wait_for_function("n => [...document.querySelectorAll('#hookList tr')].some(r => r.innerText.includes(n))", arg=RN_HOOK, timeout=6000)
        row = fr.evaluate("n => [...document.querySelectorAll('#hookList tr')].filter(r => r.innerText.includes(n)).map(r => r.innerText)[0]", RN_HOOK)
        if RN_EVENT not in row:
            fail("renew-notice", f"the saved webhook does not list the event: {row!r}")
        saved = [h for h in view().get("webhooks") or [] if h.get("name") == RN_HOOK]
        if not saved or saved[0].get("events") != [RN_EVENT]:
            fail("renew-notice", f"the webhook was not stored with the event: {saved}")

        # ---- lead time: saved, kept, bounded ----
        fr.fill("#optLead", "30")
        clear_toasts()
        fr.click("button:has-text('Save options')")
        pg.wait_for_timeout(700)
        if view().get("renewLeadSeconds") != 30:
            fail("renew-notice", f"a lead time of 30 was not stored: {view().get('renewLeadSeconds')} (toasts {toasts()})")
        # the hint names the command hook and the private-target switch; one Save button, below both number fields
        hint = fr.evaluate("document.querySelector('.tab[data-tab=hooks]').innerText")
        if "command hook subscribed" not in hint or "receiver on your own network" not in hint:
            fail("renew-notice", "the lead time hint does not mention the command hook or the private-target switch")
        geo = fr.evaluate("(() => { const b = [...document.querySelectorAll('button')].filter(x => x.innerText.includes('Save options')); const y = id => document.getElementById(id).getBoundingClientRect().bottom; return [b.length, b[0].getBoundingClientRect().top, y('optLead'), y('optWarn')]; })()")
        if geo[0] != 1 or geo[1] < geo[2] or geo[1] < geo[3]:
            fail("renew-notice", f"'Save options' must be the one button below the warn-days and lead time fields: {geo}")
        fr.fill("#optLead", "99999")
        clear_toasts()
        fr.click("button:has-text('Save options')")
        pg.wait_for_timeout(700)
        msg = " ".join(toasts())
        if "between 0 and" not in msg:
            fail("renew-notice", f"a lead time above the limit is not refused with a clear message: {msg!r}")
        if view().get("renewLeadSeconds") != 30:
            fail("renew-notice", "a refused lead time changed the stored value")
        clear_toasts()
        close_drawer()

        # ---- reopen: shown again; light, dark, 390px ----
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("390", False, 390)):
            theme(dark)
            pg.set_viewport_size({"width": w, "height": 1000})
            pg.wait_for_timeout(400)
            fr = open_hooks()
            if fr.input_value("#optLead") != "30":
                fail("renew-notice", f"{label}: the stored lead time is not shown after reopening: {fr.input_value('#optLead')!r}")
            over = fr.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            if over > 2:
                fail("layout", f"renew-notice {label}: the Event Hooks tab scrolls sideways by {over}px")
            lead = fr.evaluate("(() => { const r = document.getElementById('optLead').getBoundingClientRect(); return [r.left, r.right, innerWidth]; })()")
            if lead[0] < 0 or lead[1] > lead[2] + 1:
                fail("layout", f"renew-notice {label}: the lead time field is clipped: {lead}")
            fr.evaluate("document.getElementById('optLead').scrollIntoView({block: 'center'})")
            pg.wait_for_timeout(300)
            pg.screenshot(path=os.path.join(args.out, f"renew-notice-hooks-{label}.png"))
            close_drawer()
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 800})

        # ---- Notifications page: the channel editor marks the event as opt-in ----
        for label, scheme in (("light", "light"), ("dark", "dark")):
            c2 = pg.context.browser.new_context(viewport={"width": 1366, "height": 1000}, color_scheme=scheme)
            sp = c2.new_page()
            sp.on("pageerror", lambda e: fail("pageerror", str(e)))
            sp.on("console", lambda m: m.type == "error" and fail("console.error", m.text + " " + m.location.get("url", "")))
            sp.goto(args.url + "/snippet/notifications.html", wait_until="networkidle")
            sp.wait_for_timeout(700)
            sp.click("button:has-text('Add channel')")
            sp.wait_for_selector("#c_events .evbox", timeout=6000)
            marks = sp.evaluate("[...document.querySelectorAll('#c_events label')].filter(l => l.innerText.includes('sent only when ticked')).map(l => l.querySelector('input').value)")
            optin = view().get("optInEvents") or []
            if RN_EVENT not in marks or [m for m in marks if m not in optin]:
                fail("renew-notice", f"the channel editor must mark {RN_EVENT} and only the API's opt-in events {optin}, marked: {marks}")
            note = sp.evaluate("(() => { const e = document.getElementById('c_sevNote'); return e && e.getClientRects().length ? e.innerText : ''; })()")
            if "minimum severity" not in note:
                fail("renew-notice", f"the channel editor does not say that the minimum severity also filters ticked events: {note!r}")
            if sp.evaluate("document.querySelectorAll('#c_events .evbox:checked').length") != 0:
                fail("renew-notice", "a new channel starts with events ticked")
            check_horizontal(sp, "notifications channel editor " + label)
            sp.evaluate("document.querySelector(\"#c_events .evbox[value='certificate.renewing']\").scrollIntoView({block: 'center'})")
            sp.wait_for_timeout(300)
            sp.screenshot(path=os.path.join(args.out, f"renew-notice-channel-{label}.png"))
            c2.close()
    except Exception as ex:
        fail("renew-notice", f"scenario failed: {' '.join(str(ex).split()[:40])}")
        try:
            pg.screenshot(path=os.path.join(args.out, "renew-notice-failure.png"))
        except Exception:
            pass
    finally:
        try:
            if js("$('.sideWrapper').is(':visible')"):
                close_drawer()
            theme(False)
            pg.set_viewport_size({"width": 1366, "height": 800})
            cleanup()
        except Exception:
            pass
