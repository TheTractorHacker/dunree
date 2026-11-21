"""Smoke scenario of the enterprise baseline card (Security Center > Overview, mod/baseline, src/baselineapi.go).
exec()'d by smoke.py (namespace: fail, current, args, os, re, allow, check_horizontal); run alone with --baseline-only. It needs a throw-away
instance that is an EXISTING-STYLE install (the baseline was not applied at its first start: tools/ui-smoke/run.sh seeds a file in conf/ before
the first start for that reason) and it belongs at the very END of a full run because it changes settings: it applies the baseline, undoes it
and puts every setting back. A fresh start (baseline applied by itself, not again after an undo) is checked without a browser by
baseline_fresh_check.py.

Covers
  * on an existing install the Overview card shows the items OFF, nothing was applied by itself (state and settings APIs), the forwarded-header
    clean-up is "Not applied" with its reason while no trusted proxy is listed, then offered once one is;
  * the preview drawer lists exactly the changes and the "nothing that blocks traffic" statement; Cancel changes nothing;
  * Apply changes exactly those settings (checked through /api/deployrole/get and /api/securityheaders/default, an existing site is not touched),
    the chips flip, Undo is offered, the audit log has baseline.apply with source button and the changed items;
  * Undo (after a confirmation) restores the previous values, the audit log has baseline.undo; a setting the administrator changed in between
    is left alone and reported; a POST without the CSRF token and a second Apply are harmless;
  * light / dark / 390 px layout of the card and of the drawer without overflow, no console errors (smoke.py's page handlers).
All POSTs from the page go through $.cjax."""

import json
import time

BL_SITE = "bl-site.demo.test"
BL_PROXY = "10.77.77.1"


def baseline_ui(pg, ctx):
    current["page"] = "baseline"

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status + ' ' + (e.responseText || '').slice(0, 200)})}))""", [path, data])

    def get(path):
        return pg.evaluate("p => fetch(p).then(r => r.json())", path)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(400)

    def confirm(ok):
        pg.wait_for_selector(".zx-dialog [data-zx-ok]", timeout=5000)
        pg.click(".zx-dialog %s" % ("[data-zx-ok]" if ok else "[data-zx-cancel]"))
        pg.wait_for_timeout(700)

    def open_overview():
        js("openTabById('seccenter')")
        pg.wait_for_selector("#secTabs .item[data-sec='overview']", timeout=10000)
        pg.click("#secTabs .item[data-sec='overview']", timeout=6000)
        pg.wait_for_selector("#blCard .bl-list li", timeout=15000)

    def reload_overview():
        pg.reload(wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item", state="attached")
        open_overview()

    def bl():
        return get("/api/baseline/get")

    def item(d, iid):
        return next((i for i in d["items"] if i["id"] == iid), {})

    def chips():
        """item id -> chip text, in the order the card lists them"""
        return js("""() => [...document.querySelectorAll('#blCard .bl-list li')].map(li => [li.querySelector('.bl-txt b').innerText.trim(), li.querySelector('.zx-badge').innerText.trim()])""")

    def card_text():
        return js("document.getElementById('blCard').innerText")

    def toasts():
        return js("[...document.querySelectorAll('.zx-toast__msg, #messageBox')].filter(e => e.getClientRects().length > 0).map(e => e.innerText.trim()).filter(Boolean)")

    def settings_view():
        """what the baseline touches, read through the normal settings APIs"""
        dr = get("/api/deployrole/get")
        hd = get("/api/securityheaders/default")
        return {"hardenHeaders": dr.get("hardenHeaders"), "hardenActive": dr.get("hardenActive"), "role": dr.get("role"),
                "peerGate": dr.get("peerGate"), "defaultHeaders": hd.get("Settings")}

    def audit(prefix):
        return [e for e in (get("/api/security/audit/list?limit=200").get("entries") or []) if e["event"].startswith(prefix)]

    def layout_bad(scope):
        return js("""(scope) => { const out = [], W = document.documentElement.clientWidth;
            document.querySelectorAll(scope + ' *').forEach(el => {
              const r = el.getBoundingClientRect(); if (r.width === 0 || r.right <= W + 1) return;
              for (let p = el.parentElement; p && !p.matches(scope); p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return; }
              out.push(el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + '.' + String(el.className).slice(0, 24) + ' right=' + Math.round(r.right)); });
            const kids = [...document.querySelectorAll(scope + ' .bl-list li, ' + scope + ' .bl-actions > *')].filter(c => c.getClientRects().length).map(c => c.getBoundingClientRect());
            for (let i = 0; i < kids.length; i++) for (let j = i + 1; j < kids.length; j++) {
              const a = kids[i], b = kids[j];
              if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) out.push('items ' + i + ' and ' + j + ' overlap'); }
            return out.slice(0, 5); }""", scope)

    def drawer_bad():
        return js("""() => { const d = document.querySelector('.zx-drawer'); if (!d) return ['no drawer']; const r = d.getBoundingClientRect(), W = document.documentElement.clientWidth, H = document.documentElement.clientHeight, out = [];
            if (r.right > W + 1 || r.left < -1) out.push('drawer outside the viewport horizontally ' + Math.round(r.left) + '..' + Math.round(r.right));
            if (r.bottom > H + 1) out.push('drawer taller than the viewport');
            d.querySelectorAll('*').forEach(el => { const b = el.getBoundingClientRect(); if (b.width && b.right > r.right + 1 && !el.closest('code')) out.push(el.tagName.toLowerCase() + '.' + String(el.className).slice(0, 20) + ' sticks out of the drawer'); });
            const ok = document.getElementById('blPrevOk'); if (ok) { const o = ok.getBoundingClientRect(); if (o.bottom > H + 1 || o.right > W + 1) out.push('Apply button not fully visible'); }
            return out.slice(0, 5); }""")

    def close_drawer():
        if js("!!document.querySelector('.zx-drawer')"):
            pg.click("#blPrevCancel")
            pg.wait_for_function("!document.querySelector('.zx-drawer')", timeout=5000)
            pg.wait_for_timeout(300)

    orig = {"deploy": None, "applied": False, "proxies": None}
    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    try:
        # ---------------------------------------------------------------- setup: an existing-style instance with a site
        current["page"] = "baseline-setup"
        d0 = bl()
        if not d0.get("available"):
            fail("baseline-setup", "the baseline is not available on this instance")
            return
        if d0["state"].get("decision") != "existing" or d0.get("canUndo"):
            fail("baseline-setup", "this scenario needs an existing-style throw-away instance (state %s); a fresh instance has the baseline applied at its first start (see tools/ui-smoke/run.sh, which seeds conf/)" % d0["state"])
            return
        dep = get("/api/deployrole/get")
        orig["deploy"] = {"role": dep.get("role", "standalone"), "hardenHeaders": bool(dep.get("hardenHeaders")), "peerGate": bool(dep.get("peerGate")), "directCIDRs": dep.get("directCIDRs") or []}
        if dep.get("hardenHeaders") or dep.get("role") not in ("", "standalone"):
            fail("baseline-setup", "the instance already has the header clean-up on or a non-standalone role: not an untouched existing install (%s)" % orig["deploy"])
            return
        # the instance ships a default trusted proxy list (CDN ranges); the "no trusted proxy" case needs it empty, it is put back at the end
        orig["proxies"] = get("/api/trustedproxy/list")
        for tp in orig["proxies"]:
            post("/api/trustedproxy/remove", {"ip": tp["IP"]})
        if get("/api/trustedproxy/list"):
            fail("baseline-setup", "could not empty the trusted proxy list")
            return
        post("/api/proxy/del", {"ep": BL_SITE})
        r = post("/api/proxy/add", {"type": "host", "rootname": BL_SITE, "ep": "10.20.30.7:8080", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
        if isinstance(r, dict) and r.get("error"):
            fail("baseline-setup", "seeding the site failed: %s" % r)
            return
        site_before = get("/api/proxy/header/hardened?domain=" + BL_SITE)
        before = settings_view()
        if before["defaultHeaders"] is not None:
            fail("baseline-setup", "the instance already has default security headers for new sites: %s" % before["defaultHeaders"])
            return
        n_audit0 = len(audit("baseline."))

        # ---------------------------------------------------------------- the card on an existing install: off, nothing applied by itself
        current["page"] = "baseline-existing"
        open_overview()
        pg.wait_for_timeout(500)
        if "Enterprise baseline" not in card_text():
            fail("baseline-existing", "the card title is missing: %r" % card_text()[:200])
        ch = dict(chips())
        want = {"Security audit log": "Recording", "Clean up forwarded client-address headers": "Not applied",
                "Safe security headers for sites created later": "Off", "CrowdSec": "Not configured"}
        for k, v in want.items():
            if ch.get(k) != v:
                fail("baseline-existing", "chip of %r is %r, want %r (chips: %s)" % (k, ch.get(k), v, ch))
        if "no trusted proxy is listed" not in card_text():
            fail("baseline-existing", "the reason why the header clean-up is not applied is not shown: %r" % card_text()[:600])
        if js("document.getElementById('blApply').disabled"):
            fail("baseline-existing", "Apply must be offered (the new-site headers can be applied)")
        if js("!!document.getElementById('blUndo')"):
            fail("baseline-existing", "Undo is offered although nothing was applied")
        if "was not changed by the update" not in card_text():
            fail("baseline-existing", "the note that the update changed nothing is missing")
        d1 = bl()
        if d1["state"].get("decision") != "existing" or d1["state"].get("appliedAt") or d1["canUndo"]:
            fail("baseline-existing", "the baseline was applied by itself: %s" % d1["state"])
        if settings_view() != before:
            fail("baseline-existing", "a setting changed without a click: %s -> %s" % (before, settings_view()))
        shot("baseline-existing-light.png")

        # a trusted proxy now makes the clean-up eligible
        r = post("/api/trustedproxy/add", {"ip": BL_PROXY, "desc": "baseline smoke"})
        if isinstance(r, dict) and r.get("error"):
            fail("baseline-setup", "adding the trusted proxy failed: %s" % r)
        reload_overview()
        ch = dict(chips())
        if ch.get("Clean up forwarded client-address headers") != "Off":
            fail("baseline-existing", "with a trusted proxy listed the clean-up chip should be Off, is %r" % ch.get("Clean up forwarded client-address headers"))
        if settings_view() != before:
            fail("baseline-existing", "adding a trusted proxy and reloading changed a baseline setting")

        # ---------------------------------------------------------------- preview: lists the changes and the no-blocking statement; Cancel changes nothing
        current["page"] = "baseline-preview"
        pg.click("#blApply")
        pg.wait_for_selector("#blPrevOk", timeout=8000)
        pg.wait_for_timeout(400)
        dtxt = js("document.querySelector('.zx-drawer').innerText")
        for s in ("Nothing that blocks traffic is changed", "This is exactly what will change", "Clean up forwarded client-address headers",
                  "Safe security headers for sites created later", "Will change", "nosniff", "HSTS 30 days"):
            if s not in dtxt:
                fail("baseline-preview", "the preview does not mention %r: %r" % (s, dtxt[:700]))
        if "Security audit log" in dtxt or "CrowdSec mode is touched" not in dtxt:
            fail("baseline-preview", "info-only items are listed as changes: %r" % dtxt[:500])
        n_btn = js("document.getElementById('blPrevOk').innerText")
        if "2" not in n_btn:
            fail("baseline-preview", "the Apply button should announce 2 changes: %r" % n_btn)
        if js("document.querySelectorAll('.bl-prev li').length") != 2:
            fail("baseline-preview", "the preview should list exactly two changes, lists %s" % js("document.querySelectorAll('.bl-prev li').length"))
        shot("baseline-preview-light.png")
        bad = drawer_bad()
        if bad:
            fail("baseline-layout", "preview drawer desktop: %s" % bad)
        pg.click("#blPrevCancel")
        pg.wait_for_function("!document.querySelector('.zx-drawer')", timeout=5000)
        if settings_view() != before or bl()["canUndo"]:
            fail("baseline-preview", "Cancel changed something")
        # a POST without the CSRF token must not apply anything
        import urllib.error
        import urllib.request
        try:
            with urllib.request.urlopen(urllib.request.Request(args.url + "/api/baseline/apply", data=b"", method="POST"), timeout=8) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        if code not in (400, 401, 403):
            fail("baseline-csrf", "a POST without the CSRF token answered %s" % code)
        if bl()["canUndo"] or settings_view() != before:
            fail("baseline-csrf", "a POST without the CSRF token applied the baseline")

        # ---------------------------------------------------------------- Apply: exactly those settings
        current["page"] = "baseline-apply"
        pg.click("#blApply")
        pg.wait_for_selector("#blPrevOk", timeout=8000)
        pg.wait_for_timeout(300)
        pg.click("#blPrevOk")
        orig["applied"] = True
        pg.wait_for_function("!document.querySelector('.zx-drawer')", timeout=8000)
        pg.wait_for_function("document.getElementById('blUndo')", timeout=8000)
        pg.wait_for_timeout(500)
        after = settings_view()
        if after["hardenHeaders"] is not True or after["hardenActive"] is not True:
            fail("baseline-apply", "the header clean-up is not on after Apply: %s" % after)
        hh = after["defaultHeaders"] or {}
        if not (hh.get("Enabled") and hh.get("NoSniff") and hh.get("HSTS") and hh.get("HSTSMaxAge") == 2592000 and hh.get("ReferrerPolicy") == "strict-origin-when-cross-origin"):
            fail("baseline-apply", "the new-site headers are not the baseline value: %s" % hh)
        if hh.get("FrameProtection") or hh.get("PermissionsPolicy") or hh.get("HSTSIncludeSubdomains") or hh.get("HSTSPreload"):
            fail("baseline-apply", "the baseline switched on something it must not (frame protection, Permissions-Policy, includeSubDomains or preload): %s" % hh)
        # nothing else moved: role, gate and the existing site
        if after["role"] != before["role"] or after["peerGate"] != before["peerGate"]:
            fail("baseline-apply", "role or peer gate changed: %s -> %s" % (before, after))
        if get("/api/proxy/header/hardened?domain=" + BL_SITE) != site_before:
            fail("baseline-apply", "the existing site's own header settings changed")
        ch = dict(chips())
        for k in ("Clean up forwarded client-address headers", "Safe security headers for sites created later"):
            if ch.get(k) != "On":
                fail("baseline-apply", "chip of %r is %r after Apply, want On" % (k, ch.get(k)))
        if not js("document.getElementById('blApply').disabled"):
            fail("baseline-apply", "Apply must be disabled when nothing is left to apply")
        if "All applicable settings are on" not in card_text():
            fail("baseline-apply", "the head badge does not say that everything is on: %r" % card_text()[:200])
        if "Applied by an administrator" not in card_text():
            fail("baseline-apply", "the 'Applied by an administrator' note is missing: %r" % card_text()[-300:])
        st = bl()["state"]
        if st.get("source") != "button" or set((st.get("items") or {}).keys()) != {"harden-headers", "new-site-headers"}:
            fail("baseline-apply", "stored state is wrong: %s" % st)
        ap = audit("baseline.apply")
        if len(ap) != 1 or ap[0]["detail"].get("source") != "button" or ap[0]["outcome"] != "ok" or "harden-headers" not in ap[0]["detail"].get("items", "") or "new-site-headers" not in ap[0]["detail"].get("items", ""):
            fail("baseline-apply", "audit log: want one baseline.apply (source button, both items), got %s" % ap)
        if not any("applied" in t.lower() for t in toasts()):
            pass  # the toast may already be gone; the state checks above are what counts
        shot("baseline-applied-light.png")
        # a second Apply has nothing to do and records nothing
        r = post("/api/baseline/apply", {})
        if isinstance(r, dict) and r.get("error"):
            fail("baseline-apply", "a second Apply answered an error: %s" % r)
        if len(audit("baseline.apply")) != 1 or settings_view() != after:
            fail("baseline-apply", "a second Apply changed or recorded something")

        # ---------------------------------------------------------------- layout: light / dark / 390 px, card and drawer
        for dark in (False, True):
            for (w, h, size) in ((1366, 900, "desktop"), (390, 844, "390")):
                current["page"] = f"baseline-layout/{'dark' if dark else 'light'}/{size}"
                theme(dark)
                pg.set_viewport_size({"width": w, "height": h})
                pg.wait_for_timeout(500)
                pg.evaluate("document.getElementById('blCard').scrollIntoView()")
                bad = layout_bad("#ovPage")
                if bad:
                    fail("baseline-layout", f"{'dark' if dark else 'light'} {size}: {bad}")
                check_horizontal(pg, f"baseline {'dark' if dark else 'light'} {size}")
                shot(f"baseline-card-{'dark' if dark else 'light'}-{size}.png")
        # the preview drawer needs something to apply: undo first, look at it in dark + phone, then go on
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)

        # ---------------------------------------------------------------- Undo restores the previous values
        current["page"] = "baseline-undo"
        pg.evaluate("document.getElementById('blCard').scrollIntoView()")
        pg.click("#blUndo")
        confirm(False)  # cancel first: nothing happens
        if not bl()["canUndo"] or settings_view() != after:
            fail("baseline-undo", "cancelling the Undo confirmation changed something")
        pg.click("#blUndo")
        confirm(True)
        pg.wait_for_function("!document.getElementById('blUndo')", timeout=8000)
        pg.wait_for_timeout(400)
        orig["applied"] = False
        now = settings_view()
        if now != before:
            fail("baseline-undo", "Undo did not restore the previous values: before %s, now %s" % (before, now))
        ch = dict(chips())
        if ch.get("Clean up forwarded client-address headers") != "Off" or ch.get("Safe security headers for sites created later") != "Off":
            fail("baseline-undo", "chips after Undo: %s" % ch)
        if "will not be applied again by itself" not in card_text() and "Undone on" not in card_text():
            # the existing install keeps decision existing; the card then offers the button again
            if js("document.getElementById('blApply').disabled"):
                fail("baseline-undo", "Apply is not offered again after Undo")
        un = audit("baseline.undo")
        if len(un) != 1 or un[0]["outcome"] != "ok" or "harden-headers" not in un[0]["detail"].get("items", ""):
            fail("baseline-undo", "audit log: want one baseline.undo, got %s" % un)
        if not js("!document.getElementById('blUndo')"):
            fail("baseline-undo", "Undo is still offered")
        if get("/api/proxy/header/hardened?domain=" + BL_SITE) != site_before:
            fail("baseline-undo", "the existing site changed")
        shot("baseline-undone-light.png")

        # ---------------------------------------------------------------- a setting changed by hand is left alone by Undo
        current["page"] = "baseline-undo-edited"
        pg.click("#blApply")
        pg.wait_for_selector("#blPrevOk", timeout=8000)
        # the drawer in dark and on a phone (a bottom sheet) while it is open
        pg.wait_for_function("![...document.querySelectorAll('.zx-toast')].some(e => e.getClientRects().length)", timeout=12000)  # a leftover toast would cover the sheet's buttons in the screenshot
        for dark, (w, h, size) in ((True, (390, 844, "390")), (True, (1366, 900, "desktop"))):
            theme(dark)
            pg.set_viewport_size({"width": w, "height": h})
            pg.wait_for_timeout(500)
            bad = drawer_bad()
            if bad:
                fail("baseline-layout", f"preview drawer dark {size}: {bad}")
            check_horizontal(pg, f"baseline drawer {size}")
            shot(f"baseline-preview-dark-{size}.png")
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)
        pg.click("#blPrevOk")
        orig["applied"] = True
        pg.wait_for_function("document.getElementById('blUndo')", timeout=8000)
        # the administrator turns the clean-up off themselves
        dr = dict(orig["deploy"])
        r = post("/api/deployrole/set", {"config": json.dumps(dr)})
        if isinstance(r, dict) and r.get("error"):
            fail("baseline-undo-edited", "could not change the deployment setting by hand: %s" % r)
        pg.reload(wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item", state="attached")
        open_overview()
        pg.evaluate("document.getElementById('blCard').scrollIntoView()")
        pg.click("#blUndo")
        confirm(True)
        pg.wait_for_function("!document.getElementById('blUndo')", timeout=8000)
        orig["applied"] = False
        pg.wait_for_timeout(300)
        if settings_view() != before:
            fail("baseline-undo-edited", "after the Undo the settings are %s, want %s" % (settings_view(), before))
        un = audit("baseline.undo")
        if len(un) != 2 or not any("left as is" in u["detail"].get("items", "") and "harden-headers" in u["detail"].get("items", "") for u in un):
            fail("baseline-undo-edited", "the audit log must show two baseline.undo entries, one saying that the hand-edited clean-up was left as is: %s" % [u["detail"] for u in un])

        # ---------------------------------------------------------------- the end state is the start state
        current["page"] = "baseline-end"
        if settings_view() != before:
            fail("baseline-end", "settings differ from the start: %s vs %s" % (settings_view(), before))
        if len(audit("baseline.")) != n_audit0 + 4:
            fail("baseline-end", "unexpected number of baseline audit entries: %d (start %d)" % (len(audit("baseline.")), n_audit0))
    finally:
        # ---------------------------------------------------------------- cleanup: nothing of this scenario stays on the instance
        current["page"] = "baseline-cleanup"
        try:
            theme(False)
            pg.set_viewport_size({"width": 1366, "height": 900})
            close_drawer()
        except Exception:
            pass
        try:
            if orig["applied"] or bl().get("canUndo"):
                post("/api/baseline/undo", {})
            if orig["deploy"] is not None:
                post("/api/deployrole/set", {"config": json.dumps(orig["deploy"])})
            post("/api/trustedproxy/remove", {"ip": BL_PROXY})
            for tp in orig["proxies"] or []:
                post("/api/trustedproxy/add", {"ip": tp["IP"], "desc": tp.get("Desc", "")})
            post("/api/proxy/del", {"ep": BL_SITE})
        except Exception as e:
            fail("baseline-cleanup", "could not restore the instance: %s" % e)
        try:
            if get("/api/securityheaders/default").get("Settings") is not None:
                fail("baseline-cleanup", "the default security headers for new sites were not restored")
            if orig["proxies"] is not None and sorted(t["IP"] for t in get("/api/trustedproxy/list")) != sorted(t["IP"] for t in orig["proxies"]):
                fail("baseline-cleanup", "the trusted proxy list was not restored")
            if get("/api/deployrole/get").get("hardenHeaders"):
                fail("baseline-cleanup", "the header clean-up was not restored")
        except Exception as e:
            fail("baseline-cleanup", "could not verify the restore: %s" % e)
