"""Smoke scenario of the Phase 2 enterprise GUI (docs/enterprise-dual-proxy-plan.md). exec()'d by smoke.py (namespace: fail, current,
args, os, re, check_horizontal); run alone with --enterprise-only. Needs UI port + 2 free only as a (never contacted) upstream address.

Covers: Security Center tabs Deployment, Network exposure and Audit log (the security audit log card) in light and dark and at phone
width without sideways overflow; role defaults to standalone; settings round-trip through a reload (POSTs go through $.cjax);
invalid input shows an error and stores nothing; the admin allow-list refuses a list that excludes the client; a security audit entry
appears after each change and holds no secret; the site editor Request limits card (body limit, timeouts) saves and reloads and
refuses an out-of-range value; the upstream certificate trust fields (CA bundle, pins) check, save, reload and are refused without TLS.
Console errors / failed requests are caught by the handlers smoke.py installs on the page. Makes its own rule and restores every
setting it changed (the settings are global to the instance, so run it on a throw-away one)."""

import json
import subprocess
import tempfile

EN_HOST = "enterprise-smoke.demo.test"


def enterprise_ui(pg, ctx):
    base = int(args.url.rsplit(":", 1)[1].split("/")[0])
    up_port = base + 2
    current["page"] = "enterprise"

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])

    def get(path):
        return pg.evaluate("p => fetch(p).then(r => r.json())", path)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def toast_text():
        return js("(document.querySelector('.zx-toast-region') || document.body).innerText")

    def open_sec(tab, sentinel):
        js("openTabById('seccenter')")
        pg.wait_for_selector("#secTabs .item[data-sec='%s']" % tab, timeout=10000)
        try:
            pg.click("#secTabs .item[data-sec='%s']" % tab, timeout=6000)
        except Exception:
            shot("enterprise-click-failed-%s.png" % tab)
            raise
        pg.wait_for_selector(sentinel, timeout=10000)
        pg.wait_for_timeout(700)

    def pane_overflow(label):
        """nothing in the pane may stick out of the viewport unless it sits in a scroll container made for it (tables)"""
        bad = js("""() => { const out = [], W = document.documentElement.clientWidth;
            document.querySelectorAll('#secPane *').forEach(el => {
              const r = el.getBoundingClientRect(); if (r.width === 0 || r.right <= W + 1) return;
              for (let p = el.parentElement; p && p.id !== 'secPane'; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return; }
              out.push(el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + ' right=' + Math.round(r.right)); });
            return out.slice(0, 4); }""")
        if bad:
            fail("enterprise-layout", f"{label}: content sticks out of the viewport: {bad}")
        check_horizontal(pg, label)

    def audit_entries():
        d = get("/api/security/audit/list?limit=200")
        return d.get("entries") or []

    def reload_to(tab, sentinel):
        pg.reload(wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item", state="attached")
        open_sec(tab, sentinel)

    def type_into(sel, text):
        """type like a person (pointer + keys): the editor only keeps edits it knows came from the user, a bare fill() can be rebased away"""
        pg.click(sel)
        pg.keyboard.press("Control+A")
        pg.keyboard.type(text)

    def confirm_ok():
        pg.wait_for_selector(".zx-dialog [data-zx-ok]", timeout=5000)
        pg.click(".zx-dialog [data-zx-ok]")
        pg.wait_for_timeout(700)

    work = tempfile.mkdtemp(prefix="entsmoke")
    ca_pem = ""
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(work, "k.pem"), "-out", os.path.join(work, "ca.pem"),
                        "-days", "30", "-subj", "/CN=Enterprise smoke private CA", "-addext", "basicConstraints=critical,CA:TRUE"], check=True, capture_output=True, timeout=60)
        ca_pem = open(os.path.join(work, "ca.pem")).read().strip()
    except Exception as e:
        fail("enterprise", f"could not make a test CA with openssl: {e}")

    pg.set_viewport_size({"width": 1366, "height": 900})
    js("if (document.body.classList.contains('darkTheme')) toggleTheme()")
    base_audit = len(audit_entries())

    # ---------------------------------------------------------------- defaults: nothing is on until the admin turns it on
    current["page"] = "enterprise-defaults"
    d0 = get("/api/deployrole/get")
    if d0.get("role") != "standalone" or d0.get("hardenHeaders") or d0.get("peerGate") or d0.get("directCIDRs"):
        fail("enterprise-defaults", f"a fresh instance must be standalone with everything off, got {d0}")
    g0 = get("/api/destguard/get")
    if g0.get("restrictTools") or g0.get("allowedBackends"):
        fail("enterprise-defaults", f"destination restriction must be off by default: {g0}")
    a0 = get("/api/adminallow/get")
    if a0.get("cidrs") or a0.get("active"):
        fail("enterprise-defaults", f"the admin allow-list must be empty by default: {a0}")
    open_sec("deployment", "#drRole")
    if js("document.getElementById('drRole').value") != "standalone":
        fail("enterprise-defaults", "the Deployment tab does not show Standalone as the role")
    if js("document.getElementById('drGateBox').offsetParent !== null"):
        fail("enterprise-defaults", "the peer gate box must be hidden for the Standalone role")

    # ---------------------------------------------------------------- the three tabs: light / dark, desktop / phone
    for (tab, sentinel) in (("deployment", "#drRole"), ("exposure", "#aaCidrs"), ("auditlog", "#salRows tr")):
        for theme in ("light", "dark"):
            is_dark = js("document.body.classList.contains('darkTheme')")
            if (theme == "dark") != is_dark:
                js("toggleTheme()")
                pg.wait_for_timeout(500)
            for (w, h, tag) in ((1366, 900, "desktop"), (390, 844, "390")):
                current["page"] = f"enterprise-{tab}/{theme}/{tag}"
                pg.set_viewport_size({"width": w, "height": h})
                pg.wait_for_timeout(500)
                open_sec(tab, sentinel)
                if js("document.getElementById('secPane').innerText.trim().length") < 80:
                    fail("enterprise", f"the {tab} tab rendered (almost) nothing")
                pane_overflow(f"{tab} {theme} {tag}")
                weak = js("""(dark) => { const lum = c => { const m = c.match(/[0-9.]+/g).map(Number); const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); };
                    const out = []; document.querySelectorAll('#secPane p, #secPane small, #secPane label').forEach(e => { if (!e.offsetParent || !e.innerText.trim()) return; const l = lum(getComputedStyle(e).color);
                      if (dark ? l < 0.25 : l > 0.3) out.push((e.className || e.tagName) + ' ' + e.innerText.trim().slice(0, 30)); }); return out.slice(0, 3); }""", theme == "dark")
                if weak:
                    fail("enterprise-contrast", f"{tab} {theme}: text too close to the background colour: {weak}")
                shot(f"enterprise-{tab}-{theme}-{tag}.png")
    js("if (document.body.classList.contains('darkTheme')) toggleTheme()")
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ---------------------------------------------------------------- Deployment: round trip, forced hardening display, invalid input
    current["page"] = "enterprise-deployment"
    open_sec("deployment", "#drRole")
    pg.select_option("#drRole", "external")
    pg.wait_for_timeout(300)
    if not js("document.getElementById('drHarden').checked && document.getElementById('drHarden').disabled"):
        fail("deployment", "the External role must show header hardening as on and locked")
    pg.click("#drSave")
    pg.wait_for_timeout(900)
    if "Deployment settings saved" not in toast_text():
        fail("deployment", f"no confirmation after saving the role: {toast_text()[:120]!r}")
    d = get("/api/deployrole/get")
    if d.get("role") != "external":
        fail("deployment", f"the role was not saved: {d}")
    if d.get("hardenHeaders"):
        fail("deployment", "the role's forced hardening was saved as the administrator's own choice (it would stay on after going back to Standalone)")
    reload_to("deployment", "#drRole")
    if js("document.getElementById('drRole').value") != "external":
        fail("deployment", "the role did not survive a reload")
    shot("enterprise-deployment-external.png")
    # back to standalone: the forced box goes back to the stored choice (off)
    pg.select_option("#drRole", "standalone")
    pg.wait_for_timeout(300)
    if js("document.getElementById('drHarden').checked || document.getElementById('drHarden').disabled"):
        fail("deployment", "Standalone must restore the hardening box to the stored choice (off, editable)")
    # internal: the peer gate box appears; invalid input is refused with a message and nothing changes
    pg.select_option("#drRole", "internal")
    pg.wait_for_timeout(300)
    if not js("document.getElementById('drGateBox').offsetParent !== null"):
        fail("deployment", "the peer gate box must show for the Internal role")
    for bad in ("not a network", "0.0.0.0/0"):
        pg.fill("#drCidrs", bad)
        pg.click("#drSave")
        pg.wait_for_timeout(800)
        if not js("document.getElementById('drMsg').offsetParent !== null && document.getElementById('drMsg').innerText.trim().length > 3"):
            fail("deployment", f"invalid direct network {bad!r} shows no error message")
        if get("/api/deployrole/get").get("role") != "external":
            fail("deployment", f"invalid direct network {bad!r} changed the stored role")
    shot("enterprise-deployment-error.png")
    # a gate that would refuse every peer: refused (needs an empty trusted proxy list, which is the default)
    if get("/api/deployrole/get").get("trustedProxies") == 0:
        pg.fill("#drCidrs", "")
        pg.check("#drGate")
        pg.click("#drSave")
        confirm_ok()
        if "refuse every connection" not in js("document.getElementById('drMsg').innerText"):
            fail("deployment", "a peer gate with no trusted proxy and no network must be refused with an explanation")
        if get("/api/deployrole/get").get("peerGate"):
            fail("deployment", "the self-locking peer gate was stored")
        pg.uncheck("#drGate")
    pg.fill("#drCidrs", "10.77.0.0/24")
    pg.click("#drSave")
    pg.wait_for_timeout(900)
    d = get("/api/deployrole/get")
    if d.get("role") != "internal" or d.get("directCIDRs") != ["10.77.0.0/24"] or d.get("peerGate"):
        fail("deployment", f"internal role with a network did not save as typed: {d}")
    reload_to("deployment", "#drRole")
    if js("document.getElementById('drRole').value") != "internal" or "10.77.0.0/24" not in js("document.getElementById('drCidrs').value"):
        fail("deployment", "internal role and its network did not survive a reload")
    try:
        pg.wait_for_function("document.getElementById('drWarn').innerText.includes('peer gate')", timeout=4000)
    except Exception:
        fail("deployment", f"Internal without the peer gate must show a warning: {js('document.getElementById(\'drWarn\').innerText')!r}")
    shot("enterprise-deployment-internal.png")
    # restore through the UI
    pg.fill("#drCidrs", "")
    pg.select_option("#drRole", "standalone")
    pg.click("#drSave")
    pg.wait_for_timeout(900)
    d = get("/api/deployrole/get")
    if d.get("role") != "standalone" or d.get("hardenHeaders") or d.get("peerGate"):
        fail("deployment", f"could not go back to Standalone with everything off: {d}")

    # ---------------------------------------------------------------- Network exposure: destination restriction + admin allow-list
    current["page"] = "enterprise-exposure"
    open_sec("exposure", "#dgAllowed")
    pg.fill("#dgAllowed", "not a network!!")
    pg.click("#dgSave")
    pg.wait_for_timeout(800)
    if not js("document.getElementById('dgMsg').offsetParent !== null && document.getElementById('dgMsg').innerText.trim().length > 3"):
        fail("exposure", "an invalid allowed destination shows no error")
    if get("/api/destguard/get").get("allowedBackends"):
        fail("exposure", "an invalid allowed destination was stored")
    pg.fill("#dgAllowed", "10.20.0.0/24\n10.20.1.5 443,8000-8100")
    pg.click("#dgSave")
    pg.wait_for_timeout(900)
    if get("/api/destguard/get").get("allowedBackends") != ["10.20.0.0/24", "10.20.1.5 443,8000-8100"]:
        fail("exposure", f"the allowed destinations did not save: {get('/api/destguard/get')}")
    reload_to("exposure", "#dgAllowed")
    if "10.20.1.5" not in js("document.getElementById('dgAllowed').value"):
        fail("exposure", "the allowed destinations did not survive a reload")
    # restore
    pg.fill("#dgAllowed", "")
    pg.click("#dgSave")
    pg.wait_for_timeout(900)
    g = get("/api/destguard/get")
    if g.get("allowedBackends") or g.get("restrictTools"):
        fail("exposure", f"could not clear the destination settings: {g}")

    # admin allow-list: the lockout protection
    you = js("document.getElementById('aaYou').innerText.trim()")
    if not you or you == "?":
        fail("exposure", "the page does not show the client's own address")
    for (label, text) in (("a list without the client", "10.99.0.0/24"), ("0.0.0.0/0", "0.0.0.0/0"), ("garbage", "nonsense")):
        pg.fill("#aaCidrs", text)
        pg.click("#aaSave")
        confirm_ok()
        if not js("document.getElementById('aaMsg').offsetParent !== null && document.getElementById('aaMsg').innerText.trim().length > 3"):
            fail("exposure", f"the admin allow-list ({label}) was refused without a message")
        if get("/api/adminallow/get").get("cidrs"):
            fail("exposure", f"the admin allow-list accepted {label}: {get('/api/adminallow/get')}")
        if label == "a list without the client":
            shot("enterprise-exposure-lockout-refused.png")
    # the same through the API: the page's guard is the server's guard
    r = post("/api/adminallow/set", {"config": json.dumps({"cidrs": ["10.99.0.0/24"]})})
    if not (isinstance(r, dict) and r.get("error")):
        fail("exposure", f"the API accepted an allow-list that excludes the client: {r!r}")
    pg.fill("#aaCidrs", you + ("/128" if ":" in you else "/32"))
    pg.click("#aaSave")
    confirm_ok()
    if get("/api/adminallow/get").get("cidrs") != [you + ("/128" if ":" in you else "/32")]:
        fail("exposure", f"an allow-list that includes the client did not save: {get('/api/adminallow/get')}")
    reload_to("exposure", "#aaCidrs")
    if you not in js("document.getElementById('aaCidrs').value") or "on" not in js("document.getElementById('aaStatus').innerText"):
        fail("exposure", "the admin allow-list or its status did not survive a reload")
    shot("enterprise-exposure-saved.png")
    pg.fill("#aaCidrs", "")
    pg.click("#aaSave")
    pg.wait_for_timeout(900)
    if get("/api/adminallow/get").get("cidrs"):
        fail("exposure", "could not clear the admin allow-list")

    # ---------------------------------------------------------------- Audit log card: entries for the changes above, filter, integrity, no secrets
    current["page"] = "enterprise-auditlog"
    open_sec("auditlog", "#salRows tr")
    pg.wait_for_timeout(500)
    rows_txt = js("document.getElementById('salRows').innerHTML")  # the raw event name is the cell's title; the cell shows a plain-language label
    for ev in ("deployrole.set", "adminallow.set", "destguard.set"):
        if ev not in rows_txt:
            fail("audit", f"no audit entry {ev} after changing that setting")
    now = audit_entries()
    if len(now) <= base_audit:
        fail("audit", f"the audit log did not grow: {base_audit} -> {len(now)}")
    if not any(e.get("event") == "adminallow.set" and e.get("outcome") != "ok" for e in now):
        fail("audit", "the refused admin allow-list save left no non-ok audit entry")
    pg.select_option("#salEvent", "deployrole.*")
    pg.wait_for_timeout(900)
    evs = js("[...document.querySelectorAll('#salRows tr td:nth-child(4)')].map(e => (e.getAttribute('title') || e.innerText).trim())")
    if not evs or any(not e.startswith("deployrole.") for e in evs):
        fail("audit", f"the event filter does not filter: {evs[:5]}")
    pg.select_option("#salEvent", "")
    pg.click("#salVerify")
    pg.wait_for_selector("#salVerifyMsg.positive", timeout=8000)
    shot("enterprise-audit-light.png")

    # ---------------------------------------------------------------- site editor: request limits and upstream certificate trust
    current["page"] = "enterprise-editor"
    post("/api/proxy/del", {"ep": EN_HOST})
    r = post("/api/proxy/add", {"type": "host", "rootname": EN_HOST, "ep": "127.0.0.1:%d" % up_port, "tls": "true", "tlsval": "false", "bypassGlobalTLS": "false"})
    if isinstance(r, dict) and r.get("error"):
        fail("enterprise-editor", f"seeding {EN_HOST} failed: {r}")
        return
    try:
        def rule():
            return js("h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => l.filter(x => x.RootOrMatchingDomain === h)[0])", EN_HOST)

        def open_editor():
            js("openTabById('httprp')")
            pg.wait_for_timeout(700)
            js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", EN_HOST)
            pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=10000)
            pg.wait_for_timeout(1000)
            js("HrpEditor.setMode('advanced')")
            pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=advanced]")
            pg.wait_for_timeout(400)
            js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='limits']"); if (c) c.scrollIntoView({block: 'center'}); }""")
            pg.wait_for_timeout(300)

        def close_editor():
            js("""() => { const b = document.querySelector('#httprpEditModal .httpProxyEditClosePC'); if (b) b.click(); }""")
            pg.wait_for_timeout(500)

        if rule().get("MaxRequestBodyBytes") or rule().get("RequestTimeout") or rule().get("UpstreamDialTimeout"):
            fail("limits", "a new rule must have no request limits (default = unlimited)")
        open_editor()
        for sel in (".MaxRequestBodyMB", ".RequestTimeout", ".UpstreamDialTimeout"):
            if pg.input_value("#httprpEditModal " + sel) != "0":
                fail("limits", f"{sel} must show 0 (no limit) for a new rule")
        type_into("#httprpEditModal .MaxRequestBodyMB", "2")
        type_into("#httprpEditModal .RequestTimeout", "30")
        type_into("#httprpEditModal .UpstreamDialTimeout", "5")
        shot("enterprise-editor-limits-light.png")
        pg.click("#httprpEditModal [data-zx-save]")
        pg.wait_for_function("document.querySelector('#httprpEditModal .zx-savebar').classList.contains('is-success') || document.querySelector('#httprpEditModal .zx-savebar').hidden", timeout=8000)
        pg.wait_for_timeout(600)
        r = rule()
        if r.get("MaxRequestBodyBytes") != 2097152 or r.get("RequestTimeout") != 30 or r.get("UpstreamDialTimeout") != 5:
            fail("limits", f"the limits did not save: {r.get('MaxRequestBodyBytes')}, {r.get('RequestTimeout')}, {r.get('UpstreamDialTimeout')}")
        close_editor()
        open_editor()
        if (pg.input_value("#httprpEditModal .MaxRequestBodyMB"), pg.input_value("#httprpEditModal .RequestTimeout"), pg.input_value("#httprpEditModal .UpstreamDialTimeout")) != ("2", "30", "5"):
            fail("limits", "the limits did not show after reopening the editor")
        # out of range: the server refuses, the bar says so, the stored value stays
        type_into("#httprpEditModal .RequestTimeout", "999999")
        pg.click("#httprpEditModal [data-zx-save]")
        pg.wait_for_function("document.querySelector('#httprpEditModal .zx-savebar').classList.contains('is-error') || /invalid request limit|between 0/.test(document.body.innerText)", timeout=8000)
        if rule().get("RequestTimeout") != 30:
            fail("limits", "an out-of-range timeout changed the stored value")
        if not re.search(r"between 0|invalid request limit", js("document.body.innerText")):
            fail("limits", "an out-of-range timeout shows no explanation")
        shot("enterprise-editor-limits-error.png")
        # layout of the card in dark and at phone width
        js("toggleTheme()")
        pg.wait_for_timeout(500)
        shot("enterprise-editor-limits-dark.png")
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(600)
        js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='limits']"); if (c) c.scrollIntoView({block: 'center'}); }""")
        bad = js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='limits']"); if (!c) return ['no card']; const out = [], cr = c.getBoundingClientRect();
            c.querySelectorAll('input, .ui.label, small').forEach(e => { const r = e.getBoundingClientRect(); if (r.width && (r.right > cr.right + 1 || r.left < cr.left - 1)) out.push(e.className + ' ' + Math.round(r.left) + '-' + Math.round(r.right) + ' vs ' + Math.round(cr.left) + '-' + Math.round(cr.right)); });
            return out; }""")
        if bad:
            fail("limits", f"the limits card overflows at 390 px: {bad[:3]}")
        check_horizontal(pg, "site editor limits 390")
        shot("enterprise-editor-limits-390.png")
        pg.set_viewport_size({"width": 1366, "height": 900})
        js("toggleTheme()")
        pg.wait_for_timeout(300)
        # leave the dirty form
        js("""() => { const b = document.querySelector('#httprpEditModal [data-zx-discard]'); if (b) b.click(); }""")
        pg.wait_for_timeout(500)
        close_editor()
        js("""() => { const d = document.querySelector('.zx-dialog [data-zx-ok]'); if (d) d.click(); }""")
        pg.wait_for_timeout(400)

        # ---- upstream certificate trust (side view of the editor)
        current["page"] = "enterprise-upstream-trust"
        open_editor()
        js("editUpstreams(decodeURIComponent(document.getElementById('httprpEditModal').getAttribute('editing-host')))")
        pg.wait_for_timeout(1500)
        fr = next((f for f in pg.frames if "upstreams.html" in f.url), None)
        if fr is None:
            fail("upstream-trust", "the Upstreams side view did not load")
            return
        fr.wait_for_selector(".upstreamEntry .editbtn", timeout=8000)
        fr.click(".upstreamEntry .editbtn")
        fr.wait_for_selector(".upstreamEntry .advanceOptions", state="visible", timeout=5000)
        fr.click(".upstreamEntry .advanceUpstreamOptions .title")
        fr.wait_for_selector(".upstreamEntry .upstreamCABundle", state="visible", timeout=5000)
        if fr.input_value(".upstreamEntry .upstreamCABundle") != "" or fr.input_value(".upstreamEntry .upstreamPins") != "":
            fail("upstream-trust", "a rule without upstream trust settings must show empty CA bundle and pin fields")
        # invalid PEM: the check says why, the save is refused and nothing is stored
        fr.fill(".upstreamEntry .upstreamCABundle", "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----")
        fr.click(".upstreamEntry .upstreamTrustBox button:has-text('Check and show fingerprints')")
        pg.wait_for_timeout(900)
        if "red times" not in fr.inner_html(".upstreamEntry .upstreamTrustResult"):
            fail("upstream-trust", "an invalid CA bundle is not reported by the check button")
        fr.click(".upstreamEntry .savebtn")
        pg.wait_for_timeout(900)
        if rule()["ActiveOrigins"][0].get("TLSCABundlePEM"):
            fail("upstream-trust", "an invalid CA bundle was stored")
        if not re.search(r"certificate|PEM|CA", toast_text()):
            fail("upstream-trust", f"saving an invalid CA bundle shows no reason: {toast_text()[:150]!r}")
        # a bad pin
        fr.fill(".upstreamEntry .upstreamCABundle", "")
        fr.fill(".upstreamEntry .upstreamPins", "zz-not-a-pin")
        fr.click(".upstreamEntry .upstreamTrustBox button:has-text('Check and show fingerprints')")
        pg.wait_for_timeout(900)
        if "red times" not in fr.inner_html(".upstreamEntry .upstreamTrustResult"):
            fail("upstream-trust", "an invalid pin is not reported by the check button")
        # a good CA: the check lists subject and pin
        fr.fill(".upstreamEntry .upstreamPins", "")
        fr.fill(".upstreamEntry .upstreamCABundle", ca_pem)
        fr.click(".upstreamEntry .upstreamTrustBox button:has-text('Check and show fingerprints')")
        pg.wait_for_timeout(900)
        res = fr.inner_text(".upstreamEntry .upstreamTrustResult")
        if "Enterprise smoke private CA" not in res or "Public key pin" not in res:
            fail("upstream-trust", f"the CA check does not show the certificate and its pin: {res[:200]!r}")
        pin = re.search(r"Public key pin \(SHA-256\):\s*([0-9a-fA-F:A-Za-z+/=]+)", res)
        if pin:
            fr.fill(".upstreamEntry .upstreamPins", pin.group(1))
        shot("enterprise-upstream-trust.png")
        fr.click(".upstreamEntry .savebtn")
        pg.wait_for_timeout(1200)
        ups = rule()["ActiveOrigins"][0]
        if "BEGIN CERTIFICATE" not in (ups.get("TLSCABundlePEM") or ""):
            fail("upstream-trust", f"the CA bundle was not saved: {str(ups)[:200]}")
        if pin and not ups.get("TLSPinsSHA256"):
            fail("upstream-trust", "the pin was not saved")
        # reload the side view: the fields show what was stored
        js("editUpstreams(decodeURIComponent(document.getElementById('httprpEditModal').getAttribute('editing-host')))")
        pg.wait_for_timeout(1500)
        fr = next((f for f in pg.frames if "upstreams.html" in f.url), None)
        fr.click(".upstreamEntry .editbtn")
        fr.click(".upstreamEntry .advanceUpstreamOptions .title")
        fr.wait_for_selector(".upstreamEntry .upstreamCABundle", state="visible", timeout=5000)
        if "BEGIN CERTIFICATE" not in fr.input_value(".upstreamEntry .upstreamCABundle"):
            fail("upstream-trust", "the CA bundle did not show after reopening")
        # the textareas must fit their box (phone width)
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(600)
        ov = fr.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        if ov > 2:
            fail("upstream-trust", f"the Upstreams side view overflows by {ov}px at 390 px")
        shot("enterprise-upstream-trust-390.png")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)
        # trust without TLS is refused by the server
        r = post("/api/proxy/upstream/update", {"ep": EN_HOST, "origin": "127.0.0.1:%d" % up_port, "active": "true",
                                                "payload": json.dumps(dict(ups, RequireTLS=False))})
        if not (isinstance(r, dict) and r.get("error")):
            fail("upstream-trust", f"a CA bundle on a plain HTTP upstream was accepted: {r!r}")
        fr.click(".upstreamEntry .cancelbtn")
        close_editor()
    finally:
        post("/api/proxy/del", {"ep": EN_HOST})

    # ---------------------------------------------------------------- audit: the trust change is recorded, the PEM is not
    current["page"] = "enterprise-audit-after"
    ents = audit_entries()
    if not any(e.get("event") == "upstream.tls.change" for e in ents):
        fail("audit", "no upstream.tls.change entry after saving the CA bundle")
    if "BEGIN CERTIFICATE" in json.dumps(ents) or "Enterprise smoke private CA" in json.dumps(ents):
        fail("audit", "the audit log contains the pasted CA certificate")
    open_sec("auditlog", "#salRows tr")
    if "upstream.tls.change" not in js("document.getElementById('salRows').innerHTML"):
        fail("audit", "the audit log card does not list the upstream trust change")
    js("toggleTheme()")
    pg.wait_for_timeout(500)
    pane_overflow("audit log dark")
    shot("enterprise-audit-dark.png")
    js("toggleTheme()")
    # final state: everything back to defaults
    d = get("/api/deployrole/get")
    if d.get("role") != "standalone" or get("/api/adminallow/get").get("cidrs") or get("/api/destguard/get").get("allowedBackends"):
        fail("enterprise", "the scenario did not leave the settings at their defaults")
