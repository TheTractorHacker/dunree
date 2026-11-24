"""Smoke scenario of the saved CA gaps (issue #233). exec()'d by smoke.py (namespace: fail, current, args, os, re,
check_horizontal); run alone with --ca-profiles-only on a throw-away instance. It makes its own saved CAs and one uploaded
certificate and removes them. No CA is contacted (accounts, registration email and renewals are covered by the Go tests in
mod/acme/caprofile_gap_test.go); needs openssl on the PATH for the test certificate.

Checks, in the panel Certificates > "ACME profiles & defaults": no default CA until one is chosen ("No default" is disabled);
a saved CA takes its own registration email, shows it in the list, and a bad address is refused; "make default" marks the row,
is stored, and the certificate request dialog then starts on that CA; "Save the ACME page's CA settings as a saved CA" adds
exactly one saved CA, sets no default and refuses a second run; "make default" is a button that works with the keyboard and
"No default" sits under the list; an uploaded certificate cannot be assigned (it stays an upload); "CA of existing certificates"
moves an ACME certificate to a saved CA and back without changing the certificate file; deleting the default CA clears the
default. The panel does not scroll sideways at 1366 and 390px, and at 390px a saved CA is one block (the URL is not squeezed
into a column). Screenshots (light, dark, 390px) go to --out.

SMOKE_CERT_DIR: the conf/certs folder of the throw-away instance. With it the scenario marks its certificate as issued by ACME
(a metadata file next to it, which only an issuance writes) and runs the assignment against the real server. Without it the
list is answered as if that were so, the display checks run and the assignment round trip is skipped (said in the output)."""

CP_A = "Smoke CA one"
CP_B = "Smoke CA two"
CP_CERT = "cp-smoke.test"


def ca_profiles_ui(pg, ctx):
    import subprocess
    import tempfile

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(data, url="/api/acme/profiles/ca"):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status})}))""", [url, data])

    def view():
        return js("fetch('/api/acme/profiles/ca').then(r => r.json())")

    def by_name(name):
        return ([p for p in view().get("profiles") or [] if p.get("name") == name] or [None])[0]

    def cert():
        return ([c for c in js("fetch('/api/cert/list?date=true').then(r => r.json())") or [] if c.get("Filename") == CP_CERT] or [None])[0]

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def toasts():
        return js("[...document.querySelectorAll('.zx-toast__msg, #messageBox')].filter(e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden').map(e => e.innerText.trim()).filter(Boolean)")

    def clear_toasts():
        js("document.querySelectorAll('.zx-toast').forEach(e => e.remove())")

    def open_panel(snippet="acmeprofiles"):
        js("s => showSideWrapper('snippet/' + s + '.html?t=' + Date.now())", snippet)
        pg.wait_for_function("s => { const f = document.querySelector('.sideWrapper iframe'); try { return f.contentWindow.location.href.includes(s + '.html') && f.contentDocument.readyState === 'complete'; } catch (e) { return false; } }", arg=snippet, timeout=8000)
        pg.wait_for_timeout(900)
        return [f for f in pg.frames if snippet + ".html" in f.url][-1]

    def close_panel():
        js("hideSideWrapper()")
        pg.wait_for_timeout(600)

    def row(fr, name):
        return fr.evaluate("n => { const r = [...document.querySelectorAll('#caProfileList tr')].find(r => r.querySelector('.caName') && r.querySelector('.caName').innerText.trim() === n); return r ? r.innerText : null; }", name)

    made = []  # ids of the saved CAs this scenario created
    cert_dir = os.environ.get("SMOKE_CERT_DIR", "")

    def cleanup():
        post({"op": "setDefault", "id": ""})
        for p in view().get("profiles") or []:
            if p.get("name") in (CP_A, CP_B) or p.get("id") in made:
                post({"op": "delete", "id": p["id"]})
        post({"domain": CP_CERT}, "/api/cert/delete")
        if cert_dir:
            try:
                os.remove(os.path.join(cert_dir, CP_CERT + ".json"))
            except OSError:
                pass

    current["page"] = "ca-profiles"
    print("page", current["page"])
    cleanup()
    listed = lambda route: None
    try:
        # ---- defaults: nothing is the default, the dialog starts on no saved CA ----
        v = view()
        if v.get("default") != "":
            fail("ca-profiles", f"no default CA expected on a fresh instance, got {v.get('default')!r}")
        before = {p["id"] for p in v.get("profiles") or []}

        js("openTabById('cert')")
        pg.wait_for_timeout(600)
        fr = open_panel()
        if not fr.evaluate("document.getElementById('caNoDefaultBtn').classList.contains('disabled')"):
            fail("ca-profiles", "'No default' must be disabled while no default CA is set")

        # ---- a saved CA with its own registration email, one without ----
        fr.fill("#caName", CP_A)
        fr.fill("#caDirectory", "https://ca-one.smoke.test/acme/directory")
        fr.fill("#caEmail", "pki@smoke.test")
        fr.click("button:has-text('Save CA')")
        fr.wait_for_function("n => [...document.querySelectorAll('#caProfileList tr')].some(r => r.innerText.includes(n))", arg=CP_A, timeout=6000)
        if "pki@smoke.test" not in (row(fr, CP_A) or ""):
            fail("ca-profiles", f"the list does not show the registration email of the saved CA: {row(fr, CP_A)!r}")
        a = by_name(CP_A)
        if not a or a.get("email") != "pki@smoke.test":
            fail("ca-profiles", f"the registration email was not stored: {a}")
        fr.fill("#caName", CP_B)
        fr.fill("#caDirectory", "https://ca-one.smoke.test/acme/directory")
        fr.click("button:has-text('Save CA')")
        fr.wait_for_function("n => [...document.querySelectorAll('#caProfileList tr')].some(r => r.innerText.includes(n))", arg=CP_B, timeout=6000)
        if "ACME email of the ACME page" not in (row(fr, CP_B) or ""):
            fail("ca-profiles", f"a saved CA without email must say that the ACME email is used: {row(fr, CP_B)!r}")
        b = by_name(CP_B)
        if not a or not b:
            raise RuntimeError("the saved CAs were not created")

        # edit: the email comes back into the form; a bad address is refused and nothing changes
        fr.evaluate("n => [...document.querySelectorAll('#caProfileList tr')].find(r => r.querySelector('.caName') && r.querySelector('.caName').innerText.trim() === n).querySelector('.caEdit').click()", CP_A)
        if fr.input_value("#caEmail") != "pki@smoke.test":
            fail("ca-profiles", f"Edit does not load the registration email: {fr.input_value('#caEmail')!r}")
        fr.fill("#caEmail", "not an email")
        clear_toasts()
        fr.click("button:has-text('Save CA')")
        pg.wait_for_timeout(700)
        if "email" not in " ".join(toasts()).lower() or by_name(CP_A).get("email") != "pki@smoke.test":
            fail("ca-profiles", f"a bad registration email must be refused with a message: {toasts()} / {by_name(CP_A)}")
        fr.click("#caForm button:has-text('Clear')")
        clear_toasts()

        # ---- default CA: chosen, shown, used by the request dialog ----
        # "make default" is a real button, used here with the keyboard; "No default" belongs to the list, not to the edit form
        tag = fr.evaluate("n => { const b = [...document.querySelectorAll('#caProfileList tr')].find(r => r.querySelector('.caName') && r.querySelector('.caName').innerText.trim() === n).querySelector('.caMakeDefault'); b.focus(); return b.tagName + ':' + (document.activeElement === b); }", CP_A)
        if tag != "BUTTON:true":
            fail("ca-profiles", f"'make default' must be a focusable button: {tag}")
        pg.keyboard.press("Enter")
        fr.wait_for_function("n => { const r = [...document.querySelectorAll('#caProfileList tr')].find(r => r.querySelector('.caName') && r.querySelector('.caName').innerText.trim() === n); return r && !!r.querySelector('.caIsDefault'); }", arg=CP_A, timeout=6000)
        if fr.evaluate("!!document.querySelector('#caForm #caNoDefaultBtn') || !document.querySelector('#caTable + .caDefaultBar #caNoDefaultBtn')"):
            fail("ca-profiles", "'No default' must sit right under the list of saved CAs, not in the edit form")
        if view().get("default") != a["id"]:
            fail("ca-profiles", f"'make default' was not stored: {view().get('default')!r}")
        if fr.evaluate("document.querySelectorAll('#caProfileList .caIsDefault').length") != 1:
            fail("ca-profiles", "exactly one saved CA must be marked as the default")
        if fr.evaluate("document.getElementById('caNoDefaultBtn').classList.contains('disabled')"):
            fail("ca-profiles", "'No default' must be usable once a default is set")
        clear_toasts()
        close_panel()
        dlg = open_panel("acme")
        try:
            dlg.wait_for_function("id => $('#ca').dropdown('get value') === 'profile:' + id", arg=a["id"], timeout=6000)
        except Exception:
            fail("ca-profiles", f"the certificate request dialog does not start on the default CA: {dlg.evaluate('$(\"#ca\").dropdown(\"get value\")')!r}")
        if "default" not in dlg.evaluate("$('#ca .menu .item[data-value^=\"profile:\"]').filter((i, e) => e.dataset.value === 'profile:' + %r).text()" % a["id"]):
            fail("ca-profiles", "the dialog does not mark the default CA in its list")
        close_panel()

        # ---- the ACME page's CA settings as a saved CA: only on request, once, no default change ----
        fr = open_panel()
        n0 = len(view().get("profiles") or [])
        clear_toasts()
        fr.click("#caImportBtn")
        pg.wait_for_function("n => fetch('/api/acme/profiles/ca').then(r => r.json()).then(d => (d.profiles || []).length === n + 1)", arg=n0, timeout=8000)
        new = [p for p in view().get("profiles") or [] if p["id"] not in before and p["name"] not in (CP_A, CP_B)]
        made.extend(p["id"] for p in new)
        glob = js("fetch('/api/acme/autoRenew/ca').then(r => r.json())")
        if len(new) != 1 or not new[0]["directoryURL"].startswith("http") or (glob.get("name") != "custom" and glob.get("name") not in new[0]["name"]):
            fail("ca-profiles", f"the saved CA made from the ACME page settings ({glob}) looks wrong: {new}")
        if view().get("default") != a["id"]:
            fail("ca-profiles", "saving the ACME page settings as a saved CA must not change the default")
        pg.wait_for_timeout(500)
        if not any("Saved as" in m for m in toasts()):
            fail("ca-profiles", f"no confirmation after saving the ACME page settings: {toasts()}")
        clear_toasts()
        fr.wait_for_function("document.querySelectorAll('#caProfileList tr').length >= 3", timeout=6000)
        fr.click("#caImportBtn")
        pg.wait_for_timeout(900)
        if len(view().get("profiles") or []) != n0 + 1 or "already saved" not in " ".join(toasts()):
            fail("ca-profiles", f"a second run must be refused, not duplicated: {toasts()}")
        clear_toasts()
        close_panel()

        # ---- CA of existing certificates: assign without issuing ----
        work = tempfile.mkdtemp(prefix="cp-smoke-")
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(work, "k.pem"), "-out", os.path.join(work, "c.pem"),
                            "-days", "30", "-subj", "/CN=" + CP_CERT, "-addext", "subjectAltName=DNS:" + CP_CERT], check=True, capture_output=True, timeout=60)
            pems = [open(os.path.join(work, "c.pem")).read(), open(os.path.join(work, "k.pem")).read()]
        except Exception as e:
            raise RuntimeError(f"could not make a test certificate with openssl: {e}")
        up = js("""([d, pub, pri]) => Promise.all([['pub', pub], ['pri', pri]].map(([k, text]) => { const f = new FormData(); f.append('file', new Blob([text]), k);
            return fetch('/api/cert/upload?ktype=' + k + '&domain=' + encodeURIComponent(d), {method: 'POST', body: f, headers: {'X-CSRF-Token': document.querySelector('meta[name="zoraxy.csrf.Token"]').getAttribute('content')}}).then(r => r.status); }))""", [CP_CERT] + pems)
        c0 = cert()
        if up != [200, 200] or not c0:
            raise RuntimeError(f"test certificate upload failed: {up}")

        # an upload has no ACME metadata: it is not listed, and the API refuses to assign it instead of quietly making it an ACME certificate
        r = post({"op": "assign", "cert": CP_CERT, "id": b["id"]})
        c_up = cert()
        if "not issued by ACME" not in str((r or {}).get("error")) or not c_up or c_up.get("ManagedBy") != "upload" or c_up.get("CAProfileID"):
            fail("ca-profiles", f"an uploaded certificate must not be assignable: {r} / {c_up}")
        fr = open_panel()
        fr.wait_for_selector("#certAssignList tr", timeout=6000)
        if fr.evaluate("n => !!document.querySelector(`#certAssignList tr[data-cert='${n}']`)", CP_CERT):
            fail("ca-profiles", "an uploaded certificate must not be listed under 'CA of existing certificates'")
        close_panel()

        assignable = bool(cert_dir)
        if assignable:
            # what an issuance by ACME leaves next to the certificate
            with open(os.path.join(cert_dir, CP_CERT + ".json"), "w") as f:
                f.write('{"acme_name": "Let\'s Encrypt", "acme_url": "", "skip_tls": false, "dns": false, "prop_time": 300, "dnsServers": [], "acme_profile": "shortlived", "managed_by": "acme"}')
            c0 = cert()
            if not c0 or c0.get("ManagedBy") != "acme":
                raise RuntimeError(f"SMOKE_CERT_DIR={cert_dir!r} is not the certificate folder of this instance: {c0}")
        else:
            print("ca-profiles: SMOKE_CERT_DIR not set, the assignment round trip is SKIPPED (display checks only)")

            def listed(route):
                route.fulfill(json=[dict(c0, ManagedBy="acme")])
            ctx.route("**/api/cert/list?date=true", listed)
        fr = open_panel()
        sel = f"#certAssignList tr[data-cert='{CP_CERT}'] select"
        fr.wait_for_selector(sel, timeout=6000)
        if fr.input_value(sel) != "":
            fail("ca-profiles", f"an unassigned certificate must show 'No saved CA': {fr.input_value(sel)!r}")
        if assignable:
            clear_toasts()
            fr.select_option(sel, b["id"])
            pg.wait_for_function("n => fetch('/api/acme/profiles/ca').then(() => [...document.querySelectorAll('.zx-toast__msg, #messageBox')].some(e => e.innerText.includes(n)))", arg=CP_CERT, timeout=6000)
            c1 = cert()
            if not c1 or c1.get("CAProfileID") != b["id"] or c1.get("ManagedBy") != "acme":
                fail("ca-profiles", f"the assignment was not stored: {c1}")
            if c1 and (c1.get("ExpireDate"), c1.get("LastModifiedDate")) != (c0.get("ExpireDate"), c0.get("LastModifiedDate")):
                fail("ca-profiles", f"assigning must not touch the certificate file: {c0} -> {c1}")
            meta = open(os.path.join(cert_dir, CP_CERT + ".json")).read()
            if "shortlived" in meta or b["id"] not in meta:
                fail("ca-profiles", f"assigning must store the saved CA and drop the ACME profile name of the previous CA: {meta}")
        close_panel()
        fr = open_panel()
        fr.wait_for_selector(sel, timeout=6000)
        if assignable and fr.input_value(sel) != b["id"]:
            fail("ca-profiles", f"the assigned CA is not shown after reopening: {fr.input_value(sel)!r}")

        # ---- light, dark, 390px ----
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("390", False, 390)):
            close_panel()
            theme(dark)
            pg.set_viewport_size({"width": w, "height": 1000})
            pg.wait_for_timeout(400)
            fr = open_panel()
            fr.wait_for_selector(sel, timeout=6000)
            over = fr.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            if over > 2:
                fail("layout", f"ca-profiles {label}: the panel scrolls sideways by {over}px")
            if dark and not fr.evaluate("document.body.classList.contains('darkTheme')"):
                fail("ca-profiles", "the panel is light in the dark theme")
            # the directory URL keeps a readable width: a block per saved CA on a phone, a column next to the buttons otherwise
            url_w = fr.evaluate("Math.min(...[...document.querySelectorAll('#caProfileList .caUrl')].map(e => e.getBoundingClientRect().width))")
            if url_w < 240:
                fail("layout", f"ca-profiles {label}: the directory URL of a saved CA is squeezed to {url_w:.0f}px")
            if fr.evaluate("[...document.querySelectorAll('#caProfileList button, #caNoDefaultBtn')].some(b => b.getClientRects().length === 0)"):
                fail("layout", f"ca-profiles {label}: a button of the saved CA list is not visible")
            for anchor, shot in (("#caProfileList", "list"), ("#certAssignList", "assign")):
                fr.evaluate("s => document.querySelector(s).closest('table').scrollIntoView({block: 'center'})", anchor)
                pg.wait_for_timeout(300)
                pg.screenshot(path=os.path.join(args.out, f"ca-profiles-{shot}-{label}.png"))
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 800})
        close_panel()
        fr = open_panel()
        fr.wait_for_selector(sel, timeout=6000)

        # back to no saved CA
        if assignable:
            clear_toasts()
            fr.select_option(sel, "")
            pg.wait_for_function("n => fetch('/api/cert/list?date=true').then(r => r.json()).then(l => l.some(c => c.Filename === n && c.CAProfileID === ''))", arg=CP_CERT, timeout=6000)
        close_panel()

        # ---- deleting the default CA clears the default ----
        post({"op": "delete", "id": a["id"]})
        if view().get("default") != "":
            fail("ca-profiles", "deleting the default CA must clear the default")
        dlg = open_panel("acme")
        if dlg.evaluate("$('#ca').dropdown('get value')").startswith("profile:"):
            fail("ca-profiles", "the request dialog still starts on a saved CA after the default was cleared")
        close_panel()
    except Exception as ex:
        fail("ca-profiles", f"scenario failed: {' '.join(str(ex).split()[:40])}")
        try:
            pg.screenshot(path=os.path.join(args.out, "ca-profiles-failure.png"))
        except Exception:
            pass
    finally:
        try:
            ctx.unroute("**/api/cert/list?date=true", listed)
        except Exception:
            pass
        try:
            if js("$('.sideWrapper').is(':visible')"):
                close_panel()
            theme(False)
            pg.set_viewport_size({"width": 1366, "height": 800})
            cleanup()
        except Exception:
            pass
