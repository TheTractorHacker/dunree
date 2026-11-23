"""Smoke scenario of the Certificates / ACME / Traffic pages audit (docs/ux/audit-2026-11.md follow-up): certificate upload result handling
and double submit, the side drawer (Close button, Escape), toast de-duplication, renew wording, the certificate table (no hidden rows, mobile
card layout), CSR messages, ACME email feedback and expired highlighting, Statistics (chart colours after the theme switch, date picker Escape,
Blocked recording note), Visitors (tabs at 390px, settings validation), Uptime Monitor (error reason, empty state, long host names) and the
absence of browser warnings from the plugin iframe sandbox. Loaded by smoke.py (exec in its namespace: fail, current, settle,
check_horizontal, args, os, allow, re)."""
import subprocess
import tempfile

LONG_HOST = "very-long-hostname-for-testing-layout-" + "x" * 50 + ".example-internal-network.corp.example.com"


def certs_traffic_ui(pg, ctx):
    tmp = tempfile.mkdtemp()

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def openssl_cert(cn, extra):
        key, crt = os.path.join(tmp, cn + ".key"), os.path.join(tmp, cn + ".pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn,
                        "-addext", "subjectAltName=DNS:" + cn] + extra, check=True, capture_output=True)
        return open(crt).read(), open(key).read()

    def upload(cn, pem, key):
        return js("""async ([cn, pem, key]) => {
            const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content, out = [];
            for (const [kt, body] of [['pub', pem], ['pri', key]]) {
                const f = new FormData(); f.append('file', new Blob([body]), kt);
                const r = await fetch('/api/cert/upload?ktype=' + kt + '&domain=' + cn, {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f});
                out.push(r.status);
            }
            return out; }""", [cn, pem, key])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def toasts():
        return js("[...document.querySelectorAll('.zx-toast__msg, #messageBox')].filter(e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden').map(e => e.innerText.trim()).filter(Boolean)")

    def clear_toasts():
        js("document.querySelectorAll('.zx-toast').forEach(e => e.remove())")

    def drawer_open():
        return js("$('.sideWrapper').is(':visible') && $('.sideWrapper .content').is(':visible')")

    def wait_drawer(open_):
        pg.wait_for_function("o => ($('.sideWrapper').is(':visible') && !$('.sideWrapper .content').transition('is animating')) === o", arg=open_, timeout=6000)

    # a little traffic so the Statistics charts exist (a rule that answers 502, requests through the inbound port)
    host = "ct-traffic.smoke.test"
    r = js("""h => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST', data: {type: 'host', rootname: h, ep: '127.0.0.1:9', tls: 'false', tlsval: 'false', bypassGlobalTLS: 'false', bpgtls: 'false', cred: '', ssl: 'false'}, success: r => res(r), error: () => res('error')}))""", host)
    inbound = int(re.search(r":(\d+)$", args.url).group(1)) + 1
    import http.client
    import ssl
    for ua in ("curl/8.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"):
        for _ in range(3):
            for mk in (lambda: http.client.HTTPSConnection("127.0.0.1", inbound, timeout=5, context=ssl._create_unverified_context()),
                       lambda: http.client.HTTPConnection("127.0.0.1", inbound, timeout=5)):
                try:   # the inbound listener is TLS or plain depending on the instance
                    c = mk()
                    c.request("GET", "/x", headers={"Host": host, "User-Agent": ua})
                    c.getresponse().read()
                    c.close()
                    break
                except Exception:
                    pass
    # Referring sites: one request per reason a Referer can be missing, plus a real referrer and a hostile Origin (stats check below)
    chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    for extra in ({"Referer": "https://news.smoke.example/story"}, {"Referer": "https://news.smoke.example/story"},
                  {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-origin"},
                  {"Origin": "https://shop.smoke.example"}, {"Origin": 'https://x.smoke.example"><script>window.__refxss=1</script>'},
                  # Referer headers that turn into a classification key once markup is removed: must stay ordinary rows
                  {"Referer": "<b></b>~direct"}, {"Referer": "<i></i>~origin:https://fake.smoke.example"},
                  {"Referer": "<script>window.__refxss=1</script>"}):
        for mk in (lambda: http.client.HTTPSConnection("127.0.0.1", inbound, timeout=5, context=ssl._create_unverified_context()),
                   lambda: http.client.HTTPConnection("127.0.0.1", inbound, timeout=5)):
            try:
                c = mk()
                c.request("GET", "/x", headers=dict({"Host": host, "User-Agent": chrome}, **extra))
                c.getresponse().read()
                c.close()
                break
            except Exception:
                pass
    posts = []
    pg.on("request", lambda r: posts.append(r.url) if "/api/cert/upload" in r.url else None)
    warnings = []
    pg.on("console", lambda m: warnings.append(m.text) if m.type == "warning" else None)
    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    current["page"] = "ct-seed"
    good_pem, good_key = openssl_cert("up.smoke.test", ["-days", "200"])
    soon_pem, soon_key = openssl_cert("soon.smoke.test", ["-days", "9"])
    old_pem, old_key = openssl_cert("old.smoke.test", ["-not_before", "20250101000000Z", "-not_after", "20250201000000Z"])
    for cn, pem, key in (("soon.smoke.test", soon_pem, soon_key), ("old.smoke.test", old_pem, old_key)):
        if upload(cn, pem, key) != [200, 200]:
            fail("cert-upload", f"could not seed {cn}")
    # the server itself refuses what is not a PEM certificate / key (a bad upload is an error, not a stored file)
    allow.append(re.compile(r"400 .*api/cert/upload"))
    allow.append(re.compile(r"Failed to load resource.*400"))
    st = js("""async () => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content; const f = new FormData(); f.append('file', new Blob(['garbage']), 'x');
        const r = await fetch('/api/cert/upload?ktype=pub&domain=garbage.smoke.test', {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f}); return [r.status, await r.text()]; }""")
    if st[0] != 400 or "PEM" not in st[1]:
        fail("cert-upload", f"the server accepted a garbage certificate upload: {st}")
    try:
        # ---- Certificates ----
        current["page"] = "ct-cert"
        js("openTabById('cert')")
        pg.wait_for_selector("#certifiedDomainList tr", timeout=8000)
        pg.wait_for_function("document.querySelectorAll('#certifiedDomainList tr').length >= 2", timeout=8000)
        wrap = js("(() => { const w = document.querySelector('#certPage .zx-table-wrap'); return [w.scrollHeight, w.clientHeight]; })()")
        if wrap[0] > wrap[1] + 2:
            fail("cert-table", f"the certificate table hides rows in a nested scroll box (scrollHeight {wrap[0]} > {wrap[1]})")
        # the rows carry the Renew button (the callout above is one line: how many need attention, and what Renew does)
        titles = js("[...document.querySelectorAll('#certifiedDomainList button.renewButton')].map(b => b.title)")
        if titles and any("uploaded" not in t.lower() and "issued with" not in t.lower() for t in titles):
            fail("cert-renew", f"Renew has no explanation: {titles}")
        if pg.is_visible("#certExpiringBox"):
            if "replace" not in js("document.getElementById('certExpiringText').innerText").lower():
                fail("cert-renew", "the callout does not say what Renew does for non-ACME certificates")
            if not re.search(r"\d+ certificates? needs? attention", js("document.getElementById('certExpiringTitle').innerText")):
                fail("cert-renew", "the callout does not say how many certificates need attention")
            if js("document.querySelectorAll('#certExpiringBox button').length"):
                fail("cert-renew", "the callout repeats the Renew buttons of the rows below it")
        # chips never break inside a name: one line each, at most three shown, the rest behind "+N more"
        tall = js("[...document.querySelectorAll('#certifiedDomainList .cx-host')].filter(c => c.offsetParent && c.getClientRects().length > 1 || c.offsetHeight > 30).map(c => c.textContent)")
        if tall:
            fail("cert-table", f"a host chip wraps inside the name: {tall[:3]}")
        many = js("[...document.querySelectorAll('#certifiedDomainList .cx-hosts')].map(u => [...u.querySelectorAll('li.cx-host')].filter(c => c.offsetParent).length).filter(n => n > 3)")
        if many:
            fail("cert-table", f"a certificate row shows more than three host chips: {many}")
        # the hidden attribute must win over the display of a kit class: with an ACME email saved the guided path does not
        # ask for it again, and the buttons of the failed state are not there while a request runs
        pg.route("**/api/acme/autoRenew/email", lambda r: r.fulfill(status=200, content_type="application/json", body='"ops@smoke.test"') if r.request.method == "GET" else r.continue_())
        pg.click("#certAddOpenBtn")
        pg.wait_for_timeout(300)
        if not pg.is_visible("#certPage label[data-cert-path=acme]"):
            pg.click("#certAddOpenBtn")
        pg.click("#certPage label[data-cert-path=acme]")
        pg.wait_for_timeout(700)
        if pg.is_visible("#certAcmeEmailField") or "ops@smoke.test" not in js("document.getElementById('certAcmeSummary').innerText"):
            fail("cert-add", "the ACME path asks for the contact email although one is saved (the hidden field is visible)")
        js("certSetResult('working', 'Asking for the certificate ...', 'Keep this page open.')")
        if pg.is_visible("#certAddResultActions"):
            fail("cert-add", "'Change and try again' is visible while the request is still running")
        js("certSetResult(null)")
        pg.unroute("**/api/acme/autoRenew/email")
        pg.click("#certAddClose")
        pg.wait_for_timeout(200)
        # Add a certificate is a guided choice: open it, take the "Upload your own" path, then the paste mode
        pg.click("#certAddOpenBtn")
        pg.wait_for_timeout(300)
        if not pg.is_visible("#certPage label[data-cert-path=upload]"):
            # the button can be clicked before its handler is attached; one more click opens the card
            pg.click("#certAddOpenBtn")
            pg.wait_for_timeout(300)
        pg.click("#certPage label[data-cert-path=upload]")
        pg.wait_for_timeout(200)
        pg.click("#certPasteBtn")
        # garbage: nothing is posted, no success box, one error toast
        before = len(posts)
        pg.fill("#certdomain", "a b/../c" + "x" * 240)
        pg.fill("#pubkeyPasteContent", "garbage pem")
        pg.fill("#prikeyPasteContent", "garbage key")
        clear_toasts()
        pg.dblclick("#certPasteUploadBtn")
        pg.wait_for_timeout(600)
        if len(posts) != before:
            fail("cert-upload", f"garbage input was posted to the server ({len(posts) - before} requests)")
        if js("$('#certUploadSuccMsg').is(':visible')"):
            fail("cert-upload", "garbage input shows the green 'uploaded' box")
        if any("uploaded" in t.lower() and "not" not in t.lower() for t in toasts()):
            fail("cert-upload", f"garbage input shows an 'uploaded' toast: {toasts()}")
        if not toasts():
            fail("cert-upload", "garbage input gives no error message")
        shot("ct-cert-garbage.png")
        # a valid pair is uploaded exactly once even on a double click
        pg.fill("#certdomain", "up.smoke.test")
        pg.fill("#pubkeyPasteContent", good_pem)
        pg.fill("#prikeyPasteContent", good_key)
        before = len(posts)
        clear_toasts()
        pg.dblclick("#certPasteUploadBtn")
        pg.wait_for_function("$('#certUploadSuccMsg').is(':visible')", timeout=8000)
        pg.wait_for_timeout(500)
        if len(posts) - before != 2:
            fail("cert-upload", f"a double click sent {len(posts) - before} upload requests (expected 2: public + private key)")
        n_up = len([t for t in toasts() if "Certificate uploaded" in t])
        if n_up != 1:
            fail("toast", f"{n_up} 'Certificate uploaded' toasts after one upload")
        ov = js("(() => { const m = document.getElementById('certUploadSuccMsg'); return m.scrollWidth - m.clientWidth; })()")
        if ov > 2:
            fail("layout", f"the upload success box overflows by {ov}px")
        # toast de-duplication
        clear_toasts()
        js("ZxUI.toast('same message'); ZxUI.toast('same message'); ZxUI.toast('same message')")
        if js("document.querySelectorAll('.zx-toast').length") != 1:
            fail("toast", "the same toast message is stacked instead of shown once")
        clear_toasts()
        # side drawer: Close button and Escape
        current["page"] = "ct-drawer"
        for label in ("CSR, certificate folder", "ACME profiles"):
            pg.click(f"#certPage button:has-text('{label}')")
            wait_drawer(True)
            pg.wait_for_timeout(500)
            if not pg.is_visible(".sideWrapper .sideWrapperClose"):
                fail("a11y", f"the drawer '{label}' has no visible Close button")
            pg.keyboard.press("Escape")
            try:
                wait_drawer(False)
            except Exception:
                fail("a11y", f"Escape does not close the drawer '{label}' (focus on the page)")
                js("hideSideWrapper()")
                pg.wait_for_timeout(600)
            pg.click(f"#certPage button:has-text('{label}')")
            wait_drawer(True)
            pg.wait_for_timeout(500)
            fr = [f for f in pg.frames if "snippet/" in f.url and "placeholder" not in f.url]
            if fr:
                fr[0].locator("body").click(position={"x": 5, "y": 5})
            pg.keyboard.press("Escape")
            try:
                wait_drawer(False)
            except Exception:
                fail("a11y", f"Escape inside the drawer '{label}' does not close it")
                js("hideSideWrapper()")
                pg.wait_for_timeout(600)
            pg.click(f"#certPage button:has-text('{label}')")
            wait_drawer(True)
            pg.click(".sideWrapper .sideWrapperClose")
            try:
                wait_drawer(False)
            except Exception:
                fail("a11y", f"the Close button does not close the drawer '{label}'")
        # CSR: the field named in the message, empty submit marks the field
        pg.click("#certPage button:has-text('CSR, certificate folder')")
        wait_drawer(True)
        pg.wait_for_timeout(600)
        fr = [f for f in pg.frames if "certtools" in f.url][0]
        fr.fill("#csrCN", "not a domain!! " + "x" * 200)
        clear_toasts()
        fr.click("button:has-text('Generate key and CSR')")
        pg.wait_for_timeout(800)
        msg = " ".join(toasts())
        if "common name" not in msg.lower() or "alternative" in msg.lower():
            fail("csr", f"an invalid common name is reported as: {msg!r}")
        if len(msg) > 200:
            fail("csr", "the CSR error repeats the whole (long) value")
        if js("(() => { const m = document.getElementById('messageBox'); return m.scrollWidth - m.clientWidth; })()") > 2:
            fail("layout", "the error toast overflows its box")
        fr.fill("#csrCN", "")
        fr.click("button:has-text('Generate key and CSR')")
        pg.wait_for_timeout(300)
        if not fr.evaluate("document.getElementById('csrCN').closest('.field').classList.contains('error')"):
            fail("csr", "an empty common name does not mark the field")
        js("hideSideWrapper()")
        pg.wait_for_timeout(600)
        # 390px: tab strip of the drawer scrolls, table cards do not clip, empty cell centered
        pg.set_viewport_size({"width": 390, "height": 800})
        current["page"] = "ct-mobile"
        pg.wait_for_timeout(300)
        check_horizontal(pg, "cert 390")
        cell = js("""(() => { const td = document.querySelector('#certifiedDomainList td[data-label=Expires]'); const r = td.getBoundingClientRect();
            return {right: r.right, vw: innerWidth, kids: [...td.querySelectorAll('.zx-sub, .zx-badge')].map(e => { const b = e.getBoundingClientRect(); return b.right <= innerWidth + 1; })}; })()""")
        if not all(cell["kids"]) or cell["right"] > cell["vw"] + 1:
            fail("layout", f"the Expires cell is clipped at 390px: {cell}")
        empty = js("""(() => { const tb = document.getElementById('certifiedDomainList'); const tr = document.createElement('tr'); tr.id = 'zxProbe';
            tr.innerHTML = '<td colspan="6"><div class="zx-empty"><div class="zx-empty__title">probe</div></div></td>'; tb.appendChild(tr);
            const td = tr.firstChild, cs = getComputedStyle(td), b = tr.getBoundingClientRect(), e = td.querySelector('.zx-empty').getBoundingClientRect();
            const out = {display: cs.display, left: e.left - b.left, right: b.right - e.right}; tr.remove(); return out; })()""")
        if empty["display"] != "block" or abs(empty["left"] - empty["right"]) > 4:
            fail("layout", f"an empty-state cell is not centered in the card layout at 390px: {empty}")
        shot("ct-cert-390.png")
        pg.click("#certPage button:has-text('CSR, certificate folder')")
        wait_drawer(True)
        pg.wait_for_timeout(600)
        fr = [f for f in pg.frames if "certtools" in f.url][0]
        tabs = fr.evaluate("(() => { const m = document.querySelector('.ui.tabular.menu'); return [getComputedStyle(m).overflowX, m.scrollWidth, m.clientWidth]; })()")
        if tabs[0] not in ("auto", "scroll") and tabs[1] > tabs[2]:
            fail("layout", f"the drawer tab strip is clipped at 390px: {tabs}")
        js("hideSideWrapper()")
        pg.wait_for_timeout(600)
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- ACME ----
        current["page"] = "ct-acme"
        js("openTabById('acme')")
        pg.wait_for_selector("#acmeDomainTableBody tr", timeout=8000)
        pg.wait_for_timeout(1200)
        exp = js("[...document.querySelectorAll('#acmeDomainTableBody tr')].filter(r => r.innerText.includes('old.smoke.test')).map(r => r.querySelector('td').className)")
        if exp and "expiredDomain" not in exp[0]:
            fail("acme", f"an expired certificate is not marked expired in the auto-renew table: {exp}")
        pg.fill("#prefACMEEmail", "")
        if js("document.getElementById('acmeAutoRenewCheckbox').classList.contains('disabled')"):
            clear_toasts()
            pg.click("#acmeToggleRow", position={"x": 20, "y": 10})
            pg.wait_for_timeout(300)
            if "email" not in " ".join(toasts()).lower() or not pg.is_visible("#acmeEmailRequiredHint"):
                fail("acme", f"enabling auto renew without an email gives no feedback: {toasts()}")
        for bad in ("not-an-email", ""):
            pg.fill("#prefACMEEmail", bad)
            clear_toasts()
            pg.click("button[onclick='saveDefaultCA();']")
            pg.wait_for_timeout(500)
            text = " ".join(toasts())
            if "mail:" in text.lower() or "valid email" not in text.lower() and "required" not in text.lower():
                fail("acme", f"saving the email {bad!r} reports: {text!r}")
        r = js("""async () => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content;
            const x = await fetch('/api/acme/autoRenew/email', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'set=not-an-email'}); return await x.json(); }""")
        if "Mail:" in str(r) or "missing '@'" in str(r):
            fail("acme", f"the API still returns the raw parser error: {r}")
        shot("ct-acme.png")

        # ---- Statistics ----
        current["page"] = "ct-stats"
        js("openTabById('stats')")
        pg.wait_for_timeout(1200)
        js("document.querySelector('#sRange button[data-range=custom]').click()")
        pg.click("#statsRangeStart")
        pg.wait_for_function("document.querySelector('.picker-wrap.popup.show') !== null", timeout=10000)
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(200)
        if js("document.querySelector('.picker-wrap.popup.show') !== null"):
            fail("stats", "Escape does not close the date picker")
        js("document.querySelector('#sRange button[data-range=\"7\"]').click()")
        pg.click("#sAdvanced") if pg.is_visible("#sAdvanced") else None
        if drawer_open():
            pg.wait_for_timeout(700)
            fr = [f for f in pg.frames if "advanceStatsOprs" in f.url]
            if fr:
                body = fr[0].evaluate("document.body.innerText")
                if "Advance Statistics" in body or "RESET STATISTICS" in body or "Cancel" in body:
                    fail("stats", "the Advanced operations drawer still has the old wording (Advance / RESET / Cancel)")
                fr[0].click("button:has-text('Reset statistics')")
                pg.wait_for_selector(".zx-dialog-backdrop", timeout=3000)
                pg.keyboard.press("Escape")
            pg.wait_for_timeout(300)
            js("hideSideWrapper()")
            pg.wait_for_timeout(600)
        # the client mix is drawn as share bars (HTML, themed by tokens) for the generated traffic
        js("document.querySelector('#sRange button[data-range=today]').click()")
        try:
            pg.wait_for_function("document.querySelectorAll('#stats_device .sShare__bar i').length > 0", timeout=8000)
        except Exception:
            fail("stats", "no share bar was drawn for the generated traffic (Devices)")
        if js("[...document.querySelectorAll('#statsPage .sShare__legend .k')].some(e => e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).textOverflow !== 'ellipsis')"):
            fail("stats", "a share bar legend label is clipped without an ellipsis")
        # Referring sites: real sites first, then every request without a Referer header sorted by the reason, each with its share.
        # Nothing is lumped into one "Unknown or hidden" line any more; only days saved by older versions show as "Unknown (recorded before this version)".
        try:
            pg.wait_for_function("document.querySelectorAll('#stats_RefererWhy li').length >= 5", timeout=8000)
        except Exception:
            fail("stats", "the Referring sites card does not list the reasons for a missing referrer")
        ref = js("""() => { const q = s => [...document.querySelectorAll(s)];
            return {sites: q('#stats_RefererTable li').map(e => e.innerText.replace(/\\s+/g, ' ').trim()),
                    why: Object.fromEntries(q('#stats_RefererWhy li').map(li => [li.dataset.ref, {name: li.querySelector('.k b').innerText.trim(), sub: (li.querySelector('.k small') || {innerText: ''}).innerText.trim(),
                        n: li.querySelector('.n b').innerText.trim(), pct: li.querySelector('.n small').innerText.trim()}])),
                    share: document.getElementById('sRefWhyShare').innerText, note: document.getElementById('sRefNote').innerText,
                    noteShown: document.getElementById('sRefNote').getClientRects().length > 0,
                    page: document.getElementById('statsPage').innerText, xss: !!window.__refxss,
                    wide: q('#stats_RefererWhy li, #stats_RefererTable li').some(li => li.scrollWidth > li.clientWidth + 1) || q('#stats_RefererTable .sVia').some(e => e.scrollWidth > e.clientWidth + 1)}; }""")
        want = {"~direct": "Direct and apps", "~hidden-policy": "Hidden by policy", "~non-browser": "Bots and scripts", "~same-site": "Same site", "~unknown": "Not sent (reason unknown)", "~invalid": "Unreadable referrer"}
        for key, name in want.items():
            row = ref["why"].get(key)
            if not row or row["name"] != name:
                fail("stats", f"Referring sites: no '{name}' row for requests stored as {key}: {ref['why']}")
            elif not row["sub"] or not re.match(r"^(<)?[\d.]+%$", row["pct"]) or not re.match(r"^[\d.,\u00a0\u202f ]+$", row["n"]):
                fail("stats", f"Referring sites: the '{name}' row lacks its explanation, count or share: {row}")
        if "Unknown or hidden" in ref["page"]:
            fail("stats", "the Statistics page still shows the single 'Unknown or hidden' line")
        if "legacy" in ref["why"]:
            fail("stats", "new requests are still stored under the empty referrer key")
        if not ref["sites"] or "news.smoke.example" not in ref["sites"][0]:
            fail("stats", f"Referring sites: the real referring site is not listed first: {ref['sites']}")
        if not any("shop.smoke.example" in x and "Origin header" in x for x in ref["sites"]):
            fail("stats", f"Referring sites: a source known from the Origin header is not listed with its marker: {ref['sites']}")
        if ref["xss"] or any("script" in x for x in ref["sites"]) or "x.smoke.example" in ref["page"]:
            fail("stats", "Referring sites: a hostile Origin header was stored or run")
        if not re.search(r"\d.* requests, .*% of all", ref["share"]):
            fail("stats", f"Referring sites: the share of requests without a referrer is not stated: {ref['share']!r}")
        if not any(x.startswith("~direct") for x in ref["sites"]) or not any(x.startswith("~origin:https://fake.smoke.example") for x in ref["sites"]):
            fail("stats", f"Referring sites: a Referer header that imitates a classification key is not listed as an ordinary referrer: {ref['sites']}")
        if any("fake.smoke.example" in x and "Origin header" in x for x in ref["sites"]):
            fail("stats", f"Referring sites: a Referer header was listed as a source taken from the Origin header: {ref['sites']}")
        if "A client that presents itself as a browser" not in ref["why"].get("~unknown", {}).get("sub", ""):
            fail("stats", "Referring sites: the 'Not sent (reason unknown)' row still claims the client was a browser")
        if not ref["noteShown"] or "does not hide a referrer itself" not in ref["note"] or "every request" in ref["note"]:
            fail("stats", "Referring sites: the note on why a referrer can be missing is not shown")
        if ref["wide"]:
            fail("stats", "Referring sites: a row is wider than its card")
        # a day saved by an older version (empty key) is named as such, below the classified rows
        def legacy_day(route):
            resp = route.fetch()
            body = resp.json()
            if isinstance(body, dict) and isinstance(body.get("Referer"), dict):
                body["Referer"][""] = 7
            route.fulfill(response=resp, json=body)
        pg.route("**/api/analytic/load?*", legacy_day)
        js("document.querySelector('#sRange button[data-range=today]').click()")
        try:
            pg.wait_for_function("(() => { const li = document.querySelector('#stats_RefererWhy li[data-ref=legacy]'); return !!li && li.querySelector('.k b').innerText.trim() === 'Unknown (recorded before this version)' && li.querySelector('.n b').innerText.trim() === '7' && !li.nextElementSibling; })()", timeout=8000)
        except Exception:
            fail("stats", "requests of older days (empty referrer key) are not shown as 'Unknown (recorded before this version)'")
        js("document.getElementById('stats_RefererTable').closest('.zx-card').scrollIntoView({block: 'center'})")
        pg.locator("#stats_RefererTable").locator("xpath=ancestor::section[1]").screenshot(path=os.path.join(args.out, "ct-stats-referrers.png"))
        theme(True)
        pg.locator("#stats_RefererTable").locator("xpath=ancestor::section[1]").screenshot(path=os.path.join(args.out, "ct-stats-referrers-dark.png"))
        shot("ct-stats-dark.png")
        theme(False)
        shot("ct-stats.png")
        pg.unroute("**/api/analytic/load?*")
        # phone width: the card must not make the page scroll sideways
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        check_horizontal(pg, "stats 390")
        pg.locator("#stats_RefererTable").locator("xpath=ancestor::section[1]").screenshot(path=os.path.join(args.out, "ct-stats-referrers-390.png"))
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)
        # Blocked tab: recording off is stated on the page, the search box has a length limit
        js("document.querySelector('#statsPage .sTabs button[data-stab=blocked]').click()")
        pg.wait_for_timeout(800)
        if js("document.getElementById('sbSearch').maxLength") != 300:
            fail("stats", "the Blocked search box has no maxlength")
        # chart colours follow the theme switch (the per-hour chart of the Blocked tab is drawn on a canvas)
        try:
            pg.wait_for_function("typeof Chart !== 'undefined' && !!Chart.getChart(document.getElementById('sbHourly'))", timeout=8000)
        except Exception:
            pass
        if not js("typeof Chart !== 'undefined' && !!Chart.getChart && !!Chart.getChart(document.getElementById('sbHourly'))"):
            fail("stats", "the Blocked per hour chart was not drawn (the theme check could not run)")
        else:
            theme(True)
            pg.wait_for_timeout(300)
            col = js("Chart.getChart(document.getElementById('sbHourly')).options.scales.x.ticks.color")
            theme(False)
            if col == "#475569":
                fail("stats", "chart labels keep the light-theme colour after switching to the dark theme")
        was = js("document.getElementById('sbEnabled').checked")
        pg.set_checked("#sbEnabled", False)
        pg.wait_for_timeout(1200)
        if not pg.is_visible("#sbRecordingOff"):
            fail("stats", "switching recording off is not shown on the page")
        if was:
            pg.set_checked("#sbEnabled", True)
            pg.wait_for_timeout(800)
        pg.click("#statsPage .sTabs button[data-stab=overview]")

        # ---- Visitors ----
        current["page"] = "ct-visitors"
        js("openTabById('visitors')")
        pg.wait_for_timeout(1000)
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        check_horizontal(pg, "visitors 390")
        pg.click("#vTabs [data-vtab=settings]")
        pg.wait_for_timeout(300)
        if not pg.locator("#vTabs [data-vtab=settings]").evaluate("e => { e.scrollIntoView({inline: 'nearest'}); const r = e.getBoundingClientRect(); return r.right <= innerWidth + 1 && r.width > 90; }"):
            fail("layout", "the Settings & privacy tab is cut off at 390px")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.click("#vTabs [data-vtab=recent]")
        pg.wait_for_timeout(400)
        pg.click("#vTabs [data-vtab=settings]")
        pg.wait_for_selector("#vsAge", timeout=10000)
        saves = []
        pg.on("request", lambda r: saves.append(r.url) if "visitors/settings" in r.url and r.method == "POST" else None)
        for age, ips, ring, word in (("-5", "100", "5000", "whole number"), ("30", "5", "5000", "whole number"), ("30", "100", "99999999", "whole number"), ("", "100", "5000", "whole number")):
            pg.fill("#vsAge", age)
            pg.fill("#vsIps", ips)
            pg.fill("#vsRing", ring)
            pg.click("#vsSave")
            pg.wait_for_timeout(300)
            msg = js("document.getElementById('vsMsg').innerText")
            if word not in msg or "Saved" in msg:
                fail("visitors", f"invalid settings ({age!r}, {ips!r}, {ring!r}) give: {msg!r}")
        if saves:
            fail("visitors", "out-of-range settings were posted to the server")
        pg.fill("#vsAge", "90")
        pg.fill("#vsIps", "20000")
        pg.fill("#vsRing", "5000")
        pg.click("#vsSave")
        pg.wait_for_function("document.getElementById('vsMsg').innerText.includes('Saved')", timeout=10000)
        if js("document.querySelector('#vTabs [data-vtab=recent] i.icon') && getComputedStyle(document.querySelector('#vTabs [data-vtab=recent] i.icon'), '::before').content") in ("none", "normal", '""'):
            fail("visitors", "the Recent visits tab has no icon")
        shot("ct-visitors.png")

        # ---- Uptime Monitor ----
        current["page"] = "ct-utm"
        js("openTabById('utm')")
        pg.wait_for_selector("#utmHealthyStatus", timeout=6000)
        pg.wait_for_timeout(800)
        for bad in ("abc", "999-1", "200-", "6xx"):
            pg.fill("#utmHealthyStatus", bad)
            clear_toasts()
            pg.click("#utmHealthyStatusSave")
            pg.wait_for_timeout(500)
            text = js("document.getElementById('utmHealthyStatusErr').innerText")   # the reason is shown at the field, not in a toast
            if "request failed" in text.lower() or "invalid status" not in text.lower():
                fail("utm", f"status list {bad!r} reports {text!r} instead of the server's reason")
            if js("document.getElementById('utmHealthyStatus').getAttribute('aria-invalid')") != "true":
                fail("utm", f"status list {bad!r}: the field is not marked invalid")
            if any("invalid status" in x.lower() for x in toasts()):
                fail("utm", "a refused status list is reported in a toast as well as at the field")
        pg.fill("#utmHealthyStatus", "")
        if js("document.getElementById('utmEmpty') !== null") and js("document.querySelector('#utmEmpty .green.check') !== null"):
            fail("utm", "the empty state shows a green check mark")
        if js("document.getElementById('utmEmpty') !== null") and "refresh this page" in js("document.getElementById('utmrender').innerText"):
            fail("utm", "the empty state still tells the user to refresh the page")
        pg.set_viewport_size({"width": 390, "height": 800})
        js("""h => { const now = Math.floor(Date.now() / 1000); renderUptimeData(h, [{ID: 'x', Name: h, URL: 'http://' + h, Protocol: 'http', Online: true, StatusCode: 200, Latency: 5, Timestamp: now}]); }""", LONG_HOST)
        pg.wait_for_timeout(300)
        check_horizontal(pg, "uptime long host 390")
        shot("ct-utm-390.png")
        js("reloadUptimeList()")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- no iframe sandbox warnings on a plain page load ----
        current["page"] = "ct-warnings"
        warnings.clear()
        pg.goto("about:blank")
        pg.goto(args.url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item", state="attached")
        pg.wait_for_timeout(800)
        bad = [w for w in warnings if "sandbox" in w.lower() or "Unrecognized feature" in w]
        if bad:
            fail("console", f"the page load logs iframe sandbox warnings: {bad}")
    finally:
        current["page"] = "ct-cleanup"
        # the generated traffic must not leak into later scenarios (the Status page draws its map from today's statistics)
        js("""() => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content, d = new Date(), p = n => String(n).padStart(2, '0');
            const day = d.getFullYear() + '_' + p(d.getMonth() + 1) + '_' + p(d.getDate());
            return fetch('/api/analytic/resetRange?start=' + day + '&end=' + day, {method: 'DELETE', headers: {'X-CSRF-Token': tok}})
                .then(() => fetch('/api/visitors/delete', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'ip=127.0.0.1'})); }""")
        js("""h => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: h}, success: r => res(r), error: () => res('error')}))""", host)
        js("""async () => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content;
            for (const d of ['up.smoke.test', 'soon.smoke.test', 'old.smoke.test']) { await fetch('/api/cert/delete', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'domain=' + d}); } }""")
