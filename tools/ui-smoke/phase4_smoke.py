"""Smoke scenario of the Phase 4 GUI (docs/enterprise-dual-proxy-plan.md section 5 Phase 4: dashboard and configuration management).
exec()'d by smoke.py (namespace: fail, current, args, os, re, allow, check_horizontal); run alone with --phase4-only. Needs UI port + 2
free (a throw-away upstream started here on 127.0.0.1) and a throw-away instance: the scenario creates proxy rules, a network plan, a
certificate and (for a moment) the Fleet hub role, and removes all of it again at the end (it still belongs at the very end of a full run).

Covers
  * Security Center > Overview: every card renders with real numbers (two rules, one of them with an unreachable upstream), the warnings are
    listed with their fix links, the links open the right page / tab, light / dark / 390 px layout without overflow or overlapping cards, and
    the 10 s auto refresh runs only while the page is visible (not after leaving the tab, not while the document is hidden);
  * Security Center > Network plan: invalid input is refused and stores nothing, a saved plan survives a reload, a rule outside the plan
    produces the expected warning and a rule inside it does not, adding the rule's address to the plan clears the warning, the policy export
    downloads a markdown that carries the "NOT APPLIED" disclaimer, a POST without the CSRF token is refused;
  * Config Tools (Utilities > System Backup & Restore): the full backup is labelled as containing secrets, the shareable (redacted) export is
    downloaded and a script confirms it holds no private key (while the full backup really does), the dry run shows the diff and changes
    nothing, an old export without a manifest is shown as unverified, a truncated zip, a zip with a tampered file and a zip with a path
    traversal entry are refused with a readable message and leave Restore disabled;
  * Fleet: enabling the Certificates scope (private keys leave the machine) and the captured-keys setting ask for confirmation first, a
    cancelled dialog saves nothing, a direct API call without the acknowledgement is refused.
All POSTs from the page go through $.cjax. Console errors and failed requests are caught by the handlers smoke.py installs on the page."""

import hashlib
import http.server
import json
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import zipfile

P4_OK = "p4-ok.demo.test"        # reachable upstream, outside the plan until the plan learns about it
P4_DOWN = "p4-down.demo.test"    # unreachable upstream (a port nobody listens on)
P4_MATCH = "p4-match.demo.test"  # backend 10.20.30.5:8080, inside the plan (never contacted)
P4_RULES = (P4_OK, P4_DOWN, P4_MATCH)
P4_CERT = "p4-cert.demo.test"
P4_GROUP = "p4group"
P4_DISCLAIMER = "Zoraxy has NOT applied"


def phase4_ui(pg, ctx):
    base = int(args.url.rsplit(":", 1)[1].split("/")[0])
    up_port = base + 2
    current["page"] = "phase4"
    tmp = tempfile.mkdtemp()

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status + ' ' + (e.responseText || '').slice(0, 200)})}))""", [path, data])

    def get(path):
        return pg.evaluate("p => fetch(p).then(r => r.json())", path)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def wait_for(fn, timeout, what, step=0.5):
        end = time.time() + timeout
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(step)
        fail("phase4", f"timed out ({timeout}s) waiting for {what}")
        return None

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(400)

    def type_into(sel, text, frame=None):
        f = frame or pg
        f.click(sel)
        pg.keyboard.press("Control+A")
        pg.keyboard.type(text)

    def toasts():
        return js("[...document.querySelectorAll('.zx-toast__msg, #messageBox')].filter(e => e.getClientRects().length > 0).map(e => e.innerText.trim()).filter(Boolean)")

    def confirm(ok):
        pg.wait_for_selector(".zx-dialog [data-zx-ok]", timeout=5000)
        pg.click(".zx-dialog %s" % ("[data-zx-ok]" if ok else "[data-zx-cancel]"))
        pg.wait_for_timeout(600)

    def sec_tab(name, ready):
        js("openTabById('seccenter')")
        pg.wait_for_selector("#secTabs .item[data-sec='%s']" % name, timeout=10000)
        pg.click("#secTabs .item[data-sec='%s']" % name, timeout=6000)
        pg.wait_for_selector(ready, timeout=15000)

    def layout_bad(scope):
        """elements of the page pane that stick out of the viewport (unless inside a scroller) and card pairs that overlap"""
        return js("""(scope) => { const out = [], W = document.documentElement.clientWidth;
            document.querySelectorAll(scope + ' *').forEach(el => {
              const r = el.getBoundingClientRect(); if (r.width === 0 || r.right <= W + 1) return;
              for (let p = el.parentElement; p && !p.matches(scope); p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return; }
              out.push(el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + '.' + String(el.className).slice(0, 24) + ' right=' + Math.round(r.right)); });
            const cards = [...document.querySelectorAll(scope + ' .zx-card')].filter(c => c.getClientRects().length).map(c => c.getBoundingClientRect());
            for (let i = 0; i < cards.length; i++) for (let j = i + 1; j < cards.length; j++) {
              const a = cards[i], b = cards[j];
              if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) out.push('cards ' + i + ' and ' + j + ' overlap'); }
            return out.slice(0, 5); }""", scope)

    def layout_matrix(tag, scope, ready, shotname):
        for dark in (False, True):
            for (w, h, size) in ((1366, 900, "desktop"), (390, 844, "390")):
                current["page"] = f"phase4-{tag}-layout/{'dark' if dark else 'light'}/{size}"
                theme(dark)
                pg.set_viewport_size({"width": w, "height": h})
                pg.wait_for_timeout(500)
                pg.wait_for_selector(ready, timeout=10000)
                bad = layout_bad(scope)
                if bad:
                    fail("phase4-layout", f"{tag} {'dark' if dark else 'light'} {size}: {bad}")
                check_horizontal(pg, f"{tag} {'dark' if dark else 'light'} {size}")
                shot(f"phase4-{shotname}-{'dark' if dark else 'light'}-{size}.png")
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    class U(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"p4-upstream-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class US(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    upstream = US(("127.0.0.1", up_port), U)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    down_port = free_port()

    def openssl_cert(cn):
        key, crt = os.path.join(tmp, cn + ".key"), os.path.join(tmp, cn + ".pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn,
                        "-addext", "subjectAltName=DNS:" + cn, "-days", "200"], check=True, capture_output=True)
        return open(crt).read(), open(key).read()

    def upload_cert(cn, pem, key):
        return js("""async ([cn, pem, key]) => { const out = [];
            for (const [kt, body] of [['pub', pem], ['pri', key]]) {
                const f = new FormData(); f.append('file', new Blob([body]), kt);
                out.push(await new Promise(res => $.cjax({url: '/api/cert/upload?ktype=' + kt + '&domain=' + cn, method: 'POST', data: f, processData: false, contentType: false, success: r => res(r), error: e => res({error: e.status})})));
            }
            return out; }""", [cn, pem, key])

    def tree_hash():
        """a fingerprint of what an import would overwrite: proxy rules, access rules, redirects and the network plan (read through the full export)"""
        raw = js("""() => fetch('/api/conf/export').then(r => r.arrayBuffer()).then(b => Array.from(new Uint8Array(b)))""")
        zpath = os.path.join(tmp, "snap.zip")
        open(zpath, "wb").write(bytes(raw))
        h = hashlib.sha256()
        with zipfile.ZipFile(zpath) as z:
            for n in sorted(z.namelist()):
                rel = n[5:] if n.startswith("conf/") else n
                if rel.split("/")[0] in ("proxy", "access", "redirect", "rules", "streamproxy"):
                    h.update(n.encode() + b"\0" + z.read(n))
        h.update(json.dumps(get("/api/netplan/get").get("settings"), sort_keys=True).encode())
        return h.hexdigest()

    saved = {"hub": False}
    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    overview_reqs = []
    pg.on("request", lambda r: overview_reqs.append(time.time()) if "/api/security/overview" in r.url else None)
    try:
        # ---------------------------------------------------------------- setup
        current["page"] = "phase4-setup"
        for h in P4_RULES:
            post("/api/proxy/del", {"ep": h})
        for h, ep in ((P4_OK, "127.0.0.1:%d" % up_port), (P4_DOWN, "127.0.0.1:%d" % down_port), (P4_MATCH, "10.20.30.5:8080")):
            r = post("/api/proxy/add", {"type": "host", "rootname": h, "ep": ep, "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
            if isinstance(r, dict) and r.get("error"):
                fail("phase4-setup", f"seeding {h} failed: {r}")
                return
        pem, key = openssl_cert(P4_CERT)
        r = upload_cert(P4_CERT, pem, key)
        if any(isinstance(x, dict) and x.get("error") for x in r):
            fail("phase4-setup", f"uploading the test certificate failed: {r}")
        if (get("/api/netplan/get").get("declared")):
            fail("phase4-setup", "a throw-away instance must start without a network plan (the scenario needs a fresh one)")
        # the uptime monitor probes new rules right away; wait until it knows the unreachable one
        wait_for(lambda: (lambda b: b and b.get("down", 0) >= 1)(get("/api/security/overview").get("backends")), 40, "the uptime monitor to report the unreachable upstream as down", 2)

        # ---------------------------------------------------------------- Overview: cards with real data
        current["page"] = "phase4-overview"
        sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        pg.wait_for_timeout(600)
        titles = js("[...document.querySelectorAll('#ovGrid .zx-card__title')].map(e => e.innerText.trim())")
        want = ["Configuration warnings", "Deployment and status", "Backend health", "Proxy routes", "TLS certificates", "CrowdSec", "Rate limits",
                "Blocked and allowed requests", "Trusted proxies", "Recent security events"]
        for w in want:
            if w not in titles:
                fail("phase4-overview", f"card {w!r} is missing (cards: {titles})")
        if js("document.getElementById('ovError').hidden") is not True:
            fail("phase4-overview", "the error banner is showing on a healthy instance")
        if js("document.getElementById('ovSkel').offsetParent") is not None:
            fail("phase4-overview", "the loading skeleton is still visible after the data arrived")
        data = get("/api/security/overview")
        if data.get("errors"):
            fail("phase4-overview", f"the API reports failed sections: {data.get('errors')}")

        def card_text(title):
            return js("""t => { const c = [...document.querySelectorAll('#ovGrid .zx-card')].find(c => c.querySelector('.zx-card__title').innerText.trim() === t); return c ? c.innerText : ''; }""", title)

        routes = card_text("Proxy routes")
        if str(data["routes"]["total"]) not in routes or data["routes"]["total"] < 3:
            fail("phase4-overview", f"the Proxy routes card does not show the real rule count ({data['routes']['total']}): {routes[:120]!r}")
        back = card_text("Backend health")
        if P4_DOWN not in back or "Down" not in back:
            fail("phase4-overview", f"the Backend health card must list the unreachable upstream {P4_DOWN} as down: {back[:200]!r}")
        if js("""() => { const li = [...document.querySelectorAll('#ovGrid .zx-card')].find(c => c.querySelector('.zx-card__title').innerText.trim() === 'Backend health'); const first = li && li.querySelector('.ov-list li'); return first ? first.innerText : ''; }""").find(P4_DOWN) < 0:
            fail("phase4-overview", "the down backend must be listed first (worst first)")
        if (data.get("status") or {}).get("version") not in card_text("Deployment and status"):
            fail("phase4-overview", "the status card does not show this build's version")
        if "Standalone" not in card_text("Deployment and status"):
            fail("phase4-overview", "the status card must show the Standalone role of a fresh instance")
        certs = card_text("TLS certificates")
        if P4_CERT not in certs:
            fail("phase4-overview", f"the TLS certificates card does not list the uploaded certificate: {certs[:200]!r}")
        if "switched off" not in card_text("CrowdSec"):
            fail("phase4-overview", "the CrowdSec card of a fresh instance must say it is switched off")
        warns = js("[...document.querySelectorAll('#ovGrid .ov-warn')].map(e => e.innerText.replace(/\\s+/g, ' '))")
        if not warns:
            fail("phase4-overview", "the warnings card lists nothing: a throw-away instance has open findings (no TLS on the admin panel, ...)")
        if any(not (x.get("fix") or "").strip() or not (x.get("evidence") or "").strip() for x in data["warnings"]["items"]):
            fail("phase4-overview", "every warning must carry its evidence and its one-line fix")
        if not any("Fix:" in w for w in warns):
            fail("phase4-overview", "no warning offers a link to the page that fixes it")
        if len(warns) != min(6, len(data["warnings"]["items"])):
            fail("phase4-overview", f"the warnings card shows {len(warns)} rows for {len(data['warnings']['items'])} findings (first six expected)")
        print("  phase4 overview warnings:", [w[:70] for w in warns[:3]])
        for w in js("[...document.querySelectorAll('#ovGrid *')].filter(e => /\\[object|undefined|NaN|null/.test(e.children.length ? '' : (e.textContent || ''))).map(e => (e.textContent || '').slice(0, 40))"):
            fail("phase4-overview", f"a card shows a raw value: {w!r}")
        shot("phase4-overview.png")
        pg.evaluate("document.getElementById('ovRefresh').scrollIntoView()")

        # ---------------------------------------------------------------- Overview: links
        current["page"] = "phase4-overview-links"
        pg.click("#ovGrid .ov-go[data-page='seccenter'][data-anchor='deployment']")
        pg.wait_for_selector("#secTabs .item.active[data-sec='deployment']", timeout=8000)
        sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        pg.click("#ovGrid .ov-go[data-page='seccenter'][data-anchor='netplan']")
        pg.wait_for_selector("#secTabs .item.active[data-sec='netplan']", timeout=8000)
        pg.wait_for_selector("#npPage", timeout=8000)
        sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        for page_id in ("utm", "httprp", "cert", "trustproxy"):
            link = pg.locator("#ovGrid .ov-go[data-page='%s']" % page_id).first
            if link.count() == 0:
                fail("phase4-overview-links", f"no link to the page {page_id!r} on the overview")
                continue
            link.scroll_into_view_if_needed()
            link.click()
            pg.wait_for_timeout(700)
            if not js("id => $('#' + id).is(':visible')", page_id):
                fail("phase4-overview-links", f"the link to {page_id!r} did not open that page (hash {js('location.hash')})")
            sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        fixes = js("[...document.querySelectorAll('#ovGrid .ov-warn .ov-go')].map(a => a.dataset.page + '/' + a.dataset.anchor)")
        if fixes:
            first = pg.locator("#ovGrid .ov-warn .ov-go").first
            first.scroll_into_view_if_needed()
            first.click()
            pg.wait_for_timeout(900)
            want_page = fixes[0].split("/")[0]
            ok = js("p => p === 'seccenter' ? true : $('#' + p).is(':visible')", want_page)
            if not ok:
                fail("phase4-overview-links", f"the first warning's fix link ({fixes[0]}) did not open its page")
            sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        if js("document.getElementById('ovWarnToggle') !== null"):
            pg.click("#ovWarnToggle")
            if js("document.querySelectorAll('#ovGrid .ov-warn').length") <= 6:
                fail("phase4-overview", "Show all must list more than six warnings")
            pg.click("#ovWarnToggle")

        # ---------------------------------------------------------------- Overview: refresh only while visible
        current["page"] = "phase4-overview-refresh"
        sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        pg.wait_for_timeout(1500)
        n0 = len(overview_reqs)
        pg.wait_for_timeout(12500)
        if len(overview_reqs) <= n0:
            fail("phase4-overview-refresh", "the overview did not refresh itself within 12 s while it is on screen")
        js("""() => { Object.defineProperty(document, 'visibilityState', {configurable: true, get: () => 'hidden'}); }""")
        pg.wait_for_timeout(500)
        n1 = len(overview_reqs)
        pg.wait_for_timeout(12500)
        if len(overview_reqs) != n1:
            fail("phase4-overview-refresh", f"the overview kept polling while the document was hidden ({len(overview_reqs) - n1} requests)")
        js("""() => { delete document.visibilityState; document.dispatchEvent(new Event('visibilitychange')); }""")
        pg.wait_for_timeout(1500)
        if len(overview_reqs) <= n1:
            fail("phase4-overview-refresh", "becoming visible again must refresh at once")
        pg.click("#secTabs .item[data-sec='netplan']")
        pg.wait_for_selector("#npPage", timeout=8000)
        pg.wait_for_timeout(1000)
        n2 = len(overview_reqs)
        pg.wait_for_timeout(12500)
        if len(overview_reqs) != n2:
            fail("phase4-overview-refresh", f"the overview kept polling after its tab was left ({len(overview_reqs) - n2} requests)")

        # ---------------------------------------------------------------- Overview: layout
        sec_tab("overview", "#ovGrid:not([hidden]) .ov-card")
        layout_matrix("overview", "#ovPage", "#ovGrid:not([hidden]) .ov-card", "overview")

        # ---------------------------------------------------------------- Network plan
        current["page"] = "phase4-netplan"
        sec_tab("netplan", "#npPage #npResult .zx-callout, #npPage #npResult .np-list")
        if P4_DISCLAIMER not in js("document.getElementById('npDisclaimer').innerText") and "applies nothing" not in js("document.getElementById('npDisclaimer').innerText"):
            fail("phase4-netplan", "the standing disclaimer is missing from the tab")
        if "No plan is saved yet" not in js("document.getElementById('npResult').innerText"):
            fail("phase4-netplan", "with no plan saved the tab must say nothing is compared: " + js("document.getElementById('npResult').innerText")[:200])
        if js("document.querySelectorAll('#npResult .np-list li').length && [...document.querySelectorAll('#npResult .np-list li b')].some(b => /application network|permitted application ports/.test(b.innerText))"):
            fail("phase4-netplan", "plan-dependent checks must not report anything before a plan is saved")
        shot("phase4-netplan-empty.png")

        # invalid input is refused with a readable message and nothing is stored
        type_into("#npProxyName", "<b>bad</b>")
        type_into("#npAppCidrs", "10.20.30.0/24")
        pg.click(".zx-savebar [data-zx-save]:visible")
        pg.wait_for_function("document.getElementById('npMsg').style.display !== 'none' || document.querySelector('.zx-savebar.is-error')", timeout=8000)
        if get("/api/netplan/get").get("declared"):
            fail("phase4-netplan", "a plan with an invalid name was stored")
        shot("phase4-netplan-invalid.png")
        type_into("#npProxyName", "Proxy DMZ")
        type_into("#npAppCidrs", "0.0.0.0/0")
        pg.click(".zx-savebar [data-zx-save]:visible")
        pg.wait_for_timeout(1200)
        if get("/api/netplan/get").get("declared"):
            fail("phase4-netplan", "a plan that says 0.0.0.0/0 was stored")
        if not (js("document.getElementById('npMsg').innerText").strip() or js("document.querySelector('.zx-savebar') && document.querySelector('.zx-savebar').innerText")):
            fail("phase4-netplan", "the refusal of 0.0.0.0/0 gave no message")

        # a good plan: save, reload, it is still there
        type_into("#npProxyCidrs", "10.20.10.0/24")
        type_into("#npMgmtName", "Management")
        type_into("#npMgmtCidrs", "10.20.99.0/24")
        type_into("#npAppName", "Servers")
        type_into("#npAppCidrs", "10.20.30.0/24")
        type_into("#npPorts", "8080")
        pg.click(".zx-savebar [data-zx-save]:visible")
        wait_for(lambda: get("/api/netplan/get").get("declared"), 8, "the plan to be saved")
        s = get("/api/netplan/get")["settings"]
        if s.get("applicationVlan", {}).get("cidrs") != ["10.20.30.0/24"] or s.get("appPorts") != ["8080"] or s.get("proxyVlan", {}).get("name") != "Proxy DMZ":
            fail("phase4-netplan", f"the stored plan does not match the form: {s}")
        pg.reload(wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item", state="attached")
        sec_tab("netplan", "#npPage #npResult .np-list, #npPage #npResult .zx-callout")
        pg.wait_for_function("document.getElementById('npAppCidrs').value !== ''", timeout=8000)
        got = js("({a: document.getElementById('npAppCidrs').value, n: document.getElementById('npProxyName').value, m: document.getElementById('npMgmtCidrs').value, p: document.getElementById('npPorts').value})")
        if got != {"a": "10.20.30.0/24", "n": "Proxy DMZ", "m": "10.20.99.0/24", "p": "8080"}:
            fail("phase4-netplan", f"the saved plan did not survive a reload: {got}")

        # a rule outside the plan warns, a rule inside it does not
        current["page"] = "phase4-netplan-findings"
        pg.click("#npRecheck")
        pg.wait_for_timeout(800)
        open_rows = js("[...document.querySelectorAll('#npResult > .np-list > li')].map(li => li.innerText.replace(/\\s+/g, ' '))")
        zone_row = [r for r in open_rows if "inside the declared application network" in r]
        port_row = [r for r in open_rows if "permitted application ports" in r]
        if not zone_row or P4_OK not in zone_row[0] or "Check" not in zone_row[0] and "Mismatch" not in zone_row[0]:
            fail("phase4-netplan", f"the rule outside the plan ({P4_OK}) must produce the 'inside the declared application network' warning: {open_rows}")
        if zone_row and (P4_MATCH in zone_row[0]):
            fail("phase4-netplan", f"the rule inside the plan ({P4_MATCH}) must not be named in the warning: {zone_row[0]}")
        if not port_row or P4_OK not in port_row[0] or P4_MATCH in port_row[0]:
            fail("phase4-netplan", f"the port warning must name {P4_OK} (port {up_port}) and not {P4_MATCH} (port 8080): {port_row}")
        if zone_row and not zone_row[0].rstrip().endswith("Fix") and "Declare" not in zone_row[0] and "Network plan" not in zone_row[0] and "plan" not in zone_row[0].lower():
            fail("phase4-netplan", f"the warning should carry a fix link: {zone_row[0]}")
        shot("phase4-netplan-warning.png")
        # the same finding through the API (the page shows only the first evidence line)
        ev = json.dumps([f for f in get("/api/netplan/get")["findings"] if f["id"] == "netplan.backend_zone"])
        if P4_MATCH + " -> 10.20.30.5" in ev:
            fail("phase4-netplan", "API: the matching rule is listed as outside the plan")
        if P4_OK + " -> 127.0.0.1" not in ev:
            fail("phase4-netplan", f"API: the mismatching rule is not in the evidence: {ev[:300]}")
        # make the plan learn about the real backends: the warnings go
        type_into("#npBackends", "127.0.0.1 1-65535")
        type_into("#npPorts", "8080")
        pg.click(".zx-savebar [data-zx-save]:visible")
        pg.wait_for_function("(() => { const r = document.getElementById('npResult'); return r && !/inside the declared application network/.test(r.querySelector(':scope > .np-list') ? r.querySelector(':scope > .np-list').innerText : ''); })()", timeout=10000)
        pg.wait_for_timeout(500)
        open_rows = js("[...document.querySelectorAll('#npResult > .np-list > li')].map(li => li.innerText.replace(/\\s+/g, ' '))")
        if any("inside the declared application network" in r or "permitted application ports" in r for r in open_rows):
            fail("phase4-netplan", f"declaring the backend must clear the zone and port warnings: {open_rows}")
        if "checks match the plan" not in js("document.getElementById('npResult').innerText"):
            fail("phase4-netplan", "the matching checks must be summarised")
        # a mismatch can also come back: an unrelated rule is added with a metadata address
        r = post("/api/proxy/add", {"type": "host", "rootname": "p4-meta.demo.test", "ep": "169.254.169.254:80", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
        if isinstance(r, dict) and r.get("error"):
            print("  (note) the API refused a metadata backend on its own:", str(r)[:120])
        else:
            pg.click("#npRecheck")
            pg.wait_for_function("document.getElementById('npResult').innerText.indexOf('metadata') >= 0 || document.getElementById('npResult').innerText.indexOf('link-local') >= 0", timeout=8000)
            post("/api/proxy/del", {"ep": "p4-meta.demo.test"})

        # ---------------------------------------------------------------- Network plan: policy export
        current["page"] = "phase4-netplan-export"
        pg.click("#npRecheck")
        if not js("document.getElementById('npDl').disabled"):
            fail("phase4-netplan", "Download must be disabled until the recommendations were generated")
        pg.click("#npGen")
        pg.wait_for_selector("#npMd:not([hidden])", timeout=8000)
        md = js("document.getElementById('npMd').value")
        if P4_DISCLAIMER not in md or "NOT APPLIED" not in md:
            fail("phase4-netplan", "the recommendations on screen lack the NOT APPLIED disclaimer")
        pg.locator("#npMd").scroll_into_view_if_needed()
        shot("phase4-netplan-policy.png")
        with pg.expect_download(timeout=10000) as dl:
            pg.click("#npDl")
        path = dl.value.path()
        text = open(path, encoding="utf-8").read()
        if dl.value.suggested_filename != "zoraxy-firewall-recommendations.md":
            fail("phase4-netplan", f"unexpected download name {dl.value.suggested_filename!r}")
        if P4_DISCLAIMER not in text or text.count("NOT APPLIED") < 2:
            fail("phase4-netplan", "the downloaded markdown must open and close with the NOT APPLIED disclaimer")
        if "Proxy DMZ" not in text or "10.20.30.0/24" not in text:
            fail("phase4-netplan", "the downloaded markdown does not contain the plan")
        for secret in ("PRIVATE KEY", "password", "sys.db"):
            if secret.lower() in text.lower():
                fail("phase4-netplan", f"the downloaded markdown contains {secret!r}")
        # the audit log knows about the change and the export
        au = json.dumps(get("/api/security/audit/list?limit=200"))
        if "netplan.set" not in au or "netplan.export" not in au:
            fail("phase4-netplan", "the security audit log must hold netplan.set and netplan.export")
        # CSRF: a POST from outside the page (no token) is refused and changes nothing
        import urllib.error
        import urllib.parse
        import urllib.request
        before = json.dumps(get("/api/netplan/get")["settings"], sort_keys=True)
        rq = urllib.request.Request(args.url + "/api/netplan/set", data=urllib.parse.urlencode({"config": json.dumps({"appPorts": ["1"]})}).encode(), method="POST")
        try:
            with urllib.request.urlopen(rq, timeout=8) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        if code != 403 and code != 401:
            fail("phase4-netplan-csrf", f"a POST without the CSRF token must be refused (403), got {code}")
        if json.dumps(get("/api/netplan/get")["settings"], sort_keys=True) != before:
            fail("phase4-netplan-csrf", "a POST without the CSRF token changed the plan")
        layout_matrix("netplan", "#npPage", "#npPage #npResult", "netplan")

        # ---------------------------------------------------------------- Config Tools: export
        current["page"] = "phase4-export"
        js("openTabById('utils')")
        pg.wait_for_timeout(800)
        pg.click("#utilities .menu .item[data-tab=utiltab4], .menu .item[data-tab=utiltab4]")
        pg.wait_for_timeout(300)
        pg.click("text=Open Config Tools")
        fr = None
        for _ in range(40):
            for f in pg.frames:
                if "configTools.html" in f.url:
                    fr = f
            if fr:
                break
            pg.wait_for_timeout(250)
        if fr is None:
            fail("phase4-export", "the Config Tools frame did not open")
            return
        fr.wait_for_selector("input[name=backupmode]", timeout=8000)
        pg.wait_for_timeout(800)
        labels = fr.evaluate("[...document.querySelectorAll('input[name=backupmode]')].map(i => [i.value, i.closest('.checkbox').innerText.replace(/\\s+/g, ' ')])")
        lab = dict((k, v) for k, v in labels)
        for mode in ("rules", "full"):
            if "contains secrets" not in lab.get(mode, ""):
                fail("phase4-export", f"the {mode} backup must be labelled as containing secrets: {lab.get(mode)!r}")
        if "no secrets" not in lab.get("shareable", ""):
            fail("phase4-export", f"the redacted export must be labelled: {lab.get('shareable')!r}")
        if "CONTAINS SECRETS" not in fr.evaluate("document.getElementById('exportNote').innerText"):
            fail("phase4-export", "the note under the default (full) backup must say it contains secrets")
        shot("phase4-export-full.png")

        def download_mode(mode):
            # the button uses window.open(): Playwright reports that download on the opener page
            fr.click("input[name=backupmode][value=%s] + label" % mode)
            pg.wait_for_timeout(300)
            try:
                with pg.expect_download(timeout=25000) as d:
                    fr.click("button[onclick='downloadConfig();']")
            except Exception:
                fail("phase4-export", f"{mode}: the Download button produced no file")
                return None, ""
            p = os.path.join(tmp, "dl-%s.zip" % mode)
            d.value.save_as(p)
            for pp in ctx.pages:
                if pp is not pg:
                    try:
                        pp.close()
                    except Exception:
                        pass
            return p, d.value.suggested_filename

        full_zip, full_name = download_mode("rules")
        with zipfile.ZipFile(full_zip) as z:
            full_has_key = any(b"PRIVATE KEY" in z.read(n) for n in z.namelist())
            full_names = z.namelist()
        if not full_has_key:
            fail("phase4-export", "the control failed: the full backup holds no private key, so the redaction check below proves nothing")
        if "manifest.json" in full_names:
            fail("phase4-export", "the default full backup must keep the historic layout (no manifest.json)")
        fr.click("input[name=backupmode][value=shareable] + label")
        pg.wait_for_timeout(300)
        if "no private keys" not in fr.evaluate("document.getElementById('exportNote').innerText").lower() and "safe to share" not in fr.evaluate("document.getElementById('exportNote').innerText").lower():
            fail("phase4-export", "the shareable note must say it is safe to share")
        shot("phase4-export-shareable.png")
        share_zip, share_name = download_mode("shareable")
        if "shareable" not in share_name:
            fail("phase4-export", f"the redacted export file name should say so: {share_name}")
        with zipfile.ZipFile(share_zip) as z:
            names = z.namelist()
            blob = b"".join(z.read(n) for n in names)
            if b"PRIVATE KEY" in blob or b"-----BEGIN" in blob.replace(b"-----BEGIN CERTIFICATE-----", b""):
                fail("phase4-export", "the shareable export contains private key material")
            if any(n.endswith(".key") for n in names):
                fail("phase4-export", f"the shareable export contains a .key file: {[n for n in names if n.endswith('.key')]}")
            if "manifest.json" not in names:
                fail("phase4-export", "the shareable export must carry manifest.json")
            else:
                mf = json.loads(z.read("manifest.json"))
                if mf.get("mode") != "shareable" or mf.get("schemaVersion") != 1:
                    fail("phase4-export", f"unexpected manifest: {str(mf)[:200]}")
            for secret in ("cluster.json", "notify.json", "sys.db", "basicauth_lists.json"):
                if any(n.endswith(secret) for n in names):
                    fail("phase4-export", f"the shareable export contains {secret}")
        print("  phase4 export: full backup", len(full_names), "files (private key present), shareable", len(names), "files (none)")

        # ---------------------------------------------------------------- Config Tools: dry run
        current["page"] = "phase4-import-check"
        before = tree_hash()
        # remove one rule so the archive differs from the live state: the diff has something to show
        post("/api/proxy/del", {"ep": P4_MATCH})
        before = tree_hash()
        fr.set_input_files("#fileInput", share_zip)
        if not fr.evaluate("document.getElementById('restoreBtn').disabled"):
            fail("phase4-import-check", "Restore must be disabled until a file was checked")
        fr.click("#checkBtn")
        fr.wait_for_function("document.getElementById('checkReport').innerText.indexOf('Would add') >= 0", timeout=20000)
        rep = fr.evaluate("document.getElementById('checkReport').innerText")
        if "not authenticity" not in rep:
            fail("phase4-import-check", f"a manifest-checked archive must say 'integrity checked, not authenticity': {rep[:200]!r}")
        if not re.search(r"Would add (\d+), replace (\d+), remove (\d+)", rep):
            fail("phase4-import-check", f"the report shows no add/replace/remove counts: {rep[:300]!r}")
        if P4_MATCH not in rep:
            fail("phase4-import-check", f"the dry run must list the rule the archive would add ({P4_MATCH}): {rep[:400]!r}")
        if fr.evaluate("document.getElementById('restoreBtn').disabled"):
            fail("phase4-import-check", "Restore must be enabled after a successful check")
        shot("phase4-import-check.png")
        if tree_hash() != before:
            fail("phase4-import-check", "the dry run changed the configuration")
        if any(h == P4_MATCH for h in [x.get("RootOrMatchingDomain") for x in get("/api/proxy/list?type=host")]):
            fail("phase4-import-check", "the dry run restored a rule")
        # an old export (no manifest) imports but is shown as unverified
        fr.set_input_files("#fileInput", full_zip)
        fr.click("#checkBtn")
        fr.wait_for_function("document.getElementById('checkReport').innerText.indexOf('Unverified') >= 0", timeout=20000)
        if tree_hash() != before:
            fail("phase4-import-check", "the dry run of an old export changed the configuration")
        shot("phase4-import-unverified.png")

        # corrupted archives: refused, clearly, nothing restorable
        current["page"] = "phase4-import-corrupt"
        allow.append(re.compile(r"400.*api/conf/importcheck|Bad Request.*api/conf/importcheck"))  # the refusals below are the point of this block
        raw = open(share_zip, "rb").read()
        bad = {}
        bad["truncated.zip"] = raw[: len(raw) // 2]
        bad["notazip.zip"] = b"this is not a zip file at all\n" * 20
        # a member changed after the manifest was written
        p = os.path.join(tmp, "tampered.zip")
        with zipfile.ZipFile(share_zip) as zin, zipfile.ZipFile(p, "w") as zout:
            done = False
            for n in zin.namelist():
                d = zin.read(n)
                if not done and "/proxy/" in "/" + n and n.endswith(".config"):
                    d = d.replace(b"{", b"{ ", 1)
                    done = True
                zout.writestr(n, d)
        bad["tampered.zip"] = open(p, "rb").read()
        p = os.path.join(tmp, "slip.zip")
        with zipfile.ZipFile(p, "w") as zout:
            zout.writestr("../../evil.txt", "x")
            zout.writestr("conf/proxy/a.config", "{}")
        bad["slip.zip"] = open(p, "rb").read()
        for fname, content in bad.items():
            fp = os.path.join(tmp, "bad-" + fname)
            open(fp, "wb").write(content)
            fr.set_input_files("#fileInput", fp)
            if not fr.evaluate("document.getElementById('restoreBtn').disabled"):
                fail("phase4-import-corrupt", f"{fname}: choosing a new file must disable Restore again")
            fr.click("#checkBtn")
            try:
                fr.wait_for_function("document.getElementById('checkReport').innerText.trim() !== ''", timeout=15000)
                fr.wait_for_selector("#checkReport .negative", timeout=3000)
            except Exception:
                fail("phase4-import-corrupt", f"{fname}: no error message was shown: {fr.evaluate('document.getElementById(\"checkReport\").innerText')[:160]!r}")
                continue
            msg = fr.evaluate("document.getElementById('checkReport').innerText")
            if not msg.startswith("Refused:") or len(msg) < 20:
                fail("phase4-import-corrupt", f"{fname}: the message is not clear enough: {msg!r}")
            if fr.evaluate("!document.getElementById('restoreBtn').disabled"):
                fail("phase4-import-corrupt", f"{fname}: Restore must stay disabled after a refused file")
            if "evil" in fname or "slip" in fname:
                if not re.search(r"unsafe|invalid|path|name|outside", msg, re.I):
                    fail("phase4-import-corrupt", f"{fname}: the message should name the unsafe entry: {msg!r}")
            if fname == "tampered.zip" and not re.search(r"checksum|sha|manifest|match|modified|changed", msg, re.I):
                fail("phase4-import-corrupt", f"{fname}: the message should say the checksum does not match: {msg!r}")
            print("  phase4 refused", fname, "->", msg[:110].replace("\n", " "))
            if fname == "truncated.zip":
                shot("phase4-import-corrupt.png")
        allow.pop()
        if tree_hash() != before:
            fail("phase4-import-corrupt", "a refused archive changed the configuration")
        # dark and phone layout of the frame content
        for dark, (w, h, tag) in ((True, (1366, 900, "desktop")), (False, (390, 844, "390"))):
            theme(dark)
            pg.set_viewport_size({"width": w, "height": h})
            pg.wait_for_timeout(600)
            bad_el = fr.evaluate("""() => { const W = document.documentElement.clientWidth, out = []; document.querySelectorAll('.ui.container *').forEach(e => { const r = e.getBoundingClientRect();
                if (r.width && (r.right > W + 1 || r.left < -1)) { for (let p = e.parentElement; p; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll') return; } out.push(e.tagName + ' ' + (e.id || e.className).toString().slice(0, 20) + ' ' + Math.round(r.right) + ' of ' + W); } }); return out.slice(0, 4); }""")
            if bad_el:
                fail("phase4-export-layout", f"{'dark' if dark else 'light'} {tag}: Config Tools content sticks out: {bad_el}")
            shot(f"phase4-config-tools-{'dark' if dark else 'light'}-{tag}.png")
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        js("hideSideWrapper()")
        pg.wait_for_timeout(500)

        # ---------------------------------------------------------------- Fleet: the Certificates scope asks first
        current["page"] = "phase4-fleet"
        js("openTabById('fleet')")
        pg.wait_for_timeout(1200)
        if pg.is_visible("#flBecomeHub"):
            pg.click("#flBecomeHub")
            confirm(True)
            saved["hub"] = True
        pg.wait_for_selector("#flHub", state="visible", timeout=10000)
        pg.click("#flTabs .item[data-tab=groups]")
        pg.wait_for_selector("#flGScopes input[value=certs]", state="attached", timeout=8000)
        if "private keys" not in js("document.getElementById('flGScopes').parentElement.innerText").lower():
            fail("phase4-fleet", "the Certificates scope must carry a standing note about private keys")
        type_into("#flGName", P4_GROUP)
        js("document.querySelectorAll('#flGScopes input:checked').forEach(i => i.click())")
        pg.click("#flGScopes input[value=certs] + label")
        pg.click("#flGSave")
        pg.wait_for_selector(".zx-dialog", timeout=5000)
        dlg = js("document.querySelector('.zx-dialog').innerText")
        if "private keys" not in dlg.lower():
            fail("phase4-fleet", f"the confirmation must say private keys are sent: {dlg[:200]!r}")
        shot("phase4-fleet-certs-dialog.png")
        confirm(False)
        ov = get("/api/fleet/hub/overview")
        if any(g.get("name") == P4_GROUP for g in ov.get("groups") or []):
            fail("phase4-fleet", "cancelling the dialog must not save the group")
        # the API refuses the same change without the acknowledgement
        r = post("/api/fleet/hub/groupSet", {"name": P4_GROUP, "scopes": "certs", "tags": "", "vars": ""})
        if not (isinstance(r, dict) and r.get("error")):
            fail("phase4-fleet", f"groupSet with the certs scope and no acknowledgement must be refused: {r}")
        pg.click("#flGSave")
        confirm(True)
        wait_for(lambda: any(g.get("name") == P4_GROUP and "certs" in ((g.get("sel") or {}).get("scopes") or []) for g in get("/api/fleet/hub/overview").get("groups") or []), 8, "the group with the certs scope to be saved after confirming")
        # captured keys: same dialog on the settings tab
        pg.click("#flTabs .item[data-tab=settings]")
        pg.wait_for_selector("#flSetCerts", state="attached", timeout=5000)
        if not js("document.getElementById('flSetCerts').checked"):
            pg.click("#flSetCerts + label")
            pg.click("#flSetSave")
            pg.wait_for_selector(".zx-dialog", timeout=5000)
            confirm(False)
            if get("/api/fleet/hub/overview").get("settings", {}).get("captureCerts"):
                fail("phase4-fleet", "cancelling the dialog must not turn on the capture of private keys")
            pg.click("#flSetCerts + label")
        # a saved certs group that stays on needs no new acknowledgement (existing setups keep working): save the same group again
        pg.click("#flTabs .item[data-tab=groups]")
        r = post("/api/fleet/hub/groupSet", {"name": P4_GROUP, "scopes": "certs,proxy", "tags": "", "vars": ""})
        if isinstance(r, dict) and r.get("error"):
            fail("phase4-fleet", f"re-saving a group that already has the certs scope must not ask again: {r}")
        theme(True)
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(600)
        check_horizontal(pg, "fleet groups 390")
        shot("phase4-fleet-groups-dark-390.png")
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)
    finally:
        # ---------------------------------------------------------------- cleanup: nothing of this scenario stays on the instance
        current["page"] = "phase4-cleanup"
        try:
            theme(False)
            pg.set_viewport_size({"width": 1366, "height": 900})
            js("typeof hideSideWrapper === 'function' && hideSideWrapper()")
            js("delete document.visibilityState")
        except Exception:
            pass
        for h in P4_RULES + ("p4-meta.demo.test",):
            post("/api/proxy/del", {"ep": h})
        post("/api/cert/delete", {"domain": P4_CERT})
        post("/api/netplan/set", {"config": "{}"})
        try:
            if saved["hub"]:
                post("/api/fleet/hub/groupDelete", {"name": P4_GROUP})
                js("openTabById('fleet')")
                pg.wait_for_timeout(800)
                pg.click("#flTabs .item[data-tab=settings]")
                pg.click("#flBecomeStandalone")
                confirm(True)
                pg.wait_for_selector("#flStandalone", state="visible", timeout=8000)
        except Exception as e:
            fail("phase4-cleanup", f"could not return the instance to standalone: {e}")
        try:
            upstream.shutdown()
            upstream.server_close()
        except Exception:
            pass
        if get("/api/netplan/get").get("declared"):
            fail("phase4-cleanup", "the network plan was not cleared")
