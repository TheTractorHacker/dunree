"""Smoke scenario of the fallback-certificate diagnostics (Tools > Encrypted Client Hello card "Fallback certificate served for these
names", the info line under "Certificate for each hostname", GET /api/ech/fallbacks). exec()'d by smoke.py (namespace: fail, current,
args, os, re); run alone with --ech-fallback-only. Needs the instance's HTTPS proxy port at UI port + 1 (as tools/ui-smoke/run.sh starts
it) and openssl on the PATH. ECH stays OFF: that is the situation of a browser using an ECH config of another provider.

Checks: with no such handshake the card says "Nothing has reached the fallback certificate" and the TLS tab shows no info line; REAL TLS
handshakes with SNI cloudflare-ech.com (python ssl and openssl s_client), an unknown name, a name that is a proxy rule (never listed) and
no SNI (openssl -noservername) are classified (ECH outer name of another provider / unknown / no SNI); the certificate served for every
name is unchanged by the diagnostics (the rule host gets the self-signed localhost fallback like any other name here, the outer name gets
the same one); the card shows each row with class, count, last seen and a next step; the TLS tab shows the one info line with a link to
the ECH page. Part 5, the opt-in "Reject handshakes for unknown names" switch on the same card: off by default, the confirmation can be
cancelled, once on an unknown name and a handshake without SNI are refused with the TLS alert unrecognized_name while the rule host keeps
its certificate (and, with a rule for 127.0.0.1, a handshake without SNI on that address is answered again), the card says how many were refused, and switching off restores the fallback certificate. Part 6, the opt-in "Write the
ECH result to the request log" box: a real HTTPS request before it has no ECH field in the request log, one after it has
the result and the outer SNI ("plain outer=<the rule host>" for a TLS 1.2 client). Screenshots (light, dark, 390px) are written to --out."""

import socket
import ssl
import subprocess

EF_HOST = "ech-fb-rule.smoke.test"


def ech_fallback_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def shot(name, sel):
        pg.locator(sel).screenshot(path=os.path.join(args.out, name))

    port = int(args.url.rsplit(":", 1)[1].split("/")[0]) + 1
    current["page"] = "ech-fallback"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    post("/api/proxy/del", {"ep": EF_HOST})
    if js("fetch('/api/cert/tls').then(r => r.json())") is not True:
        post("/api/cert/tls", {"set": "true"})
        pg.wait_for_timeout(1500)
    r = post("/api/proxy/add", {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "cred": "", "rootname": EF_HOST})
    if isinstance(r, dict) and r.get("error"):
        fail("ech-fallback", f"could not create the rule: {r}")

    def served(sni):
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=sni) as t:
                return ssl.DER_cert_to_PEM_cert(t.getpeercert(True)).strip()

    def openssl_served(args_):
        p = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}"] + args_ + ["-showcerts"], input=b"", capture_output=True, timeout=15)
        m = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", p.stdout, re.S)
        return m.group(0).decode().strip() if m else None

    def table():
        return js("fetch('/api/ech/fallbacks').then(r => r.json())")

    def open_ech():
        js("openTabById('ech')")
        pg.wait_for_selector("#echFbCard", timeout=8000)
        pg.wait_for_timeout(900)

    def open_tls_tab():
        js("openTabById('httprp')")
        pg.wait_for_timeout(800)
        js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", EF_HOST)
        pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=8000)
        pg.wait_for_timeout(900)
        pg.click("#hrpMode [data-value='advanced']")  # the per-hostname table is an Advanced card
        pg.wait_for_timeout(500)
        js("document.getElementById('hrpTab-tls').click()")
        pg.wait_for_timeout(900)

    # ---- 1. empty state (nothing probed yet)
    t0 = table()
    if t0.get("Entries"):
        fail("ech-fallback", f"the table must start empty on a fresh instance, got {t0}")
    open_ech()
    if "Nothing has reached the fallback certificate" not in js("document.getElementById('echFbEmpty').innerText"):
        fail("ech-fallback", "the empty state text is missing")
    shot("ech-fallback-empty-light.png", "#echFbCard")
    open_tls_tab()
    if js("$('#httprpEditModalWrapper .hrp-echnote').is(':visible')"):
        fail("ech-fallback", "the TLS info line must be hidden while no foreign ECH name was seen")
    if js("(() => { const e = document.querySelector('#httprpEditModalWrapper .hrp-echnote'); return e.getBoundingClientRect().height; })()") > 1:
        fail("ech-fallback", "the hidden info line must not use any space")

    # ---- 2. real handshakes
    before_rule = served(EF_HOST)  # a rule host: never listed, whatever certificate it gets
    outer = served("cloudflare-ech.com")
    unknown = served("scanner.smoke.test")
    for _ in range(2):
        served("cloudflare-ech.com")
    o2 = openssl_served(["-servername", "cloudflare-ech.com"])
    o3 = openssl_served(["-noservername"])
    if not o2 or not o3:
        fail("ech-fallback", "openssl s_client could not connect")
    if outer != unknown or o2 != outer or o3 != outer:
        fail("ech-fallback", "the certificate served for the outer name, an unknown name and no SNI must be the same fallback certificate")
    if served("cloudflare-ech.com") != outer or served(EF_HOST) != before_rule:
        fail("ech-fallback", "the served certificates changed between handshakes")
    t = table()
    ents = {e["Name"]: e for e in t["Entries"]}
    want = {"cloudflare-ech.com": ("foreign-ech", 5), "scanner.smoke.test": ("unknown", 1), "": ("no-sni", 1)}
    for n, (cls, cnt) in want.items():
        e = ents.get(n)
        if not e or e["Class"] != cls or e["Count"] != cnt or e["LastSeen"] < e["FirstSeen"]:
            fail("ech-fallback", f"entry {n!r}: want {cls} x{cnt}, got {e}")
    if EF_HOST in ents:
        fail("ech-fallback", "a name that matches a proxy rule must not be listed")
    if not t["HasForeignECH"] or t["Entries"][0]["Name"] != "cloudflare-ech.com":
        fail("ech-fallback", "the foreign ECH name must be flagged and listed first")

    # ---- 3. the card
    open_ech()
    txt = js("document.getElementById('echFbCard').innerText")
    for s in ("Fallback certificate served for these names", "ECH outer name of another provider", "5 handshakes", "last seen", "cloudflare-ech.com",
              "Unknown host / scanner / IP access", "No SNI", "override or block the HTTPS record"):
        if s not in txt:
            fail("ech-fallback", f"the card lacks {s!r}: {txt!r}")
    if js("document.getElementById('echFbEmpty').offsetParent !== null"):
        fail("ech-fallback", "the empty state must be hidden when there are rows")
    shot("ech-fallback-card-light.png", "#echFbCard")
    theme(True)
    shot("ech-fallback-card-dark.png", "#echFbCard")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(400)
    shot("ech-fallback-card-390.png", "#echFbCard")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("ech-fallback", "the ECH page scrolls horizontally at 390px")
    if js("(() => { const c = document.getElementById('echFbCard'); return c.scrollWidth > c.clientWidth + 1; })()"):
        fail("ech-fallback", "the card overflows its box at 390px")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)

    # ---- 4. the TLS tab info line
    open_tls_tab()
    if not js("$('#httprpEditModalWrapper .hrp-echnote').is(':visible')"):
        fail("ech-fallback", "the info line must show once a foreign ECH name was seen")
    note = js("document.querySelector('#httprpEditModalWrapper .hrp-echnote').innerText")
    if "name you cannot choose a certificate for" not in note or "Encrypted Client Hello" not in note:
        fail("ech-fallback", f"info line text: {note!r}")
    if js("document.querySelectorAll('#httprpEditModalWrapper .hrp-echnote').length") != 1:
        fail("ech-fallback", "there must be exactly one info line")
    shot("ech-fallback-tlsline-light.png", "#httprpEditModalWrapper .hrp-card[data-hrp-card='certs']")
    theme(True)
    shot("ech-fallback-tlsline-dark.png", "#httprpEditModalWrapper .hrp-card[data-hrp-card='certs']")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(400)
    shot("ech-fallback-tlsline-390.png", "#httprpEditModalWrapper .hrp-card[data-hrp-card='certs']")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("ech-fallback", "the TLS tab scrolls horizontally at 390px")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    # the link opens the ECH page
    js("document.querySelector('#httprpEditModalWrapper .hrp-echnote a').click()")
    pg.wait_for_timeout(900)
    if js("location.hash") != "#ech":
        fail("ech-fallback", f"the link must open the ECH page, hash is {js('location.hash')!r}")

    # ---- 5. reject handshakes for unknown names (opt-in)
    def reject_state():
        return js("fetch('/api/ech/unknownsni').then(r => r.json())")

    def refused(sni):
        try:
            served(sni)
        except ssl.SSLError as e:
            return "UNRECOGNIZED_NAME" in str(e).upper().replace(" ", "_")
        return False

    open_ech()
    if reject_state()["Reject"] or js("document.getElementById('echRejectInput').checked"):
        fail("ech-reject", "rejecting unknown names must be off by default")
    if not js("document.getElementById('echRejectState').hidden"):
        fail("ech-reject", "the state line must be hidden while the option is off")
    pg.click("#echReject label")
    pg.wait_for_selector(".zx-dialog--danger", timeout=4000)
    dlg = pg.inner_text(".zx-dialog--danger")
    if "Reject handshakes for unknown names?" not in dlg or "IP address" not in dlg or "own addresses" not in dlg:
        fail("ech-reject", f"confirmation text: {dlg!r}")
    shot("ech-reject-confirm-light.png", ".zx-dialog--danger")
    pg.click(".zx-dialog--danger [data-zx-cancel]")
    pg.wait_for_timeout(700)
    if reject_state()["Reject"] or js("document.getElementById('echRejectInput').checked"):
        fail("ech-reject", "cancelling the confirmation must leave the option off")
    if served("scanner.smoke.test") != outer:
        fail("ech-reject", "after a cancelled confirmation unknown names must still get the fallback certificate")
    pg.click("#echReject label")
    pg.wait_for_selector(".zx-dialog--danger", timeout=4000)
    pg.click(".zx-dialog--danger [data-zx-ok]")
    pg.wait_for_timeout(900)
    if not reject_state()["Reject"]:
        fail("ech-reject", "confirming must switch the option on")
    if not refused("scanner.smoke.test"):
        fail("ech-reject", "an unknown name must be refused with the unrecognized_name alert")
    if openssl_served(["-noservername"]) is not None:
        fail("ech-reject", "a handshake without SNI must not get a certificate")
    if served(EF_HOST) != before_rule:
        fail("ech-reject", "the name of a proxy rule must keep its certificate while rejecting is on")
    if reject_state()["Rejected"] != 2:
        fail("ech-reject", f"two handshakes were refused, the counter says {reject_state()}")
    # a rule keyed on the IP address the connection arrives on: clients send no SNI for an IP address, it must keep working
    r = post("/api/proxy/add", {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "cred": "", "rootname": "127.0.0.1"})
    if isinstance(r, dict) and r.get("error"):
        fail("ech-reject", f"could not create the IP address rule: {r}")
    pg.wait_for_timeout(500)
    if openssl_served(["-noservername"]) is None:
        fail("ech-reject", "a proxy rule for the IP address of the listener must keep working without SNI while rejecting is on")
    post("/api/proxy/del", {"ep": "127.0.0.1"})
    if reject_state()["Rejected"] != 2:
        fail("ech-reject", f"the IP address rule must not count as refused: {reject_state()}")
    open_ech()
    txt = js("document.getElementById('echRejectBox').innerText")
    if "Rejecting is on: 2 handshake(s) refused" not in txt or not js("document.getElementById('echRejectInput').checked"):
        fail("ech-reject", f"the card must show the state and the count: {txt!r}")
    pg.locator("#echRejectBox").scroll_into_view_if_needed()
    shot("ech-reject-on-light.png", "#echFbCard")
    theme(True)
    shot("ech-reject-on-dark.png", "#echFbCard")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(400)
    shot("ech-reject-on-390.png", "#echFbCard")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1") or js("(() => { const c = document.getElementById('echFbCard'); return c.scrollWidth > c.clientWidth + 1; })()"):
        fail("ech-reject", "the card overflows at 390px with the reject switch")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    pg.click("#echReject label")  # switching off needs no confirmation
    pg.wait_for_timeout(900)
    if pg.locator(".zx-dialog--danger").count() or reject_state()["Reject"]:
        fail("ech-reject", "switching off must apply at once, without a confirmation")
    if served("scanner.smoke.test") != outer:
        fail("ech-reject", "after switching off unknown names must get the fallback certificate again")

    # ---- 6. ECH result in the request log (opt-in)
    def https_get(path, tls12=False):
        c = ssl.create_default_context()
        if tls12:
            c.maximum_version = ssl.TLSVersion.TLSv1_2  # ECH (and its placeholder) only exists in TLS 1.3
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=EF_HOST) as t:
                t.sendall(f"GET {path} HTTP/1.1\r\nHost: {EF_HOST}\r\nUser-Agent: ech-smoke\r\nConnection: close\r\n\r\n".encode())
                try:
                    while t.recv(4096):
                        pass
                except (ssl.SSLError, OSError):
                    pass

    def logged(path):  # the request log entry of a path, as the log search API parses the line
        for _ in range(20):
            res = js("fetch('/api/log/search?limit=500').then(r => r.json())")
            for e in res.get("entries") or []:
                if e.get("uri") == path:
                    return e
            pg.wait_for_timeout(250)
        return None

    open_ech()
    if js("document.getElementById('echLogReqInput').checked") or js("fetch('/api/ech/status').then(r => r.json())")["Settings"].get("LogRequests"):
        fail("ech-log", "the request log option must be off by default")
    https_get("/ech-smoke-before")
    line = logged("/ech-smoke-before")
    if not line or line.get("ech") or line.get("useragent") != "ech-smoke":
        fail("ech-log", f"with the option off the log line must not carry an ECH field: {line!r}")
    pg.click("#echLogReq label")
    pg.locator("#echLogReq").scroll_into_view_if_needed()
    shot("ech-logoption-light.png", "#echLogReq >> xpath=ancestor::section[1]")
    theme(True)
    shot("ech-logoption-dark.png", "#echLogReq >> xpath=ancestor::section[1]")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(400)
    shot("ech-logoption-390.png", "#echLogReq >> xpath=ancestor::section[1]")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("ech-log", "the ECH page scrolls horizontally at 390px with the log option")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    pg.click("#echSave")
    pg.wait_for_timeout(1200)
    st = js("fetch('/api/ech/status').then(r => r.json())")
    if not st["Settings"].get("LogRequests") or st["Settings"]["Enabled"]:
        fail("ech-log", f"saving must store the log option and leave ECH off: {st['Settings']}")
    https_get("/ech-smoke-after")
    line = logged("/ech-smoke-after")
    # a TLS 1.3 client may send an ECH placeholder (GREASE) depending on the local TLS library: "offered" or "plain"
    if not line or line.get("ech") not in (f"plain outer={EF_HOST}", f"offered outer={EF_HOST}") or line.get("useragent") != "ech-smoke" or line.get("method") != "GET":
        fail("ech-log", f"the log line must carry the ECH result and the outer SNI: {line!r}")
    https_get("/ech-smoke-tls12", tls12=True)
    line = logged("/ech-smoke-tls12")
    if not line or line.get("ech") != f"plain outer={EF_HOST}":
        fail("ech-log", f"a TLS 1.2 request must be logged as plain with its SNI: {line!r}")
    st = js("fetch('/api/ech/status').then(r => r.json())")
    if st["Outcomes"]["Plain"] < 1 or st["Outcomes"]["Accepted"] != 0:
        fail("ech-log", f"the counter by outcome must count the plain request: {st['Outcomes']}")
    pg.click("#echRefresh")
    pg.wait_for_timeout(900)
    more = js("(() => { document.querySelector('#echStateCard details').open = true; return document.getElementById('echFactsMore').innerText; })()")
    for s_ in ("Requests with ECH offered, not decrypted", "Requests without ECH", "ECH result in the request log"):
        if s_ not in more:
            fail("ech-log", f"the state card lacks {s_!r}: {more!r}")
    shown = js("""(() => { const o = {}; document.querySelectorAll('#echFactsMore .echFact').forEach(f => { o[f.querySelector('.l').textContent] = f.querySelector('.v').textContent; }); return o; })()""")
    if shown.get("Requests without ECH") != str(st["Outcomes"]["Plain"]) or shown.get("Requests with ECH offered, not decrypted") != str(st["Outcomes"]["Offered"]) or shown.get("ECH result in the request log") != "On":
        fail("ech-log", f"the state card must show the counters of the API {st['Outcomes']}: {shown}")
    shot("ech-outcomes-light.png", "#echStateCard")
    theme(True)
    shot("ech-outcomes-dark.png", "#echStateCard")
    theme(False)
    pg.click("#echLogReq label")
    pg.click("#echSave")
    pg.wait_for_timeout(1200)
    if js("fetch('/api/ech/status').then(r => r.json())")["Settings"].get("LogRequests"):
        fail("ech-log", "the option must switch off again")
    https_get("/ech-smoke-off")
    line = logged("/ech-smoke-off")
    if not line or line.get("ech"):
        fail("ech-log", f"after switching off the line format must be the old one: {line!r}")

    post("/api/proxy/del", {"ep": EF_HOST})
    pg.set_viewport_size({"width": 1366, "height": 800})
