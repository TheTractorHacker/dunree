"""Smoke scenario of the "HTTPS certificate" field of the New proxy rule dialog. exec()'d by smoke.py (namespace: fail, current, args,
os, re); run alone with --newrule-cert-only. Needs the instance's proxy port at UI port + 1 (as tools/ui-smoke/run.sh starts it) and
openssl on the PATH. It makes its own certificates and rules and removes them again.

Checks: the empty-list hint; the options (names, expiry) and the grouping by the typed hostname; the mismatch warning (does not block);
the rule is created with the choice (one request: TlsOptions.PreferredCertificate for the host and every alias, SNI matching off for
this rule only); the success toast does not offer "Create certificate for this host"; a rule created without a choice keeps the
default TLS options; an unknown certificate name creates nothing; and a REAL TLS handshake with SNI returns the chosen certificate.
Part 7 (issue #91): with a default DNS credential profile the New site page shows an unticked "Use DNS challenge (default profile: NAME)"
option and the dialog's toast a second action; the certificate request then carries dns=true (the request is answered by the test, no
CA or DNS provider is contacted), and without a default profile nothing changes.
Screenshots (light, dark, 390px) are written to --out. It needs a store without certificates (a fresh instance), so it only runs
with --newrule-cert-only, not in the full run."""

import socket
import ssl
import subprocess
import tempfile

NRC_HOST = "nrc-pick.smoke.test"
NRC_ALIAS = "nrc-alias.smoke.test"
NRC_PLAIN = "nrc-plain.smoke.test"
NRC_CERTS = ["nrc-cert-a", "nrc-cert-b", "nrc-cert-c"]
NRC_DNS = ["nrc-dns%d.smoke.test" % i for i in range(8)]


def newrule_cert_ui(pg, ctx):
    tmp = tempfile.mkdtemp()

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def shot(name, sel="#newRuleModal"):
        pg.locator(sel).screenshot(path=os.path.join(args.out, name))

    def make_cert(name, sans):
        key, crt = os.path.join(tmp, name + ".key"), os.path.join(tmp, name + ".pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=" + name,
                        "-addext", "subjectAltName=" + ",".join("DNS:" + s for s in sans)], check=True, capture_output=True)
        return crt, key

    def upload(name, crt, key):
        pem, pri = open(crt).read(), open(key).read()
        return js("""async ([cn, pem, key]) => {
            const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content, out = [];
            for (const [kt, body] of [['pub', pem], ['pri', key]]) {
                const f = new FormData(); f.append('file', new Blob([body]), kt);
                const r = await fetch('/api/cert/upload?ktype=' + kt + '&domain=' + cn, {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f});
                out.push(r.status);
            }
            return out; }""", [name, pem, pri])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def open_dialog(**opts):
        js("o => openNewRuleDialog(o)", opts)
        pg.wait_for_selector("#newRuleModal.visible", timeout=8000)
        pg.wait_for_timeout(700)

    def close_dialog():
        pg.click("#nrCancel")
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=8000)

    def hint():
        return js("document.getElementById('nrCertHint').innerText")

    def options():
        return js("[...document.querySelectorAll('#nrCert option')].map(o => [o.value, o.textContent])")

    def rule(host):
        for r in js("fetch('/api/proxy/list?type=host').then(r => r.json())"):
            if r["RootOrMatchingDomain"] == host:
                return r
        return None

    current["page"] = "newrule-cert"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    for h in (NRC_HOST, NRC_PLAIN):
        post("/api/proxy/del", {"ep": h})
    for n in NRC_CERTS:
        js("async n => { await fetch('/api/cert/delete?domain=' + n, {method: 'POST', headers: {'X-CSRF-Token': document.querySelector('meta[name=\"zoraxy.csrf.Token\"]').content}}); }", n)

    # ---- 1. no certificates: the field is there, says how to get one, and the form still works
    pre = js("fetch('/api/cert/list').then(r => r.json())")
    if not pre:  # (after other scenarios the store may hold certificates: then this part is skipped)
        open_dialog()
        if not pg.is_visible("#nrCert"):
            fail("newrule-cert", "the certificate field must be visible without opening More options")
        if options() != [["", "Automatic (match by hostname)"]]:
            fail("newrule-cert", f"with no certificates only Automatic is offered, got {options()}")
        if "No certificates yet" not in hint() or "Certificates page" not in hint():
            fail("newrule-cert", f"the empty list must explain how to get a certificate, got {hint()!r}")
        shot("newrule-cert-empty-light.png")
        theme(True)
        shot("newrule-cert-empty-dark.png")
        theme(False)
        close_dialog()

    # ---- 2. certificates: a and b cover the host (b also an alias), c does not
    files = {
        "nrc-cert-a": make_cert("nrc-cert-a", [NRC_HOST]),
        "nrc-cert-b": make_cert("nrc-cert-b", [NRC_HOST, NRC_ALIAS]),
        "nrc-cert-c": make_cert("nrc-cert-c", ["unrelated.smoke.test"]),
    }
    for n, (crt, key) in files.items():
        if upload(n, crt, key) != [200, 200]:
            fail("newrule-cert", f"could not upload {n}")
    open_dialog()
    opts = options()
    if [o[0] for o in opts] != [""] + NRC_CERTS:
        fail("newrule-cert", f"the field must list Automatic and every certificate, got {opts}")
    if not all("expires 20" in o[1] for o in opts[1:]):
        fail("newrule-cert", f"each option must show the expiry, got {opts}")
    if js("document.getElementById('nrCert').value") != "":
        fail("newrule-cert", "the default choice must be Automatic")
    if "matches the hostname" not in hint():
        fail("newrule-cert", f"the automatic hint is missing: {hint()!r}")

    pg.fill("#nrDomain", NRC_HOST + ", " + NRC_ALIAS)
    pg.wait_for_timeout(600)
    groups = js("[...document.querySelectorAll('#nrCert optgroup')].map(g => [g.label, [...g.querySelectorAll('option')].map(o => o.value)])")
    if len(groups) != 2 or groups[0][1] != ["nrc-cert-b"] or sorted(groups[1][1]) != ["nrc-cert-a", "nrc-cert-c"]:
        fail("newrule-cert", f"typing the hostnames must group the certificates that cover all of them first, got {groups}")
    pg.select_option("#nrCert", "nrc-cert-c")
    pg.wait_for_timeout(200)
    if "does not cover" not in hint() or not pg.is_visible("#nrCert"):
        fail("newrule-cert", f"a certificate that does not cover the hostname must warn, got {hint()!r}")
    if js("document.getElementById('nrCreate').disabled") or "disabled" in (js("document.getElementById('nrCreate').className") or ""):
        fail("newrule-cert", "the mismatch warning must not block creating the rule")
    pg.fill("#nrUpstream", "127.0.0.1:9")
    shot("newrule-cert-mismatch-light.png")
    theme(True)
    shot("newrule-cert-mismatch-dark.png")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(300)
    shot("newrule-cert-mismatch-390.png")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("newrule-cert", "the dialog scrolls horizontally at 390px")
    pg.select_option("#nrCert", "nrc-cert-b")
    pg.wait_for_timeout(200)
    h = hint()
    if "does not cover" in h or NRC_HOST not in h or "turn off automatic certificate matching" not in h:
        fail("newrule-cert", f"a covering certificate must list its names, say what changes and not warn, got {h!r}")
    shot("newrule-cert-chosen-390.png")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    shot("newrule-cert-chosen-dark.png")
    theme(False)
    shot("newrule-cert-chosen-light.png")

    # keyboard: the select takes the arrow keys
    pg.focus("#nrCert")
    pg.keyboard.press("Home")
    if js("document.getElementById('nrCert').value") != "":
        fail("newrule-cert", "the field is not operable with the keyboard")
    pg.select_option("#nrCert", "nrc-cert-b")

    # ---- 3. create with the choice: one request, the toast does not offer another certificate
    reqs = []
    pg.on("request", lambda r: reqs.append(r) if "/api/proxy/add" in r.url else None)
    pg.click("#nrCreate")
    pg.wait_for_selector("#nrToast.show", timeout=10000)
    toast = js("document.getElementById('nrToast').innerText")
    if NRC_HOST not in toast or "nrc-cert-b" not in toast:
        fail("newrule-cert", f"the success toast must name the certificate, got {toast!r}")
    if "Create certificate" in toast:
        fail("newrule-cert", "the toast must not offer to create a certificate when one was chosen")
    if len(reqs) != 1 or "certificate=nrc-cert-b" not in (reqs[0].post_data or ""):
        fail("newrule-cert", f"creation must be one request carrying the certificate, got {len(reqs)}")
    r = rule(NRC_HOST)
    to = (r or {}).get("TlsOptions") or {}
    pref = to.get("PreferredCertificate") or {}
    if pref.get(NRC_HOST) != "nrc-cert-b" or pref.get(NRC_ALIAS) != "nrc-cert-b" or not to.get("DisableSNI"):
        fail("newrule-cert", f"the rule must store the choice for the host and its alias and turn SNI matching off, got {to}")

    # ---- 4. a REAL handshake with SNI returns the chosen certificate
    if js("fetch('/api/cert/tls').then(r => r.json())") is not True:
        post("/api/cert/tls", {"set": "true"})
        pg.wait_for_timeout(1500)
    port = int(args.url.rsplit(":", 1)[1].split("/")[0]) + 1

    def served(sni):
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=sni) as t:
                return ssl.DER_cert_to_PEM_cert(t.getpeercert(True)).strip()

    want_b = open(files["nrc-cert-b"][0]).read().strip()
    if served(NRC_HOST) != want_b or served(NRC_ALIAS) != want_b:
        fail("newrule-cert", "the TLS handshake did not return the chosen certificate for the host and its alias")

    # ---- 5. a rule created without a choice: default TLS options, the certificate offer stays
    open_dialog()
    pg.fill("#nrDomain", NRC_PLAIN)
    pg.fill("#nrUpstream", "127.0.0.1:9")
    pg.wait_for_timeout(300)
    pg.click("#nrCreate")
    # (the toast of part 3 can still be up: wait for the one of this rule)
    pg.wait_for_function("h => { const t = document.getElementById('nrToast'); return t && t.classList.contains('show') && t.innerText.includes(h); }", arg=NRC_PLAIN, timeout=10000)
    to = (rule(NRC_PLAIN) or {}).get("TlsOptions") or {}
    if to.get("DisableSNI") or to.get("PreferredCertificate"):
        fail("newrule-cert", f"a rule created without a choice must keep the default TLS options, got {to}")
    if "nrc-cert" in js("document.getElementById('nrToast').innerText"):
        fail("newrule-cert", "the toast of an automatic rule must not name a certificate")

    # ---- 6. an unknown certificate name creates nothing
    bad = post("/api/proxy/add", {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false",
                                  "cred": "", "rootname": "nrc-bad.smoke.test", "certificate": "does-not-exist"})
    if not (isinstance(bad, dict) and bad.get("error")) or rule("nrc-bad.smoke.test"):
        fail("newrule-cert", f"an unknown certificate must be refused and nothing created, got {bad!r}")

    # ---- 7. DNS challenge with the default DNS credential profile (issue #91). The certificate request is answered by the test
    # (page.route), so no CA and no DNS provider is contacted; what is checked is the offer and the dns flag of the request.
    acme_reqs = []

    def fake_acme(route):
        acme_reqs.append(route.request.url)
        route.fulfill(status=200, content_type="application/json", body='{"error":"smoke: no CA in this test"}')

    pg.route("**/api/acme/obtainCert*", fake_acme)
    pg.route("**/api/acme/autoRenew/email", lambda route: route.fulfill(status=200, content_type="application/json", body='"smoke@example.test"'))
    js("openTabById('cert')")
    pg.wait_for_function("typeof obtainCertificate === 'function'", timeout=10000)

    def dns_state():
        return js("fetch('/api/acme/profiles/dns').then(r => r.json())")

    def last_dns():
        for _ in range(40):
            if acme_reqs:
                break
            pg.wait_for_timeout(100)
        if not acme_reqs:
            return None
        u = acme_reqs.pop()
        del acme_reqs[:]
        return re.search(r"[?&]dns=(true|false)", u).group(1), u

    def create_dialog(host):
        post("/api/proxy/del", {"ep": host})
        open_dialog()
        pg.fill("#nrDomain", host)
        pg.fill("#nrUpstream", "127.0.0.1:9")
        pg.wait_for_timeout(300)
        pg.click("#nrCreate")
        pg.wait_for_function("h => { const t = document.getElementById('nrToast'); return t && t.classList.contains('show') && t.innerText.includes(h); }", arg=host, timeout=10000)

    def create_page(host):
        post("/api/proxy/del", {"ep": host})
        js("openTabById('rules')")
        pg.wait_for_selector("#rulesCreateBtn", state="visible", timeout=10000)
        pg.fill("#rootname", host)
        pg.fill("#proxyDomain", "127.0.0.1:9")
        pg.click("#rulesCreateBtn")
        pg.wait_for_selector("#rulesResult:not([hidden])", timeout=10000)
        pg.wait_for_selector("#rulesResultCert:not([hidden])", timeout=5000)
        pg.wait_for_timeout(500)

    st0 = dns_state()
    if st0.get("default"):
        fail("newrule-dns", "this part needs an instance without a default DNS profile")
    # 7a. no default profile: nothing new is offered, and the plain request is the HTTP challenge as before
    create_dialog(NRC_DNS[0])
    toast = js("document.getElementById('nrToast').innerText")
    if "Create certificate for this host" not in toast or "DNS challenge" in toast or pg.locator("#nrToastDns").count():
        fail("newrule-dns", f"without a default DNS profile the toast must offer only the plain request, got {toast!r}")
    pg.click("#nrToast button:has-text('Create certificate for this host')")
    got = last_dns()
    if not got or got[0] != "false":
        fail("newrule-dns", f"the plain request must stay dns=false, got {got}")
    create_page(NRC_DNS[1])
    if pg.is_visible("#rulesResultDnsRow") or pg.is_visible("#rulesResultDnsHint"):
        fail("newrule-dns", "without a default DNS profile the New site page must not offer the DNS challenge")
    pg.click("#rulesResultCert")
    got = last_dns()
    if not got or got[0] != "false":
        fail("newrule-dns", f"the plain request of the New site page must stay dns=false, got {got}")

    # 7b. a saved profile that is NOT the default changes nothing; as the default it is offered by name
    saved = post("/api/acme/profiles/dns", {"op": "save", "name": "nrc-dns-profile", "provider": "cloudflare", "credentials": '{"AuthToken":"nrc-fake-token"}'})
    pid_ = (saved or {}).get("id")
    if not pid_:
        fail("newrule-dns", f"could not save the test DNS profile: {saved!r}")
    create_page(NRC_DNS[2])
    if pg.is_visible("#rulesResultDnsRow"):
        fail("newrule-dns", "a profile that is not the default must not be offered")
    post("/api/acme/profiles/dns", {"op": "setDefault", "id": pid_})

    create_page(NRC_DNS[3])
    if not pg.is_visible("#rulesResultDnsRow") or not pg.is_visible("#rulesResultDnsHint"):
        fail("newrule-dns", "with a default DNS profile the New site page must offer the DNS challenge")
    label = js("document.getElementById('rulesResultDnsRow').innerText")
    if "Use DNS challenge" not in label or "nrc-dns-profile" not in label:
        fail("newrule-dns", f"the option must name the default profile, got {label!r}")
    if js("document.getElementById('rulesResultDns').checked"):
        fail("newrule-dns", "the DNS challenge must not be ticked for the user")
    if "nrc-fake-token" in js("document.documentElement.innerHTML"):
        fail("newrule-dns", "the credential of the profile reached the page")
    # the option changes what the button does, so it comes first: in the document, on screen and in the tab order
    order = js("""(() => { const c = document.getElementById('rulesResultDns'), b = document.getElementById('rulesResultCert');
        return [!!(c.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING), c.getBoundingClientRect().bottom <= b.getBoundingClientRect().top + 1]; })()""")
    if order != [True, True]:
        fail("newrule-dns", f"the DNS option must come before 'Request a certificate' (document order, above it): {order}")
    pg.focus("#rulesResultDns")
    seen = []
    for _ in range(4):
        pg.keyboard.press("Tab")
        seen.append(js("document.activeElement.id"))
    if "rulesResultCert" not in seen:
        fail("newrule-dns", f"Tab from the DNS option must reach 'Request a certificate', got {seen}")
    js("document.activeElement.blur()")
    js("document.getElementById('rulesResult').scrollIntoView({block: 'center'})")
    pg.wait_for_timeout(600)
    shot("newrule-dns-page-light.png", "#rulesResult")
    theme(True)
    shot("newrule-dns-page-dark.png", "#rulesResult")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(300)
    js("document.getElementById('rulesResult').scrollIntoView({block: 'center'})")
    shot("newrule-dns-page-390.png", "#rulesResult")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("newrule-dns", "the result of the New site page scrolls horizontally at 390px")
    theme(False)
    js("document.getElementById('rulesResult').scrollIntoView({block: 'center'})")
    shot("newrule-dns-page-390-light.png", "#rulesResult")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    # not ticked: HTTP challenge, exactly as before
    pg.click("#rulesResultCert")
    got = last_dns()
    if not got or got[0] != "false":
        fail("newrule-dns", f"an unticked option must request dns=false, got {got}")
    # ticked with the keyboard: DNS challenge, and no profile id is sent (the server uses the default)
    create_page(NRC_DNS[4])
    pg.focus("#rulesResultDns")
    pg.keyboard.press("Space")
    if not js("document.getElementById('rulesResultDns').checked"):
        fail("newrule-dns", "the option is not operable with the keyboard")
    pg.click("#rulesResultCert")
    got = last_dns()
    if not got or got[0] != "true" or NRC_DNS[4] not in got[1]:
        fail("newrule-dns", f"a ticked option must request dns=true for the new host, got {got}")
    if pg.is_visible("#rulesResultDnsRow"):
        fail("newrule-dns", "the option must go away with the request button")
    # the next site starts unticked again
    create_page(NRC_DNS[5])
    if js("document.getElementById('rulesResultDns').checked"):
        fail("newrule-dns", "the choice must not carry over to the next site")

    # 7c. the dialog: a second, explicit action in the toast
    js("openTabById('httprp')")
    create_dialog(NRC_DNS[6])
    toast = js("document.getElementById('nrToast').innerText")
    if "Create certificate for this host" not in toast or not pg.locator("#nrToastDns").count() or "nrc-dns-profile" not in toast:
        fail("newrule-dns", f"with a default DNS profile the toast must offer both requests and name the profile, got {toast!r}")
    shot("newrule-dns-toast-light.png", "#nrToast")
    theme(True)
    shot("newrule-dns-toast-dark.png", "#nrToast")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(300)
    shot("newrule-dns-toast-390.png", "#nrToast")
    box = js("(() => { const r = document.getElementById('nrToast').getBoundingClientRect(); return [r.left, r.right, window.innerWidth]; })()")
    if box[0] < -1 or box[1] > box[2] + 1:
        fail("newrule-dns", f"the toast leaves the screen at 390px: {box}")
    theme(False)
    shot("newrule-dns-toast-390-light.png", "#nrToast")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    pg.click("#nrToastDns")
    got = last_dns()
    if not got or got[0] != "true" or NRC_DNS[6] not in got[1]:
        fail("newrule-dns", f"the DNS action of the toast must request dns=true for the new host, got {got}")
    create_dialog(NRC_DNS[7])
    pg.click("#nrToast button:has-text('Create certificate for this host')")
    got = last_dns()
    if not got or got[0] != "false":
        fail("newrule-dns", f"the plain action of the toast must stay dns=false, got {got}")

    pg.unroute("**/api/acme/obtainCert*")
    pg.unroute("**/api/acme/autoRenew/email")
    post("/api/acme/profiles/dns", {"op": "delete", "id": pid_})
    if dns_state().get("default") or dns_state().get("profiles"):
        fail("newrule-dns", "the test DNS profile was not removed")
    for h in NRC_DNS:
        post("/api/proxy/del", {"ep": h})

    # ---- clean up
    for h in (NRC_HOST, NRC_PLAIN):
        post("/api/proxy/del", {"ep": h})
    for n in NRC_CERTS:
        js("async n => { await fetch('/api/cert/delete?domain=' + n, {method: 'POST', headers: {'X-CSRF-Token': document.querySelector('meta[name=\"zoraxy.csrf.Token\"]').content}}); }", n)
    pg.set_viewport_size({"width": 1366, "height": 800})
