"""Smoke scenario of the CrowdSec bouncer tab and the hardened security headers preset (docs/enterprise-dual-proxy-plan.md Phase 3 slices E and F).
exec()'d by smoke.py (namespace: fail, current, args, os, re, check_horizontal); run alone with --crowdsec-only. Needs UI port + 1 to be the
instance's proxy port and UI port + 2 and + 3 free (a throw-away upstream and a fake CrowdSec LAPI, both started here on 127.0.0.1).

Covers: defaults (off, nothing blocked); the CrowdSec tab (status card, form, Test connection against the fake LAPI with a good key, a wrong key and a
refused metadata address); enforcement end to end through a proxied site: log only never blocks (and the match is listed), Enforce (after the
confirmation) returns the 403 for a banned address and still serves everyone else, a decision deleted at the LAPI unblocks within a pull, and with the
LAPI killed the site keeps serving (fail open, the status card turns degraded then down); the API key is never visible in the page, in any API answer or
in the security audit log; light / dark / 390 px layout of the tab without overflow; the "Hardened security headers" card of the site editor (off by
default and no header sent, the preview table, save, the headers really arrive from the proxy, an upstream header is kept unless replacing is chosen).
Console errors and failed requests are caught by the handlers smoke.py installs on the page.

The visitor address of a request from this machine is loopback, which CrowdSec never acts on. The scenario therefore makes 127.0.0.1 a trusted proxy,
turns Trusted Proxy Gating on for the default access rule and sends the address to test in X-Forwarded-For (the way a front proxy would); it restores
all of that and the CrowdSec settings at the end. Run it on a throw-away instance."""

import http.server
import json
import re
import secrets
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.request

CS_HOST = "crowdsec-smoke.demo.test"
CS_BANNED = "203.0.113.77"
CS_BANNED2 = "203.0.113.78"
CS_CLEAN = "198.51.100.5"


class FakeLAPI:
    """A stand-in for the documented CrowdSec Local API endpoints: X-Api-Key, /v1/decisions/stream (startup, then deltas), /v1/decisions?ip="""

    def __init__(self, port, key):
        self.port, self.key = port, key
        self.lock = threading.Lock()
        self.decisions = {}
        self.pend_new, self.pend_del = [], []
        self.calls = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                path, _, qs = self.path.partition("?")
                if self.headers.get("X-Api-Key") != outer.key:
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                with outer.lock:
                    outer.calls.append(self.path)
                    if path == "/v1/decisions/stream":
                        if "startup=true" in qs:
                            body = {"new": list(outer.decisions.values()) or None, "deleted": None}
                            outer.pend_new, outer.pend_del = [], []
                        else:
                            body = {"new": outer.pend_new or None, "deleted": outer.pend_del or None}
                            outer.pend_new, outer.pend_del = [], []
                    elif path == "/v1/decisions":
                        ip = qs.split("ip=")[-1] if "ip=" in qs else ""
                        body = [d for d in outer.decisions.values() if d["value"] == ip] or None
                    else:
                        self.send_response(404)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.srv = S(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def ban(self, ident, ip, typ="ban"):
        d = {"id": ident, "origin": "cscli", "type": typ, "scope": "Ip", "value": ip, "duration": "1h", "scenario": "smoke/manual ban"}
        with self.lock:
            self.decisions[ident] = d
            self.pend_new.append(d)

    def unban(self, ident):
        with self.lock:
            d = self.decisions.pop(ident, None)
            if d:
                self.pend_del.append(d)

    def stop(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass


def crowdsec_ui(pg, ctx):
    base = int(args.url.rsplit(":", 1)[1].split("/")[0])
    proxy_port, up_port, lapi_port = base + 1, base + 2, base + 3
    api_key = "csk-" + secrets.token_hex(12)
    current["page"] = "crowdsec"

    class U(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"upstream-ok"
            self.send_response(200)
            if self.path.startswith("/framed"):
                self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class US(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    upstream = US(("127.0.0.1", up_port), U)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    lapi = FakeLAPI(lapi_port, api_key)
    lapi_url = "http://127.0.0.1:%d" % lapi_port

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])

    def get(path):
        return pg.evaluate("p => fetch(p).then(r => r.json())", path)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def wait_for(fn, timeout, what, step=0.5):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            last = fn()
            if last:
                return last
            time.sleep(step)
        fail("crowdsec", f"timed out ({timeout}s) waiting for {what}")
        return None

    tls = ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    scheme = {"v": None}

    def hit(path="/", xff=None):
        """one request through the proxy port; returns (status, headers dict lower-cased, body)"""
        hdr = {"Host": CS_HOST}
        if xff:
            hdr["X-Forwarded-For"] = xff
        for sch in ([scheme["v"]] if scheme["v"] else ["https", "http"]):
            r = urllib.request.Request("%s://127.0.0.1:%d%s" % (sch, proxy_port, path), headers=hdr)
            try:
                scheme["v"] = sch
                with urllib.request.urlopen(r, timeout=8, context=tls) as resp:
                    return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                if e.code == 400 and "HTTPS server" in body:
                    scheme["v"] = "https"
                    continue
                return e.code, {k.lower(): v for k, v in e.headers.items()}, body
            except Exception:
                scheme["v"] = None
                continue
        return 0, {}, ""

    hit.scheme = scheme

    def status():
        return get("/api/crowdsec/status")

    def open_tab():
        js("openTabById('seccenter')")
        pg.wait_for_selector("#secTabs .item[data-sec='crowdsec']", state="attached", timeout=10000)
        pg.dispatch_event("#secTabs .item[data-sec='crowdsec']", "click", timeout=6000)
        pg.wait_for_selector("#csForm", timeout=10000)
        pg.wait_for_function("document.getElementById('csUrl') && document.getElementById('csPoll').value !== ''", timeout=8000)
        pg.wait_for_timeout(600)
        js("document.querySelectorAll('#secPane details.sx-group, #secPane details.zx-disclosure').forEach(d => { d.open = true; })")   # tuning, trust, the stored key and the management tools sit in collapsed groups

    def type_into(sel, text):
        pg.click(sel)
        pg.keyboard.press("Control+A")
        pg.keyboard.type(text)

    def set_toggle(sel_input, on):
        if js("s => document.querySelector(s).checked", sel_input) != on:
            pg.click("label[for='%s']" % sel_input.lstrip("#"))

    def confirm(ok):
        pg.wait_for_selector(".zx-dialog [data-zx-ok]", timeout=5000)
        pg.click(".zx-dialog %s" % ("[data-zx-ok]" if ok else "[data-zx-cancel]"))
        pg.wait_for_timeout(700)

    def audit_text():
        return json.dumps(get("/api/security/audit/list?limit=200"))

    saved = {}
    ok_setup = False
    pg.set_viewport_size({"width": 1366, "height": 900})
    if js("document.body.classList.contains('darkTheme')"):
        js("toggleTheme()")
    try:
        # ---------------------------------------------------------------- setup: trusted proxy + gating so a test address can be sent in X-Forwarded-For
        current["page"] = "crowdsec-setup"
        tp = get("/api/trustedproxy/list")
        had_loop = any(str(x.get("ip") or x.get("IP") or x.get("Cidr") or x).startswith("127.0.0.1") for x in (tp if isinstance(tp, list) else []))
        saved["trusted_added"] = False
        if not had_loop:
            r = post("/api/trustedproxy/add", {"ip": "127.0.0.1/32", "desc": "crowdsec smoke"})
            if isinstance(r, dict) and r.get("error"):
                fail("crowdsec-setup", f"could not add the loopback trusted proxy: {r}")
                return
            saved["trusted_added"] = True
        gate_now = pg.evaluate("""() => new Promise(res => $.cjax({url: '/api/whitelist/trustProxy', method: 'POST', data: {id: 'default'}, success: r => res(r), error: () => res(null)}))""")
        saved["gating"] = bool(gate_now)
        post("/api/whitelist/trustProxy", {"id": "default", "enable": "true"})
        post("/api/proxy/del", {"ep": CS_HOST})
        r = post("/api/proxy/add", {"type": "host", "rootname": CS_HOST, "ep": "127.0.0.1:%d" % up_port, "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
        if isinstance(r, dict) and r.get("error"):
            fail("crowdsec-setup", f"seeding {CS_HOST} failed: {r}")
            return
        st, _, body = hit("/")
        if st != 200 or body != "upstream-ok":
            fail("crowdsec-setup", f"the seeded rule does not reach its upstream through the proxy port (is it UI port + 1?): {st} {body[:60]!r}")
            return
        ok_setup = True

        # ---------------------------------------------------------------- defaults: off, nothing is blocked, nothing is stored
        current["page"] = "crowdsec-defaults"
        g0 = get("/api/crowdsec/get")
        if g0.get("enabled") or g0.get("keySet") or g0.get("mode") != "log":
            fail("crowdsec-defaults", f"a fresh instance must have CrowdSec off, no key, mode log: {g0}")
        if status().get("state") != "off":
            fail("crowdsec-defaults", f"the status of a switched-off CrowdSec must be 'off': {status()}")
        lapi.ban(1, CS_BANNED)
        lapi.ban(2, CS_BANNED2)
        if hit("/", CS_BANNED)[0] != 200:
            fail("crowdsec-defaults", "a request must be served while CrowdSec is off")
        if lapi.calls:
            fail("crowdsec-defaults", f"CrowdSec off must not contact the LAPI: {lapi.calls[:2]}")
        open_tab()
        if "switched off" not in js("document.getElementById('csStatus').innerText"):
            fail("crowdsec-defaults", "the status card of the switched-off feature must say so: " + js("document.getElementById('csStatus').innerText"))
        if js("document.getElementById('csEnabled').checked") or js("document.getElementById('csMode').value") != "log":
            fail("crowdsec-defaults", "the form must show CrowdSec off in Log only mode")
        shot("crowdsec-off.png")

        # ---------------------------------------------------------------- the form: Test connection (wrong key, refused address, good key)
        current["page"] = "crowdsec-form"
        type_into("#csUrl", lapi_url)
        type_into("#csKey", "wrong-" + api_key)
        pg.click("#csTest")
        pg.wait_for_selector("#csTestMsg.negative", timeout=15000)
        txt = js("document.getElementById('csTestMsg').innerText")
        if "wrong-" in txt or api_key in txt:
            fail("crowdsec-secret", "the test result repeats the key")
        shot("crowdsec-test-wrongkey.png")
        type_into("#csUrl", "http://169.254.169.254")
        type_into("#csKey", api_key)
        pg.click("#csTest")
        pg.wait_for_function("document.getElementById('csTestMsg').classList.contains('negative') && /refus|not allowed|metadata|link-local/i.test(document.getElementById('csTestMsg').innerText)", timeout=15000)
        type_into("#csUrl", lapi_url)
        type_into("#csKey", api_key)
        pg.click("#csTest")
        pg.wait_for_selector("#csTestMsg.positive", timeout=15000)
        if not any(c.startswith("/v1/decisions?ip=") for c in lapi.calls):
            fail("crowdsec-form", f"Test connection must make the documented authenticated lookup call: {lapi.calls}")
        shot("crowdsec-test-ok.png")
        # invalid number: the server refuses, nothing is stored, the form says why
        type_into("#csPoll", "1")
        set_toggle("#csEnabled", True)
        pg.click("#csSave")
        pg.wait_for_selector("#csMsg", state="visible", timeout=8000)
        if get("/api/crowdsec/get").get("enabled"):
            fail("crowdsec-form", "an invalid poll interval was stored")
        shot("crowdsec-invalid.png")
        type_into("#csPoll", "5")
        type_into("#csGrace", "10")

        # ---------------------------------------------------------------- log only: enabled, the status card turns green, matches are listed, nobody is blocked
        current["page"] = "crowdsec-logonly"
        pg.click("#csSave")
        pg.wait_for_function("!document.getElementById('csMsg') || document.getElementById('csMsg').style.display === 'none'", timeout=8000)
        s = wait_for(lambda: (lambda x: x if x.get("state") == "ok" and x.get("cacheSize", 0) >= 2 else None)(status()), 40, "the status to become ok with 2 decisions in memory")
        if s is None:
            shot("crowdsec-never-ok.png")
            return
        if s.get("mode") != "log" or not s.get("keySet"):
            fail("crowdsec-logonly", f"saved as log only with a key: {s}")
        code, _, _ = hit("/", CS_BANNED)
        if code != 200:
            fail("crowdsec-logonly", f"log only must never block, the banned address got {code}")
        s2 = status()
        if s2.get("logOnly", 0) < s.get("logOnly", 0) + 1 or s2.get("enforced", 0) != s.get("enforced", 0):
            fail("crowdsec-logonly", f"the match must be counted as log only and nothing enforced: {s2}")
        open_tab()
        pg.wait_for_function("document.querySelector('#csMatches tbody td') && document.querySelector('#csMatches tbody td').innerText.indexOf('None yet') < 0", timeout=15000)
        if CS_BANNED not in js("document.getElementById('csMatches').innerText") or "would block" not in js("document.getElementById('csMatches').innerText"):
            fail("crowdsec-logonly", "Recent matches must list the banned address as 'would block (log only)'")
        if CS_BANNED not in js("document.getElementById('csDecisions').innerText"):
            fail("crowdsec-logonly", "Recent decisions must list the ban received from the LAPI")
        if "OK" not in js("document.getElementById('csStatus').innerText") or not re.search(r"Decisions in memory:?\s*2\b", js("document.getElementById('csStatus').innerText")):
            fail("crowdsec-logonly", "the status card must show OK and 2 decisions: " + js("document.getElementById('csStatus').innerText"))
        if js("document.getElementById('csKey').value") != "" or not js("document.getElementById('csKeyBadge').offsetParent !== null"):
            fail("crowdsec-secret", "after saving, the key field must be empty and a 'Key set' badge shown")
        shot("crowdsec-logonly.png")

        # ---------------------------------------------------------------- enforce: confirmation first, then the banned address gets 403 and others are served
        current["page"] = "crowdsec-enforce"
        pg.select_option("#csMode", "enforce")
        pg.click("#csSave")
        confirm(False)  # cancelled: nothing changes
        if get("/api/crowdsec/get").get("mode") != "log" or hit("/", CS_BANNED)[0] != 200:
            fail("crowdsec-enforce", "cancelling the confirmation must leave the mode on log only")
        pg.click("#csSave")
        confirm(True)
        wait_for(lambda: get("/api/crowdsec/get").get("mode") == "enforce", 8, "enforce mode to be stored")
        code, _, body = hit("/", CS_BANNED)
        if code != 403:
            fail("crowdsec-enforce", f"enforce: the banned address must get 403, got {code}")
        if api_key in body:
            fail("crowdsec-secret", "the 403 page contains the key")
        if hit("/", CS_CLEAN)[0] != 200:
            fail("crowdsec-enforce", "enforce: an address without a decision must be served")
        if hit("/", None)[0] != 200:
            fail("crowdsec-enforce", "enforce: this machine (loopback, no forwarded address) must never be refused")
        if hit("/", "%s, %s" % (CS_CLEAN, CS_BANNED))[0] != 403:
            fail("crowdsec-enforce", "enforce: a banned address anywhere in X-Forwarded-For must still be refused")
        if status().get("enforced", 0) <= s2.get("enforced", 0):
            fail("crowdsec-enforce", "the blocks must be counted")
        open_tab()
        pg.wait_for_function("document.getElementById('csMatches').innerText.indexOf('blocked') >= 0", timeout=15000)
        shot("crowdsec-enforce.png")

        # ---------------------------------------------------------------- a deleted decision unblocks
        current["page"] = "crowdsec-unban"
        lapi.unban(1)
        wait_for(lambda: hit("/", CS_BANNED)[0] == 200, 30, "the deleted decision to unblock the address")
        if hit("/", CS_BANNED2)[0] != 403:
            fail("crowdsec-unban", "the other decision must still block after the first was deleted")

        # ---------------------------------------------------------------- the key is nowhere
        current["page"] = "crowdsec-secret"
        open_tab()
        page_html = js("document.documentElement.outerHTML") + js("document.body.innerText")
        inputs = js("[...document.querySelectorAll('input, textarea, select')].map(e => e.value).join('|')")
        pools = {"page": page_html, "form values": inputs, "get": json.dumps(get("/api/crowdsec/get")), "status": json.dumps(status()),
                 "decisions": json.dumps(get("/api/crowdsec/decisions")), "audit": audit_text(), "storage": js("JSON.stringify([localStorage, sessionStorage])")}
        for name, text in pools.items():
            if api_key in text:
                fail("crowdsec-secret", f"the API key is visible in: {name}")
        au = get("/api/security/audit/list?limit=200").get("entries") or []
        if not any((e.get("event") or e.get("Event") or "") == "crowdsec.set" for e in au):
            fail("crowdsec-audit", "saving the settings must leave a crowdsec.set entry in the security audit log")
        if not any((e.get("event") or e.get("Event") or "") == "crowdsec.test" for e in au):
            fail("crowdsec-audit", "Test connection must leave a crowdsec.test entry in the security audit log")

        # ---------------------------------------------------------------- layout: light / dark / 390 px
        for theme in ("light", "dark"):
            if (theme == "dark") != js("document.body.classList.contains('darkTheme')"):
                js("toggleTheme()")
                pg.wait_for_timeout(500)
            for (w, h, tag) in ((1366, 900, "desktop"), (390, 844, "390")):
                current["page"] = f"crowdsec-layout/{theme}/{tag}"
                pg.set_viewport_size({"width": w, "height": h})
                pg.wait_for_timeout(500)
                open_tab()
                bad = js("""() => { const out = [], W = document.documentElement.clientWidth;
                    document.querySelectorAll('#secPane *').forEach(el => {
                      const r = el.getBoundingClientRect(); if (r.width === 0 || r.right <= W + 1) return;
                      for (let p = el.parentElement; p && p.id !== 'secPane'; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return; }
                      out.push(el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + ' right=' + Math.round(r.right)); });
                    return out.slice(0, 4); }""")
                if bad:
                    fail("crowdsec-layout", f"{theme} {tag}: content sticks out of the viewport: {bad}")
                check_horizontal(pg, f"crowdsec {theme} {tag}")
                weak = js("""(dark) => { const lum = c => { const m = c.match(/[0-9.]+/g).map(Number); const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); };
                    const out = []; document.querySelectorAll('#secPane p, #secPane small, #secPane label').forEach(e => { if (!e.offsetParent || !e.innerText.trim()) return; const l = lum(getComputedStyle(e).color);
                      if (dark ? l < 0.25 : l > 0.3) out.push((e.className || e.tagName) + ' ' + e.innerText.trim().slice(0, 30)); }); return out.slice(0, 3); }""", theme == "dark")
                if weak:
                    fail("crowdsec-contrast", f"{theme}: text too close to the background colour: {weak}")
                shot(f"crowdsec-{theme}-{tag}.png")
        if js("document.body.classList.contains('darkTheme')"):
            js("toggleTheme()")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---------------------------------------------------------------- the LAPI dies: fail open, the card says so
        current["page"] = "crowdsec-lapidown"
        lapi.stop()
        wait_for(lambda: status().get("state") in ("degraded", "down"), 45, "the status to leave ok after the LAPI was killed")
        if hit("/", CS_CLEAN)[0] != 200 or hit("/", None)[0] != 200:
            fail("crowdsec-lapidown", "fail open: with the LAPI gone, visitors without a decision must still be served")
        s = wait_for(lambda: (lambda x: x if x.get("state") == "down" else None)(status()), 60, "the status to become down after the grace period")
        if s:
            if s.get("failClosedActive"):
                fail("crowdsec-lapidown", "fail-closed is off: it must not be active")
            if not any("Failing open" in w or "fail" in w.lower() for w in s.get("warnings") or []):
                fail("crowdsec-lapidown", f"the status must warn that it is failing open: {s.get('warnings')}")
            if not s.get("lastError"):
                fail("crowdsec-lapidown", "the status must show the last error")
            if api_key in json.dumps(s):
                fail("crowdsec-secret", "the status after an error contains the key")
        if hit("/", CS_CLEAN)[0] != 200 or hit("/", None)[0] != 200:
            fail("crowdsec-lapidown", "fail open: still served after the grace period")
        if hit("/", CS_BANNED2)[0] != 403:
            fail("crowdsec-lapidown", "decisions already in memory must keep applying while the LAPI is down (documented)")
        open_tab()
        pg.wait_for_function("/Down|Degraded/.test(document.getElementById('csStatus').innerText)", timeout=15000)
        if "Last error" not in js("document.getElementById('csStatus').innerText"):
            fail("crowdsec-lapidown", "the status card must show the last error")
        shot("crowdsec-down.png")
        if js("k => document.documentElement.outerHTML.indexOf(k) >= 0", api_key):
            fail("crowdsec-secret", "the key is in the page after the outage")

        # ---------------------------------------------------------------- switch off again: nothing is blocked
        current["page"] = "crowdsec-off"
        set_toggle("#csEnabled", False)
        set_toggle("#csClearKey", True)
        pg.select_option("#csMode", "log")
        pg.click("#csSave")
        wait_for(lambda: not get("/api/crowdsec/get").get("enabled") and not get("/api/crowdsec/get").get("keySet"), 8, "CrowdSec to be switched off and the key removed")
        if hit("/", CS_BANNED2)[0] != 200:
            fail("crowdsec-off", "switched off: nobody may be blocked")

        # ---------------------------------------------------------------- hardened headers: card in the site editor, header really sent
        current["page"] = "crowdsec-hardened"
        _hardened(pg, js, get, post, shot, hit, wait_for)

        # ---------------------------------------------------------------- manage CrowdSec: machine login, ban, unban, alerts
        current["page"] = "crowdsec-manage"
        _manage(pg, js, get, post, shot, wait_for, open_tab, confirm, audit_text, base + 4)
    finally:
        try:
            if ok_setup:
                post("/api/crowdsec/set", {"config": json.dumps({"enabled": False, "lapiUrl": "", "mode": "log"}), "clearkey": "true"})
                post("/api/proxy/del", {"ep": CS_HOST})
                post("/api/whitelist/trustProxy", {"id": "default", "enable": "true" if saved.get("gating") else "false"})
            if saved.get("trusted_added"):
                post("/api/trustedproxy/remove", {"ip": "127.0.0.1/32"})
        except Exception as e:
            print("  (cleanup problem: %s)" % e)
        lapi.stop()
        upstream.shutdown()
        upstream.server_close()


def _hardened(pg, js, get, post, shot, hit, wait_for):
    def raw_rule():
        return js("h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => l.filter(x => x.RootOrMatchingDomain === h)[0])", CS_HOST)

    def hh_of():
        return (raw_rule().get("HeaderRewriteRules") or {}).get("HardenedHeaders") or {}

    st, h, _ = hit("/")
    if st != 200 or any(k in h for k in ("x-content-type-options", "referrer-policy", "permissions-policy", "strict-transport-security")):
        fail("hardened", f"by default no hardening header may be sent (status {st}): {sorted(h)}")
    if hh_of().get("Enabled"):
        fail("hardened", "a new rule must not have the preset on")

    js("openTabById('httprp')")
    pg.wait_for_timeout(700)
    js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", CS_HOST)
    pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=10000)
    pg.wait_for_timeout(1000)
    js("HrpEditor.setMode('advanced')")
    pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=security]")
    pg.wait_for_timeout(500)
    js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='hardenedheaders']"); if (c) c.scrollIntoView({block: 'center'}); }""")
    pg.wait_for_timeout(800)
    fr = None
    for f in pg.frames:
        if "hardenedHeaders.html" in f.url:
            # earlier scenarios can leave stale hidden editor frames behind: take the one that is on screen
            try:
                if f.frame_element().is_visible():
                    fr = f
            except Exception:
                pass
    if fr is None:
        fail("hardened", "the Hardened security headers card has no editor frame")
        return
    fr.wait_for_selector("#hhPreview tr", timeout=10000)
    fr.wait_for_function("document.getElementById('hhPreview').innerText.indexOf('Nothing is sent') >= 0", timeout=8000)
    if fr.evaluate("document.getElementById('hhEnabled').checked"):
        fail("hardened", "the card must show the preset off for a new rule")
    shot("hardened-off.png")

    fr.click("#hhEnabledBox label")  # a click on the label text (not the box) must work
    if fr.evaluate("document.getElementById('hhOptions').classList.contains('disabled')"):
        fail("hardened", "clicking the label of the switch does not turn the preset on")
    if not fr.evaluate("document.getElementById('hhSniff').checked"):
        fr.click("#hhSniff", force=True)
    if fr.evaluate("document.getElementById('hhPP').checked"):
        fr.click("#hhPP + label")  # untick Permissions-Policy through its label text: must not be sent afterwards
    fr.select_option("#hhReferrer", "no-referrer")
    fr.select_option("#hhFrame", "deny")
    try:
        fr.wait_for_function("(() => { const t = document.getElementById('hhPreview').innerText; return /nosniff/.test(t) && /Referrer-Policy/.test(t) && /X-Frame-Options/.test(t) && /Added only if the upstream sends none/.test(t); })()", timeout=8000)
    except Exception:
        shot("hardened-preview-failed.png")
        fail("hardened", "the preview did not list the chosen headers: " + fr.evaluate("document.getElementById('hhPreview').innerText"))
        return
    if hh_of().get("Enabled"):
        fail("hardened", "the preview must not save anything")
    fr.evaluate("document.getElementById('hhPreviewTable').scrollIntoView({block: 'end'})")
    pg.wait_for_timeout(300)
    shot("hardened-preview.png")
    fr.click("#hhSave")
    wait_for(lambda: hh_of().get("Enabled"), 8, "the preset to be saved")
    hh = hh_of()
    if not hh.get("NoSniff") or hh.get("ReferrerPolicy") != "no-referrer" or hh.get("FrameProtection") != "deny" or hh.get("PermissionsPolicy"):
        fail("hardened", f"the saved preset does not match the form: {hh}")
    if hh.get("HSTSIncludeSubdomains") or hh.get("HSTSPreload"):
        fail("hardened", "includeSubDomains / preload were not ticked and must not be stored")

    # the header really arrives from the proxy (TLS path, the one that is covered)
    st, h, _ = hit("/")
    if hit.scheme["v"] == "https":
        if h.get("x-content-type-options") != "nosniff" or h.get("referrer-policy") != "no-referrer" or h.get("x-frame-options") != "DENY":
            fail("hardened", f"the proxy did not send the chosen headers: {sorted(h.items())}")
        if h.get("strict-transport-security") != "max-age=31536000":
            fail("hardened", f"HSTS (recommended value, no includeSubDomains) must be sent over https: {h.get('strict-transport-security')}")
        if "permissions-policy" in h:
            fail("hardened", "Permissions-Policy was not chosen and must not be sent")
        st, h, _ = hit("/framed")
        if h.get("x-frame-options") != "SAMEORIGIN":
            fail("hardened", f"an upstream X-Frame-Options must be kept unless replacing is chosen: {h.get('x-frame-options')}")
    else:
        fail("hardened", "the proxy port did not answer over https, the header check could not run on the covered path")

    # invalid input is refused and the stored value stays
    r = post("/api/proxy/header/hardened", {"domain": CS_HOST, "settings": json.dumps({"Enabled": True, "ReferrerPolicy": "evil\r\nX-Injected: 1"})})
    if not (isinstance(r, dict) and r.get("error")):
        fail("hardened", f"an invalid Referrer-Policy was accepted: {r}")
    if hh_of().get("ReferrerPolicy") != "no-referrer":
        fail("hardened", "invalid input changed the stored preset")
    # layout of the card at phone width and in dark mode
    for (w, h2, dark, tag) in ((1366, 900, True, "dark"), (390, 844, False, "390")):
        if dark:
            js("toggleTheme()")
        pg.set_viewport_size({"width": w, "height": h2})
        pg.wait_for_timeout(700)
        js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='hardenedheaders']"); if (c) c.scrollIntoView({block: 'center'}); }""")
        pg.wait_for_timeout(500)
        bad = fr.evaluate("""() => { const out = [], W = document.documentElement.clientWidth; document.querySelectorAll('.ui.checkbox, select, td, th, small, button').forEach(e => {
            const r = e.getBoundingClientRect(); if (r.width && (r.right > W + 1 || r.left < -1)) out.push(e.tagName + ' ' + Math.round(r.left) + '-' + Math.round(r.right) + ' of ' + W); }); return out.slice(0, 4); }""")
        if bad:
            fail("hardened-layout", f"{tag}: the card content sticks out of its frame: {bad}")
        fr.evaluate("document.getElementById('hhPreviewTable').scrollIntoView({block: 'end'})")
        pg.wait_for_timeout(300)
        check_horizontal(pg, "hardened card " + tag)
        shot("hardened-%s.png" % tag)
        if dark:
            js("toggleTheme()")
    pg.set_viewport_size({"width": 1366, "height": 900})
    js("""() => { const b = document.querySelector('#httprpEditModal .httpProxyEditClosePC'); if (b) b.click(); }""")
    pg.wait_for_timeout(500)
    js("""() => { const d = document.querySelector('.zx-dialog [data-zx-ok]'); if (d) d.click(); }""")


class FakeWatcher:
    """Documented watcher endpoints: POST /v1/watchers/login, GET/POST /v1/alerts (Bearer), DELETE /v1/decisions/<id>"""

    def __init__(self, port, mid, pw):
        self.mid, self.pw, self.token = mid, pw, "jwt-" + secrets.token_hex(8)
        self.lock = threading.Lock()
        self.decisions, self.next_id, self.posted, self.deleted = {}, 100, [], []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None):
                raw = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"null")

            def _authed(self):
                return self.headers.get("Authorization") == "Bearer " + outer.token

            def do_POST(self):
                path = self.path.partition("?")[0]
                b = self._body()
                if path == "/v1/watchers/login":
                    if b.get("machine_id") == outer.mid and b.get("password") == outer.pw:
                        return self._send(200, {"code": 200, "expire": "2099-01-01T00:00:00Z", "token": outer.token})
                    return self._send(403, {"message": "bad login"})
                if not self._authed():
                    return self._send(401)
                if path == "/v1/alerts":
                    with outer.lock:
                        for a in b:
                            for d in a.get("decisions", []):
                                outer.next_id += 1
                                d = dict(d, id=outer.next_id)
                                outer.decisions[d["id"]] = (a, d)
                            outer.posted.append(a)
                    return self._send(201, ["1"])
                self._send(404)

            def do_GET(self):
                path = self.path.partition("?")[0]
                if not self._authed():
                    return self._send(401)
                if path == "/v1/alerts":
                    with outer.lock:
                        out = [{"id": i, "created_at": "2026-11-22T10:00:00Z", "scenario": a["scenario"], "message": a["message"], "events_count": 1,
                                "source": a["source"], "decisions": [d]} for i, (a, d) in outer.decisions.items()]
                    return self._send(200, out or None)
                self._send(404)

            def do_DELETE(self):
                if not self._authed():
                    return self._send(401)
                i = int(self.path.rsplit("/", 1)[1])
                with outer.lock:
                    if i not in outer.decisions:
                        return self._send(404, {"message": "not found"})
                    del outer.decisions[i]
                    outer.deleted.append(i)
                self._send(200, {"nbDeleted": "1"})

        class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.srv = S(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass


def _manage(pg, js, get, post, shot, wait_for, open_tab, confirm, audit_text, port):
    mid, pw = "smoke-admin", "pw-" + secrets.token_hex(10)
    w = FakeWatcher(port, mid, pw)
    try:
        r = post("/api/crowdsec/set", {"config": json.dumps({"enabled": False, "lapiUrl": "http://127.0.0.1:%d" % port, "mode": "log"}), "apikey": "csk-unused-0123456789"})
        if isinstance(r, dict) and r.get("error"):
            fail("crowdsec-manage", f"could not save the LAPI address: {r}")
            return
        pg.reload()
        pg.wait_for_timeout(1500)
        open_tab()
        pg.wait_for_selector("#csMgConnect", state="attached", timeout=8000)
        pg.wait_for_function("document.getElementById('csMgConnect').style.display !== 'none'", timeout=8000)
        if js("getComputedStyle(document.getElementById('csMgPanel')).display") != "none":
            fail("crowdsec-manage", "the management panel is visible before a machine login exists")
        # wrong password is refused with a message that does not echo it
        pg.fill("#csMgId", mid)
        pg.fill("#csMgPw", "wrong-password-xyz")
        pg.click("#csMgSave")
        pg.wait_for_function("document.getElementById('csMgMsg').style.display !== 'none'", timeout=8000)
        if "wrong-password-xyz" in js("document.getElementById('csMgMsg').innerText"):
            fail("crowdsec-manage", "the error message echoes the password")
        # right password
        pg.fill("#csMgPw", pw)
        pg.click("#csMgSave")
        pg.wait_for_function("getComputedStyle(document.getElementById('csMgPanel')).display !== 'none'", timeout=10000)
        if mid not in js("document.getElementById('csMgWho').innerText"):
            fail("crowdsec-manage", "the connected machine is not shown")
        if js("p => document.documentElement.outerHTML.indexOf(p) >= 0", pw):
            fail("crowdsec-manage", "the machine password is still in the page after connecting")
        # refused targets
        pg.fill("#csBanTarget", "127.0.0.1")
        pg.click("#csBanGo")
        confirm(True)
        pg.wait_for_function("document.getElementById('csBanMsg').style.display !== 'none' && /loopback/i.test(document.getElementById('csBanMsg').innerText)", timeout=8000)
        if w.posted:
            fail("crowdsec-manage", "a refused ban reached the LAPI")
        # a real ban shows up in the list
        pg.fill("#csBanTarget", "203.0.113.44")
        pg.fill("#csBanReason", "smoke test")
        pg.click("#csBanGo")
        confirm(True)
        pg.wait_for_function("document.querySelector('#csMgDecisions tbody').innerText.indexOf('203.0.113.44') >= 0", timeout=10000)
        if len(w.posted) != 1 or w.posted[0]["decisions"][0]["value"] != "203.0.113.44":
            fail("crowdsec-manage", f"unexpected ban payload: {w.posted}")
        pg.wait_for_function("document.querySelector('#csMgAlerts tbody').innerText.indexOf('203.0.113.44') >= 0", timeout=10000)
        shot("crowdsec-manage.png")
        # remove it
        pg.click("#csMgDecisions .cs-unban")
        confirm(True)
        pg.wait_for_function("document.querySelector('#csMgDecisions tbody').innerText.indexOf('203.0.113.44') < 0", timeout=10000)
        if len(w.deleted) != 1:
            fail("crowdsec-manage", "the ban was not deleted on the LAPI")
        check_horizontal(pg, "crowdsec manage")
        # audit log has the change and no password
        a = audit_text()
        if pw in a:
            fail("crowdsec-manage", "the machine password is in the security audit log")
        if "manage" not in a:
            fail("crowdsec-manage", "the ban and unban are not in the security audit log")
        # remove the login
        pg.click("#csMgRemove")
        confirm(True)
        pg.wait_for_function("getComputedStyle(document.getElementById('csMgPanel')).display === 'none'", timeout=8000)
        if get("/api/crowdsec/manage/status").get("set"):
            fail("crowdsec-manage", "the login was not removed")
    finally:
        try:
            post("/api/crowdsec/manage/login", {"clear": "true"})
            post("/api/crowdsec/set", {"config": json.dumps({"enabled": False, "lapiUrl": "", "mode": "log"}), "clearkey": "true"})
        except Exception as e:
            print("  (manage cleanup problem: %s)" % e)
        w.stop()
