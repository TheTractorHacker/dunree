"""Smoke scenario of the Live column of the Sites table (HTTP Proxy page). exec()'d by smoke.py (namespace: fail, current, args, os, re);
run alone with --live-sites-only. Needs the instance's proxy port at UI port + 1 and UI port + 2 free (a throw-away upstream).
Seeds two rules, sends real traffic (a third of it answered 500 by the upstream) to one of them and checks: the row shows req/s, a
sparkline and the error rate while traffic flows, the idle rule says "idle", the table row is not rebuilt by the updates (same DOM node,
selection kept), the cells do not overflow or collide, polling stops off the page, and the numbers fall back to idle once traffic stops.
Makes its own rules and removes them."""

import http.server
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.request

LS_HOSTS = ["livesite-busy.demo.test", "livesite-idle.demo.test"]


def live_sites_ui(pg, ctx):
    base = int(args.url.rsplit(":", 1)[1].split("/")[0])
    proxy_port, up_port = base + 1, base + 2

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            code = 500 if self.path.startswith("/err") else 200
            body = b"x"
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    srv = S(("127.0.0.1", up_port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    tls = ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    scheme = {"v": None}

    def hit(host, path="/"):
        for sch in ([scheme["v"]] if scheme["v"] else ["http", "https"]):
            r = urllib.request.Request("%s://127.0.0.1:%d%s" % (sch, proxy_port, path), headers={"Host": host})
            try:
                scheme["v"] = sch
                return urllib.request.urlopen(r, timeout=8, context=tls).status
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                if e.code == 400 and "HTTPS server" in body:
                    scheme["v"] = None
                    continue
                return e.code
            except Exception:
                scheme["v"] = None
                continue
        return 0

    stop = threading.Event()

    def traffic():
        n = 0
        while not stop.is_set():
            threading.Thread(target=hit, args=(LS_HOSTS[0], "/err" if n % 3 == 0 else "/"), daemon=True).start()
            n += 1
            time.sleep(0.1)  # 10 req/s, a third of them answered 500

    def cell(host):
        return pg.evaluate("h => { const td = document.querySelector('#httpProxyList td.ptLive[data-live=\"' + h + '\"]'); return td ? td.innerText.replace(/\\s+/g, ' ').trim() : null; }", host)

    current["page"] = "live-sites"
    pg.set_viewport_size({"width": 1366, "height": 900})
    try:
        for h in LS_HOSTS:
            post("/api/proxy/del", {"ep": h})
            r = post("/api/proxy/add", {"type": "host", "rootname": h, "ep": "127.0.0.1:%d" % up_port, "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
            if isinstance(r, dict) and r.get("error"):
                fail("live-sites", f"seeding {h} failed: {r}")
                return
        if hit(LS_HOSTS[0]) == 0:
            fail("live-sites", "the seeded rule does not reach its upstream through the proxy port (is it UI port + 1?)")
            return
        pg.goto(args.url + "/#httprp", wait_until="networkidle")
        pg.wait_for_selector('#httpProxyList td.ptLive[data-live="%s"]' % LS_HOSTS[0], timeout=15000)
        if pg.evaluate("document.querySelector('#httpProxyTable thead .ptLiveTh') === null"):
            fail("live-sites", "the table needs a Live column header")
        # a row selected before the updates start must stay selected and be the same DOM node afterwards
        pg.evaluate("""h => { const tr = document.querySelector('#httpProxyList td.ptLive[data-live="' + h + '"]').closest('tr'); window.__lsRow = tr; const c = tr.querySelector('input.bulkSel'); c.click(); }""", LS_HOSTS[0])
        t = threading.Thread(target=traffic, daemon=True)
        t.start()
        pg.wait_for_timeout(14000)
        busy = cell(LS_HOSTS[0]) or ""
        idle = cell(LS_HOSTS[1]) or ""
        m = re.search(r"([0-9.]+) req/s", busy)
        if not m or float(m.group(1)) < 4:
            fail("live-sites", f"the busy rule must show about 10 req/s while traffic flows, got {busy!r}")
        if "5xx/s" not in busy:
            fail("live-sites", f"a third of the traffic is answered 500: the busy rule must show a 5xx rate, got {busy!r}")
        if "idle" not in idle:
            fail("live-sites", f"the idle rule must say idle, got {idle!r}")
        n = pg.evaluate("h => { const p = document.querySelector('#httpProxyList td.ptLive[data-live=\"' + h + '\"] svg.ptSpark path:not(.fill)'); return p ? (p.getAttribute('d').match(/ L/g) || []).length + 1 : 0; }", LS_HOSTS[0])
        if n < 4:
            fail("live-sites", f"the busy rule must draw a sparkline of several samples, it has {n}")
        if not pg.evaluate("h => document.querySelector('#httpProxyList td.ptLive[data-live=\"' + h + '\"]').closest('tr') === window.__lsRow && window.__lsRow.querySelector('input.bulkSel').checked", LS_HOSTS[0]):
            fail("live-sites", "the live updates must not rebuild the row: it was replaced or lost its selection")
        # layout: nothing overflows its cell, no cell overlaps another, no sideways scroll of the page
        bad = pg.evaluate("""() => { const out = []; document.querySelectorAll('#httpProxyList tr.ptRow').forEach(tr => {
              const cells = [...tr.children]; cells.forEach((td, i) => { if (td.scrollWidth > td.clientWidth + 1) out.push('cell ' + i + ' overflows'); });
              for (let i = 1; i < cells.length; i++) { const a = cells[i - 1].getBoundingClientRect(), b = cells[i].getBoundingClientRect(); if (b.left < a.right - 1) out.push('cell ' + i + ' overlaps cell ' + (i - 1)); } });
              if (document.documentElement.scrollWidth > document.documentElement.clientWidth + 1) out.push('page scrolls sideways'); return out; }""")
        if bad:
            fail("live-sites", f"layout: {bad[:4]}")
        shot("livesites-light.png")
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(800)
        shot("livesites-dark.png")
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(800)
        shot("livesites-390.png")
        if pg.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth + 1"):
            fail("live-sites", "at 390 px the page scrolls sideways (only the table may scroll inside its own wrapper)")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("toggleTheme()")
        # traffic stops: the numbers fall back to idle
        stop.set()
        pg.wait_for_timeout(16000)
        after = cell(LS_HOSTS[0]) or ""
        if "idle" not in after:
            fail("live-sites", f"after the traffic stopped the busy rule must say idle, got {after!r}")
        # no polling off the page
        pg.evaluate("openTabById('cert')")
        pg.wait_for_timeout(1500)
        cnt = {"c": 0}
        h2 = lambda rq: cnt.__setitem__("c", cnt["c"] + (1 if "/api/stats/livemap" in rq.url else 0))
        pg.on("request", h2)
        pg.wait_for_timeout(6000)
        pg.remove_listener("request", h2)
        if cnt["c"] != 0:
            fail("live-sites", f"the Sites table must not poll while another page is shown ({cnt['c']} requests)")
    finally:
        stop.set()
        for h in LS_HOSTS:
            post("/api/proxy/del", {"ep": h})
        srv.shutdown()
