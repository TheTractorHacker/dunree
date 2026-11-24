"""Smoke scenario of the Status page Traffic map, Live mode (/api/stats/livemap). exec()'d by smoke.py (namespace: fail, current, args,
os); run alone with --live-map-only. Needs the instance's proxy port at UI port + 1 (as tools/ui-smoke/run.sh starts it). It starts
two throw-away upstream servers on UI port + 2 / + 3, seeds two rules, sends real traffic through the proxy and checks that the live
numbers (API and map) rise while traffic flows and fall to zero (edges grey and static, nothing drawn) after it stops. It also checks
the Live / Today switch, that Pause and Hide stop the polling, and takes the screenshots. Undoes every change it makes."""

import http.server
import json
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.request

LM_HOSTS = ["livemap-a.demo.test", "livemap-b.demo.test"]


def live_map_ui(pg, ctx):
    allow.append(re.compile(r"\[livemap/failure\].*api/stats/livemap"))  # the failure step aborts this request on purpose
    base = int(args.url.rsplit(":", 1)[1].split("/")[0])
    proxy_port, up_ports = base + 1, [base + 2, base + 3]

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/slow"):
                time.sleep(1.2)  # a request that stays "active" for a while
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    servers = []
    for p in up_ports:
        srv = S(("127.0.0.1", p), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)

    def get(path):
        return pg.evaluate("p => new Promise(res => $.getJSON(p, r => res(r)).fail(e => res({error: 'http ' + e.status})))", path)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    ctx_tls = ssl.create_default_context()
    ctx_tls.check_hostname = False
    ctx_tls.verify_mode = ssl.CERT_NONE
    scheme = {"v": None}

    def hit(host, path="/"):
        for sch in ([scheme["v"]] if scheme["v"] else ["http", "https"]):
            r = urllib.request.Request("%s://127.0.0.1:%d%s" % (sch, proxy_port, path), headers={"Host": host})
            try:
                x = urllib.request.urlopen(r, timeout=8, context=ctx_tls)
                scheme["v"] = sch
                return x.status
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                if e.code == 400 and "HTTPS server" in body:
                    continue
                scheme["v"] = sch
                return e.code
            except Exception:
                continue
        return 0

    stop = threading.Event()

    def traffic():
        # two phases of different height so average and peak differ: 12 s at 8 req/s, then a burst of 40 req/s; one slow request
        # in five so some are always in flight. Rule A (limited to 5 req/s per client) gets two thirds of it, so it is rate-limited.
        n, t_start = 0, time.time()
        while not stop.is_set():
            rps = 8 if time.time() - t_start < 12 else 40
            host = LM_HOSTS[0] if n % 3 else LM_HOSTS[1]
            threading.Thread(target=hit, args=(host, "/slow" if n % 5 == 0 else "/"), daemon=True).start()
            n += 1
            time.sleep(1.0 / rps)

    def live():
        return get("/api/stats/livemap")

    def frame():
        for f in pg.frames:
            if "trafficFlowDiagram" in f.url:
                return f
        return None

    def poll_count(ms):
        n = {"c": 0}
        h = lambda r: n.__setitem__("c", n["c"] + (1 if "/api/stats/livemap" in r.url else 0))
        pg.on("request", h)
        pg.wait_for_timeout(ms)
        pg.remove_listener("request", h)
        return n["c"]

    try:
        current["page"] = "livemap/seed"
        for i, h in enumerate(LM_HOSTS):
            post("/api/proxy/del", {"ep": h})
            r = post("/api/proxy/add", {"type": "host", "rootname": h, "ep": "127.0.0.1:%d" % up_ports[i], "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
            if isinstance(r, dict) and r.get("error"):
                fail("livemap", f"seeding {h} failed: {r}")
        # rule A gets a host level rate limit (5 req/s per client, burst 10) so the Tune panel has a busiest client to show
        r = post("/api/proxy/edit", {"rootname": LM_HOSTS[0], "rate": "true", "ratenum": "5", "rateburst": "10"})
        if isinstance(r, dict) and r.get("error"):
            fail("livemap", f"enabling the rate limit failed: {r}")
        pg.wait_for_timeout(800)
        if hit(LM_HOSTS[0]) != 200:
            fail("livemap", "the seeded rule does not reach its upstream through the proxy port (is it UI port + 1?)")
            return

        # ---- API: warm-up, then numbers rise with traffic ----
        current["page"] = "livemap/api"
        d0 = live()
        if "totalRps" not in d0 or "proxies" not in d0:
            fail("livemap", f"unexpected /api/stats/livemap answer: {d0}")
            return
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("localStorage.removeItem('dunree_trafficflow_mode'); localStorage.removeItem('dunree_trafficflow_anim'); localStorage.removeItem('dunree_status_diagram')")
        pg.goto(args.url + "/#status", wait_until="networkidle")
        pg.wait_for_selector("#trafficFlowDiagram")
        pg.wait_for_timeout(1500)
        fr = frame()
        if fr is None:
            fail("livemap", "traffic map iframe not found")
            return
        # Live is the default
        if fr.evaluate("document.getElementById('mode-live').getAttribute('aria-pressed')") != "true":
            fail("livemap", "Live must be the default mode")

        # the map polls only while it is on screen: bring it into view
        pg.locator("#trafficFlowDiagram").scroll_into_view_if_needed()
        # idle first: everything zero, edges grey and static. The rate is averaged over 10 s, so let the seeding requests age out.
        pg.wait_for_timeout(13000)
        d = live()
        if d.get("totalRps", 1) != 0 or d.get("totalInFlight", 1) != 0:
            fail("livemap", f"nothing is flowing, but the API says {d.get('totalRps')} req/s / {d.get('totalInFlight')} active")
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        if not re.search(r"Live: 0 req/s, 0 active", txt):
            fail("livemap", f"the strip must say 'Live: 0 req/s, 0 active' when idle, got {txt!r}")
        if fr.evaluate("flowAnim.length") != 0:
            fail("livemap", "idle map: no edge may animate")
        if fr.evaluate("document.querySelectorAll('.flow-edge:not(.flow-edge-idle):not(.flow-edge-disabled)').length") != 0:
            fail("livemap", "idle map: every edge must be grey")
        pg.wait_for_selector("#trafficFlowDiagram")
        shot("livemap-idle-light.png")

        # ---- traffic: numbers rise ----
        current["page"] = "livemap/traffic"
        t = threading.Thread(target=traffic, daemon=True)
        t.start()
        best_rps, best_active, best_rule = 0, 0, 0
        for _ in range(14):
            pg.wait_for_timeout(1000)
            d = live()
            best_rps = max(best_rps, d.get("totalRps", 0))
            best_active = max(best_active, d.get("totalInFlight", 0))
            for p in d.get("proxies", []):
                if p["domain"] in LM_HOSTS:
                    best_rule = max(best_rule, p.get("rps", 0))
        if best_rps < 5:
            fail("livemap", f"total req/s must rise with traffic (about 25 sent), best {best_rps:.1f}")
        if best_rule < 3:
            fail("livemap", f"per rule req/s must rise with traffic, best {best_rule:.1f}")
        if best_active < 1:
            fail("livemap", "the in-flight count never rose above 0 although slow requests were running")
        pg.wait_for_timeout(2500)
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        m = re.search(r"Live: ([\d.<K]+) req/s, (\d+) active", txt)
        if not m or m.group(1) in ("0", "<0.1"):
            fail("livemap", f"the strip must show the live rate while traffic flows, got {txt!r}")
        if fr.evaluate("flowAnim.length") < 2:
            fail("livemap", "with traffic the busy edges must animate")
        if fr.evaluate("document.getElementById('live-dot').className") != "fresh":
            fail("livemap", "the pulse dot must pulse while the data is fresh")
        nodes = fr.evaluate("Array.from(document.querySelectorAll('.proxy-node .node-count')).map(e => e.textContent)")
        if not any(re.match(r"^[\d.K]+ req/s$", x) and not x.startswith("0 ") for x in nodes):
            fail("livemap", f"a proxy node badge must show a req/s value, got {nodes}")
        shot("livemap-traffic-light.png")
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(1200)
        shot("livemap-traffic-dark.png")
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(1500)
        shot("livemap-traffic-390.png")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("toggleTheme()")

        # ---- traffic stops: falls to zero, edges static ----
        current["page"] = "livemap/stop"
        stop.set()
        t.join(timeout=5)
        pg.wait_for_timeout(3000)  # slow requests finish
        fell = False
        for _ in range(18):
            pg.wait_for_timeout(1000)
            d = live()
            if d.get("totalRps", 1) == 0 and d.get("totalInFlight", 1) == 0:
                fell = True
                break
        if not fell:
            fail("livemap", f"after the traffic stopped the live numbers must fall to 0 within the window, got {d.get('totalRps')} req/s / {d.get('totalInFlight')} active")
        pg.wait_for_timeout(3500)
        # ---- Tune: avg / peak per rule and the busiest client against the limit, from the real traffic above ----
        current["page"] = "livemap/tune"
        tn = get("/api/stats/livetune?window=5m")
        tot = tn.get("total", {})
        if not (tot.get("peak", 0) >= 10 and 0 < tot.get("avg", 0) < tot.get("peak", 0)):
            fail("livemap", f"tune: the total peak must be well above the average after a burst: {tot}")
        ra = [r for r in tn.get("rules", []) if r["domain"] == LM_HOSTS[0]]
        rb = [r for r in tn.get("rules", []) if r["domain"] == LM_HOSTS[1]]
        if not ra or not rb:
            fail("livemap", f"tune: both seeded rules must be listed: {[r['domain'] for r in tn.get('rules', [])]}")
        else:
            la = ra[0]["limiter"]
            if not la.get("enabled") or la.get("rate") != 5 or not la.get("busiest") or la["busiest"].get("rps", 0) < 4:
                fail("livemap", f"tune: rule A has a limit of 5 req/s and a client above it: {la}")
            if la.get("denied", 0) < 1:
                fail("livemap", f"tune: requests over the limit must be counted as rate-limited: {la}")
            if rb[0]["limiter"].get("enabled") or rb[0]["limiter"].get("busiest"):
                fail("livemap", f"tune: rule B has no rate limit, so no per-client numbers may be reported: {rb[0]['limiter']}")
            if not ra[0]["stats"]["peak"] > ra[0]["stats"]["avg"] > 0:
                fail("livemap", f"tune: rule A peak must exceed its average: {ra[0]['stats']}")
        card = pg.locator(".diagramCard")
        pg.click("#diagramTuneBtn")
        pg.wait_for_selector("#tunePanel .tuneRow:not(.tuneHead)", timeout=8000)
        pg.click("#tunePanel .tuneWin button:nth-child(3)")  # 5 min
        pg.wait_for_timeout(1500)
        ptxt = pg.evaluate("document.getElementById('tunePanel').innerText")
        if LM_HOSTS[0] not in ptxt or "127.0.0.1" not in ptxt or "req/s" not in ptxt or "No rate limit" not in ptxt:
            fail("livemap", f"tune panel content: {ptxt!r}")
        if "per-client" not in ptxt.lower() and "Per-client" not in ptxt:
            fail("livemap", "tune panel must say that per-client rates need a rate limit")
        if pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth") > 2:
            fail("livemap", "tune panel makes the page overflow horizontally")
        card.scroll_into_view_if_needed()
        card.screenshot(path=os.path.join(args.out, "livemap-tune-light.png"))
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(1200)
        card.screenshot(path=os.path.join(args.out, "livemap-tune-dark.png"))
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(1500)
        card.scroll_into_view_if_needed()
        card.screenshot(path=os.path.join(args.out, "livemap-tune-390.png"))
        if pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth") > 2:
            fail("livemap", "tune panel at 390px makes the page overflow horizontally")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("toggleTheme()")
        # polling of the panel stops when it is closed
        pg.click("#diagramTuneBtn")
        pg.wait_for_timeout(500)
        n = {"c": 0}
        h2 = lambda rq: n.__setitem__("c", n["c"] + (1 if "/api/stats/livetune" in rq.url else 0))
        pg.on("request", h2)
        pg.wait_for_timeout(7000)
        pg.remove_listener("request", h2)
        if n["c"] != 0:
            fail("livemap", "a closed Tune panel must not poll")
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        if "0 req/s, 0 active" not in txt:
            fail("livemap", f"the strip must fall back to 0 req/s, 0 active, got {txt!r}")
        if fr.evaluate("flowAnim.length") != 0:
            fail("livemap", "after the traffic stopped no edge may animate")
        blank = fr.evaluate("""(() => { const c = document.getElementById('flow-canvas'); const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
            for (let i = 3; i < d.length; i += 4) if (d[i]) return false; return true })()""")
        if not blank:
            fail("livemap", "after the traffic stopped nothing may be drawn on the dash canvas")
        shot("livemap-idle2-light.png")
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(1200)
        shot("livemap-idle-dark.png")
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(1500)
        shot("livemap-idle-390.png")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(500)

        # ---- Today mode, remembered ----
        current["page"] = "livemap/today"
        fr.evaluate("document.getElementById('mode-today').click()")
        pg.wait_for_timeout(800)
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        if not txt.startswith("Today:"):
            fail("livemap", f"Today mode strip, got {txt!r}")
        if fr.evaluate("localStorage.getItem('dunree_trafficflow_mode')") != "today":
            fail("livemap", "the mode must be remembered in the browser")
        if poll_count(5000) != 0:
            fail("livemap", "Today mode must not poll /api/stats/livemap")
        if not fr.evaluate("Array.from(document.querySelectorAll('.proxy-node .node-count')).some(e => / req$/.test(e.textContent))"):
            fail("livemap", "Today mode must show the cumulative request counts")
        shot("livemap-today-light.png")
        pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(1200)
        shot("livemap-today-dark.png")
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(1500)
        shot("livemap-today-390.png")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("toggleTheme()")
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(1500)
        fr = frame()
        if fr.evaluate("document.getElementById('mode-today').getAttribute('aria-pressed')") != "true":
            fail("livemap", "Today must still be selected after a reload")
        fr.evaluate("document.getElementById('mode-live').click()")
        pg.wait_for_timeout(500)

        # ---- polling control: ~2 s while on screen; Pause and Hide stop it ----
        current["page"] = "livemap/polling"
        n = poll_count(7000)
        if n < 2 or n > 5:
            fail("livemap", f"Live mode should poll about every 2 s (7 s window), saw {n} requests")
        pg.click("#diagramAnimBtn")
        pg.wait_for_timeout(600)
        if poll_count(6000) != 0:
            fail("livemap", "Pause animation must stop the live polling")
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        if "paused" not in txt.lower() or fr.evaluate("document.getElementById('live-dot').className") == "fresh":
            fail("livemap", f"paused: the strip must say so and the dot must not pulse, got {txt!r}")
        pg.click("#diagramAnimBtn")
        pg.wait_for_timeout(2500)
        if poll_count(5000) < 1:
            fail("livemap", "Resume must restart the live polling")
        pg.click("#diagramHideBtn")
        pg.wait_for_timeout(800)
        if poll_count(5000) != 0:
            fail("livemap", "Hide must stop all traffic map requests")
        pg.click("#diagramShowLink")
        pg.wait_for_timeout(1500)

        # ---- failure: the strip says so, the dot is not green ----
        current["page"] = "livemap/failure"
        fr = frame()
        pg.route("**/api/stats/livemap*", lambda route: route.abort())
        pg.wait_for_timeout(5000)
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        if "Live data unavailable" not in txt or fr.evaluate("document.getElementById('live-dot').className") == "fresh":
            fail("livemap", f"a failing endpoint must show 'Live data unavailable', got {txt!r}")
        shot("livemap-unavailable-light.png")
        pg.unroute("**/api/stats/livemap*")
        pg.wait_for_timeout(4500)
        txt = fr.evaluate("document.getElementById('live-text').textContent")
        if "Live:" not in txt:
            fail("livemap", f"the strip must recover when the endpoint answers again, got {txt!r}")

        # ---- reduced motion: no moving dashes even with traffic ----
        current["page"] = "livemap/reduced-motion"
        pg.emulate_media(reduced_motion="reduce")
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(1500)
        fr = frame()
        if fr.evaluate("flowRunning()"):
            fail("livemap", "prefers-reduced-motion: the dashes must not run")
        pg.emulate_media(reduced_motion="no-preference")

        # ---- dry run: the limit counts what it would reject, blocks nothing; switched off it rejects ----
        current["page"] = "livemap/dryrun"
        stop.set()
        pg.wait_for_timeout(1500)
        r = post("/api/proxy/edit", {"rootname": LM_HOSTS[0], "rate": "true", "ratenum": "1", "rateburst": "2", "ratedry": "true"})
        if isinstance(r, dict) and r.get("error"):
            fail("livemap", f"enabling the dry run failed: {r}")
        pg.wait_for_timeout(2500)
        # sustained traffic, 5 req/s for 12 s from one client against a limit of 1 req/s: the sampler reads the per client counters
        # every 5 s and idle buckets are swept after about 2 s, so a burst shorter than that can be missed (a known limit)
        codes = []
        for _ in range(60):
            codes.append(hit(LM_HOSTS[0]))
            time.sleep(0.2)
        if 429 in codes or codes.count(200) != 60:
            fail("livemap", f"dry run: no request may be blocked, got status codes {sorted(set(codes))} ({codes.count(429)} x 429)")
        pg.wait_for_timeout(1500)
        ra = [x for x in get("/api/stats/livetune?window=1m").get("rules", []) if x["domain"] == LM_HOSTS[0]]
        lim = ra[0]["limiter"] if ra else {}
        if not lim.get("dryRun") or lim.get("denied", 0) < 10:
            fail("livemap", f"dry run: tune must report dryRun and the requests that would have been limited: {lim}")
        pg.evaluate("localStorage.removeItem('dunree_trafficflow_mode')")
        pg.goto(args.url + "/#status", wait_until="networkidle")
        pg.wait_for_selector("#diagramTuneBtn")
        pg.click("#diagramTuneBtn")
        pg.wait_for_selector("#tunePanel .tuneRow:not(.tuneHead)", timeout=8000)
        pg.click("#tunePanel .tuneWin button:nth-child(2)")  # 1 min
        pg.wait_for_timeout(800)
        ptxt = pg.evaluate("document.getElementById('tunePanel').innerText")
        if "Dry run" not in ptxt or "would have been rate-limited" not in ptxt:
            fail("livemap", f"dry run: the Tune panel must say that nothing is blocked and how many requests would have been limited: {ptxt!r}")
        card = pg.locator("#tunePanel")
        card.scroll_into_view_if_needed()
        card.screenshot(path=os.path.join(args.out, "livemap-dryrun-light.png"))
        r = post("/api/proxy/edit", {"rootname": LM_HOSTS[0], "ratedry": "false"})
        if isinstance(r, dict) and r.get("error"):
            fail("livemap", f"turning the dry run off failed: {r}")
        pg.wait_for_timeout(3500)
        codes = [hit(LM_HOSTS[0]) for _ in range(25)]
        if codes.count(429) < 10:
            fail("livemap", f"dry run off: the limit must reject again, got {codes.count(429)} x 429 of 25")
    finally:
        stop.set()
        for h in LM_HOSTS:
            post("/api/proxy/del", {"ep": h})
        for srv in servers:
            srv.shutdown()
        try:
            pg.unroute("**/api/stats/livemap*")
        except Exception:
            pass
