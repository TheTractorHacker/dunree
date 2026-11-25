#!/usr/bin/env python3
"""Regenerate the screenshots of docs/img/screenshots/ from a throw-away Dunree with demo data.

    PY=<python with playwright + chromium> PORT=25600 tools/screenshots/run.sh           # build, start, seed, capture
    python capture.py --bin /path/to/dunree --port 25600 [--minutes 30] [--only NAME,...]  # the same with a prebuilt program
    python capture.py --bin ... --serve        # start and seed the demo and keep it running, to look at it by hand
    python capture.py --attach URL [--only ..] # take pictures of a demo started with --serve
    python capture.py --docs-only              # only rewrite the README section and the gallery page from SHOTS

What it does:
  1. starts Dunree instances in a temp dir (own conf, database and ports; never a real configuration):
       demo   the instance the pictures are taken of. It has authentication: the script takes the first-start page,
              creates the administrator there, takes the login page and signs in. It is also the Fleet hub
       edge-* three more instances (-noauth) that join the hub, so that the Fleet page has nodes to show
  2. starts the fake backends on 127.0.0.0/8: small upstream web servers, a fake CrowdSec Local API (the FakeLAPI of
     tools/ui-smoke/crowdsec_smoke.py) and a local add-on index made and signed with tools/addon-store
  3. seeds demo data through the admin API (sites under example.com / example.test, certificates made with openssl,
     rules, WAF, auto-ban, bot rules, CrowdSec, error pages, a Fleet roll-out) and sends demo traffic through the proxy
     port for --minutes, with visitor addresses from the documentation ranges and a fixed list of public resolver
     addresses (see VISITORS)
  4. takes the pictures listed in SHOTS (1440 x 900, device scale factor 2; one at phone width). A picture is only
     taken when the page shows what MUST lists for it and shows no toast, no empty or loading state, and neither the
     name nor an address of the machine (the host name is replaced in the answers of the admin API, see mask_host)
  5. reduces each picture to an 8 bit palette PNG, writes them and manifest.json to --out, and rewrites the
     "Screenshots" section of README.md and docs/img/screenshots/README.md
It is idempotent: every run starts from an empty temp dir, writes exactly the files of SHOTS and removes PNG files in
--out that are no longer in SHOTS. Numbers, dates and charts differ from run to run (they are live data), so the
bytes of the pictures do too.

Nothing here reads a real configuration, and no name or address of a real network is used: hosts are example.com and
example.test, upstreams are loopback addresses, visitor addresses are listed below. Needs: python 3.9+, playwright with
chromium, openssl, a Go toolchain (for the add-on index), Linux (loopback addresses other than 127.0.0.1 are used for
the upstreams). tools/screenshots/test_screenshots.py checks the result without a browser."""

import argparse
import base64
import http.client
import importlib.util
import json
import os
import random
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
DEFAULT_OUT = os.path.join(ROOT, "docs", "img", "screenshots")
W, H, SCALE = 1440, 900, 2
PHONE_W, PHONE_H = 390, 844

# ---------------------------------------------------------------------------------------------------------------------
# What is captured. name -> file name; caption and alt are used by the README and the docs index (tools/screenshots/
# test_screenshots.py checks that the three agree). "readme": shown in the top-level README.
# ---------------------------------------------------------------------------------------------------------------------
SHOTS = [
    {"name": "status", "title": "Status", "readme": True,
     "caption": "Status: is the proxy running, how much traffic it handles and what needs attention."},
    {"name": "status-dark", "title": "Status, dark theme", "readme": True,
     "caption": "The same page in the dark theme. Every page has both."},
    {"name": "sites", "title": "HTTP Proxy", "readme": True,
     "caption": "Sites > HTTP Proxy: every host name, where it is sent, its tags, protection and live state."},
    {"name": "site-editor", "title": "Edit site: upstreams and load balancing", "readme": True,
     "caption": "Edit site: several upstream servers behind one host name, with weights, health and fallback."},
    {"name": "certificates", "title": "Certificates", "readme": True,
     "caption": "Certificates: what each certificate covers, who issued it and when it expires."},
    {"name": "security-overview", "title": "Security Overview", "readme": True,
     "caption": "Security > Security Overview: what protects the sites, with a recommendation for each gap."},
    {"name": "security-center", "title": "Security Center", "readme": False,
     "caption": "Security Center: deployment role, network exposure, auto-ban, bots, admin accounts and the audit log."},
    {"name": "waf", "title": "WAF", "readme": True,
     "caption": "Security > WAF: the web application firewall (OWASP Core Rule Set), its mode per site and what it stopped."},
    {"name": "rules", "title": "Rules", "readme": True,
     "caption": "Security > Rules: when a request matches, block it, challenge it, limit its rate or only log it."},
    {"name": "crowdsec", "title": "CrowdSec", "readme": True,
     "caption": "Security Center > CrowdSec: Dunree as a CrowdSec bouncer, with the decisions that are loaded and what they matched."},
    {"name": "statistics", "title": "Statistics", "readme": True,
     "caption": "Traffic > Statistics: requests, errors, blocked requests and visitors, in total and for each site."},
    {"name": "statistics-visitors", "title": "Statistics: visitors and devices", "readme": False,
     "caption": "Further down the Statistics page: countries, the most active addresses, referring sites, devices and browsers."},
    {"name": "uptime", "title": "Uptime Monitor", "readme": True,
     "caption": "Traffic > Uptime Monitor: the upstream servers, checked every few minutes."},
    {"name": "addons-empty", "title": "Add-ons, no source", "readme": False,
     "caption": "System > Add-ons on a new install: no store is built in, you add a source yourself."},
    {"name": "addons", "title": "Add-ons with a local index", "readme": True,
     "caption": "System > Add-ons with a signed index from a local folder."},
    {"name": "fleet", "title": "Fleet", "readme": True,
     "caption": "Fleet & HA > Fleet: one Dunree as the hub of several others, with groups and staged roll-out."},
    {"name": "cluster", "title": "Cluster / HA", "readme": False,
     "caption": "Fleet & HA > Cluster / HA: the role of this node."},
    {"name": "error-pages", "title": "Error pages", "readme": True,
     "caption": "Sites > Error pages: your own texts, colours and HTML for the pages Dunree shows, with a preview."},
    {"name": "about", "title": "About Dunree", "readme": True,
     "caption": "System > Utilities > About Dunree: version, publisher, licence, source code and the project Dunree is based on."},
    {"name": "setup", "title": "First start", "readme": False,
     "caption": "First start: the page that creates the administrator account."},
    {"name": "login", "title": "Login", "readme": True,
     "caption": "The login page."},
    {"name": "status-phone", "title": "Status on a phone", "readme": True, "phone": True,
     "caption": "The Status page at 390 px. The whole interface works at phone width."},
]

# ---------------------------------------------------------------------------------------------------------------------
# Demo data. Host names: example.com / example.test (RFC 2606 / 6761). Upstreams: loopback addresses of this machine.
# ---------------------------------------------------------------------------------------------------------------------
# name, loopback address, preferred port, kind
UPSTREAMS = [
    ("web-1", "127.0.10.11", 8080, "web"), ("web-2", "127.0.10.12", 8080, "web"), ("web-3", "127.0.10.13", 8080, "web"),
    ("api-1", "127.0.10.21", 9000, "api"), ("api-2", "127.0.10.22", 9000, "api"),
    ("grafana", "127.0.10.31", 3001, "web"), ("git", "127.0.10.32", 3002, "web"), ("wiki", "127.0.10.33", 8090, "web"),
    ("media", "127.0.10.34", 8096, "web"), ("mail", "127.0.10.35", 8025, "web"), ("staging", "127.0.10.41", 8080, "web"),
]
DOWN_UPSTREAM = "127.0.10.49:8080"  # nothing listens here: one site that is down, as a real install has now and then

# host, [upstream names], tags, extra options
SITES = [
    ("www.example.com", ["web-1", "web-2", "web-3"], "web,prod", {"alias": ["example.com"], "sticky": True}),
    ("api.example.com", ["api-1", "api-2"], "api,prod", {"rate": 600}),
    ("app.example.com", ["web-1", "web-2"], "web,prod", {}),
    ("grafana.example.com", ["grafana"], "internal,monitoring", {}),
    ("git.example.com", ["git"], "internal,dev", {}),
    ("wiki.example.com", ["wiki"], "internal", {}),
    ("media.example.com", ["media"], "media", {}),
    ("mail.example.com", ["mail"], "internal", {}),
    ("staging.example.test", ["staging"], "staging", {}),
    ("legacy.example.test", [None], "staging", {}),
]
SITE_WEIGHT = {"www.example.com": 34, "api.example.com": 26, "app.example.com": 12, "grafana.example.com": 5, "git.example.com": 7,
               "wiki.example.com": 5, "media.example.com": 6, "mail.example.com": 2, "staging.example.test": 2, "legacy.example.test": 1}

# Visitor addresses of the demo traffic, sent in X-Forwarded-For through a trusted proxy (127.0.0.1). The first group
# are the documentation ranges (RFC 5737 / 3849), which belong to no country. For the country map the second group is
# needed: addresses of public DNS resolvers and other public infrastructure, which are published by their operators
# and identify no person. (weight, address)
VISITORS = [
    (6, "192.0.2.14"), (5, "192.0.2.77"), (5, "198.51.100.23"), (4, "198.51.100.140"), (4, "203.0.113.9"), (3, "203.0.113.201"),
    (3, "2001:db8::1f"), (2, "2001:db8:a::52"),
    (9, "9.9.9.9"), (8, "1.1.1.1"), (7, "8.8.8.8"), (5, "208.67.222.222"), (4, "64.6.64.6"),          # US / anycast
    (6, "185.228.168.9"), (5, "194.242.2.2"), (4, "193.110.81.0"), (4, "84.200.69.80"), (3, "80.80.80.80"),  # Europe
    (3, "195.46.39.39"), (3, "77.88.8.8"), (3, "156.154.70.1"), (2, "101.101.101.101"), (2, "168.95.1.1"),
    (2, "114.114.114.114"), (2, "223.5.5.5"), (2, "210.220.163.82"), (2, "202.12.27.33"), (2, "200.160.0.8"),
    (2, "196.216.2.6"), (1, "203.50.2.71"), (1, "164.124.101.2"), (1, "200.221.11.100"),
]
CROWDSEC_BANS = [  # id, address, type, origin, scenario: all in the documentation ranges
    (1, "203.0.113.77", "ban", "crowdsec", "crowdsecurity/http-probing"),
    (2, "203.0.113.78", "ban", "crowdsec", "crowdsecurity/http-bad-user-agent"),
    (3, "198.51.100.200", "ban", "crowdsec", "crowdsecurity/ssh-bf"),
    (4, "198.51.100.201", "captcha", "crowdsec", "crowdsecurity/http-crawl-non_statics"),
    (5, "203.0.113.90", "ban", "CAPI", "crowdsecurity/community-blocklist"),
    (6, "203.0.113.91", "ban", "CAPI", "crowdsecurity/community-blocklist"),
    (7, "192.0.2.200", "ban", "cscli", "manual 'ban' from 'demo'"),
    (8, "203.0.113.120", "ban", "lists", "firehol_level1"),
]
USER_AGENTS = [
    (30, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    (14, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"),
    (12, "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"),
    (14, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"),
    (10, "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
    (6, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
    (4, "curl/8.9.1"), (3, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    (2, "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"), (2, "python-requests/2.32.3"),
]
REFERERS = [(40, ""), (16, "https://www.google.com/"), (8, "https://duckduckgo.com/"), (7, "https://www.example.com/"),
            (5, "https://www.bing.com/"), (4, "https://news.example.org/story/42"), (3, "https://forum.example.net/t/1337")]
PATHS = {
    "web": [(30, "/"), (10, "/about"), (9, "/pricing"), (8, "/blog/"), (6, "/blog/hello-world"), (6, "/assets/app.css"), (6, "/assets/app.js"),
            (4, "/favicon.ico"), (4, "/contact"), (3, "/login"), (2, "/missing-page"), (1, "/old/link")],
    "api": [(30, "/v1/items"), (14, "/v1/items/42"), (10, "/v1/users/me"), (8, "/v1/search?q=proxy"), (6, "/health"), (2, "/v1/unknown"), (1, "/v1/fail")],
}
ATTACKS = ["/?id=1%27%20OR%20%271%27=%271", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/../../etc/passwd", "/index.php?page=../../../../etc/passwd",
           "/?cmd=cat%20/etc/passwd;id", "/wp-login.php", "/.env", "/.git/config", "/admin/config.php?x=1%20UNION%20SELECT%20password%20FROM%20users"]


def log(msg):
    print("[screenshots] " + msg, flush=True)


def pick(rng, weighted):
    total = sum(w for w, _ in weighted)
    x = rng.uniform(0, total)
    for w, v in weighted:
        x -= w
        if x <= 0:
            return v
    return weighted[-1][1]


# ---------------------------------------------------------------------------------------------------------------------
# Fake backends
# ---------------------------------------------------------------------------------------------------------------------
class _Srv(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_upstream(name, addr, port, kind):
    """A small upstream web server. Returns (server, "addr:port"). Falls back to 127.0.0.1 and a free port when the
    preferred address cannot be bound (another program on that port, or a system without 127.0.0.0/8 loopback)."""

    class Hd(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def do_GET(self):
            p = self.path.split("?")[0]
            if p in ("/missing-page", "/old/link", "/v1/unknown"):
                return self._send(404, "not found")
            if p == "/v1/fail":
                return self._send(500, "demo failure")
            if kind == "api":
                return self._send(200, json.dumps({"server": name, "path": p, "items": list(range(20))}), "application/json")
            self._send(200, "<!doctype html><title>%s</title><h1>%s</h1><p>Demo upstream of the Dunree screenshots.</p>%s" % (name, name, "<p>lorem ipsum</p>" * 40))

        do_HEAD = do_GET
        do_POST = do_GET

    for a, p in ((addr, port), ("127.0.0.1", 0)):
        try:
            srv = _Srv((a, p), Hd)
        except OSError:
            continue
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, "%s:%d" % (a, srv.server_address[1])
    raise RuntimeError("cannot start the upstream " + name)


def load_fake_lapi():
    """The FakeLAPI class of the UI smoke harness (tools/ui-smoke/crowdsec_smoke.py); the module only defines things."""
    spec = importlib.util.spec_from_file_location("crowdsec_smoke", os.path.join(ROOT, "tools", "ui-smoke", "crowdsec_smoke.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FakeLAPI


# ---------------------------------------------------------------------------------------------------------------------
# Dunree instances
# ---------------------------------------------------------------------------------------------------------------------
class Instance:
    def __init__(self, binary, base, name, port, proxy_port, noauth=False, extra=()):
        self.name, self.port, self.proxy_port = name, port, proxy_port
        self.url = "http://127.0.0.1:%d" % port
        self.dir = os.path.join(base, name)
        os.makedirs(os.path.join(self.dir, "conf"), exist_ok=True)
        self.args = [binary, "-offline", "-mdns=false", "-port", "127.0.0.1:%d" % port, "-default_inbound_port", str(proxy_port),
                     "-conf", "./conf", "-dbpath", "./sys.db"] + (["-noauth"] if noauth else []) + list(extra)
        self.proc = None

    def start(self):
        self.logf = open(os.path.join(self.dir, "dunree.log"), "ab")
        self.proc = subprocess.Popen(self.args, cwd=self.dir, stdout=self.logf, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(120):
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
                c.request("GET", "/login.html")
                c.getresponse().read()
                c.close()
                return self
            except OSError:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.5)
        raise RuntimeError("the instance %s did not start, see %s" % (self.name, os.path.join(self.dir, "dunree.log")))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()


API_JS = """([u, d, m]) => new Promise(res => $.cjax({url: u, method: m || 'POST', data: d,
    success: r => res(r), error: x => res({error: 'http ' + x.status + ' ' + (x.responseText || '').slice(0, 200)})}))"""
JSON_JS = """([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', contentType: 'application/json', data: JSON.stringify(d),
    success: r => res(r), error: x => res({error: 'http ' + x.status + ' ' + (x.responseText || '').slice(0, 200)})}))"""


class Admin:
    """Calls the admin API of an instance from a page of it (the page has the CSRF token)."""

    def __init__(self, ctx, url):
        self.url = url
        self.pg = ctx.new_page()
        self.pg.goto(url + "/")
        self.pg.wait_for_function("typeof $ !== 'undefined' && !!$.cjax", timeout=30000)

    def post(self, path, data=None, must=True):
        r = self.pg.evaluate(API_JS, [path, data or {}])
        if must and isinstance(r, dict) and r.get("error"):
            raise RuntimeError("%s %s: %s" % (path, json.dumps(data)[:200], r["error"]))
        return r

    def post_json(self, path, data, must=True):
        r = self.pg.evaluate(JSON_JS, [path, data])
        if must and isinstance(r, dict) and r.get("error"):
            raise RuntimeError("%s: %s" % (path, r["error"]))
        return r

    def get(self, path):
        return self.pg.evaluate("p => fetch(p).then(r => r.json())", path)

    def upload_cert(self, name, pem, key):
        return self.pg.evaluate("""async ([cn, pem, key]) => {
            const tok = document.querySelector('meta[name="dunree.csrf.Token"], meta[name="zoraxy.csrf.Token"]').content, out = [];
            for (const [kt, body] of [['pub', pem], ['pri', key]]) {
                const f = new FormData(); f.append('file', new Blob([body]), kt);
                const r = await fetch('/api/cert/upload?ktype=' + kt + '&domain=' + cn, {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f});
                out.push(r.status);
            }
            return out; }""", [name, pem, key])


def make_cert(tmp, name, sans, days, issuer_cn=None):
    """A certificate for the demo sites, made with openssl. With issuer_cn it is signed by a demo CA of that name, so
    that the Certificates page shows an issuer other than the subject."""
    key, crt = os.path.join(tmp, name + ".key"), os.path.join(tmp, name + ".pem")
    san = "subjectAltName=" + ",".join("DNS:" + s for s in sans)
    run = lambda a: subprocess.run(a, check=True, capture_output=True)
    if not issuer_cn:
        run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt,
             "-subj", "/CN=" + sans[0], "-addext", san, "-days", str(days)])
    else:
        cakey, cacrt = os.path.join(tmp, "demo-ca.key"), os.path.join(tmp, "demo-ca.pem")
        if not os.path.exists(cacrt):
            run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", cakey, "-out", cacrt,
                 "-subj", "/O=Example Demo CA/CN=" + issuer_cn, "-days", "3650"])
        csr, ext = os.path.join(tmp, name + ".csr"), os.path.join(tmp, name + ".ext")
        with open(ext, "w") as f:
            f.write(san + "\n")
        run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=" + sans[0]])
        run(["openssl", "x509", "-req", "-in", csr, "-CA", cacrt, "-CAkey", cakey, "-CAcreateserial", "-out", crt, "-days", str(days), "-extfile", ext])
    return open(crt).read(), open(key).read()


# ---------------------------------------------------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------------------------------------------------
def seed(adm, tmp, ups, lapi_port, lapi_key):
    post, get = adm.post, adm.get
    post("/api/quickstart", {"dismissed": "true"}, must=False)
    # visitor addresses arrive in X-Forwarded-For from this machine, as from a CDN or a front proxy
    post("/api/trustedproxy/add", {"ip": "127.0.0.1/32", "desc": "Front proxy (demo)"})
    post("/api/whitelist/trustProxy", {"id": "default", "enable": "true"})

    log("certificates")
    for name, sans, days, issuer in (("example.com", ["example.com", "*.example.com"], 82, "Example Demo CA R1"),
                                     ("api.example.com", ["api.example.com"], 61, "Example Demo CA R1"),
                                     ("mail.example.com", ["mail.example.com"], 12, "Example Demo CA R1"),
                                     ("example.test", ["example.test", "*.example.test"], 340, None)):
        pem, key = make_cert(tmp, name, sans, days, issuer)
        st = adm.upload_cert(name, pem, key)
        if st != [200, 200]:
            raise RuntimeError("certificate upload %s: %s" % (name, st))

    log("sites")
    for host, names, tags, opt in SITES:
        origins = [ups[n] if n else DOWN_UPSTREAM for n in names]
        post("/api/proxy/add", {"type": "host", "rootname": host, "ep": origins[0], "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false",
                                "tags": tags, "bauth": "false", "access": "default", "stickysess": "true" if opt.get("sticky") else "false",
                                "rate": "true" if opt.get("rate") else "false", "ratenum": str(opt.get("rate", 0)),
                                "enableUtm": "true", "utmURI": "", "alias": json.dumps(opt.get("alias", []))})
        for i, o in enumerate(origins[1:]):
            post("/api/proxy/upstream/add", {"ep": host, "origin": o, "tls": "false", "tlsval": "false", "respt": "0", "maxconn": "0", "active": "true"})
        if opt.get("alias"):
            post("/api/proxy/setAlias", {"ep": host, "alias": json.dumps(opt["alias"])}, must=False)
    # www.example.com: two servers share the load 3 : 2, the third is the fallback (weight 0)
    www = next((r for r in get("/api/proxy/list?type=host") if r.get("RootOrMatchingDomain") == "www.example.com"), None)
    for up, weight in zip((www or {}).get("ActiveOrigins") or [], (3, 2, 0)):
        post("/api/proxy/upstream/update", {"ep": "www.example.com", "origin": up["OriginIpOrDomain"], "active": "true",
                                            "payload": json.dumps(dict(up, Weight=weight))}, must=False)
    post("/api/redirect/add", {"redirectUrl": "old.example.com", "destUrl": "https://www.example.com", "forwardChildpath": "true", "redirectType": "301", "deviceType": "all"}, must=False)
    post("/api/redirect/add", {"redirectUrl": "docs.example.com", "destUrl": "https://wiki.example.com/docs", "forwardChildpath": "true", "redirectType": "307", "deviceType": "all"}, must=False)

    log("WAF, rules, access rules")
    pol = get("/api/waf/policy")
    post("/api/waf/policy", {"policy": json.dumps(dict(pol, Enabled=True, DefaultMode="block"))})
    adm.post_json("/api/ruleset/list/save", {"name": "office", "type": "ip", "items": ["192.0.2.0/24", "2001:db8:42::/48"]})
    for rule in (
        {"name": "Block scanners of well-known paths", "description": "Nothing here runs WordPress or leaves dot files in the web root.",
         "expression": 'http.path in ["/wp-login.php", "/xmlrpc.php", "/.env", "/.git/config"]', "action": {"type": "block", "status": 403}},
        {"name": "Block scanner user agents", "description": "Well-known attack tools, by their user agent.",
         "expression": 'http.user_agent matches "(?i)(sqlmap|nikto|masscan|zgrab|dirbuster|nmap|wpscan)"', "action": {"type": "block", "status": 403}},
        {"name": "Admin area only from the office", "description": "The /admin pages of every site.",
         "expression": 'http.path starts_with "/admin" and ip.src not in $office', "action": {"type": "block", "status": 403}},
        {"name": "Rate limit login", "description": "Two requests a second for one address, bursts of five.",
         "expression": 'http.path == "/login"', "action": {"type": "rate_limit", "rate": 2, "burst": 5, "status": 429}},
        {"name": "Redirect the old blog", "description": "",
         "expression": 'http.host == "www.example.com" and http.path starts_with "/old/"', "action": {"type": "redirect", "status": 301, "url": "/blog/"}},
        {"name": "Watch requests without a user agent", "description": "Log only, to see how many there are before blocking them.",
         "expression": 'http.user_agent == ""', "dry_run": True, "action": {"type": "log"}},
    ):
        adm.post_json("/api/ruleset/rule/create", {"site": "", "rule": dict({"dry_run": False}, **rule)})
    for ip, why in (("198.51.100.66", "Credential stuffing, 2026-11"), ("203.0.113.0/26", "Scanner network")):
        post("/api/blacklist/ip/add", {"ip": ip, "id": "default", "comment": why}, must=False)

    log("auto-ban, bot rules, notifications")
    ab = get("/api/abuse/config")
    ab["Enabled"] = True
    for d in ("exploit_block", "login_fail"):
        if d in ab.get("Detectors", {}):
            ab["Detectors"][d]["Enabled"] = True
    post("/api/abuse/setConfig", {"config": json.dumps(ab)}, must=False)
    bots = get("/api/botrules/get")["Config"]
    bots["Enabled"] = True
    for c in ("scanner", "bad_bot"):
        bots.setdefault("Categories", {})[c] = {"Enabled": True, "Action": "block"}
    post("/api/botrules/set", {"config": json.dumps(bots)}, must=False)
    # a webhook that is never called: the instance runs with -offline
    post("/api/notify/hooks", {"op": "saveWebhook", "id": "", "name": "Operations chat", "url": "https://hooks.example.com/dunree", "secret": "",
                               "enabled": "true", "template": "", "events": "certificate.renewal_failed"}, must=False)

    log("error pages")
    r = post("/api/errorpages/theme", {"enabled": "true", "theme": json.dumps({
        "ApplyToBuiltin": True, "LogoURL": "", "LogoText": "Example Ltd.", "AccentColor": "#1a56c4",
        "FooterText": "Questions? Write to support@example.com", "ShowRequestID": True, "ShowClientIP": False})}, must=False)
    if isinstance(r, dict) and r.get("error"):
        log("  the error page theme was not accepted: %s" % r["error"])
    post("/api/errorpages/template/set", {"class": "403", "title": "This page is not open to you",
                                          "message": "If you think this is a mistake, send us the reference below and we will have a look."}, must=False)
    post("/api/errorpages/template/set", {"class": "503", "title": "Back in a few minutes",
                                          "message": "We are working on this service. Nothing is lost; please try again shortly."}, must=False)

    log("CrowdSec")
    r = post("/api/crowdsec/set", {"config": json.dumps({"enabled": True, "lapiUrl": "http://127.0.0.1:%d" % lapi_port, "mode": "enforce"}), "apikey": lapi_key}, must=False)
    if isinstance(r, dict) and r.get("error"):
        log("  CrowdSec settings were not accepted: %s" % r["error"])


class Traffic:
    """Demo requests through the proxy port, in the background: Host and SNI of a demo site, the visitor address in
    X-Forwarded-For. The rate moves between about 4 and 12 requests a second so that the charts have a shape."""

    def __init__(self, proxy_port, banned=(), seed_no=1):
        self.port, self.banned = proxy_port, list(banned)
        self.rng = random.Random(seed_no)
        self.kinds = {h: ("api" if h.startswith("api.") else "web") for h, _, _, _ in SITES}
        self.hosts = [(SITE_WEIGHT[h], h) for h, _, _, _ in SITES]
        self.cx = ssl.create_default_context()
        self.cx.check_hostname = False
        self.cx.verify_mode = ssl.CERT_NONE
        self.stop_flag = threading.Event()
        self.sem = threading.Semaphore(6)
        self.sent = 0
        self.started = None
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _one(self, host, path, ip, ua, ref):
        try:
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            c = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10, context=self.cx)
            c.sock = self.cx.wrap_socket(sock, server_hostname=host)
            hd = {"Host": host, "X-Forwarded-For": ip, "User-Agent": ua, "Accept": "text/html,*/*", "Accept-Language": "en"}
            if ref:
                hd["Referer"] = ref
            c.request("GET", path, headers=hd)
            c.getresponse().read()
            c.close()
        except Exception:
            pass
        finally:
            self.sem.release()

    def _fire(self, *job):
        if self.sem.acquire(blocking=False):  # never more than six at a time: a slow machine gets fewer requests, not a queue
            self.sent += 1
            threading.Thread(target=self._one, args=job, daemon=True).start()

    def _loop(self):
        import math
        rng, i = self.rng, 0
        while not self.stop_flag.is_set():
            t = time.time() - self.started
            rate = 8 + 3 * math.sin(t / 95.0) + 1.5 * math.sin(t / 23.0) + rng.uniform(-1, 1)
            host = pick(rng, self.hosts)
            self._fire(host, pick(rng, PATHS[self.kinds[host]]), pick(rng, VISITORS), pick(rng, USER_AGENTS), pick(rng, REFERERS))
            i += 1
            if i % 45 == 7:
                self._fire(pick(rng, self.hosts[:3]), rng.choice(ATTACKS), rng.choice(["203.0.113.45", "198.51.100.99", "203.0.113.150", "192.0.2.240"]),
                           "sqlmap/1.8.4#stable (https://sqlmap.org)" if rng.random() < 0.4 else pick(rng, USER_AGENTS), "")
            if self.banned and i % 70 == 11:
                self._fire(pick(rng, self.hosts[:3]), "/", rng.choice(self.banned), pick(rng, USER_AGENTS), "")
            self.stop_flag.wait(1.0 / max(rate, 1))

    def start(self):
        self.started = time.time()
        self.thread.start()

    def stop(self):
        self.stop_flag.set()
        self.thread.join(timeout=15)


# ---------------------------------------------------------------------------------------------------------------------
# PNG: 8 bit palette (median cut in the browser, written here). Keeps a 2880 x 1800 picture at 100 to 250 KB.
# ---------------------------------------------------------------------------------------------------------------------
QUANT_JS = r"""async (b64) => {
    const bin = atob(b64), u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    const bmp = await createImageBitmap(new Blob([u8], {type: 'image/png'}));
    const w = bmp.width, h = bmp.height, cv = new OffscreenCanvas(w, h), g = cv.getContext('2d', {willReadFrequently: true});
    g.drawImage(bmp, 0, 0);
    const px = g.getImageData(0, 0, w, h).data, n = w * h;
    // histogram of exact colours
    const hist = new Map();
    for (let i = 0; i < n; i++) { const k = (px[4*i] << 16) | (px[4*i+1] << 8) | px[4*i+2]; hist.set(k, (hist.get(k) || 0) + 1); }
    let cols = Array.from(hist, ([k, c]) => ({k, c, r: k >> 16, g: (k >> 8) & 255, b: k & 255}));
    let palette;
    if (cols.length <= 256) {
        palette = cols.map(c => [c.r, c.g, c.b]);
        cols.forEach((c, i) => c.i = i);
    } else {
        // median cut over the exact colours, weighted by pixel count; the box with the largest (weight x range) is split
        const mk = list => { let lo = [255,255,255], hi = [0,0,0], wsum = 0;
            for (const c of list) { const v = [c.r, c.g, c.b]; for (let j = 0; j < 3; j++) { if (v[j] < lo[j]) lo[j] = v[j]; if (v[j] > hi[j]) hi[j] = v[j]; } wsum += c.c; }
            const rg = [hi[0]-lo[0], hi[1]-lo[1], hi[2]-lo[2]], ax = rg[1] >= rg[0] && rg[1] >= rg[2] ? 1 : (rg[0] >= rg[2] ? 0 : 2);
            return {list, w: wsum, ax, range: rg[ax], score: rg[ax] === 0 ? 0 : rg[ax] * Math.sqrt(wsum)}; };
        let boxes = [mk(cols)];
        const key = ['r', 'g', 'b'];
        while (boxes.length < 256) {
            let bi = -1, best = 0;
            for (let i = 0; i < boxes.length; i++) if (boxes[i].list.length > 1 && boxes[i].score > best) { best = boxes[i].score; bi = i; }
            if (bi < 0) break;
            const bx = boxes[bi], a = key[bx.ax];
            bx.list.sort((x, y) => x[a] - y[a]);
            let acc = 0, cut = 0; const half = bx.w / 2;
            for (; cut < bx.list.length - 1; cut++) { acc += bx.list[cut].c; if (acc >= half) { cut++; break; } }
            cut = Math.max(1, Math.min(bx.list.length - 1, cut));
            boxes.splice(bi, 1, mk(bx.list.slice(0, cut)), mk(bx.list.slice(cut)));
        }
        palette = boxes.map((bx, i) => { let r = 0, g2 = 0, b = 0, top = bx.list[0];
            for (const c of bx.list) { r += c.r * c.c; g2 += c.g * c.c; b += c.b * c.c; c.i = i; if (c.c > top.c) top = c; }
            // a box that is mostly one colour (a flat background) keeps exactly that colour
            return top.c >= bx.w * 0.6 ? [top.r, top.g, top.b] : [Math.round(r / bx.w), Math.round(g2 / bx.w), Math.round(b / bx.w)]; });
    }
    const idx = new Map(); for (const c of cols) idx.set(c.k, c.i);
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = idx.get((px[4*i] << 16) | (px[4*i+1] << 8) | px[4*i+2]);
    let s = ''; const CH = 0x8000;
    for (let i = 0; i < out.length; i += CH) s += String.fromCharCode.apply(null, out.subarray(i, i + CH));
    return {w, h, palette, data: btoa(s), colours: cols.length};
}"""


def png_chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def write_palette_png(path, w, h, palette, indices):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += indices[y * w:(y + 1) * w]
    plte = b"".join(bytes(c) for c in palette)
    data = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0)) + png_chunk(b"PLTE", plte)
            + png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + png_chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(data)
    return len(data)


def png_size(path):
    with open(path, "rb") as f:
        head = f.read(26)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(path + " is not a PNG file")
    return struct.unpack(">II", head[16:24]) + (head[25],)


class Shooter:
    def __init__(self, browser, out, only):
        self.browser, self.out, self.only = browser, out, only
        self.tool = browser.new_context().new_page()  # a blank page that only runs the quantiser
        self.done = {}

    def want(self, name):
        return not self.only or name in self.only

    def save(self, pg, name, **kw):
        raw = pg.screenshot(type="png", **kw)
        q = self.tool.evaluate(QUANT_JS, base64.b64encode(raw).decode())
        size = write_palette_png(os.path.join(self.out, name + ".png"), q["w"], q["h"], q["palette"], base64.b64decode(q["data"]))
        self.done[name] = {"width": q["w"], "height": q["h"], "bytes": size}
        log("  %s.png  %dx%d  %d KB (from %d KB, %d colours)" % (name, q["w"], q["h"], size // 1024, len(raw) // 1024, q["colours"]))


# ---------------------------------------------------------------------------------------------------------------------
# Preparing the demo (everything that changes state)
# ---------------------------------------------------------------------------------------------------------------------
ADMIN_USER, ADMIN_PASS = "admin", "demo-only-" + "x7Kq2mVp9"  # the account of the throw-away instance, nothing else
DEMO_HOSTNAME = "dunree-demo"


def machine_names():
    """What must never be visible in a picture: the name and the addresses of the machine the pictures are made on."""
    names = set()
    for n in (socket.gethostname(), socket.getfqdn()):
        if n and n not in ("localhost", DEMO_HOSTNAME) and len(n) > 2:
            names.add(n)
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout
        names.update(a for a in out.split() if not a.startswith("127.") and a != "::1")
    except Exception:
        pass
    try:
        import getpass
        names.add("/home/" + getpass.getuser())
    except Exception:
        pass
    return sorted(names)


def mask_host(ctx):
    """Dunree shows the host name of its machine on a few pages (Status > System resources, the name of a Fleet node).
    The pictures show a neutral name instead: every answer of the admin API has the real host name replaced. Nothing
    else in an answer is changed."""
    real = socket.gethostname()
    if not real or real == DEMO_HOSTNAME:
        return

    def handler(route):
        try:
            resp = route.fetch()
            body = resp.body()
        except Exception:
            return route.abort()
        if real.encode() in body:
            body = body.replace(real.encode(), DEMO_HOSTNAME.encode())
            hd = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "content-encoding")}
            return route.fulfill(status=resp.status, headers=hd, body=body)
        route.fulfill(response=resp)

    ctx.route("**/api/**", handler)


def login(pg, url):
    pg.goto(url + "/login.html")
    pg.wait_for_selector("#username", state="visible")
    pg.fill("#username", ADMIN_USER)
    pg.fill("#magic", ADMIN_PASS)
    pg.click("#loginbtn")
    pg.wait_for_url(lambda u: "login" not in u, timeout=20000)


def first_start(shooter, browser, demo):
    """The first-start page, the registration of the demo administrator and the login page."""
    ctx = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=SCALE, locale="en-GB")
    pg = ctx.new_page()
    pg.goto(demo.url + "/login.html")
    pg.wait_for_selector("#username", state="visible")
    pg.wait_for_selector("#regsiterbtn", state="visible")
    pg.wait_for_timeout(1500)
    if shooter.want("setup"):
        shooter.save(pg, "setup")
    pg.fill("#username", ADMIN_USER)
    pg.fill("#magic", ADMIN_PASS)
    pg.fill("#repeatMagic", ADMIN_PASS)
    pg.click("#regsiterbtn")
    pg.wait_for_timeout(2500)
    pg.goto(demo.url + "/login.html")
    pg.wait_for_selector("#loginbtn", state="visible")
    pg.wait_for_timeout(1500)
    if shooter.want("login"):
        shooter.save(pg, "login")
    ctx.close()


def build_addon_index(tmp):
    """A signed add-on index in a local folder, made with the tools of this repository (tools/addon-store and
    tools/plugin-index) and a key that is created here and thrown away. The add-ons are examples: their program files
    are placeholders, nothing is installed from the index."""
    if not shutil.which("go"):
        raise RuntimeError("the add-on index is made with tools/addon-store, which needs the Go toolchain (go is not on PATH)")
    src, site, keys = os.path.join(tmp, "addon-src"), os.path.join(tmp, "addons"), os.path.join(tmp, "keys")
    os.makedirs(keys)
    demo = [
        ("test.example.maintenance-page", "Maintenance page", "A friendly page for a site while its server is being worked on, switched on per site or by schedule.", "router", ["Sites"], "1.4.0"),
        ("test.example.geo-report", "Geo report", "A weekly report of where the visitors of each site come from, as a page and as CSV.", "utility", ["Statistics"], "0.9.2"),
        ("test.example.request-mirror", "Request mirror", "Copies a share of the requests of a site to a second upstream, to try out a new version with real traffic.", "router", ["Sites", "Testing"], "2.0.1"),
        ("test.example.header-inspector", "Header inspector", "Shows the request and response headers of a site as the upstream sees them.", "utility", ["Debugging"], "1.1.0"),
        ("test.example.upnp-forwarder", "UPnP port forwarder", "Asks the router of a home network to forward the ports Dunree listens on.", "utility", ["Network"], "1.0.3"),
        ("test.example.honeypot-paths", "Honeypot paths", "Answers well-known scanner paths with a slow, empty page and reports the visitor to the auto-ban.", "router", ["Security"], "0.6.0"),
    ]
    for pid, name, desc, typ, cats, ver in demo:
        d = os.path.join(src, pid.split(".")[-1])
        os.makedirs(os.path.join(d, "artifacts"))
        with open(os.path.join(d, "artifacts", "%s_linux_amd64" % pid.split(".")[-1]), "w") as f:
            f.write("placeholder program file of a demo add-on (Dunree screenshots)\n")
        with open(os.path.join(d, "addon.json"), "w") as f:
            json.dump({"id": pid, "name": name, "publisher": "Example Add-ons", "description": desc, "homepage": "https://addons.example.com/" + pid.split(".")[-1],
                       "licence": "AGPL-3.0-only", "version": ver, "api_version": 1, "min_host_version": "1.0.0", "type": typ, "categories": cats,
                       "changelog": [{"version": ver, "date": "2026-11-20", "notes": "Demo entry."}]}, f, indent=1)
    env = dict(os.environ, GOFLAGS=os.environ.get("GOFLAGS", ""))
    pem, pub = os.path.join(keys, "index.pem"), os.path.join(keys, "index.pub")
    subprocess.run(["go", "run", "sign_plugin_index.go", "-genkey", pem, pub], cwd=os.path.join(ROOT, "tools", "plugin-index"), check=True, capture_output=True, env=env)
    r = subprocess.run(["go", "run", "tools/addon-store/main.go", "-in", src, "-out", site, "-key", pem, "-skip-binary-check",
                        "-store-name", "Example add-on store", "-publisher", "Example Add-ons"], cwd=ROOT, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise RuntimeError("tools/addon-store failed: " + (r.stderr or r.stdout)[-600:])
    with open(pub) as f:
        return site, f.read()


def setup_addons(adm, tmp):
    site, pub = build_addon_index(tmp)
    if not site:
        return False
    adm.post("/api/plugins/settings", {"index_public_key": pub})
    adm.post("/api/plugins/store/sources/add", {"kind": "local", "folder": site})
    adm.post("/api/plugins/store/resync", {}, must=False)
    return True


def setup_fleet(adm, binary, tmp, P, insts):
    """The demo instance becomes a Fleet hub with two groups; three more instances join it."""
    r = adm.post("/api/cluster/config", {"role": "hub"})
    hub = lambda action, **form: adm.post("/api/fleet/hub/" + action, form)
    hub("settings", keepVersions="10", heartbeatSecs="5", healthGraceSec="30")
    hub("groupSet", name="edge-eu", scopes="access", tags="", vars=json.dumps({"region": "eu"}))
    hub("groupSet", name="edge-us", scopes="access", tags="", vars=json.dumps({"region": "us"}))
    for i, (name, group) in enumerate((("edge-dub-1", "edge-eu"), ("edge-fra-1", "edge-eu"), ("edge-nyc-1", "edge-us"))):
        node = Instance(binary, tmp, name, P + 10 + 2 * i, P + 11 + 2 * i, noauth=True, extra=["-fastgeoip=false"])
        insts.append(node)
        node.start()
        tok = hub("tokenCreate", minutes="30", name=name, group=group)["token"]
        ctx = adm.pg.context.browser.new_context()
        nadm = Admin(ctx, node.url)
        nadm.post("/api/cert/tls", {"set": "false"}, must=False)
        nadm.post("/api/fleet/node/join", {"hubUrl": adm.url, "token": tok, "fingerprint": "", "allowHttp": "true"})
        ctx.close()
    def nodes():
        n = adm.get("/api/fleet/hub/overview").get("nodes") or []
        return list(n.values()) if isinstance(n, dict) else n

    for _ in range(40):
        if len(nodes()) >= 3:
            break
        time.sleep(1)
    else:
        raise RuntimeError("the three Fleet nodes did not join the hub")
    # one published version for the European group, so that the page shows a roll-out that has happened (the nodes
    # restart themselves to apply it); the US group stays at "nothing published"
    v = adm.post("/api/fleet/hub/capture", {"note": "Access rules and blocklist, November"}, must=False)
    ver = (v or {}).get("version") if isinstance(v, dict) else None
    if isinstance(ver, dict):
        ver = ver.get("version")
    if not ver:
        log("  no version was captured (%r): the Fleet page shows the nodes without a roll-out" % (v,))
        return
    r = adm.post("/api/fleet/hub/publish", {"group": "edge-eu", "version": str(ver), "strategy": "immediate", "note": "Access rules and blocklist, November"}, must=False)
    if isinstance(r, dict) and r.get("error"):
        log("  publishing was refused: %s" % r["error"])
        return
    for _ in range(90):
        time.sleep(1)
        eu = [n for n in nodes() if n.get("group") == "edge-eu"]
        if eu and all(str(n.get("appliedVersion") or n.get("applied") or n.get("version") or "") == str(ver) for n in eu):
            return
    log("  the nodes of edge-eu had not all reported version %s after 90 s" % ver)


# ---------------------------------------------------------------------------------------------------------------------
# The pictures (reads only)
# ---------------------------------------------------------------------------------------------------------------------
# Words a picture must show before it is taken (the page has loaded its data) and words it must not show (an empty or
# loading state). A page that does not get there within a minute is an error, not a picture.
MUST = {
    "status": ["Requests / min", "Traffic over time", "84 / 100|/ 100"], "status-dark": ["Requests / min", "/ 100"], "status-phone": ["Requests / min"],
    "sites": ["www.example.com", "legacy.example.test", "req/s", "Up"], "site-editor": ["Upstreams", "Weight", "Healthy"],
    "certificates": ["mail.example.com", "days left", "Example Demo CA"], "security-overview": ["out of 100", "What is protected", "Fix these first"],
    "security-center": ["Needs attention", "Blocked today"], "waf": ["Events", "Proxy rules inspected", "Current"],
    "rules": ["Block scanners of well-known paths", "Rate limit login"], "crowdsec": ["Blocking banned addresses", "Decisions loaded", "Activity"],
    "statistics": ["distinct addresses", "www.example.com", "Successful"], "statistics-visitors": ["Countries", "Top client IPs", "Referring sites", "United States"],
    "uptime": ["Availability", "legacy.example.test", "grafana.example.com"], "addons-empty": ["No add-on store configured"],
    "addons": ["Maintenance page", "Honeypot paths", "Example Add-ons"], "fleet": ["This Dunree is the hub", "edge-dub-1", "edge-nyc-1", "Healthy"],
    "cluster": ["Cluster"], "error-pages": ["Brand", "Preview", "Accent colour", "#1a56c4"],
    "about": ["About Dunree", "Published by Foley IT", "Based on", "AGPL-3.0"],
}
# The top bar of every desktop page of the seeded demo: its pills are filled by a poll that can come seconds after the page
TOP_BAR = ["site down", "certificate expiring", "blocked today"]
MUST_NOT = ["Status unavailable", "No requests in this period", "Loading", "loading...", "undefined", "NaN", "No hosts yet", "No nodes yet", "Something went wrong", "Failed to", "Internal Server Error"]


class Pictures:
    def __init__(self, shooter, browser, url, forbidden):
        self.s, self.browser, self.url, self.forbidden = shooter, browser, url, forbidden
        self.pages = {}

    def page(self, scheme="light", phone=False):
        key = (scheme, phone)
        if key not in self.pages:
            vp = {"width": PHONE_W, "height": PHONE_H} if phone else {"width": W, "height": H}
            ctx = self.browser.new_context(viewport=vp, device_scale_factor=SCALE, color_scheme=scheme, locale="en-GB", timezone_id="Europe/Dublin",
                                           is_mobile=phone, has_touch=phone)
            mask_host(ctx)
            pg = ctx.new_page()
            pg.errors = []
            pg.on("console", lambda m, pg=pg: pg.errors.append(m.text) if m.type == "error" else None)
            login(pg, self.url)
            pg.wait_for_function("typeof openTabById === 'function'", timeout=30000)
            pg.wait_for_timeout(1500)
            self.pages[key] = pg
        return self.pages[key]

    def open(self, pg, tab, wait=1800):
        # the menu's Recent list would otherwise show the order the pictures were taken in
        pg.evaluate("""t => { try { localStorage.removeItem('dunree_recent_tabs'); } catch (e) {}
            if (location.hash === '#' + t) { openTabById('status'); }
            openTabById(t); window.scrollTo(0, 0); }""", tab)
        pg.wait_for_timeout(wait)
        try:
            pg.wait_for_load_state("networkidle", timeout=30000)
        except Exception:
            pass
        pg.mouse.move(W - 5 if pg.viewport_size["width"] > 600 else 5, H - 5 if pg.viewport_size["width"] > 600 else 5)

    def check(self, pg, name):
        """Refuse a picture that shows a toast, an error message, the machine's own name or an address of it."""
        text = self.text(pg)
        for f in self.forbidden:
            if f in text:
                raise RuntimeError("%s: the page shows %r, which belongs to the machine the pictures are made on" % (name, f))
        toasts = pg.evaluate("""() => [...document.querySelectorAll('.zx-toast, .zx-toast__msg, #messageBox, .ui.toast')]
            .filter(e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden' && getComputedStyle(e).opacity !== '0' && e.innerText.trim())
            .map(e => e.innerText.trim().slice(0, 120))""")
        if toasts:
            raise RuntimeError("%s: a message is on the page: %r" % (name, toasts))

    @staticmethod
    def text(pg):
        """The text of the page and of the frames in it (the upstream editor and the error page preview are frames)."""
        out = []
        for f in pg.frames:
            try:
                out.append(f.evaluate("document.body ? document.body.innerText : ''"))
            except Exception:
                pass
        return "\n".join(out)

    def ready(self, pg, name):
        """Wait until the page shows every word of MUST[name] and nothing of MUST_NOT is visible."""
        bad_js = """not => { const vis = e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.bottom > 0 && r.top < innerHeight; };
            return not.filter(n => [...document.querySelectorAll('body *')].some(e => e.children.length === 0 && vis(e) && (e.innerText || '').includes(n))); }"""
        must = MUST.get(name, []) + ([] if name in ("addons-empty", "status-phone") else TOP_BAR)
        deadline, miss, bad = time.time() + 120, [], []
        while time.time() < deadline:
            t = self.text(pg)
            miss = [m for m in must if not any(x in t for x in m.split("|"))]
            bad = pg.evaluate(bad_js, MUST_NOT)
            if not miss and not bad:
                pg.wait_for_timeout(700)
                return
            pg.wait_for_timeout(500)
        raise RuntimeError("%s: the page is not ready: missing %r, showing %r" % (name, miss, bad))

    def take(self, pg, name, **kw):
        self.ready(pg, name)
        self.check(pg, name)
        self.s.save(pg, name, **kw)

    # one method per picture that needs more than "open the page"
    def plain(self, name, tab, scheme="light", phone=False):
        pg = self.page(scheme, phone)
        self.open(pg, tab, wait=3500 if tab in ("stats", "status", "fleet") else 1800)
        if name == "sites":  # the Live column: wait for the first numbers of the live poll
            pg.wait_for_function("(document.querySelector('#httpProxyList') || document.body).innerText.includes('req/s')", timeout=120000)
        self.take(pg, name)

    def uptime(self):
        pg = self.page()
        self.open(pg, "utm")
        pg.locator(".zx-segmented__item[data-value='1']:visible", has_text="1 hour").first.click()  # twelve checks instead of 288 thin ones
        pg.wait_for_timeout(1200)
        pg.mouse.move(W - 5, H - 5)
        self.take(pg, "uptime")

    def crowdsec(self):
        pg = self.page()
        self.open(pg, "seccenter")
        pg.click("#secTabs .item[data-sec='crowdsec']")
        pg.wait_for_timeout(3000)
        pg.mouse.move(W - 5, H - 5)
        self.take(pg, "crowdsec")

    def about(self):
        pg = self.page()
        self.open(pg, "utils")
        pg.click("[data-zx-section='info']")
        pg.wait_for_timeout(2000)
        pg.mouse.move(W - 5, H - 5)
        self.take(pg, "about")

    def site_editor(self):
        pg = self.page()
        self.open(pg, "httprp")
        row = pg.locator("#httpProxyList tr.ptRow", has_text="www.example.com").first
        row.get_by_role("button", name="Edit").click()
        pg.wait_for_selector("#httprpEditModal", state="visible")
        pg.wait_for_timeout(1500)
        pg.locator("#httprpEditModal .editUpstreamButton:visible").first.click()
        pg.wait_for_timeout(3000)
        pg.mouse.move(W - 5, H - 5)
        try:
            self.take(pg, "site-editor")
        finally:
            pg.reload()  # leaves the editor without saving anything
            pg.wait_for_function("typeof openTabById === 'function'", timeout=30000)
            pg.wait_for_timeout(1500)

    def statistics_visitors(self):
        pg = self.page()
        self.open(pg, "stats", wait=3500)
        pg.wait_for_function("document.body.innerText.includes('Top client IPs')", timeout=60000)
        pg.evaluate("""() => { const h = [...document.querySelectorAll('#stats h2, #stats h3, #stats .zx-card__title')].find(e => e.innerText.trim() === 'Visitors' && e.getClientRects().length);
            window.scrollTo(0, h.getBoundingClientRect().top + scrollY - 74); }""")
        pg.wait_for_timeout(1500)
        try:
            self.take(pg, "statistics-visitors")
        finally:
            pg.evaluate("window.scrollTo(0, 0)")

    def run(self):
        """Take every wanted picture. A picture that fails does not stop the others; the run fails at the end."""
        steps = [("sites", lambda: self.plain("sites", "httprp")), ("site-editor", self.site_editor),
                 ("certificates", lambda: self.plain("certificates", "cert")),
                 ("security-overview", lambda: self.plain("security-overview", "secoverview")),
                 ("security-center", lambda: self.plain("security-center", "seccenter")), ("waf", lambda: self.plain("waf", "waf")),
                 ("rules", lambda: self.plain("rules", "ruleset")), ("crowdsec", self.crowdsec),
                 ("statistics", lambda: self.plain("statistics", "stats")), ("statistics-visitors", self.statistics_visitors),
                 ("uptime", self.uptime), ("addons", lambda: self.plain("addons", "appstore")), ("fleet", lambda: self.plain("fleet", "fleet")),
                 ("cluster", lambda: self.plain("cluster", "cluster")), ("error-pages", lambda: self.plain("error-pages", "errorpages")),
                 ("about", self.about), ("status", lambda: self.plain("status", "status")),
                 ("status-dark", lambda: self.plain("status-dark", "status", scheme="dark")),
                 ("status-phone", lambda: self.plain("status-phone", "status", phone=True))]
        failed = []
        for name, step in steps:
            if not self.s.want(name):
                continue
            for attempt in (1, 2):
                try:
                    step()
                    break
                except Exception as e:
                    log("  %s failed (attempt %d): %s" % (name, attempt, str(e).split("\n")[0][:300]))
                    if attempt == 2:
                        failed.append(name)
        if failed:
            raise RuntimeError("pictures not taken: " + ", ".join(failed))


# ---------------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------------
def free_port(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # connections of an earlier run in TIME_WAIT do not count
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bin", help="the Dunree program to run (run.sh builds it from this checkout)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "25600")), help="first of 20 ports on 127.0.0.1 that this run may use")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--only", default="", help="comma separated names of SHOTS: take only these (other files in --out are left alone)")
    ap.add_argument("--minutes", type=float, default=12, help="how long the demo traffic runs before the pictures are taken. The Status chart covers 30 minutes and the uptime monitor checks every 5, so 30 gives the fullest pictures")
    ap.add_argument("--serve", action="store_true", help="start and seed everything, print the address and wait (to look at the demo by hand; user %s)" % ADMIN_USER)
    ap.add_argument("--attach", default="", help="URL of a demo started with --serve: take pictures of it instead of starting one (first start, login and the empty Add-ons page cannot be taken this way)")
    ap.add_argument("--docs-only", action="store_true", help="take no pictures: rewrite the Screenshots section of README.md and docs/img/screenshots/README.md from SHOTS")
    ap.add_argument("--keep", action="store_true", help="keep the temp dir (logs, configuration) after the run")
    args = ap.parse_args()
    if args.docs_only:
        if all(os.path.exists(os.path.join(DEFAULT_OUT, s["name"] + ".png")) for s in SHOTS):
            write_manifest(DEFAULT_OUT)
        write_docs()
        return
    only = [x for x in args.only.split(",") if x]
    names = [s["name"] for s in SHOTS]
    for o in only:
        if o not in names:
            sys.exit("unknown picture %r; known: %s" % (o, ", ".join(names)))
    import signal
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(143))  # so that the instances are stopped when the run is killed
    from playwright.sync_api import sync_playwright
    os.makedirs(args.out, exist_ok=True)
    forbidden = machine_names()
    if args.attach:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            shooter = Shooter(browser, args.out, only or [n for n in names if n not in ("setup", "login", "addons-empty")])
            Pictures(shooter, browser, args.attach.rstrip("/"), forbidden).run()
            browser.close()
        return
    if not args.bin:
        sys.exit("--bin is needed (tools/screenshots/run.sh builds the program and passes it)")
    P = args.port
    for p in range(P, P + 20):
        for attempt in range(20):  # a run that was stopped a moment ago may still be closing its listeners
            if free_port(p):
                break
            time.sleep(1)
        else:
            sys.exit("port %d is in use; choose another range with --port" % p)
    binary = os.path.abspath(args.bin)
    tmp = tempfile.mkdtemp(prefix="dunree-demo-")
    insts, servers = [], []
    try:
        ups = {}
        for name, addr, port, kind in UPSTREAMS:
            srv, where = start_upstream(name, addr, port, kind)
            servers.append(srv)
            ups[name] = where
        lapi_key = "demo-bouncer-key-0123456789abcdef"
        lapi = load_fake_lapi()(P + 3, lapi_key)
        for ident, ip, typ, origin, scenario in CROWDSEC_BANS:
            lapi.ban(ident, ip, typ=typ, origin=origin, scenario=scenario)
        demo = Instance(binary, tmp, "demo", P, P + 1)
        insts.append(demo)
        # a backup from before an update, as an install that has been updated once has (Status and Security Overview look for one)
        os.makedirs(os.path.join(demo.dir, "backups"))
        with open(os.path.join(demo.dir, "backups", "dunree-pre-update-%s.zip" % time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - 6 * 86400))), "wb") as f:
            f.write(b"PK\x05\x06" + b"\0" * 18)
        demo.start()
        log("demo instance at %s (proxy port %d), temp dir %s" % (demo.url, P + 1, tmp))
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            shooter = Shooter(browser, args.out, only)
            first_start(shooter, browser, demo)
            ctx = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=SCALE, locale="en-GB")
            pg = ctx.new_page()
            login(pg, demo.url)
            pg.close()
            adm = Admin(ctx, demo.url)
            pics = Pictures(shooter, browser, demo.url, forbidden)
            if shooter.want("addons-empty"):
                p0 = pics.page()
                pics.open(p0, "appstore")
                pics.take(p0, "addons-empty")
            seed(adm, tmp, ups, P + 3, lapi_key)
            gen = Traffic(P + 1, banned=[b[1] for b in CROWDSEC_BANS[:3]])
            gen.start()
            log("add-on index")
            setup_addons(adm, tmp)
            log("fleet")
            setup_fleet(adm, binary, tmp, P, insts)
            left = args.minutes * 60 - (time.time() - gen.started)
            if left > 0 and not args.serve:
                log("demo traffic for another %d s" % left)
                time.sleep(left)
            log("  %d demo requests so far" % gen.sent)
            if args.serve:
                log("serving: %s  user %s  password %s  (Ctrl+C to stop)" % (demo.url, ADMIN_USER, ADMIN_PASS))
                try:
                    while True:
                        time.sleep(3600)
                except KeyboardInterrupt:
                    pass
                return
            pics.run()
            browser.close()
            finish(args.out, shooter, only)
    finally:
        for i in insts:
            i.stop()
        for s in servers:
            try:
                s.shutdown()
            except Exception:
                pass
        if args.keep:
            log("kept " + tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------------------------------------------------
# The texts that show the pictures: the "Screenshots" section of README.md and docs/img/screenshots/README.md
# ---------------------------------------------------------------------------------------------------------------------
BEGIN, END = "<!-- screenshots:begin", "<!-- screenshots:end -->"
DEMO_NOTE = ("The pictures show a throw-away instance with demo data: sites under `example.com`, upstream servers on loopback "
             "addresses, generated traffic. They are made by `tools/screenshots/run.sh`.")


def readme_section():
    """The part of README.md between the screenshots markers (the markers included)."""
    rel = "docs/img/screenshots/"
    shots = [s for s in SHOTS if s.get("readme")]
    hero, phone = shots[0], [s for s in shots if s.get("phone")]
    rest = [s for s in shots[1:] if not s.get("phone")]
    cell = lambda s: "[![%s](%s%s.png)](%s%s.png)<br>%s" % (s["title"], rel, s["name"], rel, s["name"], s["caption"])
    out = [BEGIN + " written by tools/screenshots/capture.py (--docs-only) from its SHOTS list; do not edit by hand -->", "",
           "[![%s](%s%s.png)](%s%s.png)" % (hero["title"], rel, hero["name"], rel, hero["name"]), "", hero["caption"], "", "| | |", "|---|---|"]
    for i in range(0, len(rest), 2):
        pair = rest[i:i + 2]
        out.append("| " + " | ".join(cell(s) for s in pair) + (" | |" if len(pair) == 1 else " |"))
    out.append("")
    for s in phone:
        out += ['<img src="%s%s.png" alt="%s" width="260">' % (rel, s["name"], s["title"]), "", s["caption"], ""]
    out += [DEMO_NOTE + " All %d pictures, with the first-start page and more of the security and statistics pages, are in "
            "[docs/img/screenshots](docs/img/screenshots/README.md)." % len(SHOTS), "", END]
    return "\n".join(out)


def gallery_text():
    """docs/img/screenshots/README.md: every picture with its caption."""
    out = ["# Screenshots of Dunree", "",
           "<!-- written by tools/screenshots/capture.py (--docs-only) from its SHOTS list; do not edit by hand -->", "",
           DEMO_NOTE + " Nothing in them comes from a real installation.", "",
           "Desktop pictures are 1440 x 900 at twice the pixel density (2880 x 1800 pixels), the phone picture is 390 x 844 (780 x 1688). "
           "`manifest.json` lists the files. To make them again, see [How they are made](#how-they-are-made).", ""]
    for s in SHOTS:
        out += ["## " + s["title"], ""]
        if s.get("phone"):
            out += ['<img src="%s.png" alt="%s" width="320">' % (s["name"], s["title"]), ""]
        else:
            out += ["![%s](%s.png)" % (s["title"], s["name"]), ""]
        out += [s["caption"], ""]
    out += ["## How they are made", "",
            "```sh", "PY=/path/to/python-with-playwright PORT=25600 tools/screenshots/run.sh              # about 15 minutes",
            "PY=... MINUTES=30 tools/screenshots/run.sh                                         # fuller charts",
            "python3 tools/screenshots/capture.py --docs-only                                   # only rewrite this page and the README section",
            "python3 tools/screenshots/test_screenshots.py                                      # check files, sizes and texts", "```", "",
            "`run.sh` builds Dunree from this checkout and starts `capture.py`, which starts throw-away instances in a temp folder, "
            "fake backends and demo traffic, takes the pictures and writes this page and the section of the top-level README. "
            "The list of pictures, their captions and the demo data are at the top of `tools/screenshots/capture.py`. "
            "Numbers, times and charts differ from run to run. What the pictures do not show is in "
            "[the notes on the user-visible changes](../../ux/changes.md) under \"Screenshots\".", ""]
    return "\n".join(out)


def write_manifest(out):
    """manifest.json: the pictures of SHOTS with their texts and their pixel sizes (read from the files)."""
    man = []
    for s in SHOTS:
        w, h, _ = png_size(os.path.join(out, s["name"] + ".png"))
        man.append({"file": s["name"] + ".png", "title": s["title"], "caption": s["caption"], "readme": bool(s.get("readme")), "width": w, "height": h})
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump({"note": "Written by tools/screenshots/capture.py. Do not edit by hand.", "scale": SCALE, "pictures": man}, f, indent=1)
        f.write("\n")


def write_docs():
    readme = os.path.join(ROOT, "README.md")
    with open(readme, encoding="utf-8") as f:
        text = f.read()
    a, b = text.find(BEGIN), text.find(END)
    if a < 0 or b < a:
        raise RuntimeError("README.md has no screenshots markers (%s ... %s)" % (BEGIN, END))
    new = text[:a] + readme_section() + text[b + len(END):]
    if new != text:
        with open(readme, "w", encoding="utf-8") as f:
            f.write(new)
        log("README.md: Screenshots section written")
    gal = os.path.join(DEFAULT_OUT, "README.md")
    old = ""
    if os.path.exists(gal):
        with open(gal, encoding="utf-8") as f:
            old = f.read()
    if old != gallery_text():
        with open(gal, "w", encoding="utf-8") as f:
            f.write(gallery_text())
        log("docs/img/screenshots/README.md written")


def finish(out, shooter, only):
    """manifest.json, and no PNG file in the folder that is not one of SHOTS (only after a complete run)."""
    names = [s["name"] for s in SHOTS]
    if only:
        return
    missing = [n for n in names if n not in shooter.done]
    if missing:
        raise RuntimeError("not taken: " + ", ".join(missing))
    for f in sorted(os.listdir(out)):
        if f.endswith(".png") and f[:-4] not in names:
            os.remove(os.path.join(out, f))
            log("removed %s (not in SHOTS)" % f)
    write_manifest(out)
    log("%d pictures in %s" % (len(SHOTS), out))
    if os.path.abspath(out) == os.path.abspath(DEFAULT_OUT):
        write_docs()


if __name__ == "__main__":
    main()
