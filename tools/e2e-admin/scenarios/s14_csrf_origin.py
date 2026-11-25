"""Origin check of the admin interface (gorilla/csrf v1.7.3, GO-2025-3607) against started instances, with curl:
plain HTTP, -webui_tls auto, through a Dunree proxy rule (Host kept, Host replaced + X-Forwarded-Host), and the
switches -csrf_strict / -csrf_trusted_origins."""
import os, re, shutil, subprocess, tempfile
from runner import scenario, NotTestable
import lib
from .common import *

# A small real change every instance accepts, and one that does not restart the proxy (the request may come
# through that proxy): an address of the documentation range on the deny list.
SAVE = "/api/blacklist/ip/add"
DATA = "ip=203.0.113.9"


class Curl:
    """The token flow as a script does it: GET a page (cookie jar + token from the meta tag), then POST."""

    def __init__(self, base, resolve=None):
        if not shutil.which("curl"):
            raise NotTestable("curl is not installed")
        self.base = base
        self.dir = tempfile.mkdtemp(prefix="e2e-curl-")
        self.jar = os.path.join(self.dir, "jar")
        self.common = ["curl", "-sk", "--max-time", "20", "-b", self.jar, "-c", self.jar]
        if resolve:
            self.common += ["--resolve", resolve]
        self.token = None

    def _run(self, args):
        r = subprocess.run(self.common + args + ["-w", "\n%{http_code}"], capture_output=True, text=True)
        check(r.returncode == 0, f"curl failed ({r.returncode}): {r.stderr[-200:]}")
        body, _, code = r.stdout.rpartition("\n")
        return int(code), body

    def page(self):
        st, body = self._run([self.base + "/login.html"])
        if st != 200:
            st, body = self._run([self.base + "/"])
        check(st == 200, f"GET {self.base}: {st}")
        m = re.search(r'(?:dunree|zoraxy)\.csrf\.Token" content="([^"]+)"', body)  # rebrand:keep (the meta tag has both names)
        check(m, "the page has no CSRF token")
        self.token = m.group(1)
        check("dunree_csrf" in open(self.jar).read(), "no CSRF cookie in the jar")
        return self

    def post(self, headers=(), token=True, path=SAVE, data=DATA):
        args = ["-X", "POST", "-d", data]
        if token:
            args += ["-H", "X-CSRF-Token: " + self.token]
        for h in headers:
            args += ["-H", h]
        return self._run(args + [self.base + path])

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def expect(c, rows):
    """rows: (name, headers, token, wanted status). Returns the number of rows."""
    for name, headers, token, want in rows:
        st, body = c.post(headers, token)
        check(st == want, f"{name}: HTTP {st}, want {want}: {body[:200]!r}")
        check(want != 200 or body.strip('"') == "OK", f"{name}: the change was not made: {body[:200]!r}")
    return len(rows)


@scenario("csrf-origin-plain-http", ["GO-2025-3607"])
def csrf_plain():
    with Env("csrfp") as e:
        own = f"http://127.0.0.1:{e.inst.port}"
        c = Curl(own).page()
        try:
            n = expect(c, [
                ("script, cookie and token", [], True, 200),
                ("browser, own origin", ["Origin: " + own, "Referer: " + own + "/", "Sec-Fetch-Site: same-origin"], True, 200),
                ("another site", ["Origin: http://evil.example", "Sec-Fetch-Site: cross-site"], True, 403),
                ("opaque origin", ["Origin: null"], True, 403),
                ("own origin, no token", ["Origin: " + own], False, 403),
                ("script, no token", [], False, 403),
            ])
            st, body = c.post(["Origin: http://evil.example"])
            check(body.startswith("Forbidden - origin invalid") and "-csrf_trusted_origins=evil.example" in body, f"refusal text: {body!r}")
            check("page origin \"evil.example\"" in e.inst.tail(4000), "the refusal is not in the log")
        finally:
            c.close()
        return f"plain HTTP admin interface, curl token flow: {n} cases (script and browser accepted, other site / opaque origin / missing token refused with 403), refusal text and log line name the switch"


@scenario("csrf-origin-https-webui-tls-auto", ["GO-2025-3607"])
def csrf_https():
    inst = Instance("csrft", noauth=True, tls=True, flags=["-webui_tls=auto"]).start()
    try:
        own = f"https://127.0.0.1:{inst.port}"
        c = Curl(own).page()
        try:
            n = expect(c, [
                ("script, cookie and token, no Referer", [], True, 200),
                ("browser, own origin", ["Origin: " + own, "Sec-Fetch-Site: same-origin"], True, 200),
                ("old browser, own Referer only", ["Referer: " + own + "/index.html"], True, 200),
                ("another site", ["Origin: https://evil.example"], True, 403),
                ("Referer of another site, no Origin (the advisory)", ["Referer: https://evil.example/form.html"], True, 403),
                ("http page of the own host", ["Origin: http://127.0.0.1:%d" % inst.port], True, 403),
                ("browser that hides Origin and Referer", ["Sec-Fetch-Site: cross-site"], True, 403),
                ("script, no token", [], False, 403),
            ])
        finally:
            c.close()
        return f"-webui_tls auto, curl -k token flow: {n} cases (script without Referer and browser accepted; other site, foreign Referer without Origin, http downgrade refused)"
    finally:
        inst.cleanup()


def _proxied_admin(e, name="admin.test"):
    """a proxy rule of the instance that points at its own admin port; returns (curl, public origin)"""
    e.add_rule(name, upstream=f"127.0.0.1:{e.inst.port}")
    public = f"{name}:{e.pport}"
    c = Curl("http://" + public, resolve=f"{name}:{e.pport}:127.0.0.1")
    def up():
        try:  # the proxy restarts right after a rule is added: an empty reply is not a failure yet
            return c._run(["http://" + public + "/login.html"])[0] in (200, 302) or None
        except Check:
            return None
    ok = wait_until(up, 20)
    check(ok, f"the admin interface is not reachable through the proxy rule; log {e.inst.tail(600)}")
    return c.page(), public


@scenario("csrf-origin-through-proxy", ["GO-2025-3607"])
def csrf_proxy():
    with Env("csrfx") as e:
        c, public = _proxied_admin(e)
        try:
            n = expect(c, [
                ("Host kept: browser on the public name", ["Origin: http://" + public], True, 200),
                ("Host kept: TLS ended in front (https page, same host)", ["Origin: https://" + public], True, 200),
                ("Host kept: script", [], True, 200),
                ("Host kept: another site", ["Origin: http://evil.example"], True, 403),
                ("Host kept: an X-Forwarded-Proto sent by the client is replaced by the proxy", ["Origin: http://" + public, "X-Forwarded-Proto: https"], True, 200),
                ("Host kept: the admin port's own address is another origin here", ["Origin: http://127.0.0.1:%d" % e.inst.port], True, 403),
            ])
            # the rule now replaces the Host header; the proxy still sends X-Forwarded-Host
            st, js = e.c.post("/api/proxy/header/handleHostOverwrite", domain="admin.test", hostname="internal.lan")
            check(st == 200, f"host overwrite: {st} {js}")
            time.sleep(0.5)
            n += expect(c, [
                ("Host replaced: browser on the public name (X-Forwarded-Host)", ["Origin: http://" + public], True, 200),
                ("Host replaced: https page of the public name", ["Origin: https://" + public], True, 200),
                ("Host replaced: another site", ["Origin: http://evil.example"], True, 403),
                ("Host replaced: script", [], True, 200),
                ("Host replaced: no token", ["Origin: http://" + public], False, 403),
            ])
        finally:
            c.close()
        return f"admin interface behind a Dunree rule on its own admin port, curl with --resolve: {n} cases (Host passed on; Host replaced with X-Forwarded-Host; other sites refused)"


@scenario("csrf-origin-switches", ["GO-2025-3607"])
def csrf_switches():
    ev = []
    # -csrf_strict: X-Forwarded-Host is not used, a script over HTTPS needs a Referer
    e = Env("csrfs", flags=["-csrf_strict"])
    with e:
        c, public = _proxied_admin(e)
        try:
            expect(c, [("strict, Host kept", ["Origin: http://" + public], True, 200)])
            e.c.post("/api/proxy/header/handleHostOverwrite", domain="admin.test", hostname="internal.lan")
            time.sleep(0.5)
            st, body = c.post(["Origin: http://" + public])
            check(st == 403 and f"-csrf_trusted_origins={public}" in body, f"strict, Host replaced: {st} {body!r}")
            check(f'page origin "{public}"' in e.inst.tail(6000), "the refusal is not in the log")
            ev.append("-csrf_strict refuses the replaced Host and names the switch")
        finally:
            c.close()
    # the same setup with the public address listed
    e = Env("csrfl")
    e.inst.flags += ["-csrf_strict", f"-csrf_trusted_origins=http://admin.test:{e.pport}"]
    with e:
        c, public = _proxied_admin(e)
        try:
            e.c.post("/api/proxy/header/handleHostOverwrite", domain="admin.test", hostname="internal.lan")
            time.sleep(0.5)
            expect(c, [
                ("listed origin", ["Origin: http://" + public], True, 200),
                ("listed as http, https page of that host", ["Origin: https://" + public], True, 403),
                ("not listed", ["Origin: http://evil.example"], True, 403),
                ("listed origin, no token", ["Origin: http://" + public], False, 403),
            ])
            check("-csrf_trusted_origins" in e.inst.tail(200000), "the start does not log the listed origins")
            ev.append("-csrf_trusted_origins accepts the listed address and nothing else")
        finally:
            c.close()
    inst = Instance("csrfst", noauth=True, tls=True, flags=["-webui_tls=auto", "-csrf_strict"]).start()
    try:
        own = f"https://127.0.0.1:{inst.port}"
        c = Curl(own).page()
        try:
            expect(c, [
                ("strict HTTPS, script without Referer", [], True, 403),
                ("strict HTTPS, script with Referer", ["Referer: " + own + "/"], True, 200),
                ("strict HTTPS, browser", ["Origin: " + own], True, 200),
            ])
            ev.append("-csrf_strict over HTTPS wants a Referer from a script")
        finally:
            c.close()
    finally:
        inst.cleanup()
    # a list that cannot be read stops the start instead of being ignored
    d = tempfile.mkdtemp(prefix="e2e-csrfbad-")
    try:
        r = subprocess.run([lib.BIN, "-port", f":{alloc_port()}", "-conf", "./conf", "-dbpath", "./sys.db", "-mdns=false", "-fastgeoip=false",
                            "-noauth", "-csrf_trusted_origins=*.example.com"], cwd=d, capture_output=True, text=True, timeout=60)
        check(r.returncode != 0 and "-csrf_trusted_origins" in (r.stdout + r.stderr) and "wildcard" in (r.stdout + r.stderr),
              f"bad list: rc={r.returncode} {(r.stdout + r.stderr)[-300:]!r}")
        ev.append("a wildcard entry stops the start with a message")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return "; ".join(ev)


FORM = """<!doctype html><title>form</title><form id=f method=post action="%s/api/blacklist/ip/add">
<input name=ip value="%s"><input name="gorilla.csrf.Token" value=""></form>
<script>document.querySelector('[name="gorilla.csrf.Token"]').value = new URLSearchParams(location.search).get('t');
document.getElementById('f').submit();</script>"""

BROWSER_POST = """async () => {
  const tok = document.querySelector('meta[name$=".csrf.Token"]').content;
  const r = await fetch('/api/blacklist/ip/add', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'ip=%s'});
  return [r.status, await r.text()];
}"""


def _listed(client, ip):
    st, body, _ = client.raw("GET", "/api/blacklist/list?type=ip")
    return ip.encode() in body


@scenario("csrf-origin-browser", ["GO-2025-3607"])
def csrf_browser():
    """Chromium, not curl: what a real browser sends (Origin on every POST) is accepted on the own address over plain
    HTTP, HTTPS and through a proxy rule, and a form on another origin of the same site is refused although the
    browser sends the cookie and the form carries the matching token."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise NotTestable("playwright not available")
    ev = []
    with sync_playwright() as pw:
        br = pw.chromium.launch(args=["--host-resolver-rules=MAP admin.test 127.0.0.1"])
        try:
            with Env("csrfb") as e:
                own = e.inst.url
                # a page on another port of the same host: same site (the cookie is sent), other origin
                evil = Recorder(lambda r: (200, {"Content-Type": "text/html"}, FORM % (own, "203.0.113.66")))
                e.extra.append(evil)
                ctx = br.new_context()
                pg = ctx.new_page()
                pg.goto(own + "/")
                st, body = pg.evaluate(BROWSER_POST % "203.0.113.61")
                check(st == 200 and _listed(e.c, "203.0.113.61"), f"plain HTTP, fetch from the admin page: {st} {body!r}")
                tok = pg.evaluate("document.querySelector('meta[name$=\".csrf.Token\"]').content")
                import urllib.parse
                q = "?t=" + urllib.parse.quote(tok, safe="")
                # control: the same form, served by the admin interface's own origin, is accepted
                pg.route(lambda u: "/own-form.html" in u, lambda route: route.fulfill(status=200, content_type="text/html", body=FORM % (own, "203.0.113.62")))
                pg.goto(own + "/own-form.html" + q)
                pg.wait_for_load_state("load")
                wait_until(lambda: _listed(e.c, "203.0.113.62") or None, 10)
                check(_listed(e.c, "203.0.113.62"), f"control: a form with the token on the own origin was not accepted: {pg.content()[:200]!r}")
                # the attack: the same form with the same token on the other origin
                pg.goto(f"http://127.0.0.1:{evil.port}/" + q)
                pg.wait_for_url(own + "/api/blacklist/ip/add", timeout=15000)
                text = pg.inner_text("body")
                check("Forbidden - origin invalid" in text, f"form on another origin: the answer is {text[:200]!r}")
                check(not _listed(e.c, "203.0.113.66"), "the form on another origin changed the deny list")
                check("page origin \"127.0.0.1:%d\"" % evil.port in e.inst.tail(8000), "the refusal is not in the log")
                ev.append("plain HTTP: fetch and form from the admin page accepted; the same form with the matching token on another port of the same host is refused (cookie was sent) and logged")
                # through a proxy rule that replaces the Host header
                e.add_rule("admin.test", upstream=f"127.0.0.1:{e.inst.port}")
                e.c.post("/api/proxy/header/handleHostOverwrite", domain="admin.test", hostname="internal.lan")
                time.sleep(1)
                ctx2 = br.new_context()
                p2 = ctx2.new_page()
                p2.goto(f"http://admin.test:{e.pport}/")
                st, body = p2.evaluate(BROWSER_POST % "203.0.113.63")
                check(st == 200 and _listed(e.c, "203.0.113.63"), f"through the proxy rule (Host replaced): {st} {body!r}")
                ev.append("through a Dunree rule that replaces the Host header: accepted (X-Forwarded-Host)")
                ctx.close()
                ctx2.close()
            inst = Instance("csrfbt", noauth=True, tls=True, flags=["-webui_tls=auto"]).start()
            try:
                ctx = br.new_context(ignore_https_errors=True)
                pg = ctx.new_page()
                pg.goto(inst.url + "/")
                st, body = pg.evaluate(BROWSER_POST % "203.0.113.64")
                check(st == 200 and _listed(inst.client, "203.0.113.64"), f"-webui_tls auto, fetch from the admin page: {st} {body!r}")
                ev.append("-webui_tls auto: fetch from the admin page accepted")
                ctx.close()
            finally:
                inst.cleanup()
        finally:
            br.close()
    return "Chromium: " + "; ".join(ev)
