#!/usr/bin/env python3
"""Cluster / HA scenario over two Zoraxy processes on one host (Playwright + plain HTTP). Started by cluster_ha_run.sh:
both instances run with -noauth and hold the same cluster secret. Shared SSO portal sign-ins are opt-in: the primary has
them switched on in its conf/cluster.json, the follower starts with the default (off) and switches them on in the UI.

UI (Cluster page): "Sync settings" is off by default and asks for confirmation, "Keep this node's own listening ports" on
the follower, the status facts and the read-only note; layout at 1366px and 390px, light and dark (screenshots in --out).
End to end: with sync settings OFF the follower's SSO users stay untouched; with it ON the primary's SSO portal user,
portal options, forward auth address and group policy file arrive in the follower's database after its restart, the
follower keeps its own ports, refuses local edits of the synced settings, and a portal sign-in on the primary is valid on
the follower (portal cookie, one-time code, per host cookie through the follower's proxy). A forged cookie is refused.
Exit code 0 = pass, 1 = failures."""
import argparse
import http.client
import http.cookiejar
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--primary", required=True)
ap.add_argument("--follower", required=True)
for name in ("primary-proxy", "follower-proxy", "primary-gateway", "follower-gateway", "upstream"):
    ap.add_argument("--" + name, type=int, required=True)
ap.add_argument("--follower-dir", required=True)
ap.add_argument("--out", default=os.path.expanduser("~/cluster-ha-shots"))
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)
HOST = "app.ha.test"
USER, PW = "alice", "throwaway-Pass-123"
failures = []


def check(cond, what, detail=""):
    if cond:
        print("ok  ", what)
    else:
        failures.append(f"{what}: {detail}")
        print("FAIL", what, detail)


def api(base, path, data=None):
    """admin API call; the CSRF token is fetched per call because the follower restarts in between"""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    html = opener.open(base + "/", timeout=10).read().decode()
    token = re.search(r'zoraxy.csrf.Token" content="([^"]+)"', html).group(1)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(base + path, data=body, method="POST" if data is not None else "GET")
    req.add_header("X-CSRF-Token", token)
    try:
        with opener.open(req, timeout=100) as r:
            code, txt = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, txt = e.code, e.read().decode()
    try:
        return code, json.loads(txt)
    except ValueError:
        return code, txt


def raw(port, method, path, host=None, cookie=None, body=None):
    """one request without following redirects: (status, headers, body)"""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {}
    if host:
        h["Host"] = host
    if cookie:
        h["Cookie"] = cookie
    if body is not None:
        body = urllib.parse.urlencode(body)
        h["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    out = (r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read().decode(errors="replace"))
    c.close()
    return out


def wait_follower_restart(want_version):
    """the follower applies, then restarts itself 3 s later: wait until it is back and reports the version"""
    time.sleep(4)
    last = None
    for _ in range(90):
        try:
            code, st = api(args.follower, "/api/cluster/status")
            last = st
            if code == 200 and isinstance(st, dict) and (st.get("follower") or {}).get("appliedVersion") == want_version:
                time.sleep(1.5)  # the modules after the admin port (SSO gateway, proxy) are up shortly after
                return st
        except Exception as e:  # connection refused while it restarts
            last = e
        time.sleep(0.5)
    check(False, "follower came back with the new snapshot", str(last)[:300])
    return {}


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("upstream-ok user=" + self.headers.get("Remote-User", "-")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.upstream), Upstream)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# ---------- both nodes: plain http proxy on their own port ----------
for base in (args.primary, args.follower):
    api(base, "/api/cert/tls", {"set": "false"})
# the follower's own SSO portal port, set before anything is synced (it must survive the sync)
api(args.follower, "/api/sso/zorxauth/gateway", {"gatewayEnabled": "false", "gatewayPort": args.follower_gateway})
code, r = api(args.follower, "/api/sso/zorxauth/users/create", {"username": "localonly", "password": PW})
check(code == 200 and not (isinstance(r, dict) and r.get("error")), "a standalone node edits its own SSO users", str(r))

# ---------- primary: SSO portal, a user, forward auth, a protected rule ----------
api(args.primary, "/api/sso/zorxauth/gateway", {"gatewayEnabled": "true", "gatewayPort": args.primary_gateway})
api(args.primary, "/api/sso/zorxauth/provider", {"ssoRedirectURL": f"http://127.0.0.1:{args.primary_gateway}", "enableRateLimit": "false"})
code, r = api(args.primary, "/api/sso/zorxauth/users/create", {"username": USER, "password": PW})
check(code == 200 and not (isinstance(r, dict) and r.get("error")), "SSO portal user created on the primary", str(r))
code, r = api(args.primary, "/api/sso/zorxauth/grouppolicy/create", {"name": "ha-group", "allowedHosts": ""})
api(args.primary, "/api/sso/forward-auth", {"address": "https://auth.ha.test/api/verify"})
api(args.primary, "/api/proxy/add", {"type": "host", "rootname": HOST, "ep": f"127.0.0.1:{args.upstream}", "tls": "false",
                                     "tlsval": "false", "bypassGlobalTLS": "false"})
code, r = api(args.primary, "/api/proxy/edit", {"rootname": HOST, "authprovider": "4"})
check(code == 200 and not (isinstance(r, dict) and r.get("error")), "proxy rule protected by the SSO portal", str(r))


def users(base):
    code, r = api(base, "/api/sso/zorxauth/users/list")
    return sorted(u.get("username") for u in r) if isinstance(r, list) else r


with sync_playwright() as p:
    br = p.chromium.launch()
    errors = []

    def open_cluster(base):
        # one browser context per node: cookies are not scoped by port, so the two admin UIs on 127.0.0.1 would
        # overwrite each other's CSRF cookie
        pg = br.new_context(viewport={"width": 1366, "height": 900}).new_page()
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(base + "/")
        pg.wait_for_function("typeof openTabById === 'function'", timeout=15000)
        pg.evaluate("openTabById('cluster')")
        pg.wait_for_selector("#clFacts .cx-fact", timeout=10000)
        pg.wait_for_timeout(500)
        return pg

    def theme(pg, dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def layout(pg, label):
        bad = pg.evaluate("""() => {
            const msgs = [], page = document.getElementById('clusterPage');
            if (document.documentElement.scrollWidth > window.innerWidth + 1) msgs.push('page scrolls sideways: ' + document.documentElement.scrollWidth + ' > ' + window.innerWidth);
            page.querySelectorAll('.zx-toggle-row').forEach(row => {
                if (row.offsetParent === null) return;
                const card = row.closest('.zx-card').getBoundingClientRect(), r = row.getBoundingClientRect();
                if (r.left < card.left - 1 || r.right > card.right + 1) msgs.push('toggle row leaves its card');
                const text = row.querySelector('.zx-toggle-row__text').getBoundingClientRect(), sw = row.querySelector('.ui.checkbox').getBoundingClientRect();
                if (text.right > sw.left + 1 && text.bottom > sw.top + 1 && sw.bottom > text.top + 1) msgs.push('toggle text overlaps its switch: ' + row.innerText.slice(0, 30));
            });
            // no scroll container inside the page (design-v2: one scroller)
            page.querySelectorAll('*').forEach(el => { const s = getComputedStyle(el); if (/(auto|scroll)/.test(s.overflowY) && el.scrollHeight > el.clientHeight + 1 && el.tagName !== 'TEXTAREA') msgs.push('nested scroller: ' + (el.id || el.className)); });
            return msgs;
        }""")
        for m in bad:
            check(False, f"layout {label}", m)

    def shots(pg, name, sel):
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("390", False, 390)):
            theme(pg, dark)
            pg.set_viewport_size({"width": w, "height": 900 if w > 500 else 1100})
            pg.wait_for_timeout(350)
            pg.locator(sel).scroll_into_view_if_needed()
            layout(pg, f"{name}/{label}")
            pg.locator(sel).screenshot(path=os.path.join(args.out, f"cluster-ha-{name}-{label}.png"))
        theme(pg, False)
        pg.set_viewport_size({"width": 1366, "height": 900})

    def toast(pg, pattern):
        pg.wait_for_function("p => [...document.querySelectorAll('.zx-toast')].some(e => new RegExp(p, 'i').test(e.innerText))", arg=pattern, timeout=8000)
        pg.evaluate("document.querySelectorAll('.zx-toast').forEach(e => e.remove())")

    # ---------- primary: role, sync settings off by default ----------
    pa = open_cluster(args.primary)
    check("fingerprint" in pa.inner_text("#clFacts").lower(), "both nodes start with the cluster secret", pa.inner_text("#clFacts"))
    code, st = api(args.primary, "/api/cluster/status")
    check(st.get("sharedSsoSessions") is True and st.get("sharedSsoActive") is True and pa.is_checked("#clSharedSso") and "Active on this node" in pa.inner_text(".clSharedSso"),
          "primary (switched on in conf/cluster.json before its start): shared SSO portal sign-ins are active", str(st)[:300])
    pa.click("input[name=clRole][value=primary] + .cx-choice__icon")
    pa.wait_for_selector("#clSyncSettings", state="attached")
    check(pa.is_visible("#clPrimaryFields") and not pa.is_checked("#clSyncSettings") and not pa.is_checked("#clSyncCerts"),
          "sync settings (and sync certificates) are off by default")
    pa.click("#clSaveBtn")
    toast(pa, "role saved")
    check(pa.locator(".zx-dialog").count() == 0, "saving the primary role with both switches off asks nothing")
    pa.wait_for_function("document.querySelector('#clFacts').innerText.includes('Settings sync')", timeout=8000)
    facts = pa.inner_text("#clFacts")
    check(re.search(r"Settings sync\s*Off", facts, re.I) is not None, "primary status: settings sync off", facts)
    code, st = api(args.primary, "/api/cluster/status")
    check(st.get("syncSettings") is False and st.get("syncSettingsAvail") is True, "API: syncSettings false by default", str(st)[:200])

    # ---------- follower: role, keep own listening ports ----------
    pb = open_cluster(args.follower)
    pb.click("input[name=clRole][value=follower] + .cx-choice__icon")
    pb.fill("#clPrimaryUrl", args.primary)
    check(not pb.is_checked("#clKeepListener"), "keep own listening ports is off by default")
    pb.click("#clKeepListener + label")
    shots(pb, "follower-fields", "#clFollowerFields")
    pb.click("#clSaveBtn")
    toast(pb, "role saved")
    code, st = api(args.follower, "/api/cluster/status")
    check(st.get("role") == "follower" and st.get("keepLocalListener") is True, "follower role and keep-local-listener saved", str(st)[:200])

    # ---------- follower: shared SSO portal sign-ins are opt-in (a cluster secret alone does not enable them) ----------
    check(st.get("secretSet") is True and st.get("sharedSsoSessions") is False and st.get("sharedSsoActive") is False and not pb.is_checked("#clSharedSso"),
          "a node with a cluster secret does not share SSO portal sign-ins by default", str(st)[:300])
    check("Off by default" in pb.inner_text(".clSharedSso") and "Signing out only ends the session on the node" in pb.inner_text(".clSharedSso"),
          "the switch says it is off by default and what it changes for signing out")
    pb.click("#clSharedSso + label")
    pb.wait_for_selector(".zx-dialog", timeout=5000)
    dlg = pb.inner_text(".zx-dialog")
    check("until it expires" in dlg and "every node" in dlg, "switching it on explains the logout limit first", dlg[:200])
    pb.click(".zx-dialog [data-zx-cancel]")
    pb.wait_for_selector(".zx-dialog", state="detached", timeout=5000)
    code, st = api(args.follower, "/api/cluster/status")
    check(st.get("sharedSsoSessions") is False and not pb.is_checked("#clSharedSso"), "cancelling the dialog leaves it off")
    pb.click("#clSharedSso + label")
    pb.wait_for_selector(".zx-dialog", timeout=5000)
    pb.click(".zx-dialog [data-zx-ok]")
    toast(pb, "switched on")
    pb.wait_for_selector("#clSharedSsoRestart", state="visible", timeout=8000)
    code, st = api(args.follower, "/api/cluster/status")
    check(st.get("sharedSsoSessions") is True and st.get("sharedSsoActive") is False and st.get("sharedSsoRestart") is True,
          "switched on: saved, not active before the restart, restart note shown", str(st)[:300])
    shots(pb, "shared-sso", ".clSharedSso")

    # ---------- first sync, settings OFF: rules arrive, the follower's own SSO users stay ----------
    code, st = api(args.primary, "/api/cluster/status")
    v1 = st.get("snapshotVersion")
    pb.click("#clSyncBtn")
    toast(pb, "sync finished")
    st = wait_follower_restart(v1)
    check((st.get("follower") or {}).get("settingsSynced") is False, "follower: no settings synced while the primary has it off", str(st.get("follower")))
    check(st.get("sharedSsoActive") is True and st.get("sharedSsoRestart") is False, "after its restart the follower shares SSO portal sign-ins", str(st)[:300])
    check(users(args.follower) == ["localonly"], "follower keeps its own SSO users while sync settings is off", str(users(args.follower)))
    code, r = api(args.follower, "/api/sso/zorxauth/users/create", {"username": "second", "password": PW})
    check(code == 200, "follower can still edit its SSO users while sync settings is off", f"{code} {r}")
    code, rules = api(args.follower, "/api/proxy/list?type=host")
    check(HOST in json.dumps(rules), "proxy rule reached the follower")

    # ---------- primary: switch sync settings on (confirmation) ----------
    pa.reload()
    pa.wait_for_function("typeof openTabById === 'function'", timeout=15000)
    pa.evaluate("openTabById('cluster')")
    pa.wait_for_selector("#clPrimaryFields", state="visible", timeout=10000)
    pa.wait_for_timeout(500)
    pa.click("#clSyncSettings + label")
    shots(pa, "primary-fields", "#clPrimaryFields")
    pa.click("#clSaveBtn")
    pa.wait_for_selector(".zx-dialog", timeout=5000)
    dlg = pa.inner_text(".zx-dialog")
    check("password hashes" in dlg and "client secrets" in dlg, "the confirmation names what is sent to the followers", dlg[:200])
    check("Update every follower" in dlg, "the confirmation says that older followers refuse the snapshot", dlg[-220:])
    pa.screenshot(path=os.path.join(args.out, "cluster-ha-confirm-light.png"))
    theme(pa, True)
    pa.screenshot(path=os.path.join(args.out, "cluster-ha-confirm-dark.png"))
    theme(pa, False)
    code, st = api(args.primary, "/api/cluster/status")
    check(st.get("syncSettings") is False, "nothing is switched on before the confirmation")
    pa.click(".zx-dialog [data-zx-ok]")
    toast(pa, "role saved")
    pa.wait_for_function("/Settings sync\\s*On/i.test(document.querySelector('#clFacts').innerText)", timeout=8000)
    shots(pa, "primary-status", "#clStatus")
    code, r = api(args.primary, "/api/cluster/config", {"syncSettings": "false"})
    code, r = api(args.primary, "/api/cluster/config", {"syncSettings": "true"})
    check(isinstance(r, dict) and "ackSyncSettings" in r.get("error", ""), "API refuses sync settings without the acknowledgement", str(r))
    code, r = api(args.primary, "/api/cluster/config", {"syncSettings": "true", "ackSyncSettings": "true"})
    code, st = api(args.primary, "/api/cluster/status")
    v2 = st.get("snapshotVersion")
    check(st.get("syncSettings") is True and v2 != v1, "switching sync settings on gives a new snapshot version", f"{v1} -> {v2}")

    # ---------- second sync, settings ON ----------
    code, r = api(args.follower, "/api/cluster/syncNow", {"force": "false"})
    # the follower's own poll loop (every 60 s, first run 5 to 10 s after a start) may have applied it a moment earlier
    check(isinstance(r, dict) and (r.get("lastResult") == "applied" or (r.get("lastResult") == "unchanged" and r.get("settingsSynced"))),
          "follower applied the settings snapshot", str(r))
    st = wait_follower_restart(v2)
    check((st.get("follower") or {}).get("settingsSynced") is True, "follower reports settings from the primary", str(st.get("follower")))
    check(users(args.follower) == [USER], "follower's SSO users are now the primary's (its own were replaced)", str(users(args.follower)))
    code, fa = api(args.follower, "/api/sso/forward-auth")
    check("auth.ha.test" in json.dumps(fa), "forward auth address synced", str(fa)[:200])
    code, gp = api(args.follower, "/api/sso/zorxauth/grouppolicy/list")
    check("ha-group" in json.dumps(gp), "group policy file synced", str(gp)[:200])
    code, gw = api(args.follower, "/api/sso/zorxauth/gateway")
    check(isinstance(gw, dict) and str(args.follower_gateway) in json.dumps(gw) and str(args.primary_gateway) not in json.dumps(gw),
          "follower kept its own SSO portal port", str(gw))
    code, inbound = api(args.follower, "/api/proxy/status")
    check(str(args.follower_proxy) in json.dumps(inbound), "follower kept its own incoming port", str(inbound)[:200])
    for path, data in (("/api/sso/zorxauth/users/create", {"username": "x", "password": PW}), ("/api/sso/forward-auth", {"address": "https://evil.test"}),
                       ("/api/sso/zorxauth/users/logoutAll", {})):
        code, r = api(args.follower, path, data)
        check(code == 403 and "primary" in json.dumps(r), f"follower refuses a local edit of synced settings: {path}", f"{code} {r}")
    code, r = api(args.follower, "/api/proxy/setIncoming", {"incoming": str(args.follower_proxy)})
    check(code != 403, "the incoming port stays editable on a follower that keeps its own listening ports", f"{code} {r}")
    check(os.path.exists(os.path.join(args.follower_dir, "conf", ".cluster", "dbsync-baseline.json")), "the follower saved its own settings before the first import")
    mode = os.stat(os.path.join(args.follower_dir, "conf", "dbsync", "zorxauth_users.json")).st_mode & 0o777
    check(mode & 0o077 == 0, "synced settings files are private to the Zoraxy user", oct(mode))

    pb.reload()
    pb.wait_for_function("typeof openTabById === 'function'", timeout=15000)
    pb.evaluate("openTabById('cluster')")
    pb.wait_for_selector("#clReadOnly", state="visible", timeout=10000)
    pb.wait_for_function("/From the primary/.test(document.querySelector('#clFacts').innerText)", timeout=8000)
    check(pb.is_visible("#clReadOnlySettings") and "SSO portal users" in pb.inner_text("#clReadOnly"), "follower page says that the SSO settings are read-only too")
    check(pb.is_checked("#clKeepListener"), "keep own listening ports shown as on after the restart")
    shots(pb, "follower-status", "#clStatus")

    # ---------- a sign-in on the primary is valid on the follower ----------
    code, h, body = raw(args.primary_gateway, "POST", "/login", body={"username": USER, "password": PW, "redirect": "/"})
    m = re.search(r"zr_xauth_session=([^;]+)", h.get("set-cookie", ""))
    check(code == 200 and m is not None, "portal login on the primary", f"{code} {body[:120]}")
    portal = m.group(1) if m else ""
    check(portal.startswith("zxs1."), "with shared SSO portal sign-ins on, the portal cookie is a signed token", portal[:20])
    ck = "zr_xauth_session=" + portal
    code, h, body = raw(args.follower_gateway, "GET", "/user/api/info", cookie=ck)
    check(code == 200 and USER in body, "the follower's portal accepts the session the primary issued", f"{code} {body[:120]}")
    forged = portal[:-4] + ("AAAA" if not portal.endswith("AAAA") else "BBBB")
    code, h, body = raw(args.follower_gateway, "GET", "/user/api/info", cookie="zr_xauth_session=" + forged)
    check(code == 401, "a cookie with a wrong signature is refused", str(code))
    code, h, body = raw(args.follower_gateway, "POST", "/user/api/change-password", cookie=ck, body={"oldPassword": PW, "newPassword": PW + "x"})
    check(code == 409 and "read-only" in body, "self-service changes are refused on the follower (they would be overwritten)", f"{code} {body[:120]}")

    # protected site through the FOLLOWER's proxy: redirect to the portal, one-time code issued by the PRIMARY's portal
    site = f"{HOST}:{args.follower_proxy}"
    code, h, body = raw(args.follower_proxy, "GET", "/hello", host=site)
    check(code in (302, 307) and f":{args.primary_gateway}" in h.get("location", ""), "unauthenticated request on the follower is sent to the portal", f"{code} {h.get('location')}")
    target = urllib.parse.urlsplit(h.get("location", ""))
    code, h, body = raw(args.primary_gateway, "GET", (target.path or "/") + "?" + target.query, cookie=ck)
    loc = urllib.parse.urlsplit(h.get("location", ""))
    check(code == 303 and loc.netloc == site and "session_id=zxs1." in loc.query, "the primary's portal issues a signed one-time code for the site", f"{code} {h.get('location')}")
    code, h, body = raw(args.follower_proxy, "GET", loc.path + "?" + loc.query, host=site)
    m = re.search(r"zr_xauth_session=([^;]+)", h.get("set-cookie", ""))
    check(code == 303 and m is not None, "the follower accepts the code of the primary and sets the site cookie", f"{code} {body[:80]}")
    sitecookie = "zr_xauth_session=" + (m.group(1) if m else "")
    code, h, body = raw(args.follower_proxy, "GET", "/hello", host=site, cookie=sitecookie)
    check(code == 200 and body == "upstream-ok user=" + USER, "the follower proxies the signed-in request to the upstream", f"{code} {body[:80]}")
    code, h, body = raw(args.follower_proxy, "GET", loc.path + "?" + loc.query, host=site)
    check(code == 401, "the one-time code cannot be used twice", str(code))
    code, h, body = raw(args.primary_proxy, "GET", "/hello", host=f"{HOST}:{args.primary_proxy}", cookie=sitecookie)
    check(code == 200 and body == "upstream-ok user=" + USER, "the site cookie the follower issued is valid on the primary", f"{code} {body[:80]}")

    check(not errors, "no JavaScript errors on the Cluster page", "; ".join(errors)[:300])
    br.close()

print(f"\n{len(failures)} failure(s); screenshots in {args.out}")
for f in failures:
    print(" -", f)
sys.exit(1 if failures else 0)
