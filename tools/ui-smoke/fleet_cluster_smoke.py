#!/usr/bin/env python3
"""Fleet and Cluster / HA are two separate pages (Playwright + plain HTTP). Started by fleet_cluster_run.sh with three
-noauth Dunree processes: a hub and two nodes, joined here through the API over plain http on 127.0.0.1.

Covered:
- neither page carries the "Fleet | Cluster / HA" tab strip; each has its own menu entry; Fleet keeps its own sections
- Cluster / HA locked as a hub and as a node: one title, one callout that says why, exactly one button, no greyed radios
- a node the hub removed: "The hub no longer accepts this node" + Leave Fleet on both pages; the node stays a node
- Leave Fleet on the Cluster / HA page: unlocked at once, "Managed by hub" banner gone, hub address forgotten
- no old role on screen: page opened from the menu, window focus, a role change made on the other page; an unsaved
  edit in the health card does not freeze the role card
- hub role switched off on the Fleet page and with "Stop being a hub" on the Cluster / HA page
- the note for a primary / follower on the Fleet page links to Cluster / HA
- layout at 1366 px and 390 px, light and dark (screenshots in --out)
Exit code 0 = pass, 1 = failures."""
import argparse
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--hub", required=True)
ap.add_argument("--node-a", required=True)
ap.add_argument("--node-b", required=True)
ap.add_argument("--out", default=os.path.expanduser("~/fleet-cluster-shots"))
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)
HUB_HOST = urllib.parse.urlparse(args.hub).netloc
failures = []
FAST = 2500  # "at once": well under the 10 s / 15 s polling of the two pages


def check(cond, what, detail=""):
    if cond:
        print("ok  ", what)
    else:
        failures.append(f"{what}: {detail}")
        print("FAIL", what, detail)


def api(base, path, data=None):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    html = opener.open(base + "/", timeout=10).read().decode()
    token = re.search(r'csrf.Token" content="([^"]+)"', html).group(1)
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


def ok(res, what):
    code, body = res
    good = code == 200 and not (isinstance(body, dict) and body.get("error"))
    check(good, what, f"{code} {str(body)[:200]}")
    return body


def join(node, name):
    tok = ok(api(args.hub, "/api/fleet/hub/tokenCreate", {"minutes": "5", "name": name, "group": "default"}), f"hub: join token for {name}")["token"]
    ok(api(node, "/api/fleet/node/join", {"hubUrl": args.hub, "token": tok, "fingerprint": "", "allowHttp": "true"}), f"{name} joins the hub")
    api(node, "/api/fleet/node/syncNow", {})


def status(base):
    return api(base, "/api/cluster/status")[1]


def node_ids():
    return [n["id"] for n in api(args.hub, "/api/fleet/hub/overview")[1].get("nodes", [])]


# ---------- set up: a hub with two nodes ----------
ok(api(args.hub, "/api/cluster/config", {"role": "hub"}), "hub role on")
ids_before = node_ids()
join(args.node_a, "node-a")
id_a = [i for i in node_ids() if i not in ids_before][0]
join(args.node_b, "node-b")
st = status(args.hub)
check(st.get("role") == "hub" and st.get("nodeCount") == 2, "status API of the hub: role hub, nodeCount 2", str({k: st.get(k) for k in ("role", "nodeCount")}))
st = status(args.node_a)
check(st.get("role") == "node" and st["fleet"].get("hubRejected") is False, "status API of a node: role node, not rejected", str(st.get("fleet")))

with sync_playwright() as p:
    br = p.chromium.launch()
    errors = []

    def open_ui(base, tab):
        # one browser context per instance: cookies are not scoped by port
        pg = br.new_context(viewport={"width": 1366, "height": 900}).new_page()
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(base + "/")
        pg.wait_for_function("typeof openTabById === 'function'", timeout=15000)
        go(pg, tab)
        pg.wait_for_selector("#clFacts .cx-fact", state="attached", timeout=10000)
        pg.wait_for_selector("#flStatusDesc", state="attached", timeout=10000)
        pg.wait_for_timeout(600)
        return pg

    def go(pg, tab):
        """open a page the way a person does: its entry in the menu"""
        pg.evaluate("tab => openTabById(tab)", tab)
        pg.wait_for_selector(f"#{tab}", state="visible", timeout=5000)

    def theme(pg, dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def layout(pg, root, label):
        bad = pg.evaluate("""root => {
            const msgs = [], page = document.getElementById(root);
            if (document.documentElement.scrollWidth > window.innerWidth + 1) msgs.push('page scrolls sideways: ' + document.documentElement.scrollWidth + ' > ' + window.innerWidth);
            page.querySelectorAll('*').forEach(el => { const s = getComputedStyle(el); if (/(auto|scroll)/.test(s.overflowY) && el.scrollHeight > el.clientHeight + 1 && el.tagName !== 'TEXTAREA' && el.offsetParent !== null) msgs.push('nested scroller: ' + (el.id || el.className)); });
            page.querySelectorAll('.zx-callout .zx-btn').forEach(b => { if (b.offsetParent === null) return; const c = b.closest('.zx-callout').getBoundingClientRect(), r = b.getBoundingClientRect(); if (r.left < c.left - 1 || r.right > c.right + 1) msgs.push('button leaves its callout: ' + b.innerText); });
            return msgs;
        }""", root)
        for m in bad:
            check(False, f"layout {label}", m)

    def shots(pg, name, root="clusterPage", sel="#clStatus"):
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("390", False, 390), ("390-dark", True, 390)):
            theme(pg, dark)
            pg.set_viewport_size({"width": w, "height": 900 if w > 500 else 1100})
            pg.wait_for_timeout(350)
            pg.evaluate("document.querySelectorAll('.zx-toast').forEach(e => e.remove())")
            pg.locator(sel).scroll_into_view_if_needed()
            layout(pg, root, f"{name}/{label}")
            pg.evaluate("window.scrollTo(0, 0)")
            pg.screenshot(path=os.path.join(args.out, f"fleet-cluster-{name}-{label}.png"), full_page=(w < 500))
        theme(pg, False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(300)

    def title_is(pg, pattern, what, timeout=FAST):
        try:
            pg.wait_for_function("p => new RegExp(p, 'i').test(document.getElementById('clStatusTitle').innerText)", arg=pattern, timeout=timeout)
            check(True, what)
        except Exception:
            check(False, what, "title: " + pg.inner_text("#clStatusTitle"))

    def lock(pg):
        return pg.evaluate("""() => { const l = document.getElementById('clFleetLock'); return {shown: !l.hidden && l.offsetParent !== null, kind: l.getAttribute('data-lock'),
            buttons: [...document.querySelectorAll('#clStatus button')].filter(b => b.offsetParent !== null).map(b => b.innerText.trim()), text: l.innerText,
            radios: [...document.querySelectorAll('input[name=clRole]')].filter(r => r.offsetParent !== null).length,
            checked: [...document.querySelectorAll('input[name=clRole]:checked')].map(r => r.value),
            save: document.getElementById('clSaveBtn').offsetParent !== null, note: document.getElementById('clRoleLocked').offsetParent !== null ? document.getElementById('clRoleLocked').innerText : ''}; }""")

    def confirm(pg):
        pg.wait_for_selector(".zx-dialog", timeout=3000)
        pg.click(".zx-dialog [data-zx-ok]")

    # ---------- two separate pages: no cross-link tab strip ----------
    hub = open_ui(args.hub, "fleet")
    na = open_ui(args.node_a, "cluster")
    nb = open_ui(args.node_b, "cluster")
    for pg, who in ((hub, "hub"), (na, "node")):
        n = pg.evaluate("document.querySelectorAll('#fleetPage .zx-pagetabs, #clusterPage .zx-pagetabs').length")
        check(n == 0, f"{who}: no 'Fleet | Cluster / HA' tab strip on the Fleet and the Cluster / HA page", f"{n} found")
        cross = pg.evaluate("[...document.querySelectorAll('#fleetPage [data-nav-open=cluster], #clusterPage [data-nav-open=fleet]')].filter(a => a.offsetParent !== null).length")
        check(cross == 0, f"{who}: no visible link from one page to the other while none is needed", f"{cross} found")
        entries = pg.evaluate("['fleet', 'cluster'].map(t => document.querySelectorAll('#mainmenu [tag=' + t + ']').length)")
        check(all(e >= 1 for e in entries), f"{who}: Fleet and Cluster / HA each have their own menu entry", str(entries))
    check(hub.locator("#flTabs .zx-sectionnav__item").count() >= 5 and hub.is_visible("#flTabs"), "hub: the Fleet page keeps its own sections (Nodes, Join nodes, ...)")
    hub.locator("#flStatus").scroll_into_view_if_needed()
    shots(hub, "fleet-hub", "fleetPage", "#flStatus")

    # ---------- Cluster / HA locked as a hub ----------
    go(hub, "cluster")
    title_is(hub, "^This node is the Fleet hub$", "hub: the Cluster / HA page says what this node is")
    check("2 nodes" in hub.inner_text("#clStatusDesc"), "hub: the status says how many nodes it manages", hub.inner_text("#clStatusDesc"))
    lk = lock(hub)
    check(lk["shown"] and lk["kind"] == "hub" and lk["buttons"] == ["Stop being a hub"], "hub: one callout says why the roles are off, with exactly one button", str(lk))
    check(lk["radios"] == 0 and not lk["save"] and "stopped being a hub" in lk["note"] and lk["checked"] == [], "hub: no greyed role choice and no dead Save button, one sentence instead", str(lk))
    check("managed on the Fleet page and cannot be changed here" not in hub.inner_text("#clusterPage"), "hub: the old dead-end sentence is gone")
    shots(hub, "cluster-hub")

    # ---------- Cluster / HA locked as a node ----------
    title_is(na, f"managed by the Fleet hub {re.escape(HUB_HOST)}$", "node: the Cluster / HA page names the hub")
    lk = lock(na)
    check(lk["shown"] and lk["kind"] == "node" and lk["buttons"] == ["Leave Fleet"], "node: one callout says why the roles are off, with exactly one button", str(lk))
    check(lk["radios"] == 0 and not lk["save"] and "left the Fleet" in lk["note"], "node: no greyed role choice, one sentence instead", str(lk))
    check(na.inner_text("#clRoleBadge") == "In sync with the hub", "node: the badge shows the sync state", na.inner_text("#clRoleBadge"))
    check(na.is_visible("#clSecretNode") and not na.is_visible("#clGenBtn"), "node: setting a secret is a closed, optional section")
    na.click("#clSecretNode > summary")
    check(na.is_visible("#clGenBtn") and na.is_visible("#clSecretIn"), "node: the optional section opens to the two ways to set the secret")
    na.click("#clSecretNode > summary")
    check(na.is_visible("#fleetManagedBanner"), "node: the 'Managed by hub' banner is shown")
    shots(na, "cluster-node")

    # ---------- the hub removes node A while A looks at another page ----------
    go(na, "status")
    ok(api(args.hub, "/api/fleet/hub/nodeRemove", {"id": id_a}), "hub: node-a removed")
    code, body = api(args.node_a, "/api/fleet/node/syncNow", {})  # the node's next contact with the hub (normally its heartbeat, 20 s)
    check(isinstance(body, dict) and "rejected" in str(body.get("error", "")), "node-a: its next contact with the hub is refused", str(body)[:200])
    st = status(args.node_a)
    check(st["role"] == "node" and st["fleet"].get("hubRejected") is True and st["fleet"].get("hubRejectedSince", 0) > 0, "node-a: still a node, and the status says the hub refuses it", str(st.get("fleet")))
    go(na, "cluster")  # opened from the menu: must not show what it showed before
    try:
        na.wait_for_function("document.getElementById('clRoleBadge').innerText == 'The hub no longer accepts this node'", timeout=FAST)
        check(True, "node-a: Cluster / HA opened from the menu shows the new state at once (no wait for the polling)")
    except Exception:
        check(False, "node-a: Cluster / HA opened from the menu shows the new state at once", na.inner_text("#clStatus"))
    lk = lock(na)
    check(lk["kind"] == "rejected" and lk["buttons"] == ["Leave Fleet"] and "removed from the Fleet, or the hub was switched off" in lk["text"], "node-a: plain message and the one way out", str(lk))
    check("zx-btn--primary" in na.get_attribute("#clFleetLockBtn", "class") and "zx-callout--danger" in na.get_attribute("#clFleetLock", "class"), "node-a: Leave Fleet is the main action of a red callout")
    shots(na, "cluster-node-rejected")
    go(na, "fleet")
    try:
        na.wait_for_selector("#flRejected", state="visible", timeout=FAST)
        check(na.inner_text("#flRoleBadge") == "The hub no longer accepts this node" and na.is_visible("#flNodeLeave"), "node-a: the Fleet page says the same, next to its Leave Fleet button", na.inner_text("#flStatus")[:200])
    except Exception:
        check(False, "node-a: the Fleet page shows the rejection at once", na.inner_text("#flStatus")[:200])
    shots(na, "fleet-node-rejected", "fleetPage", "#flStatus")
    check(status(args.hub).get("nodeCount") == 1, "hub: counts one node less")

    # ---------- Leave Fleet on the Cluster / HA page ----------
    go(na, "cluster")
    na.wait_for_timeout(400)
    na.click("#clFleetLockBtn")
    na.wait_for_selector(".zx-dialog", timeout=3000)
    check("stays here as this node's own settings" in na.inner_text(".zx-dialog"), "node-a: Leave Fleet asks first and says what stays", na.inner_text(".zx-dialog")[:200])
    na.screenshot(path=os.path.join(args.out, "fleet-cluster-leave-confirm.png"))
    confirm(na)
    title_is(na, "^This node runs on its own$", "node-a: unlocked at once after leaving")
    na.wait_for_timeout(500)
    lk = lock(na)
    check(not lk["shown"] and lk["radios"] == 3 and lk["save"] and lk["checked"] == ["standalone"] and lk["note"] == "", "node-a: the role choice is back, Standalone selected", str(lk))
    check(not na.is_visible("#clSecretNode") and na.is_visible("#clGenBtn"), "node-a: the secret card is back to normal")
    check(not na.is_visible("#fleetManagedBanner"), "node-a: the 'Managed by hub' banner is gone without a reload")
    st = status(args.node_a)
    check(st["role"] == "standalone" and st["primaryUrl"] == "" and st["fleet"].get("managed") is False, "node-a: standalone, the hub address is forgotten", str({k: st.get(k) for k in ("role", "primaryUrl")}))
    na.click("input[name=clRole][value=follower] + .cx-choice__icon")
    check(na.input_value("#clPrimaryUrl") == "", "node-a: the old hub address is not offered as the primary's address", na.input_value("#clPrimaryUrl"))
    na.click("input[name=clRole][value=standalone] + .cx-choice__icon")
    shots(na, "cluster-after-leave")
    go(na, "fleet")
    try:
        na.wait_for_selector("#flStandalone", state="visible", timeout=FAST)
        check(not na.is_visible("#flRejected"), "node-a: the Fleet page shows 'runs on its own' at once")
    except Exception:
        check(False, "node-a: the Fleet page shows 'runs on its own' at once", na.inner_text("#flStatus")[:200])

    # ---------- an unsaved edit in the health card must not freeze the role card (node B leaves through the API) ----------
    nb.fill("#clHealthAllow", "10.9.8.0/24")
    ok(api(args.node_b, "/api/fleet/node/leave", {}), "node-b leaves through the API (as another window would)")
    nb.wait_for_timeout(1100)
    nb.evaluate("window.dispatchEvent(new Event('focus'))")  # the admin comes back to this window
    title_is(nb, "^This node runs on its own$", "node-b: the page follows when the window gets the focus back")
    nb.wait_for_timeout(500)
    lk = lock(nb)
    check(not lk["shown"] and lk["checked"] == ["standalone"] and lk["radios"] == 3, "node-b: role card unlocked with Standalone selected, although the health card has an unsaved edit", str(lk))
    check(nb.input_value("#clHealthAllow") == "10.9.8.0/24", "node-b: the unsaved edit in the health card is kept", nb.input_value("#clHealthAllow"))
    check(not nb.is_visible("#fleetManagedBanner"), "node-b: the 'Managed by hub' banner is gone")

    # ---------- hub role switched off on the Fleet page: Cluster / HA follows at once ----------
    go(hub, "fleet")
    hub.click("#flTabs .item[data-tab=settings]")
    hub.click("#flBecomeStandalone")
    confirm(hub)
    hub.wait_for_selector("#flStandalone", state="visible", timeout=8000)
    go(hub, "cluster")
    title_is(hub, "^This node runs on its own$", "hub: switched off on the Fleet page, Cluster / HA shows it at once")
    lk = lock(hub)
    check(not lk["shown"] and lk["radios"] == 3 and lk["checked"] == ["standalone"], "hub: role choice unlocked after the hub role was switched off", str(lk))

    # ---------- hub role on again (it kept its nodes), then "Stop being a hub" on the Cluster / HA page ----------
    go(hub, "fleet")
    hub.click("#flBecomeHub")
    confirm(hub)
    hub.wait_for_selector("#flHub", state="visible", timeout=8000)
    go(hub, "cluster")
    title_is(hub, "^This node is the Fleet hub$", "hub: switched on on the Fleet page, Cluster / HA shows it at once")
    check("1 node." in hub.inner_text("#clStatusDesc"), "hub: node-b left on its own and is still listed (known limit: the hub is not told)", hub.inner_text("#clStatusDesc"))
    check(lock(hub)["checked"] == [], "hub: no role radio stays checked from before")
    hub.click("#clFleetLockBtn")
    hub.wait_for_selector(".zx-dialog", timeout=3000)
    check("1 node has joined this hub" in hub.inner_text(".zx-dialog") and "kept" in hub.inner_text(".zx-dialog"), "hub: Stop being a hub asks first and says what happens to the nodes", hub.inner_text(".zx-dialog")[:300])
    hub.screenshot(path=os.path.join(args.out, "fleet-cluster-stop-hub-confirm.png"))
    confirm(hub)
    title_is(hub, "^This node runs on its own$", "hub: unlocked at once after Stop being a hub")
    check(status(args.hub)["role"] == "standalone", "hub: role standalone on the server")
    go(hub, "fleet")
    try:
        hub.wait_for_selector("#flStandalone", state="visible", timeout=FAST)
        check(True, "hub: the Fleet page shows 'runs on its own' at once")
    except Exception:
        check(False, "hub: the Fleet page shows 'runs on its own' at once", hub.inner_text("#flStatus")[:200])

    # ---------- a primary cannot start a Fleet: the note links to Cluster / HA ----------
    ok(api(args.node_a, "/api/cluster/generateSecret", {}), "node-a: secret generated")
    ok(api(args.node_a, "/api/cluster/config", {"role": "primary"}), "node-a: made a primary through the API")
    go(na, "status")
    go(na, "fleet")
    try:
        na.wait_for_selector("#flLegacyNote", state="visible", timeout=FAST)
        check(na.is_disabled("#flBecomeHub"), "primary: the Fleet page says why it cannot start a Fleet")
        shots(na, "fleet-primary-note", "fleetPage", "#flLegacyNote")
        na.click("#flLegacyLink")
        na.wait_for_selector("#cluster", state="visible", timeout=3000)
        title_is(na, "^This node is the primary$", "primary: the one link in that note opens Cluster / HA, already up to date")
    except Exception as e:
        check(False, "primary: note on the Fleet page with a link to Cluster / HA", str(e)[:200])
    ok(api(args.node_a, "/api/cluster/config", {"role": "standalone"}), "node-a: back to standalone")

    check(not errors, "no JavaScript errors", "; ".join(errors[:5]))
    br.close()

if failures:
    print(f"\n{len(failures)} FAILED")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("\nOK, screenshots in", args.out)
