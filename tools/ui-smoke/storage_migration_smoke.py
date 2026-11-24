#!/usr/bin/env python3
"""Browser storage keys after the rename (src/web/script/safestorage.js, zxStore).

The admin UI used to keep its choices under "zoraxy_..." / "zoraxy...." keys and now uses "dunree_..." / "dunree....".  # rebrand:keep
The first admin page a browser loads copies the old keys to the new names, once. This check proves, in a real browser:

  1. old keys are copied to the new names, the old keys stay, unrelated keys are untouched, a value that already
     exists under the new name wins;
  2. it happens once: a second load copies nothing, a key the user removed afterwards does not come back, an old
     key that appears later is ignored;
  3. sessionStorage is handled the same way (per tab);
  4. with storage blocked nothing throws and the helper still works in memory.

Two ways to run it:
  storage_migration_smoke.py                 no server: the real safestorage.js is served to a blank test page
  storage_migration_smoke.py --url URL       against a running admin UI (also called from smoke.py)
Prints "OK storage migration" and exits 0, or lists the failures and exits 1.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "..", "..", "src", "web", "script", "safestorage.js")
OLD, NEW = "zoraxy", "dunree"  # rebrand:keep
MARK = "dunree.storage.migrated"

BLOCK = """(() => { const boom = () => { throw new DOMException('The operation is insecure.', 'SecurityError'); };
    for (const m of ['getItem', 'setItem', 'removeItem', 'clear', 'key']) Storage.prototype[m] = boom; })()"""


def run(browser, url, fail):
    """url None: serve the helper from the source tree on a made-up origin. Returns nothing; reports through fail(what, detail)."""
    standalone = not url
    base = (url or "http://storage-migration.test").rstrip("/")

    def context(init=None):
        c = browser.new_context()
        if init:
            c.add_init_script(init)
        # a blank same-origin page to prepare storage before any script of the UI runs
        c.route(base + "/__blank.html", lambda r: r.fulfill(status=200, content_type="text/html", body="<!doctype html><title>blank</title>"))
        if standalone:
            c.route(base + "/", lambda r: r.fulfill(status=200, content_type="text/html",
                    body="<!doctype html><title>t</title><script src='script/safestorage.js'></script>"))
            c.route(base + "/script/safestorage.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=open(HELPER, encoding="utf-8").read()))
        return c

    def load(p):
        p.goto(base + "/", wait_until="domcontentloaded")
        p.wait_for_function("!!window.zxStore", timeout=10000)

    # ---- 1. first load after the upgrade
    c = context()
    p = c.new_page()
    errors = []
    p.on("pageerror", lambda e: errors.append(str(e)))
    p.goto(base + "/__blank.html")
    seed = {
        OLD + "_probe_groups": '{"security":true}',   # made-up names where a real page would rewrite the value on load
        OLD + "_pinned_tabs": '["old-pin"]',
        OLD + ".lang": "de",
        OLD + "_trafficflow_mode": "today",
        OLD + "_site_editor_mode": "simple",
        NEW + "_pinned_tabs": '["new-pin"]',     # already stored under the new name: must win
        "theme": "dark",                           # never had the name in it
        OLD + "foo": "x",                          # not "<name>_" or "<name>.": not ours
        OLD: "y",
    }
    p.evaluate("([s, sk]) => { localStorage.clear(); sessionStorage.clear(); for (const k in s) localStorage.setItem(k, s[k]); sessionStorage.setItem(sk, '3'); }",
               [seed, OLD + ".utm.range"])
    load(p)
    got = p.evaluate("(() => { const o = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); o[k] = localStorage.getItem(k); } return o; })()")
    want_new = {NEW + "_probe_groups": '{"security":true}', NEW + ".lang": "de", NEW + "_trafficflow_mode": "today", NEW + "_site_editor_mode": "simple"}
    for k, v in want_new.items():
        if got.get(k) != v:
            fail("storage-migration", f"{k} = {got.get(k)!r}, want {v!r} (copied from the old key)")
        if p.evaluate("k => zxStore.get(k)", k) != v:
            fail("storage-migration", f"zxStore.get({k!r}) does not return the copied value")
    for k, v in seed.items():
        if got.get(k) != v:
            fail("storage-migration", f"{k} changed or was removed: {got.get(k)!r}, want {v!r}")
    if got.get(NEW + "_pinned_tabs") != '["new-pin"]':
        fail("storage-migration", "a value stored under the new name was overwritten by the old one")
    for k in (NEW + "foo", NEW):
        if k in got:
            fail("storage-migration", f"{k} was created from a key that is not one of ours")
    if got.get(MARK) != "1":
        fail("storage-migration", f"the marker {MARK} was not set")
    m = p.evaluate("zxStore.migrated")
    if m.get("local") != 4 or m.get("session") != 1:
        fail("storage-migration", f"zxStore.migrated = {m}, want local 4 and session 1")
    if p.evaluate("([a, b]) => [sessionStorage.getItem(a), sessionStorage.getItem(b)]", [NEW + ".utm.range", OLD + ".utm.range"]) != ["3", "3"]:
        fail("storage-migration", "sessionStorage key was not copied (or the old one was removed)")

    # ---- 2. once: nothing on the second load, a removed key stays removed, a late old key is ignored
    p.evaluate("([k, late]) => { zxStore.remove(k); localStorage.setItem(late, 'late'); }", [NEW + "_probe_groups", OLD + "_probe_late"])
    load(p)
    m = p.evaluate("zxStore.migrated")
    if m.get("local") != -1 or m.get("session") != -1:
        fail("storage-migration", f"second load: zxStore.migrated = {m}, want -1 / -1 (already done)")
    if p.evaluate("k => zxStore.get(k)", NEW + "_probe_groups") is not None:
        fail("storage-migration", "a key removed after the copy came back on the next load")
    if p.evaluate("k => localStorage.getItem(k)", NEW + "_probe_late") is not None:
        fail("storage-migration", "an old key written after the one-time copy was copied")
    if p.evaluate("k => localStorage.getItem(k)", OLD + ".lang") != "de":
        fail("storage-migration", "the old key must be left alone")
    # a new tab of the same browser: localStorage is shared (done), sessionStorage is its own (nothing to copy)
    p2 = c.new_page()
    load(p2)
    m = p2.evaluate("zxStore.migrated")
    if m.get("local") != -1 or m.get("session") != 0:
        fail("storage-migration", f"new tab: zxStore.migrated = {m}, want local -1, session 0")
    if errors:
        fail("storage-migration", "page errors: " + " | ".join(errors[:3]))
    c.close()

    # ---- 3. a browser that never ran the old UI
    c = context()
    p = c.new_page()
    load(p)
    m = p.evaluate("zxStore.migrated")
    if m.get("local") != 0 or p.evaluate("k => localStorage.getItem(k)", MARK) != "1":
        fail("storage-migration", f"clean browser: zxStore.migrated = {m}, marker {p.evaluate('k => localStorage.getItem(k)', MARK)!r}")
    c.close()

    # ---- 4. storage blocked: no exception, memory fallback still works
    c = context(BLOCK)
    p = c.new_page()
    errors = []
    p.on("pageerror", lambda e: errors.append(str(e)))
    load(p)
    m = p.evaluate("zxStore.migrated")
    if m.get("local") is not None or m.get("session") is not None:
        fail("storage-migration", f"blocked storage: zxStore.migrated = {m}, want null / null")
    if not p.evaluate("zxStore.set('zx.probe', 'v') === false && zxStore.get('zx.probe') === 'v'"):
        fail("storage-migration", "blocked storage: the in-memory fallback stopped working")
    if errors and standalone:
        fail("storage-migration", "blocked storage: page errors: " + " | ".join(errors[:3]))
    c.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default="", help="base URL of a running admin UI (default: no server, serve the helper from the source tree)")
    a = ap.parse_args()
    from playwright.sync_api import sync_playwright
    failures = []

    def fail(what, detail):
        failures.append(f"{what}: {detail}")
        print("FAIL", what, detail)

    with sync_playwright() as pw:
        b = pw.chromium.launch()
        try:
            run(b, a.url, fail)
        finally:
            b.close()
    if failures:
        print(f"{len(failures)} failure(s)")
        return 1
    print("OK storage migration")
    return 0


if __name__ == "__main__":
    sys.exit(main())
