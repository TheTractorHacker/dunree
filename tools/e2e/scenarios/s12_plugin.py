"""Plugin request/response hooks with the example filter plugin."""
import json

from lib import *


def _ensure_running(z, pid):
    """Enable a plugin unless it already runs. A plugin folder that is seeded before the first start has no stored
    "enabled" flag, which counts as enabled: Zoraxy starts it at boot, and enabling a running plugin is an error."""
    for p in z.get("/api/plugins/list"):
        if (p.get("Spec") or {}).get("id") == pid and ((p.get("Status") or {}).get("State") == "running" or p.get("Enabled")):
            return
    z.api("/api/plugins/enable", plugin_id=pid, enable=True)


@scenario("plugin_filter_hooks", ["83"])
def plugin_filter_hooks():
    """Example filter plugin (real process): pre_auth denies matching User-Agents, tags requests, adds response headers,
    and fails open when the plugin process dies."""
    binp = build_example_plugin("filter-example")
    with Zoraxy(plugins=[("filter-example", binp)]) as z, Backend(lambda h, rec, b: send(h, 200, json.dumps({"headers": rec["headers"]}), {"X-Powered-By": "upstream"}, ctype="application/json"), name="app") as app:
        z.add_rule("pl.test", app.addr)
        pid = None
        lst = z.get("/api/plugins/list")
        for p in lst:
            sp = p.get("Spec") or p
            if "filter-example" in json.dumps(sp):
                pid = sp.get("id") or sp.get("ID")
        check(pid, "plugin not discovered: %s" % json.dumps(lst)[:300])
        _ensure_running(z, pid)
        z.api("/api/plugins/hooks/set", plugin_id=pid, **{"global": True})
        def up():
            r = z.req("pl.test", "/", headers={"User-Agent": "Mozilla"})
            return r if r.h("x-content-type-options") == "nosniff" else None
        ok = wait_for(up, timeout=15, msg="plugin to be active (response header)")
        check(ok.json()["headers"].get("x-filter-example") == "checked", "pre_auth header modification missing: %s" % ok.json()["headers"])
        check(not ok.h("x-powered-by"), "response hook did not remove X-Powered-By")
        check(ok.h("referrer-policy") == "strict-origin-when-cross-origin", "response header missing")
        n = len(app.log)
        bad = z.req("pl.test", "/", headers={"User-Agent": "sqlmap/1.7"})
        check(bad.status == 403 and len(app.log) == n, "pre_auth deny not applied: %d" % bad.status)
        # kill the plugin process: failure policy is open => traffic keeps flowing
        import subprocess
        subprocess.run(["pkill", "-9", "-f", z.dir + "/plugins/filter-example/filter-example"])
        time.sleep(1)
        after = z.req("pl.test", "/", headers={"User-Agent": "Mozilla"}, timeout=10)
        check(after.status == 200, "plugin down + fail-open policy but request failed (%d)" % after.status)
        return "plugin discovered as %s; pre_auth: sqlmap UA=403 (upstream untouched), others tagged X-Filter-Example; response hook: nosniff/referrer-policy added, X-Powered-By removed; plugin killed => still 200 (fail open)" % pid


@scenario("plugin_reference_plugins", ["plugins-phase3"])
def plugin_reference_plugins():
    """The three reference plugins of the fork (real processes) against a real Zoraxy: all start and report contract
    version 1; the filter marks requests and responses, denies its fixed path and fails open when killed (it declares
    fail_closed, nobody consented); the page-and-API plugin reads the access rules with its API key; the events plugin
    serves its counters through the admin proxy."""
    names = ["fork-ref-filter", "fork-ref-events", "fork-ref-ui-api"]
    ids = {"fork-ref-filter": "fork.zoraxy.ref.filter", "fork-ref-events": "fork.zoraxy.ref.events", "fork-ref-ui-api": "fork.zoraxy.ref.ui-api"}
    with Zoraxy(plugins=[(n, build_example_plugin(n)) for n in names]) as z, Backend(lambda h, rec, b: send(h, 200, json.dumps({"headers": rec["headers"]}), ctype="application/json"), name="app") as app:
        z.add_rule("ref.test", app.addr)
        lst = z.get("/api/plugins/list")
        found = {(p.get("Spec") or {}).get("id") for p in lst}
        check(set(ids.values()) <= found, "reference plugins not discovered: %s" % sorted(x for x in found if x))
        for pid in ids.values():
            _ensure_running(z, pid)

        def all_running():
            st = {(p.get("Spec") or {}).get("id"): (p.get("Status") or {}) for p in z.get("/api/plugins/list")}
            return st if all(st.get(pid, {}).get("State") == "running" for pid in ids.values()) else None
        st = wait_for(all_running, timeout=15, msg="the three reference plugins to be running")
        for pid in ids.values():
            c = st[pid].get("Contract") or {}
            check(c.get("APIVersion") == 1 and not c.get("Refused"), "%s contract: %s" % (pid, c))

        fid = ids["fork-ref-filter"]
        z.api("/api/plugins/hooks/set", plugin_id=fid, **{"global": True})

        def up():
            r = z.req("ref.test", "/")
            return r if r.h("x-fork-ref-filter") == "response" else None
        ok = wait_for(up, timeout=15, msg="the reference filter to be active (response header)")
        check(ok.json()["headers"].get("x-fork-ref-filter") == "pre_auth", "pre_auth header missing at the upstream: %s" % ok.json()["headers"])
        n = len(app.log)
        bad = z.req("ref.test", "/fork-ref-filter/deny/x")
        check(bad.status == 403 and len(app.log) == n, "deny path not denied: %d" % bad.status)

        # the page-and-API plugin read the access rules at start with its key, through the real plugin API
        def api_ok():
            s = z.get("/plugin.ui/%s/api/status" % ids["fork-ref-ui-api"])
            return s if isinstance(s, dict) and s.get("ok") else None
        wait_for(api_ok, timeout=10, msg="fork-ref-ui-api to read the access rules with its API key")
        ev = z.get("/plugin.ui/%s/stats" % ids["fork-ref-events"])
        check(isinstance(ev, dict) and ev.get("queue_size") == 256 and ev.get("dropped") == 0, "fork-ref-events stats: %s" % ev)

        # kill the filter: it declares fail_closed, the administrator did not consent => traffic keeps flowing
        import subprocess
        subprocess.run(["pkill", "-9", "-f", z.dir + "/plugins/fork-ref-filter/fork-ref-filter"])
        time.sleep(1)
        after = z.req("ref.test", "/fork-ref-filter/deny/x", timeout=10)
        check(after.status == 200, "filter killed, no fail-closed consent, but the request failed (%d)" % after.status)
        down = {(p.get("Spec") or {}).get("id"): (p.get("Status") or {}) for p in z.get("/api/plugins/list")}[fid]
        check(down.get("State") == "crashed", "killed filter is shown as %s" % down.get("State"))
        return "3 reference plugins running, contract version 1; filter: requests and responses marked, deny path=403 (upstream untouched); ui-api read the access rules with its key; events stats served; filter killed => 200 (fail open without consent), state crashed"
