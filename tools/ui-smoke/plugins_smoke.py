"""Plugin Manager scenario (phases 0, 1 and 2 of docs/plugins/reliability-plan.md). exec()'d by smoke.py (namespace: fail, current,
args, os, re, settle); run alone with --plugins-only, or through plugins_run.sh, which also prepares real plugins.

Part 1, on ANY instance (the plugin API is answered by mocks, so no plugin has to be installed). One good plugin whose manifest is
markup and quotes, one crashed plugin, one folder that could not be loaded:
  * nothing of the manifest (name, id, author, author_contact, description, url), of the load failure, of the last problem, of the
    plugin output or of the limits note becomes markup: no injected element, no script ran (window.__xss stays unset), the texts
    are shown literally, the author link is not a javascript: link;
  * the Status column shows the badge of each plugin (Not listening for the good one: that state only exists in the status view,
    so it also proves that the page shows what /api/plugins/status?probe=true answers; Crashed with the exit code for the other);
  * the page asks for the port probe (probe=true) only while it is on screen, and again as soon as it is opened;
  * the Details row opens for an ID full of quotes and shows process facts, exit history and output as text;
  * the Supervision form shows the stored policy, disables the limits the host cannot enforce, and Save posts exactly the
    changed values for the right plugin (capture timeout in milliseconds);
  * phase 2: the Health column and a notice say that a plugin asks for API permissions nobody approved and that it was built for
    a newer plugin contract; the Details row lists the permissions (endpoint and the reason of the author as text) with what is
    approved and granted; Approve / Withdraw / "Approve the N ..." post exactly the endpoints shown, for the right plugin; the
    "Plugin safety settings" show the stored settings and post a change;
  * the build error dialog shows hostile build output as text;
  * the side menu wording for "stopped unexpectedly", "none running" and the empty list.

Part 2, only on an instance prepared by plugins_run.sh (three real chaos plugins: hostile manifest and running, crasher, folder
that answers -introspect with garbage; --plugins-live makes their absence a failure): the same list checks against the real API,
the real Details call, a real save of the Supervision form that is read back from /api/plugins/policy, the permissions of the
hostile plugin (new, so not approved, but granted by default; then "Require my approval" is switched on with the real checkbox,
one endpoint whose name is markup is approved with its button, the rest with "Approve the N ...", each read back from
/api/plugins/permissions; the setting is switched off again), "Stop" on the crashed plugin answered as done, and the Stop button
with the hostile ID.

Items 2.4, 2.5 and 2.7 (signed index, rollback, isolated plugin pages): mocked, the "Install and updates" block of the Details row,
the signature badges, the new plugin safety settings and the attributes of the plugin page frame; against the real instance
(plugins_store_live, with the local signed index plugins_run.sh serves) an install under enforce, an update whose new version
crashes at start and the Roll back button, and a plugin page that uses the admin session when it is not isolated and cannot when
it is. The browser reports the blocked calls of that last step as errors; they are tolerated for that step only.

Screenshots go to --out (plugins-*.png)."""

import json
import time
import urllib.parse

PLUGINS_HOSTILE_ID = "test.chaos.hostile\"'><img src=x onerror=window.__xss=2>"
PLUGINS_CRASHER_ID = "test.chaos.crasher"

PLUGINS_INJECTED = """() => {
    const hits = [];
    document.querySelectorAll('img[src="x"], img[onerror], script').forEach(e => {
        if (e.tagName === 'SCRIPT' && !/__xss/.test(e.textContent)) return;   // the page's own scripts
        hits.push(e.outerHTML.slice(0, 120));
    });
    document.querySelectorAll('a[href]').forEach(a => { if (/^\\s*javascript:/i.test(a.getAttribute('href'))) hits.push(a.outerHTML.slice(0, 120)); });
    return {hits, xss: typeof window.__xss === 'undefined' ? null : window.__xss};
}"""

PLUGINS_ROW = """pid => [...document.querySelectorAll('#pluginTable tr[data-pid]')].find(e => e.dataset.pid === pid && !e.classList.contains('pm-detail'))"""
PLUGINS_DETAIL = """pid => [...document.querySelectorAll('#pluginTable tr.pm-detail')].find(e => e.dataset.pid === pid)"""

PLUGINS_HOSTILE_ENDPOINT = "/plugin/api/x\"'><img src=x onerror=window.__xss=24>"

PLUGINS_PERMS = """pid => { const d = (""" + PLUGINS_DETAIL + """)(pid); const p = d && d.querySelector('.pm-perms'); if (!p) return null;
    return {text: p.innerText, pid: p.dataset.pid, pending: p.dataset.pending, withheld: p.dataset.withheld, require: p.dataset.require, all: !!p.querySelector('.pm-perms__all'),
            rows: [...p.querySelectorAll('.pm-perms__row')].map(r => ({method: r.dataset.method, endpoint: r.dataset.endpoint, approved: r.dataset.approved, granted: r.dataset.granted,
                   badge: r.querySelector('.zx-badge').innerText.trim(), button: r.querySelector('button').innerText.trim()}))}; }"""
PLUGINS_PERM_CLICK = """([pid, endpoint]) => { const d = (""" + PLUGINS_DETAIL + """)(pid); const p = d.querySelector('.pm-perms');
    if (endpoint === null) { p.querySelector('.pm-perms__all').click(); return; }
    [...p.querySelectorAll('.pm-perms__row')].find(r => r.dataset.endpoint === endpoint).querySelector('button').click(); }"""
PLUGINS_HEALTH = """pid => { const r = (""" + PLUGINS_ROW + """)(pid); return r ? r.querySelector('.pm-health-cell').innerText : ''; }"""


PLUGINS_INSTALL = """pid => { const d = (""" + PLUGINS_DETAIL + """)(pid); const b = d && d.querySelector('.pm-install'); if (!b) return null;
    const rb = b.querySelector('.pm-install__rollback'), rel = b.querySelector('.pm-install__release');
    return {text: b.innerText, pid: b.dataset.pid, signature: b.dataset.signature, canRollback: b.dataset.canRollback, binary: b.dataset.binary,
            badges: [...b.querySelectorAll('.zx-badge')].map(x => x.innerText.trim()),
            rollback: rb ? {text: rb.innerText.trim(), primary: rb.classList.contains('primary')} : null, release: !!rel}; }"""
# confirm() is answered "yes" for one step and its question is kept (a dialog that opens is otherwise a failure of the scenario)
PLUGINS_CONFIRM_ON = "() => { window.__pmConfirmed = []; window.__pmConfirm = window.confirm; window.confirm = m => { window.__pmConfirmed.push(String(m)); return true; }; }"
PLUGINS_CONFIRM_OFF = "() => { const got = window.__pmConfirmed || []; if (window.__pmConfirm) window.confirm = window.__pmConfirm; delete window.__pmConfirm; return got; }"


def plugins_install_block(pg, pid, want=None, timeout=10.0):
    """The "Install and updates" block of an open Details row; with want it waits until want(block) is true."""
    deadline = time.time() + timeout
    while True:
        b = pg.evaluate(PLUGINS_INSTALL, pid)
        if b is not None and (want is None or want(b)):
            return b
        if time.time() > deadline:
            return b
        pg.wait_for_timeout(200)


def plugins_perms(pg, pid, want=None, timeout=10.0):
    """The permissions block of an open Details row; with want (a function of the block) it waits until want is true."""
    deadline = time.time() + timeout
    while True:
        p = pg.evaluate(PLUGINS_PERMS, pid)
        if p is not None and (want is None or want(p)):
            return p
        if time.time() > deadline:
            return p
        pg.wait_for_timeout(200)


# 1x1 transparent PNG for the mocked plugin icons
PLUGINS_PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082")


def plugins_ui(pg, ctx):
    def ok(msg):
        print("  ok   plugins: " + msg, flush=True)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def no_injection(where):
        r = pg.evaluate(PLUGINS_INJECTED)
        if r["xss"] is not None:
            fail("xss", f"{where}: script from plugin text ran: window.__xss = {r['xss']}")
        if r["hits"]:
            fail("xss", f"{where}: plugin text became markup: {r['hits']}")
        if r["xss"] is None and not r["hits"]:
            ok(f"{where}: nothing injected")

    def row_text(pid):
        return pg.evaluate("pid => { const r = (" + PLUGINS_ROW + ")(pid); return r ? r.innerText : null; }", pid)

    def badge(pid):
        return pg.evaluate("pid => { const r = (" + PLUGINS_ROW + ")(pid); const b = r && r.querySelector('.pm-status-cell .zx-badge'); const s = r && r.querySelector('.pm-status'); return b ? {text: b.innerText.trim(), cls: b.className, state: s.dataset.state, health: s.dataset.health} : null; }", pid)

    def open_details(pid):
        pg.evaluate("pid => { const r = (" + PLUGINS_ROW + ")(pid); const b = r.querySelector('.pm-status__more'); if (b.getAttribute('aria-expanded') !== 'true') b.click(); }", pid)
        try:
            pg.wait_for_function("pid => { const d = (" + PLUGINS_DETAIL + ")(pid); return !!d && !!d.querySelector('.pm-detail__live dl') && !!d.querySelector('form.pm-settings'); }", arg=pid, timeout=10000)
            return True
        except Exception:
            fail("details", f"the Details row of {pid[:30]!r} did not open with its Supervision form (the ID must reach the handlers unchanged)")
            return False

    def detail_text(pid):
        return pg.evaluate("pid => { const d = (" + PLUGINS_DETAIL + ")(pid); return d ? d.innerText : ''; }", pid)

    def form_state(pid):
        return pg.evaluate("""pid => { const d = (""" + PLUGINS_DETAIL + """)(pid); const f = d && d.querySelector('form.pm-settings'); if (!f) return null;
            const o = {pid: f.dataset.pid, title: (f.querySelector('.pm-detail__title') || {}).innerText || '', save: !!f.querySelector('button[type=submit].pm-settings__save'), text: f.innerText, fields: {}};
            f.querySelectorAll('[data-key]').forEach(e => { o.fields[e.dataset.key] = {value: e.type === 'checkbox' ? e.checked : e.value, disabled: e.disabled, labelled: e.type === 'checkbox' ? !!e.closest('label') : !!f.querySelector('label[for="' + CSS.escape(e.id) + '"]')}; });
            return o; }""", pid)

    def set_form(pid, values):
        pg.evaluate("""([pid, values]) => { const d = (""" + PLUGINS_DETAIL + """)(pid); const f = d.querySelector('form.pm-settings');
            Object.keys(values).forEach(k => { const e = f.querySelector('[data-key="' + k + '"]'); if (e.type === 'checkbox') e.checked = values[k]; else e.value = values[k]; e.dispatchEvent(new Event('change', {bubbles: true})); }); }""", [pid, values])

    def save_form(pid):
        pg.evaluate("pid => { const d = (" + PLUGINS_DETAIL + ")(pid); d.querySelector('form.pm-settings .pm-settings__save').click(); }", pid)

    def check_build_dialog():
        hostile_build = "make: *** error\n</textarea><img src=x onerror=window.__xss=9><script>window.__xss=10</script>"
        pg.evaluate("msg => showBuildErrorDialog(msg)", hostile_build)
        pg.wait_for_selector("#buildErrorOutput", state="attached", timeout=5000)
        shown = pg.evaluate("document.getElementById('buildErrorOutput').value")
        if shown != hostile_build:
            fail("build dialog", f"the build output is not shown unchanged: {shown!r}")
        no_injection("build error dialog")
        pg.evaluate("$('#buildErrorModal').modal('hide'); $('#buildErrorModal').remove(); $('.ui.dimmer.modals').removeClass('active visible')")
        pg.wait_for_timeout(500)

    def on_dialog(d):
        fail("xss", f"a dialog opened: {d.message}")
        d.dismiss()

    def show_page():
        pg.evaluate("openTabById('plugins')")
        pg.wait_for_selector("#pluginsPage", state="visible", timeout=10000)
        pg.wait_for_timeout(400)

    pg.on("dialog", on_dialog)
    pg.set_viewport_size({"width": 1366, "height": 900})
    try:
        current["page"] = "plugins/mock"
        plugins_mock_part(pg, ok, shot, no_injection, row_text, badge, open_details, detail_text, form_state, set_form, save_form, check_build_dialog, show_page)
        lst = pg.evaluate("fetch('/api/plugins/list').then(r => r.json())")
        live = any(str(x.get("Spec", {}).get("id", "")).startswith("test.chaos.") for x in lst)
        if live:
            current["page"] = "plugins/live"
            plugins_live_part(pg, ok, shot, no_injection, row_text, badge, open_details, detail_text, form_state, set_form, save_form, show_page)
        elif getattr(args, "plugins_live", False):
            fail("setup", "--plugins-live: the instance has no chaos plugins (start it with plugins_run.sh)")
        else:
            print("  note plugins: no chaos plugins in this instance, the live part was not run (plugins_run.sh runs it)", flush=True)
    except Exception as ex:   # a step that timed out is a failure of that step, not a crashed run
        fail("plugins", f"scenario aborted: {' '.join(str(ex).split()[:40])}")
    finally:
        pg.remove_listener("dialog", on_dialog)
        try:
            pg.unroute("**/api/plugins/**")
        except Exception:
            pass
        pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu();")
        pg.wait_for_timeout(800)


def plugins_mock_part(pg, ok, shot, no_injection, row_text, badge, open_details, detail_text, form_state, set_form, save_form, check_build_dialog, show_page):
    now = int(time.time())
    hid, cid = PLUGINS_HOSTILE_ID, "mock.crasher"
    counters = {"Calls": 12, "CallFailures": 2, "CallTimeouts": 1, "CaptureRequests": 4, "CaptureFailures": 1, "EventsSent": 3, "LogLines": 9}

    def status(state, **kw):
        st = {"State": state, "Health": "", "PID": 0, "StartedAt": now - 300, "ExitedAt": 0, "LastSeen": now - 5, "HasExited": False, "ExitCode": 0, "ExitReason": "",
              "LastError": "", "LastErrorAt": 0, "StartCount": 1, "RestartCount": 0, "AutoRestartCount": 0, "NextRestartAt": 0, "RecentFailures": 0, "CrashLoopLimit": 5,
              "Attached": state == "running", "ReadyAfterMs": -1, "LimitsNote": "", "Policy": dict(policy), "Counters": dict(counters)}
        st.update(kw)
        return st

    policy = {"Restart": "never", "ReadinessGate": False, "HealthCheck": "off", "BlockWhenDown": False, "CaptureTimeoutMs": 0, "LogTarget": "main", "LogMaxKB": 1024,
              "LogRateLimit": 0, "MemoryMaxMB": 0, "CPUQuotaPercent": 0, "TasksMax": 0, "MaxOpenFiles": 0}
    hostile_problem = "A call to the plugin failed: <img src=x onerror=window.__xss=13> \"quoted\""
    hostile_source = "https://index.example/<img src=x onerror=window.__xss=28>/index.json"
    prev_version = "1.2.2<img src=x onerror=window.__xss=29>"
    install = {"Known": True, "Source": hostile_source, "Signature": "signed", "Verified": "hash_ok", "Version": "1.2.3", "SHA256": "ab" * 32, "InstalledAt": now - 120,
               "BinaryState": "ok", "PreviousVersion": prev_version, "CanRollback": True, "LastChange": "update", "LastChangeAt": now - 100,
               "LastChangeNote": "Version 1.2.3 did not start properly after the update: <img src=x onerror=window.__xss=30>.", "LastChangeIssue": True, "Note": "x"}
    phase2 = {"Install": install, "Permissions": {"Requested": 2, "Pending": 1, "Withheld": 1, "RequireApproval": True},
              "Contract": {"APIVersion": 7, "SupportedMin": 0, "SupportedMax": 1, "State": "unsupported", "Refused": False, "Note": "<img src=x onerror=window.__xss=25>"}}
    list_running = status("running", Health="ok", PID=4242, **phase2)            # what the plain list says: no port probe
    view_running = status("running", Health="not_listening", PID=4242, LastError=hostile_problem, LastErrorAt=now - 20,
                          LimitsNote="systemd scope: memory 64 MB <img src=x onerror=window.__xss=14>", **phase2)   # what the status view says
    crashed = status("crashed", ExitedAt=now - 60, HasExited=True, ExitCode=3, ExitReason="exit status 3", LastError="The plugin process ended unexpectedly (exit status 3)", LastErrorAt=now - 60)

    def plugin(pid, name, st, enabled, **spec):
        s = {"id": pid, "name": name, "author": "mock", "author_contact": "", "description": "", "url": "", "type": 1, "version_major": 1, "version_minor": 2, "version_patch": 3, "ui_path": ""}
        s.update(spec)
        return {"RootDir": "plugins/x", "Spec": s, "Enabled": enabled, "AssignedPort": 5999 if enabled else 0, "SupportHotRebuild": False,
                "HookAdmin": {"Global": False, "FailClosedDeclared": True, "FailClosedConsent": True, "EffectivePolicy": "fail_closed", "BreakerOpen": False, "ConsecutiveFailure": 0}, "Status": st}

    hostile = plugin(hid, "Hostile <img src=x onerror=window.__xss=1>", list_running, True, type=0,
                     author="<img src=x onerror=window.__xss=3>\"'><script>window.__xss=4</script>", author_contact="javascript:window.__xss=5//\"><img src=x onerror=window.__xss=6>",
                     description="</td></tr><img src=x onerror=window.__xss=7> \"double\" 'single' &amp;", url="javascript:window.__xss=8",
                     hooks={"stages": ["pre_auth<img src=x onerror=window.__xss=15>"], "failure_policy": "fail_closed"})
    crasher = plugin(cid, "Mock crasher", crashed, False)
    plugins = [hostile, crasher]
    load_failures = [{"Folder": "broken<img src=x onerror=window.__xss=11>", "Error": "introspect failed: <script>window.__xss=12</script>", "Time": now}]
    seen = {"status_get": [], "status_post": [], "policy_post": [], "limits": "systemd", "perm_post": [], "settings_post": [], "store_post": [], "ticket_post": [], "ticket": None}
    perm_view = {"ID": hid, "RequireApproval": True, "Pending": 1, "Withheld": 1, "Origin": "baseline", "UpdatedAt": now, "Requested": [
        {"Method": "GET", "Endpoint": "/plugin/api/access/list", "Reason": "List rules <img src=x onerror=window.__xss=22>", "Approved": True, "Granted": True},
        {"Method": "POST", "Endpoint": PLUGINS_HOSTILE_ENDPOINT, "Reason": "\"quoted\" </code><script>window.__xss=23</script>", "Approved": False, "Granted": False}]}
    settings = {"ContractMode": "warn", "RequirePermissionApproval": True, "ContractVersionMin": 0, "ContractVersionMax": 1, "SDKVersion": "1.1.0<img src=x onerror=window.__xss=26>"}
    settings.update({"VerifyMode": "warn", "IndexPublicKey": "", "IndexKeyFromFlag": False, "IndexKeyFingerprint": "0123abcd<img src=x onerror=window.__xss=31>", "IndexKeyProblem": "",
                     "AutoRollback": False, "MaxDownloadMB": 0, "DefaultMaxDownloadMB": 256, "IsolatePluginUI": False, "PluginUIListen": "", "PluginUIOrigin": "",
                     "UIIsolation": {"Enabled": False, "Listening": False, "ListenAddr": "", "DefaultListen": ":8001", "Error": "", "Sandbox": "allow-scripts allow-forms"},
                     "Sources": [{"url": hostile_source, "official": False, "format": "signed", "signature": "bad_signature", "serial": 4, "plugins": 2,
                                  "note": "The signature of this index does not match <img src=x onerror=window.__xss=32>", "checkedAt": now, "error": ""},
                                 {"url": "https://raw.example/index2.json", "official": True, "format": "legacy", "signature": "unsigned", "serial": 0, "plugins": 9, "note": "", "checkedAt": now, "error": ""}]})
    stored = {hid: dict(policy, CaptureTimeoutMs=1500, LogRateLimit=50), cid: dict(policy)}

    def js(rt, body):
        rt.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    def on_status(rt):
        rq = rt.request
        if rq.method == "POST":
            form = dict(urllib.parse.parse_qsl(rq.post_data or "", keep_blank_values=True))
            seen["status_post"].append(form)
            pid = form.get("plugin_id")
            if pid == hid:
                js(rt, {"ID": hid, "Name": hostile["Spec"]["name"], "Status": view_running,
                        "RecentOutput": ["12:00:01 out chaos: ready", "12:00:02 err <img src=x onerror=window.__xss=16></pre><script>window.__xss=17</script>"],
                        "ExitHistory": [{"At": now - 900, "Kind": "crashed", "ExitCode": 3, "Reason": "exit status 3", "UptimeSec": 42, "Action": "would_restart", "WouldInMs": 1000},
                                        {"At": now - 600, "Kind": "<img src=x onerror=window.__xss=18>", "ExitCode": -1, "Reason": "signal: <b>killed</b>", "UptimeSec": 7, "Action": "none"}],
                        "LogFile": "/var/log/<img src=x onerror=window.__xss=19>.log"})
            else:
                js(rt, {"ID": cid, "Name": "Mock crasher", "Status": crashed, "RecentOutput": []})
            return
        seen["status_get"].append(rq.url)
        js(rt, {"Plugins": [{"ID": hid, "Name": hostile["Spec"]["name"], "Status": view_running if "probe=true" in rq.url else list_running}, {"ID": cid, "Name": "Mock crasher", "Status": crashed}],
                "LoadFailures": load_failures})

    def on_policy(rt):
        rq = rt.request
        if rq.method == "POST":
            form = dict(urllib.parse.parse_qsl(rq.post_data or "", keep_blank_values=True))
            seen["policy_post"].append(form)
            js(rt, "OK")
            return
        pid = urllib.parse.parse_qs(urllib.parse.urlparse(rq.url).query).get("plugin_id", [""])[0]
        js(rt, {"ID": pid, "Policy": stored.get(pid, policy), "FailClosedDeclared": True, "FailClosedConsent": True,
                "HealthPath": "/health<img src=x onerror=window.__xss=20>" if pid == hid else "", "ConfigureVia": "" if pid == hid else "stdin",
                "LimitsSupport": seen["limits"] if pid == hid else "none",
                "LimitsNote": "Limits are enforced with a systemd scope per plugin <img src=x onerror=window.__xss=21>" if pid == hid else "Resource limits for plugins are only available on Linux"})

    def on_permissions(rt):
        rq = rt.request
        if rq.method == "POST":
            seen["perm_post"].append(dict(urllib.parse.parse_qsl(rq.post_data or "", keep_blank_values=True)))
            js(rt, "OK")
            return
        pid = urllib.parse.parse_qs(urllib.parse.urlparse(rq.url).query).get("plugin_id", [""])[0]
        js(rt, perm_view if pid == hid else {"ID": pid, "RequireApproval": True, "Pending": 0, "Withheld": 0, "Origin": "", "UpdatedAt": 0, "Requested": []})

    def on_settings(rt):
        rq = rt.request
        if rq.method == "POST":
            seen["settings_post"].append(dict(urllib.parse.parse_qsl(rq.post_data or "", keep_blank_values=True)))
            js(rt, "OK")
            return
        js(rt, settings)

    def on_store(rt):
        rq = rt.request
        seen["store_post"].append((urllib.parse.urlparse(rq.url).path, dict(urllib.parse.parse_qsl(rq.post_data or "", keep_blank_values=True))))
        js(rt, "OK")

    def on_ticket(rt):
        seen["ticket_post"].append(dict(urllib.parse.parse_qsl(rt.request.post_data or "", keep_blank_values=True)))
        js(rt, seen["ticket"])

    def wait_post(key, n):
        deadline = time.time() + 8
        while len(seen[key]) <= n and time.time() < deadline:
            pg.wait_for_timeout(100)
        return seen[key][-1] if len(seen[key]) > n else None

    pg.route("**/api/plugins/icon**", lambda rt: rt.fulfill(status=200, content_type="image/png", body=PLUGINS_PNG))
    pg.route(re.compile(r"/api/plugins/permissions(\?.*)?$"), on_permissions)
    pg.route(re.compile(r"/api/plugins/settings(\?.*)?$"), on_settings)
    pg.route(re.compile(r"/api/plugins/store/(rollback|releaseSource)$"), on_store)
    pg.route(re.compile(r"/api/plugins/ui/ticket$"), on_ticket)
    pg.route("**/api/plugins/list", lambda rt: js(rt, plugins))
    pg.route(re.compile(r"/api/plugins/status(\?.*)?$"), on_status)
    pg.route(re.compile(r"/api/plugins/policy(\?.*)?$"), on_policy)
    try:
        show_page()
        pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu();")
        pg.wait_for_function("document.querySelectorAll('#pluginTable tr[data-pid]').length == 2", timeout=15000)
        pg.wait_for_function("document.querySelector('#pluginLoadFailures li') !== null", timeout=10000)
        pg.wait_for_timeout(600)

        # ---- escaping of the manifest and of the load failure
        no_injection("mocked plugin list")
        text = row_text(hid)
        if text is None:
            fail("escaping", "the row of the hostile plugin is missing (data-pid must hold the ID unchanged)")
            return
        for literal in ("Hostile <img src=x onerror=window.__xss=1>", "<script>window.__xss=4</script>", "</td></tr><img src=x onerror=window.__xss=7>", "\"double\" 'single' &amp;", "pre_auth<img src=x onerror=window.__xss=15>"):
            if literal not in text:
                fail("escaping", f"the manifest text {literal!r} is not shown literally in the row: {text[:400]!r}")
        hrefs = pg.evaluate("pid => { const r = (" + PLUGINS_ROW + ")(pid); return [...r.querySelectorAll('a[href]')].map(a => a.getAttribute('href')); }", hid)
        if not hrefs or not hrefs[0].startswith("mailto:") or any(h.strip().lower().startswith("javascript:") for h in hrefs):
            fail("escaping", f"author link must be mailto: and no link may be javascript:, got {hrefs!r}")
        fails = pg.inner_text("#pluginLoadFailures")
        if "broken<img src=x onerror=window.__xss=11>" not in fails or "<script>window.__xss=12</script>" not in fails or "1 plugin folder could not be loaded" not in fails:
            fail("load failures", f"the folder that cannot be loaded is not listed as text: {fails!r}")
        else:
            ok("the broken folder is listed, as text")

        # ---- status badges
        b = badge(hid)
        if not b or b["text"] != "Not listening" or b["health"] != "not_listening" or "zx-badge--warn" not in b["cls"]:
            fail("status", f"the good plugin must show what the status view answers (Not listening, warning badge), got {b!r}")
        else:
            ok("status badge of the running plugin comes from the status view (Not listening)")
        if not any("probe=true" in u for u in seen["status_get"]):
            fail("probe", f"the page did not ask the status view for the port probe while it is shown: {seen['status_get']!r}")
        b = badge(cid)
        ctext = row_text(cid) or ""
        if not b or b["text"] != "Crashed" or b["state"] != "crashed" or "zx-badge--danger" not in b["cls"] or "Exit code 3" not in ctext:
            fail("status", f"the crashed plugin must show a red Crashed badge with its exit code, got {b!r} / {ctext[:200]!r}")
        else:
            ok("status badge of the crashed plugin: Crashed, Exit code 3")
        summary = pg.inner_text("#pluginStatusSummary")
        if "2 plugins installed" not in summary or "1 crashed" not in summary or "1 not listening" not in summary:
            fail("status", f"summary line above the table: {summary!r}")
        menu = pg.inner_text("#pluginMenu")
        if "1 plugin stopped unexpectedly" not in menu or "No Plugins Installed" in menu or "Hostile <img src=x onerror=window.__xss=1>" not in menu:
            fail("menu", f"side menu with one running and one crashed plugin: {menu!r}")
        else:
            ok("side menu: the running plugin as text and '1 plugin stopped unexpectedly'")
        shot("plugins-mock-list.png")

        # ---- details row
        if open_details(hid):
            if not seen["status_post"] or seen["status_post"][-1].get("plugin_id") != hid or seen["status_post"][-1].get("probe") != "true":
                fail("details", f"the Details call must carry the unchanged plugin ID and probe=true: {seen['status_post'][-1:]!r}")
            d = detail_text(hid)
            for literal in ("Process ID", "4242", "Last problem", "<img src=x onerror=window.__xss=13> \"quoted\"", "memory 64 MB <img src=x onerror=window.__xss=14>",
                            "<img src=x onerror=window.__xss=16></pre><script>window.__xss=17</script>", "/var/log/<img src=x onerror=window.__xss=19>.log",
                            "Exit history", "Crashed (exit code 3)", "<img src=x onerror=window.__xss=18>", "Filter calls", "12 (2 failed, 1 timed out)"):
                if literal not in d:
                    fail("details", f"{literal!r} is not shown (as text) in the Details row: {d[:600]!r}")
            no_injection("details row")
            ok("details row: process facts, last problem, limits, exit history and output as text")

            # ---- Supervision form
            f = form_state(hid)
            want_keys = {"restart", "health_check", "readiness_gate", "capture_timeout_s", "log_target", "log_max_kb", "log_rate_limit", "memory_max_mb", "cpu_quota_percent", "tasks_max", "max_open_files"}
            if not f or f["pid"] != hid or "Supervision" not in f["title"] or not f["save"]:
                fail("supervision", f"the Supervision form is missing, has no Save button or lost the plugin ID: {f and (f['pid'], f['title'], f['save'])!r}")
            elif set(f["fields"]) != want_keys:
                fail("supervision", f"controls of the Supervision form: {sorted(f['fields'])}, expected {sorted(want_keys)}")
            else:
                fl = f["fields"]
                got = {k: fl[k]["value"] for k in fl}
                want = {"restart": "never", "health_check": "off", "readiness_gate": False, "capture_timeout_s": "1.5", "log_target": "main", "log_max_kb": "1024", "log_rate_limit": "50",
                        "memory_max_mb": "0", "cpu_quota_percent": "0", "tasks_max": "0", "max_open_files": "0"}
                if got != want:
                    fail("supervision", f"the form does not show the stored policy: {got} != {want}")
                if any(fl[k]["disabled"] for k in fl):
                    fail("supervision", f"with systemd limits every control must be usable: {[k for k in fl if fl[k]['disabled']]}")
                unl = [k for k in fl if not fl[k]["labelled"]]
                if unl:
                    fail("supervision", f"controls without a label: {unl}")
                for literal in ("Everything here is off unless you turn it on", "/health<img src=x onerror=window.__xss=20>", "systemd scope per plugin <img src=x onerror=window.__xss=21>", "receives its secrets on the command line"):
                    if literal not in f["text"]:
                        fail("supervision", f"{literal!r} is not shown (as text) in the Supervision form")
                set_form(hid, {"restart": "on-failure", "readiness_gate": True, "capture_timeout_s": "2.5", "memory_max_mb": "128"})
                save_form(hid)
                deadline = time.time() + 8
                while not seen["policy_post"] and time.time() < deadline:
                    pg.wait_for_timeout(100)
                post = seen["policy_post"][-1] if seen["policy_post"] else None
                want_post = {"plugin_id": hid, "restart": "on-failure", "health_check": "off", "readiness_gate": "true", "capture_timeout_ms": "2500", "log_target": "main", "log_max_kb": "1024",
                             "log_rate_limit": "50", "memory_max_mb": "128", "cpu_quota_percent": "0", "tasks_max": "0", "max_open_files": "0"}
                if post != want_post:
                    fail("supervision", f"Save posted {post}, expected {want_post}")
                else:
                    ok("Supervision form: shows the stored policy, Save posts the changed values for the right plugin")
                pg.wait_for_timeout(600)
            no_injection("supervision form")
            shot("plugins-mock-details.png")

        # ---- a host without limits: those controls are disabled and not sent
        if open_details(cid):
            f = form_state(cid)
            off = sorted(k for k in f["fields"] if f["fields"][k]["disabled"])
            if off != ["cpu_quota_percent", "max_open_files", "memory_max_mb", "tasks_max"]:
                fail("supervision", f"without limit support exactly the four limit controls must be disabled, got {off}")
            if "receives its secrets on the command line" in f["text"]:
                fail("supervision", "the command line note is shown for a plugin that is configured over stdin")
            n = len(seen["policy_post"])
            save_form(cid)
            deadline = time.time() + 8
            while len(seen["policy_post"]) == n and time.time() < deadline:
                pg.wait_for_timeout(100)
            post = seen["policy_post"][-1] if len(seen["policy_post"]) > n else {}
            if post.get("plugin_id") != cid or any(k in post for k in ("memory_max_mb", "cpu_quota_percent", "tasks_max", "max_open_files")):
                fail("supervision", f"disabled limit controls must not be sent: {post}")
            else:
                ok("Supervision form: limits the host cannot enforce are disabled and not sent")
            pg.wait_for_timeout(500)

        # ---- phase 2: permissions and contract in the list, the Details row and the safety settings
        health = pg.evaluate(PLUGINS_HEALTH, hid)
        if "1 API permission waits for your approval (not granted)" not in health or "Built for a newer Zoraxy: may not work" not in health:
            fail("permissions", f"the Health column must say that a permission waits for approval and that the plugin is of a newer contract: {health!r}")
        if "API permission" in pg.evaluate(PLUGINS_HEALTH, cid) or "newer Zoraxy" in pg.evaluate(PLUGINS_HEALTH, cid):
            fail("permissions", "the Health column of a plugin without permissions and without a contract version says something about them")
        alert = pg.evaluate("() => { const a = document.querySelector('#pluginAlerts [data-alert=permissions]'); return a ? a.innerText : ''; }")
        if "1 plugin asks for Zoraxy API permissions you have not approved" not in alert or "Hostile <img src=x onerror=window.__xss=1>" not in alert or "not granted until you approve" not in alert:
            fail("permissions", f"the notice about permissions nobody approved is missing or wrong: {alert!r}")
        else:
            ok("Health column and notice: a permission waits for approval, plugin of a newer contract")
        # A refused contract version: "not started" only when a start was refused
        refused_lines = pg.evaluate("""() => ["running", "failed_to_start", "stopped"].map(state =>
            pluginHealthInfo({Status: {State: state, Policy: {}, Counters: {}, Contract: {State: "unsupported", Refused: true, APIVersion: 7}}})
              .lines.map(l => l.text).filter(x => x.indexOf("newer Zoraxy") >= 0).join("|"))""")
        if refused_lines != ["Built for a newer Zoraxy: still running, will not be started again", "Built for a newer Zoraxy: not started", "Built for a newer Zoraxy: will not be started"]:
            fail("contract", f"Health column of a plugin of a refused contract version (running, failed to start, stopped): {refused_lines!r}")
        else:
            ok("Health column: a running plugin of a refused contract version is not called 'not started'")
        d = detail_text(hid)
        if "Plugin contract" not in d or "Version 7. This Zoraxy supports 0 to 1" not in d:
            fail("contract", f"the Details row does not explain the contract version: {d[:300]!r}")
        p = plugins_perms(pg, hid, lambda x: len(x["rows"]) == 2)
        if not p or len(p["rows"]) != 2:
            fail("permissions", f"the Details row does not list the two permissions of the plugin: {p!r}")
        else:
            r0, r1 = p["rows"]
            if p["pid"] != hid or p["pending"] != "1" or p["withheld"] != "1" or p["require"] != "true" or not p["all"]:
                fail("permissions", f"permissions block: {p!r}")
            if (r0["endpoint"], r0["badge"], r0["button"]) != ("/plugin/api/access/list", "Approved", "Withdraw") or \
               (r1["method"], r1["endpoint"], r1["badge"], r1["button"]) != ("POST", PLUGINS_HOSTILE_ENDPOINT, "Waiting for approval, not granted", "Approve"):
                fail("permissions", f"rows of the permissions block: {p['rows']!r}")
            for literal in ("Zoraxy API permissions", "POST " + PLUGINS_HOSTILE_ENDPOINT, "List rules <img src=x onerror=window.__xss=22>", "\"quoted\" </code><script>window.__xss=23</script>",
                            "Your approval is required", "installed before permissions were tracked", "Approve the 1 permission shown as not approved"):
                if literal not in p["text"]:
                    fail("permissions", f"{literal!r} is not shown (as text) in the permissions block: {p['text'][:500]!r}")
            want_one = {"plugin_id": hid, "action": "approve", "endpoints": json.dumps([{"Method": "POST", "Endpoint": PLUGINS_HOSTILE_ENDPOINT}], separators=(",", ":"))}
            n = len(seen["perm_post"])
            pg.evaluate(PLUGINS_PERM_CLICK, [hid, PLUGINS_HOSTILE_ENDPOINT])
            post = wait_post("perm_post", n)
            if post != want_one:
                fail("permissions", f"Approve posted {post}, expected {want_one}")
            pg.wait_for_timeout(500)
            plugins_perms(pg, hid, lambda x: len(x["rows"]) == 2 and x["all"])
            n = len(seen["perm_post"])
            pg.evaluate(PLUGINS_PERM_CLICK, [hid, None])
            post = wait_post("perm_post", n)
            if post != want_one:
                fail("permissions", f"'Approve the 1 permission ...' must post exactly the endpoint shown as not approved, posted {post}")
            pg.wait_for_timeout(500)
            plugins_perms(pg, hid, lambda x: len(x["rows"]) == 2)
            n = len(seen["perm_post"])
            pg.evaluate(PLUGINS_PERM_CLICK, [hid, "/plugin/api/access/list"])
            post = wait_post("perm_post", n)
            if post != {"plugin_id": hid, "action": "revoke", "endpoints": json.dumps([{"Method": "GET", "Endpoint": "/plugin/api/access/list"}], separators=(",", ":"))}:
                fail("permissions", f"Withdraw posted {post}")
            else:
                ok("permissions block: endpoints and reasons as text, Approve / Approve all / Withdraw post exactly what is shown")
            pg.wait_for_timeout(500)
        p = plugins_perms(pg, cid, lambda x: "does not ask" in x["text"])
        if not p or "This plugin does not ask for access to the Zoraxy API." not in p["text"] or p["rows"]:
            fail("permissions", f"a plugin without permissions must say so: {p!r}")
        no_injection("permissions block")
        shot("plugins-mock-permissions.png")

        # ---- phase 2 (2.4, 2.5): where a plugin came from, the signature of its index, the previous version and the rollback
        health = pg.evaluate(PLUGINS_HEALTH, hid)
        alert = pg.evaluate("() => { const a = document.querySelector('#pluginAlerts [data-alert=update_failed]'); return a ? a.innerText : ''; }")
        if "Last update did not start properly: roll back under Details" not in health or "1 plugin did not start properly after its update" not in alert or "Hostile <img src=x onerror=window.__xss=1>" not in alert:
            fail("rollback", f"a failed update with a previous version kept must be in the Health column and in a notice: {health!r} / {alert!r}")
        b = plugins_install_block(pg, hid)
        if not b:
            fail("install", "the Details row has no 'Install and updates' block")
        else:
            for literal in ("Install and updates", hostile_source, "Updates only come from this index.", "The download matched the checksum and size of the index.", "ab" * 32,
                            "Version " + prev_version + " is kept in the plugin folder.", "did not start properly after the update: <img src=x onerror=window.__xss=30>."):
                if literal not in b["text"]:
                    fail("install", f"{literal!r} is not shown literally in the install block: {b['text'][:500]!r}")
            if b["pid"] != hid or b["signature"] != "signed" or "Signed" not in b["badges"] or "As installed" not in b["badges"] or b["canRollback"] != "true":
                fail("install", f"install block state: {b!r}")
            if not b["rollback"] or b["rollback"]["text"] != "Roll back to version " + prev_version or not b["rollback"]["primary"] or not b["release"]:
                fail("rollback", f"after a failed update Roll back is the primary action of the block, and the index binding can be lifted: {b!r}")
            pg.evaluate(PLUGINS_CONFIRM_ON)
            n = len(seen["store_post"])
            pg.evaluate("pid => { const d = (" + PLUGINS_DETAIL + ")(pid); d.querySelector('.pm-install__release').click(); }", hid)
            post = wait_post("store_post", n)
            if post != ("/api/plugins/store/releaseSource", {"pluginID": hid}):
                fail("install", f"'Allow updates from any index' posted {post}")
            pg.wait_for_timeout(500)
            plugins_install_block(pg, hid, lambda x: x["rollback"] is not None)
            n = len(seen["store_post"])
            pg.evaluate("pid => { const d = (" + PLUGINS_DETAIL + ")(pid); d.querySelector('.pm-install__rollback').click(); }", hid)
            post = wait_post("store_post", n)
            asked = pg.evaluate(PLUGINS_CONFIRM_OFF)
            if post != ("/api/plugins/store/rollback", {"pluginID": hid}) or len(asked) != 2 or prev_version not in asked[1]:
                fail("rollback", f"Roll back must ask first (naming the version) and post the plugin ID: {post} / {asked}")
            else:
                ok("install block: source, signature, download check and previous version as text; Roll back and 'any index' ask first and post the plugin ID")
            pg.wait_for_function("document.querySelectorAll('#pluginTable tr[data-pid]:not(.pm-detail)').length == 2", timeout=15000)
            pg.wait_for_timeout(600)
        if open_details(cid):
            b = plugins_install_block(pg, cid)
            if not b or "Not recorded" not in b["text"] or b["rollback"] or b["release"] or "None kept" not in b["text"]:
                fail("install", f"a plugin without an install record must say so and offer no rollback: {b!r}")
        states = pg.evaluate("""() => ["signed", "unsigned", "no_key", "missing", "bad_signature", "replayed", "unchecked", "<img src=x onerror=window.__xss=33>", "downgraded"].map(x => { const d = document.createElement('div'); d.innerHTML = pluginSignatureBadge(x); return d.innerText.trim() + "|" + d.firstChild.className; })""")
        if [x.split("|")[0] for x in states] != ["Signed", "Unsigned", "Signed, no key to check it", "Signature missing", "Signature not valid", "Old index served again", "Not checked", "Unknown", "Signature removed"] \
                or "zx-badge--ok" not in states[0] or "zx-badge--danger" not in states[4] or "zx-badge--danger" not in states[5] or "zx-badge--ok" in states[1] \
                or "zx-badge--danger" not in states[8]:
            fail("install", f"signature badges: {states!r}")
        lines = pg.evaluate("""() => [{BinaryState: "changed", LastChangeIssue: true}, {LastChangeIssue: true, LastChange: "auto_rollback"}, {Verified: "hash_mismatch"}, {Known: true, Signature: "unsigned"}].map(inst =>
            pluginHealthInfo({Status: {State: "running", Policy: {}, Counters: {}, Install: inst}}).lines.filter(l => l.cls.indexOf("pm-health__line--install") >= 0).map(l => l.text).join("|"))""")
        if lines != ["Program file changed since it was installed", "Last update failed: previous version restored", "Download did not match its index", ""]:
            fail("install", f"Health column lines about the install: {lines!r}")
        else:
            ok("signature badges for every state; Health column: changed program file, failed update, mismatching download; nothing for an unsigned plugin")
        no_injection("install block")
        shot("plugins-mock-install.png")

        # ---- phase 2 (2.7): the admin page opens a plugin page where Zoraxy says it is
        frame_state = "() => { const f = document.getElementById('pluginContextLoader'); let dark = 'ok'; try { f.contentWindow.setDarkTheme && f.contentWindow.setDarkTheme(true); } catch (e) { dark = 'threw'; } return {src: f.getAttribute('src'), sandbox: f.getAttribute('sandbox'), isolated: f.dataset.isolated, srcdoc: f.getAttribute('srcdoc') || '', dark}; }"
        seen["ticket"] = {"isolated": True, "url": "/favicon.png?mock-ticket", "sandbox": "allow-scripts allow-forms"}
        pg.evaluate("pid => initPluginUIView(pid)", hid)
        pg.wait_for_function("document.getElementById('pluginContextLoader').dataset.isolated === 'true'", timeout=8000)
        fs = pg.evaluate(frame_state)
        if seen["ticket_post"][-1] != {"plugin_id": hid} or fs["src"] != "/favicon.png?mock-ticket" or "allow-same-origin" in fs["sandbox"] or fs["dark"] != "ok":
            fail("isolation", f"an isolated plugin page: the frame must open the ticket address in a sandbox without allow-same-origin, and the theme switch must not trip over it: {fs!r} / {seen['ticket_post'][-1:]!r}")
        seen["ticket"] = {"isolated": False, "url": "/favicon.png?mock-plain", "sandbox": "allow-scripts allow-same-origin"}
        pg.evaluate("pid => initPluginUIView(pid)", hid)
        pg.wait_for_function("document.getElementById('pluginContextLoader').dataset.isolated === 'false'", timeout=8000)
        fs = pg.evaluate(frame_state)
        if fs["src"] != "/favicon.png?mock-plain" or fs["sandbox"] != "allow-scripts allow-same-origin":
            fail("isolation", f"a plugin page that is not isolated opens as before: {fs!r}")
        seen["ticket"] = {"error": "Plugin pages are isolated, but <img src=x onerror=window.__xss=34> is not running"}
        pg.evaluate("pid => initPluginUIView(pid)", hid)
        pg.wait_for_function("(document.getElementById('pluginContextLoader').getAttribute('srcdoc') || '').length > 0", timeout=8000)
        fs = pg.evaluate(frame_state)
        if "&lt;img src=x onerror=window.__xss=34&gt;" not in fs["srcdoc"] or fs["src"] or fs["sandbox"] != "":
            fail("isolation", f"a ticket that cannot be given is shown as text inside the frame: {fs!r}")
        else:
            ok("plugin page frame: ticket address and sandbox without allow-same-origin when isolated, as before when not, an error as text")
        pg.evaluate("document.getElementById('pluginContextLoader').removeAttribute('srcdoc')")
        no_injection("plugin page frame")

        pg.evaluate("loadPluginSafetySettings()")
        pg.wait_for_timeout(600)
        safety = pg.evaluate("() => ({approval: document.getElementById('pluginRequireApproval').checked, refuse: document.getElementById('pluginContractRefuse').checked, info: document.getElementById('pluginContractInfo').textContent, labelled: !!document.getElementById('pluginRequireApproval').closest('label') && !!document.getElementById('pluginContractRefuse').closest('label')})")
        if not safety["approval"] or safety["refuse"] or not safety["labelled"] or "versions 0 to 1 (plugin SDK 1.1.0<img src=x onerror=window.__xss=26>)" not in safety["info"]:
            fail("safety settings", f"the Plugin safety settings do not show what is stored: {safety!r}")
        pg.evaluate("document.getElementById('pluginSafetySettings').open = true")
        n = len(seen["settings_post"])
        pg.click("#pluginContractRefuse")
        post = wait_post("settings_post", n)
        if post != {"contract_mode": "refuse"}:
            fail("safety settings", f"ticking 'Do not start plugins built for a newer plugin contract' posted {post}")
        pg.wait_for_timeout(400)
        n = len(seen["settings_post"])
        pg.click("#pluginRequireApproval")
        post = wait_post("settings_post", n)
        if post != {"require_permission_approval": "false"}:
            fail("safety settings", f"unticking 'Require my approval' posted {post}")
        else:
            ok("Plugin safety settings: show the stored settings, a change posts that one setting")
        pg.wait_for_timeout(600)
        store = pg.evaluate("""() => ({mode: document.getElementById('pluginVerifyMode').value, help: document.getElementById('pluginVerifyModeHelp').textContent,
            key: document.getElementById('pluginIndexKeyState').textContent, auto: document.getElementById('pluginAutoRollback').checked,
            iso: document.getElementById('pluginIsolateUI').checked, ui: document.getElementById('pluginUIState').textContent, listenHelp: document.getElementById('pluginUIListenHelp').textContent,
            sources: [...document.querySelectorAll('#pluginIndexSources .pm-sources__row')].map(r => ({url: r.dataset.url, text: r.innerText, sig: (r.querySelector('[data-signature]') || {dataset: {}}).dataset.signature}))})""")
        if store["mode"] != "warn" or "installed anyway" not in store["help"] or "fingerprint 0123abcd<img src=x onerror=window.__xss=31>" not in store["key"] or store["auto"] or store["iso"] \
                or "not isolated" not in store["ui"] or ":8001" not in store["listenHelp"]:
            fail("safety settings", f"signed index, rollback and plugin pages do not show what is stored: {store!r}")
        srcs = store["sources"]
        if len(srcs) != 2 or srcs[0]["url"] != hostile_source or srcs[0]["sig"] != "bad_signature" or "Signature not valid" not in srcs[0]["text"] or "serial 4" not in srcs[0]["text"] \
                or "does not match <img src=x onerror=window.__xss=32>" not in srcs[0]["text"] or srcs[1]["sig"] != "unsigned" or "Unsigned" not in srcs[1]["text"] or "9 plugins" not in srcs[1]["text"]:
            fail("safety settings", f"the list of plugin indexes with their signature state: {srcs!r}")
        n = len(seen["settings_post"])
        pg.select_option("#pluginVerifyMode", "enforce")
        post = wait_post("settings_post", n)
        if post != {"verify_mode": "enforce"}:
            fail("safety settings", f"choosing Enforce posted {post}")
        pg.wait_for_timeout(400)
        n = len(seen["settings_post"])
        pg.fill("#pluginIndexKey", "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----")
        pg.click("#pluginIndexKeySave")
        post = wait_post("settings_post", n)
        if post != {"index_public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----"}:
            fail("safety settings", f"'Save public key' posted {post}")
        pg.wait_for_timeout(400)
        n = len(seen["settings_post"])
        pg.click("#pluginAutoRollback")
        post = wait_post("settings_post", n)
        if post != {"auto_rollback": "true"}:
            fail("safety settings", f"ticking the automatic rollback posted {post}")
        pg.wait_for_timeout(400)
        n = len(seen["settings_post"])
        pg.fill("#pluginUIListen", "127.0.0.1:20712")
        pg.click("#pluginIsolateUI")
        post = wait_post("settings_post", n)
        if post != {"isolate_plugin_ui": "true", "plugin_ui_listen": "127.0.0.1:20712", "plugin_ui_origin": ""}:
            fail("safety settings", f"ticking 'Isolate plugin pages' posted {post}")
        else:
            ok("Plugin safety settings: signature mode, public key, index list with signature state, automatic rollback and isolation show what is stored and post one change each")
        pg.wait_for_timeout(600)
        shot("plugins-mock-safety.png")
        no_injection("safety settings")

        check_build_dialog()

        # ---- the port probe is only asked for while the page is on screen
        pg.evaluate("openTabById('status')")
        pg.wait_for_selector("#pluginsPage", state="hidden", timeout=10000)
        pg.wait_for_timeout(500)
        seen["status_get"].clear()
        pg.evaluate("refreshPluginStatus(true)")
        pg.wait_for_timeout(900)
        if not seen["status_get"] or any("probe" in u for u in seen["status_get"]):
            fail("probe", f"with the Plugin Manager not on screen the status must be read without the port probe: {seen['status_get']!r}")
        else:
            ok("no port probe while the page is not on screen")
        seen["status_get"].clear()
        show_page()
        pg.wait_for_timeout(900)
        if not any("probe=true" in u for u in seen["status_get"]):
            fail("probe", f"opening the Plugin Manager must refresh the status with the port probe: {seen['status_get']!r}")
        else:
            ok("opening the page refreshes the status with the port probe")

        # ---- side menu wording
        def menu_with(answer):
            pg.unroute("**/api/plugins/list")
            pg.route("**/api/plugins/list", lambda rt: js(rt, answer))
            pg.evaluate("initPluginSideMenu()")
            pg.wait_for_timeout(700)
            return pg.inner_text("#pluginMenu")

        def stopped(x):
            y = json.loads(json.dumps(x))
            y["Enabled"] = False
            y["Status"]["State"] = "stopped"
            y["Status"]["Health"] = ""
            return y

        text = menu_with([stopped(x) for x in plugins])
        if "2 plugins installed, none running" not in text or "No Plugins Installed" in text:
            fail("menu", f"two stopped plugins: expected '2 plugins installed, none running', got {text!r}")
        text = menu_with([stopped(plugins[0])])
        if "1 plugin installed, not running" not in text:
            fail("menu", f"one stopped plugin: expected '1 plugin installed, not running', got {text!r}")
        both = [stopped(x) for x in plugins]
        for x in both:
            x["Status"]["State"] = "exited"
        text = menu_with(both)
        if "2 plugins stopped unexpectedly" not in text:
            fail("menu", f"two plugins that ended by themselves: expected '2 plugins stopped unexpectedly', got {text!r}")
        text = menu_with([])
        if "No Plugins Installed" not in text:
            fail("menu", f"empty list: expected 'No Plugins Installed', got {text!r}")
        else:
            ok("side menu wording for stopped, ended and no plugins")
        no_injection("side menu")

        # ---- App Store: an install or update error can quote what a downloaded binary says its ID is; the toast renders HTML
        hostile_err = 'the downloaded plugin says its ID is "<img src=x onerror=window.__xss=40>", the index says "a.b": refused'
        store_err = re.compile(r"/api/plugins/store/(install|resync)$")
        pg.route(store_err, lambda rt: js(rt, {"error": hostile_err}))
        try:
            pg.evaluate("openTabById('appstore')")
            pg.wait_for_function("typeof asInstallApp == 'function' && typeof asEscapeHtml == 'function'", timeout=10000)
            pg.wait_for_timeout(600)
            pg.evaluate("asInstallApp('a.b')")
            pg.wait_for_function("document.getElementById('messageBox').textContent.indexOf('says its ID is') >= 0", timeout=5000)
            toast = pg.evaluate("({text: document.getElementById('messageBox').textContent, imgs: document.querySelectorAll('#messageBox img').length})")
            if "<img src=x onerror=window.__xss=40>" not in toast["text"] or toast["imgs"]:
                fail("appstore", f"the install error must be shown as text: {toast!r}")
            else:
                ok("App Store: an install error that quotes a hostile plugin ID is shown as text")
            no_injection("App Store install error")
        except Exception as e:
            fail("appstore", f"install error check: {e}")
        finally:
            pg.unroute(store_err)
    finally:
        pg.unroute("**/api/plugins/icon**")
        pg.unroute("**/api/plugins/list")
        pg.unroute(re.compile(r"/api/plugins/status(\?.*)?$"))
        pg.unroute(re.compile(r"/api/plugins/policy(\?.*)?$"))
        pg.unroute(re.compile(r"/api/plugins/permissions(\?.*)?$"))
        pg.unroute(re.compile(r"/api/plugins/settings(\?.*)?$"))
        pg.unroute(re.compile(r"/api/plugins/store/(rollback|releaseSource)$"))
        pg.unroute(re.compile(r"/api/plugins/ui/ticket$"))
        pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu(); if (typeof loadPluginSafetySettings == 'function') loadPluginSafetySettings();")
        pg.wait_for_timeout(1000)


def plugins_live_part(pg, ok, shot, no_injection, row_text, badge, open_details, detail_text, form_state, set_form, save_form, show_page):
    hid, cid = PLUGINS_HOSTILE_ID, PLUGINS_CRASHER_ID
    # ---- wait until the instance is in the expected state (the crasher exits 2 s after its start)
    state = {}
    deadline = time.time() + 30
    while time.time() < deadline:
        lst = pg.evaluate("fetch('/api/plugins/list').then(r => r.json())")
        state = {x["Spec"]["id"]: x for x in lst}
        if state.get(cid, {}).get("Status", {}).get("State") == "crashed" and state.get(hid, {}).get("Status", {}).get("State") == "running":
            break
        pg.wait_for_timeout(500)
    else:
        fail("setup", "expected the hostile plugin running and the crasher crashed, got " + json.dumps({k: v.get("Status", {}).get("State") for k, v in state.items()}))
        return
    if len(state) != 2:
        fail("setup", f"expected 2 loaded plugins, got {sorted(state)}")

    show_page()
    pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu();")
    pg.wait_for_function("document.querySelectorAll('#pluginTable tr[data-pid]').length >= 2", timeout=20000)
    pg.wait_for_function("document.querySelector('#pluginLoadFailures li') !== null", timeout=10000)
    pg.wait_for_function("document.querySelector('#pluginMenu .item') !== null", timeout=10000)
    pg.wait_for_timeout(600)

    # ---- hostile manifest stays text, status badges
    no_injection("real plugin list")
    hostile = row_text(hid)
    if hostile is None:
        fail("escaping", "the row of the hostile plugin is missing (data-pid must hold the ID unchanged)")
        return
    for literal in ("Hostile <img src=x onerror=window.__xss=1>", "<script>window.__xss=4</script>", "</td></tr><img src=x onerror=window.__xss=7>", "\"double\" 'single' &amp;"):
        if literal not in hostile:
            fail("escaping", f"the manifest text {literal!r} is not shown literally in the row: {hostile[:300]!r}")
    b = badge(hid)
    if not b or b["text"] != "Running" or b["state"] != "running" or "zx-badge--ok" not in b["cls"]:
        fail("status", f"the running plugin (its port is open) must show a green Running badge, got {b!r}")
    else:
        ok("real plugin: Running badge (port probed by the status view)")
    href = pg.evaluate("pid => { const r = (" + PLUGINS_ROW + ")(pid); const a = r && r.querySelector('.sub.header a'); return a ? a.getAttribute('href') : null; }", hid)
    if href is None or not href.startswith("mailto:"):
        fail("escaping", f"the author link of a non-http contact must be a mailto: link, got {href!r}")
    menu_item = pg.evaluate("pid => { const a = [...document.querySelectorAll('#pluginMenu .item[pluginid]')].find(e => e.getAttribute('pluginid') === pid); return a ? a.innerText : null; }", hid)
    if menu_item is None or "Hostile <img src=x onerror=window.__xss=1>" not in menu_item:
        fail("escaping", f"the running hostile plugin is not in the side menu as plain text: {menu_item!r}")
    b = badge(cid)
    crasher = row_text(cid) or ""
    if not b or b["text"] != "Crashed" or "Exit code 3" not in crasher:
        fail("status", f"the crashed plugin is not shown as Crashed with its exit code: {b!r} / {crasher[:300]!r}")
    else:
        ok("real plugin: Crashed badge with the exit code")
    fails = pg.inner_text("#pluginLoadFailures")
    if "garbage" not in fails or "1 plugin folder could not be loaded" not in fails:
        fail("load failures", f"the folder that cannot be loaded is not listed: {fails!r}")
    if row_text("test.chaos.garbage") is not None:
        fail("load failures", "the folder that cannot be loaded is in the plugin table")
    menu = pg.inner_text("#pluginMenu")
    if "1 plugin stopped unexpectedly" not in menu or "No Plugins Installed" in menu:
        fail("menu", f"the side menu does not say that a plugin stopped unexpectedly: {menu!r}")
    shot("plugins-list.png")

    # ---- details and a real save of the Supervision form, with the hostile ID
    if open_details(hid):
        d = detail_text(hid)
        if "Process ID" not in d or "chaos: ready" not in d:
            fail("details", f"the Details row does not show the process and the last output: {d[:400]!r}")
        no_injection("real details row")
        f = form_state(hid)
        if not f or f["fields"]["restart"]["value"] != "never" or f["fields"]["capture_timeout_s"]["value"] != "0" or f["fields"]["health_check"]["value"] != "off" or f["fields"]["readiness_gate"]["value"]:
            fail("supervision", f"a plugin nobody configured must show every supervision option off: {f and f['fields']!r}")
        set_form(hid, {"restart": "on-failure", "capture_timeout_s": "2.5", "log_rate_limit": "200"})
        save_form(hid)
        pol = {}
        deadline = time.time() + 10
        while time.time() < deadline:
            view = pg.evaluate("pid => fetch('/api/plugins/policy?plugin_id=' + encodeURIComponent(pid)).then(r => r.json())", hid)
            pol = view.get("Policy", {})
            if pol.get("Restart") == "on-failure":
                break
            pg.wait_for_timeout(300)
        if pol.get("Restart") != "on-failure" or pol.get("CaptureTimeoutMs") != 2500 or pol.get("LogRateLimit") != 200 or pol.get("HealthCheck") != "off" or pol.get("ReadinessGate"):
            fail("supervision", f"Save did not store the policy of the plugin with the hostile ID: {pol!r}")
        else:
            ok("real plugin: the Supervision form saved restart, answer timeout and output rate limit")
        pg.wait_for_function("pid => { const r = (" + PLUGINS_ROW + ")(pid); return !!r && r.querySelector('.pm-health-cell').innerText.includes('Restart: when it crashes'); }", arg=hid, timeout=10000)
        f = form_state(hid)
        if not f or f["fields"]["restart"]["value"] != "on-failure" or f["fields"]["capture_timeout_s"]["value"] != "2.5":
            fail("supervision", f"after Save the form does not show the stored values: {f and f['fields']!r}")
        no_injection("after saving the supervision form")
        shot("plugins-details.png")

        # ---- phase 2: permissions of a plugin that is new (plugins_run.sh adds it after the first start)
        def perm_api():
            return pg.evaluate("pid => fetch('/api/plugins/permissions?plugin_id=' + encodeURIComponent(pid)).then(r => r.json())", hid)

        def set_safety(box, on):
            pg.evaluate("document.getElementById('pluginSafetySettings').open = true")
            if pg.evaluate("id => document.getElementById(id).checked", box) != on:
                pg.click("#" + box)
            deadline = time.time() + 10
            while time.time() < deadline:
                got = pg.evaluate("fetch('/api/plugins/settings').then(r => r.json())")
                if got.get("RequirePermissionApproval") == on:
                    return True
                pg.wait_for_timeout(300)
            return False

        view = perm_api()
        eps = [(e["Method"], e["Endpoint"], e["Approved"], e["Granted"]) for e in view.get("Requested", [])]
        if view.get("RequireApproval") or view.get("Pending") != 2 or eps != [("GET", "/plugin/api/access/list", False, True), ("POST", PLUGINS_HOSTILE_ENDPOINT, False, True)]:
            fail("permissions", f"a plugin installed after the first start must have its permissions not approved but granted (approval is off by default): {view!r}")
        health = pg.evaluate(PLUGINS_HEALTH, hid)
        alert = pg.evaluate("() => { const a = document.querySelector('#pluginAlerts [data-alert=permissions]'); return a ? a.innerText : ''; }")
        if "2 API permissions you have not approved" not in health or "They are granted, because approval is not required" not in alert:
            fail("permissions", f"default mode: the Health column and the notice must report the two permissions as not approved: {health!r} / {alert!r}")
        else:
            ok("real plugin: new permissions are granted and reported by default")
        p = plugins_perms(pg, hid, lambda x: len(x["rows"]) == 2)
        if not p or [r["badge"] for r in p["rows"]] != ["Not approved, granted", "Not approved, granted"] or "Your approval is not required" not in p["text"]:
            fail("permissions", f"default mode: permissions block: {p!r}")
        no_injection("real permissions block")

        if not set_safety("pluginRequireApproval", True):
            fail("permissions", "ticking 'Require my approval' did not store the setting")
        else:
            p = plugins_perms(pg, hid, lambda x: x["require"] == "true" and x["withheld"] == "2")
            view = perm_api()
            if not p or p["withheld"] != "2" or view.get("Withheld") != 2 or [r["badge"] for r in p["rows"]] != ["Waiting for approval, not granted"] * 2:
                fail("permissions", f"with approval required nothing of the new plugin may be granted: {p!r} / {view!r}")
            pg.wait_for_function("pid => { const r = (" + PLUGINS_ROW + ")(pid); return !!r && r.querySelector('.pm-health-cell').innerText.includes('2 API permissions wait for your approval (not granted)'); }", arg=hid, timeout=15000)
            shot("plugins-permissions-required.png")
            # approve the endpoint whose name is markup, with its own button
            pg.evaluate(PLUGINS_PERM_CLICK, [hid, PLUGINS_HOSTILE_ENDPOINT])
            p = plugins_perms(pg, hid, lambda x: x["withheld"] == "1")
            view = perm_api()
            eps = [(e["Endpoint"], e["Approved"], e["Granted"]) for e in view.get("Requested", [])]
            if eps != [("/plugin/api/access/list", False, False), (PLUGINS_HOSTILE_ENDPOINT, True, True)]:
                fail("permissions", f"Approve on one row must approve exactly that endpoint (its name must reach the server unchanged): {eps!r}")
            else:
                ok("real plugin: with approval required nothing is granted; one endpoint approved with its button")
            # and the rest with the button below the list
            pg.evaluate(PLUGINS_PERM_CLICK, [hid, None])
            p = plugins_perms(pg, hid, lambda x: x["pending"] == "0")
            view = perm_api()
            if view.get("Pending") != 0 or view.get("Withheld") != 0 or not p or p["all"] or [r["badge"] for r in p["rows"]] != ["Approved", "Approved"]:
                fail("permissions", f"'Approve the N ...' must approve what is left: {view!r} / {p!r}")
            else:
                ok("real plugin: the remaining permission approved, nothing waits any more")
            pg.wait_for_function("pid => { const r = (" + PLUGINS_ROW + ")(pid); return !!r && !r.querySelector('.pm-health-cell').innerText.includes('API permission'); }", arg=hid, timeout=15000)
            if pg.evaluate("() => !!document.querySelector('#pluginAlerts [data-alert=permissions]')"):
                fail("permissions", "the notice about permissions nobody approved is still shown after approving all of them")
            no_injection("after approving permissions")
            set_safety("pluginRequireApproval", False)

    # ---- "Stop" on a plugin that is already dead is not an error
    res = pg.evaluate("""pid => new Promise(resolve => $.cjax({url: '/api/plugins/disable', type: 'POST', data: {plugin_id: pid}, success: d => resolve(d), error: x => resolve({error: 'http ' + x.status})}))""", cid)
    if isinstance(res, dict) and res.get("error") is not None:
        fail("stop", f"stopping the crashed plugin was answered as a failure: {res}")
    else:
        ok("real plugin: stopping a crashed plugin is answered as done")

    # ---- the Stop button works with the hostile ID, then the menu drops the plugin
    pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu();")
    pg.wait_for_timeout(1200)
    pg.evaluate("pid => { const r = (" + PLUGINS_ROW + ")(pid); r.querySelector('.pluginEnableButton').click(); }", hid)
    deadline = time.time() + 20
    st = None
    while time.time() < deadline:
        lst = pg.evaluate("fetch('/api/plugins/list').then(r => r.json())")
        st = next((x["Status"]["State"] for x in lst if x["Spec"]["id"] == hid), None)
        if st == "stopped":
            break
        pg.wait_for_timeout(500)
    if st != "stopped":
        fail("stop", f"the Stop button did not stop the plugin with the hostile ID (state {st!r})")
    else:
        ok("real plugin: the Stop button works for an ID full of quotes")
    pg.wait_for_timeout(1500)
    no_injection("after stop")
    menu = pg.inner_text("#pluginMenu")
    if "1 plugin stopped unexpectedly" not in menu or "Hostile" in menu:
        fail("menu", f"after stopping the last running plugin the menu should only carry the crash note: {menu!r}")
    shot("plugins-after-stop.png")

    plugins_store_live(pg, ok, shot, no_injection, open_details, show_page)


def plugins_store_live(pg, ok, shot, no_injection, open_details, show_page):
    """Items 2.4, 2.5 and 2.7 against the real API. plugins_run.sh serves a local signed plugin index (PLUGINS_STORE_URL, the files
    in PLUGINS_STORE_DIR, the public key in PLUGINS_INDEX_PUB) and names a free listen address (PLUGINS_UI_LISTEN)."""
    store_url, store_dir, pub_file, ui_listen = (os.environ.get(k, "") for k in ("PLUGINS_STORE_URL", "PLUGINS_STORE_DIR", "PLUGINS_INDEX_PUB", "PLUGINS_UI_LISTEN"))
    if not (store_url and store_dir and pub_file and ui_listen):
        fail("setup", "the local plugin store of plugins_run.sh is missing (PLUGINS_STORE_URL, PLUGINS_STORE_DIR, PLUGINS_INDEX_PUB, PLUGINS_UI_LISTEN)")
        return
    import shutil
    rid, uid = "test.chaos.rollme", "test.chaos.uiprobe"
    index = store_url + "/index.json"

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(resolve => $.cjax({url: p, type: 'POST', data: d, success: r => resolve(r), error: x => resolve({error: 'http ' + x.status})}))""", [path, data])

    def get(path):
        return pg.evaluate("p => fetch(p).then(r => r.json())", path)

    def failed(res):
        return isinstance(res, dict) and res.get("error") is not None

    def plugin_state(pid):
        return next((x for x in get("/api/plugins/list") if x["Spec"]["id"] == pid), None)

    def wait_state(pid, want, timeout=20):
        deadline = time.time() + timeout
        st = None
        while time.time() < deadline:
            p = plugin_state(pid)
            st = p and p["Status"]["State"]
            if st == want:
                return p
            pg.wait_for_timeout(400)
        fail("store", f"{pid} did not reach the state {want} (now {st})")
        return plugin_state(pid)

    def redraw():
        show_page()
        pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu(); loadPluginSafetySettings();")
        pg.wait_for_function("pid => !!(" + PLUGINS_ROW + ")(pid)", arg=rid, timeout=20000)
        pg.wait_for_timeout(600)

    # ---- 2.4: the public key goes in through the page, the index is signed, the plugin is installed from it
    res = post("/api/plugins/store/sources/add", {"url": index})
    if failed(res):
        fail("store", f"adding the local plugin index failed: {res}")
        return
    show_page()
    pg.evaluate("document.getElementById('pluginSafetySettings').open = true; loadPluginSafetySettings();")
    pg.wait_for_function("url => [...document.querySelectorAll('#pluginIndexSources .pm-sources__row')].some(r => r.dataset.url === url)", arg=index, timeout=15000)
    before = pg.evaluate("url => { const r = [...document.querySelectorAll('#pluginIndexSources .pm-sources__row')].find(r => r.dataset.url === url); return {sig: r.querySelector('[data-signature]').dataset.signature, text: r.innerText}; }", index)
    if before["sig"] != "no_key" or "no plugin index public key is configured" not in before["text"]:
        fail("signature", f"a signed index without a configured key must say so: {before!r}")
    pg.fill("#pluginIndexKey", open(pub_file).read())
    pg.click("#pluginIndexKeySave")
    try:
        pg.wait_for_function("url => { const r = [...document.querySelectorAll('#pluginIndexSources .pm-sources__row')].find(r => r.dataset.url === url); return !!r && r.querySelector('[data-signature]').dataset.signature === 'signed'; }", arg=index, timeout=20000)
        ok("real index: 'no key' before the public key is saved on the page, 'Signed' after it")
    except Exception:
        fail("signature", "after saving the public key the index is not shown as signed: " + pg.inner_text("#pluginIndexSources"))
    pg.select_option("#pluginVerifyMode", "enforce")
    pg.wait_for_function("fetch('/api/plugins/settings').then(r => r.json()).then(s => s.VerifyMode === 'enforce')", timeout=10000)
    for pid in (rid, uid):
        res = post("/api/plugins/store/install", {"pluginID": pid})
        if failed(res):
            fail("store", f"installing {pid} from the signed index under enforce failed: {res}")
            return
        res = post("/api/plugins/enable", {"plugin_id": pid})
        if failed(res):
            fail("store", f"starting {pid} failed: {res}")
    wait_state(rid, "running")
    wait_state(uid, "running")
    redraw()
    if open_details(rid):
        b = plugins_install_block(pg, rid, lambda x: x["binary"] == "ok")
        if not b or b["signature"] != "signed" or index not in b["text"] or "The download matched the checksum and size of the index." not in b["text"] or b["rollback"] or "1.0.0" not in b["text"]:
            fail("install", f"a plugin installed from the signed index: {b!r}")
        else:
            ok("real plugin: installed under enforce, Details shows the index, 'Signed', the matching download and the unchanged program file")
        shot("plugins-install-signed.png")

    # ---- 2.5: the index publishes version 1.1.0, which crashes at start. Reported, then rolled back with the button
    for name in ("index.json", "index.json.sig"):
        shutil.copyfile(os.path.join(store_dir, "next", name), os.path.join(store_dir, name))
    res = post("/api/plugins/store/resync", {})
    upd = next((u for u in get("/api/plugins/store/checkUpdates") if u["pluginID"] == rid), None)
    if failed(res) or not upd or not upd["updateAvailable"] or upd["latestVersion"] != "1.1.0" or upd["signature"] != "signed" or not upd["boundToSource"] or upd["blocked"]:
        fail("update", f"the new index must offer version 1.1.0 of the plugin, from the index it was installed from: {res} / {upd}")
    res = post("/api/plugins/store/update", {"pluginID": rid})
    if not failed(res) or "did not start properly" not in res["error"] or "Roll back" not in res["error"]:
        fail("update", f"an update whose new version crashes at start must be reported with the way out: {res}")
    redraw()
    try:
        pg.wait_for_function("pid => { const r = (" + PLUGINS_ROW + ")(pid); return !!r && r.querySelector('.pm-health-cell').innerText.includes('Last update did not start properly: roll back under Details'); }", arg=rid, timeout=15000)
        pg.wait_for_function("!!document.querySelector('#pluginAlerts [data-alert=update_failed]')", timeout=10000)
    except Exception:
        fail("update", "the failed update is not in the Health column and the notice: " + pg.evaluate(PLUGINS_HEALTH, rid))
    if open_details(rid):
        b = plugins_install_block(pg, rid, lambda x: x["rollback"] is not None)
        if not b or not b["rollback"] or b["rollback"]["text"] != "Roll back to version 1.0.0" or not b["rollback"]["primary"] or "did not start properly" not in b["text"]:
            fail("rollback", f"after the failed update the Details row must offer the rollback: {b!r}")
        else:
            shot("plugins-update-failed.png")
            pg.evaluate(PLUGINS_CONFIRM_ON)
            pg.evaluate("pid => { const d = (" + PLUGINS_DETAIL + ")(pid); d.querySelector('.pm-install__rollback').click(); }", rid)
            p = wait_state(rid, "running")
            pg.evaluate(PLUGINS_CONFIRM_OFF)
            spec = (p or {}).get("Spec", {})
            inst = (p or {}).get("Status", {}).get("Install", {})
            if (spec.get("version_major"), spec.get("version_minor")) != (1, 0) or inst.get("CanRollback") or inst.get("LastChange") != "rollback" or inst.get("Version") != "1.0.0":
                fail("rollback", f"the Roll back button must restore and start version 1.0.0: {spec} / {inst}")
            else:
                ok("real plugin: the new version crashes at start, the page reports it, the Roll back button restores version 1.0.0 and it runs")
            pg.wait_for_timeout(1500)
            if pg.evaluate("!!document.querySelector('#pluginAlerts [data-alert=update_failed]')"):
                fail("rollback", "the notice about the failed update is still shown after the rollback")
    no_injection("install and rollback")

    # ---- 2.7: an admin API call from a plugin page works when the page is not isolated, and fails when it is
    def probe(expect_isolated):
        pg.evaluate("pid => initPluginUIView(pid)", uid)
        pg.wait_for_function("want => document.getElementById('pluginContextLoader').dataset.isolated === want", arg="true" if expect_isolated else "false", timeout=15000)
        attrs = pg.evaluate("() => { const f = document.getElementById('pluginContextLoader'); return {src: f.getAttribute('src'), sandbox: f.getAttribute('sandbox')}; }")
        deadline = time.time() + 25
        text = ""
        while time.time() < deadline:
            for fr in pg.frames:
                if fr.url and ("/plugin.ui/" + uid in fr.url or "/t/" in fr.url):
                    try:
                        text = fr.evaluate("() => (document.getElementById('probe') || {}).textContent || ''")
                    except Exception:
                        text = ""
            if text.startswith("{"):
                break
            pg.wait_for_timeout(400)
        try:
            return attrs, json.loads(text)
        except Exception:
            fail("isolation", f"the plugin page did not finish its probe (frame {attrs!r}): {text!r}")
            return attrs, {}

    def contract_mode():
        return get("/api/plugins/settings").get("ContractMode")

    # From here on the browser reports what this step provokes on purpose: the admin origin answers 403, and the calls of the
    # isolated page to the admin API are blocked (CORS, no CSRF token). Those reports are the proof, not failures; they are
    # tolerated for this step only, by its page label.
    current["page"] = "plugins/isolation"
    expected_noise = re.compile(r"^\[plugins/isolation\] (http: 403 |console\.error: |requestfailed: )")
    if not any(a.pattern == expected_noise.pattern for a in allow):
        allow.append(expected_noise)
    attrs, out = probe(False)
    if attrs["src"] != "/plugin.ui/" + uid + "/" or "allow-same-origin" not in attrs["sandbox"] or out.get("read") != 200 or out.get("write") != 200 or not out.get("csrfSeen") or contract_mode() != "refuse":
        fail("isolation", f"not isolated (the default): the plugin page is under the admin origin and its admin API call works, as before: {attrs!r} / {out!r} / contract mode {contract_mode()!r}")
    else:
        ok("plugin page, not isolated (default): it read the plugin list and changed a plugin safety setting with the session of the administrator")
    post("/api/plugins/settings", {"contract_mode": "warn"})

    pg.evaluate("document.getElementById('pluginSafetySettings').open = true")
    pg.fill("#pluginUIListen", ui_listen)
    pg.click("#pluginIsolateUI")
    try:
        pg.wait_for_function("document.getElementById('pluginUIState').dataset.listening === 'true' && document.getElementById('pluginIsolateUI').checked", timeout=15000)
    except Exception:
        fail("isolation", "ticking 'Isolate plugin pages' did not open the listener: " + pg.inner_text("#pluginUIState"))
        return
    blocked = pg.evaluate("pid => fetch('/plugin.ui/' + encodeURIComponent(pid) + '/').then(r => r.status)", uid)
    attrs, out = probe(True)
    port = ui_listen.rsplit(":", 1)[1]
    if blocked != 403 or ":" + port + "/t/" not in (attrs["src"] or "") or "allow-same-origin" in attrs["sandbox"] or "allow-scripts" not in attrs["sandbox"]:
        fail("isolation", f"isolated: the page must come from the listener of its own in a sandbox without allow-same-origin, and the admin origin must refuse it: {attrs!r}, admin origin answered {blocked}")
    if out.get("csrfSeen") or out.get("cookieSeen") or out.get("isolated") != "true" or out.get("read") != "blocked" or out.get("write") != "blocked" or out.get("cookieJS") != "denied" or contract_mode() != "warn":
        fail("isolation", f"isolated: the admin API call of the plugin page must fail and it must see nothing of the session: {out!r} / contract mode {contract_mode()!r}")
    else:
        ok("plugin page, isolated: no cookie, no CSRF token, its admin API calls are blocked and the setting it tried to change is unchanged")
    shot("plugins-isolated.png")
    pg.click("#pluginIsolateUI")
    pg.wait_for_function("fetch('/api/plugins/settings').then(r => r.json()).then(s => s.IsolatePluginUI === false && s.UIIsolation.Listening === false)", timeout=15000)
    attrs, out = probe(False)
    if out.get("read") != 200:
        fail("isolation", f"isolation turned off again: plugin pages are back under the admin origin: {attrs!r} / {out!r}")
    else:
        ok("isolation off again: the plugin page is back under the admin origin")
    post("/api/plugins/settings", {"contract_mode": "warn", "verify_mode": "warn"})
    no_injection("isolated plugin page")

