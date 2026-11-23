"""Plugin Manager scenario (phases 0 and 1 of docs/plugins/reliability-plan.md). exec()'d by smoke.py (namespace: fail, current,
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
  * the build error dialog shows hostile build output as text;
  * the side menu wording for "stopped unexpectedly", "none running" and the empty list.

Part 2, only on an instance prepared by plugins_run.sh (three real chaos plugins: hostile manifest and running, crasher, folder
that answers -introspect with garbage; --plugins-live makes their absence a failure): the same list checks against the real API,
the real Details call, a real save of the Supervision form that is read back from /api/plugins/policy, "Stop" on the crashed
plugin answered as done, and the Stop button with the hostile ID.

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
    list_running = status("running", Health="ok", PID=4242)                      # what the plain list says: no port probe
    view_running = status("running", Health="not_listening", PID=4242, LastError=hostile_problem, LastErrorAt=now - 20,
                          LimitsNote="systemd scope: memory 64 MB <img src=x onerror=window.__xss=14>")   # what the status view says
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
    seen = {"status_get": [], "status_post": [], "policy_post": [], "limits": "systemd"}
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

    pg.route("**/api/plugins/icon**", lambda rt: rt.fulfill(status=200, content_type="image/png", body=PLUGINS_PNG))
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
    finally:
        pg.unroute("**/api/plugins/icon**")
        pg.unroute("**/api/plugins/list")
        pg.unroute(re.compile(r"/api/plugins/status(\?.*)?$"))
        pg.unroute(re.compile(r"/api/plugins/policy(\?.*)?$"))
        pg.evaluate("plugin_detail_open = {}; initiatePluginList(); initPluginSideMenu();")
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
