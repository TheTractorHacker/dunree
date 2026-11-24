"""Smoke scenario of the default rule template (upstream #877). exec()'d by smoke.py (namespace: fail, current, args, os, re,
check_horizontal); run alone with --tpl-default-only on a throw-away instance. It makes its own template and rules and removes them.

Checks: nothing is preselected until a default is chosen (New proxy rule dialog starts on Basic, the New site form on None, no
"default" badge); HTTP Proxy > Templates offers "Default for new rules" (app presets are not offered, an unknown name is refused by
the API); after choosing, the dialog and the New site form start on that template, a rule created without touching the template
field gets its settings (HSTS on, uptime monitor off), a rule created after picking Basic does not, and an API request that names
no template is not touched; deleting the template clears the default again; both dialogs are dark in the dark theme and do not scroll sideways at 390px. Screenshots (light, dark, 390px)
go to --out."""

TD_TPL = "Smoke default tpl"
TD_HOSTS = ["td-default.smoke.test", "td-basic.smoke.test", "td-api.smoke.test"]


def tpl_default_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def default_name():
        return js("fetch('/api/proxy/templates/default').then(r => r.json())").get("name")

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def open_dialog():
        js("openNewRuleDialog()")
        pg.wait_for_selector("#newRuleModal.visible", timeout=8000)
        pg.wait_for_timeout(900)

    def close_dialog():
        pg.click("#nrCancel")
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=8000)

    def picked():
        return js("(document.querySelector('#newRuleModal input[name=nrTpl]:checked') || {}).value")

    def badges():
        return js("[...document.querySelectorAll('#newRuleModal .nrDefTpl')].map(e => e.closest('.nrTpl').querySelector('input').value)")

    def create(host):
        pg.fill("#nrDomain", host)
        pg.fill("#nrUpstream", "127.0.0.1:9")
        pg.click("#nrCreate")
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=10000)
        pg.wait_for_timeout(600)

    def detail(host):
        return post("/api/proxy/detail", {"type": "host", "epname": host})

    def open_manager():
        js("openRuleTemplateManager()")
        pg.wait_for_selector("#ruleTplModal.visible .rtTable", timeout=8000)
        pg.wait_for_timeout(600)

    def close_manager():
        pg.click("#rtClose")
        pg.wait_for_selector("#ruleTplModal", state="hidden", timeout=8000)

    def shots(name, sel, focus):
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("390", False, 390)):
            theme(dark)
            pg.set_viewport_size({"width": w, "height": 1000})
            pg.wait_for_timeout(500)
            if w == 390:
                over = js("s => { const m = document.querySelector(s); return m.scrollWidth - m.clientWidth; }", sel)
                if over > 1:
                    fail("tpl-default", f"{name}: the dialog scrolls sideways by {over}px at 390px")
            if dark:  # a white dialog under the light dark-theme text was unreadable
                bg = js("s => getComputedStyle(document.querySelector(s)).backgroundColor", sel)
                if sum(int(x) for x in re.findall(r"\d+", bg)[:3]) > 300:
                    fail("tpl-default", f"{name}: the dialog keeps a light background ({bg}) in the dark theme")
            pg.locator(focus).scroll_into_view_if_needed()
            pg.wait_for_timeout(200)
            pg.screenshot(path=os.path.join(args.out, f"tpl-default-{name}-{label}.png"))
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 1000})
        pg.wait_for_timeout(300)

    current["page"] = "tpl-default"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    allow.append(re.compile(r"td-[a-z]+\.smoke\.test|127\.0\.0\.1:9\b"))  # the made-up upstream is not reachable, on purpose
    for h in TD_HOSTS:
        post("/api/proxy/del", {"ep": h})
    post("/api/proxy/templates/default", {"name": ""})
    post("/api/proxy/templates/delete", {"name": TD_TPL})
    js("openTabById('httprp')")
    pg.wait_for_timeout(800)

    # ---- 1. off by default: nothing preselected, nothing marked
    if default_name() != "":
        fail("tpl-default", f"no default template may be set on a fresh instance, got {default_name()!r}")
    open_dialog()
    if picked() != "" or badges():
        fail("tpl-default", f"without a default the dialog must start on Basic with no badge, got {picked()!r} / {badges()}")
    close_dialog()

    # ---- 2. choose the default in the template manager
    r = post("/api/proxy/templates/save", {"template": '{"Name":"%s","Description":"HSTS on, no uptime monitor","HSTSMaxAge":31536000,"UptimeMonitor":false,"Headers":[{"Direction":1,"Key":"X-Frame-Options","Value":"DENY"}]}' % TD_TPL})
    if r and isinstance(r, dict) and r.get("error"):
        fail("tpl-default", f"could not save the test template: {r}")
    if not post("/api/proxy/templates/default", {"name": "No such template"}).get("error") or default_name() != "":
        fail("tpl-default", "an unknown template must be refused as default")
    open_manager()
    opts = js("[...document.querySelectorAll('#rtDefault option')].map(o => o.value)")
    presets = [t["Name"] for t in js("fetch('/api/proxy/templates/list').then(r => r.json())") if t.get("Category") == "app"]
    if opts[:1] != [""] or TD_TPL not in opts or "Secure web app" not in opts or any(p in opts for p in presets):
        fail("tpl-default", f"unexpected choices for the default template: {opts}")
    if pg.input_value("#rtDefault") != "" or pg.locator("#ruleTplModal .rtDefBadge").count():
        fail("tpl-default", "the manager must show no default before one is chosen")
    # keyboard: Chrome fires "change" on every arrow step of a closed select; only the value the user stops on may be saved
    saves = []
    count_saves = lambda rq: saves.append(rq.post_data or "") if rq.method == "POST" and rq.url.endswith("/api/proxy/templates/default") else None
    pg.on("request", count_saves)
    pg.focus("#rtDefault")
    for _ in range(3):
        pg.keyboard.press("ArrowDown")
        pg.wait_for_timeout(120)
    stepped = pg.input_value("#rtDefault")
    if stepped != opts[3]:
        fail("tpl-default", f"three arrow steps should stop on {opts[3]!r}, the select shows {stepped!r}")
    pg.wait_for_selector("#ruleTplModal .rtDefBadge", timeout=5000)
    pg.wait_for_timeout(600)
    if len(saves) != 1 or default_name() != stepped:
        fail("tpl-default", f"stepping through the list with the arrow keys must save once, the value stopped on; saved {len(saves)} times, default {default_name()!r}")
    if js("document.activeElement && document.activeElement.id") != "rtDefault":
        fail("tpl-default", "saving the default must leave the keyboard focus on the select")
    # leaving the field saves at once (no waiting for the pause), again one request
    del saves[:]
    for _ in range(3):
        pg.keyboard.press("ArrowUp")
        pg.wait_for_timeout(120)
    pg.keyboard.press("Tab")
    pg.wait_for_function("() => !document.querySelector('#ruleTplModal .rtDefBadge')", timeout=3000)
    pg.wait_for_timeout(1200)
    if len(saves) != 1 or default_name() != "":
        fail("tpl-default", f"tabbing out of the select must save the value once; saved {len(saves)} times, default {default_name()!r}")
    pg.remove_listener("request", count_saves)
    pg.select_option("#rtDefault", TD_TPL)
    pg.wait_for_selector(f"#ruleTplModal tr:has-text('{TD_TPL}') .rtDefBadge", timeout=5000)
    if default_name() != TD_TPL or pg.input_value("#rtDefault") != TD_TPL or pg.locator("#ruleTplModal .rtDefBadge").count() != 1:
        fail("tpl-default", f"the chosen default was not saved / shown: {default_name()!r}")
    shots("manager-top", "#ruleTplModal", "#rtDefault")
    shots("manager", "#ruleTplModal", "#ruleTplModal .rtDefBadge")
    close_manager()

    # ---- 3. the dialog starts on it; an untouched template field applies it
    open_dialog()
    if picked() != TD_TPL or badges() != [TD_TPL]:
        fail("tpl-default", f"the dialog must start on the default template, got {picked()!r} / {badges()}")
    pg.fill("#nrDomain", TD_HOSTS[0])
    shots("dialog", "#newRuleModal", "#newRuleModal .nrDefTpl")
    if picked() != TD_TPL:
        fail("tpl-default", "the preselection was lost while the dialog was open")
    create(TD_HOSTS[0])
    d = detail(TD_HOSTS[0])
    if (d.get("HeaderRewriteRules") or {}).get("HSTSMaxAge") != 31536000 or not d.get("DisableUptimeMonitor"):
        fail("tpl-default", f"the default template was not applied to the new rule: {str(d)[:300]}")

    # ---- 4. the exception: pick Basic for one rule
    open_dialog()
    pg.click("#newRuleModal .nrTpl:has-text('Basic')")
    create(TD_HOSTS[1])
    d = detail(TD_HOSTS[1])
    if (d.get("HeaderRewriteRules") or {}).get("HSTSMaxAge") != 0 or d.get("DisableUptimeMonitor"):
        fail("tpl-default", f"a rule created with Basic must not get the default template: {str(d)[:300]}")
    # the choice was for that one rule: the next dialog starts on the default again
    open_dialog()
    if picked() != TD_TPL:
        fail("tpl-default", f"the next dialog must start on the default again, got {picked()!r}")
    close_dialog()
    # the default cannot be read: the dialog must not preselect the one it remembers from the open before (it may be gone since)
    td_down = re.compile(r"/api/proxy/templates/default")
    allow.append(td_down)
    pg.route(td_down, lambda route: route.fulfill(status=500, body="") if route.request.method == "GET" else route.continue_())
    open_dialog()
    if picked() != "" or badges():
        fail("tpl-default", f"when the default cannot be read the dialog must start on Basic, got {picked()!r} / {badges()}")
    close_dialog()
    pg.unroute(td_down)
    pg.wait_for_timeout(300)
    allow.remove(td_down)
    open_dialog()
    if picked() != TD_TPL:
        fail("tpl-default", f"with the default readable again the dialog must start on it, got {picked()!r}")
    close_dialog()

    # ---- 5. API clients that name no template get no template
    r = post("/api/proxy/add", {"type": "host", "rootname": TD_HOSTS[2], "ep": "127.0.0.1:9", "tls": False, "tlsval": False, "bpwsorg": True,
                               "bypassGlobalTLS": False, "bauth": False, "cred": "[]", "rate": False, "ratenum": 100, "access": "default",
                               "stickysess": False, "tags": "", "enableUtm": True, "utmURI": ""})
    d = detail(TD_HOSTS[2])
    if (d.get("HeaderRewriteRules") or {}).get("HSTSMaxAge") != 0 or d.get("DisableUptimeMonitor"):
        fail("tpl-default", f"a request without a template was changed by the default ({r}): {str(d)[:300]}")

    # ---- 6. the full New site form follows the same default
    js("openTabById('rules')")
    pg.wait_for_selector("#newProxyTemplate", state="attached", timeout=8000)
    pg.wait_for_function("n => document.getElementById('newProxyTemplate').value === n", arg=TD_TPL, timeout=8000)

    # ---- 7. deleting the template clears the default everywhere
    js("openTabById('httprp')")
    pg.wait_for_timeout(600)
    open_manager()
    row = f"#ruleTplModal tr:has-text('{TD_TPL}') .rtDelBtn"
    pg.click(row)
    pg.click(row)
    pg.wait_for_function("n => !document.getElementById('ruleTplModal').innerText.includes(n)", arg=TD_TPL, timeout=8000)
    if default_name() != "" or pg.input_value("#rtDefault") != "" or pg.locator("#ruleTplModal .rtDefBadge").count():
        fail("tpl-default", f"deleting the default template must clear the default, got {default_name()!r}")
    close_manager()
    open_dialog()
    if picked() != "" or badges():
        fail("tpl-default", f"after the delete the dialog must start on Basic again, got {picked()!r}")
    close_dialog()
    if js("document.getElementById('newProxyTemplate').value") != "":
        fail("tpl-default", "after the delete the New site form must be back on None")

    for h in TD_HOSTS:
        post("/api/proxy/del", {"ep": h})
