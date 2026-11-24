"""Security rules page scenario (Rules builder). Called from smoke.py: rules_ui(pg, ctx, h) with h = dict of the smoke helpers
(fail, current, settle, check_horizontal, out). Everything is built through the UI; the API is only used to read back what
the server stored and to prepare fixtures (a list, a hostile rule)."""
import json
import os
import http.server
import threading
import urllib.parse


def rules_ui(pg, ctx, h):
    fail, current, settle, check_horizontal, out = h["fail"], h["current"], h["settle"], h["check_horizontal"], h["out"]
    current["page"] = "rules"
    pg.set_viewport_size({"width": 1366, "height": 900})

    def post(url, body):
        return pg.evaluate("""([u, b]) => new Promise(res => $.cjax({url: u, method: 'POST', contentType: 'application/json', data: JSON.stringify(b), dataType: 'json',
            success: d => res(d), error: x => res({status: x.status, error: (x.responseJSON || {}).error || 'http'})}))""", [url, body])

    def get(url):
        return pg.evaluate("u => fetch(u).then(r => r.json())", url)

    def rules(site=""):
        return get("/api/ruleset/rules?site=" + site)

    def shot(name):
        pg.screenshot(path=os.path.join(out, name), full_page=True)

    def savebar_click():
        pg.click("#rbEditor .zx-savebar [data-zx-save]")

    def valid():
        pg.wait_for_selector("#rbEditor .rb-status.is-ok", timeout=8000)

    # clean slate (the instance is shared with other scenarios)
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})

    for l in get("/api/ruleset/lists"):
        post("/api/ruleset/list/delete", {"name": l["name"]})
    pg.evaluate("openTabById('ruleset')")
    pg.wait_for_selector("#rbList .zx-empty", timeout=8000)
    if pg.locator("#rbTemplates .rb-tpl").count() != 7:
        fail("rules", "the template gallery must show 7 templates")
    shot("rules-empty.png")

    # ---- template opens the builder pre-filled and log-only ----
    pg.click("#rbTemplates .rb-tpl[data-tpl=block-country]")
    pg.wait_for_selector("#rbEditor .rb-group")
    if pg.locator("#rbEditor .zx-segmented__item[aria-checked=true]").inner_text().strip() != "Log-only":
        fail("rules", "a template must open in log-only mode")
    pg.click("#rbBack")  # new rule counts as unsaved: confirm dialog
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-ok], .zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList", state="visible")

    # ---- build a rule only through the UI ----
    pg.click("#rbNew")
    pg.wait_for_selector("#rbEditor .rb-group")
    pg.locator("#rbEditor input.zx-input").first.fill("Smoke admin rule")
    row0 = pg.locator("#rbEditor .rb-row").nth(0)
    row0.locator(".rb-val input").fill("/admin")
    pg.click("#rbEditor .rb-group.is-root > .rb-ghead [data-act=addc]")
    row1 = pg.locator("#rbEditor .rb-row").nth(1)
    row1.locator(".rb-field").select_option("ip.country")
    row1.locator(".rb-op").select_option("not_in")
    row1.locator(".rb-picker input").fill("US")
    row1.locator(".rb-picker input").press("Enter")
    # nested group (OR) with two conditions
    pg.click("#rbEditor .rb-group.is-root > .rb-ghead [data-act=addg]")
    pg.wait_for_selector("#rbEditor .rb-group .rb-group")
    inner = pg.locator("#rbEditor .rb-group .rb-group")
    inner.locator(".rb-gop").select_option("or")
    inner.locator(".rb-row").nth(0).locator(".rb-val input").fill("/api")
    inner.locator("> .rb-ghead [data-act=addc]").click()
    r2 = inner.locator(".rb-row").nth(1)
    r2.locator(".rb-field").select_option("http.header")
    r2.locator(".rb-key").fill("x-api-key")
    r2.locator(".rb-op").select_option("not_exists")
    valid()
    sent = pg.inner_text("#rbEditor .rb-sentence")
    if "the path starts with /admin" not in sent or "United States (US)" not in sent or "block with status 403" not in sent or "(" not in sent:
        fail("rules", f"plain-English sentence wrong: {sent!r}")
    expr = pg.inner_text("#rbEditor .rb-expr")
    if 'http.path starts_with "/admin"' not in expr or "x-api-key" not in expr or " or " not in expr:
        fail("rules", f"expression view wrong: {expr!r}")
    shot("rules-editor-light.png")

    # ---- text view round trip and validation error display ----
    pg.check("#rbAdv")
    pg.wait_for_selector("#rbEditor textarea.rb-text")
    text = pg.input_value("#rbEditor textarea.rb-text")
    if text.strip() != expr.strip():
        fail("rules", f"text view must show the canonical expression, got {text!r} vs {expr!r}")
    pg.fill("#rbEditor textarea.rb-text", 'http.path starts_with')
    pg.wait_for_selector("#rbEditor .rb-caret", timeout=8000)
    if "Line 1, column" not in pg.inner_text("#rbEditor .rb-when"):
        fail("rules", "text errors must show line and column")
    shot("rules-text-error.png")
    pg.fill("#rbEditor textarea.rb-text", 'http.path starts_with "/admin" and ip.country not in ["US"]')
    valid()
    pg.uncheck("#rbAdv")
    pg.wait_for_selector("#rbEditor .rb-row")
    if pg.locator("#rbEditor .rb-row").count() != 2 or pg.locator("#rbEditor .rb-row").nth(0).locator(".rb-val input").input_value() != "/admin":
        fail("rules", "switching back from text must restore the visual tree")

    # ---- save as log-only ----
    savebar_click()
    pg.wait_for_function("document.querySelector('#rbEdTitle').textContent.indexOf('Edit rule') === 0", timeout=8000)
    rs = rules()
    if len(rs) != 1 or not rs[0]["dry_run"] or rs[0]["name"] != "Smoke admin rule" or "/admin" not in rs[0]["expression"]:
        fail("rules", f"saved rule wrong: {rs}")

    # ---- tester inside the editor shows the rule matching ----
    ti = pg.locator("#rbEditor .rb-tform input[type=text]")
    ti.nth(0).fill("https://example.com/admin/users")
    ti.nth(2).fill("DE")
    pg.click("#rbEditor .rb-tform button:has-text('Run the test')")
    pg.wait_for_selector("#rbEditor .rb-testres .rb-verdict", timeout=8000)
    if "This rule matches the request" not in pg.inner_text("#rbEditor .rb-testres") or "nothing was performed" not in pg.inner_text("#rbEditor .rb-testres").lower():
        fail("rules", "tester must show the match and say nothing was performed")
    ti.nth(2).fill("US")
    pg.click("#rbEditor .rb-tform button:has-text('Run the test')")
    pg.wait_for_function("document.querySelector('#rbEditor .rb-testres').textContent.indexOf('does not match') >= 0", timeout=8000)
    shot("rules-tester.png")
    pg.click("#rbBack")
    pg.wait_for_selector("#rbList tr[data-id]")
    row = pg.locator("#rbList tr[data-id]").first
    if "Log-only" not in row.inner_text() or "Smoke admin rule" not in row.inner_text():
        fail("rules", "list row must show the name and the log-only badge")

    # ---- enable / disable ----
    row.locator("input[data-act=enable]").uncheck()
    pg.wait_for_function("1", timeout=500)
    pg.wait_for_timeout(500)
    if rules()[0]["enabled"]:
        fail("rules", "disable did not reach the server")
    row.locator("input[data-act=enable]").check()
    pg.wait_for_timeout(500)
    if not rules()[0]["enabled"]:
        fail("rules", "enable did not reach the server")

    # ---- reorder ----
    post("/api/ruleset/rule/create", {"site": "", "rule": {"name": "Second", "expression": 'http.path == "/two"', "action": {"type": "log"}}})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id] >> nth=1")
    pg.locator("#rbList tr[data-id]").nth(1).locator("button[data-act=up]").click()
    pg.wait_for_function("document.querySelector('#rbList tr[data-id] b').textContent === 'Second'", timeout=5000)
    if [r["name"] for r in rules()] != ["Second", "Smoke admin rule"]:
        fail("rules", "reorder did not reach the server")
    if pg.evaluate("document.activeElement && document.activeElement.getAttribute('data-act')") not in ("up", "down"):
        fail("rules", "focus must stay on the move button after a move")

    # ---- enforce confirmation with the tester, cancel then confirm ----
    pg.locator("#rbList tr[data-id]").nth(0).locator("button[data-act=mode]").click()
    pg.wait_for_selector(".zx-dialog .rb-testres", timeout=8000)
    shot("rules-enforce-dialog.png")
    pg.keyboard.press("Escape")
    if not rules()[0]["dry_run"]:
        fail("rules", "cancelling the enforce dialog must keep the rule log-only")
    pg.locator("#rbList tr[data-id]").nth(0).locator("button[data-act=mode]").click()
    pg.wait_for_selector(".zx-dialog .rb-testres", timeout=8000)
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_function("document.querySelector('#rbList tr[data-id] .rb-modebtn').textContent.trim() === 'Enforcing'", timeout=5000)
    if rules()[0]["dry_run"]:
        fail("rules", "enforce did not reach the server")

    # ---- lock-out warning: a broad block rule that names the admin host ----
    pg.click("#rbNew")
    pg.wait_for_selector("#rbEditor .rb-group")
    pg.locator("#rbEditor input.zx-input").first.fill("Broad block")
    pg.locator("#rbEditor .rb-row").nth(0).locator(".rb-val input").fill("/")
    valid()
    pg.wait_for_selector("#rbEditor .zx-callout:has-text('lock you out')", timeout=8000)
    shot("rules-lockout.png")
    pg.click("#rbBack")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList tr[data-id]")

    # ---- delete with confirmation ----
    pg.locator("#rbList tr[data-id]").nth(1).locator("button[data-act=del]").click()
    pg.wait_for_selector(".zx-dialog")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_function("document.querySelectorAll('#rbList tr[data-id]').length === 1", timeout=5000)
    if len(rules()) != 1:
        fail("rules", "delete did not reach the server")

    # ---- lists ----
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelLists]")
    pg.click("#rbNewList")
    pg.wait_for_selector("#rbListForm input")
    pg.locator("#rbListForm input").nth(0).fill("office")
    pg.locator("#rbListForm select").select_option("ip")
    pg.locator("#rbListForm textarea").fill("203.0.113.0/24\n198.51.100.7")
    pg.click("#rbListForm button:has-text('Create list')")
    pg.wait_for_selector("#rbListsBody tr[data-list=office]")
    # "New list" with an existing name must not silently replace that list
    pg.click("#rbNewList")
    pg.wait_for_selector("#rbListForm input")
    pg.locator("#rbListForm input").nth(0).fill("office")
    pg.locator("#rbListForm select").select_option("ip")
    pg.locator("#rbListForm textarea").fill("1.1.1.1")
    pg.click("#rbListForm button:has-text('Create list')")
    pg.wait_for_function("(document.querySelector('#rbListForm .zx-error') || {textContent: ''}).textContent.indexOf('already exists') >= 0", timeout=3000)
    kept = [l for l in get("/api/ruleset/lists") if l["name"] == "office"]
    if not kept or kept[0]["items"] != ["203.0.113.0/24", "198.51.100.7"]:
        fail("rules", f"a duplicate list name overwrote the existing list: {kept}")
    pg.click("#rbListForm button:has-text('Cancel')")
    # the tester explains a malformed URL in plain words, without the Go parser text
    bad_url = post("/api/ruleset/test", {"site": "", "method": "GET", "url": "not a url"})
    msg = json.dumps(bad_url)
    if "not valid" not in msg or "parse" in msg or "invalid URI" in msg:
        fail("rules", f"the tester must not show raw parser errors: {msg[:200]}")
    pg.click("#rbListsBody tr[data-list=office] button[aria-label^='Edit list']")
    pg.wait_for_selector("#rbListForm textarea")
    pg.locator("#rbListForm textarea").fill("203.0.113.0/24")
    pg.click("#rbListForm button:has-text('Save list')")
    pg.wait_for_function("document.querySelector('#rbListsBody tr[data-list=office] td[data-label=Entries]').textContent === '1'", timeout=5000)
    ok = post("/api/ruleset/rule/create", {"site": "", "rule": {"name": "Uses office", "expression": "ip.src in $office", "action": {"type": "log"}}})
    pg.evaluate("RB.refresh()")
    pg.wait_for_function("document.querySelector('#rbListsBody tr[data-list=office]').textContent.indexOf('1 rule') >= 0", timeout=5000)
    pg.click("#rbListsBody tr[data-list=office] button[aria-label^='Delete list']", force=True)
    pg.wait_for_timeout(500)
    if pg.locator(".zx-dialog").count():
        fail("rules", "a list in use must not offer deletion")
    allow = h.get("allow")
    if allow is not None:
        import re
        allow.append(re.compile(r"400.*/api/ruleset/list/delete"))
    refused = post("/api/ruleset/list/delete", {"name": "office"})
    if "error" not in refused:
        fail("rules", "the API must refuse to delete a list in use")
    shot("rules-lists.png")
    post("/api/ruleset/rule/delete", {"site": "", "id": ok["id"]})
    pg.evaluate("RB.refresh()")
    pg.wait_for_function("document.querySelector('#rbListsBody tr[data-list=office]').textContent.indexOf('not used') >= 0", timeout=5000)
    pg.click("#rbListsBody tr[data-list=office] button[aria-label^='Delete list']")
    pg.wait_for_selector(".zx-dialog")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_function("!document.querySelector('#rbListsBody tr[data-list=office]')", timeout=5000)

    # ---- import from /api/ruleset/migrate (response mocked with one proposal; creation is real) ----
    mock = {"statement": "Read-only: nothing was created.", "proposals": [
        {"source": "path_rule", "source_ref": "app.example.com /legacy", "site": "", "exact": False, "notes": ["differs: trailing slash"], "valid": True,
         "rule": {"name": "Imported legacy", "expression": 'http.path starts_with "/legacy"', "dry_run": True, "enabled": True, "action": {"type": "block", "status": 403}}}],
        "not_converted": [{"source": "bot_rule", "source_ref": "weird bot", "reason": "uses a feature the rules cannot express"}]}
    pg.route("**/api/ruleset/migrate", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(mock)))
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelImport]")
    pg.click("#rbImportScan")
    pg.wait_for_selector("#rbImportBody .rb-prop")
    t = pg.inner_text("#rbImportBody")
    if "approximate" not in t or "differs: trailing slash" not in t or "cannot be converted" not in t.lower() or "weird bot" not in t:
        fail("rules", f"import view incomplete: {t[:300]!r}")
    pg.click("#rbImportBody button:has-text('Create selected')")
    pg.wait_for_function("document.querySelector('#rbImportBody').textContent.indexOf('1 rule(s) created as log-only') >= 0", timeout=8000)
    pg.unroute("**/api/ruleset/migrate")
    imp = [r for r in rules() if r["name"] == "Imported legacy"]
    if len(imp) != 1 or not imp[0]["dry_run"]:
        fail("rules", "imported rule must exist and be log-only")

    # ---- variables ({{name}}, issue #89): defined in one place, followed by lists and access rules ----
    def probe(ip, expr="ip.src in $office_var"):
        r = post("/api/ruleset/test", {"site": "", "method": "GET", "url": "https://probe.example/", "client_ip": ip, "expression": expr})
        return bool(r.get("rules") and r["rules"][0].get("matched"))

    def form_post(url, data):
        return pg.evaluate("""([u, d]) => new Promise(res => $.cjax({url: u, type: 'POST', data: d, success: x => res(x), error: x => res({error: x.status})}))""", [url, data])

    for v in get("/api/vars/list")["variables"]:
        post("/api/vars/delete", {"name": v["name"]})
    if allow is not None:
        allow.append(re.compile(r"400.*/api/vars/set"))  # the two refusals below (built-in name, existing name) are the point
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelVars]")
    pg.wait_for_selector("#rbVarsBody tr[data-var=external_ip]", timeout=8000)
    if "built-in" not in pg.locator("#rbVarsBody tr[data-var=external_ip]").inner_text():
        fail("rules", "{{external_ip}} must be listed as a built-in variable")
    if pg.locator("#rbVarsBody tr[data-var=external_ip] button").count():
        fail("rules", "a built-in variable must not offer edit / delete")
    if "read-only" not in pg.locator("#rbVarsBody tr[data-var=external_ip] td.zx-actions").inner_text():
        fail("rules", "the actions cell of a built-in variable must say read-only instead of being empty")
    if pg.locator("#rbVarsLoadError").count():
        fail("rules", "no load problem must be shown while the variables file is fine")
    pg.click("#rbNewVar")
    pg.wait_for_selector("#rbVarForm input")
    pg.locator("#rbVarForm input").nth(0).fill("external_ip")
    pg.locator("#rbVarForm input").nth(1).fill("192.0.2.1")
    pg.click("#rbVarForm button:has-text('Create variable')")
    pg.wait_for_function("(document.querySelector('#rbVarForm .zx-error') || {textContent: ''}).textContent.indexOf('built-in') >= 0", timeout=3000)
    pg.locator("#rbVarForm input").nth(0).fill("remote_office_ext_ip")
    pg.locator("#rbVarForm input").nth(1).fill("203.0.113.9")
    pg.locator("#rbVarForm input").nth(2).fill("Smoke office")
    pg.click("#rbVarForm button:has-text('Create variable')")
    pg.wait_for_selector("#rbVarsBody tr[data-var=remote_office_ext_ip]")
    # "New variable" with an existing name must not replace it
    pg.click("#rbNewVar")
    pg.wait_for_selector("#rbVarForm input")
    pg.locator("#rbVarForm input").nth(0).fill("remote_office_ext_ip")
    pg.locator("#rbVarForm input").nth(1).fill("1.1.1.1")
    pg.click("#rbVarForm button:has-text('Create variable')")
    pg.wait_for_function("(document.querySelector('#rbVarForm .zx-error') || {textContent: ''}).textContent.indexOf('already exists') >= 0", timeout=3000)
    pg.click("#rbVarForm button:has-text('Cancel')")
    stored = [v for v in get("/api/vars/list")["variables"] if v["name"] == "remote_office_ext_ip"]
    if len(stored) != 1 or stored[0]["value"] != "203.0.113.9":
        fail("rules", f"the variable was not stored as entered: {stored}")
    # a list entry follows the variable; an undefined one is flagged and matches nothing
    post("/api/ruleset/list/save", {"name": "office_var", "type": "ip", "items": ["{{remote_office_ext_ip}}", "{{missing_var}}"]})
    if not probe("203.0.113.9") or probe("198.51.100.50"):
        fail("rules", "a list holding {{remote_office_ext_ip}} must match the variable's address only")
    pg.click("#rbVarsBody tr[data-var=remote_office_ext_ip] button[aria-label^='Edit variable']")
    pg.wait_for_selector("#rbVarForm input")
    if not pg.locator("#rbVarForm input").nth(0).evaluate("e => e.readOnly"):
        fail("rules", "the name of an existing variable must be read-only")
    pg.locator("#rbVarForm input").nth(1).fill("198.51.100.50, 2001:db8::/48")
    pg.click("#rbVarForm button:has-text('Save variable')")
    pg.wait_for_function("document.querySelector('#rbVarsBody tr[data-var=remote_office_ext_ip] td[data-label=Value]').textContent.indexOf('198.51.100.50') === 0", timeout=5000)
    if probe("203.0.113.9") or not probe("198.51.100.50") or not probe("2001:db8::7"):
        fail("rules", "changing the variable in the UI must change what the list matches, without editing the list")
    if "list $office_var" not in pg.locator("#rbVarsBody tr[data-var=remote_office_ext_ip] td[data-label='Used in']").inner_text():
        fail("rules", "the Variables table must show the list that uses the variable")
    # the same reference as an IP entry of an access rule
    form_post("/api/whitelist/ip/add", {"ip": "{{remote_office_ext_ip}}", "id": "default", "comment": "smoke"})
    used = [v for v in get("/api/vars/list")["variables"] if v["name"] == "remote_office_ext_ip"][0]["used_by"]
    if not any(u.startswith("access rule") for u in used):
        fail("rules", f"a {{{{name}}}} whitelist entry must be reported as a use of the variable: {used}")
    # ... is marked in the access rule's table with its current value, an undefined one with a warning
    form_post("/api/whitelist/ip/add", {"ip": "{{missing_var}}", "id": "default", "comment": "smoke undefined"})
    form_post("/api/blacklist/ip/add", {"ip": "{{remote_office_ext_ip}}", "id": "default", "comment": "smoke"})
    pg.evaluate("openTabById('access')")
    for table in ("#whitelistIpTable", "#blacklistIpTable"):
        pg.wait_for_function("(t) => { var e = document.querySelector(t + \" tr[ip='\" + encodeURIComponent('{{remote_office_ext_ip}}') + \"'] .accessVarValue\"); return e && e.textContent.indexOf('198.51.100.50') >= 0; }", arg=table, timeout=8000)
    miss = pg.locator("#whitelistIpTable tr[ip='" + urllib.parse.quote("{{missing_var}}", safe="") + "']")
    if miss.locator(".accessVarMissing").count() != 1 or "matches nothing" not in miss.inner_text():
        fail("rules", "a whitelist entry whose variable has no value must carry a warning")
    if pg.locator("#whitelistIpTable .accessVarMissing, #blacklistIpTable .accessVarMissing").count() != 1:
        fail("rules", "only the undefined variable entry may carry the warning")
    if "coming from" not in pg.locator("#ipAddressInput").locator("xpath=..").inner_text():
        fail("rules", "the blacklist hint must say that an entry means requests coming from that address")
    if pg.locator(".accesscontrol.item[data-tab=tab_whitelist]").count():
        pg.click(".accesscontrol.item[data-tab=tab_whitelist]")
        settle(pg, 300)
    check_horizontal(pg, "access whitelist with variable entries")
    shot("access-variable-entries.png")
    form_post("/api/whitelist/ip/remove", {"ip": "{{missing_var}}", "id": "default"})
    form_post("/api/blacklist/ip/remove", {"ip": "{{remote_office_ext_ip}}", "id": "default"})
    form_post("/api/whitelist/ip/remove", {"ip": "{{remote_office_ext_ip}}", "id": "default"})
    pg.evaluate("openTabById('ruleset')")
    pg.wait_for_selector("#rbVarsBody tr[data-var=remote_office_ext_ip]")
    # hostile value stays text
    post("/api/vars/set", {"name": "hostile_var", "value": "<img src=x onerror=window.__pwnv=1>", "description": "<script>window.__pwnv=2</script>", "create": True})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbVarsBody tr[data-var=hostile_var]")
    pg.wait_for_timeout(300)
    if pg.evaluate("window.__pwnv") or pg.locator("#rbVarsBody img, #rbVarsBody script").count():
        fail("rules", "a variable value was interpreted as HTML")
    post("/api/vars/delete", {"name": "hostile_var"})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbVarsBody tr[data-var=hostile_var]", state="detached")
    check_horizontal(pg, "rules variables desktop")
    shot("rules-variables.png")
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelLists]")
    pg.wait_for_selector("#rbListsBody tr[data-list=office_var] .rb-unres")
    if "missing_var" not in pg.locator("#rbListsBody tr[data-list=office_var] .rb-unres").inner_text():
        fail("rules", "a list entry whose variable has no value must be flagged in the Lists table")
    if "{{missing_var}} matches nothing for now" not in pg.locator("#rbListsBody tr[data-list=office_var] .rb-unres").inner_text():
        fail("rules", "an address list must say that an entry without a value matches nothing")
    # a text list keeps the literal text for an entry without a value, and the table says so (singular and plural)
    post("/api/ruleset/list/save", {"name": "text_var", "type": "string", "items": ["{{remote_office_ext_ip}}", "{{missing_var}}", "{{other_missing}}"]})
    post("/api/ruleset/list/save", {"name": "text_one", "type": "string", "items": ["{{missing_var}}"]})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbListsBody tr[data-list=text_var] .rb-unres")
    tv = pg.locator("#rbListsBody tr[data-list=text_var] .rb-unres").inner_text()
    if "{{missing_var}}, {{other_missing}} only match their literal text for now" not in tv or "nothing" in tv:
        fail("rules", f"a text list must say its unresolved entries match their literal text: {tv!r}")
    to = pg.locator("#rbListsBody tr[data-list=text_one] .rb-unres").inner_text()
    if "{{missing_var}} only matches the literal text {{missing_var}} for now" not in to:
        fail("rules", f"a text list with one unresolved entry: {to!r}")
    shot("rules-lists-variable.png")
    post("/api/ruleset/list/delete", {"name": "text_one"})
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelVars]")
    pg.wait_for_selector("#rbVarsBody tr[data-var=remote_office_ext_ip]")
    was_dark_v = pg.evaluate("document.body.classList.contains('darkTheme')")
    if not was_dark_v:
        pg.evaluate("toggleTheme()")
    pg.click("#rbNewVar")
    pg.wait_for_selector("#rbVarForm input")
    settle(pg, 400)
    shot("rules-variables-dark.png")
    pg.click("#rbVarForm button:has-text('Cancel')")
    if not was_dark_v:
        pg.evaluate("toggleTheme()")
    pg.set_viewport_size({"width": 390, "height": 844})
    settle(pg, 400)
    check_horizontal(pg, "rules variables mobile")
    # stacked cards: no empty strip at the end of the built-in card
    empty = pg.evaluate("Array.from(document.querySelectorAll('#rbVarsBody tr[data-var=external_ip] td')).filter(td => td.getBoundingClientRect().height > 0 && !td.textContent.trim()).length")
    if empty:
        fail("rules", "the built-in variable card must not end with an empty row at 390px")
    shot("rules-variables-mobile.png")
    # a variables file that could not be read at start is announced (the list answer is extended here; the store side is unit tested)
    def with_load_problem(route, backup):
        resp = route.fetch()
        body = resp.json()
        body["load_error"] = "variables.json: unexpected end of JSON input"
        body["load_backup"] = backup
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))
    pg.route("**/api/vars/list", lambda r: with_load_problem(r, ""))
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbVarsLoadError")
    le = pg.locator("#rbVarsLoadError").inner_text()
    if "could not be read" not in le or "unexpected end of JSON input" not in le or "Nothing is overwritten" not in le:
        fail("rules", f"the load problem callout is incomplete: {le!r}")
    check_horizontal(pg, "rules variables load problem mobile")
    shot("rules-variables-loaderror-mobile.png")
    pg.unroute("**/api/vars/list")
    pg.route("**/api/vars/list", lambda r: with_load_problem(r, "variables.json.broken-20260101-120000"))
    pg.evaluate("RB.refresh()")
    pg.wait_for_function("(document.querySelector('#rbVarsLoadError') || {textContent: ''}).textContent.indexOf('variables.json.broken-20260101-120000') >= 0", timeout=5000)
    pg.set_viewport_size({"width": 1366, "height": 900})
    settle(pg, 300)
    shot("rules-variables-loaderror.png")
    pg.unroute("**/api/vars/list")
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbVarsLoadError", state="detached")
    pg.set_viewport_size({"width": 1366, "height": 900})
    settle(pg, 300)
    # delete through the UI: the list entry stops matching, the list itself stays
    pg.click("#rbVarsBody tr[data-var=remote_office_ext_ip] button[aria-label^='Delete variable']")
    pg.wait_for_selector(".zx-dialog")
    dt = pg.locator(".zx-dialog").inner_text()
    if "office_var" not in dt:
        fail("rules", "the delete confirmation must name where the variable is used")
    if "It is used in list $office_var. That entry will match nothing." not in dt or "text list $text_var. That entry will only match the literal text {{remote_office_ext_ip}}" not in dt:
        fail("rules", f"the delete confirmation must tell address lists (match nothing) from text lists (literal text): {dt!r}")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbVarsBody tr[data-var=remote_office_ext_ip]", state="detached", timeout=5000)
    if probe("198.51.100.50"):
        fail("rules", "a deleted variable must match nothing")
    post("/api/ruleset/list/delete", {"name": "office_var"})
    post("/api/ruleset/list/delete", {"name": "text_var"})

    # ---- hostile content stays text ----
    bad = "<img src=x onerror=window.__pwn=1>"
    post("/api/ruleset/rule/create", {"site": "", "rule": {"name": bad, "description": "<script>window.__pwn=2</script>", "expression": 'http.path == "<b>x</b>"', "action": {"type": "tag", "tag": "x"}}})
    post("/api/ruleset/list/save", {"name": "hostile", "type": "string", "description": bad, "items": [bad, "<script>window.__pwn=3</script>"]})
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelRules]")
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id]:has-text('onerror')")
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelLists]")
    pg.wait_for_selector("#rbListsBody tr[data-list=hostile]")
    pg.click("#rbListsBody tr[data-list=hostile] button[aria-label^='Edit list']")
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelTest]")
    pg.locator("#rbTesterMount input[type=text]").nth(0).fill("https://example.com/<b>x</b>")
    pg.locator("#rbTesterMount textarea").fill("X-Evil: <img src=x onerror=window.__pwn=4>")
    pg.click("#rbTesterMount button:has-text('Run the test')")
    pg.wait_for_selector("#rbTesterMount .rb-testres")
    pg.wait_for_timeout(300)
    if pg.evaluate("window.__pwn") or pg.locator("#rbPage img, #rbPage script:not([src])").count():
        fail("rules", "hostile rule / list / tester content was interpreted as HTML")
    post("/api/ruleset/list/delete", {"name": "hostile"})
    for r in rules():
        if r["name"] == bad:
            post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})

    # ---- AI proposal -> log-only rule (mock provider; every step is a human click) ----
    class Mock(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            name = body.get("response_format", {}).get("json_schema", {}).get("name", "")
            res = {"propose_rules": {"proposals": [
                {"name": "AI wp-login", "description": "Log wp-login probes", "reason": "120 hits", "expression": 'http.path contains "/wp-login.php"', "action": "block"},
                {"name": "AI invented", "description": "d", "reason": "r", "expression": '(http.request.uri.path contains "/x")', "action": "block"}]}}.get(name, {})
            if name == "propose_rules":
                res["proposals"] = res["proposals"][:1]
            data = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(res)}}], "usage": {"prompt_tokens": 50, "completion_tokens": 20}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ep = "http://127.0.0.1:%d/v1" % srv.server_address[1]
        pg.evaluate("openTabById('aiassist')")
        settle(pg, 700)
        pg.evaluate("""ep => { $('#aiEnabled').prop('checked', true); $('#aiProvider').val('openai_compatible').trigger('change');
            $('#aiEndpoint').val(ep); $('#aiModel').val('mock-model'); $('#aiLocal').prop('checked', true); $('#aiKey').val('sk-fake-rules-0000ABCD'); }""", ep)
        pg.click("#aiSave")
        pg.wait_for_selector("#aiMsg.ok", timeout=5000)
        before = len(rules())
        pg.click("#aiSuggest")
        pg.wait_for_selector(".ui.modal.visible .approve.button", timeout=5000)
        pg.click(".ui.modal.visible .approve.button")
        pg.wait_for_selector("#aiResult .aiProposal .aiAddRule", timeout=10000)
        if len(rules()) != before:
            fail("ai-rules", "showing a proposal must never create a rule")
        pg.click("#aiResult .aiAddRule")
        pg.wait_for_selector(".ui.modal.visible .approve.button", timeout=5000)
        if "log-only" not in pg.inner_text(".ui.modal.visible").lower():
            fail("ai-rules", "the add dialog must say log-only")
        pg.click(".ui.modal.visible .approve.button")
        pg.wait_for_function("1", timeout=300)
        pg.wait_for_timeout(1000)
        ai = [r for r in rules() if r["name"] == "AI wp-login"]
        if len(ai) != 1 or not ai[0]["dry_run"] or not ai[0]["description"].startswith("[AI proposal]"):
            fail("ai-rules", f"AI rule must exist, log-only and marked: {ai}")
        pg.click("#aiResult .aiOpenBuilder")
        pg.wait_for_selector("#rbEditor .rb-group", timeout=8000)
        valid()
        if "wp-login.php" not in pg.inner_text("#rbEditor .rb-sentence") or "proposed by the AI" not in pg.inner_text("#rbEditor"):
            fail("ai-rules", "open in builder must show the proposal and the AI notice")
        shot("rules-ai-builder.png")
        pg.click("#rbBack")
        pg.click(".zx-dialog .zx-btn--danger")
        pg.evaluate("""() => new Promise(res => $.cjax({url: './api/ai/settings/save', method: 'POST', data: {settings: JSON.stringify({enabled: false, provider: 'anthropic', endpoint: 'https://api.anthropic.com', model: 'claude-sonnet-5-5',
            feature_explain: true, feature_suggest: true, feature_audit: true, send_paths: true, monthly_token_budget: 500000, rate_per_minute: 6, clear_key: true})}, success: res, error: res}))""")
    finally:
        srv.shutdown()

    # ---- 500 rules: the list must stay responsive ----
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})
    batch = [{"name": f"Bulk {i}", "expression": f'http.path == "/bulk/{i}"', "action": {"type": "log"}} for i in range(500)]
    pg.evaluate("""async (b) => { for (const r of b) await new Promise(res => $.cjax({url: './api/ruleset/rule/create', method: 'POST', contentType: 'application/json', data: JSON.stringify({site: 'x'.slice(1), rule: r}), success: () => res(), error: () => res()})); }""", batch)
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelRules]")
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList .rb-more", timeout=10000)
    if pg.locator("#rbList tr[data-id]").count() != 100:
        fail("rules", "the list must render 100 rows and offer 'Show more'")
    pg.fill("#rbSearch", "Bulk 119")
    pg.wait_for_function("document.querySelectorAll('#rbList tr[data-id]').length === 1", timeout=5000)
    pg.fill("#rbSearch", "")
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})

    # ---- failure / edge cases (second session, API failure, model rules) ----
    from rules_edge_smoke import rules_edge
    rules_edge(pg, h, post, rules, valid, savebar_click)

    # ---- visual checks: dark and 390px ----
    pg.evaluate("RB.refresh()")
    post("/api/ruleset/rule/create", {"site": "", "rule": {"name": "Sample", "expression": 'http.path starts_with "/admin" and ip.country != "US"', "action": {"type": "block", "status": 403}}})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id]")
    check_horizontal(pg, "rules desktop")
    was_dark = pg.evaluate("document.body.classList.contains('darkTheme')")
    if not was_dark:
        pg.evaluate("toggleTheme()")
    settle(pg, 400)
    shot("rules-list-dark.png")
    pg.click("#rbList tr[data-id] button[data-act=edit]")
    pg.wait_for_selector("#rbEditor .rb-group")
    settle(pg, 400)
    shot("rules-editor-dark.png")
    pg.click("#rbBack")
    if not was_dark:
        pg.evaluate("toggleTheme()")
    pg.set_viewport_size({"width": 390, "height": 844})
    settle(pg, 400)
    check_horizontal(pg, "rules mobile list")
    shot("rules-list-mobile.png")
    nw = pg.evaluate("(() => { const b = document.querySelector('#rbList tr[data-id] .rb-name'); const r = b.getBoundingClientRect(); return [r.width, document.querySelector('#rbList tr[data-id] .rb-name b').getBoundingClientRect().height]; })()")
    if nw[0] < 200 or nw[1] > 30:
        fail("rules", f"the rule name must have its own full-width row in the stacked mobile list (width/height {nw})")
    pg.click("#rbList tr[data-id] button[data-act=edit]")
    pg.wait_for_selector("#rbEditor .rb-group")
    settle(pg, 400)
    check_horizontal(pg, "rules mobile editor")
    shot("rules-editor-mobile.png")
    pg.click("#rbBack")
    pg.set_viewport_size({"width": 1366, "height": 900})
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})
