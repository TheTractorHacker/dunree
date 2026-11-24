"""Smoke scenario of the Sites pages audit fixes (Default Site, Stream Proxy, Redirection, Path routes, rule rename and creation,
rate limit, site editor sub views, HTTP Proxy list). Every check below failed before the fix. Loaded by smoke.py (exec in its
namespace: fail, current, settle, check_horizontal, args, os)."""

import json

SITES_HOSTS = ["sitesfix-a.demo.test", "sitesfix-b.demo.test"]


def sites_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: (x) => res({error: 'HTTP ' + x.status + ' ' + x.statusText}), dataType: 'json'}))""", [url, data])

    def is_err(r):
        return isinstance(r, dict) and bool(r.get("error"))

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def host_names():
        return js("fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => l.map(x => x.RootOrMatchingDomain))")

    def contrast(sel, bg="#ffffff"):
        return js("""([sel, bg]) => {
            const el = document.querySelector(sel); if (!el) return null;
            const lum = c => { const m = c.match(/[\\d.]+/g).map(Number); const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
                return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); };
            const tmp = document.createElement('i'); tmp.style.color = bg; document.body.appendChild(tmp);
            const b = lum(getComputedStyle(tmp).color); tmp.remove();
            const a = lum(getComputedStyle(el).color), o = parseFloat(getComputedStyle(el).opacity);
            const hi = Math.max(a, b), lo = Math.min(a, b); return (hi + 0.05) / (lo + 0.05) * (o < 1 ? 0.5 : 1); }""", [sel, bg])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    base = {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"}

    # ---------------------------------------------------------------- error answers are always valid JSON (root cause of "Request failed (HTTP 200)")
    current["page"] = "sites-api"
    for h in SITES_HOSTS:
        post("/api/proxy/del", {"ep": h})
    r = post("/api/proxy/add", dict(base, rootname=SITES_HOSTS[0]))
    if r != "OK":
        fail("sites", f"could not add {SITES_HOSTS[0]}: {r!r}")
    r = post("/api/proxy/vdir/add", {"type": "host", "endpoint": SITES_HOSTS[0], "path": "/b c!!", "domain": "not host", "reqTLS": "false", "skipValid": "false"})
    if not is_err(r) or str(r.get("error", "")).startswith("HTTP"):
        fail("sites", f"vdir add with an invalid prefix must answer a readable error, got {r!r}")
    r = post("/api/proxy/vdir/add", {"type": "host", "endpoint": SITES_HOSTS[0], "path": "/ok", "domain": "not host", "reqTLS": "false", "skipValid": "false"})
    if not is_err(r) or "valid host" not in str(r.get("error", "")):
        fail("sites", f"vdir add with an invalid target must say why, got {r!r}")

    # ---------------------------------------------------------------- hostnames: creation and rename
    current["page"] = "sites-hostnames"
    for bad in ("bad host!!", "http://a.test", "a" * 300, "a" * 64 + ".test", ""):
        r = post("/api/proxy/add", dict(base, rootname=bad))
        if not is_err(r):
            fail("validation", f"/api/proxy/add accepted the hostname {bad[:30]!r}: {r!r}")
    if any(("bad host" in n or "http://a.test" in n or len(n) > 100) for n in host_names()):
        fail("validation", "an invalid hostname ended up in the rule list")
    r = post("/api/proxy/add", dict(base, rootname="UPPER.Sitesfix.Test"))
    if r != "OK" or "upper.sitesfix.test" not in host_names():
        fail("validation", f"a mixed case hostname must be stored lower case: {r!r} {host_names()}")
    post("/api/proxy/del", {"ep": "upper.sitesfix.test"})
    r = post("/api/proxy/add", dict(base, rootname=SITES_HOSTS[0]))
    if not is_err(r):
        fail("validation", f"adding a rule for an existing host must be refused: {r!r}")
    for bad in ("bad host!!", "http://x.test", "", "a" * 300, SITES_HOSTS[0]):
        r = post("/api/proxy/setHostname", {"oldHostname": SITES_HOSTS[0], "newHostname": bad})
        if not is_err(r):
            fail("validation", f"setHostname accepted {bad[:30]!r}: {r!r}")
        if SITES_HOSTS[0] not in host_names():
            fail("validation", f"the rule vanished after a rename to {bad[:30]!r}")
            break
    r = post("/api/proxy/setHostname", {"oldHostname": SITES_HOSTS[0], "newHostname": SITES_HOSTS[1]})
    if r != "OK" or SITES_HOSTS[1] not in host_names() or SITES_HOSTS[0] in host_names():
        fail("validation", f"a valid rename must work: {r!r} {host_names()}")
    post("/api/proxy/setHostname", {"oldHostname": SITES_HOSTS[1], "newHostname": SITES_HOSTS[0]})

    # ---------------------------------------------------------------- Default Site
    current["page"] = "sites-defaultsite"
    for opt, val, ep in ((1, "not a host!!", "not a host!!"), (1, "", ""), (1, "x" * 500, "x" * 500), (2, "javascript:alert(1)", "127.0.0.1:9"), (2, "", "127.0.0.1:9"), (2, "example.com", "127.0.0.1:9")):
        r = post("/api/proxy/add", {"type": "root", "tls": "false", "ep": ep, "defaultSiteOpt": opt, "defaultSiteVal": val})
        if not is_err(r):
            fail("validation", f"default site option {opt} accepted {val[:30]!r}: {r!r}")
    js("openTabById('setroot')")
    pg.wait_for_timeout(800)
    pg.click("input[name=defaultsiteOption][value=proxy] >> xpath=..")
    pg.fill("#proxyRoot", "")
    pg.click("button:has-text('Apply Changes')")
    pg.wait_for_timeout(300)
    if not js("document.querySelector('#defaultSiteProxyOptions .defaultSiteError')"):
        fail("defaultsite", "an empty reverse proxy target shows no message")
    if js("document.querySelector('button[onclick^=setProxyRoot]').classList.contains('disabled')"):
        fail("defaultsite", "Apply Changes stays disabled after an empty submit")
    shot("sites-defaultsite-empty.png")
    pg.fill("#proxyRoot", "not a host!!")
    pg.click("button:has-text('Apply Changes')")
    pg.wait_for_timeout(300)
    shot("sites-defaultsite-bad-target.png")
    if "valid host" not in (js("(document.querySelector('#defaultSiteProxyOptions .defaultSiteError') || {}).innerText") or ""):
        fail("defaultsite", "an invalid reverse proxy target is not reported")
    if js("document.querySelector('button[onclick^=setProxyRoot]').classList.contains('disabled')"):
        fail("defaultsite", "Apply Changes is disabled after an invalid target")
    pg.click("input[name=defaultsiteOption][value=redirect] >> xpath=..")
    pg.fill("#redirectDomain", "javascript:alert(1)")
    pg.click("button:has-text('Apply Changes')")
    pg.wait_for_timeout(300)
    if not js("document.querySelector('#defaultSiteRedirectOptions .defaultSiteError')"):
        fail("defaultsite", "a javascript: redirect target is not reported")
    shot("sites-defaultsite-bad-redirect.png")
    js("initRootInfo()")
    pg.wait_for_timeout(600)

    # ---------------------------------------------------------------- Redirection
    current["page"] = "sites-redirect"
    for src, dst in (("loop.sitesfix.test", "loop.sitesfix.test"), ("a.sitesfix.test", "javascript:alert(1)"), ("bad url!!", "not a url"), ("b.sitesfix.test", "x" * 2500), ("c" * 500, "d.sitesfix.test")):
        r = post("/api/redirect/add", {"redirectUrl": src, "destUrl": dst, "forwardChildpath": "true", "redirectType": 307, "deviceType": "all"})
        if not is_err(r):
            fail("validation", f"/api/redirect/add accepted {src[:20]!r} -> {dst[:20]!r}: {r!r}")
    post("/api/redirect/delete", {"redirectUrl": "old.sitesfix.test"})
    r = post("/api/redirect/add", {"redirectUrl": "old.sitesfix.test", "destUrl": "shop.sitesfix.test", "forwardChildpath": "true", "redirectType": 307, "deviceType": "all"})
    if r != "OK":
        fail("redirect", f"a valid redirection rule was refused: {r!r}")
    r = post("/api/redirect/add", {"redirectUrl": "old.sitesfix.test", "destUrl": "other.sitesfix.test", "forwardChildpath": "true", "redirectType": 307, "deviceType": "all"})
    if not is_err(r):
        fail("validation", f"adding a redirection for an existing source must not overwrite it: {r!r}")
    js("openTabById('redirectset')")
    pg.wait_for_timeout(800)
    if js("document.querySelectorAll('#redirectionRuleList tr').length") != 1:
        fail("redirect", "the redirection list does not show exactly the one valid rule")
    # duplicate through the form: an error message, no success banner, the typed values stay
    pg.click("#redirAddBtn")   # the form opens from the header button
    pg.wait_for_selector("#rurl", state="visible", timeout=5000)
    pg.fill("#rurl", "old.sitesfix.test")
    pg.fill("input[name=destination-url]", "other.sitesfix.test")
    pg.click("#addRedirectBtn")
    pg.wait_for_timeout(600)
    if js("document.getElementById('ruleAddSucc').offsetParent !== null"):
        fail("redirect", "a duplicate redirection source shows the success banner")
    if pg.input_value("#rurl") != "old.sitesfix.test":
        fail("redirect", "the form was cleared although the add failed")
    shot("sites-redirect-duplicate.png")
    # rapid double click adds one rule only
    pg.fill("#rurl", "dbl.sitesfix.test")
    pg.fill("input[name=destination-url]", "dest.sitesfix.test")
    pg.dblclick("#addRedirectBtn")
    pg.wait_for_timeout(900)
    n = js("[...document.querySelectorAll('#redirectionRuleList tr')].filter(t => t.innerText.includes('dbl.sitesfix.test')).length")
    if n != 1:
        fail("redirect", f"a double click created {n} rules")
    # labels
    if "keeps the path" not in js("document.querySelector('#redirectionRuleList').innerText").lower() or "keep the path" not in js("document.querySelector('#addRedirectCard').innerText").lower():
        fail("text", "the Redirection rows and form should say Keep(s) the path")
    if js("[...document.querySelectorAll('#redirectionRuleList button')].filter(b => !b.getAttribute('aria-label')).length"):
        fail("a11y", "a Redirection row button has no aria-label")
    if js("[...document.querySelectorAll('#redirectset input[type=text]')].filter(i => !i.getAttribute('aria-label') && !i.labels.length).length"):
        fail("a11y", "a Redirection form input has no label")
    # Edit shows Save only: with the Add button left visible, a click on it created a second rule instead of saving the change
    pg.click("#redirectionRuleList tr:has-text('dbl.sitesfix.test') .redirectEditBtn")
    pg.wait_for_timeout(300)
    if pg.is_visible("#addRedirectBtn") or not pg.is_visible("#saveRedirectBtn"):
        fail("redirect", "the edit form must show Save changes and hide Add redirection")
    js("closeRedirectForm()")
    # an empty submit marks the field and moves the focus there (no corner toast with a raw server text)
    pg.click("#redirAddBtn")
    pg.wait_for_selector("#rurl", state="visible", timeout=5000)
    pg.fill("#rurl", "")
    pg.fill("input[name=destination-url]", "")
    pg.click("#addRedirectBtn")
    pg.wait_for_timeout(300)
    if js("document.getElementById('rurl').getAttribute('aria-invalid')") != "true" or js("document.activeElement.id") != "rurl":
        fail("redirect", "an empty Redirect from field is not marked invalid and focused")
    js("closeRedirectForm()")
    # deleting asks first (a ZxUI dialog, not window.confirm)
    pg.click("#redirectionRuleList tr:has-text('dbl.sitesfix.test') button[title='Delete redirection rule']")
    pg.wait_for_timeout(300)
    if not js("!!document.querySelector('.zx-dialog, .zx-modal, [role=alertdialog], [role=dialog].zx-confirm')"):
        fail("redirect", "deleting a redirection rule shows no confirmation dialog")
    js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
    pg.wait_for_timeout(300)
    for s in ("old.sitesfix.test", "dbl.sitesfix.test"):
        post("/api/redirect/delete", {"redirectUrl": s})

    # ---------------------------------------------------------------- Stream Proxy
    current["page"] = "sites-stream"
    for old in js("fetch('/api/streamprox/config/list').then(r => r.json()).then(l => l.filter(c => c.Name.startsWith('sitesfix')).map(c => c.UUID))"):
        post("/api/streamprox/config/delete", {"uuid": old})
    good = {"name": "sitesfix-ssh", "listenAddr": ":29218", "proxyAddr": "127.0.0.1:22", "useTCP": "true", "useUDP": "false", "timeout": 10, "proxyProtocolVersion": 0}
    r = post("/api/streamprox/config/add", good)
    if is_err(r):
        fail("stream", f"a valid stream proxy was refused: {r!r}")
    for label, patch in (("empty name", {"name": ""}), ("garbage listen", {"name": "sitesfix-x", "listenAddr": "not an address"}), ("port 0", {"name": "sitesfix-x", "listenAddr": ":0"}),
                         ("port 99999", {"name": "sitesfix-x", "listenAddr": ":99999"}), ("duplicate port", {"name": "sitesfix-x"}), ("duplicate name", {"listenAddr": ":29219"}),
                         ("garbage target", {"name": "sitesfix-x", "listenAddr": ":29219", "proxyAddr": "nope"}), ("no protocol", {"name": "sitesfix-x", "listenAddr": ":29219", "useTCP": "false"}),
                         ("long name", {"name": "n" * 400, "listenAddr": ":29219"})):
        r = post("/api/streamprox/config/add", dict(good, **patch))
        if not is_err(r):
            fail("validation", f"stream proxy add accepted {label}: {r!r}")
    js("openTabById('streamproxy')")
    pg.wait_for_timeout(900)
    rows = js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length")
    if rows != 1:
        fail("stream", f"{rows} stream proxy rows, expected 1 (invalid configs were created)")
    c = contrast("#proxyTable .statusText")
    if c is not None and c < 4.5:
        fail("contrast", f"the Running / Stopped status text has contrast {c:.2f}:1")
    if js("[...document.querySelectorAll('#proxyTable tbody button')].filter(b => !b.getAttribute('aria-label')).length"):
        fail("a11y", "a Stream Proxy row button has no aria-label")
    if js("[...document.querySelectorAll('#streamProxyForm input[type=text]')].filter(i => i.offsetParent && !i.getAttribute('aria-label') && !i.labels.length).length"):
        fail("a11y", "a Stream Proxy form input has no label")
    shot("sites-stream-list.png")
    # invalid input through the form keeps what was typed and reports the reason
    pg.click("#spAddBtn")   # the form opens from the header button
    pg.wait_for_selector("#streamProxyForm input[name=name]", state="visible", timeout=5000)
    pg.fill("#streamProxyForm input[name=name]", "sitesfix-form")
    pg.fill("#streamProxyForm input[name=listenAddr]", "not an address")
    pg.fill("#streamProxyForm input[name=proxyAddr]", "127.0.0.1:22")
    pg.click("#streamProxyForm label[for=spProtoTcp]")
    if not js("document.querySelector('#streamProxyForm input[name=useTCP]').checked && !document.querySelector('#streamProxyForm input[name=useUDP]').checked"):
        fail("stream", "choosing TCP does not set the protocol fields")
    pg.click("#addStreamProxyButton")
    pg.wait_for_timeout(600)
    if pg.input_value("#streamProxyForm input[name=listenAddr]") != "not an address":
        fail("stream", "the form was cleared although the add failed")
    if js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length") != 1:
        fail("stream", "an invalid config was added through the form")
    # an empty Listen on field is marked in the form
    pg.fill("#streamProxyForm input[name=listenAddr]", "")
    pg.click("#addStreamProxyButton")
    pg.wait_for_timeout(300)
    if js("document.getElementById('spListen').getAttribute('aria-invalid')") != "true":
        fail("stream", "an empty Listen on field is not marked invalid")
    # a double click on a valid config creates one
    pg.fill("#streamProxyForm input[name=listenAddr]", ":29219")
    pg.dblclick("#addStreamProxyButton")
    pg.wait_for_timeout(900)
    if js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length") != 2:
        fail("stream", "a double click on Create did not create exactly one config")
    # delete asks first
    pg.click("#proxyTable tbody tr:has-text('sitesfix-form') button[title='Remove rule']")
    pg.wait_for_timeout(300)
    if js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length") != 2:
        fail("stream", "Delete removed the config without asking")
    js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
    pg.wait_for_timeout(300)
    # edit scrolls the form into view
    pg.click("#proxyTable tbody tr:has-text('sitesfix-ssh') button[title='Edit rule']")
    pg.wait_for_timeout(900)
    if not js("(() => { const r = document.getElementById('addproxyConfig').getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; })()"):
        fail("stream", "Edit does not bring the form into view")
    check_horizontal(pg, "Stream Proxy")
    for u in js("fetch('/api/streamprox/config/list').then(r => r.json()).then(l => l.filter(c => c.Name.startsWith('sitesfix')).map(c => c.UUID))"):
        post("/api/streamprox/config/delete", {"uuid": u})

    # ---------------------------------------------------------------- rate limit values
    current["page"] = "sites-ratelimit"
    for v in ("99999999999", "0", "-5", "1.5"):
        r = post("/api/proxy/edit", {"rootname": SITES_HOSTS[0], "rate": "true", "ratenum": v})
        if not is_err(r):
            fail("validation", f"/api/proxy/edit accepted the rate limit {v!r}: {r!r}")

    # ---------------------------------------------------------------- site editor: sub view title, Esc goes back one level, WAF help
    current["page"] = "sites-editor"
    orig_pol = js("fetch('/api/waf/policy').then(r => r.json())")
    post("/api/waf/policy", {"policy": json.dumps(dict(orig_pol, Enabled=True, DefaultMode="block"))})
    js("openTabById('httprp')")
    pg.wait_for_timeout(900)
    # the Protection column is a row of icon chips; the name of a chip is its title / aria-label
    if not js("[...document.querySelectorAll('#httpProxyList .ptBadge.waf')].some(b => (b.getAttribute('aria-label') || '').indexOf('global policy') >= 0)"):
        fail("list", "the Protection column shows no WAF although the global WAF is on and the rule follows it")
    js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", SITES_HOSTS[0])
    pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=8000)
    pg.wait_for_timeout(800)
    help_txt = js("document.getElementById('hrpProtHelp').innerText")
    if "off until you enable it" in help_txt or "currently blocking" not in help_txt:
        fail("text", f"the WAF help text does not reflect the global WAF state: {help_txt!r}")
    # renaming to an invalid hostname through the editor: a message, the old name stays, the rule stays
    # the Hostname field is one control: input + Save name + Discard, same height, apart by the kit gap, off until the name differs
    host_ctl = """() => { const q = s => document.querySelector('#httprpEditModalWrapper ' + s); const r = e => e.getBoundingClientRect();
        const i = q('.downstream_primary_hostname_edit_input input'), s = q('.saveDownstreamHostnameBtn'), c = q('.cancelDownstreamHostnameBtn');
        return {value: i.value, save: !s.disabled, discard: !c.disabled, h: [r(i).height, r(s).height, r(c).height].map(Math.round), top: [r(i).top, r(s).top, r(c).top].map(Math.round),
                gap: [Math.round(r(s).left - r(i).right), Math.round(r(c).left - r(s).right)], text: [s.innerText.trim(), c.innerText.trim()]}; }"""
    hc = js(host_ctl)
    if hc["value"] != SITES_HOSTS[0] or hc["save"] or hc["discard"]:
        fail("editor", f"the Hostname field must show the current name with Save name / Discard switched off, got {hc}")
    if len(set(hc["h"])) != 1 or len(set(hc["top"])) != 1 or min(hc["gap"]) < 6 or hc["text"] != ["Save name", "Discard"]:
        fail("editor", f"the Hostname input and its buttons are not one aligned control (same height and row, 8px apart, labelled): {hc}")
    pg.fill("#httprpEditModalWrapper .downstream_primary_hostname_edit_input input", "bad host!!")
    hc = js(host_ctl)
    if not hc["save"] or not hc["discard"]:
        fail("editor", f"Save name / Discard must switch on once the name differs, got {hc}")
    pg.click("#httprpEditModalWrapper .saveDownstreamHostnameBtn")
    pg.wait_for_timeout(700)
    if SITES_HOSTS[0] not in host_names():
        fail("editor", "the rule vanished after an invalid rename in the editor")
    if SITES_HOSTS[0] not in js("document.getElementById('hrpTitleHost').innerText"):
        fail("editor", "the editor title shows the invalid hostname")
    shot("sites-editor-rename-bad.png")
    pg.click("#httprpEditModalWrapper .cancelDownstreamHostnameBtn")
    hc = js(host_ctl)
    if hc["value"] != SITES_HOSTS[0] or hc["save"] or hc["discard"]:
        fail("editor", f"Discard must put the saved name back and switch both buttons off, got {hc}")
    js("HrpEditor.setMode('advanced')")
    pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=security]")
    pg.wait_for_timeout(500)
    shot("sites-editor-security.png")
    js("HrpEditor.setMode('easy')")
    js("editUpstreams(document.getElementById('httprpEditModal').getAttribute('editing-host') ? decodeURIComponent(document.getElementById('httprpEditModal').getAttribute('editing-host')) : '')")
    pg.wait_for_timeout(1200)
    title = js("document.querySelector('#httprpEditModal .editor_side_title').innerText")
    if "Upstreams" not in title or SITES_HOSTS[0] not in title:
        fail("editor", f"the sub view has no title with the host, got {title!r}")
    # the sub view header is a real row: back button fully inside the panel, title not a link, long names cut with an ellipsis
    sh = js("""() => { const m = document.querySelector('#httprpEditModal').getBoundingClientRect(), h = document.querySelector('#httprpEditModal .hrp-sidehead'),
        b = h.querySelector('.editor_back_button'), t = h.querySelector('.editor_side_title'), rb = b.getBoundingClientRect(), rh = h.getBoundingClientRect(),
        f = document.querySelector('#httprpEditModal .editor_side_wrapper .wrapper_frame').getBoundingClientRect(), host = h.querySelector('.hrp-sidehead__host');
        return {tag: b.tagName, inside: rb.top >= rh.top + 4 && rb.bottom <= rh.bottom - 4 && rb.left >= m.left + 4 && rh.top >= m.top - 1, link: !!t.closest('a'),
                deco: getComputedStyle(t).textDecorationLine, frameBelow: Math.round(f.top - rh.bottom), frameFills: Math.round(m.bottom - f.bottom),
                ellipsis: getComputedStyle(host).textOverflow, hostFits: host.getBoundingClientRect().right <= rh.right}; }""")
    if sh["tag"] != "BUTTON" or not sh["inside"] or sh["link"] or sh["deco"] != "none" or sh["ellipsis"] != "ellipsis" or not sh["hostFits"] \
            or abs(sh["frameBelow"]) > 1 or abs(sh["frameFills"]) > 2:
        fail("editor", f"the sub view header is not a proper header row: {sh}")
    shot("sites-editor-subview.png")
    frame = [f for f in pg.frames if "upstreams.html" in f.url]
    if not frame:
        fail("editor", "the Upstreams sub view did not load")
    else:
        # the three tabs of the Upstreams view (design v2): rows with a state badge and a weight stepper, the Add form
        # in labelled groups with the advanced group folded, the algorithm cards and the live policy summary
        uf = frame[0]
        up = uf.evaluate("""() => { const q = s => document.querySelector(s), n = s => document.querySelectorAll(s).length;
            return { rows: n('#upstreamTable .upstreamEntry'), badge: n('#upstreamTable .upstreamEntry .up-row__title .zx-badge--dot'),
                     stepper: n('#upstreamTable .upstreamEntry .up-stepper'), link: n('#upstreamTable .up-row__title a'),
                     summary: (q('#upstreamSummary') || {}).innerText || '', groups: n('#newUpstreamForm .up-group'),
                     advOpen: !!(q('#newUpstreamForm details.up-adv') || {}).open, native: n('.up-col select:not(.zx-select):not([hidden])'),
                     algos: n('#lbAlgoCards .up-algo'), picked: n('#lbAlgoCards .up-algo[aria-checked="true"]'), policy: n('#lbPolicy .up-policy__row') }; }""")
        if up["rows"] < 1 or up["badge"] != up["rows"] or up["stepper"] != up["rows"] or up["link"]:
            fail("editor", f"Upstreams list: every row needs a state badge and a weight stepper, and the address is text, not a link: {up}")
        if "upstream" not in up["summary"]:
            fail("editor", f"Upstreams list has no summary line: {up['summary']!r}")
        if up["groups"] != 3 or up["advOpen"] or up["native"]:
            fail("editor", f"Add upstream: three groups, the advanced one folded, no unstyled select: {up}")
        if up["algos"] != 9 or up["picked"] != 1 or up["policy"] < 4:
            fail("editor", f"Load balancing: nine algorithm cards with one picked and a policy summary: {up}")
        uf.click(".menu .item[data-tab=newupstream]")
        uf.click("#addUpstreamBtn")
        pg.wait_for_timeout(200)
        if not uf.evaluate("document.querySelector('#newUpstreamForm .upstreamOriginField').classList.contains('is-invalid')"):
            fail("editor", "Add upstream without an address must be refused at the field")
        shot("sites-editor-upstream-add.png")
        uf.click(".menu .item[data-tab=loadbalance]")
        pg.wait_for_timeout(200)
        shot("sites-editor-upstream-lb.png")
        tabs = uf.evaluate("""() => [document.querySelector('.ui.pointing.secondary.menu').getAttribute('role'),
            ...[...document.querySelectorAll('.ui.menu .item[data-tab]')].map(e => e.getAttribute('aria-selected'))]""")
        if tabs != ["tablist", "false", "false", "true"]:
            fail("editor", f"Upstreams tabs: role=tablist and aria-selected on the open tab: {tabs}")
        uf.click(".menu .item[data-tab=upstreamlist]")
        # dark theme: the legacy "body.darkTheme p, span" rule must not flatten muted help text and coloured badges to plain white
        dk = uf.evaluate("""() => { const b = document.body, was = b.classList.contains('darkTheme'); b.classList.add('darkTheme');
            const c = s => { const e = document.querySelector(s); return e ? getComputedStyle(e).color : null; };
            const r = {help: c('#originURL-help'), label: c('#newUpstreamForm .zx-field__label'), desc: c('#newUpstreamForm .zx-toggle-row__desc'),
                       title: c('#newUpstreamForm .zx-toggle-row__title'), summary: c('#upstreamSummary'), addr: c('.up-row__addr'), live: c('.up-row__live')};
            if (!was) b.classList.remove('darkTheme'); return r; }""")
        if dk["help"] == dk["label"] or dk["desc"] == dk["title"] or dk["summary"] == dk["addr"] or dk["live"] == dk["addr"]:
            fail("editor", f"Upstreams in dark: help and status text must be muted, not the colour of labels: {dk}")
        # the switch of a row must not save a half-edited form: it is hidden while a row is edited, and a stray change sends nothing
        sent = []
        on_req = lambda r: sent.append(r.url) if "/api/proxy/upstream/update" in r.url else None
        pg.on("request", on_req)
        ed = uf.evaluate("""() => { const row = document.querySelector('#upstreamTable .upstreamEntry'); handleUpstreamOriginEdit(row.dataset.domid);
            const mc = row.querySelector('.maxConn'); mc.value = '77'; mc.dispatchEvent(new Event('input', {bubbles: true}));
            const sw = row.querySelector('.enableState'), shown = sw.offsetParent !== null, before = sw.checked;
            sw.checked = !before; sw.dispatchEvent(new Event('change', {bubbles: true}));
            return {shown: shown, reverted: sw.checked === before, editing: row.classList.contains('is-editing')}; }""")
        pg.wait_for_timeout(400)
        pg.remove_listener("request", on_req)
        if ed["shown"] or not ed["reverted"] or not ed["editing"] or sent:
            fail("editor", f"the enable switch of a row being edited must be hidden and must not save the form: {ed} {sent}")
        uf.click("#upstreamTable .upstreamEntry.is-editing .cancelbtn")
        pg.wait_for_timeout(400)
        frame[0].locator("body").click(position={"x": 5, "y": 5})
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(800)
        if not js("document.getElementById('httprpEditModalWrapper').offsetParent !== null && getComputedStyle(document.getElementById('httprpEditModal')).display !== 'none'"):
            fail("editor", "Esc inside a sub view closed the whole editor")
        if js("getComputedStyle(document.querySelector('#httprpEditModal .editor_side_wrapper')).display") != "none":
            fail("editor", "Esc inside a sub view did not go back to the site settings")
    # keyboard: a side view takes the focus (Back button), the editor behind it leaves the Tab order, Back returns to the button that opened it
    side_shown = "getComputedStyle(document.querySelector('#httprpEditModal .editor_side_wrapper')).display !== 'none'"
    focus_at = """() => { let a = document.activeElement, p = ''; while (a && a.tagName === 'IFRAME') { p = 'frame:'; a = a.contentDocument.activeElement; }
        return p + (a ? a.tagName + '.' + [...a.classList].join('.') : 'none'); }"""
    if js("document.getElementById('httprpEditModalWrapper').offsetParent !== null") and not js(side_shown):
        js("HrpEditor.setMode('advanced')")
        pg.click("#hrpTab-general")
        pg.wait_for_timeout(300)
        pg.focus("#httprpEditModalWrapper .editUpstreamButton")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(1200)
        kb = {"open": js(focus_at), "inert": js("document.querySelector('#httprpEditModal .hrp-main').closest('[inert]') !== null")}
        for _ in range(40):   # more Tabs than the view has controls: the focus must stay inside the side view
            pg.keyboard.press("Tab")
            at = js(focus_at)
            if not at.startswith("frame:") and "editor_back_button" not in at:
                kb["escaped"] = at
                break
        pg.focus("#httprpEditModal .editor_back_button")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(900)
        kb["back"] = js(focus_at)
        kb["inertLeft"] = js("document.querySelectorAll('#httprpEditModal [inert]').length")
        if "editor_back_button" not in kb["open"] or not kb["inert"] or kb.get("escaped") or "editUpstreamButton" not in kb["back"] or kb["inertLeft"]:
            fail("editor", f"side view focus: opens on the Back button, Tab stays inside, Back returns to the button that opened it: {kb}")
        # every side view: the header row names it once (no second page title in the frame) and the content starts at the gutter of the Back button
        for view, own_title in (("pathRulesEditor", True), ("opsEditor", True), ("networkingEditor", True), ("tagEditor", False), ("upstreams", False)):
            js("v => showEditorSideWrapper('snippet/' + v + '.html?t=' + Date.now() + '#' + encodeURIComponent(JSON.stringify({ept: 'host', ep: decodeURIComponent(document.getElementById('httprpEditModal').getAttribute('editing-host'))})))", view)
            pg.wait_for_timeout(1300)
            el = pg.query_selector("#httprpEditModal .editor_side_wrapper .wrapper_frame")
            fr = el.content_frame() if el else None
            if not fr or view not in fr.url:
                fail("editor", f"the side view {view} did not load")
                continue
            sv = fr.evaluate("""() => { const t = document.querySelector('.zx-sideview-title'), de = document.documentElement; let left = null;
                for (const e of document.querySelectorAll('body p, body table, body .zx-table-wrap, body .ui.menu, body .ui.form')) { const r = e.getBoundingClientRect(); if (r.width) { left = Math.round(r.left); break; } }
                return {cls: de.classList.contains('zx-sideview'), title: t ? getComputedStyle(t).display : null, left: left, over: de.scrollWidth - de.clientWidth}; }""")
            back_left = js("Math.round(document.querySelector('#httprpEditModal .editor_back_button').getBoundingClientRect().left - document.querySelector('#httprpEditModal .editor_side_wrapper').getBoundingClientRect().left)")
            if not sv["cls"] or (own_title and sv["title"] != "none") or sv["left"] is None or abs(sv["left"] - back_left) > 1 or sv["over"] > 1:
                fail("editor", f"side view {view}: no second title, content at the gutter of the Back button ({back_left}px), no sideways scroll: {sv}")
        # Operations at phone width: the four tabs wrap, none is cut and the frame does not scroll sideways
        pg.set_viewport_size({"width": 390, "height": 844})
        js("showEditorSideWrapper('snippet/opsEditor.html?t=' + Date.now() + '#' + encodeURIComponent(JSON.stringify({ept: 'host', ep: decodeURIComponent(document.getElementById('httprpEditModal').getAttribute('editing-host'))})))")
        pg.wait_for_timeout(1300)
        el = pg.query_selector("#httprpEditModal .editor_side_wrapper .wrapper_frame")
        fr = el.content_frame() if el else None
        ops = fr.evaluate("""() => { const de = document.documentElement; return {over: de.scrollWidth - de.clientWidth,
            cut: [...document.querySelectorAll('#opsTabs .item')].filter(e => e.getBoundingClientRect().right > de.clientWidth + 1).length}; }""") if fr and "opsEditor" in fr.url else None
        if not ops or ops["over"] > 1 or ops["cut"]:
            fail("editor", f"Operations side view at 390px: the tab strip must fit the frame: {ops}")
        shot("sites-editor-ops-390.png")
        pg.set_viewport_size({"width": 1366, "height": 1000})
        js("hideEditorSideWrapper()")
        pg.wait_for_timeout(500)
        # header rewrite rules: a name or a value with markup is shown as text (no script runs), and its Remove button still works
        dialogs = []
        on_dialog = lambda d: (dialogs.append(d.message), d.dismiss())
        pg.on("dialog", on_dialog)
        post("/api/proxy/header/add", {"type": "add", "domain": SITES_HOSTS[0], "direction": "toOrigin", "name": "X-<img src=x onerror=alert(1)>'\"", "value": "<img src=x onerror=alert(2)>"})
        js("HrpEditor.setMode('advanced')")
        js("document.getElementById('hrpTab-' + document.querySelector('#httprpEditModalWrapper [data-hrp-card=headers]').closest('.hrp-sec').getAttribute('data-hrp-sec')).click()")
        pg.wait_for_timeout(1500)
        hf = [f for f in pg.frames if "customHeaders.html" in f.url]
        if not hf:
            fail("editor", "the Headers card did not load its rules")
        else:
            hf[0].evaluate("listCustomHeaders()")
            pg.wait_for_timeout(700)
            hx = hf[0].evaluate("({rows: document.querySelectorAll('#headerTable tr .removeHeaderBtn').length, img: document.querySelectorAll('#headerTable img').length, text: document.getElementById('headerTable').innerText})")
            if hx["rows"] != 1 or hx["img"] or "onerror=" not in hx["text"].lower():
                fail("editor", f"a header name with markup must be listed as plain text: {hx}")
            hf[0].click("#headerTable .removeHeaderBtn")
            pg.wait_for_timeout(900)
            left = js("d => fetch('/api/proxy/header/list?type=host&domain=' + encodeURIComponent(d)).then(r => r.json()).then(l => l.length)", SITES_HOSTS[0])
            if left != 0:
                fail("editor", f"Remove on a header whose name has quotes and markup did not remove it ({left} left)")
        pg.remove_listener("dialog", on_dialog)
        if dialogs:
            fail("editor", f"a header name with markup ran as script in the Headers card: {dialogs}")
        js("HrpEditor.setMode('easy')")
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(600)
    if js("document.getElementById('httprpEditModalWrapper').offsetParent !== null"):
        js("document.querySelector('#httprpEditModal .httpProxyEditClosePC').click()")
        pg.wait_for_timeout(600)
    post("/api/waf/policy", {"policy": json.dumps(orig_pol)})

    # ---------------------------------------------------------------- Path routes: the real reason, not "Request failed (HTTP 200)"
    current["page"] = "sites-vdir"
    js("openTabById('vdir')")
    pg.wait_for_timeout(700)
    js("h => { $('#vdirBaseRoutingRule').val(h).trigger('change'); }", SITES_HOSTS[0])
    pg.wait_for_timeout(700)
    pg.fill("#virtualDirectoryPath", "/b c!!")
    pg.fill("#virtualDirectoryDomain", "not host")
    js("addVdirToHost()")
    pg.wait_for_timeout(900)
    msg = js("document.getElementById('messageBox') ? document.getElementById('messageBox').innerText : ''")
    toast_txt = js("(document.querySelector('.zx-toast-region') || document.body).innerText")
    if "Request failed (HTTP" in toast_txt or "Request failed (HTTP" in msg:
        fail("vdir", "a failed path route add still reports 'Request failed (HTTP 200)'")
    if "spaces" not in (msg + toast_txt):
        fail("vdir", f"the real reason is not shown for an invalid path prefix: {msg!r}")
    shot("sites-vdir-bad.png")

    # ---------------------------------------------------------------- Path routes: h2c option for gRPC paths (issue #201, NetBird)
    current["page"] = "sites-vdir-h2c"
    grpc_path = "/management.ManagementService/"

    def vdir_of(path):
        return js("""([h, p]) => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => {
            const e = l.filter(x => x.RootOrMatchingDomain == h)[0]; return e ? (e.VirtualDirectories || []).filter(v => v.MatchingPath == p)[0] || null : null; })""", [SITES_HOSTS[0], path])

    js("resetVdirForm(); vdirClearErrors();")
    if js("document.getElementById('vdH2C').checked"):
        fail("vdir-h2c", "the h2c option must be off in a new path route form")
    # list chip and Edit form follow the server rule (UsesH2C): a stored flag does not count with TLS or an https:// target
    uses = js("""[{H2C: true, Domain: 'signal:80/x/'}, {H2C: true, RequireTLS: true, Domain: 'signal:443/x/'},
                 {H2C: true, Domain: ' HTTPS://signal:443/x/'}, {H2C: false, Domain: 'signal:80/x/'}, {Domain: 'signal:80/x/'}].map(vdirUsesH2C)""")
    if uses != [True, False, False, False, False]:
        fail("vdir-h2c", f"vdirUsesH2C does not match the server rule: {uses!r}")
    # the tlscheck of the target address must not be what decides this test: set the fields without a change event
    js("""([p, d]) => { $('#virtualDirectoryPath').val(p); $('#virtualDirectoryDomain').val(d); updateVdirExample(); document.getElementById('advanceVdirRules').open = true; }""",
       [grpc_path, "127.0.0.1:9" + grpc_path])
    js("document.activeElement && document.activeElement.blur()")
    pg.wait_for_timeout(1500)
    pg.check("#vdReqTls")
    if not js("document.getElementById('vdH2C').disabled") or js("document.getElementById('vdH2CTlsNote').hidden"):
        fail("vdir-h2c", "with TLS to the target ticked, h2c must be disabled and say why")
    # the disabled state with its explanation, in both themes
    shot("sites-vdir-h2c-tls-disabled.png")
    theme(True)
    shot("sites-vdir-h2c-tls-disabled-dark.png")
    theme(False)
    pg.uncheck("#vdReqTls")
    if js("document.getElementById('vdH2C').disabled") or not js("document.getElementById('vdH2CTlsNote').hidden"):
        fail("vdir-h2c", "h2c stays disabled after TLS was unticked")
    pg.check("#vdH2C")
    shot("sites-vdir-h2c-form.png")
    theme(True)
    shot("sites-vdir-h2c-form-dark.png")
    theme(False)
    js("addVdirToHost()")
    pg.wait_for_timeout(1200)
    v = vdir_of(grpc_path)
    if not v or v.get("H2C") is not True or v.get("RequireTLS"):
        fail("vdir-h2c", f"the path route was not stored with h2c: {v!r}")
    chip = js("""p => { const r = [...document.querySelectorAll('#vdirList tr.vdirEntry')].filter(x => x.querySelector('.zxs-path').textContent == p)[0];
        return r ? [...r.querySelectorAll('.zxs-fact')].map(x => x.textContent.trim()) : null; }""", grpc_path)
    if chip != ["h2c"]:
        fail("vdir-h2c", f"the list does not mark the h2c path route: {chip!r}")
    # a route added without ticking anything has no h2c (default off)
    js("""() => { $('#virtualDirectoryPath').val('/plainapi/'); $('#virtualDirectoryDomain').val('127.0.0.1:9/api/'); }""")
    js("addVdirToHost()")
    pg.wait_for_timeout(1200)
    v = vdir_of("/plainapi/")
    if not v or v.get("H2C"):
        fail("vdir-h2c", f"a path route added without the option has h2c: {v!r}")
    shot("sites-vdir-h2c-list.png")
    check_horizontal(pg, "Path routes h2c")
    theme(True)
    pg.wait_for_timeout(300)
    shot("sites-vdir-h2c-list-dark.png")
    theme(False)
    # Edit shows the stored state (advanced settings open), and unticking saves it off again
    js("""([p, h]) => editVdir(p, h)""", [grpc_path, SITES_HOSTS[0]])
    pg.wait_for_timeout(500)
    if not js("document.getElementById('vdH2C').checked") or not js("document.getElementById('advanceVdirRules').open"):
        fail("vdir-h2c", "Edit does not show that h2c is on for the path route")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(300)
    check_horizontal(pg, "Path routes h2c 390")
    shot("sites-vdir-h2c-edit-390.png")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    pg.uncheck("#vdH2C")
    js("submitVdirForm()")
    pg.wait_for_timeout(1200)
    v = vdir_of(grpc_path)
    if not v or v.get("H2C"):
        fail("vdir-h2c", f"unticking h2c in Edit did not switch it off: {v!r}")
    if js("!document.getElementById('newVDSection').hidden"):
        js("closeVdirForm()")

    # ---------------------------------------------------------------- HTTP Proxy list
    current["page"] = "sites-list"
    js("openTabById('httprp')")
    pg.wait_for_timeout(900)
    # a valid 199-character host name (63-character labels) with a long upstream and a long alias: the name wraps, the upstream and the
    # alias are cut with an ellipsis, the table stays inside its card and Edit stays reachable
    long_host = ".".join(["a" * 63, "b" * 63, "c" * 63]) + ".example"
    post("/api/proxy/add", dict(base, rootname=long_host))
    post("/api/proxy/upstream/add", {"ep": long_host, "origin": "upstream-" + "q" * 80 + ".internal.example:8080", "tls": "false", "tlsval": "false", "respt": "0", "maxconn": "0", "active": "true"})
    post("/api/proxy/setAlias", {"ep": long_host, "alias": json.dumps(["alias-" + "z" * 55 + ".example.test", "second.example.test"])})
    js("listProxyEndpoints(false)")
    pg.wait_for_timeout(1200)
    for lw_width in (1366, 1130):   # 1130: the Host column is at its narrowest before the Tags column folds away
        pg.set_viewport_size({"width": lw_width, "height": 1000})
        pg.wait_for_timeout(400)
        lw = js("""() => { const t = document.getElementById('httpProxyTable'), c = t.closest('.zx-card') || t.parentElement, r = e => e.getBoundingClientRect();
            const row = [...t.querySelectorAll('tr.ptRow')].find(e => e.getAttribute('data-ep').length > 150), cell = row ? r(row.querySelector('td.ptName')) : null;
            return {table: Math.round(r(t).right), card: Math.round(r(c).right), edit: Math.max(...[...t.querySelectorAll('td.ptAct')].map(e => Math.round(r(e).right))), vw: innerWidth,
                    row: !!row, spill: row ? [...row.querySelectorAll('.ptHost, .ptUp, .ptAliasName, .ptMoreUp')].filter(e => r(e).right > cell.right + 1 || r(e).width < 20).length : -1}; }""")
        if not lw["row"] or lw["table"] > lw["card"] + 1 or lw["edit"] > lw["card"] + 1 or lw["spill"]:
            fail("layout", f"HTTP Proxy list with a long host, upstream and alias: the table must end inside its card and nothing may leave the Host cell (window {lw_width}px): {lw}")
    shot("sites-httprp-list-longhost.png")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    post("/api/proxy/del", {"ep": long_host})
    js("listProxyEndpoints(false)")
    pg.wait_for_timeout(900)
    up_nowrap = js("""[...document.querySelectorAll('#httpProxyList .ptUps .ptUp')].every(a => a.getBoundingClientRect().height < 30)""")
    if not up_nowrap:
        fail("layout", "an upstream address wraps inside the port")
    shot("sites-httprp-list.png")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(500)
    check_horizontal(pg, "HTTP Proxy 390")
    clipped = js("(() => { const s = document.getElementById('ptSeg'); return s ? s.scrollWidth - s.clientWidth : 0; })()")
    if clipped > 2:
        fail("layout", f"the status filter group is clipped by {clipped}px at 390px")
    shot("sites-httprp-list-390.png")
    pg.set_viewport_size({"width": 1366, "height": 1000})

    # ---------------------------------------------------------------- dark theme: red outline button and footer text
    current["page"] = "sites-dark"
    theme(True)
    js("openTabById('streamproxy')")
    pg.wait_for_timeout(700)
    shot("sites-stream-dark.png")
    theme(False)

    # ---------------------------------------------------------------- no console warning from the plugin iframe
    current["page"] = "sites-console"
    warns = []
    p2 = ctx.new_page()
    p2.on("console", lambda m: warns.append(m.text) if m.type in ("warning", "error") else None)
    p2.goto(args.url + "/", wait_until="networkidle")
    p2.wait_for_timeout(1000)
    p2.close()
    for w in warns:
        if "Unrecognized feature" in w:
            fail("console", "the plugin iframe still has an invalid allow attribute: " + w)

    current["page"] = "sites-cleanup"
    for h in SITES_HOSTS:
        post("/api/proxy/del", {"ep": h})
