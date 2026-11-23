/*
    proxytable.js

    The HTTP proxy rule list (components/httprp.html): one component for listing, filtering, sorting,
    selecting (checkboxes, shift-click ranges, select all) and acting on rules.

    - Renders from a model (state.list) with one innerHTML write per page, event delegation on the table body,
      and pagination (page size 25/50/100) so that hundreds of rules never mean hundreds of DOM rows.
    - Bulk actions are handled by script/proxybulk.js (ProxyBulk.run), which calls /api/proxy/bulk.
    - Single enable / disable is the switch in each row (one click, with an undo toast).
    - A row shows the host with a muted summary of where it goes, the health of its upstream (uptime monitor) with
      the live request rate, a fixed set of protection chips, tags, the switch, Edit and a menu with the other actions.
    - No API changes: /api/proxy/list, /api/proxy/toggle, /api/proxy/del, /api/utm/list, /api/access/list.

    Globals kept for the rest of the UI (snippets call them through parent.*): listProxyEndpoints,
    renderTagsPreview, updateAccessRuleNameUnderHost, updateAliasListForEndpoint, editEndpoint, deleteEndpoint,
    filterProxyList. ProxyTable.highlight(name) scrolls to a rule and flashes its row (used after creating one).
*/
(function () {
    "use strict";

    var PAGE_SIZES = [25, 50, 100];
    var state = {
        list: [],            // rules as returned by /api/proxy/list
        healthRaw: {},       // rule -> upstream -> latest uptime monitor result
        waf: null,           // global WAF policy (Enabled, DefaultMode), decides what "follows the global policy" means
        access: {},          // access rule id -> access rule
        sel: {},             // rule -> true
        q: "",
        status: "all",       // all | enabled | disabled | errors | noauth | notls | nowaf
        tags: [],            // selected tag filters (a rule must have all of them)
        sort: { key: "host", dir: 1 },
        page: 1,
        pageSize: 50,
        view: [],            // filtered + sorted rules
        lastClicked: null,   // rule name, anchor for shift-click range selection
        flash: "",           // rule whose row is flashing (survives the re-renders caused by late health / access data)
        loaded: false
    };

    try {
        var saved = JSON.parse(zxStore.get("httprp_table") || "{}");
        if (saved.sort && saved.sort.key) { state.sort = saved.sort; }
        if (PAGE_SIZES.indexOf(saved.pageSize) > -1) { state.pageSize = saved.pageSize; }
    } catch (e) { /* storage may be blocked */ }
    function persist() {
        try { zxStore.set("httprp_table", JSON.stringify({ sort: state.sort, pageSize: state.pageSize })); } catch (e) { }
    }

    function esc(s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
        });
    }
    function $page() { return $("#httprpPage"); }
    function tr(x) { return typeof window.t === "function" ? window.t(x) : x; }
    function byName(name) {
        for (var i = 0; i < state.list.length; i++) { if (state.list[i].RootOrMatchingDomain === name) { return state.list[i]; } }
        return null;
    }
    function selNames() { return Object.keys(state.sel); }

    /* ------------------------------------------------------------------ derived values */
    function authLabel(r) {
        var m = r.AuthenticationProvider ? r.AuthenticationProvider.AuthMethod : 0;
        return { 1: "Basic Auth", 2: "Forward Auth", 3: "OAuth2", 4: "Zoraxy Auth" }[m] || "";
    }

    // "on" enabled and fine, "err" enabled but cannot serve, "off" disabled
    function ruleState(r) {
        if (r.Disabled) { return "off"; }
        if (!r.ActiveOrigins || r.ActiveOrigins.length === 0) { return "err"; }
        if (healthOf(r) === "down") { return "err"; }
        return "on";
    }
    function stateText(r) {
        if (r.Disabled) { return "Disabled"; }
        if (!r.ActiveOrigins || r.ActiveOrigins.length === 0) { return "Enabled, but no active upstream"; }
        var h = healthOf(r);
        if (h === "down") { return "Enabled, upstream offline (uptime monitor)"; }
        if (h === "up") { return "Enabled, upstream online"; }
        return "Enabled";
    }

    function prepare(r) {
        var ups = (r.ActiveOrigins || []).map(function (o) { return o.OriginIpOrDomain; });
        r._up = ups.join(" ").toLowerCase();
        r._hay = [r.RootOrMatchingDomain, (r.MatchingDomainAlias || []).join(" "), r._up, (r.Tags || []).join(" "), authLabel(r)].join(" ").toLowerCase();
        r._tags = (r.Tags || []).map(function (t) { return t.toLowerCase(); });
    }

    function applyFilter() {
        var q = state.q.trim().toLowerCase();
        var terms = q ? q.split(/\s+/) : [];
        var wantTags = state.tags.map(function (t) { return t.toLowerCase(); });
        var out = state.list.filter(function (r) {
            for (var i = 0; i < terms.length; i++) { if (r._hay.indexOf(terms[i]) < 0) { return false; } }
            for (var j = 0; j < wantTags.length; j++) { if (r._tags.indexOf(wantTags[j]) < 0) { return false; } }
            switch (state.status) {
                case "enabled": return !r.Disabled;
                case "disabled": return !!r.Disabled;
                case "errors": return ruleState(r) === "err";
                case "noauth": return !(r.AuthenticationProvider && r.AuthenticationProvider.AuthMethod);
                case "notls": return !r.Disabled && noTls(r);
                case "nowaf": return !r.Disabled && noWaf(r);
            }
            return true;
        });
        var k = state.sort.key, d = state.sort.dir;
        var rank = { err: 0, on: 1, off: 2 };
        out.sort(function (a, b) {
            var x, y;
            if (k === "upstream") { x = a._up; y = b._up; }
            else if (k === "status") { x = rank[ruleState(a)]; y = rank[ruleState(b)]; }
            else if (k === "tags") { x = (a.Tags || []).length ? a._tags.slice().sort()[0] : "￿"; y = (b.Tags || []).length ? b._tags.slice().sort()[0] : "￿"; }
            else { x = a.RootOrMatchingDomain.toLowerCase(); y = b.RootOrMatchingDomain.toLowerCase(); }
            if (x < y) { return -d; }
            if (x > y) { return d; }
            return a.RootOrMatchingDomain < b.RootOrMatchingDomain ? -1 : 1;
        });
        state.view = out;
        var pages = Math.max(1, Math.ceil(out.length / state.pageSize));
        if (state.page > pages) { state.page = pages; }
    }

    /* ------------------------------------------------------------------ rendering */
    function tlsGlobalOn() {
        try { return $("#tls").length ? $("#tls").checkbox("is checked") : false; } catch (e) { return false; }
    }
    function hostLink(r, host) {
        var proto = tlsGlobalOn() ? "https://" : "http://";
        var port = (typeof currentListeningPort !== "undefined") ? currentListeningPort : "";
        port = (port === "" || port == 80 || port == 443) ? "" : ":" + port;
        return proto + host.replace(/^\*\./, "") + port;
    }

    function noTls(r) { return !tlsGlobalOn() || !!r.BypassGlobalTLS; }
    function wafSource(r) { return r.WAFSource || (r.WAF ? "custom" : ""); }
    function noWaf(r) {
        var ws = wafSource(r);
        return ws === "off" || ((!ws || ws === "inherit") && !(state.waf && state.waf.Enabled));
    }
    function fmt(s, a) { return tr(s).replace("{0}", a); }

    // Protection: four fixed chips (HTTPS, WAF, login, rate limit) so the column lines up and a gap is visible at a glance,
    // then one "+n" chip for the rest. The label is the tooltip (data-zxs-tip) and the accessible name.
    function protHtml(r) {
        function chip(cls, st, icon, label) {
            return '<span class="zxs-protchip ptBadge ' + cls + ' is-' + st + '" role="img" aria-label="' + esc(label) + '" data-zxs-tip="' + esc(label) + '"><i class="' + icon + ' icon" aria-hidden="true"></i></span>';
        }
        var out = [], sum = [], al = authLabel(r), ws = wafSource(r);
        var chip0 = chip;
        chip = function (cls, st, icon, label) { sum.push(label); return chip0(cls, st, icon, label); };
        if (!tlsGlobalOn()) { out.push(chip("tls", "warn", "lock open", tr("Plain HTTP: HTTPS is off on the listener"))); }
        else if (r.BypassGlobalTLS) { out.push(chip("tls", "warn", "lock open", tr("HTTPS, and plain HTTP is allowed too (HTTPS bypass)"))); }
        else { out.push(chip("tls", "on", "lock", tr("HTTPS: served over TLS"))); }

        if (ws && ws !== "inherit" && ws !== "off") {
            var det = ws === "detection_only";
            out.push(chip("waf" + (det ? " detect" : ""), det ? "watch" : "on", "shield alternate", (det ? tr("WAF: detection only") : tr("WAF: on")) + (r.WAFProfile ? " (" + r.WAFProfile + ")" : "")));
        } else if ((!ws || ws === "inherit") && state.waf && state.waf.Enabled) {
            var blocking = state.waf.DefaultMode === "block";
            out.push(chip("waf" + (blocking ? "" : " detect"), blocking ? "on" : "watch", "shield alternate", blocking ? tr("WAF: follows the global policy (blocking)") : tr("WAF: follows the global policy (detection only)")));
        } else {
            out.push(chip("nowaf", "off", "shield alternate", tr("WAF: off for this host")));
        }
        out.push(al ? chip("auth", "on", "key", fmt("Login required: {0}", al)) : chip("noauth", "off", "key", tr("No login: everyone who reaches the host gets in")));
        out.push(r.RequireRateLimit ? chip("rate", "on", "tachometer alternate", fmt("Rate limit: {0} requests per second per address", r.RateLimit))
            : chip("norate", "off", "tachometer alternate", tr("No rate limit")));

        var more = [];
        if (r.RequireCaptcha) { more.push(tr("CAPTCHA challenge")); }
        if (r.BlockCommonExploits) { more.push(tr("Blocks common exploit payloads")); }
        if (r.BlockAICrawlers) { more.push(tr("Blocks AI crawlers and bots")); }
        if (more.length) {
            out.push('<span class="zxs-protchip ptBadge is-more" role="img" aria-label="' + esc(more.join(", ")) + '" data-zxs-tip="' + esc(more.join("\n")) + '">+' + more.length + '</span>');
            sum = sum.concat(more);
        }
        // one Tab stop per row: the keyboard gets the same summary the mouse gets chip by chip
        return '<span class="zxs-prot" tabindex="0" role="group" aria-label="' + esc(fmt("Protection of {0}", r.RootOrMatchingDomain) + ": " + sum.join("; ")) + '" data-zxs-sum="' + esc(sum.join("\n")) + '">' + out.join("") + '</span>';
    }

    // at most three tag chips per row (the ones being filtered on first), the rest behind "+n"; a long tag is cut with an ellipsis
    var TAGS_SHOWN = 3;
    function tagsHtml(r) {
        var tags = (r.Tags || []).slice();
        if (state.tags.length) { tags.sort(function (a, b) { return (state.tags.indexOf(b) > -1) - (state.tags.indexOf(a) > -1); }); }
        var rest = tags.slice(TAGS_SHOWN);
        var html = tags.slice(0, TAGS_SHOWN).map(function (t) {
            return '<a href="#" class="ptTag zxs-tag" data-tag="' + esc(t) + '" title="' + esc(fmt("Show only hosts tagged {0}", t)) + '"><span class="zxs-tag__dot" style="background:' + getTagColorByName(t) + '"></span><span class="zxs-tag__text">' + esc(t) + '</span></a>';
        }).join("");
        if (rest.length) {
            html += '<span class="zxs-tag zxs-tag--more ptTagMore" tabindex="0" role="note" aria-label="' + esc(fmt("{0} more tags", rest.length) + ": " + rest.join(", ")) + '" data-zxs-tip="' + esc(rest.join("\n")) + '">+' + rest.length + '</span>';
        }
        return html;
    }

    function rowHtml(r) {
        var name = r.RootOrMatchingDomain, e = esc(name);

        // second line of the host cell: where the requests go, then the facts that change how the host behaves
        var ups = r.ActiveOrigins || [], upHtml;
        if (!ups.length) {
            upHtml = '<span class="zxs-bad"><i class="exclamation triangle icon" aria-hidden="true"></i>' + esc(tr("No active upstream")) + '</span>';
        } else {
            var u = ups[0], addr = u.OriginIpOrDomain;
            var lk = u.RequireTLS ? (u.SkipCertValidations ? '<i class="lock open icon" title="' + esc(tr("TLS to the upstream, certificate not verified")) + '"></i>' : '<i class="lock icon" title="' + esc(tr("TLS to the upstream")) + '"></i>') : "";
            // .ptLead keeps the arrow, the address and the lock on one line (the address is cut with an ellipsis); "+n more" may wrap under it
            upHtml = '<span class="ptLead"><span class="zxs-arrow" aria-hidden="true">&rarr;</span>' + (/^unix:/i.test(addr) ? '<span class="ptUp" title="' + esc(addr) + '">' + esc(addr) + '</span>'
                : '<a class="ptUp" href="' + esc((u.RequireTLS ? "https://" : "http://") + addr) + '" target="_blank" rel="noopener" title="' + esc(addr + "\n" + tr("Open the upstream directly")) + '">' + esc(addr) + '</a>') + lk + '</span>';
            if (ups.length > 1) {
                upHtml += ' <a href="#" class="ptMoreUp" data-ep="' + e + '" title="' + esc(ups.slice(1).map(function (x) { return x.OriginIpOrDomain; }).join("\n")) + '">' + esc(fmt("+{0} more", ups.length - 1)) + '</a>';
            }
        }
        var sub = ['<span class="ptUps zxs-wrap">' + upHtml + '</span>'];
        if (r.MatchingDomainAlias && r.MatchingDomainAlias.length) {
            // the first alias, then "+n more aliases" (the full list is the tooltip; the click opens the editor, where they are managed)
            var al0 = r.MatchingDomainAlias[0], alMore = r.MatchingDomainAlias.length - 1;
            sub.push('<span class="ptAlias"><span class="ptLead">' + esc(tr("also")) + '&nbsp;<a class="ptAliasName" href="' + esc(hostLink(r, al0)) + '" target="_blank" rel="noopener" title="' + esc(al0) + '">' + esc(al0) + '</a></span>' +
                (alMore > 0 ? '<a href="#" class="ptMoreUp ptMoreAlias" data-ep="' + e + '" title="' + esc(r.MatchingDomainAlias.slice(1).join("\n")) + '">' + esc(alMore === 1 ? tr("+1 more alias") : fmt("+{0} more aliases", alMore)) + '</a>' : "") + '</span>');
        }
        if (r.ListeningPorts && r.ListeningPorts.length) { sub.push('<span title="' + esc(tr("Alternative listening ports")) + '"><i class="plug icon" aria-hidden="true"></i>' + r.ListeningPorts.map(esc).join(", ") + '</span>'); }
        var vd = r.VirtualDirectories || [];
        if (vd.length) {
            sub.push('<a href="#" class="ptVdir" data-ep="' + e + '" title="' + esc(vd.map(function (v) { return v.MatchingPath + " > " + v.Domain; }).join("\n")) + '">' + esc(vd.length === 1 ? tr("1 path route") : fmt("{0} path routes", vd.length)) + '</a>');
        }
        var aid = r.AccessFilterUUID || "default";
        if (aid !== "default") {
            var ar = state.access[aid];
            sub.push('<span class="ptAccess" title="' + esc(tr("Access rule")) + '">' + (ar ? '<i class="filter icon" aria-hidden="true"></i>' + esc(ar.Name) : '<span class="zxs-bad"><i class="exclamation triangle icon" aria-hidden="true"></i>' + esc(tr("Access rule missing")) + '</span>') + '</span>');
        }

        var tags = tagsHtml(r);
        var on = !r.Disabled;
        return '<tr class="subdEntry ptRow ' + (r.Disabled ? "isOff is-disabled " : "") + (state.sel[name] ? "isSel is-selected " : "") + (state.flash === name ? "ptFlash" : "") + '" eptuuid="' + e + '" data-ep="' + e + '">' +
            '<td class="ptSel"><input type="checkbox" class="zx-check bulkSel" data-ep="' + e + '" aria-label="' + esc(fmt("Select {0}", name)) + '"' + (state.sel[name] ? " checked" : "") + '></td>' +
            '<td class="ptName"><div class="ptNameBody">' +
            '<a class="ptHost zxs-cell__main zxs-clamp2" href="' + esc(hostLink(r, name)) + '" target="_blank" rel="noopener" title="' + esc(name + "\n" + tr("Open this host in a new tab")) + '">' + e + '<i class="external alternate icon" aria-hidden="true"></i></a>' +
            '<span class="ptSub zxs-cell__sub">' + sub.join('<span class="zxs-dotsep"></span>') + '</span>' +
            '<div class="ptTagsInline">' + tags + '</div></div></td>' +   // shown under the host while the Tags column is folded away (narrow windows)
            '<td class="ptLive" data-live="' + e + '">' + liveCellHtml(name, r) + '</td>' +
            '<td class="ptProt">' + protHtml(r) + '</td>' +
            '<td class="ptTagsCell">' + tags + '</td>' +
            '<td class="ptStatusCell"><input type="checkbox" class="zx-switch ptPill" role="switch" data-act="toggle"' + (on ? " checked" : "") + ' aria-label="' + esc(fmt("{0} is enabled", name)) + '" title="' + esc(tr(stateText(r))) + ". " + esc(on ? tr("Click to disable") : tr("Click to enable")) + '"></td>' +
            '<td class="ptAct"><span class="zxs-actions"><button type="button" class="zx-btn zx-btn--secondary zx-btn--sm editBtn" data-act="edit" aria-label="' + esc(fmt("Edit {0}", name)) + '">' + esc(tr("Edit")) + '</button>' +
            '<button type="button" class="zxs-iconbtn ptKebab" data-act="menu" aria-haspopup="menu" aria-expanded="false" aria-label="' + esc(fmt("More actions for {0}", name)) + '" title="' + esc(tr("More actions")) + '"><i class="ellipsis vertical icon" aria-hidden="true"></i></button></span></td>' +
            '</tr>';
    }

    /* ------------------------------------------------------------------ live column
       GET /api/stats/livemap every 2 s while this page is on screen (the same data as the Status page Traffic map, no new
       counters): requests per second now, a sparkline of the last two minutes, active requests and the error rate. The cells are
       updated in place, so selection, focus and open menus survive; the table is never rebuilt by a tick. */
    var LIVE_POLL_MS = 2000, LIVE_KEEP = 60;
    var live = { by: {}, at: 0, ok: false, timer: null, busy: false };

    function fmtRps(v) { return v >= 100 ? String(Math.round(v)) : v >= 10 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v >= 0.05 ? v.toFixed(1) : "0"; }

    function sparkSvg(vals) {
        var n = vals.length, W = 88, H = 20;
        if (n < 2) { return '<svg class="ptSpark" viewBox="0 0 ' + W + ' ' + H + '" aria-hidden="true" focusable="false"></svg>'; }
        var max = 0, i;
        for (i = 0; i < n; i++) { if (vals[i] > max) { max = vals[i]; } }
        if (max < 1) { max = 1; }                       // a quiet site draws a flat line, not noise scaled up
        var pts = [];
        for (i = 0; i < n; i++) { pts.push((i / (n - 1) * W).toFixed(1) + " " + (H - 1 - vals[i] / max * (H - 3)).toFixed(1)); } // the whole width, whatever has been seen so far
        var line = "M" + pts.join(" L");
        var x0 = pts[0].split(" ")[0], x1 = pts[n - 1].split(" ")[0];
        return '<svg class="ptSpark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" aria-hidden="true" focusable="false">' +
            '<path class="fill" d="' + line + " L" + x1 + " " + H + " L" + x0 + " " + H + ' Z"/><path d="' + line + '"/></svg>';
    }

    // first line: is the server behind the host answering (uptime monitor), with the latency of the last check
    function healthHtml(r) {
        if (r.Disabled) { return '<span class="zxs-health zxs-health--off ptLiveOff" title="' + esc(tr("This host is disabled: Zoraxy does not answer for it")) + '">' + esc(tr("Off")) + '</span>'; }
        if (!r.ActiveOrigins || r.ActiveOrigins.length === 0) { return '<span class="zxs-health zxs-health--danger" title="' + esc(tr("Enabled, but no active upstream")) + '">' + esc(tr("No upstream")) + '</span>'; }
        var h = healthInfo(r);
        if (h.state === "down") { return '<span class="zxs-health zxs-health--danger" title="' + esc(tr("The uptime monitor cannot reach the upstream")) + '">' + esc(tr("Down")) + '</span>'; }
        if (h.state === "up") {
            return '<span class="zxs-health zxs-health--ok" title="' + esc(tr("The upstream answered the last uptime check")) + '">' + esc(tr("Up")) +
                (h.ms != null ? ' <span class="zxs-health__meta">' + (h.ms >= 1000 ? (h.ms / 1000).toFixed(1) + ' s' : Math.round(h.ms) + ' ms') + '</span>' : '') + '</span>';
        }
        return '<span class="zxs-health zxs-health--off" title="' + esc(tr("No uptime check result for this host yet")) + '">' + esc(tr("Not checked")) + '</span>';
    }

    function liveCellHtml(name, r) {
        var head = r ? healthHtml(r) : "";
        if (r && r.Disabled) { return '<div class="ptLiveBox"><div class="ptLiveText">' + head + '</div></div>'; }
        var d = live.by[name];
        if (!live.ok || !d) { return '<div class="ptLiveBox"><div class="ptLiveText">' + head + '<span class="ptLiveRow ptLiveWait" aria-hidden="true">&middot;&middot;&middot;</span></div></div>'; }
        var rps = d.rps, vals = d.hist, peak = 0, i;
        for (i = 0; i < vals.length; i++) { if (vals[i] > peak) { peak = vals[i]; } }
        var title = "Now " + fmtRps(rps) + " req/s; busiest moment of the last " + Math.max(2, Math.round(vals.length * 2 / 60)) + " min: " + fmtRps(peak) + " req/s" +
            (d.inFlight ? "; " + d.inFlight + " active now" : "") + (d.err > 0.05 ? "; " + fmtRps(d.err) + " server errors (HTTP 5xx) per second" : "");
        var top = rps >= 0.05 ? '<span class="ptLiveNum">' + fmtRps(rps) + '</span> req/s' : '<span class="ptLiveIdle">idle</span>';
        if (d.err > 0.05) { top += ' <span class="ptLiveErr">&middot; ' + fmtRps(d.err) + ' 5xx/s</span>'; }
        else if (d.inFlight > 0) { top += ' <span class="ptLiveAct">&middot; ' + d.inFlight + ' active</span>'; }
        // a host that has been silent for the whole window draws no line at all (nothing to show, no space taken)
        return '<div class="ptLiveBox"><div class="ptLiveText">' + head + '<span class="ptLiveRow" title="' + esc(title) + '">' + top + '</span></div>' + (peak > 0 ? sparkSvg(vals) : "") + '</div>';
    }

    function applyLive() {
        $("#httpProxyList td.ptLive").each(function () {
            var name = $(this).closest("tr").attr("data-ep");
            var r = byName(name);
            $(this).html(liveCellHtml(name, r));
        });
    }

    function liveOnScreen() { return !document.hidden && $("#httprp").is(":visible") && state.list.length > 0; }

    function liveTick() {
        if (live.busy || !liveOnScreen()) { return; }
        live.busy = true;
        $.ajax({ url: "/api/stats/livemap", dataType: "json", cache: false, timeout: 4000 }).done(function (d) {
            live.busy = false;
            if (!d || !Array.isArray(d.proxies)) { return; }
            live.ok = true; live.at = Date.now();
            var seen = {};
            d.proxies.forEach(function (p) {
                var e = live.by[p.domain] || (live.by[p.domain] = { hist: [] });
                if (!d.warmup) { e.hist.push(p.rps || 0); if (e.hist.length > LIVE_KEEP) { e.hist.shift(); } }
                e.rps = d.warmup ? 0 : (p.rps || 0); e.err = d.warmup ? 0 : (p.errRps || 0); e.inFlight = p.inFlight || 0;
                seen[p.domain] = true;
            });
            Object.keys(live.by).forEach(function (k) { if (!seen[k]) { delete live.by[k]; } });
            applyLive();
        }).fail(function () { live.busy = false; live.ok = false; applyLive(); });
    }

    function liveStart() {
        if (live.timer) { return; }
        live.timer = setInterval(liveTick, LIVE_POLL_MS);
        liveTick();
        document.addEventListener("visibilitychange", function () { if (!document.hidden) { liveTick(); } });
    }

    function renderRows() {
        closeMenu();
        var start = (state.page - 1) * state.pageSize;
        var rows = state.view.slice(start, start + state.pageSize);
        var $body = $("#httpProxyList");
        var cols = 7;
        // an empty installation has nothing to search, filter or page through: only the explanation and the two ways to start
        $("#ptTools, #ptFooter").prop("hidden", !state.list.length);
        // one primary button per view: the empty state carries it while there is no host at all
        $("#ptNewRule").toggleClass("zx-btn--primary", !!state.list.length).toggleClass("zx-btn--secondary", !state.list.length);
        $("#httpProxyTable thead").prop("hidden", !rows.length);
        if (!state.list.length) {
            $body.html('<tr class="ptEmptyRow"><td colspan="' + cols + '"><div class="zx-empty ptEmpty"><div class="zx-empty__icon"><i class="sitemap icon" aria-hidden="true"></i></div>' +
                '<p class="zx-empty__title">' + esc(tr("No hosts yet")) + '</p>' +
                '<p class="zx-empty__text">' + esc(tr("A proxy rule tells Zoraxy which server on your network answers for a host name, for example app.example.com to 192.168.1.20:8080. Create the first one, or start from a template.")) + '</p>' +
                '<div class="zx-btn-row" style="justify-content:center;"><button type="button" class="zx-btn zx-btn--primary" onclick="openNewRuleDialog()"><i class="plus icon" aria-hidden="true"></i> ' + esc(tr("New proxy rule")) + '</button>' +
                '<button type="button" class="zx-btn zx-btn--secondary" onclick="openRuleTemplateManager()"><i class="clone outline icon" aria-hidden="true"></i> ' + esc(tr("Templates")) + '</button></div></div></td></tr>');
        } else if (!rows.length) {
            $body.html('<tr class="ptEmptyRow"><td colspan="' + cols + '"><div class="zx-empty ptEmpty"><div class="zx-empty__icon"><i class="search icon" aria-hidden="true"></i></div>' +
                '<p class="zx-empty__title">' + esc(tr("No host matches")) + '</p><p class="zx-empty__text">' + esc(tr("Nothing fits the current search and filters.")) + '</p>' +
                '<button type="button" class="zx-btn zx-btn--secondary" data-act="clearfilters">' + esc(tr("Clear filters")) + '</button></div></td></tr>');
        } else {
            var html = "";
            for (var i = 0; i < rows.length; i++) { html += rowHtml(rows[i]); }
            $body.html(html);
        }
    }

    function renderHeader() {
        $("#httpProxyTable thead [data-sort]").each(function () {
            var k = $(this).attr("data-sort"), active = state.sort.key === k;
            if (this.tagName === "TH") {   // the Host header also carries the Upstream sort: the column is sorted when either is
                var inner = $(this).find("[data-sort]").attr("data-sort");
                $(this).attr("aria-sort", (active || state.sort.key === inner) ? (state.sort.dir > 0 ? "ascending" : "descending") : "none");
            } else { $(this).attr("aria-pressed", active ? "true" : "false"); }
            $(this).toggleClass("sorted", active).children(".ptArrow").text(active ? (state.sort.dir > 0 ? "\u2191" : "\u2193") : "");
        });
    }

    var FILTER_NAMES = { errors: "Upstream down", notls: "Without HTTPS", nowaf: "Without WAF", noauth: "Without login" };

    function renderTools() {
        var counts = { all: state.list.length, enabled: 0, disabled: 0, errors: 0, noauth: 0, notls: 0, nowaf: 0 };
        state.list.forEach(function (r) {
            if (r.Disabled) { counts.disabled++; } else { counts.enabled++; }
            if (ruleState(r) === "err") { counts.errors++; }
            if (!(r.AuthenticationProvider && r.AuthenticationProvider.AuthMethod)) { counts.noauth++; }
            if (!r.Disabled && noTls(r)) { counts.notls++; }
            if (!r.Disabled && noWaf(r)) { counts.nowaf++; }
        });
        $("#ptSeg button").each(function () {
            var f = $(this).attr("data-f");
            $(this).toggleClass("active", state.status === f).attr("aria-pressed", state.status === f)
                .find(".n").text(counts[f]);
        });

        // summary tiles above the list: each one is a filter (the same state as the segmented control)
        var tiles = { sites: counts.all, down: counts.errors, notls: counts.notls, nowaf: counts.nowaf, noauth: counts.noauth };
        $("#ptStats [data-stat]").each(function () {
            var k = $(this).attr("data-stat"), f = $(this).attr("data-f");
            $(this).find(".zx-stat__value").text(tiles[k]);
            $(this).attr("aria-pressed", f !== "all" && state.status === f ? "true" : "false");
            if (k === "down") { $(this).toggleClass("zx-stat--danger", tiles[k] > 0); }
            if (k === "notls" || k === "nowaf") { $(this).toggleClass("zx-stat--warn", tiles[k] > 0); }
        });
        $("#ptStatSitesHint").text(counts.disabled ? tr("{0} enabled, {1} disabled").replace("{0}", counts.enabled).replace("{1}", counts.disabled) : tr("all enabled"));
        $("#ptStats").prop("hidden", counts.all === 0);
        // a tile filter has no button in the segmented control: say which one is on, next to it
        var note = FILTER_NAMES[state.status];
        $("#ptFilterNote").prop("hidden", !note).text(note ? tr(note) : "");

        // tag chips: most used first, the rest in a dropdown
        var tc = {};
        state.list.forEach(function (r) { (r.Tags || []).forEach(function (t) { tc[t] = (tc[t] || 0) + 1; }); });
        var tags = Object.keys(tc).sort(function (a, b) { return tc[b] - tc[a] || a.localeCompare(b); });
        state.tags = state.tags.filter(function (t) { return tc[t]; });
        var shown = tags.slice(0, 8), rest = tags.slice(8);
        state.tags.forEach(function (t) { if (shown.indexOf(t) < 0) { shown.push(t); rest = rest.filter(function (x) { return x !== t; }); } });
        var html = '<span class="zxs-list__sublabel">' + esc(tr("Tags")) + '</span>' + shown.map(function (t) {
            var on = state.tags.indexOf(t) > -1;
            return '<button type="button" class="ptChip zxs-chip' + (on ? " on" : "") + '" data-tag="' + esc(t) + '" aria-pressed="' + on + '"><span class="ptChipDot zxs-chip__dot" style="background:' + getTagColorByName(t) + '"></span><span class="zxs-chip__text" title="' + esc(t) + '">' + esc(t) + '</span> <span class="n">' + tc[t] + '</span></button>';
        }).join("");
        if (rest.length) {
            html += '<select id="ptMoreTags" class="ptMoreTags zx-select" style="width:auto;min-height:28px;height:28px;padding-top:0;padding-bottom:0;" aria-label="' + esc(tr("More tags")) + '"><option value="">' + esc(fmt("+{0} more tags", rest.length)) + '</option>' +
                rest.map(function (t) { return '<option value="' + esc(t) + '">' + esc(t) + ' (' + tc[t] + ')</option>'; }).join("") + '</select>';
        }
        $("#ptTagChips").html(html).toggle(tags.length > 0);
        $("#ptClear").toggle(!!(state.q || state.tags.length || state.status !== "all"));
    }

    function renderPager() {
        var total = state.view.length, pages = Math.max(1, Math.ceil(total / state.pageSize));
        var from = total ? (state.page - 1) * state.pageSize + 1 : 0, to = Math.min(total, state.page * state.pageSize);
        var filtered = total !== state.list.length;
        $("#ptCount").text(total ? (tr("{0} to {1} of {2} hosts").replace("{0}", from).replace("{1}", to).replace("{2}", total) + (filtered ? " (" + fmt("{0} in total", state.list.length) + ")" : "")) : fmt("0 of {0} hosts", state.list.length));
        $("#ptPager").toggle(total > 0 && (pages > 1 || total > PAGE_SIZES[0]));
        $("#ptPrev").prop("disabled", state.page <= 1);
        $("#ptNext").prop("disabled", state.page >= pages);
        $("#ptPageNo").text(tr("Page {0} of {1}").replace("{0}", state.page).replace("{1}", pages));
        $("#ptPageSize").val(state.pageSize);
    }

    function renderBulk() {
        var names = selNames(), n = names.length;
        // the bar takes the place of the search row, so the table stays where it is (uxkit.js, zxBulkSwap)
        if (!renderBulk.swap && window.zxBulkSwap) { renderBulk.swap = window.zxBulkSwap(document.getElementById("bulkBar"), document.getElementById("ptTools")); }
        if (renderBulk.swap) { renderBulk.swap.set(n > 0); } else { $("#bulkBar").prop("hidden", n === 0); }
        // header checkbox reflects the rows on this page
        var start = (state.page - 1) * state.pageSize, pageRows = state.view.slice(start, start + state.pageSize);
        var onPage = pageRows.filter(function (r) { return state.sel[r.RootOrMatchingDomain]; }).length;
        var h = document.getElementById("bulkSelectAll");
        if (h) { h.checked = pageRows.length > 0 && onPage === pageRows.length; h.indeterminate = onPage > 0 && onPage < pageRows.length; }
        if (h) {
            var some = h.indeterminate, tip = h.checked ? tr("Clear the selection on this page") : (some ? tr("Select the rest of this page") : tr("Select every host on this page"));
            h.title = tip; h.setAttribute("aria-label", tip);
        }
        // The page is only part of the list (paging): when every row shown is selected, the bar offers the rest next to the count,
        // and once everything is selected the count says so (it is then larger than what is on screen).
        var matching = state.view.length, allSel = state.view.filter(function (r) { return state.sel[r.RootOrMatchingDomain]; }).length;
        var pageFull = pageRows.length > 0 && onPage === pageRows.length && matching > pageRows.length;
        var filtered = matching !== state.list.length;
        var $more = $("#bulkSelectMatching"), mode = !pageFull ? "" : (allSel < matching ? "offer" : "all");
        $more.prop("hidden", mode !== "offer").attr("data-mode", mode);
        var count = fmt("{0} selected", n);
        if (mode === "offer") {
            var here = fmt("All {0} hosts on this page are selected.", pageRows.length), rest = fmt(filtered ? "Select all {0} matching hosts" : "Select all {0} hosts", matching);
            $more.find(".bulkMoreText").text(here);
            $more.find(".bulkMoreBtn").text(fmt("Select all {0}", matching)).attr("title", here + " " + rest).attr("aria-label", rest);
        } else if (mode === "all" && n === matching) {
            count = fmt("All {0} selected", n);
        }
        $("#bulkBar .bulkCount").text(count).attr("title", mode === "all" ? fmt(filtered ? "All {0} matching hosts are selected." : "All {0} hosts are selected.", matching) : null);
        if (renderBulk.swap) { renderBulk.swap.fit(); }
    }

    function render() {
        applyFilter();
        renderTools();
        renderHeader();
        renderRows();
        renderPager();
        renderBulk();
    }

    /* ------------------------------------------------------------------ data */
    function loadHealth() {
        $.get("/api/utm/list", function (data) {
            var h = {};
            if (data && typeof data === "object" && !data.error) {
                Object.keys(data).forEach(function (id) {
                    // newest result per probed URL; stale URLs of upstreams that were since changed are ignored below
                    var last = {};
                    (data[id] || []).forEach(function (rec) {
                        var u = String(rec.URL || "").replace(/^[a-z]+:\/\//i, "").replace(/\/$/, "");
                        if (!last[u] || rec.Timestamp >= last[u].Timestamp) { last[u] = rec; }
                    });
                    h[id] = last;
                });
            }
            state.healthRaw = h;
            if (state.loaded) { render(); }
        });
    }
    // "up" / "down" for a rule from the uptime monitor results of its current active upstreams ("" when unknown),
    // and the latency of the last successful check (the fastest upstream that answered)
    function healthInfo(r) {
        var recs = state.healthRaw && state.healthRaw[r.RootOrMatchingDomain];
        if (!recs) { return { state: "", ms: null }; }
        var seen = 0, up = 0, ms = null;
        (r.ActiveOrigins || []).forEach(function (o) {
            // the probed URL carries the health-check path (host:port/healthz), and results recorded before the
            // path was changed stay in the log under the old URL: take the newest result of any URL of this upstream
            var origin = String(o.OriginIpOrDomain).replace(/\/$/, ""), rec = null;
            Object.keys(recs).forEach(function (u) {
                if (u !== origin && u.indexOf(origin + "/") !== 0) { return; }
                if (!rec || recs[u].Timestamp >= rec.Timestamp) { rec = recs[u]; }
            });
            if (rec) {
                seen++;
                if (rec.Online) { up++; if (typeof rec.Latency === "number" && (ms === null || rec.Latency < ms)) { ms = rec.Latency; } }
            }
        });
        return { state: seen === 0 ? "" : (up > 0 ? "up" : "down"), ms: ms };
    }
    function healthOf(r) { return healthInfo(r).state; }
    function loadWaf() {
        $.getJSON("/api/waf/policy", function (p) {
            if (p && !p.error) { state.waf = p; if (state.loaded) { render(); } }
        });
    }
    function loadAccess() {
        $.get("/api/access/list", function (data) {
            if (data && !data.error && data.forEach) {
                var m = {};
                data.forEach(function (a) { m[a.ID] = a; });
                state.access = m;
                if (state.loaded) { render(); }
            }
        });
    }

    function reload(preserveFilters) {
        if (preserveFilters === false) { state.tags = []; state.status = "all"; state.q = ""; $("#searchInput").val(""); }
        return $.get("/api/proxy/list?type=host", function (data) {
            if (data && data.error !== undefined) {
                $("#httpProxyList").html('<tr class="ptEmptyRow"><td colspan="7"><div class="zx-empty ptEmpty"><div class="zx-empty__icon"><i class="exclamation triangle icon" aria-hidden="true"></i></div><p class="zx-empty__title">' + esc(tr("Could not load the hosts")) + '</p><p class="zx-empty__text">' + esc(data.error) + '</p>' +
                    '<button type="button" class="zx-btn zx-btn--secondary" onclick="ProxyTable.reload()">' + esc(tr("Try again")) + '</button></div></td></tr>');
                return;
            }
            state.list = data || [];
            state.list.forEach(prepare);
            window.httpProxyList = state.list;
            Object.keys(state.sel).forEach(function (k) { if (!byName(k)) { delete state.sel[k]; } });
            state.loaded = true;
            render();
            loadHealth();
            loadAccess(); loadWaf();
        });
    }

    /* ------------------------------------------------------------------ actions */
    function toast(msg, actionLabel, fn) {
        var $t = $("#ptToast");
        if (!$t.length) {
            $t = $('<div id="ptToast" role="status" aria-live="polite"><span class="ptToastMsg"></span><button type="button" class="ptToastAct"></button></div>').appendTo("body");
        }
        clearTimeout($t.data("timer"));
        $t.find(".ptToastMsg").text(msg);
        var $b = $t.find(".ptToastAct").off("click").toggle(!!actionLabel).text(actionLabel || "");
        if (fn) { $b.on("click", function () { $t.removeClass("show"); fn(); }); }
        $t.addClass("show").data("timer", setTimeout(function () { $t.removeClass("show"); }, 7000));
    }

    function setEnabled(name, enable, undoable) {
        var r = byName(name);
        if (!r) { return; }
        var was = !r.Disabled;
        r.Disabled = !enable;
        render();
        $.cjax({
            url: "/api/proxy/toggle", data: { ep: name, enable: enable },
            success: function (data) {
                if (data && data.error !== undefined) {
                    r.Disabled = !was; render(); msgbox(data.error, false);
                    return;
                }
                if (typeof reloadUptimeList === "function") { try { reloadUptimeList(); } catch (e) { } }
                var said = fmt(enable ? "{0} enabled" : "{0} disabled", name);
                if (undoable) { toast(said, tr("Undo"), function () { setEnabled(name, was, false); }); }
                else { toast(said); }
            },
            error: function () { r.Disabled = !was; render(); }
        });
    }

    function openEditor(name) {
        var r = byName(name);
        if (!r) { return; }
        var copy = JSON.parse(JSON.stringify(r));
        Object.keys(copy).forEach(function (k) { if (k.charAt(0) === "_") { delete copy[k]; } });
        initHttpProxyRuleEditorModal(copy);
    }

    function deleteRule(name) {
        window.confirmBox(fmt("Remove the proxy rule for {0}?", name), function (choice) {
            if (choice !== true) { return; }
            $.cjax({
                url: "/api/proxy/del", method: "POST", data: { ep: name },
                success: function (data) {
                    if (data && data.error !== undefined) { msgbox(data.error, false); return; }
                    delete state.sel[name];
                    reload();
                    msgbox("Proxy rule deleted", true);
                    if (typeof reloadUptimeList === "function") { try { reloadUptimeList(); } catch (e) { } }
                }
            });
        });
    }

    function setSelected(name, on) { if (on) { state.sel[name] = true; } else { delete state.sel[name]; } }

    function toggleRange(name, on) {
        // shift-click: every rule between the previous click and this one, in the order shown
        var a = state.view.findIndex(function (r) { return r.RootOrMatchingDomain === state.lastClicked; });
        var b = state.view.findIndex(function (r) { return r.RootOrMatchingDomain === name; });
        if (a < 0 || b < 0) { setSelected(name, on); return; }
        var lo = Math.min(a, b), hi = Math.max(a, b);
        for (var i = lo; i <= hi; i++) { setSelected(state.view[i].RootOrMatchingDomain, on); }
    }

    function syncChecks() {
        $("#httpProxyList tr.ptRow").each(function () {
            var name = $(this).attr("data-ep"), on = !!state.sel[name];
            $(this).toggleClass("isSel is-selected", on).find(".bulkSel").prop("checked", on);
        });
        renderBulk();
    }

    function clearSelection() { state.sel = {}; state.lastClicked = null; syncChecks(); }

    function highlight(name) {
        var r = byName(name);
        if (!r) { return; }
        // make sure the row is not hidden by a filter, then find its page
        if (state.view.indexOf(r) < 0) { state.q = ""; state.tags = []; state.status = "all"; $("#searchInput").val(""); applyFilter(); }
        var idx = state.view.indexOf(r);
        if (idx < 0) { return; }
        state.page = Math.floor(idx / state.pageSize) + 1;
        render();
        state.flash = name;
        render();
        var row = $("#httpProxyList tr.ptRow").filter(function () { return $(this).attr("data-ep") === name; });
        if (row.length) { row[0].scrollIntoView({ block: "center", behavior: "smooth" }); }
        clearTimeout(highlight.t);
        highlight.t = setTimeout(function () { state.flash = ""; $("#httpProxyList tr.ptFlash").removeClass("ptFlash"); }, 3500);
    }

    /* ------------------------------------------------------------------ menus
       One popup for the row menu and for "Change" in the bulk bar. It is a child of <body> with position: fixed, so no
       table or card can clip it and it never adds a scroll area. Arrow keys move, Enter / Space activate, Esc and Tab close
       and the focus goes back to the button that opened it. */
    var menu = { el: null, btn: null };

    function closeMenu(focusBack) {
        if (!menu.el) { return; }
        menu.el.remove(); menu.el = null;
        if (menu.btn) { menu.btn.setAttribute("aria-expanded", "false"); if (focusBack && document.contains(menu.btn)) { menu.btn.focus(); } }
        menu.btn = null;
    }

    // items: [{label, icon, run, danger, href}] or "sep"; head: an optional first line (the host the menu belongs to)
    function openMenu(btn, items, head) {
        if (menu.btn === btn) { closeMenu(true); return; }
        closeMenu();
        var el = document.createElement("div");
        el.className = "zxs-menu"; el.setAttribute("role", "menu");
        var html = head ? '<div class="zxs-menu__head">' + esc(head) + '</div>' : "";
        items.forEach(function (it, i) {
            if (it === "sep") { html += '<div class="zxs-menu__sep" role="separator"></div>'; return; }
            var inner = '<i class="' + it.icon + ' icon" aria-hidden="true"></i><span>' + esc(it.label) + '</span>';
            html += it.href ? '<a class="zxs-menu__item" role="menuitem" tabindex="-1" data-i="' + i + '" href="' + esc(it.href) + '" target="_blank" rel="noopener">' + inner + '</a>'
                : '<button type="button" class="zxs-menu__item' + (it.danger ? " zxs-menu__item--danger" : "") + '" role="menuitem" tabindex="-1" data-i="' + i + '"' + (it.act ? ' data-act="' + it.act + '"' : "") + '>' + inner + '</button>';
        });
        el.innerHTML = html;
        document.body.appendChild(el);
        var r = btn.getBoundingClientRect(), w = el.offsetWidth, h = el.offsetHeight;
        var left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8));
        var top = r.bottom + 4;
        if (top + h > window.innerHeight - 8) { top = Math.max(8, r.top - h - 4); }
        el.style.left = left + "px"; el.style.top = top + "px";
        menu.el = el; menu.btn = btn;
        btn.setAttribute("aria-expanded", "true");
        var list = Array.prototype.slice.call(el.querySelectorAll(".zxs-menu__item"));
        if (list[0]) { list[0].focus(); }
        el.addEventListener("click", function (ev) {
            var t = ev.target.closest(".zxs-menu__item");
            if (!t) { return; }
            var it = items[parseInt(t.getAttribute("data-i"), 10)];
            closeMenu(!it.href);
            if (it.run) { it.run(); }
        });
        el.addEventListener("keydown", function (ev) {
            var i = list.indexOf(document.activeElement);
            if (ev.key === "ArrowDown") { ev.preventDefault(); list[(i + 1) % list.length].focus(); }
            else if (ev.key === "ArrowUp") { ev.preventDefault(); list[(i - 1 + list.length) % list.length].focus(); }
            else if (ev.key === "Home") { ev.preventDefault(); list[0].focus(); }
            else if (ev.key === "End") { ev.preventDefault(); list[list.length - 1].focus(); }
            else if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); closeMenu(true); }
            else if (ev.key === "Tab") { closeMenu(true); }
        });
    }

    function rowMenu(btn, name) {
        var r = byName(name);
        if (!r) { return; }
        var items = [
            { label: tr("Edit"), icon: "edit outline", run: function () { openEditor(name); } },
            { label: tr("Open in a new tab"), icon: "external alternate", href: hostLink(r, name) },
            { label: tr("Path routes"), icon: "folder outline", run: function () { if (typeof quickEditVdir === "function") { quickEditVdir(name); } } },
            { label: tr("Copy the host name"), icon: "copy outline", run: function () {
                var done = function () { toast(fmt("{0} copied", name)); };
                if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(name).then(done, function () { }); }
            } },
            "sep",
            { label: r.Disabled ? tr("Enable") : tr("Disable"), icon: r.Disabled ? "play" : "pause", run: function () { setEnabled(name, !!r.Disabled, true); } },
            { label: tr("Remove"), icon: "trash alternate outline", danger: true, act: "delete", run: function () { deleteRule(name); } }
        ];
        openMenu(btn, items, name);
    }

    function bulkMenu(btn) {
        function go(act) { return function () { if (window.ProxyBulk) { window.ProxyBulk.run(act, selNames()); } }; }
        openMenu(btn, [
            { label: tr("WAF"), icon: "shield alternate", act: "waf", run: go("waf") },
            { label: tr("Rate limit"), icon: "tachometer alternate", act: "rate", run: go("rate") },
            { label: tr("Login"), icon: "key", act: "auth", run: go("auth") },
            { label: tr("Access rule"), icon: "filter", act: "access", run: go("access") },
            { label: tr("Certificate"), icon: "lock", act: "cert", run: go("cert") },
            "sep",
            { label: tr("Apply a template"), icon: "clone outline", act: "template", run: go("template") }
        ], fmt("Change {0} hosts", selNames().length));
    }

    /* ------------------------------------------------------------------ events */
    function bind() {
        var $body = $("#httpProxyList");

        $body.on("click", ".bulkSel", function (ev) {
            var name = $(this).attr("data-ep"), on = this.checked;
            if (ev.shiftKey && state.lastClicked) { toggleRange(name, on); } else { setSelected(name, on); }
            state.lastClicked = name;
            syncChecks();
        });
        $body.on("click", "[data-act]", function (ev) {
            var act = $(this).attr("data-act"), name = $(this).closest("tr").attr("data-ep");
            if (act === "clearfilters") { clearFilters(); return; }
            if (act === "menu") { ev.stopPropagation(); rowMenu(this, name); return; }
            if (act === "toggle") { var r = byName(name); if (r) { setEnabled(name, !!r.Disabled, true); } }
            else if (act === "edit") { openEditor(name); }
            else if (act === "delete") { deleteRule(name); }
        });
        $body.on("click", ".ptTag, .ptChip", function (ev) { ev.preventDefault(); toggleTag($(this).attr("data-tag")); });
        $page().on("click", "#ptStats [data-f]", function () {
            var f = $(this).attr("data-f");
            state.status = (state.status === f) ? "all" : f; state.page = 1; render();
        });
        $body.on("click", ".ptVdir", function (ev) { ev.preventDefault(); quickEditVdir($(this).attr("data-ep")); });
        $body.on("click", ".ptMoreUp", function (ev) { ev.preventDefault(); openEditor($(this).attr("data-ep")); });

        $page().on("click", "#ptTagChips .ptChip", function () { toggleTag($(this).attr("data-tag")); });
        $page().on("change", "#ptMoreTags", function () { if (this.value) { toggleTag(this.value); } });
        $page().on("click", "#ptSeg button", function () { state.status = $(this).attr("data-f"); state.page = 1; render(); });
        $page().on("click", "#ptClear", clearFilters);
        $page().on("click", "#httpProxyTable thead [data-sort]", function (ev) {
            ev.stopPropagation();   // "Upstream" sits inside the Host header: one click, one sort
            var k = $(this).attr("data-sort");
            if (state.sort.key === k) { state.sort.dir = -state.sort.dir; } else { state.sort = { key: k, dir: 1 }; }
            persist(); render();
        });
        $page().on("keydown", "#httpProxyTable thead [data-sort]", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); ev.stopPropagation(); $(this).click(); } });
        $page().on("input search", "#searchInput", function () {
            state.q = this.value; state.page = 1;
            clearTimeout(bind.t); bind.t = setTimeout(render, 120);
        });
        $page().on("keydown", "#searchInput", function (ev) { if (ev.key === "Escape" && this.value) { this.value = ""; state.q = ""; render(); ev.stopPropagation(); } });
        $page().on("click", "#ptPrev", function () { state.page--; render(); window.scrollTo(0, 0); });
        $page().on("click", "#ptNext", function () { state.page++; render(); window.scrollTo(0, 0); });
        $page().on("change", "#ptPageSize", function () { state.pageSize = parseInt(this.value, 10) || 50; state.page = 1; persist(); render(); });
        $page().on("click", "#ptRefresh", function () { reload(); });

        $page().on("change", "#bulkSelectAll", function () {
            var on = this.checked, start = (state.page - 1) * state.pageSize;
            state.view.slice(start, start + state.pageSize).forEach(function (r) { setSelected(r.RootOrMatchingDomain, on); });
            syncChecks();
        });
        $page().on("click", "#bulkSelectMatching .bulkMoreBtn", function () {
            state.view.forEach(function (r) { state.sel[r.RootOrMatchingDomain] = true; });
            syncChecks();
            $("#bulkSelectAll").trigger("focus");   // the offer is gone now (the count says "All N selected"); the focus goes to the header box
        });
        // Up / Down move between the selection checkboxes of the rows (Space selects, Shift+Space a range), Home / End jump
        $body.on("keydown", ".bulkSel", function (ev) {
            if (ev.altKey || ev.ctrlKey || ev.metaKey) { return; }
            var boxes = $body.find(".bulkSel").get(), i = boxes.indexOf(this), j = -1;
            if (ev.key === "ArrowDown") { j = i + 1; } else if (ev.key === "ArrowUp") { j = i - 1; }
            else if (ev.key === "Home") { j = 0; } else if (ev.key === "End") { j = boxes.length - 1; } else { return; }
            ev.preventDefault();
            if (j < 0) { $("#bulkSelectAll").trigger("focus"); } else if (boxes[j]) { boxes[j].focus(); }
        });
        $page().on("keydown", "#bulkSelectAll", function (ev) {
            if (ev.key === "ArrowDown") { ev.preventDefault(); $body.find(".bulkSel").first().trigger("focus"); }
        });
        $page().on("click", "#bulkBar button", function () {
            var act = $(this).attr("data-act");
            if (act === "clear") { clearSelection(); return; }
            if (act === "more") { bulkMenu(this); return; }
            if (window.ProxyBulk) { window.ProxyBulk.run(act, selNames()); }
        });

        // the menu closes on a click elsewhere, when the page scrolls or the window changes size
        $(document).on("mousedown.ptMenu touchstart.ptMenu", function (ev) {
            if (menu.el && !menu.el.contains(ev.target) && !(menu.btn && menu.btn.contains(ev.target))) { closeMenu(); }
        });
        window.addEventListener("scroll", function () { closeMenu(); }, true);
        window.addEventListener("resize", function () { closeMenu(); });

        // Esc clears the selection (unless a dialog or the search box wants the key)
        $(document).on("keydown.ptSel", function (ev) {
            if (ev.key !== "Escape" || !selNames().length || menu.el) { return; }
            if (!$("#httprp").is(":visible")) { return; }
            if ($(".ui.modal.visible, .ui.modal.active").length || $("#httprpEditModalWrapper").is(":visible") || $("#newRuleModal.active").length) { return; }
            var t = ev.target;
            if (t && /^(input|textarea|select)$/i.test(t.tagName) && t.type !== "checkbox") { return; }
            clearSelection();
        });
        // "n" opens the new rule dialog when nothing else wants the key
        $(document).on("keydown.ptNew", function (ev) {
            if (ev.key !== "n" || ev.ctrlKey || ev.metaKey || ev.altKey || !$("#httprp").is(":visible")) { return; }
            var t = ev.target;
            if (t && (/^(input|textarea|select)$/i.test(t.tagName) || t.isContentEditable)) { return; }
            if ($(".ui.modal.visible, .ui.modal.active").length || $("#httprpEditModalWrapper").is(":visible")) { return; }
            ev.preventDefault();
            if (typeof openNewRuleDialog === "function") { openNewRuleDialog(); }
        });
    }

    function toggleTag(t) {
        var i = state.tags.indexOf(t);
        if (i > -1) { state.tags.splice(i, 1); } else { state.tags.push(t); }
        state.page = 1; render();
    }
    function clearFilters() {
        state.q = ""; state.tags = []; state.status = "all"; state.page = 1;
        $("#searchInput").val(""); render();
    }

    /* ------------------------------------------------------------------ compatibility API (called by snippets) */
    window.listProxyEndpoints = function (preserveFilters) { return reload(preserveFilters !== false ? true : false); };
    window.filterProxyList = function () { state.q = $("#searchInput").val() || ""; state.page = 1; render(); };
    window.editEndpoint = function (hex) { openEditor(hex.hexDecode()); };
    window.deleteEndpoint = function (hex) { deleteRule(decodeURIComponent(hex).hexDecode()); };
    window.renderTagsPreview = function (endpoint, tags) {
        var r = byName(endpoint);
        if (r) { r.Tags = tags || []; prepare(r); render(); }
    };
    window.updateAccessRuleNameUnderHost = function (epuuid, newruleUID) {
        var r = byName(epuuid);
        if (r) { r.AccessFilterUUID = newruleUID; }
        loadAccess(); loadWaf(); render();
    };
    window.updateAliasListForEndpoint = function (endpointName, aliases) {
        var r = byName(endpointName);
        if (r) { r.MatchingDomainAlias = aliases || []; prepare(r); render(); }
    };
    window.ProxyTable = { reload: reload, highlight: highlight, clearSelection: clearSelection, selected: selNames, state: state };

    $(function () {
        if (!document.getElementById("httpProxyList")) { return; }
        bind();
        liveStart();
    });
})();
