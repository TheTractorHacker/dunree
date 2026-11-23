/*
    Zoraxy admin UI - small delegated page helpers (consistency pass)

    [data-zx-history="Object"]   a History shortcut button: opens System > History filtered to that object (read only).
    [data-nav-open="tag"]        handled by nav.js (links of the Related boxes).
    [data-zx-toggle="id"]        collapsible card: the button toggles the element with that id (aria-expanded kept in step).
    iframe[data-zx-fit]          the frame grows to the height of its document (ZxUI.fitFrame): no scroller inside the page.
*/
(function () {
    "use strict";
    /*
        "See also" menu (.zx-related, CSS in ui/zxui.css).  The static markup is a list of links with a reason each:
            <aside class="zx-related"><span class="zx-related__title">Related</span><ul><li><a data-nav-open="tag">Page</a> <span>why</span></li></ul></aside>
        On a page with a kit header it becomes ONE "Related" button in the header actions that opens the list as a menu
        (icon from the menu definition, page name, the reason). Tab / Shift+Tab and the arrow keys move, Esc closes and
        returns the focus, a click outside closes. Without a kit header the list stays in place as a row of chips.
    */
    function closeRelated(except, focus) {
        document.querySelectorAll(".zx-related.is-open").forEach(function (box) {
            if (box === except) { return; }
            box.classList.remove("is-open", "is-left");
            var b = box.querySelector(".zx-related__btn");
            if (b) { b.setAttribute("aria-expanded", "false"); if (focus) { b.focus(); } }
        });
    }
    function enhanceRelated() {
        document.querySelectorAll(".zx-related:not([data-zx-enhanced])").forEach(function (box) {
            var list = box.querySelector("ul");
            if (!list) { return; }
            box.setAttribute("data-zx-enhanced", "1");
            list.querySelectorAll("li").forEach(function (li) {
                var a = li.querySelector("a"), sp = li.querySelector(":scope > span");
                if (!a) { return; }
                var why = sp ? sp.textContent.replace(/\s+/g, " ").trim() : "";
                var page = window.ZxNav && window.ZxNav.find ? window.ZxNav.find(a.getAttribute("data-nav-open") || "") : null;
                var name = document.createElement("span");
                name.className = "zx-related__name";
                while (a.firstChild) { name.appendChild(a.firstChild); }
                var ic = document.createElement("span");
                ic.className = "zx-related__icon";
                ic.setAttribute("aria-hidden", "true");
                var i = document.createElement("i");
                i.className = ((page && page.item && page.item.icon) || "arrow right") + " icon";
                ic.appendChild(i);
                a.appendChild(ic);
                a.appendChild(name);
                if (sp && why) {   // the reason is part of the link (one target per row); ": " keeps name and reason apart for a screen reader
                    var sep = document.createElement("span");
                    sep.className = "zx-sr-only";
                    sep.textContent = ": ";
                    a.appendChild(sep);
                    sp.className = "zx-related__desc"; a.appendChild(sp);
                }
            });
            var scope = box.closest(".standardContainer, [data-zx-page]") || box.closest(".functiontab");
            var header = scope && scope.querySelector(".zx-page-header");
            if (!header) {   // chips: the reason is the tooltip
                box.classList.add("is-chips");
                list.querySelectorAll("a").forEach(function (a) { var d = a.querySelector(".zx-related__desc"); if (d && !a.title) { a.title = d.textContent.replace(/\s+/g, " ").trim(); } });
                return;
            }
            var actions = header.querySelector(".zx-page-header__actions");
            if (!actions) { actions = document.createElement("div"); actions.className = "zx-page-header__actions"; header.appendChild(actions); }
            var title = box.querySelector(".zx-related__title");
            var btn = document.createElement("button");
            btn.type = "button";
            btn.className = "zx-btn zx-btn--secondary zx-related__btn";
            btn.setAttribute("aria-expanded", "false");
            if (!list.id) { list.id = "zxRelated" + (++relatedSeq); }
            btn.setAttribute("aria-controls", list.id);
            var bi = document.createElement("i");
            bi.className = "compass outline icon";
            bi.setAttribute("aria-hidden", "true");
            btn.appendChild(bi);
            if (title) { btn.appendChild(title); } else { btn.setAttribute("aria-label", box.getAttribute("aria-label") || (typeof window.t === "function" ? window.t("Related") : "Related")); }
            box.insertBefore(btn, list);
            box.classList.add("is-menu");
            actions.insertBefore(box, actions.firstChild);
        });
    }
    var relatedSeq = 0;
    /* <iframe data-zx-fit> : an embedded editor page grows to its content (ZxUI.fitFrame), no scroller inside the page */
    function enhanceFrames() {
        if (!window.ZxUI || !window.ZxUI.fitFrame) { return; }
        document.querySelectorAll("iframe[data-zx-fit]:not([data-fit])").forEach(function (f) { window.ZxUI.fitFrame(f, { escape: f.getAttribute("data-zx-fit") === "escape" }); });
    }
    document.addEventListener("click", function (e) {
        var btn = e.target.closest && e.target.closest(".zx-related__btn");
        if (!btn) {
            // a click on a link navigates (nav.js) and closes; a click elsewhere closes
            if (document.querySelector(".zx-related.is-open") && !(e.target.closest && e.target.closest(".zx-related.is-open ul") && !e.target.closest("a"))) { closeRelated(); }
            return;
        }
        var box = btn.closest(".zx-related"), open = !box.classList.contains("is-open");
        closeRelated(box);
        box.classList.toggle("is-open", open);
        box.classList.remove("is-left");
        btn.setAttribute("aria-expanded", open ? "true" : "false");
        if (open) {
            var list = box.querySelector("ul"), r = list.getBoundingClientRect();
            if (r.left < 8) { box.classList.add("is-left"); }   // the button sits at the left edge (phones): open towards the right
        }
    });
    document.addEventListener("keydown", function (e) {
        var box = e.target.closest && e.target.closest(".zx-related.is-menu");
        if (!box) { return; }
        if (e.key === "Escape" && box.classList.contains("is-open")) { e.preventDefault(); e.stopPropagation(); closeRelated(null, true); return; }
        var links = Array.prototype.slice.call(box.querySelectorAll("ul a"));
        var i = links.indexOf(document.activeElement);
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            if (!box.classList.contains("is-open")) { box.querySelector(".zx-related__btn").click(); }
            var n = links.length;
            var next = i < 0 ? (e.key === "ArrowDown" ? 0 : n - 1) : (i + (e.key === "ArrowDown" ? 1 : n - 1)) % n;
            if (links[next]) { links[next].focus(); }
        } else if (e.key === "Home" && i >= 0) { e.preventDefault(); links[0].focus(); }
        else if (e.key === "End" && i >= 0) { e.preventDefault(); links[links.length - 1].focus(); }
    }, true);
    document.addEventListener("focusin", function (e) {
        var open = document.querySelector(".zx-related.is-open");
        if (open && !open.contains(e.target)) { closeRelated(); }
    });
    window.addEventListener("hashchange", function () { closeRelated(); });
    if (window.MutationObserver) {
        var tipTimer = null;
        new MutationObserver(function () { clearTimeout(tipTimer); tipTimer = setTimeout(function () { enhanceRelated(); enhanceFrames(); }, 60); }).observe(document.body, { childList: true, subtree: true });
    }
    enhanceRelated();
    enhanceFrames();

    document.addEventListener("click", function (e) {
        var h = e.target.closest && e.target.closest("[data-zx-history]");
        if (h) {
            e.preventDefault();
            if (window.ZxHistory) { window.ZxHistory.view(h.getAttribute("data-zx-history")); }
            return;
        }
        var t = e.target.closest && e.target.closest("[data-zx-toggle]");
        if (t) {
            var box = document.getElementById(t.getAttribute("data-zx-toggle"));
            if (!box) { return; }
            var open = t.getAttribute("aria-expanded") !== "true";
            t.setAttribute("aria-expanded", open ? "true" : "false");
            box.hidden = !open;
        }
    });
})();
