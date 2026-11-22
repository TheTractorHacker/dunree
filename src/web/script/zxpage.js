/*
    Zoraxy admin UI - small delegated page helpers (consistency pass)

    [data-zx-history="Object"]   a History shortcut button: opens System > History filtered to that object (read only).
    [data-nav-open="tag"]        handled by nav.js (links of the Related boxes).
    [data-zx-toggle="id"]        collapsible card: the button toggles the element with that id (aria-expanded kept in step).
*/
(function () {
    "use strict";
    /* "Related" row: the one-line explanation of each link becomes its tooltip (the row itself shows only the link names) */
    function tipRelated() {
        document.querySelectorAll(".zx-related li").forEach(function (li) {
            var a = li.querySelector("a"), sp = li.querySelector("span");
            if (a && sp && !a.title) { a.title = sp.textContent.replace(/\s+/g, " ").trim(); }
        });
    }
    if (window.MutationObserver) {
        var tipTimer = null;
        new MutationObserver(function () { clearTimeout(tipTimer); tipTimer = setTimeout(tipRelated, 150); }).observe(document.body, { childList: true, subtree: true });
    }
    tipRelated();

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
