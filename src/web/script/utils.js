/*
    i18n bootstrap: every document that loads utils.js (index, snippets, tools) also gets the
    translation engine.  index.html includes script/i18n.js directly, in which case this is a no-op.
*/
(function () {
    if (window.i18n || !document.currentScript) return;
    document.write('<script src="' + document.currentScript.src.replace(/utils\.js(\?.*)?$/, "i18n.js") + '"><\/script>');
})();

/*
    Side view of the site editor: a snippet that is opened in the frame of ".editor_side_wrapper" (components/httprp.html)
    gets the shared side view layout (ui/sideview.css: one gutter, no second page title under the header row).
    Decided here, in <head>, so the page never paints once without it.
*/
(function () {
    try {
        var frame = window.frameElement;
        if (!frame || !frame.parentElement || !frame.parentElement.classList.contains("editor_side_wrapper") || !document.currentScript) return;
        document.documentElement.classList.add("zx-sideview");
        document.write('<link rel="stylesheet" href="' + document.currentScript.src.replace(/script\/utils\.js(\?.*)?$/, "ui/sideview.css") + '">');
    } catch (e) { /* cross origin parent: not the side view */ }
})();

/*
    Utils.js

    This script holds utilities function that is commonly use
    across components

*/

function abbreviateNumber(value) {
    var newValue = value;
    var suffixes = ["", "k", "m", "b", "t"];
    var suffixNum = 0;
    while (newValue >= 1000 && suffixNum < suffixes.length - 1) {
        newValue /= 1000;
        suffixNum++;
    }
    if (value > 1000){
        newValue = newValue.toFixed(2);
    }
    
    return newValue + suffixes[suffixNum];
}

Object.defineProperty(String.prototype, 'capitalize', {
    value: function() {
        return this.charAt(0).toUpperCase() + this.slice(1);
    },
    enumerable: false
});

//Add a new function to jquery for ajax override with csrf token injected
$.cjax = function(payload){
    let requireTokenMethod = ["POST", "PUT", "DELETE"];
    if (requireTokenMethod.includes(payload.method) || requireTokenMethod.includes(payload.type)){
        //csrf token is required
        let csrfToken = document.getElementsByTagName("meta")["zoraxy.csrf.Token"].getAttribute("content");
        payload.headers = {
            "X-CSRF-Token": csrfToken,
        }
    }

    return $.ajax(payload);
}
;

/*
    Side drawer: Escape inside a snippet iframe closes the drawer of the admin page (index.html), unless an open dropdown or
    dialog inside the snippet has just used the key.
*/
(function () {
    if (window.parent === window || typeof window.parent.hideSideWrapper !== "function") return;
    document.addEventListener("keydown", function (e) {
        if (e.key !== "Escape" || e.defaultPrevented) return;
        if (document.querySelector(".ui.dropdown.active.visible, .ui.modal.visible.active, .ui.dimmer.visible.active")) return;
        try { window.parent.hideSideWrapper(); } catch (err) { }
    });
})();
