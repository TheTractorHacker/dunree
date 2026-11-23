/*
    Safe storage

    localStorage / sessionStorage can throw on every call: strict privacy modes, "block all cookies and site data",
    a sandboxed frame, a full quota. An unguarded call then stops the script that makes it, and the admin UI used to
    break before a page opened. Every script of the admin UI goes through this helper instead:

        zxStore.get(key)          string or null, never throws
        zxStore.set(key, value)   never throws; when the browser refuses, the value is kept in memory
        zxStore.remove(key)       never throws
        zxStore.session.get / set / remove   the same for sessionStorage

    Values kept in memory last until the page is reloaded. A side-panel or tool frame shares the memory of the admin
    page that opened it, so a choice made there (the theme, for one) also holds in the frames while storage is blocked.

    Load it before any script that stores something: first script of the page (see index.html).
*/
(function (w) {
    "use strict";
    if (w.zxStore) { return; }

    var mem = null;
    try {
        // same-origin parent with the helper: share its memory (throws for a cross-origin parent)
        if (w.parent && w.parent !== w && w.parent.zxStore && w.parent.zxStore._mem) { mem = w.parent.zxStore._mem; }
    } catch (e) { mem = null; }
    if (!mem) { mem = { local: {}, session: {} }; }

    function has(bag, k) { return Object.prototype.hasOwnProperty.call(bag, k); }

    function area(kind) {
        var bag = mem[kind];
        function real() { return w[kind + "Storage"]; } // the property itself may throw: always called inside try
        return {
            get: function (key) {
                key = String(key);
                if (has(bag, key)) { return bag[key]; } // only set while the browser refuses writes
                try { return real().getItem(key); } catch (e) { return null; }
            },
            set: function (key, value) {
                key = String(key); value = String(value);
                try { real().setItem(key, value); delete bag[key]; return true; }
                catch (e) { bag[key] = value; return false; }
            },
            remove: function (key) {
                key = String(key);
                delete bag[key];
                try { real().removeItem(key); } catch (e) { /* storage blocked */ }
            }
        };
    }

    var store = area("local");
    store.session = area("session");
    store._mem = mem;
    w.zxStore = store;
})(window);
