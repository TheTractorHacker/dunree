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

    Keys of the earlier product name: the admin UI used to store its choices under "zoraxy_..." and "zoraxy....". // rebrand:keep
    It now uses "dunree_..." and "dunree....". The first time this file runs in a browser it copies every old key to
    its new name (unless the new one already exists) and records that in "dunree.storage.migrated", so the copy
    happens once per browser (once per tab for sessionStorage). The old keys are left in place: a browser that goes
    back to the older build finds its choices as they were at the upgrade. Pages only use the new names.
    zxStore.migrated tells what the copy did on this page load: {local: n, session: n}, n = keys copied, -1 = already
    done earlier, null = storage not readable.
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

    var NEW_PREFIX = "dunree", OLD_PREFIX = "zoraxy", MIGRATED_KEY = "dunree.storage.migrated"; // rebrand:keep

    // "zoraxy_menu_groups" -> "dunree_menu_groups", "zoraxy.lang" -> "dunree.lang"; null for any other key // rebrand:keep
    function renamedKey(key) {
        var sep = key.charAt(OLD_PREFIX.length);
        if (key.length > OLD_PREFIX.length + 1 && key.lastIndexOf(OLD_PREFIX, 0) === 0 && (sep === "_" || sep === ".")) {
            return NEW_PREFIX + key.substring(OLD_PREFIX.length);
        }
        return null;
    }

    // One-time copy of the keys of the earlier product name. Never throws, never overwrites, never deletes.
    function migrate(kind) {
        var s, keys = [], i, n = 0, complete = true;
        try {
            s = w[kind + "Storage"];
            if (s.getItem(MIGRATED_KEY) !== null) { return -1; }
            for (i = 0; i < s.length; i++) { keys.push(s.key(i)); }
        } catch (e) { return null; }
        keys.forEach(function (oldKey) {
            var newKey = oldKey === null ? null : renamedKey(String(oldKey)), v;
            if (!newKey) { return; }
            try {
                if (s.getItem(newKey) !== null) { return; } // a value stored under the new name wins
                v = s.getItem(oldKey);
                if (v === null) { return; }
            } catch (e) { complete = false; return; }
            try { s.setItem(newKey, v); n++; }
            catch (e) { mem[kind][newKey] = v; complete = false; } // full quota: this page still sees the value
        });
        if (complete) { try { s.setItem(MIGRATED_KEY, "1"); } catch (e) { /* tried again on the next load */ } }
        return n;
    }

    var store = area("local");
    store.session = area("session");
    store._mem = mem;
    store.migrated = { local: migrate("local"), session: migrate("session") };
    w.zxStore = store;
})(window);
