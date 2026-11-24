# Admin UI component kit and navigation

Phase 0 (component kit) and Phase 1 (navigation) of the redesign in [audit-2026-11.md](audit-2026-11.md).
The kit is plain CSS plus one small helper (`ZxUI`) on top of jQuery and Fomantic UI (decision D1: no framework, no build step).

| Part | File |
|---|---|
| Tokens and component CSS | `src/web/ui/zxui.css` |
| Helper library `window.ZxUI` (toast, confirm, save bar, dirty tracker, tabs, ...) | `src/web/script/zxui.js` |
| Menu definition (`NAV`), breadcrumbs, `window.ZxNav` | `src/web/script/nav.js` |
| Command palette `window.ZxPalette` (settings index, actions) | `src/web/script/palette.js` |
| Menu, breadcrumb and palette CSS | `src/web/ui/nav.css` |
| Living documentation: every component in light and dark with copyable markup | `src/web/ui/kit.html` (+ `kit.js`) |

**Living page.** Start Dunree with `-dev` and open `/ui/kit.html` (System > UI kit in the menu). Without `-dev` the page is not served (404) and the menu entry is hidden. The page also shows the live contrast ratios of the tokens.

**Used by:** the proxy rule editor ([site-editor.md](site-editor.md): five sections, Easy / Advanced, one Save bar, app presets).

Everything is namespaced `zx-` and additive: it never styles a bare element or a Fomantic `.ui` class, and the legacy CSS variables of `darktheme.css` (`--theme_bg`, `--text_color`, ...) keep working. Pages migrate one at a time.

## 1. Design tokens

Defined in `zxui.css`; light on `:root`, dark on `body.darkTheme` (the class the theme toggle sets). `.zx-scheme-light` / `.zx-scheme-dark` force a scheme for a subtree (the kit page uses them to show both side by side). Always use the token, never a hex value.

| Group | Tokens |
|---|---|
| Surfaces | `--zx-bg` (page), `--zx-surface` (cards, inputs), `--zx-surface-2` (sunken, table head, hover), `--zx-surface-3` (pressed, tracks), `--zx-overlay` |
| Lines | `--zx-border` (decorative), `--zx-border-strong` (control borders, 3:1) |
| Text | `--zx-text`, `--zx-text-muted`, `--zx-text-faint` (placeholders only, never below 12px), `--zx-link` |
| Primary | `--zx-primary`, `--zx-primary-hover`, `--zx-on-primary`, `--zx-primary-soft`, `--zx-primary-soft-text` |
| Semantic | `--zx-{ok,warn,danger,info}-{solid,bg,text,line}`; `--zx-neutral-{bg,text,line}`; `--zx-on-solid` |
| Focus | `--zx-focus`, `--zx-focus-ring` (two-tone box-shadow) |
| Shadow | `--zx-shadow-1` cards, `-2` popovers and toasts, `-3` dialogs and the save bar |
| Radius | `--zx-radius-sm` 4, `-md` 8, `-lg` 12, `-pill` |
| Spacing | `--zx-space-1..7` = 4, 8, 12, 16, 24, 32, 48 px |
| Type | `--zx-fs-xs..2xl` = 12, 13, 14 (body), 16, 20, 26 px; `--zx-font-mono` |
| Sizes | `--zx-control-h` 36px, `--zx-touch` 44px |

`*-solid` is a filled background (button, switch) with `--zx-on-solid` text; `*-bg` is a tinted area with `*-text` on it; `*-line` its border.

## 2. Components

Markup of every component is on the kit page (copy button). Summary and the rules that are not visible in the markup:

| Component | Class / API | Notes |
|---|---|---|
| Page header | `.zx-page-header` (`__main`, `__crumbs`, `__title`, `__sub`, `__actions`) | One per page, the only `h2`. An element with `data-zx-crumbs` gets the breadcrumbs from the menu definition |
| Section card | `.zx-card` (`__head`, `__title`, `__desc`, `__body`, `__foot`), `--flat`, `--danger` | Group by purpose, title says what the section is for |
| Form row | `.zx-field` (`__label-row`, `__label`, `__control`), `.zx-help`, `.zx-error`, `.zx-whatis` + `.zx-popover` | Real `<label for>`. Errors: `ZxUI.field(el).setError(text)` (sets `aria-invalid`, `aria-describedby`) |
| Field with actions | `.zx-field-actions` > `.zx-input` + `.zx-btn`s | One input and the buttons that act on it alone (rename, add an entry): one line, same height, 8px apart, never glued to the input (no Fomantic `.ui.action.input`). Buttons stay disabled until the value differs; Enter saves, Esc discards. Phones: input on its own row. Exemplar: site editor > Hostname |
| Input with a unit | `.zx-inputgroup` > `.zx-input` + `.zx-inputgroup__unit` | A unit ("MiB", "sec") joined to a number input. Only for units, never for buttons. The field keeps a visible `<label for>` above it (the unit and the help are `aria-describedby`) |
| Side view of the site editor | `ui/sideview.css`, switched on by `script/utils.js` (class `zx-sideview` on `<html>` when the page is the frame of `.editor_side_wrapper`) | The header row of the editor (Back button, name of the view, host) is the only title: the snippet marks its own page title with `zx-sideview-title` and it is not shown there. One gutter for every view (`--zx-space-4`, the left edge of the Back button), content left aligned, no centred Fomantic container. Opening moves the focus to Back and makes the editor behind it `inert`; Back / Esc return the focus to the button that opened the view. A new snippet for the side view needs `utils.js` in `<head>` and an entry in `SIDE_VIEW_TITLES` (`components/httprp.html`) |
| Toggle row | `.zx-toggle-row` + `input.zx-switch[role=switch]` | Description says what happens when it is on |
| Checkbox | `input.zx-check` (alone, with `aria-label`) or `label.zx-check > input` (visible label) | 18px box, 5px radius, drawn tick, dash for `indeterminate` (a property: `box.indeterminate = true`), hover halo, focus ring, 32px target (44px on touch) without a larger box, disabled, forced colours. For choosing rows and for options of a form; a setting that takes effect is a `.zx-switch`. A raw checkbox of a page (not Fomantic `.ui.checkbox`) is drawn the same way without the class. See 9.4 |
| Buttons | `.zx-btn` + `--primary --secondary --danger --danger-outline --ghost --icon --sm --block`, `.is-loading` | `ZxUI.setLoading(btn, true)`. Icon buttons need `aria-label`. One primary per view |
| Badge | `.zx-badge` + `--ok --warn --danger --info`, `--dot` | Text always present, colour is never the only signal |
| Callout | `.zx-callout` + `--info --warn --danger --success` | `role="note"`; `role="alert"` only for messages that appear after an action |
| Empty state | `.zx-empty` (`__icon`, `__title`, `__text`) | Always offers the next action |
| Data table | `.zx-table-wrap > table.zx-table`, `--compact --comfortable`, `.zx-num`, `.zx-actions`, `.zx-row-actions`, `.zx-selcol`, row states `tr.is-selected`, `tr.is-disabled` (9.4) | No scroll area of its own since design v2 (the page scrolls; `.zx-table-wrap--scroll` only inside a drawer or dialog); give the wrapper `tabindex="0" role="region" aria-label`; `data-label` on every `td` for the 480px card layout |
| Tabs | `.zx-tabs > .zx-tab[data-zx-panel]`, `ZxUI.tabs(el, {onChange})` | Arrow keys, Home/End, roving tabindex. Two to six flat choices; more, or grouped: sectioned navigation (section 9) |
| Segmented control | `.zx-segmented > .zx-segmented__item[data-value]`, `ZxUI.segmented(el, {onChange})` | `role=radiogroup` |
| Stat tile | `.zx-stat` (`__label`, `__value`, `__hint`), `--ok --warn --danger` | |
| Save bar | `ZxUI.saveBar({form, onSave, onDiscard, mount, ignore, saveLabel, discardLabel, successText})` | See 2.1 |
| Toast | `ZxUI.toast(message, {type, undo, undoLabel, duration})` | See 2.2 |
| Confirm | `ZxUI.confirm({title, message, confirmLabel, cancelLabel, danger, typed})` -> `Promise<boolean>` | See 2.3 |
| Skeleton | `.zx-skeleton` (`--text --title --block --circle`), `ZxUI.skeleton(container, {lines, title, block})` | Returns a function that removes it; sets `aria-busy` |
| Breadcrumbs | `.zx-crumbs` | Filled by `nav.js` |

### 2.1 Save bar and dirty tracker

```js
var bar = ZxUI.saveBar({
    form: "#myForm",                       // container whose inputs are tracked
    ignore: ".ui.checkbox",                // optional: controls that save themselves
    onSave: function (ctx) {               // ctx.changes = [{key, label, from, to}]
        return $.cjax({url: "/api/...", method: "POST", data: {...}});   // a promise / jqXHR
    }
});
// after the page filled its fields from the API: bar.reset();   (re-baseline)
// partial saves:  ctx.tracker.commit(["fieldId"]);
```

* The bar (sticky at the bottom of the page) appears when a tracked control differs from its baseline and shows how many changes and which fields. Changing a value back hides it.
* Save is disabled while saving; success shows "Saved" briefly; failure keeps the bar, shows the reason and leaves the form dirty. Failure = rejected promise, thrown error, `false`, or a result object with `error` (Dunree APIs answer `{error: "..."}` with HTTP 200). `$.cjax` returns the jqXHR for this.
* Discard puts the fields back to the baseline. Ctrl/Cmd+S in the form saves.
* **Programmatic changes never make the form dirty**: only trusted (real) events count, plus untrusted events fired by page code within 600 ms of a pointer or keyboard action in the form (Fomantic dropdowns and checkboxes fire their change events from script). Code that fills the form must call `bar.reset()` (or `ctx.tracker.commit`) afterwards.
* Control keys: `name`, else `id`, else the id of the nearest ancestor with an id plus an index. Labels: `data-zx-label`, `label[for]`, wrapping label, `aria-label`, placeholder. Put `data-zx-ignore` on controls that are not form state.
* Integration with the unsaved-changes guard: every bar registers in `ZxUI.unsaved` (the proxy rule editor guard of `uxkit.js` too). While a bar is dirty, `beforeunload` asks, and opening another page (menu, palette, `openTabById`) shows "Leave without saving?" and discards on confirm.

Rule (decision D2): security and certificate pages use explicit Save; instant save is for toggles that are inherently live, and must say so (toast). New pages should not mix both in one card.

### 2.2 Toast with Undo

`ZxUI.toast("Rule deleted", {undo: function () { /* restore */ }})`. The caller wires the undo (the change-history work will provide real undo); the toast only offers the button (10 s) and runs the function once. Errors use `role="alert"` and stay 8 s; the message is inserted as text.

### 2.3 Confirm

```js
ZxUI.confirm({title: "Delete rule?", message: "app.example.com stops working.", danger: true,
              confirmLabel: "Delete rule", typed: "app.example.com"}).then(function (ok) { ... });
```
Danger puts the initial focus on Cancel. `typed` keeps the confirm button disabled until that exact text is typed; use it for irreversible actions on one named object. Escape cancels, Tab is trapped, focus returns to the opener.

### 2.4 Drawer

`ZxUI.drawer({title, label, onClose, returnFocus})` returns `{el, body, foot, setTitle, close, isOpen}`. A modal panel from the right edge, a bottom sheet at 600px and narrower (max 88% of the height, safe-area aware). Esc, the close button and a click on the dimmed area close it; Tab is trapped; focus returns to `returnFocus` (default: the element that was focused). One drawer at a time. Layer `--zx-z-drawer` (1100), below dialogs, toasts (an Undo toast stays visible above it) and the palette. Fill `body` and `foot` yourself; `foot` hides while empty. First user: "Why was this blocked?" on Statistics > Blocked (docs/ux/why-blocked.md).

## 3. Navigation

### 3.1 Menu definition

The menu is the `NAV` array at the top of `src/web/script/nav.js`, rendered into `#navTree` of `index.html`. Breadcrumbs and the command palette read the same array.

**Adding a page to the menu = one line**, in the `items` of the group it belongs to:

```js
{tag: "mypage", label: N_("My page"), icon: "star", kw: "words people may type"},
```
plus the page container in `index.html`: `<div id="mypage" class="functiontab" target="mypage.html"></div>` and the component `components/mypage.html`. Fields: `tag` (container id and URL hash, never rename an existing one), `label` (wrapped in `N_()` so `tools/i18n/extract.py` finds it; translated by the DOM translator), `icon` (Fomantic icon name), `kw` (extra palette search words), optional `id`, `hidden`, `dev` (only with `-dev`), `href` (opens a link in a new tab instead of a page). A group has `id` (suffix of `#group-ID`, key of the saved open/closed state), `label`, `icon`, `items`, optional `home` (tag the group breadcrumb links to, e.g. a future "Security overview").

Groups (8): **Overview** (Status, Quick Start), **Sites** (HTTP Proxy, Default Site, Redirection, Path routes, Stream Proxy, Static Web Server, Raw rule form), **Security** (Security Center, WAF, Access Rules, SSO / OAuth2, CAPTCHA), **Certificates** (TLS / SSL, ACME), **Traffic** (Statistics, Visitors, Uptime Monitor), **Network** (Listeners, Trusted Proxies, Tunnels, Encrypted Client Hello, Network Interfaces, Network Tools), **Fleet & HA** (Fleet, Cluster / HA), **System** (Update, API Tokens, Plugin Manager, App Store, Utilities, Settings, UI kit in `-dev`).

Compatibility: all `tag` ids, `#hash` deep links and `openTabById()` calls are unchanged; only the placement changed. Renamed labels (D4): Ingress -> Listeners, Virtual Directories -> Path routes, Advanced Rule Form -> Raw rule form (labels only, ids and API paths untouched). Saved menu state (`localStorage.dunree_menu_groups`) is migrated to version 3. Groups start collapsed except Overview on a first visit; opening a page expands its group and no longer collapses the others.

Behaviour: groups are `role=button` headers with `aria-expanded`/`aria-controls`; Up/Down/Home/End move through the menu, Left/Right collapse/expand a group (Left on an item jumps to its header), Enter/Space activate; the active page has `aria-current="page"`. On phones the menu is the existing slide-in panel behind the hamburger button, rows are 44px high.

### 3.2 Breadcrumbs

"Group > Page", shown above the page content of every page, from `NAV` (`ZxNav.crumbsFor(tag)`). A page that renders its own header puts `data-zx-crumbs` in `.zx-page-header__crumbs` and the strip above the page hides.

### 3.3 Command palette

Ctrl+K / Cmd+K, or the Search button in the header (the `/` menu filter still works). Searches pages (labels and `kw` synonyms: "firewall" finds WAF, "ssl" finds Certificates, "ban" finds Access Rules and Auto-ban), proxy hosts (`GET /api/proxy/list`, cached, refreshed every time the palette opens), a static index of settings (`SETTINGS` in `palette.js`, page + CSS anchor; the page opens, the tab or accordion is opened, the field scrolls into view and flashes) and actions (`ACTIONS`: New proxy rule, Enable WAF (opens the WAF page, changes nothing by itself), Check for updates, Toggle dark mode, Change language, Set up auto-ban). Fuzzy, grouped, keyboard only (type, Up/Down, Enter, Esc), recent items kept in `localStorage`. Nothing leaves the browser; every inserted string is set with `textContent` (host and rule names are user data).

To add a setting: one line in `SETTINGS`, `{label: N_("..."), page: "tag", pre: "selector to click first (tab/accordion)", at: "#anchor", kw: "synonyms"}`. `tools/ui-smoke/smoke.py` checks that every entry resolves.

### 3.4 Top bar

`<div class="menubar zx-topbar">` in `index.html`, logic in `script/topbar.js` (`window.ZxTopbar`), styles in `ui/topbar.css`. Left to right: the Dunree logo (links to Status; markup and rules in section 11), **status pills**, then the controls: **Search** (Ctrl+K, primary-coloured border so it stays the most prominent), **Theme**, **Language**, **Account** (only with authentication), and on phones **More** and the hamburger of the page menu. Every control is a `.zx-topbtn`: 36px high (40px at 748px and below), 8px radius, `--zx-border-strong` border, `--zx-focus` 2px focus ring. Colours only from `--zx-*` tokens; the bar is `--zx-surface` in both themes.

* **Theme menu**: Light / Dark / System (the button shows the current mode as icon + word). System = no stored choice, the OS preference decides and follows changes. Light and Dark store `localStorage.theme` as before, `toggleTheme()` (palette action "Toggle dark mode") still works and `darktheme.js` fires `zoraxy:theme` so the button follows.
* **Language menu**: globe + current code (`EN`, `DE`, `ZH-CN` ...), all languages of `i18n.languages` by their native names, the current one checked. Scrolls inside the menu when the list is long. The native `select.i18n-picker` stays on the Settings page.
* **Account menu** (hidden when `GET /api/auth/authEnabled` is false): user name and role (`/api/auth/username`, `/api/auth/role`), Change password (opens Utilities), Log out.
* **Status pills** (one light poll, `ZxTopbar.refresh()` forces it): health ("Online", or a danger "Proxy stopped"; the tooltip names the listening port), "N sites down" (Uptime Monitor, only when something is down), "N certificates expiring" (Certificates, only within the 30 day warning window of the Status page, danger at 7 days or less), "Update vX" (Update page), "N blocked today - See why" (opens Statistics > Blocked). Each pill is a real `<a href="#page">` with a tooltip and `aria-label`; when no data can be read one neutral "Status unavailable" pill is shown (never a spinner).
  * Data reused, nothing new on the server: `GET /api/stats/glance` (blocked today, upstreams down, certificates; what the Status tiles use) and `GET /api/proxy/status` (Running, port; what the Status banner uses), both every 45 s, only while the tab is visible (plus one refresh when it becomes visible after 30 s or more).
  * **The update badge makes no request of its own.** Dunree never contacts GitHub by itself (the Update page says "Not checked yet"), so the badge shows the result of the last check made on the Update page in this browser (`ZxTopbar.setUpdate(result)`, `localStorage.dunree.topbar.update`, kept 14 days, dropped when the running version changes).
* **Widths**: above 1180px full text; 749-1180px pills shrink to icon + number, Search to an icon, theme / language / account to icon (the full text stays in `aria-label` and tooltip); 748px and below: pills, theme, language and account fold into one **More** menu (a dot marks it when something needs attention) next to Search and the hamburger. Pills that do not fit are clipped in priority order (health first, blocked counter last), never wrapped over the content.
* **Keyboard**: Tab order is logo, pills, Search, Theme, Language, Account (phone: Search, More, hamburger). Enter / Space / ArrowDown open a menu with focus on the current choice; Up/Down/Home/End move; Enter chooses and returns focus to the button; Esc closes and returns focus; Tab and an outside click close. Menus are `role=menu` with `menuitemradio` (`aria-checked`) / `menuitem`; buttons carry `aria-haspopup="menu"` and `aria-expanded`.
* Adding a pill = one entry in `pills()` of `topbar.js` (state `ok|warn|danger|info|neutral`, icon, `tag` of an existing page). Do not add a pill that has no page to open.

## 4. Do and don't

* Do build new pages from the kit classes and tokens; do not add page-local colours, shadows or radii.
* Do use one save model per page (section 2.1). Do not put an "Apply" button next to each field.
* Do write labels and help in plain language; explain jargon once with the "what is this?" popover.
* Do give every empty list an empty state with the next action.
* Do not convey state by colour alone; do not use `--zx-text-faint` for anything but placeholders.
* Do not change a default behaviour as a side effect of a UI change (D3).
* Do not use `innerHTML` with user data; use `ZxUI.esc()` or `textContent`.
* Do not rename `tag` ids, group ids or API paths when relabelling (D4).

## 5. Accessibility rules (checked in review)

* **Keyboard.** Everything reachable and operable with the keyboard; order follows reading order; no keyboard traps except modal dialogs (confirm, palette), which trap Tab, close on Escape and return focus to the opener.
* **Focus.** A visible focus indicator on every interactive element (`--zx-focus-ring`, 3:1 against its surroundings); never `outline: none` without a replacement.
* **Names and roles.** Controls have a name (`<label for>`, text, or `aria-label` for icon buttons); toggles `role=switch`; tabs `role=tab` with `aria-selected`; disclosure headers `aria-expanded`; status changes announce through `role=status` / `aria-live=polite`, errors `role=alert`; invalid fields `aria-invalid` + `aria-describedby`.
* **Contrast.** Text at least 4.5:1 and non-text UI (control borders, focus ring) at least 3:1 in both schemes; the kit page computes the ratios of the tokens live and marks failures.
* **Touch.** At 748px and below, or on coarse pointers, controls are at least 44px (36px for small buttons in dense tables).
* **Motion.** Animations respect `prefers-reduced-motion`; forced-colors mode keeps borders and focus.
* **Responsive.** Test at 390px: no horizontal page scroll; tables collapse to cards below 480px.
* **Language.** Visible English text must be extractable (`python3 tools/i18n/extract.py`); use `N_("...")` for strings that are only in JavaScript data.

## 6. What was verified, and what was not

Verified by the browser smoke test (`tools/ui-smoke`): the top bar (`--topnav-only` via `topnav_run.sh`: sizes, overflow, collisions, contrast, pills, menus, keyboard, phone More menu, Log out), palette (Ctrl+K, page/host/setting, Enter), breadcrumbs, every legacy `tag`, every palette settings anchor, kit page load, save bar on Listeners and Settings, screenshots in light, dark and 390px. **Not verified:** real screen readers (NVDA, VoiceOver, TalkBack), real touch devices, Safari/Firefox rendering (Chromium only), forced-colors mode.

## 7. Page patterns of the consistency pass

Added in `src/web/ui/zxpages.css` and `src/web/script/zxpage.js` (loaded by `index.html`). Same rules as the kit: tokens only, namespaced `zx-`.

| Pattern | Markup | Used by |
|---|---|---|
| Page header with breadcrumbs, one-line plain-language subtitle and a History shortcut | `.zx-page-header` with `data-zx-crumbs` and `<button class="zx-btn zx-btn--secondary" data-zx-history="Object">` | Certificates, ACME, Access Rules, Trusted Proxies, SSO, CAPTCHA, Security Center, Path routes (WAF has its own hero with the same crumbs and button) |
| Related menu (design v2, section 9) | `<aside class="zx-related"><span class="zx-related__title">Related</span><ul><li><a data-nav-open="tag">Page</a> <span>why</span></li></ul></aside>` | the same pages; `data-nav-open` is handled by `nav.js` so the link uses `openTabById` and the unsaved-changes guard. `zxpage.js` moves it into the header actions as one button |
| Sibling page tabs | `.zx-pagetabs > a[data-nav-open]` with `aria-current="page"` | Certificates and ACME Client: two pages (and two menu entries) that look like tabs of one |
| Stat row | `.zx-statrow > .zx-stat` | Certificates |
| Collapsible card | `button.zx-collapse__toggle[data-zx-toggle=id][aria-expanded]` + `div#id[hidden]` | "Add a certificate" |
| Item list in a callout or card | `.zx-itemlist` | Expiring soon, Hosts without a certificate |
| Checklist | `.zx-steps` | Get started on Status |
| Help popover | `.zx-whatis` + `.zx-popover` (section 2) | SNI, fallback certificate, trusted proxy gating, paranoia level, anomaly score |

### 7.1 History hook

`ZxUI.toast(msg, {action: {label, run}})` shows one extra, non-destructive action. `ZxHistory.savedToast(msg, object)` is the standard success toast with a **View history** action; `ZxHistory.view(object)` opens System > History with the Object filter set (it never restores: every restore restarts Dunree, so a toast must not trigger one). `ZxUI.saveBar({historyObject: "Auto-ban"})` shows that toast after every successful save. The object is a substring of the history entry label ("Certificate", "ACME", "WAF", "Access rule", "Auto-ban", "Virtual directory", ...).

### 7.2 Save model decision (D2 applied)

Converted to the kit save bar (an explicit form with one Save): Listeners and Settings (earlier), **Security Center > Auto-ban**.
Deliberately left, because a save bar would change behaviour:

* Access Rules, WAF mode cards, ACME auto-renew switch, Trusted Proxies list: live switches and per-row add / remove actions. They keep instant save with the toast.
* Trusted Proxies "Edit as text": already a modal edit mode with its own Save and Cancel.
* CAPTCHA: has its own dirty tracker, a scope switch with a discard prompt and per-rule Save; rebuilding that on the kit tracker is a separate change.
* WAF profiles / exclusions, SSO providers, ACME CA settings: several independent Save buttons for independent objects.
* Bot rules, Header rules, Basic auth (Security Center): edited as lists with their own add / remove actions.

### 7.3 Escaping

Anything that came from the configuration (host names, aliases, upstreams, tags, rule names, redirect addresses, user names) is escaped with `ZxUI.esc()` (components) or the local `zxEsc()` (snippets run in their own iframe). Values that a button needs are carried in `data-*` attributes and read with `this.dataset`, never put inside `onclick="f('${value}')"`. `tools/ui-smoke` adds a rule with the host name `"><img src=x onerror=...>` and fails if it becomes markup on any listing page.

## 8. Foundation pass (shared building blocks)

Added to `zxui.css` (opt-in, new pages) and `zxpages.css` (a skin for the legacy Fomantic classes, inside `.contentWindow` only; opt out with `zx-legacy-off` on an ancestor). Tokens only, both themes.

| What | Classes | Notes |
|---|---|---|
| Page frame | automatic | `.contentWindow` has no fill: cards and tables are the only boxes. Legacy pages (`.standardContainer > .ui.basic.segment > h2`) get the kit title size and the same y as `.zx-page-header` pages |
| Tabs | `.zx-tabs`/`.zx-tab` and legacy `.ui.tabular.menu` (same look, automatic) | Underline = active, icons take the text colour, strip scrolls with an edge fade (`uxkit.js`) and the chosen tab is scrolled into view. Panels `.ui.bottom.attached.(tab.)segment` lose border and inset. `.zx-tab .zx-badge` for counts |
| Section headings | `.zx-section` + `__title` (20px) `__desc`; legacy `h3` = 20px, `h4` = 16px (automatic) | Card titles stay 16px |
| Disclosure | `details.zx-disclosure > summary + .zx-disclosure__body`; legacy `.ui.accordion` and `.advanceoptions` look the same (automatic) | Replaces "Advanced" boxes |
| Form grid | `.zx-form-grid` (+ `.zx-field--wide`) | One column on phones |
| Select | `.zx-select` and every native `select` in a page (automatic) | Kit chevron |
| Buttons | `.zx-btn`; legacy `.ui.button` (automatic): blue/green/teal/primary filled = primary, red filled = danger, orange/yellow filled = warning, all else and `basic` = secondary, `basic red` = danger outline; mini/tiny = 28px | `.zx-btn-row` for a group (8px gap, wraps) |
| Inputs, checkboxes, radios, messages, labels, `.ui.table` | automatic | `.ui.message` = callout, `.ui.label` = badge colours, `.ui.table` = kit table look |
| Long values | `.zx-cell-long`, `.zx-longvalue`, `.zx-ellipsis`, `dl.zx-kv` | Wrap anywhere, 3 lines then scroll |
| Tables in cards | `.zx-table-wrap--flush`, `td.zx-empty-cell` | |
| Empty state | `.zx-empty--inline` | Compact, left aligned |
| Related | `.zx-related` | Since design v2 a menu in the page header, see section 9 |
| `.zx-whatis` | 24px visible, 40px hit area (32/44 on touch) | |
| `.zx-card__desc` | no extra inset inside head/body | |

## 9. Design v2: page shell, Related menu, sectioned navigation

The brief (principles, type scale, spacing, page anatomy, do / don't) is [design-v2.md](design-v2.md). This section is the reference of what was added to `zxui.css` (bottom block "DESIGN V2"), `zxpages.css`, `zxui.js` and `zxpage.js`. Live examples: kit page, "Related menu" and "Sectioned navigation".

### 9.1 Page shell (automatic)

| What | How | Notes |
|---|---|---|
| Page width | ONE column for every page: `.functiontab > .standardContainer` is centred right of the menu, content width `--zx-page-max` (1360px). Every page has the same left edge, at every window width; the breadcrumb strip and the footer sit on the same column | `zx-page--wide` is a no-op now (kept so old markup does not break); a different width per page made the title jump sideways when changing pages. `zx-page--full` removes the limit (canvas, diagram). Never set `box-sizing` or `max-width` on the container yourself (Fomantic lets every descendant inherit `box-sizing`) |
| Header | `.zx-page-header` is a grid: breadcrumb / title + actions / subtitle | `__main` is `display: contents`; do not give the header a `display` of your own. Phones: actions under the subtitle |
| Cards | 20px inset (`--zx-card-pad`, 16px on phones), 15px title, footer left aligned | |
| Tables | sentence-case header, no `max-height`, no sticky header | `.zx-table-wrap--scroll` restores the scroll box (drawer / dialog only). Legacy `.ui.table` gets the same header |
| Long values | `.zx-longvalue` clamps to three lines and opens on hover / focus | no scroll box |
| Status badge | `.zx-badge--dot` (+ `--ok --warn --danger --info`) is a white pill with a coloured dot | filled badges stay for counts and results |
| Empty state | `.zx-empty__icon` is a 44px tile | markup unchanged |
| Empty table | `td.zx-empty-cell` (one cell, `colspan`) shows a 36px icon tile above the sentence, the header row is hidden | automatic for every kit table. Write a real sentence ("No active bans. Clients show up here when ..."), never "None yet."; put the fixing button inside the cell when there is one |
| Phone cards | the `data-label` of a cell is sentence case, 12px, muted | no uppercase; keep labels short ("On", "Events", "Within (s)") |
| Embedded page | `<iframe data-zx-fit>` grows to the height of its document (`ZxUI.fitFrame(frame, {min, max, escape})`), no scrollbar of its own | same-origin frames; `data-zx-fit="escape"` hands Esc to the parent (frames inside a drawer) |
| Section state | `nav.state(name, kind, word)` of the sectioned navigation: dot + word ("On", "Off", "Log only") | see 9.3 |
| Forms | a lone `.zx-input` / `.zx-select` stops at 40rem, a textarea at 56rem; the same for a lone field of a legacy `.ui.form` | `.zx-field--wide` or a `.zx-form-grid` lifts the limit; `.zx-input--short` = 9rem; a lone `input[type=number]` of a legacy form stops at 12rem |
| Save bar | lines up with the page column | |
| Font weight | only 400 and 700 exist in the UI font; `zxui.css` and `zxpages.css` no longer contain 500 or 600 | do not write them in page CSS either |
| Tokens | `--zx-page-max`, `--zx-page-max-wide` (= `--zx-page-max`, legacy), `--zx-topbar-h`, `--zx-card-pad`, `--zx-fs-title`, `--zx-ease`, `--zx-dur` | |

### 9.2 Related menu

Markup is the list that pages already have (section 7). `zxpage.js` (`enhanceRelated`, run on every DOM change) moves the `<aside>` into `.zx-page-header__actions` of the same `.standardContainer` (or `[data-zx-page]`) as the first action, adds the button (`.zx-related__btn`, labelled by the existing `.zx-related__title`, `aria-expanded`, `aria-controls`) and turns each row into one link: icon of the target page (from `ZxNav`), name (`.zx-related__name`) and the reason (`.zx-related__desc`, the former sibling `<span>`).

* The reason is shown as a sentence (first letter upper case by CSS, whatever the source text does; write new ones capitalised). A screen reader hears "Name: reason" (a visually hidden ": ").
* Keyboard: Enter / Space toggle, Down / Up open and move through the links, Home / End, Esc closes and returns the focus, Tab leaves and closes. A click outside, a click on a link and a page change close it.
* Phones: rows are 44px; the menu opens towards the side that has room.
* No kit header on the page (or no JavaScript): the same markup is a row of chips where it stands; the reason is the tooltip.
* Rules: two to six links, each with a reason of a few words; no link to the page itself and none to a page that is already a tab of this page (Certificates does not list ACME Client); no other loose cross links on the page.
* On: Security Center, WAF, SSO, CAPTCHA, Access Rules, Trusted Proxies, Certificates, ACME, Path routes, HTTP Proxy, Encrypted Client Hello, Uptime Monitor, Listeners.
* Tests: open the menu before clicking a link (`#TAG .zx-related__btn`, then `#TAG .zx-related a[data-nav-open=...]`).

### 9.3 Sectioned navigation

`.zx-sectioned` (layout) + `.zx-sectionnav` (the navigation) + `.zx-sectionhead` (title and purpose of the current section). Markup: comment in `zxui.css` and the kit page. When the page column is at least about 1000px wide (window from 1321px; a media query, because a size container would capture fixed popovers in older browsers) it is a 12rem column that stays in view (sticky under the top bar) while the page scrolls; below that one native `<select>` (label "Section", at most 24rem wide) with the groups as `<optgroup>`, built by the helper.

```js
var nav = ZxUI.sectionNav("#secTabs", { attr: "data-sec", head: "#secHead" });   // attr defaults to data-zx-section
// the page owns the switch: a click on an item (the select clicks the item for you) loads the section, then
nav.select(name);        // marks the item (class "active", aria-current), fills the head, moves the select
// a page without loading or guards:  ZxUI.sectionNav(el, { auto: true, head: head });
nav.state("abuse", "on", t("On"));          // dot + word in the navigation and in the select; kinds: on, off, warn, danger; null removes it
```

* Order: the summary section first, in a group without a label, and it is the section the page opens on. Then groups named after the job ("Block abuse", "Logins and accounts"), not after the technology. Last a group called **Advanced** with everything a beginner can skip: simple by default, advanced one click away, nothing hidden.
* Item: `button.zx-sectionnav__item` with an icon, `.zx-sectionnav__text`, and a hidden `.zx-sectionnav__desc` (one sentence; shown in the section head only, there is no tooltip). Because it is static HTML the sentence is translated like all other text. Optional `.zx-sectionnav__tag`: a quiet pill for a single marked item ("Beta"); it is `aria-hidden`, assistive technology hears ", beta", the select shows "(beta)". Prefer the Advanced group over tagging items "Advanced".
* State: a section that can be on or off shows it in the navigation: `nav.state(name, "on" | "off" | "warn" | "danger", word)`. The page fetches the state (read-only request) and refreshes it after a save. The Security Center does this for Auto-ban, Bot rules and CrowdSec.
* The section head already shows the title and the purpose: the first card of a section must not repeat them (no card titled like the section).
* Groups: `div.zx-sectionnav__group[role=group][aria-labelledby]` with a `.zx-sectionnav__label`; a group without label needs neither attribute.
* Semantics: a `nav` landmark with buttons, the current one has `aria-current="true"`. One Tab stop (roving tabindex: the current section), Up / Down / Home / End move the focus, Enter / Space open (no automatic switching, a section may load data or ask about unsaved changes).
* Exemplar: Security Center (`components/security.html`): 12 sections, Overview + 4 groups, opens on Overview. Its ids are unchanged, so `$("#secTabs .item[data-sec='crowdsec']").trigger("click")`, the palette entries and deep links work as before. Items other than the current one are not Tab stops and on narrow screens the items are not visible: tests use `dispatch_event(selector, "click")` or the select, and click the section they need (the page no longer opens on Auto-ban).
* A section that saves several cards with one button ends those cards with a `.zx-savefoot` row in the flow (button + one sentence saying what it saves); it is not sticky and never floats over fields.
* The old group label inside a tab strip (`.zx-tabgroup`) is retired; do not use it.

### 9.4 Selection: checkbox, row states, selection bar

One system for every table and list. Live examples: kit page, "Checkbox" and "Data table". Exemplars: HTTP Proxy (`components/httprp.html`, `script/proxytable.js`) and WAF > Coverage (`components/waf.html`); both use the same bar, row states and header box. Checked by `tools/ui-smoke/smoke.py --proxy-ux-only`.

**Checkbox** (`zxui.css`, "checkbox"). Markup in section 2. The edge is one whole pixel and the glyph is laid over the border box by the same amount (`--_zx-check-b`), so the tick fills the box exactly at every pixel ratio. Tokens: `--zx-border-strong` (edge), `--zx-primary` / `--zx-on-primary` (fill and tick), `--zx-check-halo` (hover), `--zx-check-tick` / `--zx-check-dash` (the glyphs, used as masks). Do not size it per page and do not set `accent-color`; the old page rules that did were removed.

**Row states** (`.zx-table`, or any table with the class `.zx-rows`):

| State | How | Looks like |
|---|---|---|
| Hover | automatic | a very light neutral wash, `--zx-row-hover` |
| Selected | `tr.is-selected` | a subtle tint (`--zx-row-selected`) and a 3px `--zx-primary` bar on the left edge; never a flood of `--zx-primary-soft` |
| Selected + hover | automatic | `--zx-row-selected-hover` |
| Disabled | `tr.is-disabled` | muted text **including the name of the row** (`.zxs-cell__main`, also when it is a link; full colour again under the pointer), grey badges and chips, the same background as every other row. Fade the contents of a cell, never the cell (an opacity on a `td` also fades its background and the row turns patchy) |
| Keyboard | automatic | a 2px ring around the row whose `td > input.zx-check` has the focus (the box itself only gets a firmer edge), and around a row that is focusable itself |

States combine: a selected disabled row has the tint, the bar and the muted contents. The background is set on the cells and is the same on every cell of a row. Phone cards: the tint and the bar sit on the card.

**Select all.** The header box (`th.zx-selcol > input.zx-check`) speaks for the rows that are shown: checked when every one of them is selected, a dash (`indeterminate`) when some are; a click on the dash selects the rest. It never selects rows that are not on screen (another page, or behind "Show more"). When every row shown is selected and more match, the bar offers the rest next to the count (`.zxs-bulkmore`: "All 50 hosts on this page are selected. Select all 64"; the sentence only where there is room, the link always). Once everything is selected the count says so ("All 64 selected"). The offer is never a line of its own: that would push the table down. The selection is always part of what the list holds: a row a filter took away is not changed behind the user's back. Phones: a `.zx-table` hides its header, but a table with a selection column keeps it as one slim line, the box with the words "Select all" (`<label class="zx-selcol__label" for="...">` after the box in `th.zx-selcol`).

**Selection bar** (`.zxs-bulk` in `zxpages.css`): exists only while something is selected, sticky under the top bar (no scroller of its own). **It takes the place of the list toolbar** (the search and filter row), so nothing below moves when a selection starts or ends and the pointer stays on the row it clicked: put the bar right after the toolbar and call `zxBulkSwap(bar, toolbar).set(count > 0)` (`uxkit.js`) instead of toggling `hidden`. The toolbar keeps its room but is not shown; filtering comes back with Clear or Esc. The bar is never taller than the toolbar: `zxBulkSwap` picks the first form that fits (`data-fit`: one line in full, without the sentence, without icons, as icons only, or two lines where the toolbar has two), so no breakpoints are needed per page or language. Order: the count as a chip (`.zxs-bulk__count`), the actions in `.zxs-bulk__actions` (quiet buttons with an icon; rarely used ones in one "Change" menu; the destructive one last, apart and outlined in the danger colour), then "Clear" with the Esc hint (`.zxs-bulk__clear`). Narrow (`data-fit~="twoline"`): count and Clear on the first line, the actions as words on the second.

**Keyboard** on the exemplar: Tab reaches the header box, Up / Down / Home / End move between the boxes of the rows, Space selects, Shift + click selects a range, Esc clears the selection.

### 9.5 Dark theme and the legacy tag rules

`darktheme.css` colours bare tags (`h1`-`h6`, `a`, `p`, `span`) for the legacy pages. Those rules are written with `:where(body.darkTheme)`, so they weigh no more than a tag selector and **any class wins** against them: a kit class or a page class sets a colour in the dark theme without `!important` and without repeating `body.darkTheme` in front.

* Headings and links: a bare `h1`-`h6` / `a` gets `--text_color`; any class on it wins.
* `p` and `span` weigh nothing at all, and the rule only applies **inside a Fomantic component** (any `.ui` ancestor): those carry dark text colours of their own (items, cards, lists), so the text inside is set to `--text_color`. Measured over every page, tab, side panel and tool window, the plugin store list is the one place that needs it today; the scope is kept wide for the legacy pages.
* Everywhere else `p` and `span` inherit, so a `span` without a colour of its own follows its parent: muted help stays muted, a number in a danger pill stays in the danger colour. That covers: no `.ui` ancestor at all; an ancestor with a `zx-` or `zxs-` class (a kit component, also under a `.ui` wrapper); an ancestor with a `block__element` class (the blocks of a redesigned page: `hx-item__meta`, `up-row__main`; Fomantic and the legacy pages have no class with `__`); the group headers of the side menu.
* A page block that sits in a `.ui` wrapper and matches none of these gives the element a class with a colour.
* Do not raise the weight of those rules again, and do not load `darktheme.css` in a cascade layer on new pages. The Upstreams drawer still does: there the layer also keeps the legacy rules for bare form controls (`select`, `textarea`: border, radius, background) below the kit classes, so it is not only about text colour.
* The rules of `darktheme.css` on Fomantic classes (`.ui.form .field label`, `.ui.table td`, ...) are `!important` on purpose and are untouched: they belong to the legacy components. A table cell is therefore the one place where a class cannot win: the kit's own cell (`td.zx-empty-cell`) is restored at the end of `darktheme.css`, and a page with coloured cells repeats them for the dark theme in its style block (`snippet/logsearch.html`, the status classes).

Checked by `tools/ui-smoke/smoke.py --storage-only` (second part) and, for the Upstreams drawer, by `--sites-only`.

### 9.6 Storage: `zxStore`

`localStorage` and `sessionStorage` throw on every call when the browser blocks site data (strict privacy modes). Never call them directly: use `zxStore.get(key)`, `zxStore.set(key, value)`, `zxStore.remove(key)` (`zxStore.session.*` for the session store) from `script/safestorage.js`. They never throw; a value the browser refuses is kept in memory until the page is reloaded, and a side-panel frame shares the memory of the admin page, so the theme chosen there also holds in the frames.

* `safestorage.js` is the first script of `index.html` and sits in front of `darktheme.js` on every page that loads it. `darktheme.js` and `i18n.js` also work without it (plugin pages include `darktheme.js` alone): they then fall back to guarded direct calls, without the memory.
* Values are strings, as in the browser API: `JSON.parse(zxStore.get(key) || "[]")` inside `try`, since a stored value may be damaged.
* Not covered: the bundled Fomantic scripts use `localStorage` in three optional features (nag, remote dropdown cache, API cache) that the admin UI does not use.

Checked by `tools/ui-smoke/smoke.py --storage-only`: two fresh browser contexts in which storage throws (the methods, then the `window.localStorage` property itself); every menu page opens, menu groups, Recent, pins and the theme menu work, no console error.

## 11. Brand: logo, icons, About

Dunree's logo and icons come from `brand/` (rules: `brand/README.md`). The admin UI uses copies in `src/web/img/public/brand/`, a folder that is readable without a login because the login page needs it. `TestWebBrandAssetsMatchBrandFolder` (`src/brandweb_test.go`) fails when a copy differs from its source: change the file in `brand/` and copy it, never edit the copy.

* **Light and dark are separate files**, chosen by the theme class, never by a CSS filter and never by `prefers-color-scheme` inside the SVG. `#1a56c4` (`--zx-primary`) is for light backgrounds only; on dark the mark is `#6d9bff`.

  ```html
  <a class="zx-top-logo" href="#status" aria-label="Dunree, go to Status">
      <img class="zx-brand zx-brand--lockup zx-brand--light" src="img/public/brand/dunree-lockup.svg" alt="" width="150" height="32">
      <img class="zx-brand zx-brand--lockup zx-brand--dark"  src="img/public/brand/dunree-lockup-dark.svg" alt="" width="150" height="32">
      <img class="zx-brand zx-brand--mark zx-brand--light"   src="img/public/brand/dunree-mark.svg" alt="" width="32" height="32">
      <img class="zx-brand zx-brand--mark zx-brand--dark"    src="img/public/brand/dunree-mark-dark.svg" alt="" width="32" height="32">
  </a>
  ```

  `ui/topbar.css` shows one of the four: the lockup from 749 px, the mark alone below; `body.darkTheme` picks the dark file. The login page does the same with `body.night`, the About card with `body.darkTheme`.
* **Sizes**: 32 px high in the top bar (a multiple of 16 keeps the battlements on whole pixels), 48 px on the About card. The lockup is never shown under 20 px; below that use the mark.
* **Icons**: every page that has a `<head>` of its own carries the same six lines (SVG icon, 32 and 16 px PNG, `favicon.ico`, the 180 px touch icon, `manifest.json`). `favicon.png` in the web root still exists for pages and plugins that link it.
* **Old paths** `img/logo.svg`, `img/logo_white.svg`, `img/logo.png`, `img/public/logo.svg`, `img/icon.png`, `img/small_icon.png` and so on keep working and now hold the Dunree files.
* **Names and version are not typed into pages.** `GET /api/info/x` reports `Product`, `ProductVersion`, `Publisher`, `BasedOn`, `BasedOnVersion`, `BasedOnAuthors`, `License`, `SourceURL` and `ProductURL` from `src/mod/brand`; `components/utils.html` fills the About card (`#dunreeabout`) and the page footer (`#zxBrandFooter`) from it. The English text in the markup is only what shows before the answer arrives.
* **Attribution stays.** The footer, the login page and the About card say "Based on Zoraxy v3.3.6 by tobychui and imuslab, AGPL-3.0". Do not remove or shorten it; `TestAttributionInAdminUI` checks it.
* **Visitor pages** (CAPTCHA, error pages, the default page of the static web server) say Dunree in text only. They carry no logo, and the CAPTCHA footer has a link only when the build names a product website.
