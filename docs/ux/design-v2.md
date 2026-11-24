# Design v2: one product, not a set of pages

The second design round of the admin UI. Round one gave every page the same colours; this round gives every page the same
**shape**. It is the brief the area teams follow when they rework a page. Components and their markup: [components.md](components.md)
(section 9) and the living kit page `/ui/kit.html` (`-dev`).

Reference feel: Linear, Vercel, the Cloudflare dashboard, Tailscale admin. Calm, dense where data is dense, generous where a
decision is made. What we are avoiding is the generic admin template: full-width stretch, boxes in boxes, a row of loose links,
uppercase everything, a tab strip that wraps.

## 1. Principles

1. **The page is a column, not the window.** Content has ONE width (1360px) and sits centred right of the menu, with the same
   left edge on every page: the title never moves sideways when you change pages. A 2560px monitor shows the same page as a
   laptop, with more air around it. Nothing stretches a switch 1500px away from its label.
2. **One scroller.** The page scrolls. Tables, lists and logs grow with their content; long lists get paging or "Show more",
   never a scroll box inside the page. Sticky is fine (sub-navigation, save bar), `overflow: auto` with a `max-height` is not.
   Exceptions: drawers and dialogs (they are their own viewport), code blocks scrolling sideways.
3. **One level of boxes.** The page background, then cards. No card in a card, no bordered table in a bordered card (use
   `.zx-table-wrap--flush`), no tinted panel around a form that is already in a card.
4. **Navigation has one place per level.** Menu (left) picks the page. Inside a page: up to six flat choices are tabs;
   more, or grouped ones, are a sectioned navigation (left column, select on phones). Links to *other* pages live in the
   Related menu of the header. Never a second row of tabs, never loose links under the title.
5. **Simple first, advanced reachable.** The default view answers "is it on, is it working, what do I do next": a page with
   sections opens on its summary. Rarely needed settings sit in a disclosure, rarely needed sections in a last group called
   *Advanced*; they are never removed.
6. **Say what it is for.** Every page, section and card starts with one plain sentence: what this does for the reader, and
   what happens by default. Jargon gets a "?" popover once.
7. **Colour means something.** Blue is the one primary action and the current selection. Green, amber and red are states
   and always come with a word. Everything else is neutral.
8. **Quiet motion.** 140ms on hover, selection and menus, nothing that moves layout, everything off under
   `prefers-reduced-motion`.

## 2. Type scale

Root is 14px. The UI font ships two weights, regular (400) and bold (700): hierarchy comes from **size and colour first**, bold
second. Do not write 500 or 600 and expect a difference.

| Use | Size | Weight | Colour | Token / class |
|---|---|---|---|---|
| Page title (one `h2`) | 24px, -0.01em | 700 | text | `--zx-fs-title`, `.zx-page-header__title` |
| Section title (current section, or a group of cards) | 20px | 700 | text | `--zx-fs-xl`, `.zx-sectionhead__title`, `.zx-section__title` |
| Card title | 15px | 700 | text | `.zx-card__title` |
| Body, labels of fields | 14px | 400 / 700 for labels | text | `--zx-fs-md` |
| Subtitle, description, help | 14px (subtitle) / 13px | 400 | muted | `.zx-page-header__sub`, `.zx-card__desc`, `.zx-help` |
| Table header, group label, badge, tag | 12px, sentence case | 700 | muted | `--zx-fs-xs` |
| Numbers in stat tiles | 26px, tabular | 700 | text or state | `.zx-stat__value` |

Sentence case everywhere ("Add a certificate", not "Add A Certificate"). No uppercase labels in pages (the main menu keeps
its uppercase group names; that is the only place). Line length of running text: at most about 46rem (subtitle, section
description) and 62rem (card description). Mono only for things you could paste into a terminal or a config file.

## 3. Spacing

4px base, tokens `--zx-space-1..7` = 4, 8, 12, 16, 24, 32, 48.

| Between | Space |
|---|---|
| Page header and content; tab strip and content | 24 |
| Cards / sections of a page | 16 |
| Sub-navigation column and content | 24 |
| Card edge and its content | 20 (`--zx-card-pad`; 16 on phones) |
| Card title and description; label and control | 4 |
| Fields of a form | 16 |
| Buttons in a row; chips; badges | 8 |
| Icon and its label | 6 to 10 |

Radius: 12 cards, tables and menus; 8 controls and buttons; pill for badges and chips. Shadow: cards have a border and a
whisper (`--zx-shadow-1`), popovers and menus `--zx-shadow-2`, dialogs and the save bar `--zx-shadow-3`. Do not add shadows
or borders of your own.

## 4. Colour use

Tokens only (`--zx-*`, both themes). Per role:

* **Surfaces:** page `--zx-bg`; cards, inputs, menus `--zx-surface`; table header, hover, sunken tiles `--zx-surface-2`;
  pressed and tracks `--zx-surface-3`.
* **Text:** `--zx-text`, `--zx-text-muted` for anything secondary, `--zx-text-faint` only for placeholders.
* **Primary:** `--zx-primary` for the one primary button of a view and for focus; `--zx-primary-soft` +
  `--zx-primary-soft-text` for "this is selected" (current section, selected row).
* **State:** `--zx-{ok,warn,danger,info}-*`. A state colour never stands alone: icon or dot plus the word.
  Running or enabled things are *not* green buttons; green is a result, not an action.
* **Borders:** `--zx-border` for separation, `--zx-border-strong` for things you can type in or press.
* **Brand:** the Dunree blue is `--zx-primary` (`#1a56c4`) in the light theme and `#6d9bff` in the dark theme, so the
  logo and the primary button share one colour. The logo is an image from `brand/` in its light or dark file; it is never
  recoloured with CSS. Rules: `brand/README.md`; markup: [components.md](components.md), section 11.

## 5. Page anatomy

```
[ breadcrumb: Group / Page                                              ]
[ Page title (h2)                      [Related v] [History] [Primary]  ]
[ One-line subtitle: what this page does for you                        ]
                                                              24px
[ optional: tabs (<= 6)  |  or the sectioned navigation, see below      ]
[ optional: one callout when something needs attention now              ]
[ optional: stat row (3 to 5 tiles)                                     ]
[ card ]  title + one sentence, content, footer with the card's actions
[ card ]
[ save bar: sticky at the bottom while there are unsaved changes        ]
```

With sections (more than six, or grouped):

```
[ header as above                                                        ]
[  > Overview   ] [ Section title (h3)                                   ]
[ Group label   ] [ One line: what this section is for                   ]
[    Section o On] [ card (no title that repeats the section head)        ]
[    Section    ] [ card ]
[ Advanced      ]
[    Section    ]
```

* **Width.** `.standardContainer` is centred with `--zx-page-max` (1360px), the same for every page (settings, lists,
  dashboards), so all pages share one left edge; breadcrumb and footer sit on the same column. `zx-page--wide` does nothing any
  more. Do not set a `max-width` on a page of your own. A table that needs more room drops its least important columns
  (HTTP Proxy hides Tags, then Live) instead of scrolling sideways. Inside a card, a lone field stops at 40rem
  (56rem for a textarea); fields that belong together go in a `.zx-form-grid`.
* **Header.** Markup unchanged (`.zx-page-header`). It is a grid: the actions sit on the title row at every width and move
  under the subtitle on phones. Action order: Related, History, other secondary buttons, the single primary button last.
  A status of the whole page (Enabled / Disabled) is a `.zx-badge--dot` in the actions, before the buttons; the state of one
  card sits next to the card title, in the same form.
* **Cards.** Title says what the group is, description says what it does and what the default is. Card actions go in
  `.zx-card__foot` (left aligned, primary first). A card that only reports (status) has no footer.
* **Tables.** `.zx-table-wrap > table.zx-table`, sentence-case header, no inner scrolling, row actions right aligned.
  More than about 25 rows: paging or "Show more". Long values: `.zx-longvalue` (three lines, expands on hover and focus).
* **Selecting rows.** A kit checkbox in the first column, the header box a dash while only some rows are selected. A selected
  row is a subtle tint with an accent bar on its left edge, not a flood of blue; a disabled row mutes its contents and keeps
  the background of the others. Actions for the selection sit in one bar that appears with it: count, actions, the
  destructive one apart, Clear (Esc). Reference: components.md 9.4.
* **Status.** `.zx-badge--dot --ok/--warn/--danger` for the state of a thing (white pill, coloured dot, the word);
  the filled badges for counts and results ("3 expiring", "No certificate").
* **Empty.** `.zx-empty`: icon tile, what is missing, one sentence, the button that fixes it. `--inline` inside a card. An
  empty table (`td.zx-empty-cell`) gets the tile by itself; write a sentence that says when rows will appear, never "None yet.".
* **Lists of things with a state** (sites, monitors): a stat row above the filters (3 to 5 tiles: how many, how many are in
  trouble), status as a dot badge in its own column, secondary facts as compact icon chips with a tooltip, row actions quiet
  (Remove is neutral until pointed at). Exemplar: HTTP Proxy.
* **Logs.** Two lines per entry (what + target, then who and from where), the result as a dot badge, details behind a
  disclosure that grows in place, 25 entries and "Show more". Filters left, actions right, on one toolbar row. Exemplar:
  Security Center > Audit log.
* **Saving.** One primary Save per view: the save bar when the page tracks changes, otherwise one button at the end of the
  cards it saves, with a label that says what it saves ("Save gateway"). Not sticky over fields.
* **Phones (390px).** One column, 16px gutter, tables become cards (`data-label`, sentence case), tabs scroll sideways with
  a fade on the side that has more, the sectioned navigation is a select, targets are 44px.

## 6. Do / don't

| Do | Don't |
|---|---|
| Let the shell set the width, the same for every page | `max-width` on your page, a wider column for one page, or content that spans a 2000px window |
| One `h2` (page), `h3` for the section, card titles below that | A second big title inside the first card that repeats the page title |
| Put links to other pages in `.zx-related` (it becomes the header menu) | A "Related:" line, or links in a help paragraph as the only way to get somewhere |
| Up to six tabs; otherwise `.zx-sectionnav` with groups named for the job ("Block abuse") | A wrapping tab strip, group labels inside a strip, tabs in tabs |
| Put what a beginner can skip in an *Advanced* group or a disclosure | Hide an advanced setting completely, show all 30 fields at once, or sprinkle "Advanced" tags over a navigation |
| Open a sectioned page on its summary; show On / Off in the navigation | Open on the first settings form; a navigation that says nothing about state |
| Let the section head name the section | A first card that repeats the section title and its sentence |
| Let lists grow; page them | `max-height` + `overflow: auto` on a list, table or log inside the page |
| One primary button per view; destructive actions are outline until confirmed | Several blue buttons, green "enable" buttons, red buttons at rest |
| State = dot badge + word, the same form in headers, cards, tables and navigation | A coloured dot alone, filled pills for on / off, a different status shape per page |
| Embed an editor page with `<iframe data-zx-fit>` | A fixed-height iframe that scrolls inside the page |
| Put a card's buttons in its footer, the page's in the header | Buttons floating between fields, "Apply" next to every input |
| Fields that belong together in `.zx-form-grid`; short values get `.zx-input--short` | A port number in a 1200px wide input |
| Sentence case, plain words, the default stated ("Off until you switch it on") | UPPERCASE labels, internal names, "N/A", raw JSON or binary shown to the reader |
| Tokens for every colour, radius, shadow and space | Hex colours, own shadows, `!important` to fight the kit (tell the design lead instead) |
| Check light, dark, 1366, 2000 and 390px, keyboard only | Ship after looking at one width in one theme |

## 7. What the shell does for you (no page edit needed)

One centred page column with one left edge (breadcrumb and footer included); header grid; card padding and title size;
sentence-case table headers on kit and legacy tables; no inner scroll on `.zx-table-wrap`; the Related menu (reasons shown
as sentences); 2px tab underline on kit and legacy tabs; lone fields capped at 40rem (numbers 12rem) in kit and legacy forms;
the save bar aligned with the column; the empty-state icon tile, also in empty tables; sentence-case labels in phone card
tables; `iframe[data-zx-fit]` sized to its content; one Tab stop for a sectioned navigation.

What needs your hands: converting a long tab strip to the sectioned navigation, regrouping fields into cards with a
sentence each, replacing scroll boxes with paging, moving loose links into `.zx-related`, removing page-local widths,
colours, uppercase and font weights 500 / 600, turning page-local status pills into dot badges, and removing card titles
that repeat a section head.

## 8. Naming note for the owner: "HTTP Proxy" or "Hosts"?

Recommendation: rename the menu entry and the page from **HTTP Proxy** to **Hosts**. The list is a list of host names, its
first column is already called Host, and "HTTP Proxy" describes the mechanism, not what the reader manages. ("Sites" would
be the friendlier word, but the menu group is already called Sites.) One entry stays a "proxy rule" in running text until
the rename is decided, because terminology.md, the translations and the smoke tests use it. Not renamed in this round: it
is one label in `nav.js` plus the page title, and a pass over the texts that say "HTTP Proxy page".
