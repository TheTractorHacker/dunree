# Dunree brand assets

Dunree is a reverse proxy and web gateway, published by Foley IT as open source under AGPL-3.0.

## The name

Dunree is named after Fort Dunree on Lough Swilly in County Donegal. "Dún" is the Irish word for a fort. A fort stands at the edge, takes traffic in, checks it, sends it to the right place and keeps the rest out. That is the job of the product.

## The mark

The mark is called "Bastion D". It is a wall with battlements, and the gate through it is the counter of a letter D.

It is drawn on a 64-unit box with a 4-unit grid, so one grid step is one pixel at 16 px:

- The body is a 56 x 56 square, from 4 to 60.
- The merlons sit at 4-20, 28-36 and 44-60. The crenels are 8 wide and 12 deep.
- Every wall is 16 thick, including the curved one. The outer corner (r24) and the gate (r8) share the centre 36,36.

```
M4 4H20V16H28V4H36V16H44V4H60V36A24 24 0 0 1 36 60H4Z M20 28H36A8 8 0 0 1 36 44H20Z
```

## The wordmark

"Dunree" is hand-drawn from circles and straight stems. It is not a font, and every file contains outlines only, so nothing depends on an installed typeface.

- The stroke is 8 units, half a wall.
- The capital D is as tall as the wall body (16 to 60), so the battlements rise above the text.
- The x-height starts at 28, level with the top of the gate.
- In the horizontal lockup the gap between mark and wordmark is 16 units, one wall thickness.

The tagline on the social card, "Reverse proxy and web gateway", is Inter Medium converted to outlines (Inter is licensed under the SIL Open Font License 1.1).

## Colours

| Role | Hex | Use | Contrast |
|---|---|---|---|
| Dunree blue | `#1a56c4` | Mark on light backgrounds, icon tile. Same as `--zx-primary` in the admin UI. | 6.6:1 on white |
| Dunree blue, dark mode | `#6d9bff` | Mark on dark backgrounds | 7.0:1 on `#0f1217` |
| Ink | `#1c2027` | Wordmark on light backgrounds. Same as `--zx-text`. | 15.7:1 on `#fafafa` |
| Paper | `#f2f2f4` | Wordmark on dark backgrounds | 16.8:1 on `#0f1217` |
| White | `#ffffff` | Mark on the blue tile | 6.6:1 on `#1a56c4` |
| Night | `#0f1217` | Background of the social card | |
| Muted | `#9aa3b2` | Tagline on Night | 7.4:1 on `#0f1217` |

There is one brand colour, blue, in two variants. Do not put `#1a56c4` on a dark background: it only reaches 2.8:1 there. Use `#6d9bff`, the white mark or the blue tile.

## Files

| File | What it is |
|---|---|
| `dunree-mark.svg` | Mark, blue, for light backgrounds |
| `dunree-mark-dark.svg` | Mark, light blue, for dark backgrounds |
| `dunree-mark-mono.svg` | Mark in `currentColor`, for one-colour use (black, white, print, masks) |
| `dunree-mark-white.svg` | Mark in white, for coloured or photographic backgrounds |
| `dunree-lockup.svg` | Horizontal lockup for light backgrounds |
| `dunree-lockup-dark.svg` | Horizontal lockup for dark backgrounds |
| `dunree-lockup-mono.svg` | Horizontal lockup in `currentColor` |
| `dunree-lockup-stacked.svg` | Stacked lockup for light backgrounds |
| `dunree-lockup-stacked-dark.svg` | Stacked lockup for dark backgrounds |
| `dunree-app-icon.svg` | App icon: blue tile (rx 14 of 64) with the white mark |
| `favicon.svg` | Favicon: blue tile with a 12 x 12 mark redrawn on the 16-px grid |
| `favicon.ico` | Favicon at 16, 32 and 48 px |
| `favicon-16.png`, `favicon-32.png` | Favicon PNGs |
| `apple-touch-icon-180.png` | Full-bleed square for iOS, no transparency |
| `dunree-app-icon-192.png`, `dunree-app-icon-512.png` | App icon PNGs (web manifest) |
| `dunree-mark-64.png`, `dunree-mark-256.png`, `dunree-mark-512.png` | Mark on a transparent background |
| `social-card-1280x640.png`, `social-card.svg` | Social preview card |
| `src/` | Build script, preview script and the outlined tagline |
| `concepts/` | The three concepts that were considered. Not for use. |

The light and dark variants are separate files on purpose. The SVGs contain no `<style>`, no classes and no `prefers-color-scheme` rule, so they are safe to inline and they follow the page theme you choose, not the OS setting.

## Clear space and minimum size

- **Clear space:** keep one wall thickness free on every side. That is 16 units, a quarter of the mark's box. The SVG files already include 4 units, so add at least 12 more, about a fifth of the rendered mark.
- **Mark:** 16 px minimum. Use whole multiples of 16 px (16, 32, 48, 64) where you can, so the battlements land on whole pixels.
- **Favicon and icons under 32 px:** use `favicon.svg`, `favicon.ico` or the favicon PNGs. They are a separate pixel-fitted drawing. Do not scale `dunree-app-icon.svg` down to 16 px.
- **Horizontal lockup:** 20 px high minimum (about 93 px wide). Below that, use the mark alone.
- **Stacked lockup:** 64 px high minimum.

## Do

- Use the blue mark on white and light grey, and the light blue mark on dark backgrounds.
- Use the mono or white mark when only one colour is available.
- Use the tile for app icons, favicons and avatars.
- Scale the files proportionally.

## Don't

- Don't redraw, stretch, rotate or outline the mark, or round its corners.
- Don't add gradients, shadows, glows or a second colour.
- Don't change the gap between mark and wordmark, or set "Dunree" in a font next to the mark.
- Don't put the mark inside a shield, a padlock or a circle.
- Don't place the blue mark on a busy photo or on a dark background.
- Don't use the mark or the name for a modified build in a way that suggests it comes from Foley IT.

## Rebuilding

All SVG, PNG and ICO files are generated. Change the numbers in `src/build.py` and rebuild instead of editing the output. The PNG step needs Python with Playwright and Chromium.

```sh
python brand/src/build.py              # everything
python brand/src/build.py --svg-only   # SVG only, no browser needed
python brand/src/preview.py /tmp/out   # contact sheets on light and dark, at 512, 64, 32 and 16 px
```

## Credit and licence

Dunree is based on [Zoraxy](https://github.com/tobychui/zoraxy) by tobychui and imuslab, and is distributed under the same licence, AGPL-3.0. Dunree is published by Foley IT. It is a separate project and is not affiliated with or endorsed by the Zoraxy authors.

The Dunree name and logo identify Foley IT's releases. The AGPL covers the code. It does not grant the right to use the name or logo for other products.
