#!/usr/bin/env python3
"""Builds the Dunree brand assets (SVG, PNG, ICO) into the brand/ directory.

Run with a Python that has playwright + chromium:
    ~/ui-test-tools/py.sh brand/src/build.py            # everything
    ~/ui-test-tools/py.sh brand/src/build.py --svg-only # no browser needed

Everything is generated from the geometry below. Do not hand-edit the output
files: change the numbers here and rebuild.
"""
import json
import math
import struct
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
OUT = SRC.parent

# ---------------------------------------------------------------- colours
BLUE = "#1a56c4"        # primary, light backgrounds (= --zx-primary of the admin UI)
BLUE_DARK = "#6d9bff"   # primary, dark backgrounds
INK = "#1c2027"         # wordmark on light (= --zx-text)
PAPER = "#f2f2f4"       # wordmark on dark
WHITE = "#ffffff"
NIGHT = "#0f1217"       # calm dark background (social card)
MUTED_ON_NIGHT = "#9aa3b2"

# ---------------------------------------------------------------- the mark
# 64 x 64 box, 4-unit grid (one pixel at 16 px). Body is a 56 x 56 square at 4..60.
# Merlons 4-20, 28-36, 44-60; crenels 8 wide, 12 deep; every wall is 16 thick;
# outer corner r24 and gate r8 share the centre 36,36.
MARK = "M4 4H20V16H28V4H36V16H44V4H60V36A24 24 0 0 1 36 60H4Z M20 28H36A8 8 0 0 1 36 44H20Z"

# Pixel-hinted small icon: 16 x 16 tile, 12 x 12 mark, every edge on a whole pixel.
# Merlons 3,2,3 px, crenels 2 x 2 px, walls 3 px, gate 6 x 4 px.
TILE16_MARK = "M2 2H5V4H7V2H9V4H11V2H14V9A5 5 0 0 1 9 14H2Z M5 7H9A2 2 0 0 1 9 11H5Z"


def n(v):
    s = "%.2f" % v
    return s.rstrip("0").rstrip(".") if "." in s else s


# ---------------------------------------------------------------- the wordmark
# Hand-built geometric letters, drawn as filled outlines (no font, no strokes).
# Stroke 8 (half a wall), baseline y=60, x-height top y=28 (the gate top),
# cap top y=16 (the top of the wall body, so the battlements rise above the text).
BASE, XTOP, CAP, ST = 60, 28, 16, 8
R_OUT, R_IN = 16, 8                      # round letters: outer and inner radius
MID = (BASE + XTOP) / 2                  # 44, centre line of the lowercase
NOTCH = math.sqrt(R_OUT ** 2 - (R_OUT - ST) ** 2)  # where a bowl meets a stem


def glyph_D(x):
    ro = (BASE - CAP) / 2                # 22
    ri = ro - ST
    a = 12                               # straight part before the bowl
    cy = (BASE + CAP) / 2
    d = (f"M{n(x)} {CAP}H{n(x + a)}A{n(ro)} {n(ro)} 0 0 1 {n(x + a)} {BASE}H{n(x)}Z"
         f"M{n(x + ST)} {CAP + ST}H{n(x + a)}A{n(ri)} {n(ri)} 0 0 1 {n(x + a)} {BASE - ST}H{n(x + ST)}Z")
    return d, a + ro


def glyph_u(x):
    w = 2 * R_OUT
    d = (f"M{n(x)} {XTOP}h{ST}V{n(MID)}a{R_IN} {R_IN} 0 0 0 {2 * R_IN} 0V{XTOP}h{ST}V{BASE}h-{ST}"
         f"V{n(MID + NOTCH)}A{R_OUT} {R_OUT} 0 0 1 {n(x)} {n(MID)}Z")
    return d, w


def glyph_n(x):
    w = 2 * R_OUT
    d = (f"M{n(x)} {BASE}V{XTOP}h{ST}V{n(MID - NOTCH)}A{R_OUT} {R_OUT} 0 0 1 {n(x + w)} {n(MID)}V{BASE}h-{ST}"
         f"V{n(MID)}a{R_IN} {R_IN} 0 0 0 -{2 * R_IN} 0V{BASE}Z")
    return d, w


def glyph_r(x, arm=4):
    d = (f"M{n(x)} {BASE}V{XTOP}h{ST}V{n(MID - NOTCH)}A{R_OUT} {R_OUT} 0 0 1 {n(x + R_OUT)} {XTOP}h{arm}v{ST}h-{arm}"
         f"A{R_IN} {R_IN} 0 0 0 {n(x + ST)} {n(MID)}V{BASE}Z")
    return d, R_OUT + arm


def glyph_e(x, term_deg=37, bar=6):
    # The bar is a little thinner than the stems so the eye stays open at small sizes.
    # The terminal is cut square to the stroke, term_deg below the horizontal.
    cx, cy = x + R_OUT, MID
    h = bar / 2
    t = math.radians(term_deg)
    ox, oy = cx + R_OUT * math.cos(t), cy + R_OUT * math.sin(t)       # terminal, outer
    ix, iy = cx + R_IN * math.cos(t), cy + R_IN * math.sin(t)         # terminal, inner
    bx_o = math.sqrt(R_OUT ** 2 - h ** 2)                             # bar meets outer circle
    bx_i = math.sqrt(R_IN ** 2 - h ** 2)                              # bar meets inner circle
    d = (f"M{n(ox)} {n(oy)}A{R_OUT} {R_OUT} 0 1 1 {n(cx + bx_o)} {n(cy + h)}H{n(cx - bx_i)}"
         f"A{R_IN} {R_IN} 0 0 0 {n(ix)} {n(iy)}Z"
         f"M{n(cx - bx_i)} {n(cy - h)}A{R_IN} {R_IN} 0 0 1 {n(cx + bx_i)} {n(cy - h)}Z")
    return d, 2 * R_OUT


# (glyph, gap before it). Straight-to-straight 10, round-to-straight 8, r-e 3, e-e 6.
WORD = [(glyph_D, 0), (glyph_u, 8), (glyph_n, 10), (glyph_r, 10), (glyph_e, 3), (glyph_e, 6)]


def wordmark(x0):
    x, parts = x0, []
    for fn, gap in WORD:
        x += gap
        d, w = fn(x)
        parts.append(d)
        x += w
    return "".join(parts), x


# ---------------------------------------------------------------- SVG files
def svg(viewbox, body, label="Dunree", w=None, h=None):
    size = f' width="{w}" height="{h}"' if w else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{viewbox}"{size} role="img" aria-label="{label}">'
            f"{body}</svg>\n")


def path(d, fill, extra=""):
    rule = ' fill-rule="evenodd"' if "Z M" in d or "ZM" in d else ""
    return f'<path fill="{fill}"{rule}{extra} d="{d}"/>'


GAP = 16                      # mark to wordmark: one wall thickness
WORD_X = 60 + GAP
WORD_D, WORD_END = wordmark(WORD_X)
LOCK_W = WORD_END + 4         # same 4-unit margin the mark has inside its box


def lockup(mark_fill, word_fill):
    return svg(f"0 0 {n(LOCK_W)} 64", path(MARK, mark_fill) + path(WORD_D, word_fill))


def stacked(mark_fill, word_fill):
    ww = WORD_END - WORD_X                    # wordmark width
    W = ww + 8
    k = 2                                     # mark scale
    mx = W / 2 - 32 * k
    my = -4 * k + 4                           # mark top lands on y=4
    mark_bottom = my + 60 * k
    wy = mark_bottom + 24 - CAP               # cap top 24 below the mark
    H = wy + BASE + 4
    body = (path(MARK, mark_fill, f' transform="translate({n(mx)} {n(my)}) scale({k})"')
            + path(WORD_D, word_fill, f' transform="translate({n(4 - WORD_X)} {n(wy)})"'))
    return svg(f"0 0 {n(W)} {n(H)}", body)


def app_icon(rx=14, k=0.66, lift=1.0, tile=BLUE, fg=WHITE):
    t = 32 - 32 * k
    return svg("0 0 64 64",
               f'<rect width="64" height="64" rx="{rx}" fill="{tile}"/>'
               + path(MARK, fg, f' transform="translate({n(t)} {n(t - lift)}) scale({k})"'))


def favicon():
    return svg("0 0 16 16", f'<rect width="16" height="16" rx="3" fill="{BLUE}"/>' + path(TILE16_MARK, WHITE))


def social_card():
    tag = json.loads((SRC / "tagline-outline.json").read_text())
    W, H = 1280, 640
    k = 2.75
    lw, lh = LOCK_W * k, 64 * k
    lx = (W - lw) / 2
    ly = 190
    word_left = lx + WORD_X * k
    word_w = (WORD_END - WORD_X) * k
    ts = word_w / tag["width"]                     # tagline spans the wordmark exactly
    ty = ly + lh + 64
    body = (f'<rect width="{W}" height="{H}" fill="{NIGHT}"/>'
            + f'<g transform="translate({n(lx)} {n(ly)}) scale({k})">' + path(MARK, BLUE_DARK) + path(WORD_D, PAPER) + "</g>"
            + f'<path fill="{MUTED_ON_NIGHT}" transform="translate({n(word_left)} {n(ty)}) scale({ts:.5f})" d="{tag["d"]}"/>')
    return svg(f"0 0 {W} {H}", body, label="Dunree. Reverse proxy and web gateway", w=W, h=H)


SVGS = {
    "dunree-mark.svg": lambda: svg("0 0 64 64", path(MARK, BLUE)),
    "dunree-mark-dark.svg": lambda: svg("0 0 64 64", path(MARK, BLUE_DARK)),
    "dunree-mark-mono.svg": lambda: svg("0 0 64 64", path(MARK, "currentColor")),
    "dunree-mark-white.svg": lambda: svg("0 0 64 64", path(MARK, WHITE)),
    "dunree-lockup.svg": lambda: lockup(BLUE, INK),
    "dunree-lockup-dark.svg": lambda: lockup(BLUE_DARK, PAPER),
    "dunree-lockup-mono.svg": lambda: lockup("currentColor", "currentColor"),
    "dunree-lockup-stacked.svg": lambda: stacked(BLUE, INK),
    "dunree-lockup-stacked-dark.svg": lambda: stacked(BLUE_DARK, PAPER),
    "dunree-app-icon.svg": lambda: app_icon(),
    "favicon.svg": favicon,
    "social-card.svg": social_card,
}

# name -> (svg source, width, height)
PNGS = {
    "dunree-mark-512.png": ("dunree-mark.svg", 512, 512),
    "dunree-mark-256.png": ("dunree-mark.svg", 256, 256),
    "dunree-mark-64.png": ("dunree-mark.svg", 64, 64),
    "dunree-app-icon-512.png": ("dunree-app-icon.svg", 512, 512),
    "dunree-app-icon-192.png": ("dunree-app-icon.svg", 192, 192),
    "favicon-48.png": ("favicon.svg", 48, 48),
    "favicon-32.png": ("favicon.svg", 32, 32),
    "favicon-16.png": ("favicon.svg", 16, 16),
    "social-card-1280x640.png": ("social-card.svg", 1280, 640),
}


def write_svgs():
    for name, fn in SVGS.items():
        (OUT / name).write_text(fn())


def render_pngs():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page(device_scale_factor=1)

        def shot(svg_text, w, h, dest, opaque=False):
            page.set_viewport_size({"width": max(w, 16), "height": max(h, 16)})
            s = svg_text.replace("<svg ", f'<svg style="display:block;width:{w}px;height:{h}px" ', 1)
            page.set_content(f"<!doctype html><html><body style='margin:0;background:transparent'>{s}</body></html>")
            page.screenshot(path=str(dest), omit_background=not opaque, clip={"x": 0, "y": 0, "width": w, "height": h})

        for name, (src, w, h) in PNGS.items():
            shot((OUT / src).read_text(), w, h, OUT / name, opaque=name.startswith("social"))
        # iOS masks the corners itself and does not want transparency: full-bleed square.
        shot(app_icon(rx=0, k=0.62, lift=1.0), 180, 180, OUT / "apple-touch-icon-180.png", opaque=True)
        b.close()

    # favicon.ico with PNG-compressed 16, 32 and 48 entries (all from the hinted 16-px drawing)
    imgs = [(s, (OUT / f"favicon-{s}.png").read_bytes()) for s in (16, 32, 48)]
    head = struct.pack("<HHH", 0, 1, len(imgs))
    off = 6 + 16 * len(imgs)
    entries = b""
    for s, data in imgs:
        entries += struct.pack("<BBBBHHII", s, s, 0, 0, 1, 32, len(data), off)
        off += len(data)
    (OUT / "favicon.ico").write_bytes(head + entries + b"".join(d for _, d in imgs))
    (OUT / "favicon-48.png").unlink()


if __name__ == "__main__":
    write_svgs()
    if "--svg-only" not in sys.argv:
        render_pngs()
    print("built", len(SVGS), "svg in", OUT)
