#!/usr/bin/env python3
"""Contact sheets for eyeballing the brand assets. Writes PNGs to the directory given as argv[1].

    ~/ui-test-tools/py.sh brand/src/preview.py /tmp/somewhere
"""
import base64
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent.parent
DEST = Path(sys.argv[1])
DEST.mkdir(parents=True, exist_ok=True)


def uri(name):
    p = OUT / name
    mime = "image/svg+xml" if name.endswith(".svg") else ("image/x-icon" if name.endswith(".ico") else "image/png")
    return f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode()


def img(name, w, h=None, style=""):
    hh = f"height:{h}px;" if h else ""
    return f'<img src="{uri(name)}" style="width:{w}px;{hh}{style}">'


def panel(bg, fg, mark, lockup, stacked, mono_color):
    sizes = "".join(f'<div class="c">{img(mark, s, s)}<small>{s}</small></div>' for s in (512, 64, 32, 16))
    icons = "".join(f'<div class="c">{img("dunree-app-icon.svg", s, s)}<small>icon {s}</small></div>' for s in (128, 64, 32, 16))
    favs = "".join(f'<div class="c">{img("favicon.svg", s, s)}<small>fav {s}</small></div>' for s in (64, 32, 16))
    monos = "".join(
        f'<div class="c"><div style="width:{s}px;height:{s}px;background:{mono_color};'
        f'-webkit-mask:url({uri("dunree-mark-mono.svg")}) center/contain no-repeat"></div><small>mono {s}</small></div>'
        for s in (64, 32, 16))
    locks = "".join(f'<div class="c">{f'<img src="{uri(lockup)}" style="height:{h}px">'}<small>lockup {h}</small></div>' for h in (96, 48, 24, 16))
    return f"""<div class="p" style="background:{bg};color:{fg}">
      <div class="r">{sizes}</div>
      <div class="r">{monos}{icons}</div>
      <div class="r">{favs}<div class="c">{img(stacked, 220)}<small>stacked</small></div></div>
      <div class="r">{locks}</div>
    </div>"""


CSS = """<style>
body{margin:0;font:11px sans-serif}
.w{display:flex}
.p{width:900px;padding:24px;box-sizing:border-box}
.r{display:flex;align-items:flex-end;gap:28px;margin-bottom:28px;flex-wrap:wrap}
.c{display:flex;flex-direction:column;gap:6px;align-items:flex-start}
small{opacity:.55}
img{display:block}
</style>"""

sheet = CSS + '<div class="w">' + panel("#fafafa", "#1c2027", "dunree-mark.svg", "dunree-lockup.svg",
                                         "dunree-lockup-stacked.svg", "#000") \
    + panel("#0f1217", "#f2f2f4", "dunree-mark-dark.svg", "dunree-lockup-dark.svg",
            "dunree-lockup-stacked-dark.svg", "#fff") + "</div>"

# small sizes magnified 8x with nearest-neighbour, to judge pixel snapping and the "face" reading
zoom_items = [("favicon-16.png", 16), ("favicon-32.png", 32), ("dunree-mark-64.png", 64)]
zoom = CSS + '<div class="w" style="gap:24px;padding:24px;background:#888;align-items:flex-start;flex-direction:column">'
for bg in ("#fafafa", "#ffffff", "#202124", "#0f1217"):
    zoom += f'<div style="background:{bg};padding:16px;display:flex;gap:16px;align-items:flex-end">'
    zoom += img("favicon-16.png", 128, 128, "image-rendering:pixelated")
    zoom += img("favicon-32.png", 128, 128, "image-rendering:pixelated")
    m = "dunree-mark.svg" if bg in ("#fafafa", "#ffffff") else "dunree-mark-dark.svg"
    zoom += f'<canvas data-src="{uri(m)}" data-s="16" width="16" height="16" style="width:128px;height:128px;image-rendering:pixelated"></canvas>'
    zoom += f'<canvas data-src="{uri("dunree-app-icon.svg")}" data-s="16" width="16" height="16" style="width:128px;height:128px;image-rendering:pixelated"></canvas>'
    zoom += img("favicon-16.png", 16, 16) + img(m, 16, 16) + "</div>"
zoom += """</div><script>
window.done = Promise.all([...document.querySelectorAll('canvas')].map(c => new Promise(r => {
  const i = new Image(); i.onload = () => { c.getContext('2d').drawImage(i, 0, 0, +c.dataset.s, +c.dataset.s); r(); }; i.src = c.dataset.src; })));
</script>"""

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(device_scale_factor=1, viewport={"width": 1800, "height": 1200})
    page.set_content("<!doctype html>" + sheet)
    page.wait_for_timeout(300)
    page.screenshot(path=str(DEST / "sheet.png"), full_page=True)
    page.set_content("<!doctype html>" + zoom)
    page.evaluate("window.done")
    page.wait_for_timeout(300)
    page.screenshot(path=str(DEST / "zoom.png"), full_page=True)
    # the lockup alone, large, for letter-shape and spacing checks
    page.set_content("<!doctype html><body style='margin:0;padding:40px;background:#fafafa'>"
                     + img("dunree-lockup.svg", 1480, 320) + "</body>")
    page.wait_for_timeout(200)
    page.locator("img").screenshot(path=str(DEST / "lockup-large.png"))
    page.set_content("<!doctype html><body style='margin:0;padding:40px;background:#888;display:flex;gap:40px;align-items:center'>"
                     + img("apple-touch-icon-180.png", 180, 180) + img("dunree-app-icon-512.png", 256, 256)
                     + img("favicon.ico", 48, 48) + img("favicon.ico", 16, 16)
                     + img("dunree-lockup-stacked.svg", 300, None, "background:#fafafa;padding:30px")
                     + img("dunree-lockup-stacked-dark.svg", 300, None, "background:#0f1217;padding:30px")
                     + f'<div style="color:#1c2027;background:#fff;padding:20px"><div style="width:259px;height:56px;background:currentColor;-webkit-mask:url({uri("dunree-lockup-mono.svg")}) center/contain no-repeat"></div></div>'
                     + "</body>")
    page.wait_for_timeout(200)
    page.screenshot(path=str(DEST / "misc.png"), full_page=True)
    b.close()
print("previews in", DEST)
