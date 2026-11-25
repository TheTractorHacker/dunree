#!/usr/bin/env python3
"""Checks of docs/img/screenshots/ and of the tool that makes it (tools/screenshots/capture.py).

    python3 tools/screenshots/test_screenshots.py

Standard library only; no browser and no Dunree is started. What is checked: the folder holds exactly the pictures of
SHOTS (PNG, 8 bit palette, the expected pixel size, small enough, no metadata chunks), the pictures of the old
website stay away, manifest.json, the README section and the gallery page are what capture.py writes, every picture a
text shows exists, the documentation index lists the gallery, and the demo data of capture.py uses only example names,
loopback upstreams and documented visitor addresses. It cannot look at the pictures: that is done by a person (or an
agent) after every run, see docs/ux/changes.md, "Screenshots"."""

import ipaddress
import json
import os
import re
import struct
import sys
import tempfile
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capture  # noqa: E402

ROOT = capture.ROOT
SHOTS_DIR = capture.DEFAULT_OUT
NAMES = [s["name"] for s in capture.SHOTS]
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def chunks(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", path + " is not a PNG file"
    pos, out = 8, []
    while pos < len(data):
        n, tag = struct.unpack(">I4s", data[pos:pos + 8])
        out.append((tag, data[pos + 8:pos + 8 + n]))
        pos += 12 + n
    return out


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class Files(unittest.TestCase):
    def test_the_folder_holds_exactly_the_pictures_of_SHOTS(self):
        have = sorted(f for f in os.listdir(SHOTS_DIR) if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".psd")))
        self.assertEqual(have, sorted(n + ".png" for n in NAMES), "run tools/screenshots/run.sh (it removes pictures that are no longer in SHOTS)")
        self.assertEqual(sorted(os.listdir(SHOTS_DIR)), sorted(have + ["README.md", "manifest.json"]))

    def test_the_pictures_of_the_old_website_stay_away(self):
        for n in range(1, 11):
            self.assertFalse(os.path.exists(os.path.join(SHOTS_DIR, "%d.png" % n)), "docs/img/screenshots/%d.png showed the interface of the old website" % n)
        for f in ("og.png", "og.psd", "preview-pc.png", "preview-mobile.png", "preview-mobile.psd", "title.png", "icons"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, "docs", "img", f)), "docs/img/%s belongs to the old website" % f)

    def test_names(self):
        self.assertEqual(len(NAMES), len(set(NAMES)))
        for s in capture.SHOTS:
            self.assertRegex(s["name"], r"^[a-z][a-z0-9-]*$")
            self.assertTrue(s["title"] and s["caption"].endswith("."), s["name"])
        self.assertEqual(sum(1 for s in capture.SHOTS if s.get("phone")), 1, "one picture at phone width")
        for need in ("setup", "login", "status", "status-dark", "sites", "site-editor", "certificates", "security-overview", "waf", "rules", "crowdsec",
                     "statistics", "uptime", "addons-empty", "addons", "fleet", "error-pages", "about", "status-phone"):
            self.assertIn(need, NAMES)

    def test_every_picture_is_an_optimised_png_of_the_expected_size(self):
        total = 0
        for s in capture.SHOTS:
            path = os.path.join(SHOTS_DIR, s["name"] + ".png")
            ch = chunks(path)
            self.assertEqual([t for t, _ in ch], [b"IHDR", b"PLTE", b"IDAT", b"IEND"], s["name"] + ": only the four chunks capture.py writes, so no text or time metadata")
            w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", ch[0][1])
            want = (capture.PHONE_W * capture.SCALE, capture.PHONE_H * capture.SCALE) if s.get("phone") else (capture.W * capture.SCALE, capture.H * capture.SCALE)
            self.assertEqual((w, h), want, s["name"])
            self.assertEqual((depth, ctype, interlace), (8, 3, 0), s["name"] + ": 8 bit palette")
            self.assertLessEqual(len(ch[1][1]), 256 * 3)
            raw = zlib.decompress(ch[2][1])
            self.assertEqual(len(raw), h * (w + 1), s["name"] + ": picture data is complete")
            self.assertGreater(len(set(raw[::997])), 8, s["name"] + " looks empty")
            size = os.path.getsize(path)
            self.assertLess(size, 450 * 1024, "%s is %d KB" % (s["name"], size // 1024))
            total += size
        self.assertLess(total, 5 * 1024 * 1024, "all pictures together: %d KB" % (total // 1024))

    def test_manifest(self):
        man = json.loads(read("docs", "img", "screenshots", "manifest.json"))
        self.assertEqual(man["scale"], capture.SCALE)
        self.assertEqual([p["file"] for p in man["pictures"]], [n + ".png" for n in NAMES])
        for p, s in zip(man["pictures"], capture.SHOTS):
            self.assertEqual((p["title"], p["caption"], p["readme"]), (s["title"], s["caption"], bool(s.get("readme"))))
            self.assertEqual((p["width"], p["height"]), capture.png_size(os.path.join(SHOTS_DIR, p["file"]))[:2])


class Texts(unittest.TestCase):
    def test_readme_section_is_what_capture_writes(self):
        text = read("README.md")
        a, b = text.find(capture.BEGIN), text.find(capture.END)
        self.assertTrue(0 <= a < b, "README.md has the screenshots markers")
        self.assertEqual(text[a:b + len(capture.END)], capture.readme_section(), "run python3 tools/screenshots/capture.py --docs-only")
        self.assertIn("## Screenshots", text[:a])
        self.assertNotIn("not in the repository yet", text)

    def test_gallery_is_what_capture_writes(self):
        self.assertEqual(read("docs", "img", "screenshots", "README.md"), capture.gallery_text(), "run python3 tools/screenshots/capture.py --docs-only")

    def test_every_picture_named_in_a_text_exists_and_every_picture_is_shown(self):
        pat = re.compile(r"""(?:\]\(|src=")([^)"\s]+\.png)""")
        for page, base, must in ((capture.readme_section(), ROOT, [s["name"] for s in capture.SHOTS if s.get("readme")]),
                                 (capture.gallery_text(), SHOTS_DIR, NAMES)):
            found = set(pat.findall(page))
            self.assertTrue(found)
            for target in found:
                self.assertTrue(os.path.isfile(os.path.join(base, target)), target)
            self.assertEqual(sorted(os.path.basename(t)[:-4] for t in found), sorted(must))
        for s in capture.SHOTS:
            self.assertIn(s["caption"], capture.gallery_text())

    def test_texts_name_the_product_only(self):
        for page in (capture.readme_section(), capture.gallery_text(), json.dumps(capture.SHOTS)):
            self.assertNotRegex(page, r"(?i)zoraxy|imuslab|tobychui")

    def test_documentation_index_lists_the_gallery(self):
        self.assertIn("(img/screenshots/README.md)", read("docs", "README.md"))
        self.assertIn('href="img/screenshots/README.md"', read("docs", "index.html"))
        self.assertIn("### Screenshots", read("docs", "ux", "changes.md"))

    def test_docs_only_changes_nothing_else_in_the_readme(self):
        text = read("README.md")
        a, b = text.find(capture.BEGIN), text.find(capture.END)
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "docs", "img", "screenshots"))
            with open(os.path.join(d, "README.md"), "w", encoding="utf-8") as f:
                f.write(text[:a] + capture.BEGIN + " old -->\nold text\n" + capture.END + text[b + len(capture.END):])
            root, out = capture.ROOT, capture.DEFAULT_OUT
            capture.ROOT, capture.DEFAULT_OUT = d, os.path.join(d, "docs", "img", "screenshots")
            try:
                capture.write_docs()
                capture.write_docs()  # a second run changes nothing
                with open(os.path.join(d, "README.md"), encoding="utf-8") as f:
                    self.assertEqual(f.read(), text)
                with open(os.path.join(d, "docs", "img", "screenshots", "README.md"), encoding="utf-8") as f:
                    self.assertEqual(f.read(), capture.gallery_text())
            finally:
                capture.ROOT, capture.DEFAULT_OUT = root, out


class DemoData(unittest.TestCase):
    """Nothing of a real network is in the demo data."""

    def test_host_names_are_example_names(self):
        for host, ups, tags, opt in capture.SITES:
            for name in [host] + opt.get("alias", []):
                self.assertRegex(name, r"(^|\.)example\.(com|test)$")
            self.assertIn(host, capture.SITE_WEIGHT)
        src = read("tools", "screenshots", "capture.py")
        for name in set(re.findall(r"[a-z0-9.-]+\.(?:com|net|org|test|io|ie|de|uk)\b", src)):
            ok = re.search(r"(^|\.)example\.(com|net|org|test)$", name) or name in ("www.google.com", "duckduckgo.com", "www.bing.com", "sqlmap.org", "www.bing.com")
            self.assertTrue(ok, "capture.py names %s, which is not an example name" % name)

    def test_upstreams_are_loopback(self):
        for name, addr, port, kind in capture.UPSTREAMS:
            self.assertTrue(ipaddress.ip_address(addr).is_loopback, addr)
        self.assertTrue(ipaddress.ip_address(capture.DOWN_UPSTREAM.split(":")[0]).is_loopback)

    def test_visitor_addresses_are_documentation_ranges_or_public_resolvers(self):
        doc = 0
        for weight, addr in capture.VISITORS:
            ip = ipaddress.ip_address(addr)
            if any(ip in n for n in DOC_NETS):
                doc += 1
                continue
            self.assertFalse(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved,
                             "%s is an address of a private network: it could be a real one of the place the pictures are made" % addr)
        self.assertGreaterEqual(doc, 6)
        for ident, addr, typ, origin, scenario in capture.CROWDSEC_BANS:
            self.assertTrue(any(ipaddress.ip_address(addr) in n for n in DOC_NETS), addr)

    def test_the_machine_is_kept_out_of_the_pictures(self):
        names = capture.machine_names()
        self.assertTrue(any(n.startswith("/home/") for n in names) or not os.environ.get("HOME", "").startswith("/home/"))
        self.assertNotIn(capture.DEMO_HOSTNAME, names)
        src = read("tools", "screenshots", "capture.py")
        self.assertIn("mask_host(ctx)", src)
        self.assertRegex(src, r"def take\(self, pg, name, \*\*kw\):\n\s+self\.ready\(pg, name\)\n\s+self\.check\(pg, name\)\n\s+self\.s\.save\(",
                         "every picture of the admin interface waits for its page and goes through the check")
        for s in capture.SHOTS:
            if s["name"] not in ("setup", "login"):
                self.assertTrue(capture.MUST.get(s["name"]), "MUST says what %s has to show" % s["name"])
        for n in names:
            for page in (capture.readme_section(), capture.gallery_text(), read("docs", "img", "screenshots", "manifest.json")):
                self.assertNotIn(n, page)

    def test_instances_are_throw_away(self):
        src = read("tools", "screenshots", "capture.py")
        self.assertIn('tempfile.mkdtemp(prefix="dunree-demo-")', src)
        self.assertIn('"-offline", "-mdns=false", "-port", "127.0.0.1:%d"', src, "admin port on loopback only, no outbound calls")
        self.assertNotRegex(src, r"/opt/|systemctl|\.service\b|start\.sh")


class Png(unittest.TestCase):
    def test_palette_png_round_trip(self):
        w, h = 5, 3
        idx = bytes((x + y) % 4 for y in range(h) for x in range(w))
        pal = [[255, 255, 255], [0, 0, 0], [26, 86, 196], [109, 155, 255]]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.png")
            n = capture.write_palette_png(p, w, h, pal, idx)
            self.assertEqual(n, os.path.getsize(p))
            self.assertEqual(capture.png_size(p), (w, h, 3))
            ch = dict(chunks(p))
            self.assertEqual(ch[b"PLTE"], bytes(sum(pal, [])))
            raw = zlib.decompress(ch[b"IDAT"])
            self.assertEqual(b"".join(raw[y * (w + 1) + 1:(y + 1) * (w + 1)] for y in range(h)), idx)
            self.assertTrue(all(raw[y * (w + 1)] == 0 for y in range(h)), "filter type 0 on every line")
            with open(p, "wb") as f:
                f.write(b"not a png")
            with self.assertRaises(ValueError):
                capture.png_size(p)

    def test_pick_is_weighted_and_repeatable(self):
        import random
        a = [capture.pick(random.Random(7), capture.VISITORS) for _ in range(5)]
        b = [capture.pick(random.Random(7), capture.VISITORS) for _ in range(5)]
        self.assertEqual(a, b)
        self.assertEqual(capture.pick(random.Random(1), [(1, "only")]), "only")


if __name__ == "__main__":
    unittest.main(verbosity=1)
