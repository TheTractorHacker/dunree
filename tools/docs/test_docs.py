#!/usr/bin/env python3
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Tests of the documentation, deploy and container files of Dunree ("Dunree rebrand: finish" in
docs/ux/changes.md).  Standard library only (PyYAML is used when it is installed).

    python3 tools/docs/test_docs.py
"""
import glob
import os
import re
import subprocess
import sys
import unittest
from html.parser import HTMLParser

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_index  # noqa: E402

# hosts of the project Dunree is derived from: never a default, never a link target of these files
UPSTREAM_HOSTS = ("aroz.org", "imuslab.com", "aroz-online", "github.com/tobychui", "tobychui.github.io", "zoraxydocker/")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def same(a, b):
    with open(os.path.join(ROOT, a), "rb") as fa, open(os.path.join(ROOT, b), "rb") as fb:
        return fa.read() == fb.read()


def settings(unit_text):
    """The lines of a unit file that are not comments or empty."""
    return [l for l in unit_text.split("\n") if l.strip() and not l.lstrip().startswith("#")]


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs, self.tags = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for k, v in attrs:
            if k in ("href", "src", "srcset", "action", "data") and v:
                self.refs.append((tag, k, v))


def md_links(text):
    """Relative link targets of a Markdown text (code spans and fenced blocks left out)."""
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"`[^`\n]*`", "", text)
    out = []
    for m in re.finditer(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text):
        t = m.group(1)
        if re.match(r"[a-z][a-z0-9+.-]*:", t) or t.startswith("#"):
            continue
        out.append(t.split("#", 1)[0])
    return [t for t in out if t]


class DocsIndex(unittest.TestCase):
    """(3) the upstream website is gone; docs/index.html is a plain Dunree index."""

    def test_upstream_website_sources_are_gone(self):
        for f in ("CNAME", "index_legacy.html", "zorxauth.html", "main.js", "main.css", "style.css", "dom-i18n.min.js",
                  "nginx2dunree.html", "nginx2zoraxy.html", "img/og.png", "img/title.png", "img/preview-pc.png",
                  "img/preview-mobile.png", "img/zorxauth", "img/screenshots/1.png", "img/screenshots/10.png"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, "docs", f)), "docs/%s is part of the old website and must stay removed" % f)
        self.assertTrue(os.path.isdir(os.path.join(ROOT, "docs", "img", "screenshots")), "the screenshot step writes here")

    def test_index_is_what_the_script_writes(self):
        self.assertEqual(read("docs", "index.html"), build_index.build(), "run python3 tools/docs/build_index.py")

    def test_index_is_static_and_self_contained(self):
        page = read("docs", "index.html")
        p = Links()
        p.feed(page)
        for tag in ("script", "iframe", "form", "object", "embed"):
            self.assertNotIn(tag, p.tags, "the index is static: no <%s>" % tag)
        self.assertNotIn("@import", page)
        self.assertNotIn("url(", page)
        self.assertTrue(p.refs)
        for tag, attr, ref in p.refs:
            self.assertFalse(re.match(r"([a-z][a-z0-9+.-]*:)?//", ref) or re.match(r"[a-z][a-z0-9+.-]*:", ref),
                             "the index must not point to another host: %s" % ref)
            self.assertFalse(ref.startswith("/") or ".." in ref.split("/"), "the index must stay inside docs/: %s" % ref)
            self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", ref.split("#")[0])), "broken link in docs/index.html: %s" % ref)
        for host in UPSTREAM_HOSTS:
            self.assertNotIn(host, page)
        self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", ".nojekyll")), "without .nojekyll a pages host would rewrite the .md files the index links")

    def test_index_uses_the_brand_assets(self):
        page = read("docs", "index.html")
        files = sorted(os.listdir(os.path.join(ROOT, "docs", "img", "brand")))
        self.assertIn("dunree-lockup.svg", files)
        for f in files:
            self.assertTrue(same("docs/img/brand/" + f, "brand/" + f), "docs/img/brand/%s is not the file of brand/" % f)
        for f in ("dunree-lockup.svg", "dunree-lockup-dark.svg", "favicon.svg"):
            self.assertIn('"img/brand/%s"' % f, page)
        imgs = [r for t, a, r in self._refs(page) if t == "img"]
        self.assertTrue(imgs and all(r.startswith("img/brand/") for r in imgs), imgs)

    @staticmethod
    def _refs(page):
        p = Links()
        p.feed(page)
        return p.refs

    def test_index_is_honest_and_credits_upstream(self):
        page = read("docs", "index.html")
        text = re.sub(r"\s+", " ", re.sub(r"<style>.*?</style>|<[^>]+>", " ", page, flags=re.S))
        for want in ("Dunree documentation", "Foley IT", "AGPL-3.0", "no download", "not a product website",
                     "based on Zoraxy v3.3.6", "tobychui and imuslab", "not affiliated with, sponsored by or endorsed by"):
            self.assertIn(want, text)
        for href in ("legal/LICENSE.txt", "legal/NOTICE.txt", "legal/THIRD_PARTY_NOTICES.txt"):
            self.assertIn('href="%s"' % href, page)
        self.assertTrue(same("docs/legal/LICENSE.txt", "LICENSE"))
        self.assertTrue(same("docs/legal/NOTICE.txt", "NOTICE"))
        self.assertTrue(same("docs/legal/THIRD_PARTY_NOTICES.txt", "THIRD_PARTY_NOTICES.md"))
        # the old name appears only as credit and as the name of the migration guide
        rest = text.replace("Migrating from Zoraxy", "")
        for m in re.finditer(r"[^.]*Zoraxy[^.]*\.", rest):
            self.assertRegex(m.group(0), r"based on Zoraxy|Zoraxy contributors|Zoraxy project|Based on Zoraxy", m.group(0))

    def test_index_lists_every_guide_and_deploy_page(self):
        page = read("docs", "index.html")
        for g in glob.glob(os.path.join(ROOT, "docs", "guides", "*.md")):
            self.assertIn('href="guides/%s"' % os.path.basename(g), page)
        for f in ("deploy/README.md", "deploy/dunree.service", "deploy/windows.md", "deploy/macos.md", "migrating-from-zoraxy.md"):
            self.assertIn('href="%s"' % f, page)
        self.assertNotIn('href="deploy/zoraxy.service"', page, "the legacy unit is not what a new reader should pick")


class Deploy(unittest.TestCase):
    """(2) docs/deploy: reference unit, Windows and macOS pages."""

    def test_reference_unit_is_the_packaged_unit_with_comments(self):
        ref = read("docs", "deploy", "dunree.service")
        self.assertEqual(settings(ref), settings(read("packaging", "linux", "dunree.service")),
                         "docs/deploy/dunree.service and packaging/linux/dunree.service must have the same settings")
        for want in ("Type=notify", "NotifyAccess=main", "WorkingDirectory=/opt/dunree", "ExecStart=/opt/dunree/dunree -port=:8000",
                     "KillMode=control-group", "TimeoutStopSec=30", "Restart=on-failure", "WantedBy=multi-user.target"):
            self.assertIn(want, settings(ref))
        self.assertFalse([l for l in settings(ref) if re.search(r"(?i)zoraxy|tobychui|aroz", l)])
        self.assertNotIn("Alias=", ref, "an alias would collide with the unit of an existing install (plan row 38)")
        # every setting is explained: a comment line stands directly above each block of settings
        lines = ref.split("\n")
        for i, l in enumerate(lines):
            if "=" in l and not l.startswith("#") and not lines[i - 1].startswith(("#", "[")) and "=" not in lines[i - 1]:
                self.fail("setting without a comment above it: " + l)

    def test_units_parse(self):
        import configparser
        for name in ("dunree.service", "zoraxy.service"):
            cp = configparser.RawConfigParser(strict=False, interpolation=None)
            cp.optionxform = str
            cp.read_string(read("docs", "deploy", name))
            self.assertEqual(cp.sections(), ["Unit", "Service", "Install"], name)
            self.assertEqual(cp.get("Service", "Type"), "notify")

    def test_legacy_unit_says_what_it_is_and_keeps_its_paths(self):
        leg = read("docs", "deploy", "zoraxy.service")
        self.assertTrue(leg.startswith("# LEGACY unit"))
        self.assertIn("WorkingDirectory=/opt/zoraxy", leg)
        self.assertIn("ExecStart=/opt/zoraxy/zoraxy -port=:8000", leg)
        self.assertIn("dunree.service", leg)
        self.assertNotIn("Documentation=", leg, "the upstream project is not the documentation of this unit")
        for host in UPSTREAM_HOSTS:
            self.assertNotIn(host, leg)
        # apart from the two paths it is the same unit
        swap = [l.replace("/opt/zoraxy/zoraxy", "/opt/dunree/dunree").replace("/opt/zoraxy", "/opt/dunree") for l in settings(leg)]
        self.assertEqual(swap, settings(read("docs", "deploy", "dunree.service")))

    def test_windows_and_macos_pages_point_to_packaging(self):
        win, mac = read("docs", "deploy", "windows.md"), read("docs", "deploy", "macos.md")
        for want in ("packaging/windows/", "packaging/README.md", r"C:\Program Files\Dunree\dunree.exe", r"C:\ProgramData\Dunree",
                     "install.ps1", "uninstall.ps1", "dunree.exe service install", "## Known limits", "not code-signed"):
            self.assertIn(want, win)
        for want in ("packaging/macos/", "packaging/README.md", "/usr/local/bin/dunree", "/usr/local/var/dunree",
                     "ie.foleyit.dunree", "build-pkg.sh", "uninstall.sh", "## Known limits", "not signed or notarised"):
            self.assertIn(want, mac)
        # what the pages name exists
        for f in ("packaging/windows/install.ps1", "packaging/windows/uninstall.ps1", "packaging/windows/dunree.iss",
                  "packaging/macos/build-pkg.sh", "packaging/macos/uninstall.sh", "packaging/macos/ie.foleyit.dunree.plist"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, f)), f)
        self.assertIn("ie.foleyit.dunree", read("packaging", "macos", "ie.foleyit.dunree.plist"))
        for sw in ("OpenFirewall", "InstallDir", "DataDir", "NoService", "NoStart", "ExpectedSha256"):
            self.assertIn("$" + sw, read("packaging", "windows", "install.ps1"), "windows.md names -%s" % sw)
        self.assertIn("$RemoveData", read("packaging", "windows", "uninstall.ps1"))
        self.assertIn("--remove-data", read("packaging", "macos", "uninstall.sh"))


class Guides(unittest.TestCase):
    """(2) guides, DEVELOPMENT.md and the other rewritten pages."""

    PAGES = (sorted(glob.glob(os.path.join(ROOT, "docs", "guides", "*.md"))) + sorted(glob.glob(os.path.join(ROOT, "docs", "deploy", "*.md"))) +
             [os.path.join(ROOT, p) for p in ("docs/README.md", "docker/README.md", "docs/img/screenshots/README.md")])

    def test_relative_links_resolve(self):
        for page in self.PAGES:
            with open(page, encoding="utf-8") as fh:
                for target in md_links(fh.read()):
                    self.assertTrue(os.path.exists(os.path.normpath(os.path.join(os.path.dirname(page), target))),
                                    "%s: broken link %s" % (os.path.relpath(page, ROOT), target))

    def test_no_upstream_address_and_no_fork_wording(self):
        for page in self.PAGES + [os.path.join(ROOT, "docs", "deploy", "dunree.service")]:
            rel = os.path.relpath(page, ROOT)
            with open(page, encoding="utf-8") as fh:
                text = fh.read()
            for host in UPSTREAM_HOSTS:
                for line in text.split("\n"):
                    if host in line:
                        # naming upstream's image as someone else's is allowed, using it is not
                        self.assertTrue(host == "zoraxydocker/" and re.search(r"belongs to the Zoraxy project|different product", line),
                                        "%s names an upstream address: %s" % (rel, line.strip()[:120]))
            self.assertNotRegex(text, r"(?i)\bthis fork\b|\bnew in this fork\b|what this fork ships", rel)
            self.assertNotIn("App Store", text, rel)

    def test_guides_use_the_dunree_names(self):
        for page in sorted(glob.glob(os.path.join(ROOT, "docs", "guides", "*.md"))):
            rel = os.path.relpath(page, ROOT)
            with open(page, encoding="utf-8") as fh:
                for line in fh:
                    # commands use the Dunree names (which old names may stay, and why, is the leftover audit's job)
                    self.assertNotRegex(line, r"systemctl \w+ zoraxy|\./zoraxy\b|zoraxy -\w", rel)
                    if re.search(r"Zoraxy", line):
                        self.assertIn("rebrand:keep", line, "%s: the old product name without a marker: %s" % (rel, line.strip()[:120]))

    def test_updating_guide_is_accurate(self):
        g = read("docs", "guides", "updating.md")
        for want in ("There is no Dunree download yet", "System > Update", "-update_repo", "no published Dunree image", "Only Dunree releases count",
                     "packaging/container/compose.yaml", "/opt/dunree/config", "/opt/zoraxy/config", "tools/sign_release.go -verify"):
            self.assertIn(want, g)
        self.assertNotIn("releases/download", g, "there is no release to download from")
        self.assertIn("flag.Bool(\"verify\"", read("tools", "sign_release.go"))
        self.assertTrue(os.path.exists(os.path.join(ROOT, "packaging", "container", "compose.yaml")))

    def test_development_notes_name_dunree(self):
        d = read("DEVELOPMENT.md")
        self.assertTrue(d.startswith("# Dunree development notes\n"))
        for want in ("github.com/TheTractorHacker/dunree", "PRODUCT_VERSION", "COMPAT_VERSION", "$DUNREE_RELEASE_KEY", "~/.dunree-release-key/private.pem",
                     "dunree_windows_amd64.exe", "tools/docs/test_docs.py", "docs/migrating-from-zoraxy.md"):
            self.assertIn(want, d)
        self.assertNotIn("fork-specific", d)
        self.assertNotIn("(System menu, \"Others\" group", d)
        # what it says about the release tools is what the tools say (the release section itself is tested with the tools)
        b = read("tools", "build_release.sh")
        for want in ("DUNREE_RELEASE_KEY", ".dunree-release-key/private.pem", "--packages", "--dry-run", "windows/amd64", "darwin/arm64"):
            self.assertIn(want, b)

    def test_docs_readme_lists_the_new_pages(self):
        r = read("docs", "README.md")
        for want in ("deploy/dunree.service", "deploy/windows.md", "deploy/macos.md", "index.html", "tools/docs/build_index.py"):
            self.assertIn(want, r)
        self.assertNotIn("## Not Dunree documentation", r)


class Docker(unittest.TestCase):
    """(1) docker/: image name, compose, labels, paths, health check."""

    def setUp(self):
        self.df = read("docker", "Dockerfile")
        self.readme = read("docker", "README.md")

    def test_dockerfile_layout_labels_and_healthcheck(self):
        df = self.df
        for want in ('go build -o /usr/local/bin/dunree', 'ln -s /opt/dunree /opt/zoraxy', 'ln -s dunree /usr/local/bin/zoraxy',
                     'WORKDIR /opt/dunree/config/', 'ENV PLUGIN="/opt/dunree/plugin/"', 'VOLUME [ "/opt/dunree/config/" ]',
                     'ENTRYPOINT [ "python3", "-u", "/opt/dunree/entrypoint.py" ]', 'EXPOSE 80 443 443/udp 8000',
                     'org.opencontainers.image.title="Dunree"', 'org.opencontainers.image.vendor="Foley IT"',
                     'org.opencontainers.image.licenses="AGPL-3.0-only"', 'ie.foleyit.dunree.container-identifier="Dunree"',
                     '/usr/share/doc/dunree/'):
            self.assertIn(want, df)
        # the label the container picker compares, with its value, as audited (tools/rebrand/legacy-allow.txt)
        self.assertIn('LABEL com.imuslab.zoraxy.container-identifier="Zoraxy"', df)
        self.assertIn('container.Labels["com.imuslab.zoraxy.container-identifier"]', read("src", "web", "snippet", "dockerContainersList.html"))
        self.assertRegex(df, r'ie\.foleyit\.dunree\.based-on="Zoraxy v3\.3\.6 by tobychui and imuslab')
        hc = [l for l in df.split("\n") if l.startswith("HEALTHCHECK")]
        self.assertEqual(len(hc), 1)
        self.assertIn("nc -vz 127.0.0.1 $PORT", hc[0])
        self.assertIn("netcat-openbsd", df, "the health check needs nc in the image")
        for host in UPSTREAM_HOSTS:
            self.assertNotIn(host, df)
        self.assertNotRegex(df, r"(?m)^FROM\s+\S*zoraxy")

    def test_both_dockerfiles_agree(self):
        """docker/Dockerfile and packaging/container/Dockerfile describe the same image."""
        other = read("packaging", "container", "Dockerfile")
        env = lambda t: sorted(re.findall(r'(?m)^ENV (\w+="[^"]*")', t))
        self.assertEqual(env(self.df), env(other))
        self.assertEqual(re.findall(r"(?m)^WORKDIR .*$", self.df)[-1], re.findall(r"(?m)^WORKDIR .*$", other)[-1])
        for pat in (r"(?m)^HEALTHCHECK .*$", r"(?m)^ENTRYPOINT .*$", r"(?m)^VOLUME .*$", r"(?m)^EXPOSE .*$",
                    r'com\.imuslab\.zoraxy\.container-identifier="[^"]*"', r'ie\.foleyit\.dunree\.container-identifier="[^"]*"',
                    r'ie\.foleyit\.dunree\.based-on="[^"]*"', r'org\.opencontainers\.image\.licenses="[^"]*"'):
            self.assertEqual(re.findall(pat, self.df), re.findall(pat, other), pat)

    def test_entrypoint_reads_what_the_image_sets(self):
        ep = read("docker", "entrypoint.py")
        for var in re.findall(r"getenv\(['\"](\w+)['\"]", ep):
            self.assertRegex(self.df, r'(?m)^ENV %s=' % var, "Dockerfile: no default for %s" % var)
            self.assertIn("| `%s` |" % var, self.readme, "docker/README.md does not document %s" % var)

    def test_compose_files(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        main = yaml.safe_load(read("docker", "docker-compose.yml"))
        svc = main["services"]["dunree"]
        self.assertEqual(list(main["services"]), ["dunree"])
        self.assertTrue(svc["image"].startswith("${DUNREE_IMAGE:?"), "the image must be a variable without a default")
        self.assertEqual(svc["container_name"], "dunree")
        self.assertEqual(svc["stop_grace_period"], "30s")
        self.assertEqual([v.split(":")[1] for v in svc["volumes"]], ["/opt/dunree/config/", "/opt/dunree/plugin/"])
        self.assertNotIn("docker.sock", str(svc), "the Docker socket must not be mounted by default")
        self.assertTrue({"80:80", "443:443", "443:443/udp", "8000:8000"} <= set(map(str, svc["ports"])))
        sp = yaml.safe_load(read("docker", "docker-compose.socket-proxy.yml"))
        self.assertEqual(set(sp["services"]), {"dunree", "docker-socket-proxy"})
        self.assertEqual(sp["services"]["docker-socket-proxy"]["environment"]["POST"], "0")
        self.assertTrue(all(str(v).endswith(":ro") for v in sp["services"]["docker-socket-proxy"]["volumes"]))
        self.assertNotIn("ports", sp["services"]["docker-socket-proxy"])
        t = yaml.safe_load(read("docker", "docker-compose-test.yaml"))
        self.assertEqual(t["services"]["test-dunree"]["image"], "test-dunree")
        for doc in (main, sp, t):
            for host in UPSTREAM_HOSTS:
                self.assertNotIn(host, str(doc))
            self.assertNotRegex(str(doc), r"image': '[^']*zoraxy")

    def test_readme(self):
        r = self.readme
        self.assertTrue(r.startswith("# Dunree in a container\n"))
        for want in ("There is no published Dunree image", "DUNREE_IMAGE", "dunree:local", "/opt/dunree/config/", "/opt/dunree/plugin/",
                     "/opt/zoraxy/config/", "Health check", "stop_grace_period: 30s", "--stop-timeout 30",
                     'ie.foleyit.dunree.container-identifier="Dunree"', 'com.imuslab.zoraxy.container-identifier="Zoraxy"',
                     "--platform linux/amd64,linux/arm64", "packaging/container/Dockerfile", "WITH_ZEROTIER=false", "System > Add-ons",
                     "## Known limits", "/.dunree/health"):
            self.assertIn(want, r)
        self.assertNotIn("official plugins", r)
        self.assertNotIn("dunree_build", r)
        # every compose example in the page takes the image from the variable
        for m in re.finditer(r"(?m)^\s+image:\s*(\S+)", r):
            self.assertTrue(m.group(1).startswith("${DUNREE_IMAGE"), m.group(0))
        self.assertIn("WITH_ZEROTIER", read("packaging", "container", "Dockerfile"))

    def test_entrypoint_tests_pass(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "docker", "test_entrypoint.py")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 0, r.stdout.decode())


class Addons(unittest.TestCase):
    """(4) the page and navigation entry "App Store" are "Add-ons"."""

    def test_no_app_store_label_left(self):
        skip_dirs = {"node_modules", "third_party", "triage", "verification", "rebrand", "conformance-reports"}
        # history and records keep the old label; these files explain or test the rename itself
        allowed = {"CHANGELOG.md", "docs/ux/changes.md", "docs/ux/terminology.md", "docs/ux/components.md", "docs/ux/audit-2026-11.md",
                   "docs/plugins/addon-store.md", "docs/plugins/reliability-plan.md", "tools/docs/test_docs.py", "tools/ui-smoke/smoke.py", "tools/ui-smoke/topnav_smoke.py",
                   "src/web/script/nav.js", "src/web/index.html", "src/web/components/appstore.html", "tools/rebrand/leftover-audit-checks.md"}
        hits = []
        for base, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]   # .git, .claude worktrees, caches
            for f in files:
                if not f.endswith((".html", ".js", ".go", ".md", ".py", ".json", ".txt", ".sh", ".yml", ".yaml")):
                    continue
                rel = os.path.relpath(os.path.join(base, f), ROOT)
                if rel in allowed:
                    continue
                try:
                    with open(os.path.join(base, f), encoding="utf-8") as fh:
                        if "App Store" in fh.read():
                            hits.append(rel)
                except (UnicodeDecodeError, OSError):
                    pass
        self.assertEqual(hits, [], "the label is 'Add-ons' now")

    def test_navigation_page_and_search(self):
        nav = read("src", "web", "script", "nav.js")
        m = re.search(r'\{ tag: "appstore", label: N_\("([^"]+)"\), icon: "[^"]+", kw: "([^"]+)" \}', nav)
        self.assertTrue(m, "the tag appstore must stay (deep links, openTabById)")
        self.assertEqual(m.group(1), "Add-ons")
        self.assertIn("app store", m.group(2), "the palette must still find the page under its old name")
        page = read("src", "web", "components", "appstore.html")
        self.assertIn('<h2 class="zx-page-header__title">Add-ons</h2>', page)
        self.assertIn('<div class="header">Add-on sources</div>', page)
        visible = re.sub(r"<!--.*?-->|//[^\n]*|/\*.*?\*/", "", page, flags=re.S)
        self.assertNotIn("App Store", visible)
        self.assertIn("Dunree add-on store", page)
        plugins = read("src", "web", "components", "plugins.html")
        self.assertIn("Open Add-ons", plugins)
        self.assertIn('id="appstore" class="functiontab" target="appstore.html"', read("src", "web", "index.html"))
        self.assertIn("| App Store | **Add-ons** |", read("docs", "ux", "terminology.md"))
        self.assertIn('"appstore": ("System", "Add-ons")', read("tools", "ui-smoke", "smoke.py"))

    def test_recent_and_pinned_show_the_current_name(self):
        # Recent and pinned menu entries are stored in the browser with the label the page had then; an admin who
        # visited or pinned "App Store" before the rename must see "Add-ons" (tools/ui-smoke/topnav_smoke.py checks it live).
        idx = read("src", "web", "index.html")
        m = re.search(r"function buildRecentItem\(tab, pinned\) \{(.*?)\n            \}", idx, flags=re.S)
        self.assertTrue(m, "buildRecentItem not found")
        body = m.group(1)
        self.assertIn("ZxNav.find(tab.tag)", body)
        self.assertNotIn(".text(tab.label)", body, "the stored label must not be shown as it is")
        self.assertIn("recent-pinned-label", read("tools", "ui-smoke", "topnav_smoke.py"))

    def test_log_lines_name_the_page(self):
        self.assertIn("System > Add-ons", read("src", "start.go"))
        self.assertIn("System > Add-ons", read("src", "mod", "plugins", "plugins.go"))

    def test_locales(self):
        import json
        en = json.loads(read("src", "web", "locales", "en.json"))["strings"]
        for k in ("Add-ons", "Add-on sources", "Open Add-ons", "Dunree add-on store", "No plugins installed. Browse Add-ons to add one."):
            self.assertIn(k, en)
        for k in ("App Store", "App Store sources", "Open App Store"):
            self.assertNotIn(k, en)
        for code in ("de", "es", "fr", "ja", "pt-BR", "ru", "zh-CN", "zh-TW"):
            s = json.loads(read("src", "web", "locales", code + ".json"))["strings"]
            self.assertIn("Add-ons", s, code)
            self.assertNotIn("App Store", s, code)
            self.assertFalse([k for k in s if k not in en], code + ": stale keys")


class Locales(unittest.TestCase):
    """(5) the catalogue is current and no locale has stale keys."""

    def test_extract_check_passes(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "i18n", "extract.py"), "--check"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(r.returncode, 0, r.stdout.decode()[-2000:])

    def test_meta_coverage_is_written(self):
        import json
        for code in ("de", "es", "fr", "ja", "pt-BR", "ru", "zh-CN", "zh-TW"):
            meta = json.loads(read("src", "web", "locales", code + ".json"))["_meta"]
            self.assertIsInstance(meta.get("coverage"), (int, float), code)
            self.assertIs(meta.get("reviewed"), False, code + ": machine-made texts are not reviewed")


class TopBarPolling(unittest.TestCase):
    """(6) Utilities reads its summaries when it is opened, not with every page load (browser check: topnav_smoke.py)."""

    def test_utilities_does_not_fetch_at_load(self):
        u = read("src", "web", "components", "utils.html")
        script = u[u.index("function utLoadUpdater"):]
        calls = re.findall(r"(?m)^    (utLoad\w+\(\);.*)$", script)
        self.assertEqual(calls, [], "a top-level call reads the API when the component is loaded: %s" % calls)
        self.assertIn('tabSwitchEventBind["utils"] = function(){ utRefresh(utNav.current()); }', u)
        self.assertRegex(u, r"if \(!utLoadedOnce\)\{\s*utLoadedOnce = true;\s*utLoadUpdater\(\); utLoadSessions\(\); utLoadTokens\(\);")

    def test_smoke_waits_for_the_page_before_counting(self):
        t = read("tools", "ui-smoke", "topnav_smoke.py")
        self.assertIn("loadingComponents === 0", t)
        self.assertIn('wait_for_load_state("networkidle"', t)
        self.assertIn("opening Utilities must request /api/updater/info", t)


if __name__ == "__main__":
    unittest.main()
