#!/usr/bin/env python3
# Dunree rebrand - tests for the mechanical rename pass.
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Tests for tools/rebrand/rename.py.

    python3 tools/rebrand/test_rename.py            all tests
    python3 tools/rebrand/test_rename.py Fixture    only the tests on a throw-away repository
    python3 tools/rebrand/test_rename.py Repo       only the checks on this repository

Fixture tests copy the tool and its three input files into a temporary git repository that holds one small
example of every kind of surface, run the tool there and look at the result.  Repo tests check the real tree:
the pass is fully applied (a new run would change nothing), the module root is the policy's, and the strings
that existing installs depend on are still there.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
INPUTS = ["rename.py", "policy.json", "mechanical.json", "legacy-allow.txt"]

OLD = "Zor" + "axy"           # written in two parts so that nothing in this file depends on being excluded
OLD_L = OLD.lower()
OLD_U = OLD.upper()
OLD_MOD = "imuslab.com/" + OLD_L
OLD_SDK = OLD_L + "_plugin"

FILES = {
    "LICENSE": "GNU AGPL\n%s is free software.\n" % OLD,
    "NOTICE": "Based on %s by tobychui and imuslab.\n" % OLD,
    "THIRD_PARTY_NOTICES.md": "%s uses these libraries.\n" % OLD,
    "CHANGELOG.md": "# v3.3.6\n%s got faster.\n" % OLD,
    "docs/rebrand/plan.md": "%s -> Dunree\n" % OLD,
    "docs/guide.md": "\n".join([
        "# %s guide" % OLD,
        "%s is developed by tobychui for imuslab." % OLD,
        "See tobychui/%s#77 and https://github.com/tobychui/%s/issues/267 for history." % (OLD_L, OLD_L),
        "Health check: `curl http://host/.%s/health` answers with `X-%s-Ref`." % (OLD_L, OLD),
        "The old header X-%s-Whatever is listed here. <!-- rebrand:keep --> %s stays on this line." % (OLD, OLD),
        "Set %s_BIN to the binary. %s_EVENT is passed to hooks." % (OLD_U, OLD_U),
        "Import `%s/mod/plugins/%s`." % (OLD_MOD, OLD_SDK),
        "",
    ]),
    "src/go.mod": "module %s\n\ngo 1.23\n" % OLD_MOD,
    "src/main.go": "\n".join([
        "package main",
        "",
        "/*",
        "\t%s main" % OLD,
        "\tauthor: tobychui",
        "\tCopyright (c) 2018-present tobychui and contributors",
        "*/",
        "",
        "import (",
        "\t\"fmt\"",
        "",
        "\t\"%s/mod/plugins/%s\"" % (OLD_MOD, OLD_SDK),
        "\t\"%s/mod/utils\"" % OLD_MOD,
        ")",
        "",
        "const salt = \"%s-oauth2-session-v1\"" % OLD_L,
        "const ruleSeed = \"%s-rule:\"" % OLD_L,
        "const cookie = \"%s_csrf\"" % OLD_L,
        "const header = \"X-%s-Plugin-Token\"" % OLD,
        "const internal = \"X-%s-Internal-Ref\"" % OLD,
        "const SYSTEM_NAME = \"%s\"" % OLD,
        "",
        "func collect%sMetrics() {" % OLD,
        "\tfmt.Println(\"%s started\", %s.%sPort, utils.X) // prose in a string" % (OLD, OLD_SDK, OLD),
        "\tfmt.Println(\"%s\" + \"x\") // legacy-compat: asserted on purpose" % OLD,
        "}",
        "",
    ]),
    "src/mod/utils/utils.go": "package utils\n\nconst X = 1\n",
    "src/mod/plugins/%s/%s.go" % (OLD_SDK, OLD_SDK): "\n".join([
        "package %s" % OLD_SDK,
        "",
        "type ConfigureSpec struct {",
        "\t%sPort int `json:\"%s_port\"`" % (OLD, OLD_L),
        "}",
        "",
        "var %sPort = 0" % OLD,
        "",
    ]),
    "src/mod/plugins/%s/CHANGELOG.md" % OLD_SDK: "# 1.1.0\n%s SDK history.\n" % OLD,
    "src/mod/plugins/testdata/sdk-1.0.0/%s/%s.go" % (OLD_SDK, OLD_SDK): "package %s\n\n// %s 1.0.0\n" % (OLD_SDK, OLD),
    "example/plugins/hello/go.mod": "module example.com/%s/hello\n\ngo 1.23\n" % OLD_L,
    "example/plugins/hello/main.go":
        "package main\n\nimport plugin \"example.com/%s/hello/mod/%s\"\n\nvar _ = plugin.%sPort\n\nfunc main() {}\n"
        % (OLD_L, OLD_SDK, OLD),
    "example/plugins/hello/mod/%s/%s.go" % (OLD_SDK, OLD_SDK): "package %s\n\nvar %sPort = 0\n" % (OLD_SDK, OLD),
    "src/web/index.html": "\n".join([
        "<title>%s</title>" % OLD,
        "<meta name=\"%s.csrf.Token\" content=\"x\">" % OLD_L,
        "<p>Welcome to %s</p>" % OLD,
        "<p><a href=\"https://%s.aroz.org\">%s</a> (c) 2021 tobychui. Licensed under AGPL</p>" % (OLD_L, OLD),
        "<script>localStorage.getItem('%s_menu_groups')</script>" % OLD_L,
        "",
    ]),
    "src/web/locales/en.json": json.dumps({"_meta": {"language": "English"}, "strings": {
        "Welcome to %s" % OLD: "Welcome to %s" % OLD,
        "%s is developed by tobychui for imuslab" % OLD: "",
    }}, indent=1) + "\n",
    "src/web/locales/de.json": json.dumps({"_meta": {"language": "German"}, "strings": {
        "Welcome to %s" % OLD: "Willkommen bei %s" % OLD,
        "Welcome to Dunree": "Schon da",
    }}, indent=1, ensure_ascii=False) + "\n",
    "docs/nginx2%s.html" % OLD_L: "<a href=\"./nginx2%s.html\">%s converter</a>\n" % (OLD_L, OLD),
    "img/logo.png": None,   # binary
}


def run(cwd, *args):
    return subprocess.run([sys.executable, os.path.join(cwd, "tools", "rebrand", "rename.py")] + list(args),
                          cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)


def sh(cwd, *args):
    subprocess.run(list(args), cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tree(root):
    out = {}
    for dp, dn, fns in os.walk(root):
        if ".git" in dn:
            dn.remove(".git")
        for f in fns:
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


class Fixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rebrand-test-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        os.makedirs(os.path.join(self.dir, "tools", "rebrand"))
        for f in INPUTS:
            shutil.copy(os.path.join(HERE, f), os.path.join(self.dir, "tools", "rebrand", f))
        for rel, body in FILES.items():
            p = os.path.join(self.dir, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(b"\x89PNG\x00" + OLD.encode() if body is None else body.encode("utf-8"))
        sh(self.dir, "git", "init", "-q")
        sh(self.dir, "git", "add", "-A")
        sh(self.dir, "git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "fixture")

    def read(self, rel):
        with open(os.path.join(self.dir, rel), encoding="utf-8") as fh:
            return fh.read()

    def apply(self):
        r = run(self.dir, "--apply", "--no-gofmt")
        self.assertIn("Changed", r.stdout, r.stdout)
        return r

    def test_dry_run_is_the_default_and_writes_nothing(self):
        before = tree(self.dir)
        r = run(self.dir)
        self.assertIn("Dry run. Nothing was written.", r.stdout)
        self.assertIn("module-path", r.stdout)
        self.assertEqual(before, tree(self.dir))
        self.assertEqual(run(self.dir, "--check").returncode, 1, "--check must fail while there is work left")
        r = run(self.dir, "--dry-run")
        self.assertIn("Dry run. Nothing was written.", r.stdout)
        self.assertEqual(before, tree(self.dir), "--dry-run wrote something")
        self.assertNotEqual(run(self.dir, "--dry-run", "--apply").returncode, 0, "--dry-run --apply must be refused")
        self.assertEqual(before, tree(self.dir))

    def test_module_path_comes_from_the_policy_variable(self):
        self.apply()
        with open(os.path.join(self.dir, "tools", "rebrand", "policy.json")) as fh:
            root = json.load(fh)["variables"]["MODULE_ROOT"]
        self.assertEqual(self.read("src/go.mod").split("\n")[0], "module " + root)
        main = self.read("src/main.go")
        self.assertIn('"%s/mod/plugins/dunree_plugin"' % root, main)
        self.assertIn('"%s/mod/utils"' % root, main)
        self.assertNotIn(OLD_MOD, main)
        self.assertIn("`%s/mod/plugins/dunree_plugin`" % root, self.read("docs/guide.md"))

    def test_module_root_can_be_changed_later_in_one_place(self):
        self.apply()
        pol = os.path.join(self.dir, "tools", "rebrand", "policy.json")
        with open(pol) as fh:
            d = json.load(fh)
        first = d["variables"]["MODULE_ROOT"]
        d["variables"]["MODULE_ROOT"] = "git.example.org/acme/gateway"
        with open(pol, "w") as fh:
            json.dump(d, fh)
        self.apply()
        self.assertEqual(self.read("src/go.mod").split("\n")[0], "module git.example.org/acme/gateway")
        self.assertIn('"git.example.org/acme/gateway/mod/utils"', self.read("src/main.go"))
        self.assertNotIn(first, self.read("src/main.go"))
        self.assertEqual(run(self.dir, "--check").returncode, 0)

    def test_protected_files_are_byte_identical(self):
        before = tree(self.dir)
        self.apply()
        after = tree(self.dir)
        for rel in ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md", "docs/rebrand/plan.md",
                    "tools/rebrand/policy.json", "tools/rebrand/legacy-allow.txt", "img/logo.png",
                    "src/mod/plugins/testdata/sdk-1.0.0/%s/%s.go" % (OLD_SDK, OLD_SDK)]:
            self.assertEqual(before[rel], after[rel], rel + " was changed")
        # the SDK change log moves with its folder but its text is history
        self.assertEqual(before["src/mod/plugins/%s/CHANGELOG.md" % OLD_SDK],
                         after["src/mod/plugins/dunree_plugin/CHANGELOG.md"])

    def test_attribution_and_history_stay(self):
        self.apply()
        main = self.read("src/main.go")
        self.assertIn("author: tobychui", main)
        self.assertIn("Copyright (c) 2018-present tobychui and contributors", main)
        self.assertIn("\tDunree main", main)
        guide = self.read("docs/guide.md")
        self.assertIn("# Dunree guide", guide)
        self.assertIn("%s is developed by tobychui for imuslab." % OLD, guide, "must not credit upstream with Dunree")
        self.assertIn("tobychui/%s#77" % OLD_L, guide)
        self.assertIn("https://github.com/tobychui/%s/issues/267" % OLD_L, guide)
        html = self.read("src/web/index.html")
        self.assertIn(">%s</a> (c) 2021 tobychui." % OLD, html, "footer must not say 'Dunree (c) tobychui'")
        self.assertIn("<title>Dunree</title>", html)

    def test_frozen_and_legacy_strings_stay(self):
        self.apply()
        main = self.read("src/main.go")
        for keep in ['"%s-oauth2-session-v1"' % OLD_L, '"%s-rule:"' % OLD_L, '"%s_csrf"' % OLD_L,
                     '"X-%s-Plugin-Token"' % OLD, 'SYSTEM_NAME = "%s"' % OLD,
                     'fmt.Println("%s" + "x") // legacy-compat' % OLD]:
            self.assertIn(keep, main)
        self.assertIn('"X-Dunree-Internal-Ref"', main, "the in-process context key is a plain rename")
        guide = self.read("docs/guide.md")
        self.assertIn("/.%s/health" % OLD_L, guide)
        self.assertIn("`X-%s-Ref`" % OLD, guide)
        self.assertIn("X-%s-Whatever is listed here. <!-- rebrand:keep --> %s stays" % (OLD, OLD), guide)
        self.assertIn("DUNREE_BIN", guide)
        self.assertIn("%s_EVENT" % OLD_U, guide, "hook environment names are a wire surface")
        html = self.read("src/web/index.html")
        self.assertIn('name="%s.csrf.Token"' % OLD_L, html)
        self.assertIn("'%s_menu_groups'" % OLD_L, html)
        self.assertIn('href="https://%s.aroz.org"' % OLD_L, html)

    def test_identifiers_and_sdk_package(self):
        self.apply()
        main = self.read("src/main.go")
        self.assertIn("func collectDunreeMetrics() {", main)
        self.assertIn('"Dunree started", dunree_plugin.DunreePort', main)
        sdk = self.read("src/mod/plugins/dunree_plugin/dunree_plugin.go")
        self.assertIn("package dunree_plugin", sdk)
        self.assertIn('DunreePort int `json:"%s_port"`' % OLD_L, sdk, "identifier renamed, wire name kept")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "src/mod/plugins", OLD_SDK)))
        ex = self.read("example/plugins/hello/main.go")
        self.assertIn('plugin "example.com/dunree/hello/mod/dunree_plugin"', ex)
        self.assertEqual(self.read("example/plugins/hello/go.mod").split("\n")[0], "module example.com/dunree/hello")
        self.assertTrue(os.path.exists(os.path.join(self.dir, "example/plugins/hello/mod/dunree_plugin/dunree_plugin.go")))
        # frozen fixture keeps its directory and its package name
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "src/mod/plugins/testdata/sdk-1.0.0", OLD_SDK)))

    def test_renames_are_git_moves(self):
        self.apply()
        st = subprocess.run(["git", "status", "--porcelain"], cwd=self.dir, stdout=subprocess.PIPE,
                            universal_newlines=True).stdout
        self.assertNotIn("?? src/mod/plugins/dunree_plugin", st, "moved files must be known to git:\n" + st)
        self.assertNotIn("?? docs/nginx2dunree.html", st, st)
        tracked = subprocess.run(["git", "ls-files"], cwd=self.dir, stdout=subprocess.PIPE,
                                 universal_newlines=True).stdout.split("\n")
        self.assertIn("src/mod/plugins/dunree_plugin/dunree_plugin.go", tracked)
        self.assertIn("docs/nginx2dunree.html", tracked)
        self.assertNotIn("src/mod/plugins/%s/%s.go" % (OLD_SDK, OLD_SDK), tracked)
        self.assertIn('href="./nginx2dunree.html"', self.read("docs/nginx2dunree.html"))
        log = subprocess.run(["git", "log", "--oneline"], cwd=self.dir, stdout=subprocess.PIPE,
                             universal_newlines=True).stdout.strip().split("\n")
        self.assertEqual(len(log), 1, "the tool must never commit")

    def test_locale_keys_and_values_move_together(self):
        r = self.apply()
        en = json.loads(self.read("src/web/locales/en.json"))["strings"]
        self.assertIn("Welcome to Dunree", en)
        self.assertEqual(en["Welcome to Dunree"], "Welcome to Dunree")
        self.assertNotIn("Welcome to %s" % OLD, en)
        self.assertIn("%s is developed by tobychui for imuslab" % OLD, en, "attribution key stays")
        de = json.loads(self.read("src/web/locales/de.json"))["strings"]
        self.assertEqual(list(de), ["Welcome to Dunree"], "a renamed key that already exists must not be duplicated")
        self.assertIn("key collision", r.stdout)
        self.assertIn("src/web/locales/de.json", r.stdout)
        self.assertNotEqual(r.returncode, 0, "a collision is reported as a problem")
        self.assertEqual(json.loads(self.read("src/web/locales/de.json"))["_meta"]["language"], "German")

    def test_second_run_changes_nothing(self):
        self.apply()
        first = tree(self.dir)
        r = run(self.dir, "--apply", "--no-gofmt")
        self.assertIn("Changed 0 files", r.stdout, r.stdout)
        self.assertEqual(first, tree(self.dir))
        self.assertEqual(run(self.dir, "--check").returncode, 0)

    def test_left_report_names_the_reason(self):
        self.apply()
        r = run(self.dir, "--left")
        self.assertEqual(r.returncode, 0, r.stdout)
        for tag in ["[allow:cookies]", "[allow:plugin-headers]", "[protect:frozen-crypto-oauth2]",
                    "[attribution-line]", "[keep-marker]", "In globally excluded files"]:
            self.assertIn(tag, r.stdout)
        self.assertNotIn("PENDING", r.stdout)


class Repo(unittest.TestCase):
    """Checks on the real tree."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "policy.json"), encoding="utf-8") as fh:
            cls.policy = json.load(fh)

    def text(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_pass_is_fully_applied(self):
        r = run(ROOT, "--check")
        self.assertEqual(r.returncode, 0, "tools/rebrand/rename.py would still change files:\n" + r.stdout[-3000:])

    def test_no_leftover_in_the_audit(self):
        # tools/rebrand/leftover_audit.py classes every mention of the old names; none may be a LEFTOVER
        r = subprocess.run([sys.executable, os.path.join(HERE, "leftover_audit.py"), "--check", "-v"], cwd=ROOT,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(r.returncode, 0, "leftovers of the old names:\n" + r.stdout[-3000:])

    def test_notice_is_accurate(self):
        notice = self.text("NOTICE")
        for want in ["Dunree", "Foley IT", "tobychui", "imuslab", "Zoraxy v3.3.6", "not affiliated with, sponsored by or endorsed by",
                     "modified, independent derivative", "did not write, review or approve", "GNU Affero General Public License"]:
            self.assertIn(want, notice)
        self.assertEqual(notice, self.text("src/web/legal/NOTICE.txt"), "the copy served by the About page differs")

    def test_module_root_matches_policy(self):
        root = self.policy["variables"]["MODULE_ROOT"]
        self.assertEqual(self.text("src/go.mod").split("\n")[0].strip(), "module " + root)
        for rel in ["tools/nt6.1_go_mod/NT_61_3.0.6.go.mod", "tools/nt6.1_go_mod/NT_61_3.0.7go.mod",
                    "tools/nt6.1_go_mod/NT_61_3.1.0go.mod"]:
            self.assertEqual(self.text(rel).split("\n")[0].strip(), "module " + root, rel)
        for rel in ["tools/benchmark/go.mod", "tools/plugin-check/go.mod", "tools/websocket_echo/go.mod",
                    "tools/header_test_server/go.mod", "docs/plugins/go.mod"]:
            self.assertTrue(self.text(rel).split("\n")[0].startswith("module " + root + "/"), rel)
        out = subprocess.run(["git", "-C", ROOT, "grep", "-l", "-F", self.policy["variables"]["LEGACY_MODULE_ROOT"] + "/",
                              "--", "*.go", "*go.mod", ":!src/mod/plugins/testdata/sdk-1.*"],
                             stdout=subprocess.PIPE, universal_newlines=True).stdout.strip()
        self.assertEqual(out, "", "old module path still imported in:\n" + out)

    def test_legal_files_untouched(self):
        for rel in ["LICENSE", "THIRD_PARTY_NOTICES.md"]:
            head = subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + rel], stdout=subprocess.PIPE).stdout
            with open(os.path.join(ROOT, rel), "rb") as fh:
                self.assertEqual(hashlib.sha256(head).hexdigest(), hashlib.sha256(fh.read()).hexdigest(), rel)
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", self.text("LICENSE"))

    def test_readme_credits_upstream(self):
        readme = self.text("README.md")
        self.assertIn("# Dunree", readme)
        self.assertRegex(readme, r"based on %s v3\.3\.6" % OLD)
        for word in ["tobychui", "imuslab", "not endorsed", "https://github.com/tobychui/" + OLD_L]:
            self.assertIn(word, readme)

    def test_frozen_strings_still_in_the_source(self):
        where = {
            OLD_L + "-oauth2-session-v1": "src/mod/auth/sso/oauth2/session.go",
            OLD_L + "-cluster-v1": "src/mod/cluster/keys.go",
            OLD_L + "-captcha-session-v1|": "src/mod/dynamicproxy/captcha/captcha.go",
            OLD_L + "-rule:": "src/mod/plugins/ruleinfo.go",
            OLD_L + "-plugin-index": "src/mod/plugins/store_verify.go",
            "# " + OLD_L + "-release ": "src/mod/updater/verify.go",
        }
        listed = {f["string"] for f in self.policy["frozen"]}
        for s, rel in where.items():
            self.assertIn(s, listed, "policy.json no longer lists %r as frozen" % s)
            self.assertIn(s, self.text(rel), "%r is gone from %s" % (s, rel))

    def test_legacy_surfaces_still_in_the_source(self):
        """One witness per class: a blind replace that slipped past the allowlist fails here."""
        for needle, rel in [
            ('SYSTEM_NAME    = "%s"' % OLD, "src/def.go"),
            ('"/.%s/health"' % OLD_L, "src/mod/cluster/health.go"),
            ('"/.%s/captcha/verify"' % OLD_L, "src/mod/dynamicproxy/captcha/captcha.go"),
            # metrics are written as dunree_* and doubled under this prefix (mod/metrics/expose.go, Registry.Write)
            ('LegacyMetricPrefix = "%s_"' % OLD_L, "src/mod/wirecompat/wirecompat.go"),
            ('LegacyHeaderPrefix = "X-%s-"' % OLD, "src/mod/wirecompat/wirecompat.go"),
            ('LegacyPathPrefix = "/.%s"' % OLD_L, "src/mod/wirecompat/wirecompat.go"),
            ('"%s-HealthCheck"' % OLD, "src/mod/dynamicproxy/loadbalance/healthcheck.go"),
            ('json:"%s_port' % OLD_L, "src/mod/plugins/dunree_plugin/dunree_plugin.go"),
            ('"X-%s-' % OLD, "src/mod/plugins/hooks_validate.go"),
            ('%s.csrf.Token' % OLD_L, "src/web/index.html"),
            ('container-identifier="%s"' % OLD, "docker/Dockerfile"),
            # persisted names and derivation labels found by the leftover audit (docs/rebrand/leftover-audit.md)
            ('"%s-aiassist-apikey-v1"' % OLD_L, "src/mod/aiassist/secret.go"),
            ('"%s-aiassist-fallback"' % OLD_L, "src/mod/aiassist/secret.go"),
            ('"%s-crowdsec-machine-v1"' % OLD_L, "src/mod/crowdsec/vault.go"),
            ('"%s-crowdsec-apikey-v1"' % OLD_L, "src/mod/crowdsec/vault.go"),
            ('"%s-waf-challenge|"' % OLD_L, "src/mod/dynamicproxy/waf_challenge.go"),
            ('snapshotFormat    = "%s-cluster-snapshot"' % OLD_L, "src/mod/cluster/snapshot.go"),
            ('ManifestFmt   = "%s-config-export"' % OLD_L, "src/mod/confpack/manifest.go"),
            ('Format: "%s-history-diff"' % OLD_L, "src/mod/confhistory/api.go"),
            ('previousDirName = ".%s-previous"' % OLD_L, "src/mod/plugins/store_safe.go"),
            ('return "%s-plugin-" + scopeSafeID' % OLD_L, "src/mod/plugins/limits_linux.go"),
            ('CustomEvent("%s:i18n"' % OLD_L, "src/web/script/i18n.js"),
            ('CustomEvent("%s:theme")' % OLD_L, "src/web/script/darktheme.js"),
            ('LegacyCookieName       = "%s_captcha_session"' % OLD_L, "src/mod/dynamicproxy/captcha/captcha.go"),
            ('LegacyBackupPrefix = "%s-pre-update-"' % OLD_L, "src/mod/updater/backupname.go"),
            ('LegacyEnvPrefix = "%s_"' % OLD_U, "src/mod/wirecompat/values.go"),
            ('MDNS_LEGACY_HOSTNAME_PREFIX  = "%s_"' % OLD_L, "src/def.go"),
        ]:
            self.assertIn(needle, self.text(rel), "%r is gone from %s" % (needle, rel))

    def test_allowlist_lines_are_well_formed(self):
        ids = set()
        with open(os.path.join(HERE, "legacy-allow.txt"), encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                parts = re.split(r"\t+| {2,}", line.strip(), maxsplit=2)
                self.assertEqual(len(parts), 3, "line %d needs id, regex and reason" % n)
                self.assertNotIn(parts[0], ids, "line %d: duplicate id %s" % (n, parts[0]))
                ids.add(parts[0])
                re.compile(parts[1])
                self.assertRegex(parts[2], r"rows? \d+", "line %d: the reason must name a plan row" % n)

    def test_locales_hold_no_unprotected_old_name(self):
        loc = os.path.join(ROOT, "src", "web", "locales")
        for f in sorted(os.listdir(loc)):
            if not f.endswith(".json"):
                continue
            with open(os.path.join(loc, f), encoding="utf-8") as fh:
                strings = json.load(fh)["strings"]
            for k, v in strings.items():
                for s in (k, v):
                    if OLD in s and not re.search(r"tobychui|imuslab|X-%s-|Cloudflare WAF|GitHub|Wiki" % OLD, s) \
                            and OLD in self._mask_protected(s):
                        self.fail("%s: old name in %r" % (f, s[:120]))

    def _mask_protected(self, s):
        """s with every span that rename.py itself never rewrites (policy.json "protect" regexes and
        legacy-allow.txt lines) blanked out, so attribution such as "based on <old name>" or
        "supporters of <old name>" is accepted the same way the rename pass accepts it."""
        pats = getattr(self, "_protect_pats", None)
        if pats is None:
            pats = []
            with open(os.path.join(HERE, "policy.json"), encoding="utf-8") as fh:
                pats += [p["regex"] for p in json.load(fh).get("protect", [])]
            with open(os.path.join(HERE, "legacy-allow.txt"), encoding="utf-8") as fh:
                for line in fh:
                    if line.strip() and not line.lstrip().startswith("#"):
                        parts = re.split(r"\t+| {2,}", line.strip(), maxsplit=2)
                        if len(parts) == 3:
                            pats.append(parts[1])
            pats = [re.compile(p) for p in pats]
            self._protect_pats = pats
        for p in pats:
            s = p.sub(lambda m: " " * len(m.group(0)), s)
        return s


if __name__ == "__main__":
    unittest.main(verbosity=1)
