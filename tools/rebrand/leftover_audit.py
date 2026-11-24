#!/usr/bin/env python3
# Dunree rebrand - final leftover audit.
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Classify every remaining mention of the old names in the repository.

    tools/rebrand/leftover_audit.py                 print the counts per class
    tools/rebrand/leftover_audit.py -v              ... and every LEFTOVER with file:line
    tools/rebrand/leftover_audit.py --write         also (re)write docs/rebrand/leftover-audit.md
    tools/rebrand/leftover_audit.py --check         exit 1 when anything is classed LEFTOVER

What is scanned: the same files as `git grep -I -i --untracked` (tracked and untracked, not ignored, not
binary), for the words zoraxy, imuslab, tobychui and aroz, case-insensitive.  Every single match gets
exactly one class:

    attribution     credit of the upstream project and its authors (NOTICE, licence headers, "based on")
    legacy-compat   a name an existing install, plugin, peer, monitor or signed file depends on; kept on
                    purpose, with Dunree's own name next to it, and covered by a test (group table below)
    historical      changelog, triage notes, rebrand records, references to upstream issues and releases
    third-party     names of things other people own (upstream's store, website, image, third-party plugins)
    LEFTOVER        none of the above: must be renamed

The class of a match comes from, in this order: the file it is in (PATHS), an audit rule for the exact
line (LINES), and the span rename.py itself claims for it (its protect list, legacy-allow.txt and the
"rebrand:keep" / "// legacy-compat" markers; see TAGS).  Anything rename.py leaves unclaimed or only
claims for a manual rule is a LEFTOVER unless an audit rule says otherwise.
"""
import argparse
import collections
import fnmatch
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rename  # noqa: E402  (same folder)

ROOT = rename.ROOT
DOC = os.path.join(ROOT, "docs", "rebrand", "leftover-audit.md")
# hand-written part of the report (the other checks of the final audit), appended as it is
CHECKS = os.path.join(HERE, "leftover-audit-checks.md")
WORDS = re.compile(r"(?i)zoraxy|imuslab|tobychui|aroz")
CLASSES = ["attribution", "legacy-compat", "historical", "third-party", "LEFTOVER"]

# ---------------------------------------------------------------------------------------------- 1. files
# (glob, class, group, why).  First match wins.
PATHS = [
    ("LICENSE", "attribution", "legal-files", "licence text, never edited"),
    ("NOTICE", "attribution", "legal-files", "credits Zoraxy by tobychui and imuslab; says Dunree is not endorsed"),
    ("src/web/legal/NOTICE.txt", "attribution", "legal-files", "copy of NOTICE served by the About page"),
    ("THIRD_PARTY_NOTICES.md", "third-party", "third-party-notices", "licences of bundled components"),
    ("src/web/legal/THIRD_PARTY_NOTICES.txt", "third-party", "third-party-notices", "copy served by the About page"),
    ("third_party/**", "third-party", "third-party-notices", "vendored licence texts"),
    ("src/web/script/supporters.txt", "attribution", "upstream-supporters", "people who supported the Zoraxy project"),
    ("brand/README.md", "attribution", "brand-rules", "brand rules: what may and may not be said about Zoraxy"),
    ("src/mod/brand/**", "attribution", "brand-package", "the one place the product's credit line, upstream name and URL are defined"),
    ("README.md", "attribution", "readme", "'Based on Zoraxy v3.3.6', licence and attribution section, migration section"),
    ("SECURITY.md", "attribution", "readme", "says Dunree reports do not go to the Zoraxy project"),
    ("CONTRIBUTING.md", "attribution", "readme", "says which code came from Zoraxy and must keep its headers"),
    ("CODEOWNERS", "attribution", "readme", "comment that names the upstream maintainers as not owners of this repo"),
    ("ROADMAP.md", "historical", "roadmap", "compatibility goals with Zoraxy builds and plugins"),
    ("CHANGELOG.md", "historical", "changelog", "release history, kept as written"),
    ("**/CHANGELOG.md", "historical", "changelog", "SDK release history, kept as written"),
    ("docs/triage/**", "historical", "triage", "triage of upstream issues, references by number"),
    ("docs/rebrand/**", "historical", "rebrand-records", "plan and audit of this rename"),
    ("docs/roadmap-history.md", "historical", "roadmap", "history of the roadmap before the rename"),
    ("docs/verification/**", "historical", "verification-records", "recorded test runs from before the rename"),
    ("docs/README.md", "historical", "upstream-website", "explains which files in docs/ are the old Zoraxy website"),
    # The old upstream website, taken over with the code and not published by Dunree (docs/README.md,
    # docs/ux/changes.md "Dunree rebrand").  docs/CNAME was deleted so this folder can never claim its address.
    ("docs/index.html", "historical", "upstream-website", "source of the Zoraxy project website; not published by Dunree"),
    ("docs/index_legacy.html", "historical", "upstream-website", "source of the old Zoraxy project website; not published"),
    ("docs/zorxauth.html", "historical", "upstream-website", "page of the Zoraxy project website; not published"),
    ("docs/main.js", "historical", "upstream-website", "script of the Zoraxy project website; not published"),
    ("docs/nginx2dunree.html", "historical", "upstream-website", "converter page of the Zoraxy project website (\"Part of the Zoraxy project\"); not published"),
    ("docs/plugins/conformance-reports/**", "historical", "verification-records", "stored conformance reports made before the rename"),
    ("**/go.sum", "third-party", "coincidental-bytes", "checksums of third-party modules; the letters occur inside a hash"),
    ("tools/rebrand/**", "legacy-compat", "rebrand-tooling", "rule tables of the rename itself; tested by tools/rebrand/test_rename.py"),
    ("src/mod/plugins/testdata/sdk-1.*/**", "legacy-compat", "old-sdk-fixtures", "frozen copies of the Zoraxy plugin SDK 1.0.0/1.1.0/1.2.0; old plugins are built from them in the contract tests"),
    ("src/mod/plugins/testdata/sdkplugin/**", "legacy-compat", "old-sdk-fixtures", "fixture plugin built against the frozen old SDKs"),
    ("src/mod/plugins/testdata/chaosplugin/**", "legacy-compat", "old-sdk-fixtures", "fault-injection plugin built against the legacy SDK package"),
    ("src/mod/plugins/testdata/manifests/installed/**", "third-party", "third-party-plugins", "manifests of real third-party plugins, used as fixtures"),
    ("src/mod/plugins/testdata/manifests/examples/**", "attribution", "upstream-example-plugins", "author, contact and ID fields of the example plugins the Zoraxy authors wrote (introspect fixtures, example code, plugin docs)"),
    ("src/mod/plugins/zoraxy_plugin/**", "legacy-compat", "legacy-sdk-package", "deprecated Zoraxy SDK package kept for plugin authors (plan row 22)"),
    ("docs/migrating-from-zoraxy.md", "legacy-compat", "migration", "how an existing Zoraxy install becomes Dunree"),
    ("tools/install/migrate-from-zoraxy.sh", "legacy-compat", "migration", "migration script for existing Zoraxy installs; tested by legacycompat/migratescript_test.go"),
    ("src/mod/legacycompat/**", "legacy-compat", "legacycompat-package", "the code that reads the old names on existing installs, and its tests"),
    ("src/mod/wirecompat/**", "legacy-compat", "wirecompat-package", "the code that emits the old wire names while legacy_emit is ON, and its tests"),
    ("src/mod/upstreamguard/**", "third-party", "upstream-guard", "the test that fails when product code calls an upstream host; it has to name those hosts"),
    ("src/brandweb_test.go", "legacy-compat", "brand-tests", "asserts the credit to tobychui/imuslab and the absence of the old name in the UI"),
    ("tools/ui-smoke/brand_smoke.py", "legacy-compat", "brand-tests", "same assertions in the browser"),
    ("docs/deploy/zoraxy.service", "legacy-compat", "systemd-legacy-unit", "the unit file of existing installs, documented as legacy (plan row 38)"),
    ("src/mod/auth/sso/deprecated/*/README.txt", "historical", "upstream-history", "'Original implementation: tobychui/zoraxy#NNN'"),
    (".gitignore", "legacy-compat", "build-outputs", "old build output names stay ignored so an old checkout's binaries are never committed"),
]

# ---------------------------------------------------------------------------------------------- 2. lines
# (path glob, line regex, class, group, why).  For matches that rename.py leaves unclaimed or claims only
# for a manual rule, after a person read the line.
LINES = [
    # names of other people's things
    ("**", r"zoraxy-community", "third-party", "zoraxy-community-store",
     "store source kind of the Zoraxy community store (a third-party source on migrated installs)"),
    ("src/web/components/appstore.html", r"includes\(\"aroz\"\)", "third-party", "zoraxy-community-store",
     "recognises plugins of the Zoraxy community store by their author field"),
    ("**", r"zoraxy-cloudflare-waf|zoraxyresourcemonitor|zoraxy_cf_waf_blocklist|/srv/zoraxy/log", "third-party", "third-party-plugins",
     "names and defaults of third-party plugins"),
    ("**", r"ArozOS|arozos|t\.me/ArOZBeta", "third-party", "upstream-website", "upstream's other projects"),
    ("docs/plugins/conformance.md", r"zoraxy-plugin-check", "historical", "verification-records",
     "names the tool under which the stored conformance reports were made"),
    # the letters occur inside random data, not as a name
    ("**", r"base64,|h1:[A-Za-z0-9+/=]{20,}", "third-party", "coincidental-bytes",
     "the letters occur inside base64 image data or a go.sum checksum; not a name"),
    # upstream example plugins: their author field credits upstream
    ("example/plugins/*/main.go", r"aroz\.org|aroz-online", "attribution", "upstream-example-plugins",
     "author and contact fields of the example plugins written by the Zoraxy authors"),
    ("docs/plugins/**", r"aroz\.org", "attribution", "upstream-example-plugins",
     "the same author fields quoted in the plugin documentation"),
    ("src/mod/database/database.go", r"(?i)aroz online", "attribution", "upstream-module-headers",
     "header of a module tobychui wrote for ArOZ Online, kept with its author line"),
    # tests that prove upstream is not contacted have to name upstream
    ("**", r"aroz\.org|aroz-online|zoraxydocker|github\.com/tobychui", "third-party", "upstream-guard",
     "a test or check that fails when an upstream host appears; it names the host it looks for"),
    # frozen derivation labels found by this audit
    ("src/mod/aiassist/secret.go", r"zoraxy-aiassist-fallback", "legacy-compat", "frozen-crypto",
     "key-derivation fallback label of sealed AI-assist secrets; changing it makes stored keys unreadable"),
    # tests and code that keep the old process, unit and file names on purpose
    ("src/mod/instance/*_test.go", r"zoraxy", "legacy-compat", "binary-and-unit-names",
     "an install updated in place keeps the file name zoraxy and the unit zoraxy.service (plan rows 37, 38); the doctor must still recognise it"),
    ("src/mod/plugins/fault_review_linux_test.go", r"zoraxy", "legacy-compat", "binary-and-unit-names",
     "cgroup parsing of units of existing installs (zoraxy.service, zoraxy@.service)"),
    ("src/mod/adminallow/adminallow_test.go", r"zoraxy-", "legacy-compat", "identity-values",
     "proves the X-Forwarded-Server value of older builds no longer decides access"),
    ("src/mod/plugins/hooks_test.go", r"X-Zoraxy-Plugin-Token", "legacy-compat", "plugin-headers",
     "a plugin may not set the legacy invoke-token header either"),
    ("**", r'UserAgent\("', "legacy-compat", "user-agents", "the inherited User-Agent token, appended while legacy_emit is ON"),
    ("src/start.sh", r".", "legacy-compat", "binary-and-unit-names", "start.sh recognises the unit and file name of an upgraded install (TestStartScriptKnowsBothNames)"),
    ("src/startsh_test.go", r".", "legacy-compat", "binary-and-unit-names", ""),
    ("contrib/crowdsec/**", r".", "legacy-compat", "crowdsec-helper-legacy",
     "the helper keeps the acquisition file and key name an earlier run created (test_crowdsec_setup.py)"),
    ("docker/**", r".", "legacy-compat", "container-legacy-layout",
     "the image answers on /opt/zoraxy and zoraxy for containers created from the older image (test_entrypoint.py)"),
    ("src/Makefile", r".", "legacy-compat", "release-assets", ""),
    ("tools/ui-polish/instance.sh", r"zoraxy", "legacy-compat", "build-outputs", "removes the cached binary under its earlier name"),
    ("src/mod/plugins/chaos_helper_test.go", r"zoraxy-chaos", "legacy-compat", "build-outputs", "sweeps build folders of runs before the rename"),
    ("src/dunreecompat.go", r"migrating-from-zoraxy", "legacy-compat", "migration", "points to the migration document"),
    ("packaging/**", r"migrate-from-zoraxy", "legacy-compat", "migration", "points to the migration script"),
    # lines that explain the old name kept for an upgraded install, next to the Dunree name
    ("**", r"(?i)upgraded (in place|from zoraxy)|upgraded install|before the rename|earlier (zoraxy|build|run|name)|older (zoraxy|dockerfile|builds?)|"
           r"existing installs|kept file name|old file name|legacy names are on|legacy-compat|rebrand:keep|from zoraxy|zoraxy-compatible",
     "legacy-compat", "upgrade-notes", "a line that explains (or implements) the old name that an install upgraded from Zoraxy keeps, next to the Dunree name"),
    # comments about the history of the code
    ("src/reverseproxy.go", r"really old version of zoraxy", "historical", "upstream-history",
     "comment about configs written by old Zoraxy versions"),
    ("docs/ux/changes.md", r".", "historical", "ux-changelog", "change log of the admin interface; earlier entries stay as written"),
    ("docs/plugins/contract.md", r".", "legacy-compat", "plugin-contract-doc", "section 10 of the plugin contract documents both sets of names"),
    ("src/mod/metrics/legacy_names_test.go", r".", "legacy-compat", "metrics", "metrics legacy-name test"),
]

# ---------------------------------------------------------------------------------------------- 3. tags
# rename.py claim tag -> class.  allow:* default to legacy-compat (legacy-allow.txt gives each id's reason).
TAGS = {
    "attribution-line": ("attribution", "attribution-lines"),
    "protect:attr-copyright": ("attribution", "copyright-headers"),
    "protect:attr-author-line": ("attribution", "copyright-headers"),
    "protect:attr-added-by": ("attribution", "attribution-lines"),
    "protect:attr-based-on": ("attribution", "attribution-lines"),
    "protect:attr-names": ("attribution", "attribution-lines"),
    "protect:history-issue-links": ("historical", "upstream-history"),
    "allow:historic-release": ("historical", "upstream-history"),
    "allow:historic-contributor": ("attribution", "attribution-lines"),
    "allow:credit-supporters": ("attribution", "upstream-supporters"),
    "allow:third-party-names": ("third-party", "third-party-names"),
    "allow:third-party-article": ("third-party", "third-party-names"),
    "allow:store-repo": ("third-party", "zoraxy-community-store"),
    "allow:store-index-url": ("third-party", "zoraxy-community-store"),
    "allow:upstream-site": ("third-party", "upstream-links"),
    "allow:upstream-repo": ("third-party", "upstream-links"),
    "allow:upstream-short": ("third-party", "upstream-links"),
    "allow:docker-upstream": ("third-party", "upstream-image"),
    "protect:legacy-compat-tests": ("legacy-compat", "marked-legacy-compat"),
    "keep-marker": ("legacy-compat", "keep-marked-docs"),
}


# ---------------------------------------------------------------------------------------------- 4. tests
# The test that keeps each legacy-compat group working (or why there is none).
TESTS = {
    "marked-legacy-compat": "the lines carry `// legacy-compat`; they are the compat code and its tests: mod/wirecompat, mod/legacycompat, mod/plugins/dunree_wire_test.go, sdk_dunree_test.go, cluster/dynamicproxy/notify dunree_wire_test.go",
    "rebrand-tooling": "tools/rebrand/test_rename.py",
    "old-sdk-fixtures": "mod/plugins/sdk_dunree_test.go and phase2_contract_test.go build plugins from testdata/sdk-1.x",
    "legacy-sdk-package": "mod/plugins/sdk_dunree_test.go",
    "keep-marked-docs": "documentation of a legacy surface (no code); the surface itself is tested under its own group",
    "plugin-headers": "mod/plugins/dunree_wire_test.go, hooks_test.go",
    "brand-tests": "src/brandweb_test.go, tools/ui-smoke/brand_smoke.py (they are the tests)",
    "csrf-meta": "src/brandweb_test.go (both meta tags), mod/plugins/phase2_store_test.go",
    "plugin-fields": "mod/plugins/sdk_dunree_test.go, dunree_wire_test.go (configure payload golden test)",
    "migration": "mod/legacycompat/migratescript_test.go, migratescript_linux_test.go",
    "plugin-ids": "persisted IDs of installed plugins; mod/plugins/phase3_reference_test.go loads the fork.zoraxy.ref.* examples by ID",
    "binary-name": "mod/instance/doctor_linux_test.go (IsDunreeName), unitname_test.go, startsh_test.go",
    "binary-and-unit-names": "mod/instance/unitname_test.go, doctor_linux_test.go, holder_test.go, startsh_test.go",
    "release-assets": "mod/updater/version_verify_test.go, flow_test.go, tools/sign_release_test.go, tools/build_release_test.sh",
    "release-asset-globs": "mod/instance/doctor_linux_test.go (IsDunreeName), mod/metrics/legacy_names_test.go, tools/sign_release_test.go",
    "release-checksum": "src/Makefile dev target only; no installed updater reads it",
    "legacycompat-package": "its own *_test.go",
    "wirecompat-package": "mod/wirecompat/wirecompat_test.go, values_test.go",
    "install-paths": "packaging/test.sh, docker/test_entrypoint.py, mod/legacycompat/migratescript_test.go",
    "systemd-unit": "mod/instance/parse_test.go, holder_test.go, startsh_test.go, packaging/test.sh",
    "systemd-legacy-unit": "documentation file for existing installs; packaging/test.sh lints the Dunree unit",
    "well-known-paths": "mod/dynamicproxy/dunree_wire_test.go (both prefixes answer), mod/cluster/dunree_wire_test.go",
    "env-input-vars": "src/wirecompatapi_test.go (metrics token), mod/legacycompat/env_test.go, tools/sign_release_test.go",
    "env-hook-vars": "mod/notify/hookenv_dunree_test.go",
    "frozen-strings": "tools/rebrand/test_rename.py Repo.test_frozen_strings_still_in_the_source",
    "frozen-crypto-more": "tools/rebrand/test_rename.py Repo.test_legacy_surfaces_still_in_the_source",
    "frozen-crypto": "tools/rebrand/test_rename.py Repo.test_legacy_surfaces_still_in_the_source",
    "public-headers": "mod/dynamicproxy/dunree_wire_test.go, mod/notify/dunree_wire_test.go",
    "headers-wildcard": "prose naming the legacy headers; headers tested under public-headers / plugin-headers",
    "headers-any": "mod/plugins/dunree_wire_test.go, mod/wirecompat/wirecompat_test.go",
    "headers-lowercase": "mod/dynamicproxy/dunree_wire_test.go",
    "cluster-headers": "mod/cluster/dunree_wire_test.go",
    "updater-previous": "mod/plugins/phase2_store_test.go, phase2_store_review_test.go; mod/updater/flow_test.go",
    "updater-backups": "mod/updater/backupname_test.go",
    "upgrade-notes": "explanatory lines next to the code they describe; tested under the group of that code",
    "user-agents": "mod/wirecompat/values_test.go (helper and source scan)",
    "identity-values": "mod/dynamicproxy/dpcore/identity_test.go, mod/auth/sso/zorxauth/authmethod_dunree_test.go, adminallow_test.go",
    "docker-label": "packaging/test.sh; tools/rebrand/test_rename.py Repo.test_legacy_surfaces_still_in_the_source",
    "docker-label-value": "packaging/test.sh",
    "container-legacy-layout": "docker/test_entrypoint.py, packaging/test.sh",
    "plugin-scope-units": "mod/plugins/fault_review_linux_test.go; tools/rebrand/test_rename.py (pinned)",
    "ui-events": "tools/rebrand/test_rename.py (pinned); plugin pages listen to these events",
    "crowdsec-helper-legacy": "contrib/crowdsec/test_crowdsec_setup.py",
    "crowdsec-scenario": "mod/crowdsec/scenario_dunree_test.go, admin_test.go",
    "release-key-dirs": "tools/sign_release_test.go",
    "confpack-field": "src/confbackup_test.go",
    "update-repo": "policy variable UPDATE_REPO (deliberate until a Dunree repository has releases); mod/updater tests",
    "build-outputs": "ignore patterns and cache cleanup only",
    "format-ids": "tools/rebrand/test_rename.py (pinned); confbackup_test.go, cluster tests read them",
    "config-export-names": "-",
    "localstorage": "tools/ui-smoke/storage_migration_smoke.py, src/storagekeys_test.go",
    "cookies": "mod/dynamicproxy/captcha/cookie_dunree_test.go, challenge_cookie_dunree_test.go, mod/legacycompat/csrfcookie_test.go",
    "mdns": "src/mdnsnames_test.go",
    "mdns-hostname": "src/mdnsnames_test.go",
    "metrics": "mod/metrics/legacy_names_test.go",
    "metrics-realm": "mod/metrics/legacy_names_test.go",
    "admin-cookie": "mod/auth/legacy_session_test.go",
    "sdk-fixture-paths": "mod/plugins/sdk_dunree_test.go",
    "plugin-contract-doc": "documentation; the contract is tested by mod/plugins/phase2_contract_test.go",
    "zrok-share-prefix": "-",
}


def render_markdown(rows, why):
    by_class = collections.Counter(r[3] for r in rows)
    files = collections.defaultdict(set)
    groups = collections.defaultdict(collections.Counter)
    gfiles = collections.defaultdict(set)
    words = collections.Counter(r[2].lower() for r in rows)
    for r in rows:
        files[r[3]].add(r[0])
        groups[r[3]][r[4]] += 1
        gfiles[(r[3], r[4])].add(r[0])
    out = []
    w = out.append
    w("# Dunree rebrand: leftover audit")
    w("")
    w("Generated by `tools/rebrand/leftover_audit.py --write` (do not edit by hand; rerun it). The scan covers the same files")
    w("as `git grep -I -i --untracked` and every match of `zoraxy`, `imuslab`, `tobychui` and `aroz`, case-insensitive.")
    w("`tools/rebrand/test_rename.py` runs `leftover_audit.py --check`, which fails on any LEFTOVER.")
    w("")
    w("## Counts")
    w("")
    w("| Class | Matches | Files |")
    w("|---|---:|---:|")
    for c in CLASSES:
        w("| %s | %d | %d |" % (c, by_class[c], len(files[c])))
    w("| **total** | **%d** | **%d** |" % (len(rows), len(set(r[0] for r in rows))))
    w("")
    w("By word: " + ", ".join("`%s` %d" % kv for kv in sorted(words.items())) + ".")
    w("")
    w("Classes: **attribution** credits the upstream project and its authors; **legacy-compat** is a name an existing")
    w("install, plugin, peer, monitor or signed file depends on, kept next to the Dunree name and tested; **historical** is")
    w("changelog, triage and records; **third-party** names things other people own; **LEFTOVER** must be renamed.")
    for c in CLASSES:
        w("")
        w("## %s" % c)
        w("")
        if not groups[c]:
            w("None.")
            continue
        if c == "legacy-compat":
            w("| Group | Matches | Files | Why it stays | Test |")
            w("|---|---:|---:|---|---|")
            for g, n in groups[c].most_common():
                w("| `%s` | %d | %d | %s | %s |" % (g, n, len(gfiles[(c, g)]), why.get((c, g), "").replace("|", "\\|"),
                                                 TESTS.get(g, "").replace("|", "\\|")))
        else:
            w("| Group | Matches | Files | Justification |")
            w("|---|---:|---:|---|")
            for g, n in groups[c].most_common():
                w("| `%s` | %d | %d | %s |" % (g, n, len(gfiles[(c, g)]), why.get((c, g), "").replace("|", "\\|")))
    if os.path.exists(CHECKS):
        w("")
        with open(CHECKS, encoding="utf-8") as fh:
            w(fh.read().rstrip("\n"))
    return "\n".join(out) + "\n"


TAG_WHY = {
    ("attribution", "attribution-lines"): "the line names tobychui or imuslab: a credit ('based on Zoraxy by tobychui and imuslab', 'Added in Zoraxy vX by tobychui')",
    ("attribution", "copyright-headers"): "upstream copyright and Author: headers, kept in the files they belong to",
    ("historical", "upstream-history"): "references to upstream issues, pull requests and releases",
    ("third-party", "upstream-links"): "links a person clicks to upstream's repository or site, in attribution context or in the unpublished upstream example data; the guard test proves none is fetched",
    ("third-party", "upstream-image"): "upstream's Docker image named as someone else's (never as a default)",
    ("third-party", "third-party-names"): "names of other people's things (a third-party plugin, upstream's wiki and repository)",
    ("legacy-compat", "marked-legacy-compat"): "a line marked `// legacy-compat`: compat code or a test that asserts the old name on purpose",
    ("legacy-compat", "keep-marked-docs"): "documentation line marked `rebrand:keep`: explains a legacy name, the migration, or the upstream store",
    ("legacy-compat", "frozen-strings"): "key-derivation salts, rule-ID seed and signed-format identifiers (plan row 47): changing one breaks sessions, clusters, rule IDs or signatures",
}

def class_of_tag(tag):
    if tag in TAGS:
        return TAGS[tag]
    if tag.startswith("protect:frozen"):
        return ("legacy-compat", "frozen-strings")
    if tag.startswith("allow:"):
        return ("legacy-compat", tag[6:])
    return ("LEFTOVER", tag)


def glob_match(glob, path):
    rx = rename.glob_to_re(glob)
    return re.match(rx, path) is not None if isinstance(rx, str) else rx.match(path) is not None


_GLOBS = {}


def gm(glob, path):
    if glob not in _GLOBS:
        _GLOBS[glob] = rename.Globs([glob])
    return _GLOBS[glob].match(path)


def files_with_hits():
    r = subprocess.run(["git", "-C", ROOT, "grep", "-I", "-i", "-l", "--untracked", "-E", "zoraxy|imuslab|tobychui|aroz"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return sorted(p for p in r.stdout.decode("utf-8", "surrogateescape").split("\n") if p)


def read(path):
    with open(os.path.join(ROOT, path), "rb") as f:
        raw = f.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def audit(cfg):
    """[(path, lineno, word, class, group, line)]"""
    out = []
    for path in files_with_hits():
        if path == os.path.relpath(DOC, ROOT):
            continue  # this report quotes the names it counts; counting it would never settle
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full) or os.path.islink(full):
            continue
        text = read(path)
        lines = text.split("\n")
        file_class = next(((c, g) for glob, c, g, _w in PATHS if gm(glob, path)), None)
        claims = None
        line_starts = [0]
        for ln in lines:
            line_starts.append(line_starts[-1] + len(ln) + 1)
        import bisect
        for m in WORDS.finditer(text):
            n = bisect.bisect_right(line_starts, m.start())
            line = lines[n - 1]
            if file_class:
                c, g = file_class
            else:
                if claims is None:
                    cl = []
                    rename.plan_text(cfg, path, text, None, None, cl)
                    cl.sort(key=lambda x: x[1])
                    claims = cl
                    starts = [x[1] for x in claims]
                i = bisect.bisect_right(starts, m.start()) - 1
                tag = "UNCLAIMED"
                if i >= 0 and claims[i][2] > m.start():
                    tag = claims[i][0]
                elif i + 1 < len(claims) and claims[i + 1][1] < m.end():
                    tag = claims[i + 1][0]
                c, g = class_of_tag(tag)
                if tag.startswith("done:"):
                    g = "pending-rename"  # rename.py would still rewrite it: never excused by a line rule
                elif c == "LEFTOVER":
                    # only a line a person has read and described in LINES leaves this class
                    for glob, rx, lc, lg, _w in LINES:
                        if gm(glob, path) and re.search(rx, line):
                            c, g = lc, lg
                            break
            out.append((path, n, m.group(0), c, g, line))
    return out


def render(rows, allow_reasons):
    by_class = collections.Counter(r[3] for r in rows)
    files_by_class = collections.defaultdict(set)
    groups = collections.defaultdict(collections.Counter)
    gfiles = collections.defaultdict(set)
    words = collections.Counter(r[2].lower() for r in rows)
    for r in rows:
        files_by_class[r[3]].add(r[0])
        groups[r[3]][r[4]] += 1
        gfiles[(r[3], r[4])].add(r[0])
    why = {}
    for _g, c, g, w in PATHS:
        why.setdefault((c, g), w)
    for _p, _r, c, g, w in LINES:
        if w:
            why.setdefault((c, g), w)
    for k, v in allow_reasons.items():
        why.setdefault(("legacy-compat", k), v)
    for k, v in TAG_WHY.items():
        why.setdefault(k, v)
    return by_class, files_by_class, groups, gfiles, words, why


def allow_reasons():
    out = {}
    with open(rename.ALLOW, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = re.split(r"\t+| {2,}", line.strip(), maxsplit=2)
            if len(parts) == 3:
                out[parts[0]] = parts[2]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--groups", action="store_true", help="print the groups of every class")
    ap.add_argument("--tsv", help="write every classified match to this file")
    ap.add_argument("--write", action="store_true", help="(re)write docs/rebrand/leftover-audit.md")
    args = ap.parse_args()
    cfg = rename.Config()
    rows = audit(cfg)
    by_class, files_by_class, groups, gfiles, words, why = render(rows, allow_reasons())
    print("matches: %d in %d files" % (len(rows), len(set(r[0] for r in rows))))
    print("by word: " + ", ".join("%s %d" % kv for kv in sorted(words.items())))
    for c in CLASSES:
        print("  %-14s %6d matches in %4d files" % (c, by_class[c], len(files_by_class[c])))
        if args.groups:
            for g, n in groups[c].most_common():
                print("      %6d  %-28s %3d files  %s" % (n, g, len(gfiles[(c, g)]), why.get((c, g), "")[:110]))
    if args.verbose:
        for r in rows:
            if r[3] == "LEFTOVER":
                print("LEFTOVER %s:%d [%s] %s" % (r[0], r[1], r[4], r[5].strip()[:200]))
    if args.tsv:
        with open(args.tsv, "w", encoding="utf-8") as f:
            for r in rows:
                f.write("%s\t%d\t%s\t%s\t%s\t%s\n" % (r[0], r[1], r[2], r[3], r[4], r[5].strip()[:300]))
    if args.write:
        with open(DOC, "w", encoding="utf-8") as f:
            f.write(render_markdown(rows, why))
        print("wrote " + os.path.relpath(DOC, ROOT))
    if args.check and by_class["LEFTOVER"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
