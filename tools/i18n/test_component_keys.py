#!/usr/bin/env python3
"""Every t("...") / tf("...") string literal in a component or script must be in en.json.

extract.py lexes the inline scripts itself. A regex literal that holds a quote
(for example .replace(/'/g, "&#39;")) throws that lexer off for the rest of the
script, and extract.py --check still looks clean. This test finds the literals
with a plain regex that does not depend on the lexer, so a desync shows up as
missing keys.

  python3 tools/i18n/test_component_keys.py            check the guarded files (CHECKED below)
  python3 tools/i18n/test_component_keys.py --all      check every file (other pages still have
                                                       strings the lexer misses, for example inside
                                                       template literals; they are not guarded yet)
  python3 tools/i18n/test_component_keys.py FILE...    paths relative to src/web

Exit 1 and list the missing strings.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
WEB = os.path.join(ROOT, "src", "web")
sys.path.insert(0, HERE)
import extract  # noqa: E402

# Files kept clean. Add a page here once all of its t()/tf() literals are extracted.
CHECKED = ["components/cluster.html"]

LIT = re.compile(r"""(?<![\w$.])tf?\(\s*(["'])((?:(?!\1)[^\\\n]|\\.)*)\1\s*[,)]""")


def main(argv):
    only = None if "--all" in argv else ([a for a in argv if not a.startswith("-")] or CHECKED)
    cat = json.load(open(os.path.join(WEB, "locales", "en.json"), encoding="utf-8"))["strings"]
    have = set(cat)
    missing = []
    for base, dirs, files in os.walk(WEB):
        dirs[:] = [d for d in dirs if d not in extract.SKIP_DIRS]
        for f in files:
            if not f.endswith((".html", ".js")) or f in extract.SKIP_JS or f in extract.SKIP_HTML:
                continue
            path = os.path.join(base, f)
            if only is not None and os.path.relpath(path, WEB).replace(os.sep, "/") not in only:
                continue
            src = open(path, encoding="utf-8").read()
            for m in LIT.finditer(src):
                raw = m.group(2)
                try:
                    key = json.loads('"' + raw.replace('\\"', '"').replace('"', '\\"').replace("\\'", "'") + '"')
                except ValueError:
                    continue
                key = extract.norm(key)
                if extract.keep(key) and key not in have:
                    missing.append((os.path.relpath(path, WEB), key))
    for p, k in sorted(set(missing)):
        print("missing from en.json: %s: %r" % (p, k))
    if missing:
        print("%d string(s) missing: run tools/i18n/extract.py (and check the script for a regex literal with a quote)" % len(set(missing)))
        return 1
    print("ok: every t()/tf() literal is in en.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
