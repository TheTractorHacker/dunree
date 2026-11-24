#!/usr/bin/env python3
# Dunree rebrand - mechanical rename pass.
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Mechanical Zoraxy -> Dunree rename.

    tools/rebrand/rename.py [--dry-run]     dry run: what would change (nothing is written)
    tools/rebrand/rename.py --apply         write the changes and do the git mv renames
    tools/rebrand/rename.py --left          list what is still there afterwards, by class
    tools/rebrand/rename.py --left -v       ... with every file:line
    tools/rebrand/rename.py --check         exit 1 when a dry run would still change something
    tools/rebrand/rename.py --only RULE     limit the run to one rule id (repeatable)

Inputs (all next to this file):
    policy.json        variables (MODULE_ROOT lives only there), global excludes, protected spans, rules
    mechanical.json    what this pass does on top of the policy's "auto" rules (promoted and extra rules,
                       path renames, extra excludes)
    legacy-allow.txt   strings that must keep the old name because an existing install, plugin, cluster
                       peer, monitor or signature depends on them.  This pass never rewrites them.

How a file is processed.  Spans are claimed in this order and a claimed span is never touched again:
    1. policy "protect" regexes, the legacy-allow list, and any line that carries the marker "rebrand:keep"
       (or, in code, the policy's "// legacy-compat")
    2. attribution lines: every zoraxy/Zoraxy on a line that names tobychui or imuslab
    3. rules in order.  auto (or promoted) rules rewrite their matches; manual rules only claim them,
       so a later, broader rule cannot rewrite what a work package has to change by hand.

The pass is idempotent: no replacement produces text that a rule matches again, and a second --apply is
a no-op (--check proves it).  It works on the files git knows (tracked + untracked, not ignored), so other
worktrees under .claude/ and build output are never touched.  It never commits and never pushes.
"""
import argparse
import bisect
import collections
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
POLICY = os.path.join(HERE, "policy.json")
MECH = os.path.join(HERE, "mechanical.json")
ALLOW = os.path.join(HERE, "legacy-allow.txt")

# Always protected, whatever the policy says (the task's hard floor).
HARD_EXCLUDE = ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "docs/rebrand/**", "tools/rebrand/**", ".git/**"]

# a person / organisation named as author, not as part of a URL, e-mail address or module path
ATTR_NAME = re.compile(r"(?<![\w/@.-])(?:tobychui|imuslab)(?![\w/-]|\.[a-z])")
KEEP_MARK = "rebrand:keep"
KEEP_LINE = re.compile(r"[^\n]*rebrand:keep[^\n]*")
ANY_OLD = re.compile(r"(?i)zoraxy")
LEFT_SCAN = re.compile(r"(?i)zoraxy|imuslab|tobychui|aroz\.org|aroz-online")


# ---------------------------------------------------------------- helpers

def glob_to_re(glob):
    """git ':(glob)' pathspec -> regex.  '*' stays inside one path segment, '**' crosses them."""
    out, i, n = [], 0, len(glob)
    while i < n:
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z")


class Globs:
    def __init__(self, globs):
        self.res = [glob_to_re(g) for g in (globs or [])]

    def match(self, path):
        return any(r.match(path) for r in self.res)


def expand(template, variables):
    """${VAR} -> policy variable, $1 -> \\g<1> (python re template)."""
    def var(m):
        name = m.group(1)
        if name not in variables:
            raise SystemExit("policy: unknown variable ${%s}" % name)
        return variables[name].replace("\\", "\\\\")
    s = re.sub(r"\$\{([A-Z_]+)\}", var, template)
    return re.sub(r"\$(\d)", r"\\g<\1>", s)


def expand_plain(template, variables):
    return re.sub(r"\$\{([A-Z_]+)\}", lambda m: variables[m.group(1)], template)


def git(*args, check=True):
    r = subprocess.run(["git", "-C", ROOT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and r.returncode != 0:
        raise SystemExit("git %s failed: %s" % (" ".join(args), r.stderr.decode(errors="replace")))
    return r.stdout.decode("utf-8", errors="surrogateescape")


def list_files():
    out = git("ls-files", "-z", "-co", "--exclude-standard")
    files = sorted(set(p for p in out.split("\0") if p))
    return [p for p in files if os.path.isfile(os.path.join(ROOT, p)) and not os.path.islink(os.path.join(ROOT, p))]


EXTRA_QUICK = []        # more byte strings that make a file worth reading (a module root being moved)
QUICK = re.compile(rb"(?i)zoraxy|imuslab|tobychui|aroz")


def read_text(path):
    """Text of a file, or None for binary / non UTF-8 content (those are never rewritten) and for
    files that mention none of the old names (nothing to do, and it keeps the pass fast)."""
    try:
        with open(os.path.join(ROOT, path), "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if b"\0" in raw or not (QUICK.search(raw) or any(x in raw for x in EXTRA_QUICK)):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def write_text(path, text):
    full = os.path.join(ROOT, path)
    mode = os.stat(full).st_mode
    tmp = full + ".rebrand-tmp"
    with open(tmp, "wb") as f:
        f.write(text.encode("utf-8"))
    os.chmod(tmp, mode & 0o7777)
    os.replace(tmp, full)


class Spans:
    """Sorted, non-overlapping claimed [start, end) intervals."""

    def __init__(self):
        self.starts, self.ends, self.tags = [], [], []

    def overlaps(self, s, e):
        i = bisect.bisect_right(self.starts, s)
        if i > 0 and self.ends[i - 1] > s:
            return self.tags[i - 1]
        if i < len(self.starts) and self.starts[i] < e:
            return self.tags[i]
        return None

    def add(self, s, e, tag):
        """Claim [s, e); merges into neighbours when it overlaps (first tag wins)."""
        if e <= s:
            return
        i = bisect.bisect_right(self.starts, s)
        if i > 0 and self.ends[i - 1] > s:
            i -= 1
            s, tag = self.starts[i], self.tags[i]
            e = max(e, self.ends[i])
            del self.starts[i], self.ends[i], self.tags[i]
        while i < len(self.starts) and self.starts[i] < e:
            e = max(e, self.ends[i])
            del self.starts[i], self.ends[i], self.tags[i]
        self.starts.insert(i, s)
        self.ends.insert(i, e)
        self.tags.insert(i, tag)

    def tag_at(self, s, e):
        return self.overlaps(s, e)


# ---------------------------------------------------------------- configuration

class Rule:
    def __init__(self, d, variables, mode=None):
        self.id = d["id"]
        self.mode = mode or d.get("mode", "manual")
        self.applies_to = d.get("applies_to", "content")
        self.find_src = d["find"]
        self.find = re.compile(d["find"], re.M)
        self.raw_replace = d.get("replace", "")
        self.replace = expand(self.raw_replace, variables) if self.mode == "auto" else None
        self.paths = Globs(d.get("paths") or ["**"])
        self.exclude = Globs(d.get("exclude"))
        self.include_excluded = Globs(d.get("include_globally_excluded"))
        self.notes = d.get("notes", "")

    def wants(self, path):
        return self.paths.match(path) and not self.exclude.match(path)


class Config:
    def __init__(self):
        with open(POLICY, encoding="utf-8") as f:
            self.policy = json.load(f)
        with open(MECH, encoding="utf-8") as f:
            self.mech = json.load(f)
        self.vars = dict(self.policy["variables"])
        v = self.vars
        self.global_exclude = Globs(self.policy["global_exclude"] + HARD_EXCLUDE +
                                    [expand_plain(g, v) for g in self.mech.get("extra_exclude", [])])
        self.protect = [(p["id"], re.compile(p["regex"], re.M)) for p in self.policy["protect"]]
        self.allow = self.load_allow()
        self.rules = self.build_rules()
        self.name_renames = [(re.compile(d["match"]), expand_plain(d["to"], v), set(d.get("kinds", ["file"])),
                              Globs(d.get("paths") or ["**"]), Globs(d.get("exclude")))
                             for d in self.mech.get("name_renames", [])]
        self.json_key_files = Globs(self.mech.get("json_key_value_files", []))

    def load_allow(self):
        """legacy-allow.txt: 'id<TAB or 2+ spaces>regex<TAB or 2+ spaces>reason'; '#' starts a comment line."""
        out = []
        if not os.path.exists(ALLOW):
            return out
        with open(ALLOW, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                parts = re.split(r"\t+| {2,}", line.strip(), maxsplit=2)
                if len(parts) < 2:
                    raise SystemExit("legacy-allow.txt:%d: need 'id  regex  reason'" % n)
                try:
                    out.append(("allow:" + parts[0], re.compile(parts[1], re.M)))
                except re.error as e:
                    raise SystemExit("legacy-allow.txt:%d: bad regex: %s" % (n, e))
        return out

    def current_module_root(self):
        """The module root in src/go.mod when it is neither the legacy one nor the policy's (else None)."""
        try:
            with open(os.path.join(ROOT, "src", "go.mod"), encoding="utf-8") as f:
                m = re.search(r"^module\s+(\S+)", f.read(), re.M)
        except OSError:
            return None
        cur = m.group(1) if m else None
        if not cur or cur in (self.vars["MODULE_ROOT"], self.vars["LEGACY_MODULE_ROOT"]):
            return None
        return cur

    def build_rules(self):
        v = self.vars
        promote = {p["id"]: p for p in self.mech.get("promote", [])}
        extra = collections.defaultdict(list)
        for r in self.mech.get("extra_rules", []):
            extra[r["before"]].append(r)
        rules = []
        seen = set()
        moved = self.current_module_root()
        if moved:
            EXTRA_QUICK.append(moved.encode("utf-8"))
            # MODULE_ROOT was changed in policy.json after an earlier run: move from the root that is in
            # src/go.mod now.  This is what makes the one variable enough to change the path later.
            rules.append(Rule({"id": "module-path-move", "mode": "auto", "paths": ["**"],
                               "find": re.escape(moved) + r"(?=[/\"'`\s]|$)", "replace": "${MODULE_ROOT}"}, v))
        for d in self.policy["rules"]:
            for x in extra.get(d["id"], []):
                rules.append(Rule(x, v))
            seen.add(d["id"])
            if d["id"] in promote:
                p = dict(d)
                p.update({k: val for k, val in promote[d["id"]].items() if k not in ("id", "why")})
                rules.append(Rule(p, v, mode="auto"))
            else:
                rules.append(Rule(d, v))
        for x in extra.get("END", []):
            rules.append(Rule(x, v))
        for anchor in extra:
            if anchor != "END" and anchor not in seen:
                raise SystemExit("mechanical.json: extra rule anchored before unknown rule %r" % anchor)
        for pid in promote:
            if pid not in seen:
                raise SystemExit("mechanical.json: promotes unknown rule %r" % pid)
        return rules


# ---------------------------------------------------------------- content pass

def plan_text(cfg, path, text, only=None, counts=None, claims=None):
    """Return the rewritten text.  counts[rule] += n; claims gets (tag, start, end) of protected spans."""
    spans = Spans()
    for tag, rx in cfg.protect:
        if tag == "legacy-compat-tests" and "// legacy-compat" not in text:
            continue        # the leading [^\n]* is quadratic on minified one-line files
        for m in rx.finditer(text):
            spans.add(m.start(), m.end(), "protect:" + tag)
    for tag, rx in cfg.allow:
        for m in rx.finditer(text):
            spans.add(m.start(), m.end(), tag)
    if KEEP_MARK in text:       # a line that says "rebrand:keep" is left alone (docs that must name the old names)
        for m in KEEP_LINE.finditer(text):
            spans.add(m.start(), m.end(), "keep-marker")
    # attribution lines
    for m in ATTR_NAME.finditer(text):
        ls = text.rfind("\n", 0, m.start()) + 1
        le = text.find("\n", m.end())
        le = len(text) if le < 0 else le
        if le - ls > 2000:      # minified / one-line files: stay near the name
            ls, le = max(ls, m.start() - 300), min(le, m.end() + 300)
        for z in ANY_OLD.finditer(text, ls, le):
            # the Go module path on such a line is not attribution
            if text[max(0, z.start() - 12):z.start()] == "imuslab.com/":
                continue
            if not spans.overlaps(z.start(), z.end()):
                spans.add(z.start(), z.end(), "attribution-line")
    edits = []
    for rule in cfg.rules:
        if rule.applies_to != "content" or not rule.wants(path):
            continue
        active = rule.mode == "auto" and (not only or rule.id in only)
        for m in rule.find.finditer(text):
            s, e = m.start(), m.end()
            if e == s or spans.overlaps(s, e):
                continue
            if active:
                new = m.expand(rule.replace)
                if new != m.group(0):
                    edits.append((s, e, new))
                    if counts is not None:
                        counts[rule.id] += 1
                spans.add(s, e, "done:" + rule.id)
            else:
                spans.add(s, e, "manual:" + rule.id)
    if claims is not None:
        claims.extend(zip(spans.tags, spans.starts, spans.ends))
    if not edits:
        return text
    edits.sort()
    out, pos = [], 0
    for s, e, new in edits:
        out.append(text[pos:s])
        out.append(new)
        pos = e
    out.append(text[pos:])
    return "".join(out)


def plan_json_keys(cfg, path, text, only, counts, problems):
    """Locale catalogues: keys are the English text.  Rewrite keys and values with the same rules and
    report key collisions instead of silently dropping one side."""
    try:
        data = json.loads(text, object_pairs_hook=collections.OrderedDict)
    except ValueError as e:
        problems.append("%s: not valid JSON (%s), skipped" % (path, e))
        return text
    strings = data.get("strings") if isinstance(data, dict) else None
    if not isinstance(strings, dict):
        return plan_text(cfg, path, text, only, counts)
    new = collections.OrderedDict()
    changed = False
    for k, val in strings.items():
        nk = plan_text(cfg, path, k, only, counts)
        nv = plan_text(cfg, path, val, only, counts) if isinstance(val, str) else val
        if nk != k or nv != val:
            changed = True
        if nk in new and nk != k:
            problems.append("%s: key collision after rename: %r (kept the existing entry)" % (path, nk))
            continue
        if nk in new:
            # the already renamed twin arrived first; keep the original spelling's value only if empty
            if not new[nk]:
                new[nk] = nv
            problems.append("%s: key collision after rename: %r" % (path, nk))
            continue
        new[nk] = nv
    if not changed:
        return text
    data["strings"] = new
    indent = len(re.match(r"\{\n( *)", text).group(1)) if re.match(r"\{\n( *)", text) else 1
    out = json.dumps(data, ensure_ascii=False, indent=indent)
    return out + ("\n" if text.endswith("\n") else "")


_GOFMT = []


def gofmt(text):
    """gofmt output for text, or None when gofmt is missing or the source does not parse."""
    if not _GOFMT:
        import shutil
        _GOFMT.append(shutil.which("gofmt"))
    if not _GOFMT[0]:
        return None
    r = subprocess.run([_GOFMT[0]], input=text.encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return r.stdout.decode("utf-8") if r.returncode == 0 else None


def gofmt_if_was_clean(old, new):
    """A new module path sorts differently inside an import block.  Re-run gofmt, but only on files that
    were gofmt-clean before, so the pass never reformats code it did not change."""
    if gofmt(old) != old:
        return new
    out = gofmt(new)
    return out if out is not None else new


# ---------------------------------------------------------------- path pass

def plan_renames(cfg, files):
    """[(old, new)] for directories (first, top-down) and then files, as paths that are valid when the
    moves are done in this order."""
    def renamed(base, path, kind):
        for rx, to, kinds, inc, exc in cfg.name_renames:
            if kind in kinds and inc.match(path) and not exc.match(path) and rx.search(base):
                base = rx.sub(to, base)
        return base

    moves, dir_map = [], {}
    dirs = set()
    for p in files:
        parts = p.split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))

    def mapped(path):
        """path after the directory moves planned so far"""
        best = ""
        for d in dir_map:
            if (path == d or path.startswith(d + "/")) and len(d) > len(best):
                best = d
        return dir_map[best] + path[len(best):] if best else path

    for d in sorted(dirs):
        if cfg.global_exclude.match(d + "/x"):
            continue
        parent, _, base = d.rpartition("/")
        nb = renamed(base, d + "/x", "dir")
        if nb != base:
            cur = mapped(d)
            new = cur[:len(cur) - len(base)] + nb
            moves.append((cur, new))
            dir_map[d] = new
    for p in files:
        if cfg.global_exclude.match(p):
            continue
        parent, _, base = p.rpartition("/")
        nb = renamed(base, p, "file")
        if nb != base:
            cur = mapped(p)
            moves.append((cur, cur[:len(cur) - len(base)] + nb))
    return moves


def apply_renames(moves, problems):
    done = 0
    for old, new in moves:
        fo, fn = os.path.join(ROOT, old), os.path.join(ROOT, new)
        if not os.path.exists(fo):
            continue
        if os.path.exists(fn):
            problems.append("rename %s -> %s: target exists, skipped" % (old, new))
            continue
        os.makedirs(os.path.dirname(fn), exist_ok=True)
        # ask git each time: an earlier directory move changes which paths are tracked
        is_tracked = bool(git("ls-files", "-z", "--", old, check=False))
        if is_tracked:
            r = subprocess.run(["git", "-C", ROOT, "mv", "-k", old, new], stderr=subprocess.PIPE)
            if r.returncode != 0 or os.path.exists(fo) and not os.path.isdir(fo):
                problems.append("git mv %s -> %s: %s" % (old, new, r.stderr.decode(errors="replace").strip()))
                continue
            # untracked leftovers inside a moved directory (git mv -k leaves them behind)
            if os.path.isdir(fo):
                for dp, _dn, fns in os.walk(fo):
                    for f in fns:
                        src = os.path.join(dp, f)
                        dst = os.path.join(fn, os.path.relpath(src, fo))
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        os.replace(src, dst)
                for dp, _dn, _fn in os.walk(fo, topdown=False):
                    try:
                        os.rmdir(dp)
                    except OSError:
                        pass
        else:
            os.replace(fo, fn)
        done += 1
    return done


# ---------------------------------------------------------------- reports

def classify(tok):
    return re.sub(r"[0-9a-f]{8,}", "<hex>", tok)[:60]


def report_left(cfg, files, verbose):
    """Everything that still names the old product / upstream after the pass, grouped by why it stays."""
    groups = collections.defaultdict(lambda: collections.Counter())
    where = collections.defaultdict(list)
    excluded = collections.Counter()
    for path in files:
        text = read_text(path)
        if text is None:
            continue
        if cfg.global_exclude.match(path):
            n = len(LEFT_SCAN.findall(text))
            if n:
                top = path.split("/")[0] if "/" in path else path
                excluded[re.sub(r"^(src/mod/plugins/testdata/[^/]+|docs/[^/]+|tools/rebrand).*", r"\1", path)
                         if "/" in path else top] += n
            continue
        claims = []
        plan_text(cfg, path, text, None, None, claims)
        claims.sort(key=lambda c: c[1])
        starts = [c[1] for c in claims]
        for m in LEFT_SCAN.finditer(text):
            i = bisect.bisect_right(starts, m.start()) - 1
            tag = "UNCLAIMED"
            if i >= 0 and claims[i][2] > m.start():
                tag = claims[i][0]
            elif i + 1 < len(claims) and claims[i + 1][1] < m.end():
                tag = claims[i + 1][0]
            if tag.startswith("done:"):
                tag = "PENDING (run --apply)"
            # the word around the match
            s = m.start()
            while s > 0 and not text[s - 1].isspace() and text[s - 1] not in "\"'`()<>,;=" and m.start() - s < 40:
                s -= 1
            e = m.end()
            while e < len(text) and not text[e].isspace() and text[e] not in "\"'`()<>,;=" and e - m.end() < 40:
                e += 1
            groups[tag][classify(text[s:e])] += 1
            if verbose:
                where[tag].append("%s:%d: %s" % (path, text.count("\n", 0, m.start()) + 1, text[s:e]))
    total = 0
    for tag in sorted(groups, key=lambda t: (t != "UNCLAIMED", t)):
        n = sum(groups[tag].values())
        total += n
        print("\n[%s] %d" % (tag, n))
        for tok, c in groups[tag].most_common(None if verbose else 12):
            print("   %6d  %s" % (c, tok))
        if verbose:
            for w in where[tag]:
                print("      " + w)
    print("\nIn globally excluded files (never touched): %d matches" % sum(excluded.values()))
    for k, c in excluded.most_common():
        print("   %6d  %s" % (c, k))
    print("\nTotal left in processed files: %d" % total)
    return groups


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    ap.add_argument("--dry-run", action="store_true", help="explicit dry run (the default); cannot be combined with --apply")
    ap.add_argument("--check", action="store_true", help="exit 1 if a run would change anything")
    ap.add_argument("--left", action="store_true", help="report remaining old names by class and exit")
    ap.add_argument("--only", action="append", help="apply only this rule id (repeatable)")
    ap.add_argument("--no-gofmt", action="store_true", help="do not re-run gofmt on changed .go files")
    ap.add_argument("--no-renames", action="store_true", help="skip file and directory renames")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("paths", nargs="*", help="limit to these path prefixes (relative to the repo root)")
    args = ap.parse_args()
    if args.dry_run and args.apply:
        ap.error("--dry-run and --apply exclude each other")

    cfg = Config()
    files = list_files()
    if args.paths:
        pref = [p.rstrip("/") for p in args.paths]
        files = [f for f in files if any(f == p or f.startswith(p + "/") for p in pref)]

    if args.left:
        report_left(cfg, files, args.verbose)
        return 0

    problems = []
    only = set(args.only) if args.only else None
    if only:
        known = {r.id for r in cfg.rules}
        for o in only:
            if o not in known:
                raise SystemExit("unknown rule id %r" % o)

    # 1. paths
    moves = [] if (args.no_renames or only or args.paths) else plan_renames(cfg, files)
    if moves:
        print("Renames (%s):" % ("git mv" if args.apply else "planned"))
        for old, new in moves:
            print("   %s -> %s" % (old, new))
        if args.apply:
            apply_renames(moves, problems)
            files = list_files()

    # 2. content
    counts = collections.Counter()
    file_counts = collections.Counter()
    changed = []
    for path in files:
        if cfg.global_exclude.match(path):
            continue
        text = read_text(path)
        if text is None or not text:
            continue
        before = collections.Counter(counts)
        if cfg.json_key_files.match(path):
            new = plan_json_keys(cfg, path, text, only, counts, problems)
        else:
            new = plan_text(cfg, path, text, only, counts)
        if new != text:
            changed.append(path)
            for rid in counts:
                if counts[rid] != before[rid]:
                    file_counts[rid] += 1
            if args.apply:
                # re-read right before writing: another agent may have edited the file meanwhile
                again = read_text(path)
                if again != text:
                    text = again
                    new = (plan_json_keys(cfg, path, text, only, collections.Counter(), problems)
                           if cfg.json_key_files.match(path) else plan_text(cfg, path, text, only))
                if new != text:
                    if path.endswith(".go") and not args.no_gofmt:
                        new = gofmt_if_was_clean(text, new)
                    write_text(path, new)
            if args.verbose:
                print("   %s %s" % ("wrote" if args.apply else "would change", path))

    print("\n%s %d files" % ("Changed" if args.apply else "Would change", len(changed)))
    for rule in cfg.rules:
        if counts[rule.id]:
            print("   %-28s %6d replacements in %4d files" % (rule.id, counts[rule.id], file_counts[rule.id]))
    for p in problems:
        print("PROBLEM: " + p)
    if not args.apply and (changed or moves):
        print("\nDry run. Nothing was written. Use --apply to write.")
    if args.check and (changed or moves):
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
