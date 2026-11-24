#!/usr/bin/env bash
# Checks of the packaging files that run on any Linux machine (CI job "packaging").
#
#   packaging/test.sh
#
# What it checks: shell syntax of every script, the systemd units (systemd-analyze verify when
# available), the launchd plist, every YAML file, the Inno Setup and PowerShell files (structure
# only: they cannot be executed here), the archive layout from build_packages.sh with stand-in
# binaries, install.sh in dry-run and in a private folder, the winget templates, and that no
# address or name of the upstream project is used as a default anywhere in packaging/.
# Tools that are missing (shellcheck, systemd-analyze) are reported and skipped.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
ok() { echo "ok    $*"; }
skip() { echo "skip  $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }

# 1. shell syntax
for f in "$here/build_packages.sh" "$here/test.sh" "$here/windows/winget/render.sh" "$root/tools/build_release.sh" "$root/tools/build_release_test.sh"; do
  if bash -n "$f"; then ok "bash -n ${f#"$root"/}"; else bad "bash -n ${f#"$root"/}"; fi
done
for f in "$here/linux/install.sh" "$here"/linux/scripts/*.sh "$here/macos/build-pkg.sh" "$here/macos/uninstall.sh" "$here"/macos/scripts/* "$here/freebsd/dunree"; do
  if sh -n "$f"; then ok "sh -n ${f#"$root"/}"; else bad "sh -n ${f#"$root"/}"; fi
  [ -x "$f" ] || bad "${f#"$root"/} is not executable"
done
if command -v shellcheck >/dev/null 2>&1; then
  # SC1091: /etc/rc.subr only exists on FreeBSD. SC2034: rc.subr reads the variables the rc script sets.
  if shellcheck -S warning -e SC1091,SC2034 "$here/build_packages.sh" "$here/windows/winget/render.sh" "$root/tools/build_release.sh" \
      "$here/linux/install.sh" "$here"/linux/scripts/*.sh "$here/macos/build-pkg.sh" "$here/macos/uninstall.sh" "$here"/macos/scripts/* "$here/freebsd/dunree"; then
    ok "shellcheck"
  else
    bad "shellcheck"
  fi
else
  skip "shellcheck is not installed"
fi

# 2. systemd units
for unit in dunree.service dunree-package.service; do
  u="$here/linux/$unit"
  for key in "Type=notify" "KillMode=control-group" "TimeoutStopSec=30" "Restart=on-failure" "WantedBy=multi-user.target"; do
    grep -qx "$key" "$u" || bad "$unit: missing $key"
  done
  if grep -q "zoraxy" <(grep -v '^#' "$u"); then bad "$unit: an old name outside a comment"; fi
  if command -v systemd-analyze >/dev/null 2>&1; then
    # verify wants the program to exist: check a copy that points at a stand-in
    mkdir -p "$tmp/unit/work"
    printf '#!/bin/sh\nexit 0\n' >"$tmp/unit/dunree"
    chmod 755 "$tmp/unit/dunree"
    sed -e "s|^ExecStart=[^ ]*|ExecStart=$tmp/unit/dunree|" -e "s|^WorkingDirectory=.*|WorkingDirectory=$tmp/unit/work|" "$u" >"$tmp/unit/dunree.service"
    out="$(systemd-analyze verify "$tmp/unit/dunree.service" 2>&1 || true)"
    # messages about other units of this machine are not ours
    if printf '%s\n' "$out" | grep -F "$tmp/unit/dunree.service" | grep -q .; then
      bad "systemd-analyze verify $unit: $(printf '%s\n' "$out" | grep -F "$tmp/unit/dunree.service")"
    else
      ok "systemd-analyze verify $unit"
    fi
  else
    skip "systemd-analyze is not installed ($unit: key check only)"
  fi
done
grep -q '^ExecStart=/usr/bin/dunree \$DUNREE_ARGS$' "$here/linux/dunree-package.service" || bad "package unit: ExecStart"
grep -q '^DUNREE_ARGS=' "$here/linux/dunree.default" || bad "dunree.default: DUNREE_ARGS"

# 3. plist, YAML, and structure of the files that cannot be executed here
python3 - "$here" "$root" <<'PY' || fails=$((fails + 1))
import glob, os, plistlib, re, sys
here, root = sys.argv[1], sys.argv[2]
errors = []
def check(cond, msg):
    if not cond:
        errors.append(msg)

with open(os.path.join(here, "macos", "ie.foleyit.dunree.plist"), "rb") as f:
    p = plistlib.load(f)
check(p["Label"] == "ie.foleyit.dunree", "plist: Label")
check(p["ProgramArguments"][0] == "/usr/local/bin/dunree", "plist: program")
check(p["KeepAlive"] == {"SuccessfulExit": False}, "plist: KeepAlive")
check(p["ExitTimeOut"] >= 30, "plist: ExitTimeOut must cover the 28 s stop")
check(p["WorkingDirectory"] == "/usr/local/var/dunree", "plist: WorkingDirectory")

try:
    import yaml
except ImportError:
    yaml = None
    print("skip  PyYAML is not installed: YAML files not parsed")
if yaml:
    files = glob.glob(os.path.join(here, "container", "*.yaml")) + [os.path.join(here, "linux", "nfpm.yaml")]
    files += glob.glob(os.path.join(here, "windows", "winget", "*.tmpl"))
    files += glob.glob(os.path.join(root, ".github", "workflows", "*.y*ml"))
    docs = {}
    for f in files:
        try:
            with open(f) as fh:
                docs[os.path.relpath(f, root)] = yaml.safe_load(fh)
        except Exception as e:
            errors.append("%s: %s" % (f, e))
    n = docs.get("packaging/linux/nfpm.yaml", {})
    check(n.get("name") == "dunree" and n.get("license") == "AGPL-3.0-only", "nfpm: name / license")
    dsts = [c.get("dst") for c in n.get("contents", [])]
    for want in ("/usr/bin/dunree", "/usr/lib/systemd/system/dunree.service", "/etc/default/dunree", "/var/lib/dunree",
                 "/usr/share/doc/dunree/LICENSE", "/usr/share/doc/dunree/NOTICE", "/usr/share/doc/dunree/THIRD_PARTY_NOTICES.md"):
        check(want in dsts, "nfpm: %s is not packaged" % want)
    for c in n.get("contents", []):
        src = c.get("src", "")
        if src.startswith("${DUNREE_ROOT}/"):
            check(os.path.exists(os.path.join(root, src[len("${DUNREE_ROOT}/"):])), "nfpm: source %s does not exist" % src)
    for s in n.get("scripts", {}).values():
        check(os.path.exists(os.path.join(root, s.replace("${DUNREE_ROOT}/", ""))), "nfpm: script %s does not exist" % s)
    c = docs.get("packaging/container/compose.yaml", {})
    svc = c.get("services", {}).get("dunree", {})
    check("zoraxydocker" not in str(c), "compose: upstream image namespace")
    check(svc.get("image", "").startswith("${DUNREE_IMAGE"), "compose: the image must be a variable")
    check("/var/run/docker.sock" not in str(svc), "compose: the Docker socket must not be mounted by default")
    for name, wf in docs.items():
        if not name.startswith(".github/workflows/"):
            continue
        check("permissions" in wf, "%s: no top-level permissions" % name)
        check(wf.get("permissions") in ({"contents": "read"}, {}), "%s: top-level permissions must be contents: read" % name)
        with open(os.path.join(root, name)) as fh:
            for line in fh:
                m = re.search(r"uses:\s*(\S+)", line)
                if m and not m.group(1).startswith("./"):
                    check(re.search(r"@[0-9a-f]{40}\s+#\s*v\d", line), "%s: action not pinned to a commit with a version comment: %s" % (name, m.group(1)))
                check("zoraxydocker" not in line, "%s: upstream image namespace" % name)
    for t in glob.glob(os.path.join(here, "windows", "winget", "*.tmpl")):
        d = docs.get(os.path.relpath(t, root), {})
        check(d.get("PackageIdentifier") == "FoleyIT.Dunree", "%s: PackageIdentifier" % t)
        check(d.get("ManifestVersion") == "1.6.0", "%s: ManifestVersion" % t)

def balanced(path, pairs):
    """Brackets outside strings and comments must pair up (catches a cut-off file or a lost brace)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    stack = []
    for ln, line in enumerate(text.split("\n"), 1):
        line = re.sub(r"'[^']*'", "''", line)
        line = re.sub(r'"(?:[^"`]|`.)*"', '""', line)
        line = line.split("#", 1)[0]
        for ch in line:
            if ch in pairs:
                stack.append((ch, ln))
            elif ch in pairs.values():
                if not stack or pairs[stack[-1][0]] != ch:
                    return "%s: unexpected %s in line %d" % (path, ch, ln)
                stack.pop()
    return "%s: %s opened in line %d is never closed" % (path, stack[-1][0], stack[-1][1]) if stack else ""

for ps in ("install.ps1", "uninstall.ps1", "test-service.ps1"):
    f = os.path.join(here, "windows", ps)
    msg = balanced(f, {"{": "}", "(": ")", "[": "]"})
    check(not msg, msg)
    text = open(f, encoding="utf-8").read()
    check(text.isascii(), "%s: non-ASCII character (Windows PowerShell 5 reads scripts without a BOM as ANSI)" % ps)
    check("$ErrorActionPreference = 'Stop'" in text, "%s: must stop on errors" % ps)
    if ps != "test-service.ps1":  # the test asks the local admin port
        check("Invoke-WebRequest" not in text and "DownloadFile" not in text, "%s: must not download anything" % ps)

iss = open(os.path.join(here, "windows", "dunree.iss"), encoding="utf-8").read()
sections = re.findall(r"^\[(\w+)\]", iss, flags=re.M)
for want in ("Setup", "Tasks", "Files", "Run", "UninstallRun", "Code"):
    check(want in sections, "dunree.iss: section [%s] is missing" % want)
check(re.search(r"^AppId=\{\{[0-9A-F-]{36}\}$", iss, flags=re.M), "dunree.iss: AppId")
check("SignTool=" not in re.sub(r"^;.*$", "", iss, flags=re.M), "dunree.iss: no signing configuration belongs here")
for src in re.findall(r'Source: "\{#RepoRoot\}\\([^"]+)"', iss) + re.findall(r"=\{#RepoRoot\}\\(\S+)", iss):
    check(os.path.exists(os.path.join(root, src.replace("\\", "/"))), "dunree.iss: %s does not exist" % src)

df = open(os.path.join(here, "container", "Dockerfile")).read()
check("--platform=$BUILDPLATFORM" in df and "TARGETARCH" in df, "Dockerfile: not cross-compiling for the target platform")
check('ie.foleyit.dunree.container-identifier="Dunree"' in df, "Dockerfile: Dunree label")
check('com.imuslab.zoraxy.container-identifier="Zoraxy"' in df, "Dockerfile: the old label must stay for existing tools")
check("ln -s /opt/dunree /opt/zoraxy" in df, "Dockerfile: old paths must keep working")
check(not re.search(r"^ARG VERSION\b", df, flags=re.M), "Dockerfile: ARG VERSION would clash with the VERSION environment variable")
envs = set(re.findall(r'^ENV (\w+)=', df, flags=re.M))
entry = open(os.path.join(root, "docker", "entrypoint.py")).read()
for var in set(re.findall(r"getenv\(['\"](\w+)['\"]", entry)):
    check(var in envs, "Dockerfile: no default for %s, which docker/entrypoint.py reads" % var)

# No address or name of the upstream project as a default (attribution text is fine).
for d, _, names in os.walk(here):
    for nme in names:
        f = os.path.join(d, nme)
        with open(f, encoding="utf-8", errors="replace") as fh:
            for ln, line in enumerate(fh, 1):
                for banned in ("zoraxydocker", "github.com/tobychui", "zoraxy.aroz.org", "aroz-online", "TheTractorHacker"):
                    if banned in line and nme != "test.sh":
                        errors.append("%s:%d: %s" % (os.path.relpath(f, root), ln, banned))

rc = open(os.path.join(here, "freebsd", "dunree")).read()
for want in ("# PROVIDE: dunree", "# REQUIRE: LOGIN NETWORKING", "# KEYWORD: shutdown", ". /etc/rc.subr", 'rcvar="dunree_enable"', 'run_rc_command "$1"'):
    check(want in rc, "rc script: %s is missing" % want)
check("${dunree_program} ${dunree_args}" in rc, "rc script: Dunree flags must come after the program, not in dunree_flags")

for e in errors:
    print("FAIL  " + e)
if not errors:
    print("ok    plist, YAML, PowerShell, Inno Setup, Dockerfile, rc script, no upstream defaults")
sys.exit(1 if errors else 0)
PY

# 4. archive layout with stand-in binaries
d="$tmp/dist"
mkdir -p "$d"
for n in linux_amd64 linux_arm windows_amd64.exe windows_arm64.exe darwin_arm64 freebsd_amd64; do
  printf 'stand-in %s\n' "$n" >"$d/dunree_$n"
done
cp "$d/dunree_linux_amd64" "$d/zoraxy_linux_amd64" # a legacy copy must not get a package of its own
if "$here/build_packages.sh" --dist "$d" --version 1.2.3-rc.1 --no-nfpm >"$tmp/pkg.log" 2>&1; then
  want="dunree_1.2.3-rc.1_darwin_arm64.tar.gz dunree_1.2.3-rc.1_freebsd_amd64.tar.gz dunree_1.2.3-rc.1_linux_amd64.tar.gz dunree_1.2.3-rc.1_linux_arm.tar.gz dunree_1.2.3-rc.1_windows_amd64.zip dunree_1.2.3-rc.1_windows_arm64.zip"
  got="$(cd "$d" && ls | grep -E '\.(tar\.gz|zip|deb|rpm)$' | tr '\n' ' ' | sed 's/ $//')"
  if [ "$got" = "$want" ]; then ok "archives: $got"; else bad "archives: got '$got', want '$want'"; fi
  lin="$(tar tzf "$d/dunree_1.2.3-rc.1_linux_amd64.tar.gz" | LC_ALL=C sort | tr '\n' ' ')"
  wantlin="dunree_1.2.3-rc.1_linux_amd64/ dunree_1.2.3-rc.1_linux_amd64/LICENSE dunree_1.2.3-rc.1_linux_amd64/NOTICE dunree_1.2.3-rc.1_linux_amd64/THIRD_PARTY_NOTICES.md dunree_1.2.3-rc.1_linux_amd64/dunree dunree_1.2.3-rc.1_linux_amd64/dunree.service dunree_1.2.3-rc.1_linux_amd64/install.sh "
  if [ "$lin" = "$wantlin" ]; then ok "linux tarball layout"; else bad "linux tarball layout: $lin"; fi
  tar tzf "$d/dunree_1.2.3-rc.1_freebsd_amd64.tar.gz" | grep -q '/rc.d/dunree$' || bad "freebsd tarball: rc.d/dunree"
  tar tzf "$d/dunree_1.2.3-rc.1_darwin_arm64.tar.gz" | grep -q '/ie.foleyit.dunree.plist$' || bad "darwin tarball: plist"
  if python3 - "$d/dunree_1.2.3-rc.1_windows_amd64.zip" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = sorted(z.namelist())
base = "dunree_1.2.3-rc.1_windows_amd64/"
want = sorted(base + n for n in ("dunree.exe", "install.ps1", "uninstall.ps1", "README-windows.txt", "LICENSE.txt", "NOTICE.txt", "THIRD_PARTY_NOTICES.md"))
assert names == want, names
assert z.read(base + "dunree.exe") == b"stand-in windows_amd64.exe\n", "the program must be stored unchanged"
for n in ("install.ps1", "NOTICE.txt"):
    data = z.read(base + n)
    assert b"\r\n" in data and b"\r\r\n" not in data and data.count(b"\n") == data.count(b"\r\n"), n + ": line ends"
assert b"tobychui" in z.read(base + "NOTICE.txt"), "attribution must be in the zip"
PY
  then ok "windows zip layout, CRLF text, program unchanged"; else bad "windows zip"; fi
  # the same input gives the same archives
  (cd "$d" && sha256sum ./*.tar.gz ./*.zip) >"$tmp/sums1"
  "$here/build_packages.sh" --dist "$d" --version 1.2.3-rc.1 --no-nfpm >/dev/null 2>&1
  if (cd "$d" && sha256sum -c "$tmp/sums1" >/dev/null 2>&1); then ok "archives are reproducible"; else bad "archives differ between two runs"; fi
else
  bad "build_packages.sh failed: $(cat "$tmp/pkg.log")"
fi
if "$here/build_packages.sh" --dist "$d" --version "1.0;rm" >/dev/null 2>&1; then bad "a malformed version was accepted"; else ok "malformed version refused"; fi
if "$here/build_packages.sh" --dist "$d" --version 1.0.0 --targets linux/s390x >/dev/null 2>&1; then bad "a target without a binary was accepted"; else ok "target without a binary refused"; fi
if command -v nfpm >/dev/null 2>&1; then
  if "$here/build_packages.sh" --dist "$d" --version 1.2.3-rc.1 --targets linux/amd64 --require-nfpm >"$tmp/nfpm.log" 2>&1 \
     && [ -f "$d/dunree_1.2.3-rc.1_linux_amd64.deb" ] && [ -f "$d/dunree_1.2.3-rc.1_linux_amd64.rpm" ]; then
    ok "nfpm: .deb and .rpm built"
    if command -v dpkg-deb >/dev/null 2>&1; then
      list="$(dpkg-deb -c "$d/dunree_1.2.3-rc.1_linux_amd64.deb" | awk '{print $6}' | sed 's|^\./||; s|^/||; s|/$||')"
      for p in usr/bin/dunree usr/lib/systemd/system/dunree.service etc/default/dunree var/lib/dunree usr/share/doc/dunree/NOTICE; do
        printf '%s\n' "$list" | grep -qx "$p" || bad ".deb: /$p is missing"
      done
      if dpkg-deb -c "$d/dunree_1.2.3-rc.1_linux_amd64.deb" | grep -v '^d' | grep -q '^.....w'; then bad ".deb: a file is group-writable"; fi
      dpkg-deb -c "$d/dunree_1.2.3-rc.1_linux_amd64.deb" | grep -q '^drwxr-x--- .* \./var/lib/dunree/$' || bad ".deb: /var/lib/dunree must be mode 0750"
      dpkg-deb --ctrl-tarfile "$d/dunree_1.2.3-rc.1_linux_amd64.deb" | tar t | grep -q 'conffiles' || bad ".deb: /etc/default/dunree is not a conffile"
      dpkg-deb -f "$d/dunree_1.2.3-rc.1_linux_amd64.deb" Package Version Architecture | tr '\n' ' '; echo
    fi
  else
    bad "nfpm: $(cat "$tmp/nfpm.log")"
  fi
else
  skip "nfpm is not installed: .deb and .rpm not built"
fi

# 5. install.sh: dry run changes nothing, a real run into a private folder writes the unit with the chosen path
t="$tmp/tar"
mkdir -p "$t"
tar xzf "$d/dunree_1.2.3-rc.1_linux_amd64.tar.gz" -C "$t"
pkg="$t/dunree_1.2.3-rc.1_linux_amd64"
mkdir -p "$tmp/units"
if out="$(DUNREE_UNIT_DIR="$tmp/units" "$pkg/install.sh" --dir "$tmp/opt/dunree" --dry-run 2>&1)" \
   && [ ! -e "$tmp/opt" ] && [ -z "$(ls -A "$tmp/units")" ] && printf '%s' "$out" | grep -q "would write: $tmp/units/dunree.service"; then
  ok "install.sh --dry-run changes nothing"
else
  bad "install.sh --dry-run: $out"
fi
mkdir -p "$tmp/shared"
if out="$(DUNREE_UNIT_DIR="$tmp/units" "$pkg/install.sh" --dir "$tmp/shared" --dry-run 2>&1)" \
   && ! printf '%s' "$out" | grep -q "chmod" && printf '%s' "$out" | grep -q "permissions are not changed"; then
  ok "install.sh leaves the mode of an existing --dir alone"
else
  bad "install.sh would chmod an existing --dir: $out"
fi
if DUNREE_UNIT_DIR="$tmp/units" "$pkg/install.sh" --dir "relative" --dry-run >/dev/null 2>&1; then bad "install.sh accepted a relative --dir"; else ok "install.sh refuses a relative --dir"; fi
if [ "$(id -u)" != 0 ]; then
  if DUNREE_UNIT_DIR="$tmp/units" "$pkg/install.sh" --dir "$tmp/opt/dunree" >/dev/null 2>&1; then bad "install.sh ran without root"; else ok "install.sh refuses to run without root"; fi
fi
printf 'existing\n' >"$tmp/units/dunree.service"
if DUNREE_UNIT_DIR="$tmp/units" "$pkg/install.sh" --dir "$tmp/opt/dunree" --dry-run >/dev/null 2>&1; then bad "install.sh would overwrite an existing unit"; else ok "install.sh refuses to overwrite an existing unit"; fi

# 6. winget templates render completely, and only with every address given
w="$tmp/winget"
mkdir -p "$w/dist"
printf 'a' >"$w/dist/dunree_1.2.3_windows_amd64_setup.exe"
printf 'b' >"$w/dist/dunree_1.2.3_windows_arm64_setup.exe"
if "$here/windows/winget/render.sh" --version 1.2.3 --base-url https://downloads.example/v1.2.3/ --dist "$w/dist" --out "$w/out" \
     --publisher-url https://example.org --package-url https://example.org/dunree --license-url https://example.org/license >/dev/null 2>&1 \
   && grep -q 'InstallerUrl: https://downloads.example/v1.2.3/dunree_1.2.3_windows_amd64_setup.exe' "$w/out/FoleyIT.Dunree.installer.yaml" \
   && grep -q 'InstallerSha256: CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB' "$w/out/FoleyIT.Dunree.installer.yaml" \
   && ! grep -rq '\${' "$w/out"; then
  ok "winget manifests render"
else
  bad "winget render"
fi
if "$here/windows/winget/render.sh" --version 1.2.3 --base-url https://downloads.example --dist "$w/dist" --out "$w/out2" >/dev/null 2>&1; then bad "winget render without addresses"; else ok "winget render needs every address"; fi

# 7. macOS package script: the dry run lists the steps on any system
if out="$(sh "$here/macos/build-pkg.sh" --version 1.2.3-rc.1 --dist "$d" --dry-run 2>&1)" \
   && printf '%s' "$out" | grep -q 'pkgbuild .*--identifier ie.foleyit.dunree --version 1.2.3 ' \
   && printf '%s' "$out" | grep -q 'lipo -create'; then
  ok "build-pkg.sh --dry-run"
else
  bad "build-pkg.sh --dry-run: $out"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails check(s) FAILED"
  exit 1
fi
echo "OK, packaging checks passed"
