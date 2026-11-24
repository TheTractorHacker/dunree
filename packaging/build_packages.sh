#!/usr/bin/env bash
# Build the Dunree archives and Linux packages from the binaries in a dist folder.
#
#   packaging/build_packages.sh --dist DIST_DIR --version 1.0.0-beta.1
#                               [--targets os/arch,...] [--require-nfpm] [--no-nfpm]
#
# DIST_DIR holds dunree_<os>_<arch>[.exe] from tools/build_release.sh. Without --targets a
# package is built for every binary found there. Results, all in DIST_DIR:
#
#   dunree_<version>_linux_<arch>.tar.gz     dunree, install.sh, dunree.service, licence files
#   dunree_<version>_linux_<arch>.deb/.rpm   when nfpm is on the PATH (packaging/linux/nfpm.yaml)
#   dunree_<version>_windows_<arch>.zip      dunree.exe, install.ps1, uninstall.ps1, licence files
#   dunree_<version>_darwin_<arch>.tar.gz    dunree, launchd plist, licence files
#   dunree_<version>_freebsd_<arch>.tar.gz   dunree, rc.d script, licence files
#
# Every archive unpacks into one folder with the name of the archive. The names start with
# "dunree_", so tools/sign_release.go lists them in SHA256SUMS.
#
# Not built here, because they need their own system: the macOS .pkg (packaging/macos/build-pkg.sh,
# macOS) and the Windows installer (packaging/windows/dunree.iss, Inno Setup on Windows).
#
# nfpm is not downloaded by this script. Without it the .deb and .rpm are skipped with a
# message (--require-nfpm makes that an error, --no-nfpm skips them even when it is installed).
# The zip is written with python3 (no zip program needed). Archives are reproducible: fixed
# file order, owner root, and the time stamp $SOURCE_DATE_EPOCH (default: 2026-01-01 UTC).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

dist="" version="" subset="" nfpm_mode=auto
while [ $# -gt 0 ]; do
  case "$1" in
    --dist) dist="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --targets) subset="$2"; shift 2 ;;
    --require-nfpm) nfpm_mode=require; shift ;;
    --no-nfpm) nfpm_mode=off; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$dist" ] && [ -d "$dist" ] || { echo "--dist DIST_DIR is required and must exist" >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "--version must look like 1.0.0 or 1.0.0-beta.1" >&2; exit 2; }
dist="$(cd "$dist" && pwd)"
epoch="${SOURCE_DATE_EPOCH:-1767225600}"

targets=()
if [ -n "$subset" ]; then
  IFS=, read -r -a targets <<<"$subset"
else
  for f in "$dist"/dunree_*_*; do
    [ -f "$f" ] || continue
    n="$(basename "$f")"; n="${n%.exe}"
    case "$n" in
      dunree_linux_*|dunree_windows_*|dunree_darwin_*|dunree_freebsd_*) ;;
      *) continue ;; # an archive from an earlier run
    esac
    rest="${n#dunree_}"
    case "${rest#*_}" in *[._]*) continue ;; esac
    targets+=("${rest%%_*}/${rest#*_}")
  done
fi
[ "${#targets[@]}" -gt 0 ] || { echo "no dunree_<os>_<arch> binaries in $dist" >&2; exit 1; }

have_nfpm=0
if [ "$nfpm_mode" != off ] && command -v nfpm >/dev/null 2>&1; then
  have_nfpm=1
elif [ "$nfpm_mode" = require ]; then
  echo "nfpm is not installed (https://nfpm.goreleaser.com): cannot build the .deb and .rpm" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# make_tar FOLDER_NAME: packs $work/FOLDER_NAME into $dist/FOLDER_NAME.tar.gz
make_tar() {
  ( cd "$work" && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" -cf - "$1" ) | gzip -n -9 >"$dist/$1.tar.gz"
  echo "wrote $dist/$1.tar.gz"
}

# make_zip FOLDER_NAME: packs $work/FOLDER_NAME into $dist/FOLDER_NAME.zip
make_zip() {
  command -v python3 >/dev/null 2>&1 || { echo "python3 is needed to write the zip" >&2; exit 1; }
  python3 - "$work" "$1" "$dist/$1.zip" "$epoch" <<'PY'
import os, sys, time, zipfile
base, name, out, epoch = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
stamp = time.gmtime(max(epoch, 315532800))[:6]  # zip cannot store a date before 1980
paths = []
for d, dirs, files in os.walk(os.path.join(base, name)):
    dirs.sort()
    for f in sorted(files):
        paths.append(os.path.join(d, f))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for p in paths:
        info = zipfile.ZipInfo(os.path.relpath(p, base).replace(os.sep, "/"), stamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        with open(p, "rb") as fh:
            z.writestr(info, fh.read())
PY
  echo "wrote $dist/$1.zip"
}

# to_crlf SRC DST: Windows text files get CRLF line ends (Notepad, PowerShell 5 here-strings)
to_crlf() {
  sed 's/\r$//; s/$/\r/' "$1" >"$2"
}

nfpm_arch() {
  case "$1" in
    arm) echo arm6 ;; # the release builds linux/arm with GOARM=6
    *) echo "$1" ;;
  esac
}

for t in "${targets[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  bin="$dist/dunree_${os}_${arch}"
  [ "$os" != windows ] || bin="$bin.exe"
  [ -f "$bin" ] || { echo "missing binary for $t: $bin" >&2; exit 1; }
  name="dunree_${version}_${os}_${arch}"
  stage="$work/$name"
  rm -rf "$stage"
  mkdir -p "$stage"

  case "$os" in
    linux)
      install -m 755 "$bin" "$stage/dunree"
      install -m 755 "$here/linux/install.sh" "$stage/install.sh"
      install -m 644 "$here/linux/dunree.service" "$stage/dunree.service"
      install -m 644 "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES.md" "$stage/"
      make_tar "$name"
      if [ "$have_nfpm" = 1 ]; then
        cfg="$work/nfpm_${arch}.yaml"
        sed -e "s|\${DUNREE_VERSION}|$version|g" \
            -e "s|\${DUNREE_ARCH}|$(nfpm_arch "$arch")|g" \
            -e "s|\${DUNREE_BINARY}|$bin|g" \
            -e "s|\${DUNREE_ROOT}|$root|g" "$here/linux/nfpm.yaml" >"$cfg"
        for fmt in deb rpm; do
          nfpm package --config "$cfg" --packager "$fmt" --target "$dist/$name.$fmt"
          echo "wrote $dist/$name.$fmt"
        done
      fi
      ;;
    windows)
      install -m 644 "$bin" "$stage/dunree.exe"
      for f in install.ps1 uninstall.ps1 README-windows.txt; do
        to_crlf "$here/windows/$f" "$stage/$f"
      done
      to_crlf "$root/LICENSE" "$stage/LICENSE.txt"
      to_crlf "$root/NOTICE" "$stage/NOTICE.txt"
      to_crlf "$root/THIRD_PARTY_NOTICES.md" "$stage/THIRD_PARTY_NOTICES.md"
      make_zip "$name"
      ;;
    darwin)
      install -m 755 "$bin" "$stage/dunree"
      install -m 644 "$here/macos/ie.foleyit.dunree.plist" "$stage/ie.foleyit.dunree.plist"
      install -m 755 "$here/macos/uninstall.sh" "$stage/uninstall.sh"
      install -m 644 "$here/macos/README-macos.txt" "$stage/README-macos.txt"
      install -m 644 "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES.md" "$stage/"
      make_tar "$name"
      ;;
    freebsd)
      install -m 755 "$bin" "$stage/dunree"
      mkdir -p "$stage/rc.d"
      install -m 755 "$here/freebsd/dunree" "$stage/rc.d/dunree"
      install -m 644 "$here/freebsd/README-freebsd.txt" "$stage/README-freebsd.txt"
      install -m 644 "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES.md" "$stage/"
      make_tar "$name"
      ;;
    *)
      echo "no package layout for $os" >&2
      exit 1
      ;;
  esac
done

if [ "$have_nfpm" = 0 ] && [ "$nfpm_mode" != off ]; then
  echo "note: nfpm is not installed, so no .deb or .rpm was built"
fi
