#!/usr/bin/env bash
# Fill in the winget manifest templates for one release.
#
#   packaging/windows/winget/render.sh --version 1.0.0 --base-url URL --dist DIST_DIR --out OUT_DIR \
#       --publisher-url URL --package-url URL --license-url URL
#
# DIST_DIR must hold dunree_<version>_windows_amd64_setup.exe and ..._arm64_setup.exe (built
# on Windows from packaging/windows/dunree.iss); their SHA-256 goes into the manifest.
# BASE_URL is where those two files can be downloaded (no trailing slash). The addresses are
# arguments on purpose: the project's home is not decided, so none is written in the templates.
# Nothing is submitted anywhere: the three files in OUT_DIR are what a pull request to the
# winget package repository would contain.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="" base="" dist="" out="" publisher="" package="" license=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --base-url) base="${2%/}"; shift 2 ;;
    --dist) dist="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --publisher-url) publisher="$2"; shift 2 ;;
    --package-url) package="$2"; shift 2 ;;
    --license-url) license="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
for v in version base dist out publisher package license; do
  [ -n "${!v}" ] || { echo "--${v//_/-} is required (see the head of this script)" >&2; exit 2; }
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "--version must look like 1.0.0 or 1.0.0-beta.1" >&2; exit 2; }
case "$base$publisher$package$license" in
  *[\|\&\\]*) echo "addresses must not contain | & or \\" >&2; exit 2 ;;
esac

sum() {
  local f="$dist/dunree_${version}_windows_$1_setup.exe"
  [ -f "$f" ] || { echo "missing installer: $f" >&2; exit 1; }
  sha256sum "$f" | cut -d' ' -f1 | tr 'a-f' 'A-F'
}
sha_amd64="$(sum amd64)"
sha_arm64="$(sum arm64)"

mkdir -p "$out"
for tmpl in "$here"/*.yaml.tmpl; do
  name="$(basename "${tmpl%.tmpl}")"
  sed -e "s|\${VERSION}|$version|g" \
      -e "s|\${BASE_URL}|$base|g" \
      -e "s|\${SHA256_AMD64}|$sha_amd64|g" \
      -e "s|\${SHA256_ARM64}|$sha_arm64|g" \
      -e "s|\${PUBLISHER_URL}|$publisher|g" \
      -e "s|\${PACKAGE_URL}|$package|g" \
      -e "s|\${LICENSE_URL}|$license|g" \
      "$tmpl" | grep -v '^# winget .* template' >"$out/$name"
  if grep -q '\${' "$out/$name"; then
    echo "unfilled placeholder left in $out/$name" >&2
    exit 1
  fi
  echo "wrote $out/$name"
done
