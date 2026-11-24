#!/bin/sh
# Build the macOS installer package for Dunree. Runs on macOS only (pkgbuild, lipo).
#
#   packaging/macos/build-pkg.sh --version 1.0.0 --dist DIST_DIR [--arch universal|amd64|arm64]
#                                [--sign "Developer ID Installer: NAME (TEAMID)"] [--dry-run]
#
# DIST_DIR holds dunree_darwin_amd64 and dunree_darwin_arm64 from tools/build_release.sh.
# "universal" (the default) joins both into one program with lipo.
# Result: DIST_DIR/dunree_<version>_darwin_<arch>.pkg
#
# The package installs
#   /usr/local/bin/dunree
#   /Library/LaunchDaemons/ie.foleyit.dunree.plist
#   /usr/local/share/doc/dunree/{LICENSE,NOTICE,THIRD_PARTY_NOTICES.md,uninstall.sh}
# and its postinstall script creates /usr/local/var/dunree and starts the daemon.
#
# Signing: --sign takes the NAME of an installer identity that is already in the keychain of
# the build machine. No key or certificate is read from or stored in this repository. Without
# --sign the package is unsigned and Gatekeeper asks the user to confirm it (right click, Open).
# Notarisation (xcrun notarytool submit ... --wait, then xcrun stapler staple) is a separate
# step that needs an Apple developer account; it is not done here.
#
# --dry-run prints the steps and runs nothing, so the script can be checked on any system.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
version=""
dist=""
arch=universal
sign=""
dry=no

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=$2; shift 2 ;;
    --dist) dist=$2; shift 2 ;;
    --arch) arch=$2; shift 2 ;;
    --sign) sign=$2; shift 2 ;;
    --dry-run) dry=yes; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$version" ] && [ -n "$dist" ] || { echo "--version and --dist are required" >&2; exit 2; }
case "$arch" in
  universal|amd64|arm64) ;;
  *) echo "--arch must be universal, amd64 or arm64" >&2; exit 2 ;;
esac
# pkgbuild wants a dotted numeric version: 1.0.0-beta.1 becomes 1.0.0 there, the file name keeps the full version.
pkgversion=$(printf '%s' "$version" | sed 's/[^0-9.].*$//')
[ -n "$pkgversion" ] || { echo "--version must start with a number" >&2; exit 2; }

run() {
  if [ "$dry" = yes ]; then
    echo "would run: $*"
  else
    "$@"
  fi
}

if [ "$dry" = no ]; then
  [ "$(uname -s)" = Darwin ] || { echo "this script needs macOS (pkgbuild). Use --dry-run elsewhere." >&2; exit 1; }
  if [ "$arch" = universal ]; then
    need="amd64 arm64"
  else
    need=$arch
  fi
  for a in $need; do
    [ -f "$dist/dunree_darwin_$a" ] || { echo "missing $dist/dunree_darwin_$a" >&2; exit 1; }
  done
fi

if [ "$dry" = yes ]; then
  stage="<temp folder>"
else
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
fi
payload="$stage/root"
out="$dist/dunree_${version}_darwin_${arch}.pkg"

run mkdir -p "$payload/usr/local/bin" "$payload/Library/LaunchDaemons" "$payload/usr/local/share/doc/dunree" "$stage/scripts"
if [ "$arch" = universal ]; then
  run lipo -create -output "$payload/usr/local/bin/dunree" "$dist/dunree_darwin_amd64" "$dist/dunree_darwin_arm64"
else
  run cp "$dist/dunree_darwin_$arch" "$payload/usr/local/bin/dunree"
fi
run chmod 755 "$payload/usr/local/bin/dunree"
run cp "$here/ie.foleyit.dunree.plist" "$payload/Library/LaunchDaemons/ie.foleyit.dunree.plist"
run cp "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES.md" "$here/uninstall.sh" "$payload/usr/local/share/doc/dunree/"
run cp "$here/scripts/preinstall" "$here/scripts/postinstall" "$stage/scripts/"
run chmod 755 "$stage/scripts/preinstall" "$stage/scripts/postinstall" "$payload/usr/local/share/doc/dunree/uninstall.sh"

if [ -n "$sign" ]; then
  run pkgbuild --root "$payload" --scripts "$stage/scripts" --identifier ie.foleyit.dunree \
    --version "$pkgversion" --install-location / --ownership recommended --sign "$sign" "$out"
else
  run pkgbuild --root "$payload" --scripts "$stage/scripts" --identifier ie.foleyit.dunree \
    --version "$pkgversion" --install-location / --ownership recommended "$out"
fi
echo "package: $out"
