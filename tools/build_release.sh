#!/usr/bin/env bash
# Cross-compile the Dunree release binaries, sign them and verify the result.
#
#   tools/build_release.sh -t TAG [-b BUILD] [-k PRIVATE_KEY.pem] [-o DIST_DIR] [-p]
#                          [--targets LIST] [--packages] [--no-legacy-names] [--dry-run]
#
# TAG is the release tag (e.g. v3.3.6-topic.1); it is signed into SHA256SUMS so
# the updater can refuse a replayed older release. BUILD is a monotonically
# increasing integer (default: current unix time) and must be larger than the
# previous release's build.
#
# Targets. Without --targets every default target is built:
#   linux/amd64 linux/arm64 linux/arm linux/386 linux/riscv64 linux/mipsle
#   windows/amd64 windows/arm64 darwin/amd64 darwin/arm64
# --targets takes a comma separated subset, e.g. --targets linux/amd64,windows/amd64.
# freebsd/amd64 and freebsd/arm64 are known but only built when named there.
# The files are called dunree_<os>_<arch>, with .exe for Windows.
#
# Legacy names. The updater of an existing install asks for zoraxy_linux_<arch>,
# so every Linux binary is also written under that name (a byte-identical copy,
# signed in the same SHA256SUMS). --no-legacy-names leaves the copies out; such
# a release cannot be installed by the in-app updater of an existing install.
#
# --packages also builds the archives (.tar.gz, .zip) and, when nfpm is on the
# PATH, the .deb and .rpm packages for the built targets with
# packaging/build_packages.sh. They are created before signing, so they are in
# SHA256SUMS too. Off by default.
#
# --dry-run prints what would be built, copied and signed and exits. It builds
# nothing, needs no key and does not touch DIST_DIR.
#
# The private key defaults to $DUNREE_RELEASE_KEY, then $ZORAXY_RELEASE_KEY,
# then ~/.dunree-release-key/private.pem, then ~/.zoraxy-release-key/private.pem.
# It is only passed by path to tools/sign_release.go and is never read, copied
# or printed by this script. The committed public key
# (src/mod/updater/release_pubkey.pem) is used to verify the produced
# SHA256SUMS.sig, so a wrong key aborts the build. $DUNREE_RELEASE_PUB (or the
# older $ZORAXY_RELEASE_PUB) names another public key, for tests with a
# throwaway key.
#
# Optional build-time addresses (shown in About, never contacted):
# $DUNREE_SOURCE_URL, $DUNREE_PRODUCT_URL, $DUNREE_SECURITY_CONTACT.
# $GO names the go command (default "go"), e.g. GO="$HOME/capped.sh go".
#
# -p (optional, off by default) also builds the fork's reference plugins into
# DIST_DIR/plugins and runs the conformance kit on them
# (tools/build_ref_plugins.sh). They are extra files: the release itself, its
# SHA256SUMS and its signature are the same with and without -p, and the
# reference plugins are not signed with the release key.
#
# Nothing is published: attach the files in DIST_DIR to a release by hand.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  echo "usage: $0 -t tag [-b build] [-k private.pem] [-o dist_dir] [-p] [--targets os/arch,...] [--packages] [--no-legacy-names] [--dry-run]" >&2
  exit 2
}

# os/arch[:GOARM]. The first block is the default release.
default_targets=(
  "linux/amd64" "linux/arm64" "linux/arm:6" "linux/386" "linux/riscv64" "linux/mipsle"
  "windows/amd64" "windows/arm64"
  "darwin/amd64" "darwin/arm64"
)
extra_targets=("freebsd/amd64" "freebsd/arm64")

key=""
dist="$root/dist"
pub="${DUNREE_RELEASE_PUB:-${ZORAXY_RELEASE_PUB:-$root/src/mod/updater/release_pubkey.pem}}"
tag=""
build="$(date +%s)"
refplugins=0
subset=""
dryrun=0
packages=0
legacy=1

while [ $# -gt 0 ]; do
  case "$1" in
    -k) [ $# -ge 2 ] || usage; key="$2"; shift 2 ;;
    -o) [ $# -ge 2 ] || usage; dist="$2"; shift 2 ;;
    -t) [ $# -ge 2 ] || usage; tag="$2"; shift 2 ;;
    -b) [ $# -ge 2 ] || usage; build="$2"; shift 2 ;;
    -p) refplugins=1; shift ;;
    --targets) [ $# -ge 2 ] || usage; subset="$2"; shift 2 ;;
    --targets=*) subset="${1#*=}"; shift ;;
    --dry-run) dryrun=1; shift ;;
    --packages) packages=1; shift ;;
    --no-legacy-names) legacy=0; shift ;;
    *) usage ;;
  esac
done

if [ -z "$key" ]; then
  key="${DUNREE_RELEASE_KEY:-${ZORAXY_RELEASE_KEY:-}}"
fi
if [ -z "$key" ]; then
  key="$HOME/.dunree-release-key/private.pem"
  [ -r "$key" ] || key="$HOME/.zoraxy-release-key/private.pem"
fi

[ -n "$tag" ] || { echo "-t TAG is required (the release tag to sign)" >&2; exit 2; }
case "$build" in ''|*[!0-9]*) echo "-b BUILD must be a positive integer" >&2; exit 2 ;; esac
[ -n "$dist" ] && [ "$dist" != "/" ] || { echo "-o DIST_DIR must not be empty or /" >&2; exit 2; }

# Resolve the target list.
targets=()
if [ -z "$subset" ]; then
  targets=("${default_targets[@]}")
else
  IFS=, read -r -a wanted <<<"$subset"
  for w in "${wanted[@]}"; do
    found=""
    for t in "${default_targets[@]}" "${extra_targets[@]}"; do
      if [ "${t%%:*}" = "$w" ]; then found="$t"; break; fi
    done
    [ -n "$found" ] || { echo "unknown target '$w'. Known: ${default_targets[*]%%:*} ${extra_targets[*]%%:*}" >&2; exit 2; }
    for t in "${targets[@]:-}"; do
      [ "$t" != "$found" ] || { echo "target '$w' is named twice" >&2; exit 2; }
    done
    targets+=("$found")
  done
fi
[ "${#targets[@]}" -gt 0 ] || { echo "no targets" >&2; exit 2; }

# The in-app updater smoke-tests the new binary and requires "Version X.Y.Z" in its output to match the tag.
srcver=$(sed -n 's/.*SYSTEM_VERSION *= *"\([^"]*\)".*/\1/p' "$root/src/def.go" | head -1)
tagver=$(printf '%s' "$tag" | sed -n 's/^v\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p')
[ "$srcver" = "$tagver" ] || { echo "tag $tag has base version '$tagver' but src/def.go SYSTEM_VERSION is '$srcver': the in-app updater would reject this build" >&2; exit 2; }

read -r -a gocmd <<<"${GO:-go}"

# The module path comes from src/go.mod, the one place it is written (see tools/rebrand/policy.json MODULE_ROOT).
module=$(sed -n 's/^module[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' "$root/src/go.mod" | head -1)
[ -n "$module" ] || { echo "cannot read the module path from src/go.mod" >&2; exit 1; }
ldflags="-s -w"
[ -z "${DUNREE_SOURCE_URL:-}" ] || ldflags="$ldflags -X $module/mod/brand.SourceURL=$DUNREE_SOURCE_URL"
[ -z "${DUNREE_PRODUCT_URL:-}" ] || ldflags="$ldflags -X $module/mod/brand.ProductURL=$DUNREE_PRODUCT_URL"
[ -z "${DUNREE_SECURITY_CONTACT:-}" ] || ldflags="$ldflags -X $module/mod/brand.SecurityContact=$DUNREE_SECURITY_CONTACT"

# asset_name os arch -> dunree_<os>_<arch>[.exe]
asset_name() {
  local n="dunree_$1_$2"
  [ "$1" != "windows" ] || n="$n.exe"
  printf '%s' "$n"
}

if [ "$dryrun" = 1 ]; then
  echo "DRY RUN for tag $tag, build $build, output $dist"
  for t in "${targets[@]}"; do
    IFS=: read -r pair goarm <<<"$t"
    goos="${pair%/*}"; goarch="${pair#*/}"
    echo "would build $(asset_name "$goos" "$goarch") (GOOS=$goos GOARCH=$goarch${goarm:+ GOARM=$goarm} CGO_ENABLED=0)"
    if [ "$legacy" = 1 ] && [ "$goos" = "linux" ]; then
      echo "would copy  $(asset_name "$goos" "$goarch") to zoraxy_linux_$goarch (legacy asset name)"
    fi
  done
  echo "would copy  crowdsec-setup.sh crowdsec-docker-compose.yml CROWDSEC-README.md"
  [ "$packages" = 0 ] || echo "would run   packaging/build_packages.sh (archives; .deb and .rpm when nfpm is installed)"
  echo "would sign  SHA256SUMS with the private key (path not shown) and verify it with $pub"
  [ "$refplugins" = 0 ] || echo "would build the reference plugins into $dist/plugins"
  echo "DRY RUN: nothing was built, signed or changed"
  exit 0
fi

[ -r "$key" ] || { echo "private key not readable: $key (use -k or \$DUNREE_RELEASE_KEY)" >&2; exit 1; }
[ -r "$pub" ] || { echo "public key not found: $pub" >&2; exit 1; }

rm -rf "$dist"
mkdir -p "$dist"
dist="$(cd "$dist" && pwd)"

built=()
cd "$root/src"
for t in "${targets[@]}"; do
  IFS=: read -r pair goarm <<<"$t"
  goos="${pair%/*}"; goarch="${pair#*/}"
  out="$dist/$(asset_name "$goos" "$goarch")"
  echo "building $out"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" ${goarm:+GOARM=$goarm} \
    "${gocmd[@]}" build -trimpath -ldflags "$ldflags" -o "$out" .
  chmod 755 "$out"
  built+=("$goos/$goarch")
  if [ "$legacy" = 1 ] && [ "$goos" = "linux" ]; then
    cp -p "$out" "$dist/zoraxy_linux_$goarch"
    cmp -s "$out" "$dist/zoraxy_linux_$goarch" || { echo "legacy copy of $out differs" >&2; exit 1; }
  fi
done
cd "$root"

# CrowdSec setup helpers: shipped as release assets, signed in SHA256SUMS like the binaries.
cs="$root/contrib/crowdsec"
cp "$cs/crowdsec-setup.sh" "$dist/crowdsec-setup.sh"
chmod 755 "$dist/crowdsec-setup.sh"
cp "$cs/docker-compose.yml" "$dist/crowdsec-docker-compose.yml"
cp "$cs/README.md" "$dist/CROWDSEC-README.md"
chmod 644 "$dist/crowdsec-docker-compose.yml" "$dist/CROWDSEC-README.md"

if [ "$packages" = 1 ]; then
  echo "packaging"
  pkgver="${tag#v}"
  "$root/packaging/build_packages.sh" --dist "$dist" --version "$pkgver" --targets "$(IFS=,; echo "${built[*]}")"
fi

echo "signing"
"${gocmd[@]}" run tools/sign_release.go -dist "$dist" -key "$key" -pub "$pub" -tag "$tag" -build "$build"

echo "verifying with the public key"
"${gocmd[@]}" run tools/sign_release.go -verify -dist "$dist" -pub "$pub"

if [ "$refplugins" = 1 ]; then
  # After signing and verifying, in a sub-folder: the signed release is not changed by this
  echo "building the reference plugins (optional, -p)"
  "$root/tools/build_ref_plugins.sh" -o "$dist/plugins" -c
fi

echo
echo "Release assets in $dist:"
ls -l "$dist"
echo "Attach all of them (dunree_* and zoraxy_* files, crowdsec-setup.sh, crowdsec-docker-compose.yml, CROWDSEC-README.md, SHA256SUMS, SHA256SUMS.sig) to the release."
