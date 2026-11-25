#!/usr/bin/env bash
# Cross-compile the Dunree release binaries, sign them and verify the result.
#
#   tools/build_release.sh -t TAG [-b BUILD] [-k PRIVATE_KEY.pem] [-o DIST_DIR] [-p]
#                          [--targets LIST | --targets-subset LIST] [--packages] [--dry-run]
#
# TAG is the release tag: "v" plus the Dunree version of the source tree
# (PRODUCT_VERSION, mod/brand Version), e.g. v1.0.0-beta.1. A tag for another
# version is refused: the in-app updater runs the new program with -version and
# requires exactly the version of the tag. The tag is signed into SHA256SUMS so
# the updater can refuse a replayed older release. BUILD is a monotonically
# increasing integer (default: current unix time) and must be larger than the
# previous release's build.
#
# Targets. Without --targets every default target is built (the full release):
#   linux/amd64 linux/arm64 linux/arm linux/386 linux/riscv64 linux/mipsle
#   windows/amd64 windows/arm64 darwin/amd64 darwin/arm64
# --targets takes a comma separated subset, e.g. --targets linux/amd64,windows/amd64.
# freebsd/amd64 and freebsd/arm64 are known but only built when named there.
# The files are called dunree_<os>_<arch>, with .exe for Windows.
#
# --targets-subset LIST is the test mode: it builds the named targets like
# --targets, so that the whole path (build, sign, verify) can be tried in a
# minute or two, and marks the result as not being a release: the output says
# so and DIST_DIR gets a file NOT-A-COMPLETE-RELEASE.txt (it is not signed and
# not in SHA256SUMS). Use --targets for a real release with fewer targets.
#
# The signed first line of SHA256SUMS is
#   # dunree-release product=dunree tag=TAG build=BUILD upstream=COMPAT_VERSION
# where COMPAT_VERSION is the version of the code base Dunree is derived from
# (mod/brand BasedOnVersion). Only Dunree's own updater installs such a
# release. The updater of the earlier fork does not: it asks for other file
# names and another header, and its version numbers are higher. An install of
# that fork is switched by replacing the program file, see the migration guide
# in docs/. --no-legacy-names is still accepted and does nothing (copies under
# the earlier file names are not made any more).
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
  echo "usage: $0 -t tag [-b build] [-k private.pem] [-o dist_dir] [-p] [--targets os/arch,... | --targets-subset os/arch,...] [--packages] [--dry-run]" >&2
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
subset_mode=0
subset_given=0

while [ $# -gt 0 ]; do
  case "$1" in
    -k) [ $# -ge 2 ] || usage; key="$2"; shift 2 ;;
    -o) [ $# -ge 2 ] || usage; dist="$2"; shift 2 ;;
    -t) [ $# -ge 2 ] || usage; tag="$2"; shift 2 ;;
    -b) [ $# -ge 2 ] || usage; build="$2"; shift 2 ;;
    -p) refplugins=1; shift ;;
    --targets) [ $# -ge 2 ] || usage; subset="$2"; subset_given=$((subset_given + 1)); shift 2 ;;
    --targets=*) subset="${1#*=}"; subset_given=$((subset_given + 1)); shift ;;
    --targets-subset) [ $# -ge 2 ] || usage; subset="$2"; subset_mode=1; subset_given=$((subset_given + 1)); shift 2 ;;
    --targets-subset=*) subset="${1#*=}"; subset_mode=1; subset_given=$((subset_given + 1)); shift ;;
    --dry-run) dryrun=1; shift ;;
    --packages) packages=1; shift ;;
    --no-legacy-names) shift ;; # accepted for older command lines; there are no such copies any more
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
[ "$subset_given" -le 1 ] || { echo "give --targets or --targets-subset once, not both" >&2; exit 2; }
[ "$subset_given" = 0 ] || [ -n "$subset" ] || { echo "the target list is empty" >&2; exit 2; }
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

# The two version numbers of the source tree (src/mod/brand/brand.go; src/def.go names them
# PRODUCT_VERSION and COMPAT_VERSION).
brandgo="$root/src/mod/brand/brand.go"
product_version=$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$brandgo" | head -1)
compat_version=$(sed -n 's/^[[:space:]]*BasedOnVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$brandgo" | head -1)
[ -n "$product_version" ] && [ -n "$compat_version" ] || { echo "cannot read Version and BasedOnVersion from $brandgo" >&2; exit 1; }
# The tag is "v" plus PRODUCT_VERSION, exactly: the in-app updater runs the new program with
# -version and requires the version of the tag in its output, pre-release part included.
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
printf '%s' "$tag" | grep -Eq "$semver" || { echo "tag '$tag' is not a Dunree release tag (vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-PRERELEASE, e.g. v$product_version)" >&2; exit 2; }
[ "$tag" = "v$product_version" ] || { echo "tag $tag is for version '${tag#v}' but the source tree is Dunree $product_version (mod/brand Version): the in-app updater would reject this build. Tag it v$product_version, or change the version first." >&2; exit 2; }

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
  echo "DRY RUN for tag $tag (Dunree $product_version, based on $compat_version), build $build, output $dist"
  [ "$subset_mode" = 0 ] || echo "TEST MODE (--targets-subset): the result would not be a complete release"
  for t in "${targets[@]}"; do
    IFS=: read -r pair goarm <<<"$t"
    goos="${pair%/*}"; goarch="${pair#*/}"
    echo "would build $(asset_name "$goos" "$goarch") (GOOS=$goos GOARCH=$goarch${goarm:+ GOARM=$goarm} CGO_ENABLED=0)"
  done
  echo "would copy  crowdsec-setup.sh crowdsec-docker-compose.yml CROWDSEC-README.md"
  [ "$packages" = 0 ] || echo "would run   packaging/build_packages.sh (archives; .deb and .rpm when nfpm is installed)"
  echo "would sign  SHA256SUMS with the private key (path not shown) and verify it with $pub"
  echo "would write the header: # dunree-release product=dunree tag=$tag build=$build upstream=$compat_version"
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
"${gocmd[@]}" run tools/sign_release.go -dist "$dist" -key "$key" -pub "$pub" -tag "$tag" -build "$build" -upstream "$compat_version"

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
if [ "$subset_mode" = 1 ]; then
  printf '%s\n' "This folder was built with --targets-subset (${subset}): a test build, not a complete Dunree release." \
    "Do not publish it. A release is built without --targets-subset." >"$dist/NOT-A-COMPLETE-RELEASE.txt"
  echo "TEST MODE (--targets-subset $subset): this is NOT a complete release. Do not publish it."
else
  echo "Attach all of them (dunree_* files, crowdsec-setup.sh, crowdsec-docker-compose.yml, CROWDSEC-README.md, SHA256SUMS, SHA256SUMS.sig) to the release."
fi
