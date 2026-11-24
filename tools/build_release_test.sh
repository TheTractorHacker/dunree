#!/usr/bin/env bash
# Test of tools/build_release.sh with a throwaway key. Never touches the real release key or ./dist.
#
#   tools/build_release_test.sh [--build]
#
# Without --build only the checks that compile nothing run (argument handling, --dry-run).
# With --build two targets (linux/amd64 and windows/amd64) are really built, packaged, signed
# and verified in a temporary folder; that takes a few minutes and about 150 MB there (set
# $TMPDIR when /tmp is small). $GO names the go command.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/tools/build_release.sh"
real_build=0
[ "${1:-}" != "--build" ] || real_build=1
read -r -a gocmd <<<"${GO:-go}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }

ver=$(sed -n 's/.*SYSTEM_VERSION *= *"\([^"]*\)".*/\1/p' "$root/src/def.go" | head -1)
tag="v$ver-test.1"
# No key anywhere: a dry run must not need one, and nothing may fall back to a real key.
# Go keeps using its normal caches (they are found through HOME by default).
GOCACHE="$("${gocmd[@]}" env GOCACHE)"; GOMODCACHE="$("${gocmd[@]}" env GOMODCACHE)"; GOPATH="$("${gocmd[@]}" env GOPATH)"
export GOCACHE GOMODCACHE GOPATH
export HOME="$tmp/home"
mkdir -p "$HOME"
unset DUNREE_RELEASE_KEY ZORAXY_RELEASE_KEY DUNREE_RELEASE_PUB ZORAXY_RELEASE_PUB

# 1. dry run: the full default matrix, nothing written
out="$("$script" -t "$tag" -b 5 -o "$tmp/never" --dry-run 2>&1)" || bad "dry run failed: $out"
[ ! -e "$tmp/never" ] && ok "dry run does not create the output folder" || bad "dry run created the output folder"
for a in dunree_linux_amd64 dunree_linux_arm64 dunree_linux_arm dunree_linux_386 dunree_linux_riscv64 dunree_linux_mipsle \
         dunree_windows_amd64.exe dunree_windows_arm64.exe dunree_darwin_amd64 dunree_darwin_arm64; do
  printf '%s\n' "$out" | grep -q "^would build $a " || bad "dry run: $a is not in the default targets"
done
[ "$(printf '%s\n' "$out" | grep -c '^would build ')" = 10 ] && ok "dry run lists the 10 default targets" || bad "dry run: wrong number of targets"
printf '%s\n' "$out" | grep -q "would build dunree_linux_arm (GOOS=linux GOARCH=arm GOARM=6 " && ok "linux/arm is built with GOARM=6" || bad "linux/arm GOARM"
[ "$(printf '%s\n' "$out" | grep -c 'to zoraxy_linux_')" = 6 ] && ok "six legacy copies, Linux only" || bad "legacy copies"
printf '%s\n' "$out" | grep -q "freebsd" && bad "freebsd must not be a default target" || ok "freebsd is not a default target"

# 2. subset and switches
out="$("$script" -t "$tag" --targets linux/amd64,freebsd/amd64 --no-legacy-names --packages --dry-run 2>&1)" || bad "subset dry run failed"
[ "$(printf '%s\n' "$out" | grep -c '^would build ')" = 2 ] && printf '%s\n' "$out" | grep -q "would build dunree_freebsd_amd64 " \
  && ! printf '%s\n' "$out" | grep -q "zoraxy_linux_" && printf '%s\n' "$out" | grep -q "build_packages.sh" \
  && ok "--targets, --no-legacy-names and --packages" || bad "subset dry run: $out"

# 3. refusals (all before anything is built)
refuse() { # name, then the arguments
  local name="$1"; shift
  if "$script" "$@" >/dev/null 2>&1; then bad "$name was accepted"; else ok "$name is refused"; fi
}
refuse "a missing tag" --dry-run
refuse "an unknown target" -t "$tag" --targets linux/s390x --dry-run
refuse "a target named twice" -t "$tag" --targets linux/amd64,linux/amd64 --dry-run
refuse "a tag for another version" -t v0.0.1 --dry-run
refuse "a build number that is not a number" -t "$tag" -b abc --dry-run
refuse "an unknown option" -t "$tag" --publish --dry-run
refuse "a missing private key" -t "$tag" -o "$tmp/nokey" --targets linux/amd64
[ ! -e "$tmp/nokey" ] && ok "nothing is built without a key" || bad "output folder created without a key"

if [ "$real_build" = 1 ]; then
  # 4. a real build of two targets with a throwaway key
  (cd "$root" && "${gocmd[@]}" run tools/sign_release.go -genkey "$tmp/k.pem" "$tmp/k.pub") >/dev/null
  d="$tmp/dist"
  if DUNREE_RELEASE_PUB="$tmp/k.pub" DUNREE_SOURCE_URL="https://source.example/dunree" \
       "$script" -t "$tag" -b 7 -k "$tmp/k.pem" -o "$d" --targets linux/amd64,windows/amd64 --packages >"$tmp/build.log" 2>&1; then
    ok "build, package, sign and verify of linux/amd64 and windows/amd64"
  else
    bad "real build failed: $(tail -20 "$tmp/build.log")"
    echo "1 check FAILED (the remaining checks need the build)"
    exit 1
  fi
  for f in dunree_linux_amd64 dunree_windows_amd64.exe zoraxy_linux_amd64 SHA256SUMS SHA256SUMS.sig \
           "dunree_${tag#v}_linux_amd64.tar.gz" "dunree_${tag#v}_windows_amd64.zip" crowdsec-setup.sh; do
    [ -f "$d/$f" ] || bad "$f was not produced"
  done
  [ ! -e "$d/zoraxy_windows_amd64.exe" ] || bad "a legacy copy was made for Windows"
  cmp -s "$d/dunree_linux_amd64" "$d/zoraxy_linux_amd64" && ok "the legacy copy is byte-identical" || bad "the legacy copy differs"
  (cd "$d" && sha256sum -c SHA256SUMS >/dev/null 2>&1) && ok "sha256sum -c SHA256SUMS" || bad "sha256sum -c SHA256SUMS"
  for f in dunree_linux_amd64 dunree_windows_amd64.exe zoraxy_linux_amd64 "dunree_${tag#v}_linux_amd64.tar.gz" "dunree_${tag#v}_windows_amd64.zip"; do
    grep -q "  $f\$" "$d/SHA256SUMS" || bad "$f is not signed in SHA256SUMS"
  done
  head -1 "$d/SHA256SUMS" | grep -q "^# zoraxy-release tag=$tag build=7 upstream=$ver\$" && ok "signed header (tag and build)" || bad "signed header: $(head -1 "$d/SHA256SUMS")"
  head -c 2 "$d/dunree_windows_amd64.exe" | grep -q '^MZ' && ok "the Windows binary is a PE file" || bad "the Windows binary is not a PE file"
  if "$d/dunree_linux_amd64" -version 2>/dev/null | grep -q "Version $ver"; then ok "the Linux binary runs and reports version $ver"; else bad "the Linux binary does not report its version"; fi
  # "service" off Windows: a clear message, exit 2, and nothing started
  set +e
  svc_out="$(cd "$tmp" && "$d/dunree_linux_amd64" service status 2>&1)"; svc_code=$?
  set -e
  if [ "$svc_code" = 2 ] && printf '%s' "$svc_out" | grep -q "only available on Windows" && [ ! -e "$tmp/conf" ] && [ ! -e "$tmp/sys.db" ]; then
    ok "'dunree service' off Windows: message, exit 2, no files created"
  else
    bad "'dunree service' off Windows: exit $svc_code: $svc_out"
  fi
  # a normal start is unchanged by the service code: it serves, and SIGTERM ends it cleanly with exit 0
  run="$tmp/run"; mkdir -p "$run"
  port="${DUNREE_TEST_PORT:-24731}"
  (cd "$run" && exec "$d/dunree_linux_amd64" -port="127.0.0.1:$port" -mdns=false -default_inbound_enabled=false -offline=true >"$tmp/run.log" 2>&1) &
  pid=$!
  up=0
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null "http://127.0.0.1:$port/"; then up=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  if [ "$up" = 1 ]; then ok "the built binary starts and the admin port answers"; else bad "the built binary did not start: $(tail -5 "$tmp/run.log")"; fi
  kill -TERM "$pid" 2>/dev/null || true
  set +e; wait "$pid"; code=$?; set -e
  if [ "$up" = 1 ] && [ "$code" = 0 ]; then ok "SIGTERM runs the stop sequence and the process exits 0"; else bad "exit code $code after SIGTERM: $(tail -5 "$tmp/run.log")"; fi
  [ -d "$run/conf" ] && [ ! -e "$run/log/service.log" ] && ok "data is in the start folder; no service.log outside a Windows service" || bad "unexpected files in the start folder: $(ls "$run")"
  grep -aq "https://source.example/dunree" "$d/dunree_linux_amd64" && ok "the source address is set through the module path from go.mod" || bad "DUNREE_SOURCE_URL is not in the binary"
  # a tampered file is caught by the verify step
  printf 'x' >>"$d/dunree_windows_amd64.exe"
  if (cd "$root" && "${gocmd[@]}" run tools/sign_release.go -verify -dist "$d" -pub "$tmp/k.pub") >/dev/null 2>&1; then bad "a tampered binary verified"; else ok "a tampered binary fails verification"; fi
  # the wrong public key aborts the build
  (cd "$root" && "${gocmd[@]}" run tools/sign_release.go -genkey "$tmp/k2.pem" "$tmp/k2.pub") >/dev/null
  if DUNREE_RELEASE_PUB="$tmp/k2.pub" "$script" -t "$tag" -b 8 -k "$tmp/k.pem" -o "$tmp/dist2" --targets linux/amd64 >/dev/null 2>&1; then
    bad "a key that does not match the public key was accepted"
  else
    ok "a key that does not match the public key aborts the build"
  fi
else
  echo "skip  real build (run with --build)"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails check(s) FAILED"
  exit 1
fi
echo "OK, build_release checks passed"
