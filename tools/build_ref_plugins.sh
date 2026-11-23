#!/usr/bin/env bash
# Build the fork's reference plugins (example/plugins/fork-ref-*) for Linux and,
# with -c, run the conformance kit (tools/plugin-check) on the ones this machine
# can run.
#
#   tools/build_ref_plugins.sh -o OUT_DIR [-a "amd64 arm64"] [-c]
#
# OUT_DIR gets <plugin>_linux_<arch> for every plugin and architecture, and a
# plain SHA256SUMS. Nothing is signed here and nothing is published: these files
# are NOT part of the signed Zoraxy release (SHA256SUMS.sig of the release does
# not cover them). To offer them in a plugin index, list them in a draft index
# and sign it with the PLUGIN key (tools/plugin-index/sign_plugin_index.go), never
# with the release key.
#
# Everything builds offline: the plugins only use the SDK copy in their mod/ folder.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""
arches="amd64 arm64 arm 386 riscv64 mipsle"
check=0
while getopts "o:a:c" opt; do
  case "$opt" in
    o) out="$OPTARG" ;;
    a) arches="$OPTARG" ;;
    c) check=1 ;;
    *) echo "usage: $0 -o out_dir [-a \"amd64 arm64\"] [-c]" >&2; exit 2 ;;
  esac
done
[ -n "$out" ] || { echo "-o OUT_DIR is required" >&2; exit 2; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"

plugins=(fork-ref-filter fork-ref-events fork-ref-ui-api)
export CGO_ENABLED=0 GOOS=linux GOPROXY=off GOWORK=off GOFLAGS="${GOFLAGS:+$GOFLAGS }-mod=mod"

for p in "${plugins[@]}"; do
  # the SDK copy of a reference plugin must be the SDK of this tree
  if ! diff -rq "$root/src/mod/plugins/zoraxy_plugin" "$root/example/plugins/$p/mod/zoraxy_plugin" >/dev/null; then
    echo "example/plugins/$p/mod/zoraxy_plugin differs from src/mod/plugins/zoraxy_plugin (run example/plugins/build_all.sh)" >&2
    exit 1
  fi
  for a in $arches; do
    goarm=""
    [ "$a" = "arm" ] && goarm=6
    echo "building ${p}_linux_$a"
    (cd "$root/example/plugins/$p" && env GOARCH="$a" ${goarm:+GOARM=$goarm} go build -trimpath -ldflags "-s -w" -o "$out/${p}_linux_$a" .)
    chmod 755 "$out/${p}_linux_$a"
  done
done

(cd "$out" && sha256sum fork-ref-*_linux_* > SHA256SUMS)

if [ "$check" = 1 ]; then
  host="$(go env GOHOSTARCH)"
  kit="$(mktemp -d)/plugin-check"
  trap 'rm -rf "$(dirname "$kit")"' EXIT
  (cd "$root/tools/plugin-check" && env -u GOOS GOARCH="$host" go build -o "$kit" .)
  ran=0
  for p in "${plugins[@]}"; do
    bin="$out/${p}_linux_$host"
    [ -x "$bin" ] || continue
    # the kit wants the entry point as Zoraxy sees it: <folder>/<folder name>
    stage="$(dirname "$kit")/$p"
    mkdir -p "$stage"
    cp "$bin" "$stage/$p"
    echo "conformance kit: $p ($host)"
    "$kit" ${PLUGIN_CHECK_PORTS:+-ports "$PLUGIN_CHECK_PORTS"} -out "$out/${p}_conformance.json" "$stage/$p" >"$out/${p}_conformance.txt" || {
      cat "$out/${p}_conformance.txt" >&2
      echo "$p does not pass the conformance kit" >&2
      exit 1
    }
    tail -n 1 "$out/${p}_conformance.txt"
    ran=$((ran + 1))
  done
  [ "$ran" -gt 0 ] || echo "no binary for this machine ($host) was built: the conformance kit was not run" >&2
fi

echo
echo "Reference plugins in $out (not signed, not part of the Zoraxy release checksums):"
ls -l "$out"
