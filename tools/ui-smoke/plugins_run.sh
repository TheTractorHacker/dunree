#!/usr/bin/env bash
# Plugin Manager scenario (phases 0 and 1 of docs/plugins/reliability-plan.md): builds Zoraxy and the chaos test plugin
# (src/mod/plugins/testdata/chaosplugin, standard library only), starts ONE throw-away -noauth instance in a temp dir with three
# plugin folders and runs smoke.py --plugins-only --plugins-live (plugins_smoke.py: the mocked part, which is also in the full
# smoke.py run, plus the part against these real plugins) against it:
#   hostile   runs; its manifest (name, id, author, author_contact, description) is markup and quotes
#   crasher   starts and exits with code 3 after 2 s
#   garbage   answers -introspect with garbage, so it cannot be loaded
# Env: PY (python with playwright + chromium), PORT (default 18830), OUT (screenshot directory),
#      ZORAXY_BIN (use this Zoraxy binary instead of building one; it must contain the Go code of this checkout).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-18830}"
tmp="$(mktemp -d)"
pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null || true; sleep 1; rm -rf "$tmp"' EXIT
if [ -n "${ZORAXY_BIN:-}" ]; then
  cp "$ZORAXY_BIN" "$tmp/zoraxy"
else
  (cd "$root/src" && go build -o "$tmp/zoraxy" .)
fi
(cd "$root/src" && CGO_ENABLED=0 go build -o "$tmp/chaos" ./mod/plugins/testdata/chaosplugin)
ln -s "$root/src/web" "$tmp/web"
mkdir -p "$tmp/conf"
echo "seeded by plugins_run.sh: marks this throw-away instance as an existing installation" >"$tmp/conf/existing-install.txt"
start_zoraxy() {
  (cd "$tmp" && exec ./zoraxy -noauth -dev -default_inbound_port "$((PORT+1))" -port ":$PORT" -conf ./conf -dbpath ./sys.db >>zoraxy.log 2>&1) &
  pid=$!
  for _ in $(seq 60); do curl -fs "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 0.5; done
}
# First start: creates the database and runs the config upgrades, without plugins.
start_zoraxy
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
chaos() { # chaos FOLDER  (chaos.conf on stdin)
  mkdir -p "$tmp/plugins/$1"
  cp "$tmp/chaos" "$tmp/plugins/$1/$1"
  cat >"$tmp/plugins/$1/chaos.conf"
}
chaos hostile <<'CONF'
mode=ok
name=Hostile <img src=x onerror=window.__xss=1>
id=test.chaos.hostile"'><img src=x onerror=window.__xss=2>
author=<img src=x onerror=window.__xss=3>"'><script>window.__xss=4</script>
author_contact=javascript:window.__xss=5//"><img src=x onerror=window.__xss=6>
description=</td></tr><img src=x onerror=window.__xss=7> "double" 'single' &amp;
CONF
chaos crasher <<'CONF'
mode=crash
delay=2s
name=Chaos crasher
CONF
chaos garbage <<'CONF'
mode=introspect_garbage
CONF
# Folders dropped into the plugin directory have no stored state, so Zoraxy starts them at boot (the upstream rule).
start_zoraxy
"$PY" "$here/smoke.py" --url "http://127.0.0.1:$PORT" --plugins-only --plugins-live ${OUT:+--out "$OUT"} "$@"
