#!/usr/bin/env bash
# Plugin Manager scenario (phases 0, 1 and 2 of docs/plugins/reliability-plan.md): builds Zoraxy and the chaos test plugin
# (src/mod/plugins/testdata/chaosplugin, standard library only), starts ONE throw-away -noauth instance in a temp dir with three
# plugin folders and runs smoke.py --plugins-only --plugins-live (plugins_smoke.py: the mocked part, which is also in the full
# smoke.py run, plus the part against these real plugins) against it:
#   hostile   runs; its manifest (name, id, author, author_contact, description) is markup and quotes; it asks for two API
#             permissions (one endpoint name is markup). It is added after the first start, so it is a "new" plugin whose
#             permissions nobody approved
#   crasher   starts and exits with code 3 after 2 s
#   garbage   answers -introspect with garbage, so it cannot be loaded
# It also serves a local signed plugin index on PORT+3 (items 2.4, 2.5 and 2.7): two more chaos plugins that the scenario installs
# from it (rollme 1.0.0, whose version 1.1.0 crashes at start, for the update and the Roll back button; uiprobe, whose page tries
# to use the admin session, for the isolated plugin pages, which listen on PORT+2). The index is signed with a throw-away key
# made here by tools/plugin-index; no real key is read.
# Env: PY (python with playwright + chromium), PORT (default 18830), OUT (screenshot directory),
#      ZORAXY_BIN (use this Zoraxy binary instead of building one; it must contain the Go code of this checkout).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-18830}"
tmp="$(mktemp -d)"
pid=""
spid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null || true; [ -n "$spid" ] && kill "$spid" 2>/dev/null || true; sleep 1; rm -rf "$tmp"' EXIT
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
api_endpoints=GET /plugin/api/access/list;POST /plugin/api/x"'><img src=x onerror=window.__xss=24>
CONF
chaos crasher <<'CONF'
mode=crash
delay=2s
name=Chaos crasher
CONF
chaos garbage <<'CONF'
mode=introspect_garbage
CONF
# The local plugin store: binaries with settings of their own appended (see the chaos plugin), an index over them signed with a
# throw-away key, and the next index (serial 2, version 1.1.0 of rollme) the scenario publishes by copying it over the first.
store="$tmp/store"
mkdir -p "$store/next" "$tmp/keys"
SPORT="$((PORT+3))"
variant() { cp "$tmp/chaos" "$store/$1"; printf '\n##CHAOS-TRAILER##\n%b\n' "$2" >>"$store/$1"; }
variant rollme-1.0.0 'version=1.0.0\nname=Chaos rollme'
variant rollme-1.1.0 'version=1.1.0\nmode=crash\nname=Chaos rollme'
variant uiprobe-1.0.0 'version=1.0.0\nfeatures=adminprobe\nname=Chaos uiprobe'
indextool() { (cd "$root/tools/plugin-index" && go run sign_plugin_index.go "$@"); }
draft() { # draft ROLLME_VERSION ROLLME_MINOR
  cat <<JSON
{"format":"zoraxy-plugin-index","version":1,"plugins":[
 {"IconPath":"","PluginIntroSpect":{"id":"test.chaos.rollme","name":"rollme","author":"test","description":"update and rollback fixture","ui_path":"/ui","version_major":1,"version_minor":$2,"version_patch":0},
  "Downloads":{"$(go env GOOS)_$(go env GOARCH)":{"url":"http://127.0.0.1:$SPORT/rollme-$1"}}},
 {"IconPath":"","PluginIntroSpect":{"id":"test.chaos.uiprobe","name":"uiprobe","author":"test","description":"plugin page fixture","ui_path":"/ui","version_major":1,"version_minor":0,"version_patch":0},
  "Downloads":{"$(go env GOOS)_$(go env GOARCH)":{"url":"http://127.0.0.1:$SPORT/uiprobe-1.0.0"}}}]}
JSON
}
indextool -genkey "$tmp/keys/index.pem" "$tmp/keys/index.pub" >/dev/null
draft 1.0.0 0 >"$tmp/draft1.json"
draft 1.1.0 1 >"$tmp/draft2.json"
indextool -index "$tmp/draft1.json" -out "$store/index.json" -key "$tmp/keys/index.pem" -serial 1 -files "$store" -allow-http >/dev/null
indextool -index "$tmp/draft2.json" -out "$store/next/index.json" -key "$tmp/keys/index.pem" -serial 2 -files "$store" -allow-http >/dev/null
(cd "$store" && exec "$PY" -m http.server "$SPORT" --bind 127.0.0.1 >/dev/null 2>&1) &
spid=$!
# Folders dropped into the plugin directory have no stored state, so Zoraxy starts them at boot (the upstream rule).
start_zoraxy
PLUGINS_STORE_URL="http://127.0.0.1:$SPORT" PLUGINS_STORE_DIR="$store" PLUGINS_INDEX_PUB="$tmp/keys/index.pub" PLUGINS_UI_LISTEN="127.0.0.1:$((PORT+2))" \
"$PY" "$here/smoke.py" --url "http://127.0.0.1:$PORT" --plugins-only --plugins-live ${OUT:+--out "$OUT"} "$@"
