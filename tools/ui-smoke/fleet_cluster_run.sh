#!/usr/bin/env bash
# Fleet and Cluster / HA as two separate pages, with THREE Dunree processes on this host: a Fleet hub and two nodes
# (each -noauth in its own temp dir with its own conf, database and ports). Runs fleet_cluster_smoke.py: no cross-link
# tab strip on either page, the Cluster / HA page locked as a hub and as a node with one sentence and one button, a node the
# hub removed ("the hub no longer accepts this node" + Leave Fleet), leaving, the hub role switched off, and that neither
# page ever shows an old role (menu, window focus, role change on the other page). Light, dark and 390 px screenshots.
# Three processes on one host are not three hosts: plain http between them, no real network (see DEVELOPMENT.md).
# Env: PY (python with playwright), PORT (default 21405, uses PORT..PORT+5), OUT (screenshot directory), BIN (prebuilt binary).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-21405}"
tmp="$(mktemp -d)"
trap 'for f in "$tmp"/*/pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done; sleep 1; rm -rf "$tmp"' EXIT
if [ -n "${BIN:-}" ]; then cp "$BIN" "$tmp/dunree"; else (cd "$root/src" && go build -o "$tmp/dunree" .); fi
start() { # name admin-port inbound-port
  local dir="$tmp/$1"
  mkdir -p "$dir/conf"
  ln -s "$root/src/web" "$dir/web"
  echo "marks this throw-away instance as an existing installation" >"$dir/conf/existing-install.txt"
  (cd "$dir" && exec "$tmp/dunree" -noauth -dev -offline -default_inbound_port "$3" -port ":$2" -conf ./conf -dbpath ./sys.db >>dunree.log 2>&1) &
  echo $! >"$dir/pid"
  for _ in $(seq 80); do curl -fs "http://127.0.0.1:$2/" >/dev/null && return 0; sleep 0.5; done
  echo "instance $1 did not start"; tail -n 30 "$dir/dunree.log"; return 1
}
start hub "$PORT" "$((PORT+3))"
start node-a "$((PORT+1))" "$((PORT+4))"
start node-b "$((PORT+2))" "$((PORT+5))"
"$PY" "$here/fleet_cluster_smoke.py" --hub "http://127.0.0.1:$PORT" --node-a "http://127.0.0.1:$((PORT+1))" --node-b "http://127.0.0.1:$((PORT+2))" \
  ${OUT:+--out "$OUT"} "$@" || { rc=$?; for n in hub node-a node-b; do echo "--- $n"; tail -n 8 "$tmp/$n/dunree.log"; done; exit $rc; }
