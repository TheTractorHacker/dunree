#!/usr/bin/env bash
# Cluster / HA scenario with TWO Dunree processes on this host (issue #81): builds Dunree, starts a primary and a follower
# (each -noauth in its own temp dir with its own conf, database and ports, both with the same generated cluster secret)
# and runs cluster_ha_smoke.py: the Cluster page (sync settings, keep own listening ports), settings sync from the
# primary's database into the follower's, and an SSO portal (ZorxAuth) sign-in on one node that is valid on the other.
# Two processes on one host are not two hosts: no VRRP, no real network between the nodes (see DEVELOPMENT.md).
# Env: PY (python with playwright), PORT (default 21305, uses PORT..PORT+6), OUT (screenshot directory), BIN (prebuilt binary).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-21305}"
tmp="$(mktemp -d)"
trap 'for f in "$tmp"/*/pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done; sleep 1; rm -rf "$tmp"' EXIT
if [ -n "${BIN:-}" ]; then cp "$BIN" "$tmp/dunree"; else (cd "$root/src" && go build -o "$tmp/dunree" .); fi
secret="$("$tmp/dunree" -cluster_gen_secret | tail -n 1)"
start() { # name admin-port inbound-port
  local dir="$tmp/$1"
  mkdir -p "$dir/conf"
  ln -s "$root/src/web" "$dir/web"
  echo "marks this throw-away instance as an existing installation" >"$dir/conf/existing-install.txt"
  # shared SSO portal sign-ins are opt-in: on for the primary through the config file, the follower switches them on in the UI
  printf '{"role":"standalone","secret":"%s"%s}\n' "$secret" "$([ "$1" = primary ] && echo ',"sharedSsoSessions":true')" >"$dir/conf/cluster.json"
  chmod 600 "$dir/conf/cluster.json"
  # the follower restarts itself after a sync (exec, same pid), so the pid file stays valid
  (cd "$dir" && exec "$tmp/dunree" -noauth -dev -offline -default_inbound_port "$3" -port ":$2" -conf ./conf -dbpath ./sys.db >>dunree.log 2>&1) &
  echo $! >"$dir/pid"
  for _ in $(seq 80); do curl -fs "http://127.0.0.1:$2/" >/dev/null && return 0; sleep 0.5; done
  echo "instance $1 did not start"; tail -n 30 "$dir/dunree.log"; return 1
}
start primary "$PORT" "$((PORT+2))"
start follower "$((PORT+1))" "$((PORT+3))"
"$PY" "$here/cluster_ha_smoke.py" --primary "http://127.0.0.1:$PORT" --follower "http://127.0.0.1:$((PORT+1))" \
  --primary-proxy "$((PORT+2))" --follower-proxy "$((PORT+3))" --primary-gateway "$((PORT+4))" --follower-gateway "$((PORT+5))" \
  --upstream "$((PORT+6))" --follower-dir "$tmp/follower" ${OUT:+--out "$OUT"} "$@" || { rc=$?; tail -n 25 "$tmp/follower/dunree.log"; exit $rc; }
