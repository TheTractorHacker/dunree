#!/usr/bin/env bash
# Start a throw-away Dunree admin instance for UI work: ./instance.sh PORT
# Serves src/web LIVE from the checkout (symlink), so a CSS/HTML/JS edit shows after a reload; no rebuild needed.
# Own conf/db in a temp dir (never your real config). Prints the URL; stop it with: kill $(cat DIR/pid)
# The binary is built once into ~/.cache/ui-polish/dunree (rebuild with REBUILD=1 after Go changes).
set -euo pipefail
PORT="${1:?usage: instance.sh PORT}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="$HOME/.cache/ui-polish/dunree"
rm -f "$HOME/.cache/ui-polish/zoraxy"   # the binary under its earlier name; not used any more
mkdir -p "$(dirname "$bin")"
if [ ! -x "$bin" ] || [ "${REBUILD:-}" = 1 ]; then
  (cd "$root/src" && GOTMPDIR="$HOME/.cache/go-tmp" go build -o "$bin.tmp" . && mv "$bin.tmp" "$bin")
fi
dir="$(mktemp -d "$HOME/.cache/ui-polish/inst-$PORT-XXXX")"
ln -s "$root/src/web" "$dir/web"
mkdir -p "$dir/conf"; echo existing > "$dir/conf/existing-install.txt"   # looks like an existing install (no automatic baseline)
for pass in 1 2; do   # first start creates the db and runs upgrades
  (cd "$dir" && exec "$bin" -noauth -dev -allow_external_tools -default_inbound_port "$((PORT+1))" -port ":$PORT" -conf ./conf -dbpath ./sys.db >>dunree.log 2>&1) &
  pid=$!
  for _ in $(seq 60); do curl -fs "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 0.5; done
  if [ "$pass" = 1 ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
done
echo "$pid" > "$dir/pid"
echo "URL=http://127.0.0.1:$PORT  proxy-port=$((PORT+1))  dir=$dir  stop: kill \$(cat $dir/pid)"
