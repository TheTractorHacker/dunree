#!/usr/bin/env bash
# Brand scenario: builds Dunree, starts ONE throw-away -noauth instance in a temp dir and runs smoke.py --brand-only
# (brand_smoke.py: logo in the top bar and on the login page, icons, attribution footer, About, source offer, Credits).
# The scenario only reads. Env: PY (python with playwright), PORT (default 18840), OUT (screenshot directory).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-18840}"
tmp="$(mktemp -d)"
pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
(cd "$root/src" && go build -o "$tmp/dunree" .)
ln -s "$root/src/web" "$tmp/web"
(cd "$tmp" && exec ./dunree -noauth -dev -default_inbound_port "$((PORT+1))" -port ":$PORT" -conf ./conf -dbpath ./sys.db >>dunree.log 2>&1) &
pid=$!
for _ in $(seq 60); do curl -s -o /dev/null "http://127.0.0.1:$PORT/login.html" && break; sleep 0.5; done
"$PY" "$here/smoke.py" --url "http://127.0.0.1:$PORT" --brand-only ${OUT:+--out "$OUT"} "$@"
