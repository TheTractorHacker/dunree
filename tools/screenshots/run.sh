#!/usr/bin/env bash
# Regenerate docs/img/screenshots/: build Dunree from this checkout and run capture.py against throw-away instances
# with demo data (own temp folder, own ports on 127.0.0.1; never a real configuration). See capture.py for what it does.
# Needs a python with playwright + chromium (see DEVELOPMENT.md), openssl and Go.
# Env: PY (python with playwright, default python3), PORT (first of 20 free ports, default 25600),
#      MINUTES (how long the demo traffic runs before the pictures are taken, default 12; 30 fills the charts),
#      BIN (a prebuilt Dunree to use instead of building one).
# Extra arguments are passed to capture.py (for example --only status,sites or --out DIR).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
PY="${PY:-python3}"
PORT="${PORT:-25600}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if [ -n "${BIN:-}" ]; then cp "$BIN" "$tmp/dunree"; else (cd "$root/src" && go build -o "$tmp/dunree" .); fi
"$PY" "$here/capture.py" --bin "$tmp/dunree" --port "$PORT" --minutes "${MINUTES:-12}" "$@"
