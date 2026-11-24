#!/usr/bin/env bash
# Dual-proxy integration harness (external + internal Dunree + backend app, private CA, optional mutual TLS).
# Builds Dunree from this checkout, then runs dual_proxy.py (smoke) or, with the first argument "enterprise", enterprise.py
# (the Phase 5 checks: spoofing, rate-limit identity, TLS trust, mTLS, route limits, CrowdSec, failure/recovery, drain, admin
# exposure, config management, history rollback). Everything heavy runs through ~/capped.sh under the shared heavy lock;
# instances live in temp dirs under $HOME on high ports and are removed on exit.
# usage: tools/e2e/dual_proxy/run.sh [--mode tls|mtls|both] [--keep]
#        tools/e2e/dual_proxy/run.sh enterprise [--only 1,3,7] [--keep]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../../.."
script=dual_proxy.py
if [ "${1:-}" = "enterprise" ]; then script=enterprise.py; shift; fi
export GOTMPDIR="${GOTMPDIR:-$HOME/.cache/go-tmp}"
export TMPDIR="${DUAL_TMP:-$HOME/.cache/zx-dual-tmp}"
mkdir -p "$GOTMPDIR" "$TMPDIR"
export DUNREE_BIN="$TMPDIR/dunree-dual"
export E2E_NOBUILD=1
CAP="${CAPPED:-$HOME/capped.sh}"
LOCK="${HEAVY_LOCK:-$HOME/.cache/heavy.lock}"
if [ -z "${DUAL_NOBUILD:-}" ]; then
  (cd "$root/src" && flock "$LOCK" "$CAP" go build -o "$DUNREE_BIN" .)
fi
exec flock "$LOCK" "$CAP" "${PY:-python3}" "$here/$script" "$@"
