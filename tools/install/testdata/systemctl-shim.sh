#!/usr/bin/env bash
# Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.
#
# A stand-in for systemctl, for tools/install/test_swap.sh and for rehearsals of
# swap-to-dunree.sh without root. It really starts and stops what ExecStart names, as the
# calling user, so "active" means a live process. It knows only what the swap script uses:
#   start, stop, enable, disable, is-active, is-enabled, daemon-reload, show -p MainPID --value
# and of a unit file only ExecStart, WorkingDirectory and Conflicts.
#
#   SHIM_UNITS   folder with the unit files (the --systemd-dir of the swap script)
#   SHIM_STATE   folder for its own records: <unit>.pid, <unit>.enabled, <unit>.log, calls.log
set -u
: "${SHIM_UNITS:?SHIM_UNITS is not set}" "${SHIM_STATE:?SHIM_STATE is not set}"
mkdir -p "$SHIM_STATE"
printf '%s\n' "$*" >>"$SHIM_STATE/calls.log"

alive() { [ -f "$SHIM_STATE/$1.pid" ] && kill -0 "$(cat "$SHIM_STATE/$1.pid")" 2>/dev/null; }
unit_key() { sed -n "s/^$2=[[:space:]]*//p" "$SHIM_UNITS/$1" | head -n 1 | sed 's/[[:space:]]*$//'; }

stop_unit() {
  local u="$1" pid n=0
  if alive "$u"; then
    pid="$(cat "$SHIM_STATE/$u.pid")"
    kill -TERM "$pid" 2>/dev/null
    while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 400 ]; do sleep 0.1; n=$((n + 1)); done
    kill -KILL -- "-$pid" 2>/dev/null     # whatever is left of its process group, as KillMode=control-group
    kill -KILL "$pid" 2>/dev/null
  fi
  rm -f "$SHIM_STATE/$u.pid"
  return 0
}

cmd="${1:-}"; shift || true
case "$cmd" in
  daemon-reload) exit 0 ;;
  enable|disable)
    for u in "$@"; do
      case "$u" in -*) continue ;; esac
      [ -f "$SHIM_UNITS/$u" ] || { echo "Failed: unit $u not found" >&2; exit 1; }
      if [ "$cmd" = enable ]; then : >"$SHIM_STATE/$u.enabled"; else rm -f "$SHIM_STATE/$u.enabled"; fi
    done ;;
  is-enabled)
    if [ -f "$SHIM_STATE/$1.enabled" ] && [ -f "$SHIM_UNITS/$1" ]; then echo enabled; exit 0; fi
    echo disabled; exit 1 ;;
  is-active)
    if alive "$1"; then echo active; exit 0; fi
    if [ -f "$SHIM_STATE/$1.pid" ]; then echo failed; else echo inactive; fi
    exit 3 ;;
  show)
    u=""; for a in "$@"; do case "$a" in -*|MainPID) ;; *) u="$a" ;; esac; done
    if alive "$u"; then cat "$SHIM_STATE/$u.pid"; else echo 0; fi ;;
  stop) for u in "$@"; do stop_unit "$u"; done ;;
  start)
    u="$1"
    [ -f "$SHIM_UNITS/$u" ] || { echo "Failed to start $u: Unit $u not found." >&2; exit 5; }
    alive "$u" && exit 0
    for c in $(unit_key "$u" Conflicts); do stop_unit "$c"; done
    wd="$(unit_key "$u" WorkingDirectory)"; ex="$(unit_key "$u" ExecStart)"
    [ -n "$ex" ] || { echo "Failed to start $u: no ExecStart" >&2; exit 1; }
    # shellcheck disable=SC2086
    # systemd starts a service with default signal handling, whatever the caller ignores (the swap
    # script ignores INT, TERM, HUP and PIPE while it rolls back): do the same where env can
    dflt=""; env --default-signal true >/dev/null 2>&1 && dflt="env --default-signal"
    ( cd "${wd:-/}" && exec $dflt setsid $ex >>"$SHIM_STATE/$u.log" 2>&1 </dev/null ) &
    echo "$!" >"$SHIM_STATE/$u.pid"
    sleep 0.3 ;;
  *) echo "systemctl-shim: unknown command $cmd" >&2; exit 1 ;;
esac
exit 0
