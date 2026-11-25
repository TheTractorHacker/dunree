#!/usr/bin/env bash
# Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.
#
# Swap a running proxy that is started by systemd through a start.sh in its home folder
# to the Dunree program file, check that it works, and go back by itself when it does not.
# Documentation: docs/deploy/swapping-from-zoraxy.md                                    # rebrand:keep
#
# The layout it expects (the folder is --dir, default /home/sysadmin):
#   <dir>/zoraxy            the program file that runs today (never changed or removed)  # rebrand:keep
#   <dir>/start.sh          one line that starts it with its flags
#   <dir>/conf, sys.db, sys.uuid, plugins/, backups/
#   /etc/systemd/system/zoraxy.service  with ExecStart=<dir>/start.sh                    # rebrand:keep
# For an install below /opt with the program started by the unit itself use
# tools/install/migrate-from-zoraxy.sh instead.                                         # rebrand:keep
#
# What it does, in this order:
#   1. checks, nothing changed yet: root, the new program file (checksum, release signature),
#      free disk space, the old service (active, admin port listening, admin page answers),
#      what runs today (listening ports, plugin processes, number of rules, one proxied host)
#   2. backup into <dir>/backups/pre-dunree-<time>/: old program file, unit and start.sh
#      (program.tgz, before the stop) and conf, sys.db, sys.uuid, plugins (data.tgz, after the
#      stop, so the database is copied closed), with a README that says how to restore
#   3. stops the old service
#   4. installs the new program file as <dir>/dunree (mode 755, root)
#   5. rewrites start.sh to start <dir>/dunree with the same flags (copy: start.sh.pre-dunree)
#   6. writes dunree.service from the old unit (same User, WorkingDirectory, ExecStart;
#      Description and SyslogIdentifier say Dunree) and disables the old unit, whose file stays
#   7. daemon-reload, enable, start
#   8. checks for up to 60 s: unit active, admin port listening, admin page answers,
#      conf/dunree_install.json written, the same plugin processes run again, the same ports
#      listen again, the number of rules is the same, the proxied host answers again
#   9. any failed check, a time-out or an interruption: stops Dunree, puts start.sh and the old
#      unit back, starts the old service, checks that it is healthy again, exits 1. The data
#      (conf, sys.db, plugins) stays as it is, with two exceptions where it is put back from
#      data.tgz: the number of rules changed, or the old service does not come up on it
#
# Usage: sudo swap-to-dunree.sh --role dev|live [options]
#   --role dev|live      required. live: the old service must be healthy, at least 1 GB must be
#                        free, and the host name has to be typed to confirm
#   --dir DIR            home folder of the install          (default /home/sysadmin)
#   --binary FILE        the new Dunree program file         (default dunree_linux_<arch> next to
#                        this script, else <dir>/dunree-staging/dunree_linux_<arch>)
#   --sha256 HEX         SHA-256 the new program file must have
#   --sums FILE          SHA256SUMS of the release           (default: next to --binary, if there)
#   --pubkey FILE        ed25519 public key (PEM) that must have signed SHA256SUMS(.sig)
#                        (default: the Dunree release key, the one the updater has built in)
#   --timeout SECONDS    how long the checks after the start may take   (default 60)
#   --dry-run            run the checks of step 1, show what would be written, change nothing
#   --no-start           do steps 2 to 6 and enable, but do not start Dunree and skip step 8
#   --rollback           go back to the old program by hand (same steps as 9)
#   --restore-data       with --rollback: also put conf, sys.db, sys.uuid and plugins back from
#                        the backup taken at the swap (everything changed since then is lost)
#   --old-unit NAME      unit name today                     (default zoraxy.service)   # rebrand:keep
#   --new-unit NAME      unit name afterwards                (default dunree.service)
#   --systemd-dir DIR    where the unit file is              (default /etc/systemd/system)
#   -h, --help           this text
#
# Every line of a step starts with OK, WARN or FAIL. No network access is needed or used
# (the checks talk to 127.0.0.1 only).
#
# Exit status: 0 swapped (or already swapped, or rolled back by hand), 1 a check failed and the
# old service runs again, 2 refused before anything was changed, 3 the roll back itself did not
# end with a healthy old service (act by hand, the backup README says how).
#
# Tests: tools/install/test_swap.sh (temporary folder, stand-in systemctl, ss and curl).
set -Eeuo pipefail

OLD_NAME="zoraxy"   # rebrand:keep
NEW_NAME="dunree"
DIR="/home/sysadmin"
OLD_UNIT="${OLD_NAME}.service"
NEW_UNIT="${NEW_NAME}.service"
SYSTEMD_DIR="/etc/systemd/system"
ROLE=""
BINARY=""
WANT_SHA=""
SUMS=""
PUBKEY=""
TIMEOUT=60
DRY_RUN=0
NO_START=0
DO_ROLLBACK=0
RESTORE_DATA=0

# The Dunree release key (src/mod/updater/release_pubkey.pem; test_swap.sh compares the two).
RELEASE_PUBKEY_B64="MCowBQYDK2VwAyEAG/Zl2l7h73RtSFNlNknDEtNvtGQlLYSRGkn6P2IOPy4="

WARNINGS=0
# Every line goes to the terminal and, once the backup folder exists, to <backup>/swap.log (the lines
# before that are kept in EARLY_LOG and written first). A terminal that is gone (ssh dropped) never
# stops the script: a failed write to it is ignored, and SIGPIPE is ignored from the first change on.
LOG=""; EARLY_LOG=""
out() {
  if [ -n "$LOG" ]; then printf '%s\n' "$*" >>"$LOG" 2>/dev/null || true; else EARLY_LOG+="$*"$'\n'; fi
  printf '%s\n' "$*" 2>/dev/null || true
}
# Only the main shell reports: with set -E the trap also runs inside $(...), where its line would
# become part of the captured value (a du that cannot read a folder gave "FAIL ..." in a number).
MAIN_PID=$$
trap 'st_=$?; [ "$BASHPID" != "$MAIN_PID" ] || fail "unexpected error in line $LINENO of $0 (status $st_)"' ERR
say()  { out "$*"; }
head_() { out ""; out "== $*"; }
ok()   { out "OK    $*"; }
warn() { out "WARN  $*"; WARNINGS=$((WARNINGS + 1)); }
fail() { out "FAIL  $*"; }
refuse() { fail "$*"; say ""; say "Refused. Nothing was changed."; exit 2; }
usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); sub(/[[:space:]]*# rebrand:keep$/, ""); print; next } NR > 2 { exit }' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="${2:?--role needs dev or live}"; shift ;;
    --dir) DIR="${2:?--dir needs a value}"; shift ;;
    --binary) BINARY="${2:?--binary needs a value}"; shift ;;
    --sha256) WANT_SHA="${2:?--sha256 needs a value}"; shift ;;
    --sums) SUMS="${2:?--sums needs a value}"; shift ;;
    --pubkey) PUBKEY="${2:?--pubkey needs a value}"; shift ;;
    --timeout) TIMEOUT="${2:?--timeout needs a value}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    --no-start) NO_START=1 ;;
    --rollback) DO_ROLLBACK=1 ;;
    --restore-data) RESTORE_DATA=1 ;;
    --old-unit) OLD_UNIT="${2:?--old-unit needs a value}"; shift ;;
    --new-unit) NEW_UNIT="${2:?--new-unit needs a value}"; shift ;;
    --systemd-dir) SYSTEMD_DIR="${2:?--systemd-dir needs a value}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) refuse "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# The paths go into sed expressions, a unit file and start.sh: plain paths and names only.
plain_path='^/[A-Za-z0-9._/-]+$'
plain_unit='^[A-Za-z0-9._@-]+\.service$'
[[ "$DIR" =~ $plain_path ]] || refuse "--dir must be an absolute path of letters, digits, . _ - and /"
[[ "$SYSTEMD_DIR" =~ $plain_path ]] || refuse "--systemd-dir must be an absolute path of letters, digits, . _ - and /"
[[ "$OLD_UNIT" =~ $plain_unit ]] || refuse "--old-unit must be a unit name ending in .service"
[[ "$NEW_UNIT" =~ $plain_unit ]] || refuse "--new-unit must be a unit name ending in .service"
[ "$OLD_UNIT" != "$NEW_UNIT" ] || refuse "old and new unit name are the same"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] && [ "$TIMEOUT" -ge 1 ] || refuse "--timeout must be a number of seconds"
DIR="${DIR%/}"; SYSTEMD_DIR="${SYSTEMD_DIR%/}"
[ -d "$DIR" ] || refuse "$DIR is not a folder (see --dir)"
DIR="$(cd "$DIR" && pwd -P)"
[[ "$DIR" =~ $plain_path ]] || refuse "the real path of --dir has characters this script does not accept: $DIR"
if [ "$DO_ROLLBACK" -eq 0 ]; then
  case "$ROLE" in dev|live) ;; "") refuse "say which machine this is: --role dev or --role live" ;; *) refuse "--role must be dev or live" ;; esac
  [ "$RESTORE_DATA" -eq 0 ] || refuse "--restore-data only goes with --rollback"
fi
if [ -n "$WANT_SHA" ]; then
  WANT_SHA="$(printf '%s' "$WANT_SHA" | tr 'A-F' 'a-f')"
  [[ "$WANT_SHA" =~ ^[0-9a-f]{64}$ ]] || refuse "--sha256 must be 64 hex digits"
fi

# Test mode (tools/install/test_swap.sh and rehearsals): runs without root on a folder of its own and
# takes stand-ins for systemctl, ss, curl and the process list. Never set it on a real proxy.
TEST_MODE=0
SC="systemctl"; SS="ss"; CURL="curl"; PLUGIN_PS=""; SETTLE=5
if [ "${SWAP_TEST_MODE:-0}" = "1" ]; then
  TEST_MODE=1
  SC="${SYSTEMCTL:-systemctl}"; SS="${SWAP_SS:-ss}"; CURL="${SWAP_CURL:-curl}"
  PLUGIN_PS="${SWAP_PLUGIN_PS:-}"; SETTLE="${SWAP_SETTLE:-5}"
fi

OLD_BIN="$DIR/$OLD_NAME"
NEW_BIN="$DIR/$NEW_NAME"
START_SH="$DIR/start.sh"
START_KEEP="$DIR/start.sh.pre-dunree"
OLD_UNIT_FILE="$SYSTEMD_DIR/$OLD_UNIT"
NEW_UNIT_FILE="$SYSTEMD_DIR/$NEW_UNIT"
BACKUPS="$DIR/backups"
LATEST="$BACKUPS/pre-dunree-latest"
MARKER="$DIR/conf/dunree_install.json"
TS="$(date -u +%Y%m%d-%H%M%S)"
BK="$BACKUPS/pre-dunree-$TS"
dir_re="$(printf '%s' "$DIR" | sed 's/[.]/\\./g')"

# ---------------------------------------------------------------- small helpers
# file descriptor 9 is the lock of this script: a service must never inherit it
sc_() { "$SC" "$@" 9>&-; }
sc_is() { sc_ "$@" >/dev/null 2>&1; }
unit_state() { sc_ is-active "$1" 2>/dev/null | head -n 1 || true; }
main_pid() { sc_ show -p MainPID --value "$1" 2>/dev/null | head -n 1 || true; }
# (both always print a number and succeed: du fails for a folder it cannot fully read)
free_kb() { { df -Pk "$1" 2>/dev/null || true; } | awk 'NR == 2 { v = $4 } END { print v + 0 }'; }
size_kb() { if [ -e "$1" ]; then { du -sk "$1" 2>/dev/null || true; } | awk 'NR == 1 { v = $1 } END { print v + 0 }'; else echo 0; fi; }
sha_of() { sha256sum "$1" | awk '{ print $1 }'; }
human_kb() { awk -v k="$1" 'BEGIN { if (k >= 1048576) printf "%.1f GB", k / 1048576; else printf "%d MB", k / 1024 }'; }

# all TCP ports in LISTEN state
listening_ports() { { "$SS" -H -ltn 2>/dev/null || true; } | awk '{ n = split($4, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }' | sort -un; }
port_listening() { listening_ports | grep -qx "$1"; }
# TCP ports a process listens on (needs root to see the process of another user)
ports_of_pid() {
  [ -n "$1" ] && [ "$1" != "0" ] || return 0
  { "$SS" -H -ltnp 2>/dev/null || true; } | { grep -E "pid=$1[,)]" || true; } | awk '{ n = split($4, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }' | sort -un
}
# the answer code of a URL, 000 when nothing answered. Extra arguments go to curl.
http_code() {
  local url="$1" code; shift
  code="$("$CURL" -k -s -o /dev/null -m 6 -w '%{http_code}' "$@" "$url" 2>/dev/null || true)"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code="000"
  printf '%s' "$code"
}
# plugin programs that run from <dir>/plugins, one path below plugins/ per line
running_plugins() {
  if [ -n "$PLUGIN_PS" ]; then { "$PLUGIN_PS" || true; } | sort -u; return 0; fi
  local p exe
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null || true)"
    case "$exe" in "$DIR/plugins/"*) printf '%s\n' "${exe#"$DIR"/plugins/}" ;; esac
  done | sed 's/ (deleted)$//' | sort -u
}
# processes that still run a program file of this install (the given file, or anything in plugins/)
leftover_pids() {
  [ -z "$PLUGIN_PS" ] || return 0
  local p exe
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null || true)"
    exe="${exe% (deleted)}"
    case "$exe" in "$1"|"$DIR/plugins/"*) printf '%s\n' "${p#/proc/}" ;; esac
  done
}
rule_count() { find "$DIR/conf/proxy" -maxdepth 1 -type f -name '*.config' 2>/dev/null | wc -l | tr -d ' '; }

# ---------------------------------------------------------------- start.sh
# The line(s) of start.sh that run the old program file, by its full path.
old_bin_pat="(^|[^A-Za-z0-9._/-])${dir_re}/${OLD_NAME}([[:space:]\"']|\$)"
new_bin_pat="(^|[^A-Za-z0-9._/-])${dir_re}/${NEW_NAME}([[:space:]\"']|\$)"
start_runs_old() { [ -f "$START_SH" ] && grep -v '^[[:space:]]*#' "$START_SH" | grep -Eq "$old_bin_pat"; }
start_runs_new() { [ -f "$START_SH" ] && grep -v '^[[:space:]]*#' "$START_SH" | grep -Eq "$new_bin_pat"; }
rewrite_start() { sed -E "/^[[:space:]]*#/! s#${old_bin_pat}#\\1${DIR}/${NEW_NAME}\\2#g" "$1"; }
# the flags of the program line, from a start.sh given as $1
# (what follows the FIRST mention of the program file: a later "<dir>/zoraxy.log" on the same line   # rebrand:keep
# must not be taken for it)
prog_pat="(^|[^A-Za-z0-9._/-])${dir_re}/(${OLD_NAME}|${NEW_NAME})([[:space:]\"']|\$)"
start_flags() {
  local line m rest
  line="$({ grep -v '^[[:space:]]*#' "$1" || true; } | { grep -E "$old_bin_pat|$new_bin_pat" || true; } | head -n 1)"
  [[ "$line" =~ $prog_pat ]] || return 0
  m="${BASH_REMATCH[0]}"; rest="${line#*"$m"}"
  case "${BASH_REMATCH[3]}" in [[:space:]]) rest="${BASH_REMATCH[3]}$rest" ;; esac
  printf '%s\n' "$rest"
}
# value of -port in those flags (default :8000), as host and port
ADMIN_HOST="127.0.0.1"; ADMIN_PORT="8000"
read_admin_port() {
  local v
  v="$(start_flags "$1" | grep -oE -- '(^|[[:space:]])--?port[= ]+[^[:space:]]+' | head -n 1 | sed -E 's/^[[:space:]]*--?port[= ]+//; s/^["'"'"']//; s/["'"'"']$//' || true)"
  [ -n "$v" ] || return 0
  ADMIN_PORT="${v##*:}"
  local h="${v%:*}"
  if [ "$h" != "$v" ] && [ -n "$h" ] && [ "$h" != "0.0.0.0" ] && [ "$h" != "[::]" ]; then ADMIN_HOST="$h"; fi
  [[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] || refuse "cannot read the admin port from the -port flag in $1 ($v)"
}
# ports named by other flags that end in "port" (-fleet_port :8010, -metrics_port, -health_port).
# -default_inbound_port is left out: it only counts on an install without a database.
flag_ports() {
  start_flags "$1" | grep -oE -- '--?[a-z_]*port[= ]+[^-[:space:]][^[:space:]]*' | grep -v -- 'default_inbound_port' \
    | sed -E 's/^[[:space:]]*--?[a-z_]*port[= ]+//; s/["'"'"']//g' | grep -oE '[0-9]+$' | sort -un || true
}

ADMIN_URL=""
probe_admin() {
  local scheme code
  for scheme in https http; do
    code="$(http_code "$scheme://$ADMIN_HOST:$ADMIN_PORT/")"
    if [ "$code" != "000" ]; then ADMIN_URL="$scheme://$ADMIN_HOST:$ADMIN_PORT/"; ADMIN_CODE="$code"; return 0; fi
  done
  return 1
}

# ---------------------------------------------------------------- unit file
build_unit() {
  say "# $NEW_UNIT: written by swap-to-dunree.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ) from $OLD_UNIT."
  say "# $OLD_UNIT is still in $SYSTEMD_DIR, disabled. To go back: swap-to-dunree.sh --rollback"
  awk -v conflicts="$OLD_UNIT" '
    /^Description=/ { print "Description=Dunree reverse proxy and web gateway"; next }
    /^SyslogIdentifier=/ { print "SyslogIdentifier=dunree"; next }
    /^Alias=/ { print "# " $0 " (left out: an alias of the old unit cannot also name the new one)"; next }
    { print }
    /^\[Unit\][[:space:]]*$/ && !done {
      print "# Never run next to the old unit: both use the same folder, ports and database."
      print "Conflicts=" conflicts
      done = 1
    }' "$OLD_UNIT_FILE"
}

# ---------------------------------------------------------------- health of a service
# wait_healthy UNIT SECONDS: active, admin port listening, admin page answers. Sets HEALTH_MSG.
HEALTH_MSG=""
wait_healthy() {
  local unit="$1" until=$(( $(date +%s) + $2 )) st
  while :; do
    st="$(unit_state "$unit")"
    if [ "$st" = "active" ] && port_listening "$ADMIN_PORT" && probe_admin; then
      HEALTH_MSG="$unit is active, port $ADMIN_PORT listens, $ADMIN_URL answers $ADMIN_CODE"; return 0
    fi
    if [ "$st" = "failed" ] || [ "$(date +%s)" -ge "$until" ]; then
      HEALTH_MSG="$unit is ${st:-unknown}"
      port_listening "$ADMIN_PORT" || HEALTH_MSG="$HEALTH_MSG, port $ADMIN_PORT does not listen"
      return 1
    fi
    sleep 1
  done
}

# ---------------------------------------------------------------- going back
# go_back MODE: MODE is auto (after a failed swap of this run) or manual (--rollback).
# Returns 0 when the old service is healthy again (or was not running before and is back in place).
state_get() { [ -f "$1/state" ] && sed -n "s/^$2=//p" "$1/state" | head -n 1; }
go_back() {
  local mode="$1" bk="${2:-}" was_enabled=1 was_active=1 n pids
  set +e
  if [ -n "$bk" ] && [ -f "$bk/state" ]; then
    was_enabled="$(state_get "$bk" was_enabled)"; was_active="$(state_get "$bk" was_active)"
    [ -n "$was_enabled" ] || was_enabled=1
    [ -n "$was_active" ] || was_active=1
  else
    warn "no record of this swap in $BACKUPS: assuming $OLD_UNIT was enabled and running"
  fi
  # The old service may run already (a roll back after a roll back, with --restore-data, or a stop
  # that failed): it is stopped first, so that the processes below are never its plugins and its
  # data is never moved away under it. It is started again at the end.
  if [ "$(unit_state "$OLD_UNIT")" = "active" ]; then
    if sc_ stop "$OLD_UNIT" >/dev/null 2>&1; then ok "stopped $OLD_UNIT (it runs now; it is started again below)"
    else warn "systemctl stop $OLD_UNIT reported an error"; fi
    was_active=1
  fi

  if [ -f "$NEW_UNIT_FILE" ]; then
    if sc_ stop "$NEW_UNIT" >/dev/null 2>&1; then ok "stopped $NEW_UNIT"; else warn "systemctl stop $NEW_UNIT reported an error"; fi
    sc_ disable "$NEW_UNIT" >/dev/null 2>&1
  fi
  # nothing of the new program may be left behind: it would hold the ports and the database
  n=0
  while pids="$(leftover_pids "$NEW_BIN")"; [ -n "$pids" ] && [ "$n" -lt 10 ]; do sleep 1; n=$((n + 1)); done
  if [ -n "$pids" ]; then
    warn "processes of $NEW_BIN or its plugins still run after the stop: ending them ($(echo $pids))"
    # shellcheck disable=SC2086
    kill -TERM $pids 2>/dev/null; sleep 3
    pids="$(leftover_pids "$NEW_BIN")"
    # shellcheck disable=SC2086
    [ -z "$pids" ] || kill -KILL $pids 2>/dev/null
  fi

  if [ -f "$START_KEEP" ]; then
    if mv -f "$START_KEEP" "$START_SH"; then ok "start.sh is the one from before the swap again"; else fail "could not put $START_KEEP back as $START_SH"; fi
  elif start_runs_old; then
    ok "start.sh already starts $OLD_BIN"
  else
    fail "start.sh does not start $OLD_BIN and there is no $START_KEEP: correct start.sh by hand"
  fi

  if [ -f "$NEW_UNIT_FILE" ]; then
    local keep="${bk:-$BACKUPS}/rolled-back-$TS"
    mkdir -p "$keep" && mv -f "$NEW_UNIT_FILE" "$keep/" && ok "moved $NEW_UNIT to $keep/"
    [ ! -d "$NEW_UNIT_FILE.d" ] || mv -f "$NEW_UNIT_FILE.d" "$keep/"
  fi
  sc_ daemon-reload >/dev/null 2>&1

  if [ ! -f "$OLD_UNIT_FILE" ]; then fail "$OLD_UNIT_FILE is missing: cannot start the old service"; set -e; return 1; fi
  if [ ! -x "$OLD_BIN" ]; then fail "$OLD_BIN is missing: cannot start the old service"; set -e; return 1; fi
  if [ "$was_enabled" = "1" ]; then
    if sc_ enable "$OLD_UNIT" >/dev/null 2>&1; then ok "enabled $OLD_UNIT"; else warn "could not enable $OLD_UNIT"; fi
  fi

  # the data goes back too: when asked for (--restore-data), and by itself when the check of the
  # rules failed (Dunree ran for a minute at most; the copy is from the moment of the stop)
  if [ "$RESTORE_DATA" -eq 1 ]; then
    [ "$mode" = "manual" ] || warn "the number of rules changed while Dunree ran: putting conf, sys.db, sys.uuid and plugins back as they were at the stop"
    restore_data "$bk" || { set -e; return 1; }
  fi

  if [ "$was_active" != "1" ]; then
    ok "$OLD_UNIT was not running before the swap: not started"
    set -e; return 0
  fi
  read_admin_port "$START_SH"
  sc_ start "$OLD_UNIT" >/dev/null 2>&1 || warn "systemctl start $OLD_UNIT reported an error"
  if wait_healthy "$OLD_UNIT" "$TIMEOUT"; then
    ok "old service healthy again: $HEALTH_MSG"
    set -e; return 0
  fi
  fail "old service not healthy after going back: $HEALTH_MSG"
  if [ "$mode" = "auto" ] && [ "$RESTORE_DATA" -eq 0 ] && [ -n "$bk" ] && [ -f "$bk/data.tgz" ] && [ -f "$bk/data.complete" ]; then
    warn "putting conf, sys.db, sys.uuid and plugins back as they were at the stop, then starting $OLD_UNIT again"
    sc_ stop "$OLD_UNIT" >/dev/null 2>&1
    if restore_data "$bk"; then
      sc_ start "$OLD_UNIT" >/dev/null 2>&1
      if wait_healthy "$OLD_UNIT" "$TIMEOUT"; then
        ok "old service healthy again with the data from the backup: $HEALTH_MSG"
        set -e; return 0
      fi
      fail "old service still not healthy: $HEALTH_MSG"
    fi
  fi
  set -e; return 1
}

# restore_data BACKUP: what is there now is moved into BACKUP/after-dunree-<time>/, never deleted.
restore_data() {
  local bk="$1" aside f
  if [ -z "$bk" ] || [ ! -f "$bk/data.tgz" ] || [ ! -f "$bk/data.complete" ]; then
    fail "no complete data.tgz in ${bk:-the backup folder}: data not restored"; return 1
  fi
  aside="$bk/after-dunree-$TS"
  mkdir -p "$aside" || { fail "cannot create $aside"; return 1; }
  for f in conf sys.db sys.uuid plugins; do
    if [ -e "$DIR/$f" ]; then mv "$DIR/$f" "$aside/" || { fail "cannot move $DIR/$f aside"; return 1; }; fi
  done
  if tar -C "$DIR" -xpzf "$bk/data.tgz"; then
    ok "data restored from $bk/data.tgz (what Dunree left is in $aside)"
  else
    fail "tar could not unpack $bk/data.tgz; what was there is in $aside"; return 1
  fi
}

latest_backup() { if [ -f "$LATEST" ]; then local d; d="$(head -n 1 "$LATEST")"; [ -d "$BACKUPS/$d" ] && printf '%s' "$BACKUPS/$d"; fi; return 0; }

# ---------------------------------------------------------------- start
say "swap-to-dunree.sh on $(hostname 2>/dev/null || echo unknown), $(date -u +%Y-%m-%dT%H:%M:%SZ), folder $DIR"
[ "$TEST_MODE" -eq 0 ] || warn "test mode (SWAP_TEST_MODE=1): no root needed, stand-in commands allowed. Never use this on a real proxy."

for c in systemctl:sc_ ss:"$SS" curl:"$CURL" tar:tar sha256sum:sha256sum awk:awk sed:sed df:df du:du install:install find:find; do
  command -v "${c#*:}" >/dev/null 2>&1 || refuse "the program ${c%%:*} is needed and was not found"
done
if [ "$TEST_MODE" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  refuse "run this as root (sudo). Use --dry-run to look first."
fi

HAVE_NEW_UNIT=0; [ -f "$NEW_UNIT_FILE" ] && HAVE_NEW_UNIT=1
RUNS_NEW=0; start_runs_new && RUNS_NEW=1
RUNS_OLD=0; start_runs_old && RUNS_OLD=1

# ---------------------------------------------------------------- --rollback
if [ "$DO_ROLLBACK" -eq 1 ]; then
  head_ "Going back to $OLD_UNIT"
  if [ "$HAVE_NEW_UNIT" -eq 0 ] && [ "$RUNS_NEW" -eq 0 ] && [ ! -f "$START_KEEP" ] && [ "$RESTORE_DATA" -eq 0 ]; then
    ok "nothing to roll back: there is no $NEW_UNIT and start.sh starts $OLD_BIN"
    exit 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would: stop and disable $NEW_UNIT, put $START_KEEP back as start.sh, move $NEW_UNIT_FILE into the backup folder,"
    say "       enable and start $OLD_UNIT and check it. --dry-run: nothing was changed."
    exit 0
  fi
  mkdir -p "$BACKUPS"
  exec 9>"$BACKUPS/.swap-to-dunree.lock"
  if command -v flock >/dev/null 2>&1; then flock -n 9 || refuse "another swap-to-dunree.sh is running on $DIR"; fi
  LBK="$(latest_backup)"
  # a terminal that goes away must not stop a roll back half way (Ctrl+C still does)
  trap '' HUP PIPE
  if [ -n "$LBK" ]; then LOG="$LBK/rollback-$TS.log"; printf '%s' "$EARLY_LOG" >>"$LOG" 2>/dev/null || true; fi
  if [ "$RESTORE_DATA" -eq 1 ]; then
    [ -n "$LBK" ] && [ -f "$LBK/data.complete" ] || refuse "--restore-data: no complete backup of a swap found in $BACKUPS"
    warn "--restore-data: conf, sys.db, sys.uuid and plugins go back to $LBK/data.tgz; everything changed since then is lost"
  fi
  if go_back manual "$LBK"; then
    [ ! -f "$NEW_BIN" ] || ok "$NEW_BIN was left in place (not used by anything now)"
    say ""; say "RESULT: rolled back. $OLD_UNIT runs the old program. Administrators have to log in again."
    exit 0
  fi
  say ""; say "RESULT: FAILED to get a healthy $OLD_UNIT. Look at: systemctl status $OLD_UNIT ; journalctl -u $OLD_UNIT -n 50"
  [ -z "$LBK" ] || say "        The backup and its README are in $LBK"
  exit 3
fi

# ---------------------------------------------------------------- already swapped?
if [ "$HAVE_NEW_UNIT" -eq 1 ] && [ "$RUNS_NEW" -eq 1 ]; then
  head_ "Already swapped"
  read_admin_port "$START_SH"
  ok "already swapped: $NEW_UNIT_FILE exists and start.sh starts $NEW_BIN. Nothing was changed."
  st="$(unit_state "$NEW_UNIT")"
  if [ "$st" = "active" ]; then
    ok "$NEW_UNIT is active"
    if port_listening "$ADMIN_PORT" && probe_admin; then ok "admin page answers: $ADMIN_URL ($ADMIN_CODE)"; else warn "the admin page on port $ADMIN_PORT does not answer"; fi
    exit 0
  fi
  warn "$NEW_UNIT is ${st:-unknown}, not active. Start it (systemctl start $NEW_UNIT) or go back (--rollback)."
  exit 1
fi
if [ "$HAVE_NEW_UNIT" -eq 1 ] || [ "$RUNS_NEW" -eq 1 ] || [ -f "$START_KEEP" ]; then
  fail "half swapped: $NEW_UNIT_FILE $([ "$HAVE_NEW_UNIT" -eq 1 ] && echo exists || echo "does not exist"), start.sh starts $([ "$RUNS_NEW" -eq 1 ] && echo "$NEW_BIN" || echo "something else"), $START_KEEP $([ -f "$START_KEEP" ] && echo exists || echo "does not exist")"
  refuse "run this script with --rollback first; it puts everything back, then swap again"
fi

# ---------------------------------------------------------------- 1. checks
head_ "1. Checks before anything is changed (role: $ROLE)"
PRE_FAIL=0
pre_fail() { fail "$*"; PRE_FAIL=1; }
# a finding about the old service: refuses on live, a warning on dev
health_issue() { if [ "$ROLE" = "live" ]; then pre_fail "$*"; else warn "$* (role dev: continuing)"; fi; }

if [ "$TEST_MODE" -eq 1 ]; then :; elif [ "$(id -u)" -eq 0 ]; then ok "running as root"; else warn "not root: this is a dry run, some checks cannot see the service's processes"; fi

# --- layout
[ -f "$OLD_UNIT_FILE" ] || refuse "no $OLD_UNIT in $SYSTEMD_DIR: this is not the layout this script is for (see --old-unit, --systemd-dir)"
grep -q '^\[Unit\]' "$OLD_UNIT_FILE" || refuse "$OLD_UNIT_FILE has no [Unit] section"
grep -Eq "^ExecStart=[^[:space:]]*${dir_re}/start\.sh([[:space:]]|\$)" "$OLD_UNIT_FILE" \
  || refuse "$OLD_UNIT does not have ExecStart=$START_SH: this script only handles a service started through start.sh"
[ -f "$START_SH" ] || refuse "$START_SH does not exist"
[ "$RUNS_OLD" -eq 1 ] || refuse "$START_SH has no line that runs $OLD_BIN by its full path"
[ -x "$OLD_BIN" ] || refuse "$OLD_BIN does not exist or is not executable"
if start_flags "$START_SH" | grep -Eq -- '(^|[[:space:]])--?(conf|dbpath|uuid|plugin)[= ]'; then
  refuse "start.sh moves conf, the database, sys.uuid or plugins with a flag: this script only handles the default places below $DIR"
fi
[ -d "$DIR/conf" ] || refuse "$DIR/conf does not exist"
ok "layout: $OLD_UNIT -> $START_SH -> $OLD_BIN$(start_flags "$START_SH")"
read_admin_port "$START_SH"
if [ "$TEST_MODE" -eq 0 ] && [ "$(stat -c %u "$START_SH")" != "0" ]; then
  warn "$START_SH belongs to $(stat -c %U "$START_SH") and is run as root by the unit: that user can run anything as root. Not changed by this script."
fi

# --- the new program file
if [ -z "$BINARY" ]; then
  case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; armv7l) arch=arm ;; riscv64) arch=riscv64 ;; *) arch="$(uname -m)" ;; esac
  here="$(cd "$(dirname "$0")" && pwd -P)"
  for cand in "$here/dunree_linux_$arch" "$DIR/dunree-staging/dunree_linux_$arch"; do
    if [ -f "$cand" ]; then BINARY="$cand"; break; fi
  done
  [ -n "$BINARY" ] || refuse "no dunree_linux_$arch next to this script or in $DIR/dunree-staging: give the file with --binary"
fi
[ -f "$BINARY" ] || refuse "--binary $BINARY is not a file"
BINARY="$(cd "$(dirname "$BINARY")" && pwd -P)/$(basename "$BINARY")"
[ "$BINARY" != "$NEW_BIN" ] || refuse "--binary is $NEW_BIN itself: give the file you downloaded or built, in another folder"
[ "$BINARY" != "$OLD_BIN" ] || refuse "--binary is the old program file"
if [ -d "$NEW_BIN" ] || [ -L "$NEW_BIN" ]; then refuse "$NEW_BIN is a folder or a link: move it away first"; fi
GOT_SHA="$(sha_of "$BINARY")"
VERIFIED=""
if [ -n "$WANT_SHA" ]; then
  if [ "$GOT_SHA" = "$WANT_SHA" ]; then ok "SHA-256 of $(basename "$BINARY") is the one given with --sha256"; VERIFIED="checksum given on the command line"
  else pre_fail "SHA-256 of $BINARY is $GOT_SHA, not the $WANT_SHA given with --sha256"; fi
fi
[ -n "$SUMS" ] || { [ -f "$(dirname "$BINARY")/SHA256SUMS" ] && SUMS="$(dirname "$BINARY")/SHA256SUMS"; } || true
if [ -n "$SUMS" ]; then
  if [ ! -f "$SUMS" ]; then
    pre_fail "--sums $SUMS is not a file"
  else
    first="$(head -n 1 "$SUMS" | tr -d '\r')"
    case "$first" in
      "# dunree-release "*product=dunree*) ok "SHA256SUMS is for a Dunree release: ${first#\# dunree-release }" ;;
      *) pre_fail "$SUMS does not start with the header of a Dunree release (# dunree-release product=dunree ...)" ;;
    esac
    name="$(basename "$BINARY")"
    listed="$(awk -v n="$name" 'NF == 2 { f = $2; sub(/^\*/, "", f); if (f == n) print tolower($1) }' "$SUMS" | tr -d '\r')"
    if [ -z "$listed" ]; then pre_fail "$name is not listed in $SUMS (keep the file name of the release)"
    elif [ "$(printf '%s\n' "$listed" | wc -l)" -ne 1 ]; then pre_fail "$name is listed more than once in $SUMS"
    elif [ "$listed" = "$GOT_SHA" ]; then ok "SHA-256 of $name is the one in SHA256SUMS"
    else pre_fail "SHA-256 of $name is $GOT_SHA, SHA256SUMS says $listed"; fi
    SIG="$SUMS.sig"
    if [ ! -f "$SIG" ]; then
      warn "there is no $SIG: SHA256SUMS is NOT signed, the checksum only shows that the copy is not damaged"
    elif ! command -v openssl >/dev/null 2>&1 || ! openssl version 2>/dev/null | grep -Eq '^OpenSSL ([3-9]|[1-9][0-9])\.'; then
      warn "openssl 3 or newer is needed to check $SIG and was not found: the release signature was NOT checked"
    else
      keyfile="$PUBKEY"; keyname="the key given with --pubkey"; tmpkey=""
      if [ -z "$keyfile" ]; then
        tmpkey="$(mktemp)"; keyfile="$tmpkey"; keyname="the Dunree release key"
        printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$RELEASE_PUBKEY_B64" >"$tmpkey"
      fi
      if [ ! -f "$keyfile" ]; then pre_fail "--pubkey $keyfile is not a file"
      elif [ "$(wc -c <"$SIG")" -ne 64 ]; then pre_fail "$SIG is not a 64 byte ed25519 signature"
      elif openssl pkeyutl -verify -pubin -inkey "$keyfile" -rawin -in "$SUMS" -sigfile "$SIG" >/dev/null 2>&1; then
        ok "SHA256SUMS is signed by $keyname (ed25519)"
        [ "$PRE_FAIL" -ne 0 ] || VERIFIED="release signature"
      else
        pre_fail "the signature $SIG does not fit SHA256SUMS and $keyname: do not install this file"
      fi
      [ -z "$tmpkey" ] || rm -f "$tmpkey"
    fi
  fi
elif [ -n "$PUBKEY" ]; then
  pre_fail "--pubkey was given but there is no SHA256SUMS next to the program file (see --sums)"
fi
if [ -z "$VERIFIED" ] && [ "$PRE_FAIL" -eq 0 ]; then
  if [ -n "$SUMS" ]; then warn "the new program file is NOT verified by a signature (checksum only). SHA-256: $GOT_SHA"
  else warn "the new program file is NOT verified: no --sha256 and no SHA256SUMS next to it. SHA-256: $GOT_SHA"; fi
fi
# it must run here and say that it is Dunree (run in an empty folder: -version writes nothing).
# A file whose checksum or signature was just found wrong is never run, not even with -version.
if [ "$PRE_FAIL" -ne 0 ]; then
  fail "$BINARY was not run (-version): its checksum or signature is wrong"
else
  vdir="$(mktemp -d)"
  ver="$(cd "$vdir" && { [ -x "$BINARY" ] || chmod u+x "$BINARY" 2>/dev/null || true; } && timeout 15 "$BINARY" -version 2>&1 | head -n 1 || true)"
  rm -rf "$vdir"
  case "$ver" in
    Dunree*) ok "new program file runs on this machine: $ver" ;;
    *) pre_fail "$BINARY -version did not answer as Dunree (answer: ${ver:-none}). Wrong file or wrong processor type?" ;;
  esac
fi

# --- disk
need_kb=$(( $(size_kb "$OLD_BIN") + 2 * $(size_kb "$BINARY") + 2 * $(size_kb "$DIR/conf") + 2 * $(size_kb "$DIR/sys.db") + $(size_kb "$DIR/plugins") + 51200 ))
have_kb="$(free_kb "$DIR")"; [[ "$have_kb" =~ ^[0-9]+$ ]] || have_kb=0
if [ "$have_kb" -lt "$need_kb" ]; then
  pre_fail "free disk space in $DIR is $(human_kb "$have_kb"), the swap needs about $(human_kb "$need_kb") (backup, new program file, the copy Dunree takes at its first start)"
elif [ "$have_kb" -lt 1048576 ]; then
  if [ "$ROLE" = "live" ]; then pre_fail "free disk space in $DIR is $(human_kb "$have_kb"): role live needs at least 1 GB"
  else warn "free disk space in $DIR is $(human_kb "$have_kb"), under 1 GB (enough for the swap, which needs about $(human_kb "$need_kb"))"; fi
else
  ok "free disk space: $(human_kb "$have_kb") (the swap needs about $(human_kb "$need_kb"))"
fi

# --- the old service
WAS_ENABLED=0; sc_is is-enabled "$OLD_UNIT" && WAS_ENABLED=1
WAS_ACTIVE=0; OLD_STATE="$(unit_state "$OLD_UNIT")"; [ "$OLD_STATE" = "active" ] && WAS_ACTIVE=1
PRE_PORTS=""; PRE_PLUGINS=""; SAMPLE_URL=""; SAMPLE_HOST=""; SAMPLE_PORT=""; SAMPLE_CODE=""
if [ "$WAS_ACTIVE" -eq 1 ]; then
  ok "$OLD_UNIT is active$([ "$WAS_ENABLED" -eq 1 ] && echo " and enabled" || echo " (not enabled: $NEW_UNIT will not be enabled either)")"
  if port_listening "$ADMIN_PORT"; then ok "admin port $ADMIN_PORT listens"; else health_issue "admin port $ADMIN_PORT does not listen"; fi
  if probe_admin; then ok "admin page answers: $ADMIN_URL ($ADMIN_CODE)"; else health_issue "the admin page on $ADMIN_HOST:$ADMIN_PORT does not answer (https and http tried)"; fi
  OLD_PID="$(main_pid "$OLD_UNIT")"
  PRE_PORTS="$(ports_of_pid "$OLD_PID")"
  if [ -n "$PRE_PORTS" ]; then ok "the old program (process $OLD_PID) listens on: $(echo $PRE_PORTS)"
  else warn "cannot see which ports the old program listens on (not root, or no process number): only ports named in start.sh are checked afterwards"; fi
  PRE_PLUGINS="$(running_plugins)"
  if [ -n "$PRE_PLUGINS" ]; then ok "plugins running: $(printf '%s\n' "$PRE_PLUGINS" | wc -l | tr -d ' ') ($(printf '%s\n' "$PRE_PLUGINS" | sed 's#/.*##' | paste -sd, - | sed 's/,/, /g'))"
  elif [ -n "$(find "$DIR/plugins" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1)" ]; then warn "no plugin process of $DIR/plugins is running now: plugins are not checked after the swap"
  else ok "no plugins installed"; fi
else
  health_issue "$OLD_UNIT is ${OLD_STATE:-unknown}, not active"
  warn "the old service does not run: ports, plugins and the proxied host cannot be compared after the swap"
fi
for p in $(flag_ports "$START_SH"); do PRE_PORTS="$(printf '%s\n%s\n' "$PRE_PORTS" "$p" | sed '/^$/d' | sort -un)"; done
PRE_RULES="$(rule_count)"
ok "proxy rules in conf/proxy: $PRE_RULES"

# --- one proxied host that answers today (from conf/proxy, through the proxy on this machine)
if [ "$WAS_ACTIVE" -eq 1 ] && [ "$PRE_RULES" -gt 0 ]; then
  cand_ports=""
  for p in $PRE_PORTS; do [ "$p" = "$ADMIN_PORT" ] || cand_ports="$cand_ports $p"; done
  # ports 443 and 80 first, then whatever else the old program listens on
  cand_ports="$(for p in 443 80; do case " $cand_ports " in *" $p "*) echo "$p" ;; esac; done; for p in $cand_ports; do case "$p" in 443|80) ;; *) echo "$p" ;; esac; done)"
  [ -n "$cand_ports" ] || cand_ports="443 80"
  tried=0; fallback=""
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    host="$(sed -n 's/^\([[:space:]]*\)"RootOrMatchingDomain":[[:space:]]*"\([^"]*\)".*/\2/p' "$f" | head -n 1)"
    ind="$(sed -n 's/^\([[:space:]]*\)"RootOrMatchingDomain":.*/\1/p' "$f" | head -n 1)"
    [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || continue
    grep -q "^${ind}\"Disabled\":[[:space:]]*false" "$f" || continue
    grep -q "^${ind}\"ProxyType\":[[:space:]]*1," "$f" || continue
    tried=$((tried + 1)); [ "$tried" -le 8 ] || break
    for p in $cand_ports; do
      for scheme in https http; do
        code="$(http_code "$scheme://$host:$p/" --resolve "$host:$p:127.0.0.1")"
        [ "$code" != "000" ] || continue
        if [[ "$code" =~ ^[23] ]]; then SAMPLE_URL="$scheme://$host:$p/"; SAMPLE_HOST="$host"; SAMPLE_PORT="$p"; SAMPLE_CODE="$code"; break 3; fi
        [ -n "$fallback" ] || fallback="$scheme://$host:$p/ $host $p $code"
        break
      done
    done
  done < <(find "$DIR/conf/proxy" -maxdepth 1 -type f -name '*.config' | sort)
  if [ -z "$SAMPLE_URL" ] && [ -n "$fallback" ]; then read -r SAMPLE_URL SAMPLE_HOST SAMPLE_PORT SAMPLE_CODE <<<"$fallback"; fi
  if [ -n "$SAMPLE_URL" ]; then ok "proxied host answers through the proxy on this machine: $SAMPLE_URL ($SAMPLE_CODE)"
  else warn "no enabled rule answered through the proxy on this machine ($tried tried): a proxied host is not checked after the swap"; fi
fi

if [ "$PRE_FAIL" -ne 0 ]; then say ""; say "Refused. Nothing was changed."; exit 2; fi

NEW_START="$(rewrite_start "$START_SH")"
NEW_UNIT_TEXT="$(build_unit)"
printf '%s\n' "$NEW_START" | grep -v '^[[:space:]]*#' | grep -Eq "$new_bin_pat" || refuse "could not rewrite start.sh (the program line was not found again)"
if printf '%s\n' "$NEW_START" | grep -v '^[[:space:]]*#' | grep -Eq "$old_bin_pat"; then refuse "start.sh would still run $OLD_BIN after the rewrite"; fi
printf '%s\n' "$NEW_START" | bash -n 2>/dev/null || refuse "the rewritten start.sh is not valid shell"
[ "$(start_flags "$START_SH")" = "$(start_flags <(printf '%s\n' "$NEW_START"))" ] \
  || refuse "the flags in the rewritten start.sh are not the same as before"
ok "flags kept:$(start_flags "$START_SH")"

if [ "$DRY_RUN" -eq 1 ]; then
  head_ "Dry run: what would be done"
  say "backup    $BK/ (program.tgz, data.tgz, README.txt)"
  say "stop      $OLD_UNIT"
  say "install   $BINARY -> $NEW_BIN (mode 755); $OLD_BIN stays"
  say "start.sh  copy kept as $START_KEEP, new content:"
  printf '%s\n' "$NEW_START" | sed 's/^/    | /'
  say "unit      $NEW_UNIT_FILE:"
  printf '%s\n' "$NEW_UNIT_TEXT" | sed 's/^/    | /'
  say "then      disable $OLD_UNIT (file stays), daemon-reload, $([ "$WAS_ENABLED" -eq 1 ] && echo "enable $NEW_UNIT, ")$([ "$NO_START" -eq 1 ] && echo "no start (--no-start)" || echo "start $NEW_UNIT, checks for up to $TIMEOUT s, automatic roll back when one fails")"
  say ""; say "--dry-run: nothing was changed. Warnings: $WARNINGS"
  exit 0
fi

if [ "$ROLE" = "live" ]; then
  hn="$(hostname 2>/dev/null || echo live)"
  say ""
  say "This is the LIVE proxy $hn. $OLD_UNIT will be stopped and visitors get no answer until Dunree"
  say "has started (usually well under a minute; up to about $((TIMEOUT * 2 + 60)) s when the swap fails and is rolled back)."
  say "New program file: $BINARY"
  if [ -n "$VERIFIED" ]; then say "  SHA-256 $GOT_SHA, verified by: $VERIFIED"; else say "  SHA-256 $GOT_SHA, NOT VERIFIED"; fi
  [ "$NO_START" -eq 0 ] || say "--no-start: Dunree will NOT be started. The proxy stays down until you start $NEW_UNIT."
  printf 'Type the host name (%s) to go on, anything else stops here: ' "$hn"
  ans=""; read -r ans || true
  say ""
  [ "$ans" = "$hn" ] || refuse "not confirmed"
fi

mkdir -p "$BACKUPS"
exec 9>"$BACKUPS/.swap-to-dunree.lock"
if command -v flock >/dev/null 2>&1; then flock -n 9 || refuse "another swap-to-dunree.sh is running on $DIR"; fi

# ---------------------------------------------------------------- from here on things change
PHASE="backup"      # backup -> changing -> done
INSTALLED_BIN=0
CHECKS_FAILED=0
BK_MADE=0
finish() {
  status=$?
  # Nothing may stop the roll back half way: not a second Ctrl+C, not the ssh session going away
  # (SIGHUP, and writes to a terminal that is gone), not an error of one command in it.
  trap '' INT TERM HUP PIPE
  trap - EXIT
  set +e
  # half-written files of this run: a full disk must not stay full
  rm -f "$NEW_BIN.swap-new" "$NEW_UNIT_FILE.swap-new"
  if [ "$BK_MADE" -eq 1 ] && [ ! -f "$BK/data.complete" ] && [ -f "$BK/data.tgz" ]; then
    rm -f "$BK/data.tgz"; warn "removed the incomplete $BK/data.tgz"
  fi
  if [ "$PHASE" = "changing" ]; then
    head_ "9. Going back to $OLD_UNIT"
    [ "$status" -eq 0 ] || [ "$CHECKS_FAILED" -eq 1 ] || fail "the swap stopped (status $status)"
    if go_back auto "$BK"; then
      if [ "$INSTALLED_BIN" -eq 1 ]; then rm -f "$NEW_BIN" && ok "removed $NEW_BIN (installed by this run)"; fi
      say ""; say "RESULT: NOT swapped. $OLD_UNIT runs the old program again. The reason is above (FAIL lines)."
      say "        Backup and details: $BK"
      exit 1
    fi
    say ""; say "RESULT: NOT swapped, and the old service is NOT healthy. Act now:"
    say "        systemctl status $OLD_UNIT ; journalctl -u $OLD_UNIT -n 50"
    say "        how to restore by hand: $BK/README.txt"
    exit 3
  fi
  if [ "$PHASE" = "backup" ] && [ "$status" -ne 0 ]; then
    [ "$BK_MADE" -eq 0 ] || [ -f "$BK/data.complete" ] || rm -f "$BK/program.tgz"
    fail "stopped during the backup (status $status). The service was not touched."
    exit 2
  fi
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM HUP
# a write to a terminal or pipe that is gone must give an error (handled in out), not end the script
trap '' PIPE

# ---------------------------------------------------------------- 2. backup, first part
mkdir "$BK"; chmod 700 "$BK"; BK_MADE=1
LOG="$BK/swap.log"; printf '%s' "$EARLY_LOG" >"$LOG" 2>/dev/null || true
head_ "2. Backup (program, unit, start.sh)"
{
  say "role=$ROLE"; say "time=$TS"; say "dir=$DIR"; say "old_unit=$OLD_UNIT"; say "new_unit=$NEW_UNIT"
  say "was_enabled=$WAS_ENABLED"; say "was_active=$WAS_ACTIVE"; say "new_sha256=$GOT_SHA"; say "rules=$PRE_RULES"
} >"$BK/state"
{
  say "# plugin folders in $DIR/plugins at $TS"
  if [ -d "$DIR/plugins" ]; then (cd "$DIR/plugins" && find . -mindepth 1 -maxdepth 2 -printf '%M %u:%g %10s %p\n' | sort -k4); fi
  say "# plugin programs running before the swap"
  printf '%s\n' "$PRE_PLUGINS"
} >"$BK/plugins.list"
cp -p "$OLD_UNIT_FILE" "$BK/$OLD_UNIT"
[ ! -d "$OLD_UNIT_FILE.d" ] || cp -rp "$OLD_UNIT_FILE.d" "$BK/"
tar -C "$DIR" -czf "$BK/program.tgz" "$OLD_NAME" start.sh
tar -tzf "$BK/program.tgz" >/dev/null
cat >"$BK/README.txt" <<EOF
Backup taken by swap-to-dunree.sh at $TS (UTC) on $(hostname 2>/dev/null || echo unknown), before the swap to Dunree.

  program.tgz     $OLD_BIN and start.sh as they were
  $OLD_UNIT       the unit file as it was
  plugins.list    the plugin folders and the plugin programs that ran
  data.tgz        conf, sys.db, sys.uuid and plugins, taken after the old service was stopped
                  (only complete when the file data.complete is next to it)
  state           what the script recorded (was the unit enabled, running, ...)
  swap.log        everything the script printed (also when the terminal was gone)

Going back, the normal way (keeps the data as it is now, the old program reads it):

  sudo $(cd "$(dirname "$0")" && pwd -P)/$(basename "$0") --rollback --dir $DIR

Going back and also restoring the data of this backup (everything changed since $TS is lost):

  sudo $(cd "$(dirname "$0")" && pwd -P)/$(basename "$0") --rollback --restore-data --dir $DIR

By hand, when the script is not there:

  systemctl stop $NEW_UNIT; systemctl disable $NEW_UNIT
  tar -C $DIR -xpzf $BK/program.tgz              # old program file and start.sh
  cp -p $BK/$OLD_UNIT $OLD_UNIT_FILE
  mv $NEW_UNIT_FILE $BK/
  # only when the data must go back too:
  #   mkdir $BK/after && mv $DIR/conf $DIR/sys.db $DIR/sys.uuid $DIR/plugins $BK/after/
  #   tar -C $DIR -xpzf $BK/data.tgz
  systemctl daemon-reload; systemctl enable $OLD_UNIT; systemctl start $OLD_UNIT
  systemctl status $OLD_UNIT

Dunree also took its own copy at its first start: $DIR/conf.pre-dunree-<time> and $DIR/sys.db.pre-dunree-<time>.
This folder holds keys and the database: keep it private (mode 0700), delete it when you are sure you stay.
EOF
printf '%s\n' "pre-dunree-$TS" >"$LATEST"
ok "old program file, unit and start.sh saved in $BK"

# ---------------------------------------------------------------- 3. stop
head_ "3. Stop $OLD_UNIT"
PHASE="changing"
T_STOP="$(date +%s)"
if [ "$WAS_ACTIVE" -eq 1 ]; then
  sc_ stop "$OLD_UNIT"
  n=0
  while pids="$(leftover_pids "$OLD_BIN")"; [ -n "$pids" ] && [ "$n" -lt 30 ]; do sleep 1; n=$((n + 1)); done
  [ -z "$pids" ] || { fail "processes of $OLD_BIN or its plugins still run after the stop ($(echo $pids))"; exit 1; }
  ok "stopped $OLD_UNIT"
else
  ok "$OLD_UNIT was not running"
fi

head_ "2b. Backup (conf, database, plugins; the service is stopped)"
items=""
for f in conf sys.db sys.uuid plugins; do [ ! -e "$DIR/$f" ] || items="$items $f"; done
# shellcheck disable=SC2086
tar -C "$DIR" -czf "$BK/data.tgz" $items
tar -tzf "$BK/data.tgz" >/dev/null
: >"$BK/data.complete"
ok "saved$items in $BK/data.tgz ($(human_kb "$(size_kb "$BK/data.tgz")"))"

# ---------------------------------------------------------------- 4. program file
head_ "4. Install $NEW_BIN"
MARKER_BEFORE=0; [ -f "$MARKER" ] && MARKER_BEFORE=1
[ ! -e "$NEW_BIN" ] || warn "$NEW_BIN existed already (an earlier attempt?): replaced"
INSTALLED_BIN=1
if [ "$(id -u)" -eq 0 ]; then install -o root -g root -m 755 "$BINARY" "$NEW_BIN.swap-new"; else install -m 755 "$BINARY" "$NEW_BIN.swap-new"; fi
mv -fT "$NEW_BIN.swap-new" "$NEW_BIN"
[ "$(sha_of "$NEW_BIN")" = "$GOT_SHA" ] || { fail "$NEW_BIN is not the file that was checked (copy damaged?)"; exit 1; }
ok "installed $NEW_BIN (mode 755, SHA-256 as checked); $OLD_BIN is untouched"

# ---------------------------------------------------------------- 5. start.sh
head_ "5. Rewrite start.sh"
cp -p "$START_SH" "$START_KEEP"
printf '%s\n' "$NEW_START" >"$START_SH"       # written into the existing file: owner and mode stay
start_runs_new || { fail "start.sh does not start $NEW_BIN after the rewrite"; exit 1; }
ok "start.sh starts $NEW_BIN$(start_flags "$START_SH")   (the old one is $START_KEEP)"

# ---------------------------------------------------------------- 6. unit
head_ "6. Write $NEW_UNIT, disable $OLD_UNIT"
printf '%s\n' "$NEW_UNIT_TEXT" >"$NEW_UNIT_FILE.swap-new"
chmod 644 "$NEW_UNIT_FILE.swap-new"
mv -fT "$NEW_UNIT_FILE.swap-new" "$NEW_UNIT_FILE"
if [ -d "$OLD_UNIT_FILE.d" ]; then cp -rp "$OLD_UNIT_FILE.d" "$NEW_UNIT_FILE.d"; ok "copied the drop-ins $OLD_UNIT.d"; fi
ok "wrote $NEW_UNIT_FILE (Description and SyslogIdentifier: Dunree; User, WorkingDirectory, ExecStart as before)"
if [ "$WAS_ENABLED" -eq 1 ]; then sc_ disable "$OLD_UNIT" >/dev/null 2>&1 || warn "systemctl disable $OLD_UNIT reported an error"; fi
ok "$OLD_UNIT disabled; its file stays in $SYSTEMD_DIR"

# ---------------------------------------------------------------- 7. start
head_ "7. Start $NEW_UNIT"
sc_ daemon-reload || { fail "systemctl daemon-reload failed"; exit 1; }
if [ "$WAS_ENABLED" -eq 1 ]; then
  sc_ enable "$NEW_UNIT" >/dev/null 2>&1 || { fail "systemctl enable $NEW_UNIT failed (an Alias= of the old unit in [Install]?)"; exit 1; }
  ok "enabled $NEW_UNIT"
else ok "$NEW_UNIT not enabled: $OLD_UNIT was not enabled either"; fi
if [ "$NO_START" -eq 1 ]; then
  PHASE="done"
  warn "--no-start: $NEW_UNIT was NOT started and nothing was checked. The proxy is down until: systemctl start $NEW_UNIT"
  say ""; say "RESULT: swapped, not started. Go back with: $0 --rollback --dir $DIR"
  exit 0
fi
sc_ start "$NEW_UNIT" || { fail "systemctl start $NEW_UNIT failed"; exit 1; }
ok "start requested"

# ---------------------------------------------------------------- 8. checks after the start
head_ "8. Checks (up to $TIMEOUT s)"
ephemeral_from="$(awk '{ print $1 }' /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo 32768)"
C_NAMES=(unit port admin marker plugins ports rules host)
declare -A C_OK C_MSG
run_checks() {
  local st p missing code now_plugins n
  st="$(unit_state "$NEW_UNIT")"
  C_OK[unit]=0; C_MSG[unit]="$NEW_UNIT is ${st:-unknown}"
  [ "$st" != "active" ] || { C_OK[unit]=1; C_MSG[unit]="$NEW_UNIT is active"; }

  C_OK[port]=0; C_MSG[port]="admin port $ADMIN_PORT does not listen"
  ! port_listening "$ADMIN_PORT" || { C_OK[port]=1; C_MSG[port]="admin port $ADMIN_PORT listens"; }

  C_OK[admin]=0; C_MSG[admin]="the admin page on $ADMIN_HOST:$ADMIN_PORT does not answer"
  if [ "${C_OK[port]}" -eq 1 ] && probe_admin; then C_OK[admin]=1; C_MSG[admin]="admin page answers: $ADMIN_URL ($ADMIN_CODE)"; fi

  C_OK[marker]=0; C_MSG[marker]="conf/dunree_install.json was not written (Dunree's first start did not get as far as the configuration)"
  if [ -s "$MARKER" ]; then
    C_OK[marker]=1
    if [ "$MARKER_BEFORE" -eq 1 ]; then C_MSG[marker]="conf/dunree_install.json is there (from an earlier Dunree start)"
    else C_MSG[marker]="conf/dunree_install.json written (first Dunree start; its own copies: $(cd "$DIR" && { ls -d conf.pre-dunree-* sys.db.pre-dunree-* 2>/dev/null || true; } | paste -sd' ' -))"; fi
  fi

  if [ -z "$PRE_PLUGINS" ]; then
    C_OK[plugins]=1; C_MSG[plugins]="plugins: none ran before, nothing to compare"
  else
    now_plugins="$(running_plugins)"; missing=""; n=0
    while IFS= read -r p; do
      if printf '%s\n' "$now_plugins" | grep -Fqx -- "$p"; then n=$((n + 1)); else missing="$missing, ${p%%/*}"; fi
    done <<<"$PRE_PLUGINS"
    if [ -z "$missing" ]; then C_OK[plugins]=1; C_MSG[plugins]="all $n plugins run again ($(printf '%s\n' "$PRE_PLUGINS" | sed 's#/.*##' | paste -sd, - | sed 's/,/, /g'))"
    else C_OK[plugins]=0; C_MSG[plugins]="plugins not running: ${missing#, } ($n of $(printf '%s\n' "$PRE_PLUGINS" | wc -l | tr -d ' ') run)"; fi
  fi

  missing=""; C_WARN_PORTS=""
  local now_ports back=""; now_ports="$(listening_ports)"
  for p in $PRE_PORTS; do
    if printf '%s\n' "$now_ports" | grep -qx "$p"; then back="$back $p"; continue; fi
    if [ "$p" -ge "$ephemeral_from" ]; then C_WARN_PORTS="$C_WARN_PORTS $p"; else missing="$missing $p"; fi
  done
  if [ -z "$missing" ]; then C_OK[ports]=1; C_MSG[ports]="the ports from before listen again:${back:- none to compare}"
  else C_OK[ports]=0; C_MSG[ports]="ports that listened before and do not now:$missing"; fi

  n="$(rule_count)"
  if [ "$n" = "$PRE_RULES" ]; then C_OK[rules]=1; C_MSG[rules]="proxy rules in conf/proxy: $n, as before"
  else C_OK[rules]=0; C_MSG[rules]="proxy rules in conf/proxy: $n, before the swap $PRE_RULES"; fi

  if [ -z "$SAMPLE_URL" ]; then
    C_OK[host]=1; C_MSG[host]="proxied host: none answered before, not checked"
  else
    code="$(http_code "$SAMPLE_URL" --resolve "$SAMPLE_HOST:$SAMPLE_PORT:127.0.0.1")"
    if [ "$code" = "000" ]; then C_OK[host]=0; C_MSG[host]="proxied host $SAMPLE_URL does not answer (before the swap: $SAMPLE_CODE)"
    else C_OK[host]=1; C_MSG[host]="proxied host answers: $SAMPLE_URL ($code$([ "$code" = "$SAMPLE_CODE" ] || echo ", before the swap $SAMPLE_CODE"))"; fi
  fi
}
all_ok() { local c; for c in "${C_NAMES[@]}"; do [ "${C_OK[$c]}" -eq 1 ] || return 1; done; }
deadline=$(( $(date +%s) + TIMEOUT ))
PASSED=0
while :; do
  run_checks
  if all_ok; then
    # it must also stay up: the same process, still passing, a few seconds later
    pid1="$(main_pid "$NEW_UNIT")"
    sleep "$SETTLE"
    run_checks
    pid2="$(main_pid "$NEW_UNIT")"
    if all_ok && [ "$pid2" = "$pid1" ]; then PASSED=1; break; fi
    if [ "$pid2" != "$pid1" ] && [ "${C_OK[unit]}" -eq 1 ]; then C_OK[unit]=0; C_MSG[unit]="$NEW_UNIT restarted by itself while it was checked"; fi
  fi
  [ "$(unit_state "$NEW_UNIT")" != "failed" ] || break
  [ "$(date +%s)" -lt "$deadline" ] || break
  sleep 2
done
for c in "${C_NAMES[@]}"; do if [ "${C_OK[$c]}" -eq 1 ]; then ok "${C_MSG[$c]}"; else fail "${C_MSG[$c]}"; fi; done
[ -z "${C_WARN_PORTS:-}" ] || warn "ports from the range for outgoing connections listened before and do not now (normal for a helper port):$C_WARN_PORTS"
if [ -n "$SAMPLE_URL" ] && [ "${C_OK[host]}" -eq 1 ] && [[ "${C_MSG[host]}" == *"before the swap"* ]]; then warn "the proxied host answers with another code than before the swap: look at it"; fi
if [ "$PASSED" -ne 1 ]; then
  [ "${C_OK[rules]}" -eq 1 ] || RESTORE_DATA=1
  fail "not all checks passed within $TIMEOUT s"
  CHECKS_FAILED=1
  if [ "$TEST_MODE" -eq 0 ]; then
    say "      last lines of the service log:"
    jl="$(journalctl -u "$NEW_UNIT" -n 15 --no-pager 2>/dev/null | cut -c1-300 || true)"
    while IFS= read -r l; do say "      | $l"; done <<<"$jl"
  fi
  exit 1
fi

PHASE="done"
say ""
say "RESULT: swapped. $NEW_UNIT runs $NEW_BIN; the proxy was down for about $(( $(date +%s) - T_STOP - SETTLE )) s. Warnings: $WARNINGS"
say "        Log:        journalctl -u $NEW_UNIT -f      (the log name is now dunree, no longer $OLD_NAME)"
say "        Go back:    $0 --rollback --dir $DIR"
say "        Kept:       $OLD_BIN, $OLD_UNIT_FILE (disabled), $START_KEEP, $BK"
exit 0
