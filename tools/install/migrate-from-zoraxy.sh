#!/usr/bin/env bash
# Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.
#
# Rename the service and the install folder of an existing Zoraxy install to Dunree.   # rebrand:keep
# Documentation: docs/migrating-from-zoraxy.md                                          # rebrand:keep
#
# What it does, in this order (nothing is deleted, and it undoes its own steps when one fails):
#   1. stops the old service
#   2. moves the install folder (/opt/zoraxy -> /opt/dunree) and leaves a link at the old path,   # rebrand:keep
#      so scripts, cron jobs and backups that use the old path keep working
#   3. writes dunree.service as a copy of the old unit with the folder path replaced
#      (and copies the unit's drop-in folder, if it has one)
#   4. disables the old unit. Its file stays where it is, so going back is one command
#   5. reloads systemd, enables and starts dunree.service if the old unit was enabled / running
#
# It does not touch the configuration, the database, certificates or plugins: they move with the folder.
# It does not rename the program file: an install that was updated in place keeps its file name.
# Run it as root on the machine itself. It is safe to run twice: the second run reports "already migrated".
#
# Usage: migrate-from-zoraxy.sh [options]                                               # rebrand:keep
#   --dry-run            show what would be done and the unit that would be written; change nothing
#   --no-start           do not start dunree.service at the end (enable only)
#   --keep-dir           rename the service only, leave the install folder where it is
#   --old-dir DIR        install folder today              (default /opt/zoraxy)         # rebrand:keep
#   --new-dir DIR        install folder afterwards         (default /opt/dunree)
#   --old-unit NAME      unit name today                   (default zoraxy.service)      # rebrand:keep
#   --new-unit NAME      unit name afterwards              (default dunree.service)
#   --systemd-dir DIR    where the unit file is            (default /etc/systemd/system)
#   --root DIR           work below DIR instead of / (tests, images). systemctl is then only called
#                        when the SYSTEMCTL environment variable names a program to use
#   -h, --help           this text
#
# Exit status: 0 done or already migrated, 1 a step failed and was undone, 2 nothing to migrate or refused.
set -euo pipefail

OLD_DIR="/opt/zoraxy"          # rebrand:keep
NEW_DIR="/opt/dunree"
OLD_UNIT="zoraxy.service"      # rebrand:keep
NEW_UNIT="dunree.service"
SYSTEMD_DIR="/etc/systemd/system"
ROOT=""
DRY_RUN=0
NO_START=0
KEEP_DIR=0

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit "${2:-2}"; }
usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); sub(/[[:space:]]*# rebrand:keep$/, ""); print; next } NR > 2 { exit }' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --no-start) NO_START=1 ;;
    --keep-dir) KEEP_DIR=1 ;;
    --old-dir) OLD_DIR="${2:?--old-dir needs a value}"; shift ;;
    --new-dir) NEW_DIR="${2:?--new-dir needs a value}"; shift ;;
    --old-unit) OLD_UNIT="${2:?--old-unit needs a value}"; shift ;;
    --new-unit) NEW_UNIT="${2:?--new-unit needs a value}"; shift ;;
    --systemd-dir) SYSTEMD_DIR="${2:?--systemd-dir needs a value}"; shift ;;
    --root) ROOT="${2:?--root needs a value}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# The paths go into a sed expression and into a unit file: accept plain paths and names only.
plain_path='^/[A-Za-z0-9._/-]+$'
plain_unit='^[A-Za-z0-9._@-]+\.service$'
[[ "$OLD_DIR" =~ $plain_path ]] || die "--old-dir must be an absolute path of letters, digits, . _ - and /"
[[ "$NEW_DIR" =~ $plain_path ]] || die "--new-dir must be an absolute path of letters, digits, . _ - and /"
[[ "$SYSTEMD_DIR" =~ $plain_path ]] || die "--systemd-dir must be an absolute path of letters, digits, . _ - and /"
[[ "$OLD_UNIT" =~ $plain_unit ]] || die "--old-unit must be a unit name ending in .service"
[[ "$NEW_UNIT" =~ $plain_unit ]] || die "--new-unit must be a unit name ending in .service"
OLD_DIR="${OLD_DIR%/}"; NEW_DIR="${NEW_DIR%/}"; ROOT="${ROOT%/}"
[ "$OLD_UNIT" != "$NEW_UNIT" ] || die "old and new unit name are the same"
if [ "$KEEP_DIR" -eq 0 ]; then
  [ "$OLD_DIR" != "$NEW_DIR" ] || die "old and new folder are the same (use --keep-dir to rename the service only)"
  case "$NEW_DIR/" in "$OLD_DIR"/*) die "the new folder cannot be inside the old one" ;; esac
fi

# systemctl: the real one on a live system; below --root only what SYSTEMCTL names (nothing by default).
if [ -n "${SYSTEMCTL:-}" ]; then
  SC="$SYSTEMCTL"
elif [ -z "$ROOT" ]; then
  SC="systemctl"
else
  SC=""
fi
sc() {
  if [ -z "$SC" ]; then say "  (not run, --root given: systemctl $*)"; return 0; fi
  "$SC" "$@"
}
# answers of "is-..." questions; without systemctl everything counts as "no"
sc_is() { [ -n "$SC" ] && "$SC" "$@" >/dev/null 2>&1; }

if [ -z "$ROOT" ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "run this as root (it stops a service and moves $OLD_DIR). Use --dry-run to look first."
fi

UNIT_DIR="$ROOT$SYSTEMD_DIR"
OLD_UNIT_FILE="$UNIT_DIR/$OLD_UNIT"
NEW_UNIT_FILE="$UNIT_DIR/$NEW_UNIT"
OLD_PATH="$ROOT$OLD_DIR"
NEW_PATH="$ROOT$NEW_DIR"

# The link left at the old path: relative when both folders have the same parent (it then also works
# below --root and after the parent is moved), absolute otherwise.
if [ "$(dirname "$OLD_DIR")" = "$(dirname "$NEW_DIR")" ]; then
  LINK_TARGET="$(basename "$NEW_DIR")"
else
  LINK_TARGET="$NEW_DIR"
fi

same_dir() { [ -d "$1" ] && [ -d "$2" ] && [ "$(cd "$1" && pwd -P)" = "$(cd "$2" && pwd -P)" ]; }

# ---- already done?
if [ -e "$NEW_UNIT_FILE" ]; then
  if [ "$KEEP_DIR" -eq 1 ] || { [ -L "$OLD_PATH" ] && same_dir "$OLD_PATH" "$NEW_PATH"; } || { [ ! -e "$OLD_PATH" ] && [ ! -L "$OLD_PATH" ]; }; then
    say "Already migrated: $NEW_UNIT_FILE exists. Nothing to do."
    exit 0
  fi
  die "$NEW_UNIT_FILE exists already but $OLD_PATH is still a folder of its own. Refusing to overwrite; look at both first."
fi

# ---- checks, before anything is changed
if [ ! -f "$OLD_UNIT_FILE" ]; then
  die "no $OLD_UNIT in $UNIT_DIR: nothing to migrate. If the unit lives somewhere else, pass --systemd-dir (see: systemctl cat $OLD_UNIT)."
fi
MOVE_DIR=0
if [ "$KEEP_DIR" -eq 0 ]; then
  if [ -L "$OLD_PATH" ]; then
    die "$OLD_PATH is a link already. Move the real folder yourself or run with --keep-dir."
  elif [ -d "$OLD_PATH" ]; then
    if [ -e "$NEW_PATH" ] || [ -L "$NEW_PATH" ]; then
      die "$NEW_PATH exists already. Refusing to merge two folders; remove or rename it, or run with --keep-dir."
    fi
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$OLD_PATH"; then
      die "$OLD_PATH is a mount point and cannot be renamed. Change the mount to $NEW_DIR yourself, or run with --keep-dir."
    fi
    [ -d "$(dirname "$NEW_PATH")" ] || die "the parent folder of $NEW_PATH does not exist"
    # mv between two file systems copies and deletes: not atomic, and a copy that fails half way cannot be undone
    if [ "$(stat -L -c %d "$OLD_PATH" 2>/dev/null)" != "$(stat -L -c %d "$(dirname "$NEW_PATH")" 2>/dev/null)" ]; then
      die "$OLD_PATH and $(dirname "$NEW_PATH") are on different file systems: the folder can only be renamed within one. Move it yourself, or run with --keep-dir."
    fi
    MOVE_DIR=1
  else
    warn "$OLD_PATH does not exist: only the service is renamed (pass --old-dir if the install is somewhere else)."
  fi
fi

# ---- the new unit, built from the old one
old_re="$(printf '%s' "$OLD_DIR" | sed 's/[.]/\\./g')"
rewrite_paths() {
  # replaces OLD_DIR only where it is a whole path: at the start of the line or after anything but a letter,
  # digit, . or _ (=, white space, a quote, the - + ! @ prefixes of Exec lines), so a longer path that only
  # ends the same (/usr/local/opt/zoraxy) stays as it is; and followed by /, white space,   # rebrand:keep
  # a quote, : ; , or the end of the line. The expression runs twice: one match takes the character after it, so
  # in "/opt/zoraxy:/opt/zoraxy/x" the second path is only found on the second pass.   # rebrand:keep
  if [ "$MOVE_DIR" -eq 1 ]; then
    local e="s#(^|[^A-Za-z0-9._])${old_re}(/|[[:space:]]|[\"':;,]|\$)#\\1${NEW_DIR}\\2#g"
    sed -E -e "$e" -e "$e"
  else
    cat
  fi
}
build_unit() {
  say "# $NEW_UNIT: written by migrate-from-zoraxy.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ) from $OLD_UNIT."   # rebrand:keep
  say "# $OLD_UNIT is still in $SYSTEMD_DIR, disabled. To go back: see docs/migrating-from-zoraxy.md."      # rebrand:keep
  rewrite_paths <"$OLD_UNIT_FILE" | awk -v conflicts="$OLD_UNIT" '
    { print }
    /^\[Unit\][[:space:]]*$/ && !done {
      print "# Never run next to the old unit: both would use the same folder, ports and database."
      print "Conflicts=" conflicts
      done = 1
    }' | sed -E 's/^Description=.*[Zz]oraxy.*$/Description=Dunree reverse proxy and web gateway/'   # rebrand:keep
}
grep -q '^\[Unit\]' "$OLD_UNIT_FILE" || die "$OLD_UNIT_FILE has no [Unit] section: not a unit file this script understands"

say "Plan:"
say "  service   $OLD_UNIT -> $NEW_UNIT   (in $UNIT_DIR; the old file stays, disabled)"
if [ "$MOVE_DIR" -eq 1 ]; then
  say "  folder    $OLD_PATH -> $NEW_PATH   (a link stays at the old path)"
else
  say "  folder    not moved"
fi
if [ -d "$OLD_UNIT_FILE.d" ]; then say "  drop-ins  $OLD_UNIT.d -> $NEW_UNIT.d (copied)"; fi

if [ "$DRY_RUN" -eq 1 ]; then
  say ""
  say "--- $NEW_UNIT_FILE would be:"
  build_unit
  say "--- dry run: nothing was changed."
  exit 0
fi

WAS_ENABLED=0; WAS_ACTIVE=0
if sc_is is-enabled "$OLD_UNIT"; then WAS_ENABLED=1; fi
if sc_is is-active "$OLD_UNIT"; then WAS_ACTIVE=1; fi

# ---- undo, newest step first
DID_STOP=0; DID_MOVE=0; DID_UNIT=0; DID_DROPIN=0; DID_DISABLE=0; DID_ENABLE=0
undo() {
  status=$?
  trap - EXIT
  [ "$status" -ne 0 ] || exit 0
  warn "a step failed (status $status). Putting everything back."
  set +e
  if [ "$DID_ENABLE" -eq 1 ]; then sc disable "$NEW_UNIT" >/dev/null 2>&1; fi
  if [ "$DID_UNIT" -eq 1 ]; then sc stop "$NEW_UNIT" >/dev/null 2>&1; fi
  if [ "$DID_DROPIN" -eq 1 ]; then rm -rf "$NEW_UNIT_FILE.d"; fi
  if [ "$DID_UNIT" -eq 1 ]; then rm -f "$NEW_UNIT_FILE" "$NEW_UNIT_FILE.tmp"; fi
  if [ "$DID_MOVE" -eq 1 ]; then
    if [ -L "$OLD_PATH" ]; then rm -f "$OLD_PATH"; fi
    if [ ! -e "$OLD_PATH" ]; then mv "$NEW_PATH" "$OLD_PATH"; fi
  fi
  sc daemon-reload >/dev/null 2>&1
  if [ "$DID_DISABLE" -eq 1 ] && [ "$WAS_ENABLED" -eq 1 ]; then sc enable "$OLD_UNIT" >/dev/null 2>&1; fi
  if [ "$DID_STOP" -eq 1 ] && [ "$WAS_ACTIVE" -eq 1 ]; then
    if sc start "$OLD_UNIT"; then say "  $OLD_UNIT is running again."; else warn "could not start $OLD_UNIT again: start it by hand"; fi
  fi
  warn "nothing was migrated. Fix the problem above and run the script again."
  exit 1
}
trap undo EXIT

say "1. Stopping $OLD_UNIT"
if [ "$WAS_ACTIVE" -eq 1 ]; then DID_STOP=1; sc stop "$OLD_UNIT"; else say "  (was not running)"; fi

if [ "$MOVE_DIR" -eq 1 ]; then
  say "2. Moving $OLD_PATH to $NEW_PATH"
  mv "$OLD_PATH" "$NEW_PATH"
  DID_MOVE=1
  ln -s "$LINK_TARGET" "$OLD_PATH"
else
  say "2. Folder not moved"
fi

say "3. Writing $NEW_UNIT_FILE"
DID_UNIT=1
build_unit >"$NEW_UNIT_FILE.tmp"
chmod 644 "$NEW_UNIT_FILE.tmp"
mv "$NEW_UNIT_FILE.tmp" "$NEW_UNIT_FILE"
if [ -d "$OLD_UNIT_FILE.d" ]; then
  DID_DROPIN=1
  mkdir "$NEW_UNIT_FILE.d"
  for f in "$OLD_UNIT_FILE.d"/*.conf; do
    [ -f "$f" ] || continue
    rewrite_paths <"$f" >"$NEW_UNIT_FILE.d/$(basename "$f")"
    chmod 644 "$NEW_UNIT_FILE.d/$(basename "$f")"
  done
fi

say "4. Disabling $OLD_UNIT (the file stays in $UNIT_DIR)"
DID_DISABLE=1
if [ "$WAS_ENABLED" -eq 1 ]; then sc disable "$OLD_UNIT"; else say "  (was not enabled)"; fi

say "5. Reloading systemd"
sc daemon-reload
if [ "$WAS_ENABLED" -eq 1 ]; then DID_ENABLE=1; sc enable "$NEW_UNIT"; else say "  $NEW_UNIT not enabled: $OLD_UNIT was not enabled either"; fi
if [ "$WAS_ACTIVE" -eq 1 ] && [ "$NO_START" -eq 0 ]; then
  sc start "$NEW_UNIT"
  say "  $NEW_UNIT started."
elif [ "$WAS_ACTIVE" -eq 1 ]; then
  say "  not started (--no-start). Start it with: systemctl start $NEW_UNIT"
else
  say "  not started: $OLD_UNIT was not running. Start it with: systemctl start $NEW_UNIT"
fi

trap - EXIT
say ""
say "Done. The service is now $NEW_UNIT."
if [ "$MOVE_DIR" -eq 1 ]; then
  say "The install is in $NEW_DIR; $OLD_DIR is a link to it, so old paths keep working."
  say "Paths outside the unit (cron jobs, backup scripts, log rotation) were not changed. Find them with:"
  say "  grep -rIl -- '$OLD_DIR' /etc 2>/dev/null"
fi
say "The old unit file $SYSTEMD_DIR/$OLD_UNIT was kept, disabled. Do not start it next to $NEW_UNIT"
say "(the new unit has Conflicts=$OLD_UNIT, so systemd stops one when the other starts)."
say "To go back: docs/migrating-from-zoraxy.md, section \"Going back\"."   # rebrand:keep
