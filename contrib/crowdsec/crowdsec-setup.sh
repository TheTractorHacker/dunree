#!/usr/bin/env bash
# crowdsec-setup.sh - helper that installs CrowdSec (a separate program) for use with Dunree.
#
# Dunree itself never installs software. This script is shipped next to the Dunree
# release; YOU run it, as root, on the machine that should run CrowdSec. It does not
# touch Dunree, its files or its settings.
#
# Steps (each one asks first, unless --yes is given):
#   1. add the CrowdSec package repository (the documented installer is DOWNLOADED to a
#      temp file, its sha256 is shown, and it only runs after you confirm)
#   2. apt install crowdsec
#   3. optional (--log-dir DIR): let CrowdSec read Dunree's request logs
#   4. create a bouncer key 'dunree-<hostname>' (only if that name is not registered yet)
#      and print the Local API address and the key ONCE on the terminal
#
# Commands used come from https://docs.crowdsec.net/u/getting_started/installation/linux
# and https://docs.crowdsec.net/docs/local_api/bouncers . Not tested against every
# CrowdSec release; read the --dry-run output first.
set -euo pipefail

INSTALLER_URL="https://install.crowdsec.net"
LAPI_DEFAULT="http://127.0.0.1:8080"
ACQUIS_DIR="${CROWDSEC_ACQUIS_DIR:-/etc/crowdsec/acquis.d}"   # override only for tests
ACQUIS_FILE="$ACQUIS_DIR/dunree.yaml"
# The file an earlier run (as the Zoraxy helper) wrote: when it exists it is used and left alone. # legacy-compat rebrand:keep
LEGACY_ACQUIS_FILE="$ACQUIS_DIR/zoraxy.yaml"
[ -e "$LEGACY_ACQUIS_FILE" ] && [ ! -e "$ACQUIS_FILE" ] && ACQUIS_FILE="$LEGACY_ACQUIS_FILE"

DRY=0; YES=0; LOGDIR=""; BNAME=""

usage() {
  cat <<USAGE
Usage: sudo bash crowdsec-setup.sh [--dry-run] [--yes] [--log-dir DIR] [--name NAME]

  --dry-run      print what would be done; change nothing (does not need root)
  --yes          do not ask for confirmation (also runs the downloaded repo installer
                 without asking; its sha256 is still printed)
  --log-dir DIR  full path of Dunree's log folder; creates $ACQUIS_FILE so CrowdSec
                 reads zr_*.log there (CrowdSec has no built-in parser for these lines)
  --name NAME    bouncer name (default: dunree-<hostname>)
  -h, --help     this text

Supported: Debian and Ubuntu (apt). Anything else: use the Docker option, see
crowdsec-docker-compose.yml and CROWDSEC-README.md.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --yes|-y) YES=1 ;;
    --log-dir) [ $# -ge 2 ] || { echo "--log-dir needs a value" >&2; exit 2; }; LOGDIR="$2"; shift ;;
    --name) [ $# -ge 2 ] || { echo "--name needs a value" >&2; exit 2; }; BNAME="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[ -n "$BNAME" ] || BNAME="dunree-$(hostname)"
case "$BNAME" in *[!A-Za-z0-9._-]*|"") echo "bouncer name may only contain letters, digits . _ -" >&2; exit 2 ;; esac
if [ -n "$LOGDIR" ]; then
  case "$LOGDIR" in /*) ;; *) echo "--log-dir must be a full path starting with /" >&2; exit 2 ;; esac
  case "$LOGDIR" in *[!A-Za-z0-9._/+@:-]*) echo "--log-dir contains characters this script will not write into a YAML file; use a simpler path" >&2; exit 2 ;; esac
fi

say() { printf '%s\n' "$*"; }
plan() { printf '[dry-run] %s\n' "$*"; }

# ask "question": returns 0 for yes. --yes answers yes. Dry run never asks.
ask() {
  [ "$YES" = 1 ] && return 0
  local a
  read -r -p "$1 [y/N] " a </dev/tty || return 1
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ---- OS check (read-only) ----
OS_ID=""; OS_LIKE=""; OS_PRETTY=""
if [ -r /etc/os-release ]; then
  # read the fields in a subshell so os-release cannot overwrite this script's variables
  OS_ID="$(. /etc/os-release; printf '%s' "${ID:-}")"
  OS_LIKE="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
  OS_PRETTY="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-}")"
fi
case " $OS_ID $OS_LIKE " in
  *" debian "*|*" ubuntu "*) ;;
  *)
    say "This script supports Debian and Ubuntu only (found: ${OS_PRETTY:-unknown})."
    say "Use the Docker option instead: crowdsec-docker-compose.yml and CROWDSEC-README.md,"
    say "or see https://docs.crowdsec.net/u/getting_started/installation/linux"
    exit 1 ;;
esac

# ---- root check (never calls sudo itself) ----
if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then
  say "This script must run as root because it installs a package."
  say "Run it again with sudo:   sudo bash $0 $*"
  exit 1
fi
[ "$DRY" = 1 ] && say "DRY RUN: nothing will be changed."

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT

# ---- 1+2: install ----
if [ "$DRY" = 0 ] && command -v cscli >/dev/null 2>&1 && dpkg -s crowdsec >/dev/null 2>&1; then
  say "CrowdSec is already installed; skipping the install steps."
else
  if [ "$DRY" = 1 ]; then
    plan "download $INSTALLER_URL to a temp file (curl -fsS), print its sha256, ask before running it with sh"
    plan "apt install crowdsec"
  else
    command -v curl >/dev/null 2>&1 || { say "curl is needed (apt install curl)"; exit 1; }
    say
    say "Step 1: add the CrowdSec package repository."
    say "The documented installer is downloaded to a temp file first so you can read it."
    TMP="$(mktemp -d)"
    curl -fsS "$INSTALLER_URL" -o "$TMP/install.sh"
    say "Downloaded to $TMP/install.sh"
    say "sha256: $(sha256sum "$TMP/install.sh" | cut -d' ' -f1)"
    say "(You can read it now in another terminal: less $TMP/install.sh)"
    ask "Run this installer as root now?" || { say "Stopped. Nothing was changed."; exit 1; }
    sh "$TMP/install.sh"
    say
    say "Step 2: install the crowdsec package."
    ask "Run 'apt install crowdsec' now?" || { say "Stopped after adding the repository."; exit 1; }
    if [ "$YES" = 1 ]; then apt install -y crowdsec; else apt install crowdsec; fi
  fi
fi

# ---- 3: acquisition (optional) ----
if [ -n "$LOGDIR" ]; then
  content="filenames:
  - ${LOGDIR%/}/zr_*.log
labels:
  type: dunree"
  if [ "$DRY" = 1 ]; then
    plan "write $ACQUIS_FILE (refuse to overwrite an existing file) with:"
    printf '%s\n' "$content" | sed 's/^/[dry-run]   /'
    plan "crowdsec -t && systemctl restart crowdsec"
  else
    say
    say "Step 3: let CrowdSec read Dunree's logs from $LOGDIR"
    say "Note: CrowdSec has no built-in parser for type 'dunree'; see the Dunree CrowdSec guide."
    if [ -e "$ACQUIS_FILE" ]; then
      say "$ACQUIS_FILE already exists; leaving it alone."
    elif ask "Create $ACQUIS_FILE and restart CrowdSec?"; then
      mkdir -p "$(dirname "$ACQUIS_FILE")"
      printf '%s\n' "$content" >"$ACQUIS_FILE"
      if crowdsec -t; then
        systemctl restart crowdsec
      else
        # never leave a file behind that makes every later CrowdSec start or reload fail
        rm -f -- "$ACQUIS_FILE"
        say "CrowdSec rejected the new acquisition file; it was removed again. Nothing else was changed."
        exit 1
      fi
    else
      say "Skipped."
    fi
  fi
else
  say "Log reading not configured (no --log-dir). That is fine: the community blocklist works without it."
fi

# ---- 4: bouncer key ----
if [ "$DRY" = 1 ]; then
  plan "if you confirm: cscli bouncers add $BNAME   (CrowdSec prints the key once on the terminal; this script does not read or save it)"
  plan "print the Local API address (default $LAPI_DEFAULT) for Dunree > Security Center > CrowdSec"
  say "DRY RUN finished; nothing was changed."
  exit 0
fi

command -v cscli >/dev/null 2>&1 || { say "cscli not found; is crowdsec installed?"; exit 1; }
say
say "Step 4: create a bouncer key for Dunree."
ask "Create bouncer '$BNAME' now (cscli bouncers add $BNAME)?" || { say "Skipped."; exit 0; }
say "CrowdSec prints the key below ONCE. Copy it now; this script does not save it."
cscli bouncers add "$BNAME" || {
  say "cscli could not create '$BNAME'. If it already exists, list with 'cscli bouncers list',"
  say "delete it with 'cscli bouncers delete $BNAME' and run this script again."
  exit 1
}
say
say "======================================================================"
say " Paste into Dunree: Security Center > CrowdSec"
say "   Local API address: $LAPI_DEFAULT"
say "   (use this machine's address instead if Dunree runs on another server;"
say "    check where the Local API listens in /etc/crowdsec/config.yaml)"
say "   Bouncer key:       the key printed by cscli above (shown only once)"
say "======================================================================"
