#!/bin/sh
# Install Dunree from the release tarball on a Linux machine with systemd.
#
#   sudo ./install.sh [--dir /opt/dunree] [--start] [--dry-run]
#
# Copies the dunree binary next to this script into DIR and writes
# /etc/systemd/system/dunree.service. It does not enable or start the service unless
# --start is given, and it refuses to touch an existing unit file or an existing binary
# in DIR (upgrade an install with the Update page, or copy the binary by hand).
# --dry-run prints what would be done and changes nothing.
#
# $DUNREE_UNIT_DIR overrides /etc/systemd/system (for tests).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dir=/opt/dunree
unitdir=${DUNREE_UNIT_DIR:-/etc/systemd/system}
start=no
dry=no

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || { echo "--dir needs a folder" >&2; exit 2; }; dir=$2; shift 2 ;;
    --start) start=yes; shift ;;
    --dry-run) dry=yes; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$dir" in
  /*) ;;
  *) echo "--dir must be an absolute path" >&2; exit 2 ;;
esac
case "$dir" in
  *[!A-Za-z0-9/._-]*) echo "--dir may only contain letters, digits and / . _ -" >&2; exit 2 ;;
esac

[ -f "$here/dunree" ] || { echo "dunree binary not found next to install.sh" >&2; exit 1; }
[ -f "$here/dunree.service" ] || { echo "dunree.service not found next to install.sh" >&2; exit 1; }
unit="$unitdir/dunree.service"
[ ! -e "$unit" ] || { echo "$unit already exists: not overwriting it" >&2; exit 1; }
[ ! -e "$dir/dunree" ] || { echo "$dir/dunree already exists: not overwriting it" >&2; exit 1; }

run() {
  if [ "$dry" = yes ]; then
    echo "would run: $*"
  else
    "$@"
  fi
}

if [ "$dry" = no ] && [ "$(id -u)" != 0 ]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

if [ -d "$dir" ]; then
  # An existing folder (e.g. --dir /opt) keeps its mode: making it 0750 could lock other users out.
  echo "$dir exists: its permissions are not changed"
else
  run mkdir -p "$dir"
  run chmod 750 "$dir"
fi
run install -m 755 "$here/dunree" "$dir/dunree"
for f in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
  [ ! -f "$here/$f" ] || run install -m 644 "$here/$f" "$dir/$f"
done
if [ "$dry" = yes ]; then
  echo "would write: $unit (paths set to $dir)"
else
  sed "s|/opt/dunree|$dir|g" "$here/dunree.service" >"$unit"
  chmod 644 "$unit"
fi
if command -v systemctl >/dev/null 2>&1; then
  run systemctl daemon-reload
  if [ "$start" = yes ]; then
    run systemctl enable --now dunree.service
  fi
fi

echo "Dunree is installed in $dir."
if [ "$start" != yes ]; then
  echo "Start it with: systemctl enable --now dunree"
fi
echo "Then open http://<this machine>:8000 to create the admin account."
