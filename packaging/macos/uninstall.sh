#!/bin/sh
# Remove a Dunree install made by the .pkg. The data folder is kept unless --remove-data is given.
#   sudo ./uninstall.sh [--remove-data]
set -eu

remove_data=no
[ "${1:-}" != "--remove-data" ] || remove_data=yes
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

launchctl bootout system/ie.foleyit.dunree >/dev/null 2>&1 || true
rm -f /Library/LaunchDaemons/ie.foleyit.dunree.plist /usr/local/bin/dunree
rm -rf /usr/local/share/doc/dunree
pkgutil --forget ie.foleyit.dunree >/dev/null 2>&1 || true
if [ "$remove_data" = yes ]; then
  rm -rf /usr/local/var/dunree /usr/local/var/log/dunree
  echo "Dunree and its data were removed."
else
  echo "Dunree was removed. Data kept in /usr/local/var/dunree, logs in /usr/local/var/log/dunree."
fi
