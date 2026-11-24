#!/bin/sh
# Dunree package: before removal. Stops and disables the service on removal, not on upgrade.
set -e

removing=no
case "$1" in
  remove|purge) removing=yes ;;   # deb
  0) removing=yes ;;              # rpm: 0 versions left after this step
esac

if [ "$removing" = yes ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now dunree.service >/dev/null 2>&1 || true
fi
exit 0
