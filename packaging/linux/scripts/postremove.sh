#!/bin/sh
# Dunree package: after removal. The data folder is never deleted, not even on purge.
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
case "$1" in
  purge|0)
    if [ -d /var/lib/dunree ]; then
      echo "Dunree: /var/lib/dunree (configuration, database, certificates) was kept. Delete it by hand if you no longer need it."
    fi
    ;;
esac
exit 0
