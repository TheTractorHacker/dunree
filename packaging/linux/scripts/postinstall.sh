#!/bin/sh
# Dunree package: after install or upgrade (.deb and .rpm).
# First install: the service is NOT enabled and NOT started (another proxy may hold the ports).
# Upgrade: a running service is restarted, a stopped one stays stopped.
set -e

upgrade=no
case "$1" in
  configure) [ -n "$2" ] && upgrade=yes ;;   # deb: $2 = version that was installed before
  2|[3-9]|[1-9][0-9]*) upgrade=yes ;;        # rpm: number of installed versions after this step
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  if [ "$upgrade" = yes ]; then
    systemctl try-restart dunree.service || true
  fi
fi

if [ "$upgrade" = no ]; then
  echo "Dunree is installed but not started."
  echo "  Flags:  /etc/default/dunree      Data: /var/lib/dunree"
  echo "  Start:  systemctl enable --now dunree"
  echo "  Then open http://<this machine>:8000 to create the admin account."
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet zoraxy.service 2>/dev/null; then
    echo "  NOTE: zoraxy.service is running on this machine. Do not start both: see tools/install/migrate-from-zoraxy.sh."
  fi
fi
exit 0
