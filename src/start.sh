#!/bin/sh
# Start Dunree by hand, in the foreground, for a quick test or a first run.
#
# Stop it with Ctrl+C. NEVER press Ctrl+Z: that freezes Dunree (and its plugins) but leaves its
# ports open, so browsers hang or get "connection refused", and the frozen process keeps the
# database locked so a second start (for example systemctl start dunree) waits forever.
#
# If Dunree is installed as a systemd service, do not run this script next to it:
#   sudo systemctl restart dunree     # restart
#   sudo systemctl stop dunree        # stop, then run this script if you really want a manual run
# An install upgraded in place from Zoraxy keeps its service name and file name: use zoraxy there. (rebrand:keep)
# To start anyway (you know what you are doing): FORCE=1 ./start.sh
# To see what is running and who holds the database: sudo ./dunree -doctor

# The program in this folder: dunree, or zoraxy on an install upgraded in place (legacy-compat).
bin=dunree
if [ ! -e ./dunree ] && [ -e ./zoraxy ]; then bin=zoraxy; fi

# A unit whose ExecStart is this script runs inside the service's own cgroup: that is fine, so the
# guard is skipped. (INVOCATION_ID is not used for this: terminals started as user services inherit it.)
in_unit=""
if grep -E '(dunree|zoraxy)\.service' /proc/self/cgroup >/dev/null 2>&1; then in_unit=1; fi

unit=dunree
if [ -z "$FORCE" ] && [ -z "$in_unit" ]; then
    refuse=""

    if command -v systemctl >/dev/null 2>&1; then
        for u in dunree zoraxy; do
            state=$(systemctl is-active "$u" 2>/dev/null)
            case "$state" in
                active | activating | reloading)
                    unit=$u
                    refuse="the systemd service '$u' is $state. A second copy would fight it for the database and the ports."
                    break
                    ;;
            esac
        done
    fi

    if [ -z "$refuse" ] && command -v pgrep >/dev/null 2>&1; then
        others=$( (pgrep -x dunree; pgrep -x zoraxy) 2>/dev/null | tr '\n' ' ')
        if [ -n "${others% }" ]; then
            refuse="another Dunree is already running (PID ${others% }). Only one can hold the database."
        fi
    fi

    if [ -n "$refuse" ]; then
        {
            echo "start.sh: not starting, $refuse"
            echo
            echo "  To restart the service:   sudo systemctl restart $unit"
            echo "  To see who is running it: sudo ./$bin -doctor"
            echo "  To start by hand anyway:  FORCE=1 ./start.sh"
            echo
            echo "  Reminder: stop a foreground Dunree with Ctrl+C, never Ctrl+Z (a frozen Dunree keeps its"
            echo "  ports and database lock and blocks everything)."
        } >&2
        exit 1
    fi
fi

sudo "./$bin"
