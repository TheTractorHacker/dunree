#!/usr/bin/env bash
# Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0. This file is new in Dunree.
#
# Tests of tools/install/swap-to-dunree.sh. Nothing real is touched: every test builds the layout
# of a proxy in a temporary folder (home folder, unit folder), with stand-ins for the two program
# files (shell scripts that record what they "listen" on), for systemctl
# (testdata/systemctl-shim.sh, which really starts and stops them), ss, curl and the process list.
# Needs bash, coreutils, tar; openssl 3 for the signature tests (skipped without it).
#
# Usage: tools/install/test_swap.sh [-v] [name-filter]
#   -v            show the output of the swap script for every test
#   name-filter   run only the tests whose name contains this text
# Exit status: 0 all passed, 1 at least one failed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
SWAP="$HERE/swap-to-dunree.sh"
SHIM="$HERE/testdata/systemctl-shim.sh"
REPO="$(cd "$HERE/../.." && pwd -P)"
VERBOSE=0; FILTER=""
for a in "$@"; do case "$a" in -v) VERBOSE=1 ;; *) FILTER="$a" ;; esac; done

OLD="zoraxy"                                   # rebrand:keep
PLUGINS=("Data-Shield Blocklist" "Resource Monitor" "Zoraxy Cloudflare WAF plugin")   # rebrand:keep

BASE="$(mktemp -d "${TMPDIR:-/tmp}/swaptest.XXXXXX")"
chmod 700 "$BASE"
cleanup() {
  # stop whatever a test left running
  for f in "$BASE"/*/state/*.pid; do [ -f "$f" ] && kill -KILL "$(cat "$f")" 2>/dev/null; done
  rm -rf "$BASE"
}
trap cleanup EXIT

PASS=0; FAILED=0; CUR=""; CUR_OK=1
T=""; H=""; U=""; OUT=""; RC=0

# ---------------------------------------------------------------- stand-ins
# The program: flavour "old" or "dunree". It "listens" by writing its ports into run/<flavour>.ports.
# Files in <home>/knobs change what it does, so a test can make one check fail.
write_program() {   # $1 file, $2 flavour
  cat >"$1" <<'EOF'
#!/usr/bin/env bash
FLAVOUR=__FLAVOUR__
if [ "${1:-}" = "-version" ]; then
  if [ "$FLAVOUR" = dunree ]; then echo "Dunree - Version 1.0.0-test (based on 3.3.6)"; else echo "Version 3.3.6"; fi
  exit 0
fi
home="$(cd "$(dirname "$0")" && pwd -P)"
knob() { [ -e "$home/knobs/$1" ]; }
mkdir -p "$home/run"
echo "$FLAVOUR started with: $*" >>"$home/run/starts.log"
ports="443 80"
while [ $# -gt 0 ]; do
  case "$1" in
    -port=*|-fleet_port=*) ports="$ports ${1##*:}" ;;
    -port|-fleet_port) ports="$ports ${2##*:}"; shift ;;
  esac
  shift
done
if [ "$FLAVOUR" = old ]; then
  knob old-dead-after-swap && knob swap-seen && exit 1
  knob old-cannot-read-new-data && [ -e "$home/conf/dunree_install.json" ] && exit 1
  n_plugins=3
else
  : >"$home/knobs/swap-seen"
  knob crash && exit 1
  knob no-marker || echo '{"product":"dunree"}' >"$home/conf/dunree_install.json"
  knob lose-rule && rm -f "$home/conf/proxy/b.example.com.config"
  knob no-proxy-port && ports="${ports/443 /}"
  n_plugins=3; knob plugin-missing && n_plugins=2
fi
: >"$home/run/$FLAVOUR.plugins"
i=0
while IFS= read -r p; do
  i=$((i + 1)); [ "$i" -le "$n_plugins" ] || break
  echo "$p/$p" >>"$home/run/$FLAVOUR.plugins"
done <"$home/plugins.names"
echo "$ports" | tr ' ' '\n' >"$home/run/$FLAVOUR.ports"
echo $$ >"$home/run/$FLAVOUR.pid"
trap 'rm -f "$home/run/$FLAVOUR.ports" "$home/run/$FLAVOUR.pid" "$home/run/$FLAVOUR.plugins"; exit 0' TERM INT
if knob dies-soon && [ "$FLAVOUR" = dunree ]; then sleep 0.8; rm -f "$home/run/$FLAVOUR."*; exit 1; fi
while :; do sleep 0.2; done
EOF
  sed -i "s/__FLAVOUR__/$2/" "$1"
  chmod 755 "$1"
}

write_hooks() {
  # ss: one LISTEN line per port of every stand-in program that is alive
  cat >"$T/bin/ss" <<EOF
#!/usr/bin/env bash
for f in "$H"/run/*.pid; do
  [ -f "\$f" ] || continue
  pid="\$(cat "\$f")"; kill -0 "\$pid" 2>/dev/null || continue
  while read -r p; do [ -n "\$p" ] && echo "LISTEN 0 4096 *:\$p *:* users:((\"x\",pid=\$pid,fd=3))"; done <"\${f%.pid}.ports"
done
exit 0
EOF
  # curl: answers 200 when the port of the URL is "listened" on, else 000 like the real one
  cat >"$T/bin/curl" <<EOF
#!/usr/bin/env bash
url="\${!#}"; port="\$(printf '%s' "\$url" | sed -E 's#^[a-z]+://[^/:]+:([0-9]+)/.*#\1#')"
echo "\$*" >>"$T/curl.log"
flavour=""
for f in "$H"/run/*.pid; do
  [ -f "\$f" ] || continue
  kill -0 "\$(cat "\$f")" 2>/dev/null || continue
  grep -qx "\$port" "\${f%.pid}.ports" && flavour="\$(basename "\${f%.pid}")"
done
code=200
[ -n "\$flavour" ] || code=000
if [ "\$flavour" = dunree ]; then
  case "\$url" in
    *example.com*) [ -e "$H/knobs/host-down" ] && code=000; [ -e "$H/knobs/host-other-code" ] && code=502 ;;
    *) [ -e "$H/knobs/no-ui" ] && code=000 ;;
  esac
fi
case "\$url" in http://*) [ "\$port" = 443 ] && code=000 ;; esac
printf '%s' "\$code"
[ "\$code" != 000 ] || exit 7
EOF
  cat >"$T/bin/plugin-ps" <<EOF
#!/usr/bin/env bash
for f in "$H"/run/*.pid; do
  [ -f "\$f" ] || continue
  kill -0 "\$(cat "\$f")" 2>/dev/null && cat "\${f%.pid}.plugins"
done
exit 0
EOF
  chmod 755 "$T/bin/ss" "$T/bin/curl" "$T/bin/plugin-ps"
}

# ---------------------------------------------------------------- one proxy in a folder
setup() {
  T="$(mktemp -d "$BASE/t.XXXXXX")"; H="$T/home"; U="$T/etc/systemd/system"
  mkdir -p "$H/conf/proxy" "$H/conf/certs" "$H/backups" "$H/knobs" "$U" "$T/bin" "$T/stage" "$T/state"
  write_program "$H/$OLD" old
  write_program "$T/stage/dunree_linux_amd64" dunree
  printf '%s\n' "${PLUGINS[@]}" >"$H/plugins.names"
  for p in "${PLUGINS[@]}"; do mkdir -p "$H/plugins/$p"; echo "program" >"$H/plugins/$p/$p"; done
  for h in a b c; do
    dis=false; [ "$h" = a ] && dis=true
    printf '{\n "ProxyType": 1,\n "RootOrMatchingDomain": "%s.example.com",\n "ActiveOrigins": [\n  {\n   "Disabled": true\n  }\n ],\n "Disabled": %s\n}\n' "$h" "$dis" >"$H/conf/proxy/$h.example.com.config"
  done
  printf '{\n "ProxyType": 0,\n "RootOrMatchingDomain": "/",\n "Disabled": false\n}\n' >"$H/conf/proxy/root.config"
  echo "336" >"$H/conf/version"; echo "database" >"$H/sys.db"; echo "uuid" >"$H/sys.uuid"
  printf '#!/bin/bash\n# starts the proxy\nexec %s -port=:3000 -webui_tls auto -fleet_port :8010\n' "$H/$OLD" >"$H/start.sh"
  chmod 755 "$H/start.sh"
  cat >"$U/$OLD.service" <<EOF
[Unit]
Description=Reverse Proxy Server
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$H/
ExecStart=$H/start.sh
StandardOutput=syslog
SyslogIdentifier=$OLD

[Install]
WantedBy=multi-user.target
EOF
  write_hooks
  sc enable "$OLD.service"; sc start "$OLD.service"
  wait_file "$H/run/old.pid"
  cp "$H/start.sh" "$T/start.sh.orig"
}
sc() { SHIM_UNITS="$U" SHIM_STATE="$T/state" "$SHIM" "$@"; }
wait_file() { local n=0; while [ ! -e "$1" ] && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done; }
knob() { : >"$H/knobs/$1"; }

# swap ARGS...: runs the script on the folder of the current test; output in $OUT, status in $RC
swap() {
  OUT="$(SWAP_TEST_MODE=1 SYSTEMCTL="$SHIM" SHIM_UNITS="$U" SHIM_STATE="$T/state" SWAP_SS="$T/bin/ss" SWAP_CURL="$T/bin/curl" \
    SWAP_PLUGIN_PS="$T/bin/plugin-ps" SWAP_SETTLE=1 bash "$SWAP" --dir "$H" --systemd-dir "$U" "$@" 2>&1 <"${STDIN:-/dev/null}")"
  RC=$?
  [ "$VERBOSE" -eq 0 ] || printf '%s\n' "----- $CUR: swap $* (status $RC)" "$OUT" "-----"
}
std() { swap --binary "$T/stage/dunree_linux_amd64" --timeout 4 "$@"; }

# ---------------------------------------------------------------- assertions
bad() { CUR_OK=0; printf '    not ok: %s\n' "$*"; }
want_rc() { [ "$RC" -eq "$1" ] || { bad "exit status $RC, expected $1"; printf '%s\n' "$OUT" | sed 's/^/      | /' | tail -n 25; }; }
want_out() { printf '%s\n' "$OUT" | grep -Eq -- "$1" || bad "output has no line matching: $1"; }
want_no_out() { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then bad "output has a line matching: $1"; fi; }
want() { local msg="$1"; shift; "$@" >/dev/null 2>&1 || bad "$msg"; }
want_not() { local msg="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$msg"; fi; }
active() { [ "$(sc is-active "$1")" = active ]; }
enabled() { sc is-enabled "$1" >/dev/null; }
tree_sum() { (cd "$T" && find home etc -type f ! -path 'home/run/*' ! -path 'home/backups/.swap-to-dunree.lock' -print0 | sort -z | xargs -0 sha256sum | sha256sum); }
# the proxy is exactly as before the swap and the old service runs
want_old_state() {
  want "old unit is not active" active "$OLD.service"
  want "old unit is not enabled" enabled "$OLD.service"
  want_not "new unit is active" active dunree.service
  want_not "dunree.service still exists" test -e "$U/dunree.service"
  want "start.sh is not the original" cmp -s "$H/start.sh" "$T/start.sh.orig"
  want_not "start.sh.pre-dunree was left behind" test -e "$H/start.sh.pre-dunree"
  want "the old program file is gone" test -x "$H/$OLD"
  want "the old unit file is gone" test -f "$U/$OLD.service"
}
want_new_state() {
  want "new unit is not active" active dunree.service
  want "new unit is not enabled" enabled dunree.service
  want_not "old unit is active" active "$OLD.service"
  want_not "old unit is enabled" enabled "$OLD.service"
  want "the old unit file was removed" test -f "$U/$OLD.service"
  want "the old program file was removed" test -x "$H/$OLD"
  want "start.sh.pre-dunree is not the original start.sh" cmp -s "$H/start.sh.pre-dunree" "$T/start.sh.orig"
  want "start.sh does not start dunree with all flags" grep -qx "exec $H/dunree -port=:3000 -webui_tls auto -fleet_port :8010" "$H/start.sh"
  want "dunree was not started with the flags" grep -q "^dunree started with: -port=:3000 -webui_tls auto -fleet_port :8010$" "$H/run/starts.log"
}

run_test() {
  local name="$1"
  case "$name" in *"$FILTER"*) ;; *) return 0 ;; esac
  CUR="$name"; CUR_OK=1; STDIN=""
  setup
  "$name"
  for f in "$T"/state/*.pid; do [ -f "$f" ] && kill -KILL "$(cat "$f")" 2>/dev/null; done
  if [ "$CUR_OK" -eq 1 ]; then PASS=$((PASS + 1)); echo "ok      $name"; else FAILED=$((FAILED + 1)); echo "FAILED  $name"; fi
  rm -rf "$T"
}

# ---------------------------------------------------------------- the tests
t_dry_run_changes_nothing() {
  local before; before="$(tree_sum)"
  std --role dev --dry-run
  want_rc 0
  want "the dry run changed a file" test "$before" = "$(tree_sum)"
  want "the old unit was stopped" active "$OLD.service"
  want_out "exec $H/dunree -port=:3000 -webui_tls auto -fleet_port :8010"
  want_out "SyslogIdentifier=dunree"
  want_out "^WARN  the new program file is NOT verified"
  want_out "nothing was changed"
  want_not "a backup folder was made" ls -d "$H"/backups/pre-dunree-2*
}

t_swap_ok() {
  local sum old_sum; sum="$(sha256sum "$T/stage/dunree_linux_amd64" | cut -d' ' -f1)"; old_sum="$(sha256sum "$H/$OLD" | cut -d' ' -f1)"
  std --role dev --sha256 "$sum"
  want_rc 0
  want_new_state
  want_out "^RESULT: swapped"
  want_out "^OK    SHA-256 of dunree_linux_amd64 is the one given with --sha256"
  want_out "^OK    all 3 plugins run again"
  want_out "^OK    conf/dunree_install.json written"
  want_out "^OK    proxy rules in conf/proxy: 4, as before"
  want_out "^OK    the ports from before listen again: 80 443 3000 8010"
  want_out "^OK    proxied host answers: https://b.example.com:443/ \(200\)"
  want_no_out "^FAIL"
  want_no_out "a.example.com"          # a disabled rule is never the sample
  want "the old program file changed" test "$old_sum" = "$(sha256sum "$H/$OLD" | cut -d' ' -f1)"
  want "dunree is not mode 755" test "$(stat -c %a "$H/dunree")" = 755
  want "dunree is not the staged file" cmp -s "$H/dunree" "$T/stage/dunree_linux_amd64"
  # every line says what it is
  if printf '%s\n' "$OUT" | grep -Ev '^(OK    |WARN  |FAIL  |== |RESULT: |        |swap-to-dunree\.sh on |$)' | grep -q .; then bad "a line of the output has no OK/WARN/FAIL prefix"; fi
  # the unit
  want "Description" grep -qx "Description=Dunree reverse proxy and web gateway" "$U/dunree.service"
  want "SyslogIdentifier" grep -qx "SyslogIdentifier=dunree" "$U/dunree.service"
  want "Conflicts" grep -qx "Conflicts=$OLD.service" "$U/dunree.service"
  want "User line changed" grep -q "^User=root" "$U/dunree.service"
  want "WorkingDirectory changed" grep -q "^WorkingDirectory=$H/" "$U/dunree.service"
  want "ExecStart changed" grep -q "^ExecStart=$H/start.sh" "$U/dunree.service"
  want_not "old identifier left in the new unit" grep -q "^SyslogIdentifier=$OLD" "$U/dunree.service"
  # the backup
  local bk; bk="$(ls -d "$H"/backups/pre-dunree-2* | head -n 1)"
  want "backup folder is not private" test "$(stat -c %a "$bk")" = 700
  want "README missing" grep -q -- "--rollback" "$bk/README.txt"
  want "old unit not in the backup" cmp -s "$bk/$OLD.service" "$U/$OLD.service"
  want "plugins.list incomplete" grep -q "Resource Monitor/Resource Monitor" "$bk/plugins.list"
  want "program.tgz has no old program" sh -c "tar -tzf '$bk/program.tgz' | grep -qx '$OLD'"
  want "program.tgz has no start.sh" sh -c "tar -tzf '$bk/program.tgz' | grep -qx 'start.sh'"
  for f in conf/proxy/b.example.com.config conf/version sys.db sys.uuid "plugins/Resource Monitor/Resource Monitor"; do
    want "data.tgz has no $f" sh -c "tar -tzf '$bk/data.tgz' | grep -qxF '$f'"
  done
  want_not "the marker of Dunree is in the backup of the data" sh -c "tar -tzf '$bk/data.tgz' | grep -q dunree_install.json"
  want "the latest pointer is wrong" test "$(cat "$H/backups/pre-dunree-latest")" = "$(basename "$bk")"
  # the order: the old unit was stopped before the new one was started
  want "order of the systemctl calls" awk -v a="stop $OLD.service" -v b="start dunree.service" '$0 == a { s = NR } $0 == b { t = NR } END { exit !(s && t && s < t) }' "$T/state/calls.log"
}

t_second_run_says_already_swapped() {
  std --role dev; want_rc 0
  local before; before="$(tree_sum)"
  std --role dev
  want_rc 0
  want_out "^OK    already swapped"
  want_out "^OK    dunree.service is active"
  want "the second run changed a file" test "$before" = "$(tree_sum)"
  want "a second backup folder was made" test "$(ls -d "$H"/backups/pre-dunree-2* | wc -l)" -eq 1
  want_new_state
  # stopped by hand: the second run says so and does not start anything
  sc stop dunree.service
  std --role dev
  want_rc 1
  want_out "^WARN  dunree.service is inactive, not active"
}

t_rollback_by_hand_and_swap_again() {
  std --role dev; want_rc 0
  swap --rollback
  want_rc 0
  want_old_state
  want_out "^RESULT: rolled back"
  want_out "^OK    old service healthy again"
  want "dunree was removed by a roll back by hand" test -x "$H/dunree"
  want "the marker was removed (data must stay as it is)" test -f "$H/conf/dunree_install.json"
  want "the unit was not kept in the backup folder" sh -c "ls '$H'/backups/pre-dunree-2*/rolled-back-*/dunree.service"
  swap --rollback
  want_rc 0
  want_out "^OK    nothing to roll back"
  std --role dev
  want_rc 0
  want_new_state
  want_out "conf/dunree_install.json is there \(from an earlier Dunree start\)"
  want_out "^WARN  .*dunree existed already"
}

t_rollback_with_restore_data() {
  std --role dev; want_rc 0
  echo changed >"$H/sys.db"
  swap --rollback --restore-data
  want_rc 0
  want_old_state
  want "sys.db was not restored" grep -qx database "$H/sys.db"
  want_not "the marker is still in conf" test -e "$H/conf/dunree_install.json"
  want "what was there was not kept" sh -c "grep -qx changed '$H'/backups/pre-dunree-2*/after-dunree-*/sys.db"
  want "a plugin is missing after the restore" test -f "$H/plugins/Resource Monitor/Resource Monitor"
}

# one failing check -> automatic roll back, status 1, old service healthy, nothing of the swap left
fails_and_goes_back() {   # $1 knob, $2 expected FAIL line
  knob "$1"
  std --role dev
  want_rc 1
  want_out "$2"
  want_out "^FAIL  not all checks passed within 4 s"
  want_out "^OK    old service healthy again"
  want_out "^RESULT: NOT swapped. $OLD.service runs the old program again"
  want_old_state
  want_not "dunree was left behind" test -e "$H/dunree"
  want "the backup is gone" sh -c "ls '$H'/backups/pre-dunree-2*/data.tgz"
}
t_fail_program_exits()        { fails_and_goes_back crash "^FAIL  dunree.service is failed"; }
t_fail_no_marker()            { fails_and_goes_back no-marker "^FAIL  conf/dunree_install.json was not written"; }
t_fail_admin_page()           { fails_and_goes_back no-ui "^FAIL  the admin page on 127.0.0.1:3000 does not answer"; }
t_fail_plugin_missing()       { fails_and_goes_back plugin-missing "^FAIL  plugins not running: .* Cloudflare WAF plugin \(2 of 3 run\)"; }
t_fail_proxy_port()           { fails_and_goes_back no-proxy-port "^FAIL  ports that listened before and do not now: 443"; }
t_fail_proxied_host()         { fails_and_goes_back host-down "^FAIL  proxied host https://b.example.com:443/ does not answer"; }
t_fail_dies_while_checked()   { fails_and_goes_back dies-soon "^FAIL  dunree.service is failed"; }
t_fail_rule_lost_restores_data() {
  fails_and_goes_back lose-rule "^FAIL  proxy rules in conf/proxy: 3, before the swap 4"
  want_out "^WARN  the number of rules changed while Dunree ran"
  want "the lost rule did not come back" test -f "$H/conf/proxy/b.example.com.config"
  want_not "the marker is still in conf" test -e "$H/conf/dunree_install.json"
}

t_old_cannot_read_new_data_restores_data() {
  knob no-ui; knob old-cannot-read-new-data
  std --role dev
  want_rc 1
  want_out "^FAIL  old service not healthy after going back"
  want_out "^OK    old service healthy again with the data from the backup"
  want_old_state
  want_not "the marker is still in conf" test -e "$H/conf/dunree_install.json"
  want "what Dunree left was not kept" sh -c "ls '$H'/backups/pre-dunree-2*/after-dunree-*/conf/dunree_install.json"
}

t_rollback_fails_exit_3() {
  knob no-ui; knob old-dead-after-swap
  std --role dev
  want_rc 3
  want_out "^RESULT: NOT swapped, and the old service is NOT healthy"
  want_out "README.txt"
  want "start.sh was not put back" cmp -s "$H/start.sh" "$T/start.sh.orig"
  want_not "dunree.service still exists" test -e "$U/dunree.service"
}

t_other_answer_code_is_a_warning() {
  knob host-other-code
  std --role dev
  want_rc 0
  want_out "^OK    proxied host answers: https://b.example.com:443/ \(502, before the swap 200\)"
  want_out "^WARN  the proxied host answers with another code"
}

t_interrupted_goes_back() {
  knob no-ui
  SWAP_TEST_MODE=1 SYSTEMCTL="$SHIM" SHIM_UNITS="$U" SHIM_STATE="$T/state" SWAP_SS="$T/bin/ss" SWAP_CURL="$T/bin/curl" \
    SWAP_PLUGIN_PS="$T/bin/plugin-ps" SWAP_SETTLE=1 bash "$SWAP" --dir "$H" --systemd-dir "$U" --role dev \
    --binary "$T/stage/dunree_linux_amd64" --timeout 60 >"$T/out.txt" 2>&1 </dev/null &
  local pid=$! n=0
  while ! grep -q "^== 8" "$T/out.txt" 2>/dev/null && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
  sleep 1; kill -TERM "$pid"
  wait "$pid"; RC=$?; OUT="$(cat "$T/out.txt")"
  want_rc 1
  want_out "^FAIL  the swap stopped \(status 130\)"
  want_out "^OK    old service healthy again"
  want_old_state
}

t_live_needs_the_host_name() {
  local before; before="$(tree_sum)"
  echo "yes" >"$T/answer"; STDIN="$T/answer"
  std --role live
  want_rc 2
  want_out "^FAIL  not confirmed"
  want_out "NOT VERIFIED"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
  want "the old unit was stopped" active "$OLD.service"
  STDIN=""; std --role live          # no answer at all (no terminal)
  want_rc 2
  hostname >"$T/answer"; STDIN="$T/answer"
  std --role live
  want_rc 0
  want_new_state
}

t_live_refuses_unhealthy_old_service() {
  local before
  sc stop "$OLD.service"
  before="$(tree_sum)"
  hostname >"$T/answer"; STDIN="$T/answer"
  std --role live
  want_rc 2
  want_out "^FAIL  $OLD.service is inactive, not active"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
}

t_dev_with_stopped_old_service() {
  sc stop "$OLD.service"
  std --role dev
  want_rc 0
  want_out "^WARN  $OLD.service is inactive, not active \(role dev: continuing\)"
  want "new unit is not active" active dunree.service
  swap --rollback
  want_rc 0
  want_out "was not running before the swap: not started"
  want_not "the old unit was started although it did not run before" active "$OLD.service"
  want "start.sh is not the original" cmp -s "$H/start.sh" "$T/start.sh.orig"
}

t_low_disk() {
  # a df that reports 500 MB free: enough for the swap of this small folder, under the 1 GB of role live
  printf '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted on"\necho "/dev/x 9999999 1 512000 1%% /"\n' >"$T/bin/df"; chmod 755 "$T/bin/df"
  local before; before="$(tree_sum)"
  hostname >"$T/answer"; STDIN="$T/answer"
  PATH="$T/bin:$PATH" std --role live
  want_rc 2
  want_out "^FAIL  free disk space in .* is 500 MB: role live needs at least 1 GB"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
  STDIN=""
  PATH="$T/bin:$PATH" std --role dev --dry-run
  want_rc 0
  want_out "^WARN  free disk space in .* is 500 MB, under 1 GB"
  printf '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted on"\necho "/dev/x 9999999 1 1000 1%% /"\n' >"$T/bin/df"
  PATH="$T/bin:$PATH" std --role dev
  want_rc 2
  want_out "^FAIL  free disk space in .* the swap needs about"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
}

t_checksum_and_signature() {
  local before sum d="$T/stage"; before="$(tree_sum)"
  std --role dev --sha256 "$(printf '0%.0s' $(seq 64))"
  want_rc 2
  want_out "^FAIL  SHA-256 of .* not the 0000"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
  # SHA256SUMS without a signature: a warning, never silent
  sum="$(sha256sum "$d/dunree_linux_amd64" | cut -d' ' -f1)"
  printf '# dunree-release product=dunree tag=v1.0.0-test build=7 upstream=3.3.6\n%s  dunree_linux_amd64\n' "$sum" >"$d/SHA256SUMS"
  std --role dev --dry-run
  want_rc 0
  want_out "^OK    SHA-256 of dunree_linux_amd64 is the one in SHA256SUMS"
  want_out "^WARN  there is no .*SHA256SUMS.sig: SHA256SUMS is NOT signed"
  want_out "^WARN  the new program file is NOT verified by a signature"
  # a wrong entry
  printf '# dunree-release product=dunree tag=v1.0.0-test build=7 upstream=3.3.6\n%s  dunree_linux_amd64\n' "$(printf 'a%.0s' $(seq 64))" >"$d/SHA256SUMS"
  std --role dev --dry-run
  want_rc 2
  want_out "^FAIL  SHA-256 of dunree_linux_amd64 is .* SHA256SUMS says aaaa"
  # the header of another product is refused by name
  printf '# %s-release tag=v3.3.6 build=7\n%s  dunree_linux_amd64\n' "$OLD" "$sum" >"$d/SHA256SUMS"
  std --role dev --dry-run
  want_rc 2
  want_out "^FAIL  .*does not start with the header of a Dunree release"
  if ! openssl version 2>/dev/null | grep -Eq '^OpenSSL ([3-9]|[1-9][0-9])\.'; then echo "    (signature tests skipped: no openssl 3)"; return 0; fi
  # signed with a key made for this test
  printf '# dunree-release product=dunree tag=v1.0.0-test build=7 upstream=3.3.6\n%s  dunree_linux_amd64\n' "$sum" >"$d/SHA256SUMS"
  openssl genpkey -algorithm ed25519 -out "$T/key.pem" 2>/dev/null
  openssl pkey -in "$T/key.pem" -pubout -out "$T/pub.pem" 2>/dev/null
  openssl pkeyutl -sign -inkey "$T/key.pem" -rawin -in "$d/SHA256SUMS" -out "$d/SHA256SUMS.sig"
  std --role dev --dry-run --pubkey "$T/pub.pem"
  want_rc 0
  want_out "^OK    SHA256SUMS is signed by the key given with --pubkey \(ed25519\)"
  want_no_out "NOT verified"
  # the same file checked with the release key: not signed by it
  std --role dev --dry-run
  want_rc 2
  want_out "^FAIL  the signature .* does not fit SHA256SUMS and the Dunree release key"
  # one byte of SHA256SUMS changed after signing
  sed -i 's/build=7/build=8/' "$d/SHA256SUMS"
  std --role dev --dry-run --pubkey "$T/pub.pem"
  want_rc 2
  want_out "^FAIL  the signature .* does not fit"
  # a signature that is not 64 bytes
  echo short >"$d/SHA256SUMS.sig"
  std --role dev --dry-run --pubkey "$T/pub.pem"
  want_rc 2
  want_out "^FAIL  .*is not a 64 byte ed25519 signature"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
}

t_release_key_is_the_one_of_the_updater() {
  local pem="$REPO/src/mod/updater/release_pubkey.pem" b64
  [ -f "$pem" ] || { echo "    (skipped: $pem not found)"; return 0; }
  b64="$(grep -v '^-----' "$pem" | tr -d '\n\r ')"
  want "RELEASE_PUBKEY_B64 in swap-to-dunree.sh is not the key in src/mod/updater/release_pubkey.pem" grep -qxF "RELEASE_PUBKEY_B64=\"$b64\"" "$SWAP"
}

t_refusals_change_nothing() {
  local before; before="$(tree_sum)"
  swap --binary "$T/stage/dunree_linux_amd64"
  want_rc 2; want_out "^FAIL  say which machine this is"
  swap --role dev --binary "$H/$OLD"
  want_rc 2; want_out "^FAIL  --binary is the old program file"
  cp "$H/$OLD" "$T/stage/not-dunree"
  swap --role dev --binary "$T/stage/not-dunree"
  want_rc 2; want_out "^FAIL  .* -version did not answer as Dunree"
  rm -f "$T/stage/not-dunree"
  swap --role dev --binary "$T/stage/missing"
  want_rc 2; want_out "^FAIL  --binary .* is not a file"
  swap --role dev --dir "$T/nowhere" --binary "$T/stage/dunree_linux_amd64"
  want_rc 2
  std --role dev --old-unit other.service
  want_rc 2; want_out "^FAIL  no other.service"
  std --role dev --restore-data
  want_rc 2
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
  want "the old unit was stopped" active "$OLD.service"
  if [ "$(id -u)" -ne 0 ]; then
    OUT="$(bash "$SWAP" --dir "$H" --systemd-dir "$U" --role dev --binary "$T/stage/dunree_linux_amd64" 2>&1)"; RC=$?
    want_rc 2; want_out "^FAIL  run this as root"
  fi
  # another layout: flags that move the data, a unit that does not use start.sh
  echo "exec $H/$OLD -port=:3000 -conf /srv/conf" >"$H/start.sh"
  std --role dev
  want_rc 2; want_out "^FAIL  start.sh moves conf"
  cp "$T/start.sh.orig" "$H/start.sh"
  sed -i "s#^ExecStart=.*#ExecStart=$H/$OLD -port=:3000#" "$U/$OLD.service"
  std --role dev
  want_rc 2; want_out "only handles a service started through start.sh"
}

t_half_swapped_is_refused_and_rollback_cleans_up() {
  # as if a run had been killed between start.sh and the unit
  cp -p "$H/start.sh" "$H/start.sh.pre-dunree"
  sed -i "s#$H/$OLD #$H/dunree #" "$H/start.sh"
  std --role dev
  want_rc 2
  want_out "^FAIL  half swapped"
  want_out "--rollback first"
  swap --rollback
  want_rc 0
  want_out "^WARN  no record of this swap"
  want_old_state
  std --role dev
  want_rc 0
  want_new_state
}

t_no_start() {
  std --role dev --no-start
  want_rc 0
  want_out "^WARN  --no-start: dunree.service was NOT started"
  want_not "new unit is active" active dunree.service
  want "new unit is not enabled" enabled dunree.service
  want_not "old unit is active" active "$OLD.service"
  want "dunree was not installed" test -x "$H/dunree"
  swap --rollback
  want_rc 0
  want_old_state
}

t_unit_not_enabled_stays_not_enabled_and_dropins_are_copied() {
  sc disable "$OLD.service"
  mkdir "$U/$OLD.service.d"; printf '[Service]\nLimitNOFILE=65536\n' >"$U/$OLD.service.d/limits.conf"
  std --role dev
  want_rc 0
  want "new unit is not active" active dunree.service
  want_not "new unit was enabled although the old one was not" enabled dunree.service
  want "the drop-in was not copied" cmp -s "$U/dunree.service.d/limits.conf" "$U/$OLD.service.d/limits.conf"
  swap --rollback
  want_rc 0
  want_not "old unit was enabled by the roll back" enabled "$OLD.service"
  want "old unit is not active" active "$OLD.service"
  want_not "the drop-in folder of the new unit was left" test -e "$U/dunree.service.d"
}

t_port_flag_forms() {
  # -port with a space and an address; the admin page is then asked on that address
  printf '#!/bin/bash\nexec "%s" -port 127.0.0.1:3000 -fleet_port=:8010\n' "$H/$OLD" >"$H/start.sh"
  cp "$H/start.sh" "$T/start.sh.orig"
  sc stop "$OLD.service"; sc start "$OLD.service"; wait_file "$H/run/old.pid"
  swap --binary "$T/stage/dunree_linux_amd64" --timeout 4 --role dev
  want_rc 0
  want_out "^OK    admin page answers: https://127.0.0.1:3000/"
  want "start.sh was not rewritten with the quotes kept" grep -qx "exec \"$H/dunree\" -port 127.0.0.1:3000 -fleet_port=:8010" "$H/start.sh"
  want_out "listen again: 80 443 3000 8010"
}

t_script_is_clean() {
  want "bash -n" bash -n "$SWAP"
  want "bash -n (shim)" bash -n "$SHIM"
  if command -v shellcheck >/dev/null 2>&1; then
    OUT="$(shellcheck -S warning "$SWAP" "$SHIM" 2>&1)" || bad "shellcheck: $OUT"
  fi
  OUT="$(bash "$SWAP" --help)"; RC=$?
  want_rc 0; want_out "^Usage: sudo swap-to-dunree.sh --role dev\|live"; want_no_out "rebrand:keep"
  # no network: the script names no host but 127.0.0.1
  want_not "the script calls out" grep -En '(https?|ftp)://[A-Za-z]' "$SWAP"
  want_not "the script uses a download tool" grep -Enw 'wget|apt|apt-get|git' "$SWAP"
}

# ---------------------------------------------------------------- failure injection (review of 2026-11-25)
# runs the swap in the background with its output into a pipe read by cat; sets BG_PID and READER
swap_bg() {
  mkfifo "$T/out.fifo"
  cat "$T/out.fifo" >"$T/out.txt" &
  READER=$!
  SWAP_TEST_MODE=1 SYSTEMCTL="${BG_SYSTEMCTL:-$SHIM}" SHIM_UNITS="$U" SHIM_STATE="$T/state" SWAP_SS="$T/bin/ss" SWAP_CURL="$T/bin/curl" \
    SWAP_PLUGIN_PS="$T/bin/plugin-ps" SWAP_SETTLE=1 bash "$SWAP" --dir "$H" --systemd-dir "$U" --role dev \
    --binary "$T/stage/dunree_linux_amd64" "$@" >"$T/out.fifo" 2>&1 </dev/null &
  BG_PID=$!
}
wait_out() { local n=0; while ! grep -q -- "$1" "$T/out.txt" 2>/dev/null && [ "$n" -lt 150 ]; do sleep 0.1; n=$((n + 1)); done; }

t_hangup_with_dead_terminal_still_goes_back() {
  # the ssh session drops during the checks: SIGHUP, and nothing reads the output any more
  knob no-ui
  swap_bg --timeout 60
  wait_out "^== 8"
  kill -KILL "$READER" 2>/dev/null; wait "$READER" 2>/dev/null
  kill -HUP "$BG_PID"
  wait "$BG_PID"; RC=$?
  want_rc 1
  want_old_state
  want "the swap log in the backup folder does not show the roll back" sh -c "grep -q '^RESULT: NOT swapped' '$H'/backups/pre-dunree-2*/swap.log"
}

t_second_interrupt_does_not_stop_the_roll_back() {
  knob no-ui
  swap_bg --timeout 60
  wait_out "^== 8"
  sleep 0.5; kill -INT "$BG_PID"
  wait_out "^== 9"
  # an impatient owner: Ctrl+C, kill and a lost session, again and again while it rolls back
  local n=0
  while kill -0 "$BG_PID" 2>/dev/null && [ "$n" -lt 100 ]; do
    kill -INT "$BG_PID" 2>/dev/null; kill -TERM "$BG_PID" 2>/dev/null; kill -HUP "$BG_PID" 2>/dev/null
    sleep 0.1; n=$((n + 1))
  done
  wait "$BG_PID"; RC=$?; wait "$READER" 2>/dev/null; OUT="$(cat "$T/out.txt")"
  want_rc 1
  want_out "^OK    old service healthy again"
  want_old_state
}

t_restore_data_after_a_roll_back_stops_the_old_service_first() {
  std --role dev; want_rc 0
  swap --rollback; want_rc 0
  want_old_state
  local starts; starts="$(grep -c '^old started' "$H/run/starts.log")"
  : >"$T/state/calls.log"
  echo changed >"$H/sys.db"
  swap --rollback --restore-data
  want_rc 0
  want "the old service was not stopped before its data was moved" grep -qx "stop $OLD.service" "$T/state/calls.log"
  want "the old service was not started again on the restored data" test "$(grep -c '^old started' "$H/run/starts.log")" -gt "$starts"
  want "sys.db was not restored" grep -qx database "$H/sys.db"
  want_old_state
}

t_hash_mismatch_never_runs_the_file() {
  printf '#!/bin/sh\n: >"%s/ran"\necho "Dunree - Version 1"\n' "$T" >"$T/stage/evil"; chmod 755 "$T/stage/evil"
  swap --role dev --binary "$T/stage/evil" --sha256 "$(printf '0%.0s' $(seq 64))"
  want_rc 2
  want_not "a program file with the wrong SHA-256 was run" test -e "$T/ran"
  want_out "^FAIL  SHA-256 of"
}

t_disk_full_during_the_data_backup() {
  # tar fails while writing data.tgz (as with a full disk) and leaves a part of the file behind
  printf '#!/bin/sh\nfor a in "$@"; do case "$a" in *data.tgz) case "$*" in *-czf*) echo part >"$a"; echo "tar: write error: No space left on device" >&2; exit 2 ;; esac ;; esac; done\nexec %s "$@"\n' "$(command -v tar)" >"$T/bin/tar"
  chmod 755 "$T/bin/tar"
  PATH="$T/bin:$PATH" std --role dev
  want_rc 1
  want_out "^OK    old service healthy again"
  want_old_state
  want_not "a part of data.tgz was left (it fills the disk)" sh -c "ls '$H'/backups/pre-dunree-2*/data.tgz"
  want_not "dunree was installed" test -e "$H/dunree"
}

# a systemctl that fails one call, given as "verb unit"
failing_systemctl() {
  printf '#!/bin/sh\n[ "$1 $2" = "%s" ] && { echo "Failed: injected" >&2; exit 1; }\nexec %s "$@"\n' "$1" "$SHIM" >"$T/bin/systemctl"
  chmod 755 "$T/bin/systemctl"
}
swap_sc() { OUT="$(SWAP_TEST_MODE=1 SYSTEMCTL="$T/bin/systemctl" SHIM_UNITS="$U" SHIM_STATE="$T/state" SWAP_SS="$T/bin/ss" SWAP_CURL="$T/bin/curl" \
    SWAP_PLUGIN_PS="$T/bin/plugin-ps" SWAP_SETTLE=1 bash "$SWAP" --dir "$H" --systemd-dir "$U" --binary "$T/stage/dunree_linux_amd64" --timeout 4 "$@" 2>&1 </dev/null)"; RC=$?
  [ "$VERBOSE" -eq 0 ] || printf '%s\n' "----- $CUR: swap $* (status $RC)" "$OUT" "-----"; }

t_unit_does_not_start() {
  failing_systemctl "start dunree.service"
  swap_sc --role dev
  want_rc 1
  want_out "^FAIL  systemctl start dunree.service failed"
  want_out "^OK    old service healthy again"
  want_old_state
}

t_enable_of_the_new_unit_fails() {
  failing_systemctl "enable dunree.service"
  swap_sc --role dev
  want_rc 1
  want_out "^FAIL  systemctl enable dunree.service failed"
  want_out "^OK    old service healthy again"
  want_old_state
}

t_start_sh_with_other_lines_and_flags() {
  cat >"$H/start.sh" <<EOF
#!/bin/bash
# $H/$OLD is started below; the backups are in $H/$OLD-conf-backup-*.tgz
ulimit -n 65535
export GOMAXPROCS=4
cd $H
exec $H/$OLD -port=:3000 -webui_tls auto -noauth=false -log=true -fleet_port :8010 >>$H/$OLD.log 2>&1
EOF
  cp "$H/start.sh" "$T/start.sh.orig"
  sc stop "$OLD.service"; sc start "$OLD.service"; wait_file "$H/run/old.pid"
  std --role dev
  want_rc 0
  want "a line other than the program line changed" diff <(sed "s#^exec $H/$OLD #exec $H/dunree #" "$T/start.sh.orig") "$H/start.sh"
  want "the comment was changed" grep -qF "# $H/$OLD is started below; the backups are in $H/$OLD-conf-backup-*.tgz" "$H/start.sh"
  swap --rollback
  want_rc 0
  want_old_state
}

t_alias_of_the_old_unit_is_left_out() {
  printf 'Alias=proxy.service\n' >>"$U/$OLD.service"
  std --role dev
  want_rc 0
  want_new_state
  want_not "the alias of the old unit is in the new unit" grep -q '^Alias=' "$U/dunree.service"
}

t_unreadable_folder_does_not_break_the_disk_check() {
  # a du that fails (a folder it cannot read, as for a dry run without root) inside $(...)
  printf '#!/bin/sh\necho "4\t$2"\nexit 1\n' >"$T/bin/du"; chmod 755 "$T/bin/du"
  PATH="$T/bin:$PATH" std --role dev --dry-run
  want_rc 0
  want_no_out "unbound variable"
  want_no_out "^FAIL"
  want_out "^OK    free disk space"
}

t_dunree_path_is_a_folder() {
  mkdir "$H/dunree"
  local before; before="$(tree_sum)"
  std --role dev
  want_rc 2
  want_out "^FAIL  .*dunree is a folder"
  want "a refused run changed a file" test "$before" = "$(tree_sum)"
  want "the old unit was stopped" active "$OLD.service"
}

TESTS="$(declare -F | awk '{ print $3 }' | grep '^t_')"
for t in $TESTS; do run_test "$t"; done
echo ""
echo "passed: $PASS, failed: $FAILED"
[ "$FAILED" -eq 0 ] && [ "$PASS" -gt 0 ]
