package vip

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// The installer script (docs/cluster/vip-simple-setup.md section 8).
//
// Dunree only GENERATES this text. The user pastes it into a terminal on the
// server it is made for; Dunree never runs it. Values enter the script only
// through the variable block, each one checked against its own whitelist and
// written inside single quotes; the keepalived.conf travels in a quoted
// heredoc. The script itself is fixed text.

const (
	scriptDelimInner = "DUNREE_KEEPALIVED_CONF_END"
	scriptDelimOuter = "DUNREE_SETUP_END"
)

// Whitelists of the variable block. None of them admits a quote, backslash,
// dollar sign, backtick, newline or any control character. Spaces are
// admitted only where the label rule (reLabel) already admits them: inside
// single quotes and only ever used as "$VAR" or as a printf argument.
var (
	reScriptLabel = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,32}$`)
	reScriptV4    = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)
	reScriptV6    = regexp.MustCompile(`^[0-9a-f:]{2,39}$`)
	reScriptIface = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	reScriptInt   = regexp.MustCompile(`^[0-9]{1,3}$`)
	reScriptProbe = regexp.MustCompile(`^https?://[A-Za-z0-9.:\[\]-]+/\.dunree/health$`)
	reScriptFP    = regexp.MustCompile(`^[0-9a-f]{8}$`)
	reScriptRoot  = regexp.MustCompile(`^(/[A-Za-z0-9._+-]+)*$`)
)

// ScriptOutput is what Script returns. The page shows Script (one block to
// paste) and offers Inner as a download.
type ScriptOutput struct {
	Label       string   `json:"label"`
	Address     string   `json:"address"`
	Role        string   `json:"role"` // "Main server" or "Backup server"
	Script      string   `json:"script"`
	Inner       string   `json:"inner"` // the file for "can't paste": starts with #!/bin/sh
	Conf        string   `json:"keepalivedConf"`
	Commands    Commands `json:"commands"`
	Fingerprint string   `json:"fingerprint"`
	HealthURL   string   `json:"healthUrl"`
	// Guessed names the values Dunree had to guess because the other server
	// did not tell it (the script re-checks them on that server).
	Guessed  []string `json:"guessed,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Commands are the same texts as the classic output, for "Show details".
type Commands struct {
	Install  string `json:"install"`
	Verify   string `json:"verify"`
	Sysctl   string `json:"sysctl,omitempty"`
	Firewall string `json:"firewall,omitempty"`
}

// Script builds the installer for one member (member < 0 means this node).
// It is a pure function of its inputs and is built on Generate.
func Script(s *Shared, l *Local, env *Env, member int, pf *PeerFacts) (*ScriptOutput, error) {
	return script(s, l, env, member, pf, "")
}

// script is Script with the test-only root prefix. Root is "" in production
// and is not reachable from the API: it lets the tests run the real script
// against a temporary directory tree.
func script(s *Shared, l *Local, env *Env, member int, pf *PeerFacts, root string) (*ScriptOutput, error) {
	out, d, err := generate(s, l, env, member, pf)
	if err != nil {
		return nil, err
	}
	main := true
	for _, m := range s.Members {
		if m.Address != d.Source && m.Priority > d.Priority {
			main = false
		}
	}
	role := "Backup server"
	if main {
		role = "Main server"
	}
	vipAddr := netip.MustParseAddr(s.VIP)
	vars := []scriptVar{
		{"D_ROOT", root, reScriptRoot},
		{"D_LABEL", d.Label, reScriptLabel},
		{"D_ROLE", role, regexp.MustCompile(`^(Main|Backup) server$`)},
		{"D_ADDR", d.Source, addrRe(d.V6)},
		{"D_IFACE", d.Iface, reScriptIface},
		{"D_VIP", vipAddr.String(), addrRe(d.V6)},
		{"D_PREFIX", strconv.Itoa(s.Prefix), reScriptInt},
		{"D_PEERS", strings.Join(d.Peers, " "), peersRe(d.V6)},
		{"D_MCAST", b01(d.Multicast), regexp.MustCompile(`^[01]$`)},
		{"D_PROBE", out.HealthURL, reScriptProbe},
		{"D_PROBE_K", probeK(out.HealthURL), regexp.MustCompile(`^(-k)?$`)},
		{"D_MAXTIME", strconv.Itoa(CurlMaxTime(s.Health.Timeout)), reScriptInt},
		{"D_WAIT", strconv.Itoa(3*s.AdvertInt + 3), reScriptInt},
		{"D_FP", d.Fingerprint, reScriptFP},
		{"D_FROM", fromText(d), regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,32} \([0-9a-f:.]+\)$`)},
		{"D_NEED_SYSCTL", b01(out.Sysctl != ""), regexp.MustCompile(`^[01]$`)},
		{"D_V6", b01(d.V6), regexp.MustCompile(`^[01]$`)},
		{"D_VERSION", d.Version, regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,40}$`)},
	}
	block, err := renderVars(vars)
	if err != nil {
		return nil, err
	}
	inner := strings.Replace(scriptBody, "@@VARS@@", block, 1)
	// The config goes in last, so nothing in it can be taken for a marker.
	if strings.Contains(out.KeepalivedConf, "@@") {
		return nil, errors.New("render guard: marker in config")
	}
	inner = strings.Replace(inner, "@@CONF@@", out.KeepalivedConf, 1)
	if strings.Count(inner, "\n"+scriptDelimInner+"\n") != 1 {
		return nil, errors.New("render guard: heredoc delimiter in output")
	}
	if strings.Contains(inner, "\n"+scriptDelimOuter+"\n") || strings.HasPrefix(inner, scriptDelimOuter+"\n") {
		return nil, errors.New("render guard: heredoc delimiter in output")
	}
	title := fmt.Sprintf("%s (%s) - %s", d.Label, d.Source, role) // every part was whitelisted above
	wrapped := "# Dunree floating IP installer for " + title + "\n" +
		"# Paste all of this into a terminal ON " + d.Label + ". It asks for your sudo password if needed.\n" +
		"if [ \"$(id -u)\" = 0 ]; then sh -s\n" +
		"elif command -v sudo >/dev/null 2>&1; then sudo sh -s\n" +
		"else echo \"Dunree: please log in as root (type: su -) and paste this again.\"; cat >/dev/null\n" +
		"fi <<'" + scriptDelimOuter + "'\n" + inner + scriptDelimOuter + "\n"
	so := &ScriptOutput{
		Label: d.Label, Address: d.Source, Role: role,
		Script: wrapped, Inner: "#!/bin/sh\n" + inner, Conf: out.KeepalivedConf,
		Fingerprint: out.Fingerprint, HealthURL: out.HealthURL, Warnings: out.Warnings,
		Commands: Commands{Install: out.InstallCommands, Verify: out.VerifyCommands, Sysctl: out.Sysctl, Firewall: out.FirewallNote},
	}
	if member >= 0 {
		if (pf == nil || pf.Iface == "") && s.Members[member].InterfaceHint == "" {
			so.Guessed = append(so.Guessed, "interface")
		}
		if pf == nil || pf.ProbeBase == "" {
			so.Guessed = append(so.Guessed, "healthUrl")
		}
	}
	return so, nil
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func probeK(u string) string {
	if strings.HasPrefix(u, "https://") {
		return "-k"
	}
	return ""
}

func fromText(d *tmplData) string { return d.Label + " (" + d.Source + ")" }

func addrRe(v6 bool) *regexp.Regexp {
	if v6 {
		return reScriptV6
	}
	return reScriptV4
}

func peersRe(v6 bool) *regexp.Regexp {
	if v6 {
		return regexp.MustCompile(`^[0-9a-f:]{2,39}( [0-9a-f:]{2,39})*$`)
	}
	return regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}( [0-9]{1,3}(\.[0-9]{1,3}){3})*$`)
}

type scriptVar struct {
	name, value string
	re          *regexp.Regexp
}

// renderVars checks every value against its whitelist right before it is
// written. A mismatch is an internal error, never a script.
func renderVars(vars []scriptVar) (string, error) {
	var b strings.Builder
	for _, v := range vars {
		if !v.re.MatchString(v.value) || strings.ContainsAny(v.value, "'\\$`\"\n\r\x00") {
			return "", fmt.Errorf("render guard: %s value %q", v.name, v.value)
		}
		b.WriteString(v.name + "='" + v.value + "'\n")
	}
	return b.String(), nil
}

// scriptBody is the fixed inner script. Everything runs inside one function
// that is called with stdin from /dev/null, so no command can swallow the
// rest of a script that is being read from a pipe or a heredoc.
const scriptBody = `set -eu
umask 077
LC_ALL=C
export LC_ALL

# ---- values generated by Dunree (checked one by one before they were written) ----
@@VARS@@# -------------------------------------------------------------------------------

if [ -z "$D_ROOT" ]; then PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"; export PATH; fi

dunree_main() {
CONF="$D_ROOT/etc/keepalived/keepalived.conf"
MARK="$D_ROOT/etc/keepalived/dunree-installed"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CHANGED=0
TMPD=''
NOTE='Your previous keepalived setup was not changed.'

say()  { printf 'Dunree: %s\n' "$1"; }
fail() {
  printf '\nDunree: PROBLEM: %s\n' "$1"
  if [ -n "${2:-}" ]; then printf 'Dunree: What to do: %s\n' "$2"; fi
  if [ -n "$NOTE" ]; then printf 'Dunree: %s\n' "$NOTE"; fi
  exit 1
}
hide() { sed 's/auth_pass.*/auth_pass (hidden)/'; }
addr_on() {
  if [ -n "${1:-}" ]; then ip -o addr show dev "$1" 2>/dev/null; else ip -o addr show 2>/dev/null; fi | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$D_ADDR"
}

# 1. Root
[ "$(id -u)" -eq 0 ] || fail "This must run as root." "Paste it again. It uses sudo by itself, or log in as root with: su -"

# 2. Right server
if ! addr_on ""; then
  fail "This is not $D_LABEL ($D_ADDR)." "Open a terminal on $D_LABEL and paste it there. The script for each server is on its own card."
fi

# 3. Right network card
if ! ip -o link show dev "$D_IFACE" >/dev/null 2>&1 || ! addr_on "$D_IFACE"; then
  FOUND=$(ip -o addr show 2>/dev/null | awk -v a="$D_ADDR" '{split($4, x, "/"); if (x[1] == a) print $2}' | head -n 1 || true)
  if [ -n "$FOUND" ]; then
    printf 'Dunree: The network card of %s is called %s here.\n' "$D_LABEL" "$FOUND"
  fi
  fail "The network card of $D_LABEL is not called $D_IFACE." "Open the Dunree page on $D_LABEL and copy its script there, or set the network card name for $D_LABEL under Show details."
fi

# 4. Packages, only if missing
if ! command -v keepalived >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  OSIDS=$(grep -E '^(ID|ID_LIKE)=' "$D_ROOT/etc/os-release" 2>/dev/null | tr -d '"' | cut -d= -f2 | tr '\n' ' ' || true)
  case " $OSIDS " in
    *" debian "*|*" ubuntu "*)
      say "Installing keepalived and curl (apt)..."
      DEBIAN_FRONTEND=noninteractive apt-get update -qq || fail "apt-get update failed." "Check this server's internet access and package sources, then paste the script again."
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq keepalived curl || fail "apt could not install keepalived and curl." "Install them yourself, then paste the script again."
      ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*)
      say "Installing keepalived and curl (dnf)..."
      dnf install -y -q keepalived curl || fail "dnf could not install keepalived and curl." "Install them yourself, then paste the script again."
      ;;
    *)
      fail "This script supports Debian, Ubuntu, RHEL, Rocky, Alma and Fedora." "Install keepalived and curl yourself, then paste the script again."
      ;;
  esac
  command -v keepalived >/dev/null 2>&1 || fail "keepalived is still missing after the install." "Install it yourself, then paste the script again."
fi
if ! id keepalived_script >/dev/null 2>&1; then
  NOLOGIN=$(command -v nologin || echo /bin/false)
  useradd -r -M -s "$NOLOGIN" keepalived_script || fail "Could not create the keepalived_script user." "Create it with: useradd -r -M -s /usr/sbin/nologin keepalived_script"
fi

# 5. The health check, run the way keepalived will run it
# shellcheck disable=SC2086
if ! runuser -u keepalived_script -- /usr/bin/curl -fsS --max-time "$D_MAXTIME" $D_PROBE_K -o /dev/null "$D_PROBE" >/dev/null 2>&1; then
  fail "Dunree on $D_LABEL does not answer its health check at $D_PROBE." "Check that Dunree is running on $D_LABEL, then see Health check on the Dunree page."
fi

# 6. Write the config to a temporary file and test it
mkdir -p "$D_ROOT/etc/keepalived"
chmod 755 "$D_ROOT/etc/keepalived"
TMPD=$(mktemp -d "$D_ROOT/etc/keepalived/.dunree.XXXXXX")
trap 'rm -rf "$TMPD"' EXIT INT TERM
cat > "$TMPD/keepalived.conf" <<'DUNREE_KEEPALIVED_CONF_END'
@@CONF@@DUNREE_KEEPALIVED_CONF_END
chown root:root "$TMPD/keepalived.conf"
chmod 600 "$TMPD/keepalived.conf"
if ! keepalived -t -f "$TMPD/keepalived.conf" >"$TMPD/test.log" 2>&1; then
  hide < "$TMPD/test.log" | tail -n 15
  fail "keepalived did not accept the generated settings." "Copy the lines above into a Dunree issue."
fi

# 7. ip_nonlocal_bind, only when a Dunree listener binds the floating IP itself
if [ "$D_NEED_SYSCTL" = 1 ]; then
  SYSF="$D_ROOT/etc/sysctl.d/60-dunree-vip.conf"
  if [ "$D_V6" = 1 ]; then SYSL='net.ipv6.ip_nonlocal_bind = 1'; else SYSL='net.ipv4.ip_nonlocal_bind = 1'; fi
  printf '%s\n' "$SYSL" > "$TMPD/sysctl.new"
  if ! cmp -s "$TMPD/sysctl.new" "$SYSF" 2>/dev/null; then
    mkdir -p "$D_ROOT/etc/sysctl.d"
    cat "$TMPD/sysctl.new" > "$SYSF"
    chmod 644 "$SYSF"
    sysctl -p "$SYSF" >/dev/null 2>&1 || say "Could not apply $SYSF now. It applies after the next reboot."
  fi
fi

# 8. Host firewall, only if active (ufw or firewalld)
ufw_update() {
  UF="$1"
  [ -f "$UF" ] || return 0
  if ! awk -v peers="$D_PEERS" -v chain="$2" -v group="$3" -v mc="$D_MCAST" '
    BEGIN { skip = 0; done = 0 }
    $0 == "# BEGIN dunree-vip" { skip = 1; next }
    $0 == "# END dunree-vip" { skip = 0; next }
    skip { next }
    $0 == "COMMIT" && !done {
      print "# BEGIN dunree-vip"
      if (mc == "1") { print "-A " chain " -p vrrp -d " group " -j ACCEPT" }
      else {
        n = split(peers, a, " ")
        for (i = 1; i <= n; i++) {
          if (a[i] ~ /^[0-9.]+$/ || a[i] ~ /^[0-9a-fA-F:]+$/) print "-A " chain " -p vrrp -s " a[i] " -j ACCEPT"
        }
      }
      print "# END dunree-vip"
      done = 1
    }
    { print }
    END { if (!done) exit 3 }
  ' "$UF" > "$TMPD/rules.new"; then
    say "Could not find the end of the rules in $UF, so the ufw rule was not added. Allow protocol 112 (VRRP) from $D_PEERS yourself."
    return 0
  fi
  if cmp -s "$TMPD/rules.new" "$UF"; then return 0; fi
  cp -p "$UF" "$UF.dunree-backup-$STAMP"
  cat "$TMPD/rules.new" > "$UF"
  if ! ufw reload >/dev/null 2>&1; then
    cat "$UF.dunree-backup-$STAMP" > "$UF"
    fail "ufw did not accept the rule." "Your old ufw rules were put back. Allow protocol 112 (VRRP) from $D_PEERS yourself."
  fi
  say "Allowed VRRP in ufw."
}
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  if [ "$D_V6" = 1 ]; then
    ufw_update "$D_ROOT/etc/ufw/before6.rules" ufw6-before-input ff02::12
  else
    ufw_update "$D_ROOT/etc/ufw/before.rules" ufw-before-input 224.0.0.18
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  if ! firewall-cmd --permanent --query-rich-rule='rule protocol value="vrrp" accept' >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule='rule protocol value="vrrp" accept' >/dev/null 2>&1 || fail "firewalld did not accept the rule." "Allow protocol 112 (VRRP) from $D_PEERS yourself."
    firewall-cmd --reload >/dev/null 2>&1 || say "firewalld could not reload. Run: firewall-cmd --reload"
    say "Allowed VRRP in firewalld."
  fi
else
  say "If you use another firewall on this server, allow protocol 112 (VRRP) from $D_PEERS."
fi

# 9. Install the config (atomic move; the old file is kept as a backup)
if [ -f "$CONF" ] && cmp -s "$TMPD/keepalived.conf" "$CONF"; then
  CHANGED=0
else
  if [ -f "$CONF" ]; then
    cp -p "$CONF" "$CONF.dunree-backup-$STAMP"
    say "Saved your old keepalived.conf as $CONF.dunree-backup-$STAMP."
  fi
  mv -f "$TMPD/keepalived.conf" "$CONF"
  CHANGED=1
  NOTE=''
fi

# 10. Enable and (re)start
systemctl enable keepalived >/dev/null 2>&1 || say "Could not enable keepalived at boot. Run: systemctl enable keepalived"
if [ "$CHANGED" = 1 ] || ! systemctl is-active --quiet keepalived; then
  systemctl restart keepalived >/dev/null 2>&1 || true
fi
i=0
UP=0
while [ "$i" -lt 10 ]; do
  if systemctl is-active --quiet keepalived; then UP=1; break; fi
  sleep 1
  i=$((i + 1))
done
if [ "$UP" != 1 ]; then
  journalctl -u keepalived -n 15 --no-pager 2>/dev/null | hide || true
  fail "keepalived did not start." "Copy the lines above into a Dunree issue. Your old keepalived.conf, if there was one, is saved next to the new one."
fi

# 11. Marker for the Dunree page (no password in it)
{
  printf 'fingerprint=%s\n' "$D_FP"
  printf 'member=%s\n' "$D_ADDR"
  printf 'generatedBy=%s\n' "$D_FROM"
  printf 'version=%s\n' "$D_VERSION"
  printf 'installedAt=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$TMPD/marker"
cat "$TMPD/marker" > "$MARK"
chmod 644 "$MARK"

# 12. Result
i=0
HOLDS=0
while [ "$i" -lt "$D_WAIT" ]; do
  if ip -o addr show dev "$D_IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$D_VIP"; then HOLDS=1; break; fi
  sleep 1
  i=$((i + 1))
done
if [ "$HOLDS" = 1 ]; then
  say "OK: keepalived is running on $D_LABEL. $D_LABEL answers on the floating IP $D_VIP now."
else
  say "OK: keepalived is running on $D_LABEL. It is standing by; the other server answers on $D_VIP."
fi
say "Go back to the Dunree page. It shows this server's progress by itself."
}

dunree_main </dev/null
`
