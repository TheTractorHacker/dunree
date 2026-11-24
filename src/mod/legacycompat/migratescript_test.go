package legacycompat

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Tests of tools/install/migrate-from-zoraxy.sh: the script runs against a temporary root with a fake // legacy-compat
// systemd folder and a fake systemctl. Nothing outside the temporary folder is touched.

const (
	oldUnitName = "zoraxy.service" // legacy-compat
	newUnitName = "dunree.service"
	oldInstall  = "/opt/zoraxy" // legacy-compat
	newInstall  = "/opt/dunree"
)

const oldUnitText = "# my own comment\n[Unit]\nDescription=Zoraxy reverse proxy\n" + // legacy-compat
	`After=network-online.target

[Service]
Type=notify
WorkingDirectory=/opt/zoraxy
EnvironmentFile=-/opt/zoraxy/env
Environment="ZORAXY_METRICS_TOKEN=abc" "CERTS=/opt/zoraxy/conf/certs:/opt/zoraxy-other/certs"
ExecStart=/opt/zoraxy/zoraxy -port=:8000 -conf /opt/zoraxy/conf
ExecStartPre=/usr/local/bin/check /opt/zoraxy
SyslogIdentifier=zoraxy
Restart=on-failure

[Install]
WantedBy=multi-user.target
` // legacy-compat (the whole literal: an existing unit file)

const fakeSystemctl = `#!/usr/bin/env bash
# fake systemctl for the test: enabled = link in multi-user.target.wants, active = file in the state folder
echo "$*" >>"$FAKE_STATE/log"
cmd="$1"; unit="${2:-}"
wants="$FAKE_UNITDIR/multi-user.target.wants"
case "$cmd" in
  is-enabled) [ -L "$wants/$unit" ] ;;
  is-active) [ -e "$FAKE_STATE/active.$unit" ] ;;
  stop) rm -f "$FAKE_STATE/active.$unit" ;;
  start)
    if [ "$unit" = "${FAKE_FAIL_START:-none}" ]; then echo "Job for $unit failed." >&2; exit 1; fi
    [ -f "$FAKE_UNITDIR/$unit" ] || { echo "Unit $unit not found." >&2; exit 5; }
    wd="$(sed -n 's/^WorkingDirectory=//p' "$FAKE_UNITDIR/$unit")"
    [ -d "$FAKE_ROOT$wd" ] || { echo "WorkingDirectory $wd missing" >&2; exit 1; }
    : >"$FAKE_STATE/active.$unit" ;;
  enable) [ -f "$FAKE_UNITDIR/$unit" ] || exit 1; mkdir -p "$wants"; ln -sf "../$unit" "$wants/$unit" ;;
  disable) rm -f "$wants/$unit" ;;
  daemon-reload) ;;
  *) echo "fake systemctl: unexpected $*" >&2; exit 64 ;;
esac
`

type fakeHost struct {
	t                    *testing.T
	root, unitDir, state string
	script               string
}

func newFakeHost(t *testing.T, enabled, active bool) *fakeHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "tools", "install", "migrate-from-zoraxy.sh")) // legacy-compat
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the migration script is missing: %v", err)
	}
	root := t.TempDir()
	h := &fakeHost{t: t, root: root, unitDir: filepath.Join(root, "etc", "systemd", "system"), state: filepath.Join(root, "state"), script: script}
	os.MkdirAll(h.state, 0o755)
	write(t, filepath.Join(h.unitDir, oldUnitName), oldUnitText, 0o644)
	write(t, filepath.Join(h.unitDir, oldUnitName+".d", "override.conf"), "[Service]\nEnvironment=WEBROOT=/opt/zoraxy/www\nLimitNOFILE=65535\n", 0o644) // legacy-compat
	write(t, filepath.Join(root, "bin", "systemctl"), fakeSystemctl, 0o755)
	inst := filepath.Join(root, "opt", "zoraxy")                               // legacy-compat
	write(t, filepath.Join(inst, "zoraxy"), "#!/bin/sh\necho binary\n", 0o755) // legacy-compat
	write(t, filepath.Join(inst, "conf", "proxy", "a.example.com.config"), `{"RootOrMatchingDomain":"a.example.com"}`, 0o664)
	write(t, filepath.Join(inst, "conf", "certs", "a.example.com.key"), "KEY", 0o600)
	write(t, filepath.Join(inst, "sys.db"), "database", 0o600)
	write(t, filepath.Join(inst, "plugins", "hello", "hello"), "#!/bin/sh\n", 0o755)
	if enabled {
		os.MkdirAll(filepath.Join(h.unitDir, "multi-user.target.wants"), 0o755)
		if err := os.Symlink("../"+oldUnitName, filepath.Join(h.unitDir, "multi-user.target.wants", oldUnitName)); err != nil {
			t.Fatal(err)
		}
	}
	if active {
		write(t, filepath.Join(h.state, "active."+oldUnitName), "", 0o644)
	}
	return h
}

func (h *fakeHost) run(env []string, args ...string) (string, int) {
	h.t.Helper()
	cmd := exec.Command("bash", append([]string{h.script, "--root", h.root}, args...)...)
	cmd.Env = append(os.Environ(), "SYSTEMCTL="+filepath.Join(h.root, "bin", "systemctl"), "FAKE_STATE="+h.state,
		"FAKE_UNITDIR="+h.unitDir, "FAKE_ROOT="+h.root)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		h.t.Fatalf("could not run the script: %v", err)
	}
	return string(out), code
}

func (h *fakeHost) log() string {
	b, _ := os.ReadFile(filepath.Join(h.state, "log"))
	return string(b)
}
func (h *fakeHost) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(h.root, rel))
	return err == nil
}
func (h *fakeHost) enabled(unit string) bool {
	return h.exists(filepath.Join("etc", "systemd", "system", "multi-user.target.wants", unit))
}
func (h *fakeHost) active(unit string) bool { return h.exists(filepath.Join("state", "active."+unit)) }
func (h *fakeHost) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(h.root, rel))
	if err != nil {
		h.t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestMigrateServiceScript(t *testing.T) {
	h := newFakeHost(t, true, true)
	installBefore := snapshot(t, filepath.Join(h.root, "opt", "zoraxy")) // legacy-compat
	out, code := h.run(nil)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}

	//the install moved as a whole, nothing lost, modes kept; the old path is a link to it
	if d := diff(installBefore, snapshot(t, filepath.Join(h.root, "opt", "dunree"))); d != "" {
		t.Fatalf("the install folder changed while moving:\n%s", d)
	}
	oldPath := filepath.Join(h.root, "opt", "zoraxy") // legacy-compat
	if st, err := os.Lstat(oldPath); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("no compatibility link at the old path: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(oldPath, "conf", "proxy", "a.example.com.config")); err != nil || !strings.Contains(string(b), "a.example.com") {
		t.Fatalf("the old path no longer leads to the install: %v", err)
	}
	if l, _ := os.Readlink(oldPath); l != "dunree" {
		t.Fatalf("link target %q, want the relative name (works wherever the parent is)", l)
	}

	//the old unit: kept byte for byte, disabled, stopped
	unitRel := filepath.Join("etc", "systemd", "system")
	if h.read(filepath.Join(unitRel, oldUnitName)) != oldUnitText {
		t.Fatal("the old unit file must be kept unchanged")
	}
	if h.enabled(oldUnitName) || h.active(oldUnitName) {
		t.Fatal("the old unit must be disabled and stopped")
	}
	//the new unit: same settings, folder path replaced where it is a whole path, never together with the old one
	nu := h.read(filepath.Join(unitRel, newUnitName))
	for _, want := range []string{
		"WorkingDirectory=/opt/dunree\n",
		"EnvironmentFile=-/opt/dunree/env\n",
		"ExecStart=/opt/dunree/zoraxy -port=:8000 -conf /opt/dunree/conf\n", // legacy-compat: the program file keeps its name
		"ExecStartPre=/usr/local/bin/check /opt/dunree\n",
		`"CERTS=/opt/dunree/conf/certs:/opt/zoraxy-other/certs"`, // legacy-compat: another folder that only starts the same
		`"ZORAXY_METRICS_TOKEN=abc"`,                             // legacy-compat: variables are left alone (still read)
		"SyslogIdentifier=zoraxy\n",                              // legacy-compat: log filters keep matching
		"Conflicts=" + oldUnitName + "\n",
		"Description=Dunree reverse proxy and web gateway\n",
		"# my own comment\n", "Type=notify\n", "Restart=on-failure\n", "WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(nu, want) {
			t.Errorf("new unit lacks %q", want)
		}
	}
	if strings.Contains(nu, "/opt/zoraxy/") || strings.Contains(nu, "=/opt/zoraxy\n") { // legacy-compat
		t.Errorf("new unit still uses the old folder:\n%s", nu)
	}
	if strings.Index(nu, "Conflicts=") < strings.Index(nu, "[Unit]") || strings.Index(nu, "Conflicts=") > strings.Index(nu, "[Service]") {
		t.Error("Conflicts= must be in the [Unit] section")
	}
	if !h.enabled(newUnitName) || !h.active(newUnitName) {
		t.Fatalf("the new unit must be enabled and running (the old one was)\n%s", out)
	}
	if d := h.read(filepath.Join(unitRel, newUnitName+".d", "override.conf")); !strings.Contains(d, "WEBROOT=/opt/dunree/www") || !strings.Contains(d, "LimitNOFILE=65535") {
		t.Fatalf("drop-in not carried over: %q", d)
	}
	if !h.exists(filepath.Join(unitRel, oldUnitName+".d", "override.conf")) {
		t.Fatal("the old drop-in must stay")
	}
	//order: stop the old service before anything moves, start the new one last
	want := "is-enabled zoraxy.service\nis-active zoraxy.service\nstop zoraxy.service\ndisable zoraxy.service\ndaemon-reload\nenable dunree.service\nstart dunree.service\n" // legacy-compat
	if h.log() != want {
		t.Fatalf("systemctl calls:\n%s\nwant:\n%s", h.log(), want)
	}

	//second run: nothing to do, nothing called that changes state
	after := snapshot(t, filepath.Join(h.root, "etc"))
	os.Remove(filepath.Join(h.state, "log"))
	out, code = h.run(nil)
	if code != 0 || !strings.Contains(out, "Already migrated") {
		t.Fatalf("second run: exit %d\n%s", code, out)
	}
	if h.log() != "" {
		t.Fatalf("second run called systemctl: %s", h.log())
	}
	if d := diff(after, snapshot(t, filepath.Join(h.root, "etc"))); d != "" {
		t.Fatalf("second run changed something:\n%s", d)
	}
}

func TestMigrateServiceScriptDryRun(t *testing.T) {
	h := newFakeHost(t, true, true)
	before := snapshot(t, h.root)
	out, code := h.run(nil, "--dry-run")
	if code != 0 || !strings.Contains(out, "WorkingDirectory=/opt/dunree") || !strings.Contains(out, "nothing was changed") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if d := diff(before, snapshot(t, h.root)); d != "" {
		t.Fatalf("a dry run changed something:\n%s", d)
	}
}

// When the new service does not start, every step is undone and the old service runs again.
func TestMigrateServiceScriptUndoesOnFailure(t *testing.T) {
	h := newFakeHost(t, true, true)
	before := without(snapshot(t, h.root), "state")
	out, code := h.run([]string{"FAKE_FAIL_START=" + newUnitName})
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if d := diff(before, without(snapshot(t, h.root), "state")); d != "" {
		t.Fatalf("a failed run left changes behind:\n%s\n%s", d, out)
	}
	if !h.enabled(oldUnitName) || !h.active(oldUnitName) {
		t.Fatalf("the old service must be enabled and running again\n%s\n%s", out, h.log())
	}
	if h.enabled(newUnitName) || h.active(newUnitName) {
		t.Fatal("the new unit must not be left enabled or running")
	}
	//and the run can simply be repeated once the cause is gone
	if out, code := h.run(nil); code != 0 || !h.active(newUnitName) {
		t.Fatalf("repeat after the failure: exit %d\n%s", code, out)
	}
}

// A unit that was disabled and stopped stays that way under its new name; --no-start enables without starting.
func TestMigrateServiceScriptKeepsServiceState(t *testing.T) {
	h := newFakeHost(t, false, false)
	if out, code := h.run(nil); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if h.enabled(newUnitName) || h.active(newUnitName) {
		t.Fatal("a service that was disabled and stopped must not be enabled or started")
	}
	if strings.Contains(h.log(), "start ") || strings.Contains(h.log(), "enable ") {
		t.Fatalf("unexpected systemctl calls: %s", h.log())
	}

	h2 := newFakeHost(t, true, true)
	if out, code := h2.run(nil, "--no-start"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !h2.enabled(newUnitName) || h2.active(newUnitName) || h2.active(oldUnitName) {
		t.Fatal("--no-start: want enabled, not running")
	}
}

// Refusals change nothing: a new folder that exists already, no old unit, an old path that is a link.
func TestMigrateServiceScriptRefusals(t *testing.T) {
	h := newFakeHost(t, true, true)
	write(t, filepath.Join(h.root, "opt", "dunree", "something"), "x", 0o644)
	before := snapshot(t, h.root)
	out, code := h.run(nil)
	if code != 2 || !strings.Contains(out, "exists already") {
		t.Fatalf("existing target folder: exit %d\n%s", code, out)
	}
	if d := diff(before, snapshot(t, h.root)); d != "" {
		t.Fatalf("a refused run changed something:\n%s", d)
	}
	if !h.active(oldUnitName) {
		t.Fatal("a refused run must not stop the service")
	}

	h = newFakeHost(t, true, true)
	os.Remove(filepath.Join(h.unitDir, oldUnitName))
	if out, code := h.run(nil); code != 2 || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("no old unit: exit %d\n%s", code, out)
	}

	h = newFakeHost(t, true, true)
	if out, code := h.run(nil, "--new-dir", "/opt/dun ree"); code != 2 {
		t.Fatalf("odd path accepted: exit %d\n%s", code, out)
	}
}

// --keep-dir, and an install that is not in the default folder: only the service is renamed.
func TestMigrateServiceScriptServiceOnly(t *testing.T) {
	h := newFakeHost(t, true, true)
	out, code := h.run(nil, "--keep-dir")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if st, err := os.Lstat(filepath.Join(h.root, "opt", "zoraxy")); err != nil || !st.IsDir() { // legacy-compat
		t.Fatal("--keep-dir must leave the folder alone")
	}
	if h.exists(filepath.Join("opt", "dunree")) {
		t.Fatal("--keep-dir created the new folder")
	}
	nu := h.read(filepath.Join("etc", "systemd", "system", newUnitName))
	if !strings.Contains(nu, "WorkingDirectory=/opt/zoraxy\n") || !strings.Contains(nu, "Conflicts="+oldUnitName) { // legacy-compat
		t.Fatalf("--keep-dir must keep the paths:\n%s", nu)
	}
	if !h.active(newUnitName) || h.enabled(oldUnitName) {
		t.Fatal("service not switched")
	}
	if out, code := h.run(nil, "--keep-dir"); code != 0 || !strings.Contains(out, "Already migrated") {
		t.Fatalf("second run: exit %d\n%s", code, out)
	}
}

// Review regression: the folder path is replaced only where it is the whole path. A longer path that only ends
// the same stays; the "-" prefix of Exec and EnvironmentFile lines and two paths separated by one character
// (":") are both replaced.
func TestMigrateServiceScriptPathBoundaries(t *testing.T) {
	h := newFakeHost(t, false, false)
	unit := "[Unit]\nDescription=proxy\n[Service]\nWorkingDirectory=/opt/zoraxy\n" + // legacy-compat
		"ExecStartPre=-/opt/zoraxy/pre.sh\n" + // legacy-compat
		"ReadWritePaths=/usr/local/opt/zoraxy /srv/opt/zoraxy/data\n" + // legacy-compat
		"Environment=P=/opt/zoraxy:/opt/zoraxy/bin:/opt/zoraxy\n" + // legacy-compat
		"ExecStart=/opt/zoraxy/zoraxy\n" // legacy-compat
	write(t, filepath.Join(h.unitDir, oldUnitName), unit, 0o644)
	if out, code := h.run(nil); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	nu := h.read(filepath.Join("etc", "systemd", "system", newUnitName))
	for _, want := range []string{
		"WorkingDirectory=/opt/dunree\n",
		"ExecStartPre=-/opt/dunree/pre.sh\n",
		"ReadWritePaths=/usr/local/opt/zoraxy /srv/opt/zoraxy/data\n", // legacy-compat: other folders
		"Environment=P=/opt/dunree:/opt/dunree/bin:/opt/dunree\n",
		"ExecStart=/opt/dunree/zoraxy\n", // legacy-compat: program file name kept
	} {
		if !strings.Contains(nu, want) {
			t.Errorf("new unit lacks %q:\n%s", want, nu)
		}
	}
}
