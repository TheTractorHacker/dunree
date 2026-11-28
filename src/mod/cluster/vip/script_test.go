package vip

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testPass = "Xb7kQ2mT"

type scriptCase struct {
	name      string
	mk        func() Shared
	host      string // address/prefix of the host the script is for
	multicast bool
}

func scriptCases() []scriptCase {
	var out []scriptCase
	for _, fam := range []string{"v4", "v6"} {
		for _, role := range []string{"main", "backup"} {
			for _, tr := range []string{"unicast", "multicast"} {
				fam, role, tr := fam, role, tr
				c := scriptCase{name: fam + "_" + role + "_" + tr, multicast: tr == "multicast"}
				mk := fixture4
				hosts := [2]string{"192.0.2.11/24", "192.0.2.12/24"}
				if fam == "v6" {
					mk = fixture6
					hosts = [2]string{"2001:db8::11/64", "2001:db8::12/64"}
				}
				c.host = hosts[0]
				if role == "backup" {
					c.host = hosts[1]
				}
				c.mk = func() Shared {
					s := mk()
					if tr == "multicast" {
						s.Transport = TransportMulticast
					}
					return s
				}
				out = append(out, c)
			}
		}
	}
	return out
}

func TestScriptGolden(t *testing.T) {
	for _, c := range scriptCases() {
		t.Run(c.name, func(t *testing.T) {
			s := c.mk()
			so, err := Script(&s, nil, envFor(c.host), -1, nil)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "scripts/"+c.name, so.Script)
			wantRole := "Main server"
			if strings.Contains(c.name, "backup") {
				wantRole = "Backup server"
			}
			if so.Role != wantRole {
				t.Errorf("role %q, want %q", so.Role, wantRole)
			}
			if !strings.HasPrefix(so.Inner, "#!/bin/sh\n") || strings.Contains(so.Inner, scriptDelimOuter) {
				t.Error("download file shape")
			}
		})
	}
}

func lookTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return p
}

func TestScriptSyntax(t *testing.T) {
	sh := lookTool(t, "sh")
	bash, _ := exec.LookPath("bash")
	shellcheck, _ := exec.LookPath("shellcheck")
	if shellcheck == "" {
		t.Log("shellcheck is not installed: skipped, sh -n and bash -n still run")
	}
	for _, c := range scriptCases() {
		s := c.mk()
		so, err := Script(&s, nil, envFor(c.host), -1, nil)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		for name, text := range map[string]string{"wrapped.sh": so.Script, "inner.sh": so.Inner} {
			f := filepath.Join(dir, name)
			os.WriteFile(f, []byte(text), 0o600)
			if b, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
				t.Errorf("%s %s: sh -n: %v %s", c.name, name, err, b)
			}
			if bash != "" {
				if b, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
					t.Errorf("%s %s: bash -n: %v %s", c.name, name, err, b)
				}
			}
			if shellcheck != "" && name == "inner.sh" {
				if b, err := exec.Command(shellcheck, "-s", "sh", f).CombinedOutput(); err != nil {
					t.Errorf("%s: shellcheck: %s", c.name, b)
				}
			}
		}
	}
}

// Every $D_ variable is used inside double quotes, except $D_PROBE_K whose
// whitelist is empty or "-k".
func TestScriptNoUnquotedValues(t *testing.T) {
	re := regexp.MustCompile(`\$\{?D_[A-Z_]+`)
	for n, line := range strings.Split(scriptBody, "\n") {
		for _, m := range re.FindAllStringIndex(line, -1) {
			name := line[m[0]:m[1]]
			if strings.HasPrefix(name, "$D_PROBE_K") {
				continue
			}
			if strings.Count(line[:m[0]], `"`)%2 == 0 {
				t.Errorf("line %d uses %s outside double quotes: %s", n+1, name, line)
			}
		}
	}
	if strings.Count(scriptBody, "$D_PROBE_K") != 1 {
		t.Error("$D_PROBE_K must be used exactly once")
	}
}

var hostile = []string{
	"a'b", "a;b", "a$(id)b", "a`id`b", "a\\b", "a\nb", "a\"b", "a b", "a|b", "a&b", "a>b", "a\x00b", "a\rb",
	"x'; rm -rf / #", "$(touch /tmp/pwn)", "`touch /tmp/pwn`", "a\nDUNREE_KEEPALIVED_CONF_END\nb", "a\nDUNREE_SETUP_END\nb",
}

func TestScriptRenderVarsRefuseHostile(t *testing.T) {
	res := map[string]*regexp.Regexp{
		"label": reScriptLabel, "v4": reScriptV4, "v6": reScriptV6, "iface": reScriptIface, "int": reScriptInt,
		"probe": reScriptProbe, "fp": reScriptFP, "root": reScriptRoot,
	}
	for name, re := range res {
		for _, h := range hostile {
			// labels may hold a plain space; everything else here has more than that
			if _, err := renderVars([]scriptVar{{"D_X", h, re}}); err == nil && h != "a b" {
				t.Errorf("%s accepted %q", name, h)
			} else if err == nil && name != "label" {
				t.Errorf("%s accepted %q", name, h)
			}
		}
	}
	// even a permissive regexp cannot let a dangerous byte through
	for _, h := range hostile {
		if h == "a b" || h == "a;b" || h == "a|b" || h == "a&b" || h == "a>b" {
			continue
		}
		if _, err := renderVars([]scriptVar{{"D_X", h, regexp.MustCompile(`(?s)^.*$`)}}); err == nil {
			t.Errorf("byte guard accepted %q", h)
		}
	}
}

// Hostile values in every field a user can type end as a refusal or as text
// that holds none of the hostile payload.
func TestScriptInjectionSuite(t *testing.T) {
	type mut struct {
		field string
		apply func(s *Shared, l *Local, v string)
	}
	muts := []mut{
		{"label", func(s *Shared, l *Local, v string) { s.Members[0].Label = v }},
		{"label1", func(s *Shared, l *Local, v string) { s.Members[1].Label = v }},
		{"address", func(s *Shared, l *Local, v string) { s.Members[1].Address = v }},
		{"vip", func(s *Shared, l *Local, v string) { s.VIP = v }},
		{"hint", func(s *Shared, l *Local, v string) { s.Members[1].InterfaceHint = v }},
		{"password", func(s *Shared, l *Local, v string) { s.Password = v }},
		{"main", func(s *Shared, l *Local, v string) { s.Main = v }},
		{"local-iface", func(s *Shared, l *Local, v string) { l.Interface = v }},
		{"local-src", func(s *Shared, l *Local, v string) { l.SourceAddress = v }},
		{"healthTarget", func(s *Shared, l *Local, v string) { l.HealthTarget = v }},
	}
	payload := regexp.MustCompile(`pwn|rm -rf /|\$\(id\)|` + "`id`" + ``)
	for _, m := range muts {
		for _, h := range hostile {
			s := fixture4()
			l := Local{}
			m.apply(&s, &l, h)
			so, err := Script(&s, &l, envFor("192.0.2.11/24"), -1, nil)
			if err != nil {
				continue // refused by the validator or the render guard
			}
			if payload.MatchString(so.Script) {
				t.Errorf("%s %q reached the script", m.field, h)
			}
			if strings.Contains(h, "\n") && strings.Contains(so.Script, h) {
				t.Errorf("%s %q (newline) reached the script", m.field, h)
			}
		}
	}
	// peer facts come from another server's JSON: hostile ones are refused too
	for _, h := range hostile {
		s := fixture4()
		for _, pf := range []*PeerFacts{{Iface: h}, {ProbeBase: h}, {ProbeBase: "http://127.0.0.1:8081" + h}} {
			so, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, pf)
			if err != nil {
				continue
			}
			if payload.MatchString(so.Script) {
				t.Errorf("peer fact %+v reached the script", pf)
			}
		}
	}
	// the hostile label that IS allowed by the label rule (spaces) stays inside quotes
	s := fixture4()
	s.Members[0].Label = "node a"
	so, err := Script(&s, nil, envFor("192.0.2.11/24"), -1, nil)
	if err != nil || !strings.Contains(so.Script, "D_LABEL='node a'\n") {
		t.Fatalf("label with a space: %v", err)
	}
}

func FuzzVIPScript(f *testing.F) {
	for _, h := range hostile {
		f.Add(h, h, h)
	}
	f.Add("node-a", "ens18", "http://127.0.0.1:8081")
	f.Fuzz(func(t *testing.T, label, iface, probe string) {
		s := fixture4()
		s.Members[0].Label = label
		s.Members[1].InterfaceHint = iface
		so, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, &PeerFacts{Iface: iface, ProbeBase: probe})
		if err != nil {
			return
		}
		for _, line := range strings.Split(so.Script, "\n") {
			if strings.HasPrefix(line, "D_") {
				if !regexp.MustCompile(`^D_[A-Z0-9_]+='[A-Za-z0-9 ._:/\[\]()+-]*'$`).MatchString(line) {
					t.Fatalf("variable line out of shape: %q", line)
				}
			}
		}
		if strings.Count(so.Script, "\n"+scriptDelimOuter+"\n") != 1 || !strings.HasSuffix(so.Script, "\n"+scriptDelimOuter+"\n") {
			t.Fatal("outer delimiter")
		}
	})
}

// ---- sandbox: run the real script with stub commands in a temp tree ----

type sandbox struct {
	t                    *testing.T
	dir, root, st, bin   string
	tool                 string
	ipFile               string
	hostAddr, iface, vip string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	sh := lookTool(t, "sh")
	b := &sandbox{t: t, dir: t.TempDir()}
	b.root = filepath.Join(b.dir, "root")
	b.st = filepath.Join(b.dir, "state")
	b.bin = filepath.Join(b.dir, "bin")
	b.tool = filepath.Join(b.dir, "tools")
	b.ipFile = filepath.Join(b.st, "ip-addr.txt")
	for _, d := range []string{b.root + "/etc/keepalived", b.root + "/etc/ufw", b.st, b.bin, b.tool} {
		os.MkdirAll(d, 0o755)
	}
	// the only real programs the script may reach
	for _, n := range []string{"awk", "sed", "grep", "cut", "tr", "head", "tail", "cat", "mkdir", "chmod", "mktemp", "cp", "mv", "rm", "cmp", "date"} {
		p, err := exec.LookPath(n)
		if err != nil {
			t.Skipf("%s is not installed", n)
		}
		os.Symlink(p, filepath.Join(b.tool, n))
	}
	os.Symlink(sh, filepath.Join(b.tool, "sh"))
	stub := func(dir, name, body string) {
		os.WriteFile(filepath.Join(dir, name), []byte("#!"+sh+"\n"+body), 0o755)
	}
	log := `echo "${0##*/} $*" >> "$ST/calls.log"` + "\n"
	// countok NAME: succeeds unless the flag file ST/NAME asks for a failure. An empty file fails every time, a number fails that many times.
	os.WriteFile(filepath.Join(b.st, "countok"), []byte("#!"+sh+"\n"+`f="$ST/$1"; [ -f "$f" ] || exit 0; n=$(cat "$f"); [ -n "$n" ] || exit 1; if [ "$n" -gt 0 ]; then echo $((n - 1)) > "$f"; exit 1; fi; exit 0`+"\n"), 0o755)
	stub(b.bin, "id", log+`case "$*" in "-u") cat "$ST/uid" 2>/dev/null || echo 0;; *) [ -f "$ST/has-user" ];; esac`+"\n")
	stub(b.bin, "ip", log+`case "$*" in
"-o addr show dev "*) awk -v d="$5" '$2==d' "$ST/ip-addr.txt";;
"-o addr show") cat "$ST/ip-addr.txt";;
"-o link show dev "*) awk -v d="$5" '$2==d{f=1} END{exit !f}' "$ST/ip-addr.txt";;
"-o route show default") cat "$ST/ip-route4.txt" 2>/dev/null;;
"-o -6 route show default") cat "$ST/ip-route6.txt" 2>/dev/null;;
*) exit 2;;
esac
`)
	stub(b.bin, "runuser", log+`[ ! -f "$ST/health-fail" ]`+"\n")
	stub(b.bin, "useradd", log+`: > "$ST/has-user"`+"\n")
	stub(b.bin, "chown", log)
	stub(b.bin, "sleep", ``)
	stub(b.bin, "sysctl", log)
	stub(b.bin, "journalctl", log+`echo "keepalived: auth_pass `+testPass+` in a log line"`+"\n")
	stub(b.bin, "systemctl", log+`case "$1" in
is-active) [ -f "$ST/active" ];;
restart|start) if ! "$ST/countok" fail-start; then rm -f "$ST/active"; exit 1; fi; : > "$ST/active"; if [ -f "$ST/will-hold" ]; then cat "$ST/vip-line" >> "$ST/ip-addr.txt"; fi;;
*) :;;
esac
`)
	kaBody := log + `if [ -f "$ST/conf-bad" ]; then grep auth_pass "$3"; echo "bad config" >&2; exit 1; fi; cat "$3" > "$ST/tested.conf"` + "\n"
	os.MkdirAll(filepath.Join(b.st, "pkgs"), 0o755)
	for _, d := range []string{b.bin, filepath.Join(b.st, "pkgs")} {
		stub(d, "keepalived", kaBody)
		stub(d, "curl", "")
	}
	stub(b.bin, "ufw", log+`case "$1" in status) if [ -f "$ST/ufw-active" ]; then echo "Status: active"; else echo "Status: inactive"; fi;; reload) "$ST/countok" ufw-fail;; esac`+"\n")
	stub(b.bin, "firewall-cmd", log+`case "$1" in --state) [ -f "$ST/fwd" ];; --permanent) case "$2" in --query-rich-rule=*) [ -f "$ST/fwd-has" ];; *) :;; esac;; *) :;; esac`+"\n")
	inst := `cp "$ST/pkgs/"* "` + b.bin + `/"`
	stub(b.bin, "apt-get", log+`case "$1" in update) [ ! -f "$ST/pkg-fail" ];; install) `+inst+`;; esac`+"\n")
	stub(b.bin, "dnf", log+`case "$1" in install) `+inst+`;; esac`+"\n")
	os.WriteFile(filepath.Join(b.root, "etc/os-release"), []byte("NAME=\"Debian GNU/Linux\"\nID=debian\n"), 0o644)
	return b
}

func (b *sandbox) uninstallPackages() {
	os.Remove(filepath.Join(b.bin, "keepalived"))
	os.Remove(filepath.Join(b.bin, "curl"))
}

func (b *sandbox) set(name string, on bool) {
	f := filepath.Join(b.st, name)
	if on {
		os.WriteFile(f, nil, 0o644)
	} else {
		os.Remove(f)
	}
}

func (b *sandbox) write(rel, text string) {
	p := filepath.Join(b.root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *sandbox) read(rel string) string {
	d, _ := os.ReadFile(filepath.Join(b.root, rel))
	return string(d)
}

func (b *sandbox) calls() string {
	d, _ := os.ReadFile(filepath.Join(b.st, "calls.log"))
	return string(d)
}

func (b *sandbox) clearCalls() { os.Remove(filepath.Join(b.st, "calls.log")) }

// host sets the interface lines the stub ip prints.
func (b *sandbox) host(iface, addr string, v6 bool, vip string) {
	kind := "inet"
	if v6 {
		kind = "inet6"
	}
	lines := "1: lo    inet 127.0.0.1/8 scope host lo\n"
	if addr != "" {
		lines += fmt.Sprintf("2: %s    %s %s/24 scope global %s\n", iface, kind, addr, iface)
	}
	os.WriteFile(b.ipFile, []byte(lines), 0o644)
	os.WriteFile(filepath.Join(b.st, "vip-line"), []byte(fmt.Sprintf("2: %s    %s %s/24 scope global secondary %s\n", iface, kind, vip, iface)), 0o644)
}

// run executes a generated script and returns its combined output and exit code.
func (b *sandbox) run(text string) (string, int) {
	b.t.Helper()
	f := filepath.Join(b.dir, "run.sh")
	os.WriteFile(f, []byte(text), 0o700)
	cmd := exec.Command(b.tool+"/sh", f)
	cmd.Env = []string{"PATH=" + b.bin + ":" + b.tool, "ST=" + b.st, "HOME=" + b.dir, "TMPDIR=" + b.dir}
	cmd.Dir = b.dir
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		b.t.Fatal(err)
	}
	if strings.Contains(string(out), testPass) {
		b.t.Errorf("the password was printed:\n%s", out)
	}
	return string(out), code
}

// files lists every file under the fake root.
func (b *sandbox) files() []string {
	var out []string
	filepath.Walk(b.root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			r, _ := filepath.Rel(b.root, p)
			out = append(out, r)
		}
		return nil
	})
	return out
}

func (b *sandbox) script(s Shared, host string, member int) string {
	b.t.Helper()
	so, err := script(&s, nil, envFor(host), member, nil, b.root)
	if err != nil {
		b.t.Fatal(err)
	}
	return so.Inner
}

func readyBackup(t *testing.T) (*sandbox, Shared) {
	b := newSandbox(t)
	s := fixture4()
	b.host("ens18", "192.0.2.12", false, "192.0.2.10")
	return b, s
}

func hasFile(b *sandbox, rel string) bool {
	_, err := os.Stat(filepath.Join(b.root, rel))
	return err == nil
}

func TestSandboxGuards(t *testing.T) {
	t.Run("not root", func(t *testing.T) {
		b, s := readyBackup(t)
		os.WriteFile(filepath.Join(b.st, "uid"), []byte("1000\n"), 0o644)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "must run as root") {
			t.Fatalf("code %d\n%s", code, out)
		}
		if strings.Contains(b.calls(), "apt-get") || len(b.files()) != 1 { // only os-release
			t.Errorf("changed things: %v\n%s", b.files(), b.calls())
		}
	})
	t.Run("wrong server", func(t *testing.T) {
		b, s := readyBackup(t)
		b.host("ens18", "192.0.2.77", false, "192.0.2.10")
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "This is not node-b (192.0.2.12)") {
			t.Fatalf("code %d\n%s", code, out)
		}
		if strings.Contains(b.calls(), "systemctl") || len(b.files()) != 1 {
			t.Errorf("changed things: %v", b.files())
		}
	})
	t.Run("wrong interface", func(t *testing.T) {
		b, s := readyBackup(t)
		b.host("eth9", "192.0.2.12", false, "192.0.2.10")
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "called eth9") || !strings.Contains(out, "not called ens18") {
			t.Fatalf("code %d\n%s", code, out)
		}
	})
	t.Run("health check fails", func(t *testing.T) {
		b, s := readyBackup(t)
		b.set("health-fail", true)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "does not answer its health check at http://127.0.0.1:8081/.dunree/health") {
			t.Fatalf("code %d\n%s", code, out)
		}
		if hasFile(b, "etc/keepalived/keepalived.conf") {
			t.Error("config written")
		}
	})
	t.Run("config test fails", func(t *testing.T) {
		b, s := readyBackup(t)
		b.set("conf-bad", true)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "auth_pass (hidden)") || !strings.Contains(out, "did not accept") {
			t.Fatalf("code %d\n%s", code, out)
		}
		if hasFile(b, "etc/keepalived/keepalived.conf") || strings.Contains(b.calls(), "systemctl restart") {
			t.Error("a rejected config was installed or started")
		}
		if ents, _ := os.ReadDir(filepath.Join(b.root, "etc/keepalived")); len(ents) != 0 {
			t.Errorf("temp files left: %v", ents)
		}
	})
}

func TestSandboxPackages(t *testing.T) {
	for _, c := range []struct{ name, osr, tool string }{
		{"debian", "ID=debian\n", "apt-get install -y -qq keepalived curl"},
		{"ubuntu like", "ID=pop\nID_LIKE=\"ubuntu debian\"\n", "apt-get install -y -qq keepalived curl"},
		{"rocky", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", "dnf install -y -q keepalived curl"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, s := readyBackup(t)
			b.uninstallPackages()
			b.write("etc/os-release", c.osr)
			out, code := b.run(b.script(s, "192.0.2.12/24", -1))
			if code != 0 || !strings.Contains(b.calls(), c.tool) {
				t.Fatalf("code %d\n%s\n%s", code, out, b.calls())
			}
			if !strings.Contains(b.calls(), "useradd -r -M -s /bin/false keepalived_script") {
				t.Errorf("user not created:\n%s", b.calls())
			}
		})
	}
	t.Run("unsupported", func(t *testing.T) {
		b, s := readyBackup(t)
		b.uninstallPackages()
		b.write("etc/os-release", "ID=arch\n")
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "supports Debian, Ubuntu, RHEL") || strings.Contains(b.calls(), "apt-get") || strings.Contains(b.calls(), "dnf") {
			t.Fatalf("code %d\n%s\n%s", code, out, b.calls())
		}
	})
	t.Run("apt fails", func(t *testing.T) {
		b, s := readyBackup(t)
		b.uninstallPackages()
		b.set("pkg-fail", true)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "apt-get update failed") {
			t.Fatalf("code %d\n%s", code, out)
		}
	})
	t.Run("present packages are not touched", func(t *testing.T) {
		b, s := readyBackup(t)
		b.run(b.script(s, "192.0.2.12/24", -1))
		if strings.Contains(b.calls(), "apt-get") {
			t.Error("apt ran although everything was installed")
		}
	})
}

func TestSandboxInstallAndRepeat(t *testing.T) {
	b, s := readyBackup(t)
	text := b.script(s, "192.0.2.12/24", -1)
	out, code := b.run(text)
	if code != 0 || !strings.Contains(out, "OK: keepalived is running on node-b. It is standing by; the other server answers on 192.0.2.10.") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out, "Go back to the Dunree page") {
		t.Error("missing last line")
	}
	conf := b.read("etc/keepalived/keepalived.conf")
	if !strings.Contains(conf, "auth_pass "+testPass) || !strings.Contains(conf, "priority 100") {
		t.Errorf("config:\n%s", conf)
	}
	fi, _ := os.Stat(filepath.Join(b.root, "etc/keepalived/keepalived.conf"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v", fi.Mode().Perm())
	}
	mk := b.read("etc/keepalived/dunree-installed")
	if !strings.Contains(mk, "fingerprint=") || !strings.Contains(mk, "member=192.0.2.12") || strings.Contains(mk, testPass) {
		t.Errorf("marker:\n%s", mk)
	}
	if fi, _ := os.Stat(filepath.Join(b.root, "etc/keepalived/dunree-installed")); fi.Mode().Perm() != 0o644 {
		t.Errorf("marker mode %v", fi.Mode().Perm())
	}
	tested, _ := os.ReadFile(filepath.Join(b.st, "tested.conf"))
	if string(tested) != conf {
		t.Error("the tested file is not the installed file")
	}
	want := []string{"etc/keepalived/dunree-installed", "etc/keepalived/keepalived.conf", "etc/os-release"}
	if got := b.files(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("files written: %v, want %v", got, want)
	}
	for _, w := range []string{"keepalived -t -f", "systemctl enable keepalived", "systemctl restart keepalived"} {
		if !strings.Contains(b.calls(), w) {
			t.Errorf("missing call %q:\n%s", w, b.calls())
		}
	}
	if strings.Index(b.calls(), "keepalived -t -f") > strings.Index(b.calls(), "systemctl restart") {
		t.Error("the config test must come before the restart")
	}
	// second run: nothing changes
	b.clearCalls()
	out2, code := b.run(text)
	if code != 0 || !strings.Contains(out2, "OK: keepalived is running on node-b.") {
		t.Fatalf("second run %d\n%s", code, out2)
	}
	if strings.Contains(b.calls(), "restart") || strings.Contains(out2, "Saved your old") {
		t.Errorf("second run changed things:\n%s\n%s", out2, b.calls())
	}
	if got := b.files(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("second run files: %v", got)
	}
}

func TestSandboxHoldsAndChange(t *testing.T) {
	b, s := readyBackup(t)
	b.set("will-hold", true)
	out, code := b.run(b.script(s, "192.0.2.12/24", -1))
	if code != 0 || !strings.Contains(out, "node-b answers on the floating IP 192.0.2.10 now.") {
		t.Fatalf("%d\n%s", code, out)
	}
	// changed settings: one backup, one restart
	s.VRID = 60
	b.clearCalls()
	out, code = b.run(b.script(s, "192.0.2.12/24", -1))
	if code != 0 || !strings.Contains(out, "Saved your old keepalived.conf as ") {
		t.Fatalf("%d\n%s", code, out)
	}
	if !strings.Contains(b.calls(), "systemctl restart keepalived") {
		t.Error("no restart after a change")
	}
	n := 0
	for _, f := range b.files() {
		if strings.Contains(f, "keepalived.conf.dunree-backup-") {
			n++
			if !strings.Contains(b.read(f), "virtual_router_id 51") {
				t.Error("the backup is not the old file")
			}
		}
	}
	if n != 1 {
		t.Errorf("%d backups", n)
	}
	if !strings.Contains(b.read("etc/keepalived/keepalived.conf"), "virtual_router_id 60") {
		t.Error("new config not installed")
	}
}

func TestSandboxStartTimeout(t *testing.T) {
	b, s := readyBackup(t)
	b.set("fail-start", true)
	out, code := b.run(b.script(s, "192.0.2.12/24", -1))
	if code == 0 || !strings.Contains(out, "keepalived did not start") || !strings.Contains(out, "auth_pass (hidden)") {
		t.Fatalf("%d\n%s", code, out)
	}
}

const rulesFile = "*filter\n:ufw-before-input - [0 0]\n-A ufw-before-input -i lo -j ACCEPT\nCOMMIT\n"

func TestSandboxUFW(t *testing.T) {
	t.Run("insert repeat replace", func(t *testing.T) {
		b, s := readyBackup(t)
		b.set("ufw-active", true)
		b.write("etc/ufw/before.rules", rulesFile)
		text := b.script(s, "192.0.2.12/24", -1)
		out, code := b.run(text)
		if code != 0 {
			t.Fatalf("%d\n%s", code, out)
		}
		r := b.read("etc/ufw/before.rules")
		block := "# BEGIN dunree-vip\n-A ufw-before-input -p vrrp -s 192.0.2.11 -j ACCEPT\n# END dunree-vip\nCOMMIT\n"
		if !strings.HasSuffix(r, block) || strings.Count(r, "# BEGIN dunree-vip") != 1 {
			t.Fatalf("rules:\n%s", r)
		}
		if !strings.Contains(b.calls(), "ufw reload") {
			t.Error("no reload")
		}
		backups := func() int {
			n := 0
			for _, f := range b.files() {
				if strings.Contains(f, "before.rules.dunree-backup-") {
					n++
				}
			}
			return n
		}
		if backups() != 1 {
			t.Errorf("%d backups", backups())
		}
		// same again: no change, no reload, no backup
		b.clearCalls()
		b.run(text)
		if strings.Contains(b.calls(), "ufw reload") || backups() != 1 {
			t.Errorf("repeat changed the rules:\n%s", b.calls())
		}
		// other peers: the block is replaced in place
		s2 := s
		s2.Members = append(append([]Member{}, s.Members...), Member{Label: "node-c", Address: "192.0.2.13", Priority: 90})
		b.run(b.script(s2, "192.0.2.12/24", -1))
		r = b.read("etc/ufw/before.rules")
		if strings.Count(r, "# BEGIN dunree-vip") != 1 || !strings.Contains(r, "-s 192.0.2.13 -j ACCEPT") || !strings.Contains(r, "-s 192.0.2.11 -j ACCEPT") {
			t.Errorf("replace:\n%s", r)
		}
	})
	t.Run("reload fails restores", func(t *testing.T) {
		b, s := readyBackup(t)
		b.set("ufw-active", true)
		b.set("ufw-fail", true)
		b.write("etc/ufw/before.rules", rulesFile)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "ufw did not accept the rule") {
			t.Fatalf("%d\n%s", code, out)
		}
		if b.read("etc/ufw/before.rules") != rulesFile {
			t.Error("old rules not restored")
		}
		if hasFile(b, "etc/keepalived/keepalived.conf") {
			t.Error("config installed after the failure")
		}
	})
	t.Run("multicast and v6", func(t *testing.T) {
		b := newSandbox(t)
		b.host("ens18", "2001:db8::12", true, "2001:db8::10")
		b.set("ufw-active", true)
		b.write("etc/ufw/before6.rules", strings.ReplaceAll(rulesFile, "ufw-", "ufw6-"))
		s := fixture6()
		s.Transport = TransportMulticast
		out, code := b.run(b.script(s, "2001:db8::12/64", -1))
		if code != 0 {
			t.Fatalf("%d\n%s", code, out)
		}
		if !strings.Contains(b.read("etc/ufw/before6.rules"), "-A ufw6-before-input -p vrrp -d ff02::12 -j ACCEPT") {
			t.Errorf("rules:\n%s", b.read("etc/ufw/before6.rules"))
		}
	})
	t.Run("inactive ufw is left alone", func(t *testing.T) {
		b, s := readyBackup(t)
		b.write("etc/ufw/before.rules", rulesFile)
		out, _ := b.run(b.script(s, "192.0.2.12/24", -1))
		if b.read("etc/ufw/before.rules") != rulesFile || !strings.Contains(out, "another firewall") {
			t.Errorf("%s", out)
		}
	})
}

func TestSandboxFirewalldAndSysctl(t *testing.T) {
	b, s := readyBackup(t)
	b.set("fwd", true)
	out, code := b.run(b.script(s, "192.0.2.12/24", -1))
	if code != 0 || !strings.Contains(b.calls(), `firewall-cmd --permanent --add-rich-rule=rule protocol value="vrrp" accept`) || !strings.Contains(b.calls(), "firewall-cmd --reload") {
		t.Fatalf("%d\n%s\n%s", code, out, b.calls())
	}
	b.clearCalls()
	b.set("fwd-has", true)
	b.run(b.script(s, "192.0.2.12/24", -1))
	if strings.Contains(b.calls(), "--add-rich-rule") {
		t.Error("rule added twice")
	}
	// ip_nonlocal_bind only when a listener binds the VIP
	if hasFile(b, "etc/sysctl.d/60-dunree-vip.conf") {
		t.Error("sysctl written without need")
	}
	env := envFor("192.0.2.12/24")
	env.Listener.BoundAddr = "192.0.2.10"
	so, err := script(&s, nil, env, -1, nil, b.root)
	if err != nil {
		t.Fatal(err)
	}
	b.run(so.Inner)
	if b.read("etc/sysctl.d/60-dunree-vip.conf") != "net.ipv4.ip_nonlocal_bind = 1\n" || !strings.Contains(b.calls(), "sysctl -p") {
		t.Errorf("sysctl: %q\n%s", b.read("etc/sysctl.d/60-dunree-vip.conf"), b.calls())
	}
}

func TestSandboxWrapper(t *testing.T) {
	b, s := readyBackup(t)
	so, err := script(&s, nil, envFor("192.0.2.12/24"), -1, nil, b.root)
	if err != nil {
		t.Fatal(err)
	}
	// as root: the wrapper feeds the inner script to sh -s
	out, code := b.run(so.Script)
	if code != 0 || !strings.Contains(out, "OK: keepalived is running on node-b") {
		t.Fatalf("%d\n%s", code, out)
	}
	// not root and no sudo: a plain instruction, nothing runs
	b2, s2 := readyBackup(t)
	os.WriteFile(filepath.Join(b2.st, "uid"), []byte("1000\n"), 0o644)
	so2, _ := script(&s2, nil, envFor("192.0.2.12/24"), -1, nil, b2.root)
	out, code = b2.run(so2.Script)
	if code != 0 || !strings.Contains(out, "please log in as root (type: su -)") || hasFile(b2, "etc/keepalived/keepalived.conf") {
		t.Fatalf("%d\n%s", code, out)
	}
}
