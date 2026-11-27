package vip

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func gen(t *testing.T, s Shared, l *Local, env *Env, member int) *Output {
	t.Helper()
	o, err := Generate(&s, l, env, member)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return o
}

func TestGoldenMasterAndBackup(t *testing.T) {
	s := fixture4()
	golden(t, "v4_master_unicast", gen(t, s, nil, envFor("192.0.2.11/24"), -1).KeepalivedConf)
	golden(t, "v4_backup_unicast", gen(t, s, nil, envFor("192.0.2.12/24"), -1).KeepalivedConf)
}

func TestGoldenPreemptOff(t *testing.T) {
	s := fixture4()
	s.Preempt = false
	for _, h := range []struct{ addr, name string }{{"192.0.2.11/24", "v4_nopreempt_a"}, {"192.0.2.12/24", "v4_nopreempt_b"}} {
		o := gen(t, s, nil, envFor(h.addr), -1)
		if strings.Contains(o.KeepalivedConf, "state MASTER") || !strings.Contains(o.KeepalivedConf, "nopreempt") || strings.Contains(o.KeepalivedConf, "preempt_delay") {
			t.Errorf("preempt=false must give BACKUP + nopreempt and no preempt_delay:\n%s", o.KeepalivedConf)
		}
		golden(t, h.name, o.KeepalivedConf)
	}
}

func TestGoldenMulticastAndNoAuth(t *testing.T) {
	s := fixture4()
	s.Transport, s.Auth, s.Password = TransportMulticast, AuthNone, ""
	o := gen(t, s, nil, envFor("192.0.2.11/24"), -1)
	if strings.Contains(o.KeepalivedConf, "unicast") || strings.Contains(o.KeepalivedConf, "authentication") {
		t.Errorf("multicast + no auth must omit unicast and authentication:\n%s", o.KeepalivedConf)
	}
	golden(t, "v4_multicast_noauth", o.KeepalivedConf)
}

func TestGoldenIPv6(t *testing.T) {
	s := fixture6()
	for _, h := range []struct{ addr, name string }{{"2001:db8::11/64", "v6_master"}, {"2001:db8::12/64", "v6_backup"}} {
		env := envFor(h.addr)
		o := gen(t, s, nil, env, -1)
		c := o.KeepalivedConf
		if !strings.Contains(c, "vrrp_version 3") || !strings.Contains(c, "native_ipv6") || strings.Contains(c, "authentication") || !strings.Contains(c, "VI_DUNREE6") {
			t.Errorf("IPv6 needs VRRPv3, native_ipv6 and no authentication:\n%s", c)
		}
		if !strings.Contains(c, "http://127.0.0.1:8081/.dunree/health") || strings.Contains(c, "::1]") {
			t.Errorf("the loopback probe is IPv4 whatever the VIP family:\n%s", c)
		}
		golden(t, h.name, c)
	}
}

func TestClusterAuthDerivedPassword(t *testing.T) {
	s := fixture4()
	s.Auth, s.Password = AuthCluster, ""
	env := envFor("192.0.2.11/24")
	if _, err := Generate(&s, nil, env, -1); err == nil {
		t.Fatal("auth=cluster without a generated cluster password must block")
	}
	s.ClusterPass = "Zq81LmPx"
	o := gen(t, s, nil, env, -1)
	if !strings.Contains(o.KeepalivedConf, "auth_pass Zq81LmPx") {
		t.Errorf("derived password missing:\n%s", o.KeepalivedConf)
	}
	golden(t, "v4_cluster_auth", o.KeepalivedConf)
}

func TestHealthTargetBranches(t *testing.T) {
	cases := []struct {
		name string
		f    ListenerFacts
		l    *Local
		want string
		k    bool
	}{
		{"health_port", ListenerFacts{HealthPort: ":8081", Port80: true, InboundPort: 443, TLS: true}, nil, "http://127.0.0.1:8081/.dunree/health", false},
		{"health_port_bound", ListenerFacts{HealthPort: "192.0.2.11:8081"}, nil, "http://192.0.2.11:8081/.dunree/health", false},
		{"port80", ListenerFacts{Port80: true, InboundPort: 443, TLS: true}, nil, "http://127.0.0.1:80/.dunree/health", false},
		{"port80_custom", ListenerFacts{Port80: true, TLS: true, InboundPort: 443, HTTPPort: 8080}, nil, "http://127.0.0.1:8080/.dunree/health", false},
		{"port80_plain_http_proxy", ListenerFacts{Port80: true, InboundPort: 8443}, nil, "http://127.0.0.1:8443/.dunree/health", false},
		{"tls", ListenerFacts{InboundPort: 443, TLS: true}, nil, "https://127.0.0.1:443/.dunree/health", true},
		{"plain", ListenerFacts{InboundPort: 8443}, nil, "http://127.0.0.1:8443/.dunree/health", false},
		{"override", ListenerFacts{HealthPort: ":8081"}, &Local{HealthTarget: "https://127.0.0.1:9443"}, "https://127.0.0.1:9443/.dunree/health", true},
	}
	for _, c := range cases {
		env := envFor("192.0.2.11/24")
		env.Listener = c.f
		o := gen(t, fixture4(), c.l, env, -1)
		if o.HealthURL != c.want {
			t.Errorf("%s: health url %q, want %q", c.name, o.HealthURL, c.want)
		}
		if got := strings.Contains(o.KeepalivedConf, " -k "); got != c.k {
			t.Errorf("%s: -k = %v, want %v", c.name, got, c.k)
		}
		golden(t, "health_"+c.name, o.KeepalivedConf)
	}
}

func TestBlockers(t *testing.T) {
	cases := []struct {
		name string
		mut  func(e *Env)
		want string
	}{
		{"health disabled", func(e *Env) { e.Listener.HealthDisabled = true }, "switched off"},
		{"allow list excludes loopback", func(e *Env) { e.Listener.HealthAllow = []string{"198.51.100.0/24"} }, "allow-list"},
		{"health bound to the vip", func(e *Env) { e.Listener.HealthPort = "192.0.2.10:8081" }, "floating IP"},
		{"not a member", func(e *Env) { e.Interfaces = nil }, "not a member"},
		{"health_port host with spaces", func(e *Env) { e.Listener.HealthPort = "127.0.0.1/ -o /etc/cron.d/dunree:8081" }, "not an IP address"},
		{"health_port host name", func(e *Env) { e.Listener.HealthPort = "evil.example:8081" }, "not an IP address"},
		{"reject unknown sni on the tls probe", func(e *Env) {
			e.Listener = ListenerFacts{InboundPort: 443, TLS: true, RejectUnknownSNI: true}
		}, "-health_port"},
	}
	for _, c := range cases {
		env := envFor("192.0.2.11/24")
		c.mut(env)
		_, err := Generate(ptr(fixture4()), nil, env, -1)
		var be *BlockedError
		if !errors.As(err, &be) || !strings.Contains(be.Error(), c.want) {
			t.Errorf("%s: err = %v, want a blocker containing %q", c.name, err, c.want)
		}
	}
	// the allow-list admits loopback: no blocker
	env := envFor("192.0.2.11/24")
	env.Listener.HealthAllow = []string{"127.0.0.1"}
	if _, err := Generate(ptr(fixture4()), nil, env, -1); err != nil {
		t.Errorf("allow-list with 127.0.0.1 must pass: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestOtherMemberWarnings(t *testing.T) {
	o := gen(t, fixture4(), nil, envFor("192.0.2.11/24"), 1)
	if !strings.Contains(o.KeepalivedConf, "priority 100") || !strings.Contains(o.KeepalivedConf, "state BACKUP") || !strings.Contains(o.KeepalivedConf, "unicast_src_ip 192.0.2.12") {
		t.Errorf("config for node-b wrong:\n%s", o.KeepalivedConf)
	}
	if len(o.Warnings) == 0 {
		t.Error("generating for another member must warn about interface and health target")
	}
	s := fixture4()
	s.Members[1].InterfaceHint = "eth0"
	o = gen(t, s, nil, envFor("192.0.2.11/24"), 1)
	if !strings.Contains(o.KeepalivedConf, "interface eth0") {
		t.Errorf("interface hint not used:\n%s", o.KeepalivedConf)
	}
	if _, err := Generate(ptr(fixture4()), nil, envFor("192.0.2.11/24"), 7); err == nil {
		t.Error("unknown member index must fail")
	}
}

func TestLocalOverrides(t *testing.T) {
	l := &Local{Interface: "bond0", PriorityOverride: 90}
	o := gen(t, fixture4(), l, envFor("192.0.2.11/24"), -1)
	c := o.KeepalivedConf
	if !strings.Contains(c, "interface bond0") || !strings.Contains(c, "priority 90") || !strings.Contains(c, "state BACKUP") {
		t.Errorf("overrides not applied (a demoted node must be BACKUP):\n%s", c)
	}
}

func TestInstallCommandsAndSysctl(t *testing.T) {
	o := gen(t, fixture4(), nil, envFor("192.0.2.11/24"), -1)
	for _, want := range []string{"sudo apt update", "sudo apt install -y keepalived curl", "<<'DUNREE_EOF'",
		"sudo keepalived -t -f /etc/keepalived/keepalived.conf && sudo systemctl enable keepalived && sudo systemctl restart keepalived\n"} {
		if !strings.Contains(o.InstallCommands, want) {
			t.Errorf("install commands miss %q", want)
		}
	}
	// the config test, enable and restart are one chain: a failed test must not start keepalived
	for _, line := range strings.Split(o.InstallCommands, "\n") {
		if (strings.HasPrefix(line, "sudo systemctl") || strings.HasPrefix(line, "sudo keepalived")) && !strings.HasPrefix(line, "sudo keepalived -t") {
			t.Errorf("systemctl on its own line: %q", line)
		}
	}
	if o.Sysctl != "" || o.FirewallNote != "" {
		t.Error("sysctl and ufw notes only when needed")
	}
	// heredoc delimiter appears exactly twice: open and close
	if n := strings.Count(o.InstallCommands, "DUNREE_EOF"); n != 2 {
		t.Errorf("DUNREE_EOF appears %d times", n)
	}
	for _, line := range strings.Split(o.KeepalivedConf, "\n") {
		if strings.TrimSpace(line) == "DUNREE_EOF" {
			t.Error("a generated line equals the heredoc delimiter")
		}
	}
	env := envFor("192.0.2.11/24")
	env.Listener.BoundAddr = "192.0.2.10"
	env.UFWEnabled = true
	o = gen(t, fixture4(), nil, env, -1)
	if !strings.Contains(o.Sysctl, "net.ipv4.ip_nonlocal_bind = 1") || !strings.Contains(o.FirewallNote, "-p vrrp -s 192.0.2.12") {
		t.Errorf("sysctl %q / ufw %q", o.Sysctl, o.FirewallNote)
	}
	env.Listener.BoundAddr = "2001:db8::10"
	s := fixture6()
	env = envFor("2001:db8::11/64")
	env.Listener.BoundAddr = "2001:db8::10"
	o = gen(t, s, nil, env, -1)
	if !strings.Contains(o.Sysctl, "net.ipv6.ip_nonlocal_bind") {
		t.Errorf("v6 sysctl %q", o.Sysctl)
	}
}

func TestFingerprintStableAndSensitive(t *testing.T) {
	a, b := fixture4(), fixture4()
	if Fingerprint(&a, "x") != Fingerprint(&b, "x") {
		t.Error("fingerprint must be stable")
	}
	b.VRID = 52
	if Fingerprint(&a, "x") == Fingerprint(&b, "x") || Fingerprint(&a, "x") == Fingerprint(&a, "y") {
		t.Error("fingerprint must change with settings and password")
	}
}

func TestDeterministic(t *testing.T) {
	a := gen(t, fixture4(), nil, envFor("192.0.2.11/24"), -1)
	b := gen(t, fixture4(), nil, envFor("192.0.2.11/24"), -1)
	if a.KeepalivedConf != b.KeepalivedConf || a.InstallCommands != b.InstallCommands {
		t.Error("output must be deterministic")
	}
}

func TestNeverMasterWithPreemptDelay(t *testing.T) {
	for _, s := range []Shared{fixture4(), fixture6()} {
		for _, addr := range []string{"192.0.2.11/24", "192.0.2.12/24", "2001:db8::11/64", "2001:db8::12/64"} {
			if (s.VIP[0] == '2') != (addr[0] == '2') {
				continue
			}
			for _, delay := range []int{0, 60} {
				s.PreemptDelay = delay
				c := gen(t, s, nil, envFor(addr), -1).KeepalivedConf
				if strings.Contains(c, "state MASTER") && strings.Contains(c, "preempt_delay") {
					t.Errorf("state MASTER with preempt_delay is ignored by keepalived:\n%s", c)
				}
				if delay > 0 && !strings.Contains(c, "state BACKUP") {
					t.Errorf("preempt_delay needs the initial state BACKUP:\n%s", c)
				}
				if !strings.Contains(c, "    init_fail\n") {
					t.Errorf("the health script needs init_fail:\n%s", c)
				}
			}
		}
	}
}

func TestScriptGuard(t *testing.T) {
	good := []string{
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8081/.dunree/health",
		"/usr/bin/curl -fsS --max-time 2 -k -o /dev/null https://127.0.0.1:443/.dunree/health",
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null http://[::1]:8081/.dunree/health",
	}
	for _, g := range good {
		if err := checkScript(g); err != nil {
			t.Errorf("%q: %v", g, err)
		}
	}
	bad := []string{
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null http://127.0.0.1/ -o /etc/cron.d/dunree:8081/.dunree/health",
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8081/.dunree/health extra",
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null  http://127.0.0.1:8081/.dunree/health",
		"/usr/bin/curl -fsS --max-time 2 -K -o /dev/null http://127.0.0.1:8081/.dunree/health",
		"/usr/bin/curl -fsS --max-time x -o /dev/null http://127.0.0.1:8081/.dunree/health",
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null file:///etc/passwd",
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8081/other",
		"/usr/bin/curl -fsS --max-time 2 -o /dev/null http://u@127.0.0.1:8081/.dunree/health",
		"/bin/sh -c x",
	}
	for _, b := range bad {
		if checkScript(b) == nil {
			t.Errorf("guard accepted %q", b)
		}
	}
}

func TestUFWNoteIPv6(t *testing.T) {
	env := envFor("2001:db8::11/64")
	env.UFWEnabled = true
	o := gen(t, fixture6(), nil, env, -1)
	n := o.FirewallNote
	if !strings.Contains(n, "/etc/ufw/before6.rules") || !strings.Contains(n, "-A ufw6-before-input -p vrrp -s 2001:db8::12 -j ACCEPT") || strings.Contains(n, "ufw-before-input -p") && !strings.Contains(n, "ufw6-before-input") {
		t.Errorf("v6 unicast note:\n%s", n)
	}
	s := fixture6()
	s.Transport = TransportMulticast
	n = gen(t, s, nil, env, -1).FirewallNote
	if !strings.Contains(n, "-d ff02::12") || strings.Contains(n, "224.0.0.18") {
		t.Errorf("v6 multicast note:\n%s", n)
	}
	env = envFor("192.0.2.11/24")
	env.UFWEnabled = true
	n = gen(t, fixture4(), nil, env, -1).FirewallNote
	if !strings.Contains(n, "/etc/ufw/before.rules") || strings.Contains(n, "before6") {
		t.Errorf("v4 note changed:\n%s", n)
	}
}

func TestFingerprintHidesPassword(t *testing.T) {
	a := fixture4()
	fp := Fingerprint(&a, "Xb7kQ2mT")
	if strings.Contains(fp, "Xb7k") || len(fp) != 8 {
		t.Errorf("fingerprint %q", fp)
	}
	// the stored secrets are not part of the settings part
	b := fixture4()
	b.Password, b.ClusterPass = "other123", "zzzzzzzz"
	if Fingerprint(&a, "p") != Fingerprint(&b, "p") {
		t.Error("only the effective password may feed the fingerprint")
	}
}

// TestKeepalivedAcceptsGolden runs the real keepalived config test over every
// golden file when a binary is available (PATH or $KEEPALIVED_BIN). The
// unit test host usually has none, so it skips.
func TestKeepalivedAcceptsGolden(t *testing.T) {
	bin := os.Getenv("KEEPALIVED_BIN")
	if bin == "" {
		p, err := exec.LookPath("keepalived")
		if err != nil {
			t.Skip("no keepalived binary (set KEEPALIVED_BIN to run the config test)")
		}
		bin = p
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "*.golden"))
	if len(files) == 0 {
		t.Fatal("no golden files")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		conf := strings.Replace(string(raw), "script_user keepalived_script", "script_user "+u.Username, 1)
		tmp := filepath.Join(t.TempDir(), "keepalived.conf")
		if err := os.WriteFile(tmp, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "-t", "-f", tmp).CombinedOutput()
		if err != nil || strings.Contains(string(out), "Warning") {
			t.Errorf("%s: keepalived -t: %v\n%s", filepath.Base(f), err, out)
		}
	}
}
