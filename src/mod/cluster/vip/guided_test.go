package vip

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests of the review round "Floating IP: simple guided setup": the health
// check address a peer reports, the installer's rollbacks and refusals, and the
// marker that lets an unlinked server report its progress.

func TestValidProbeBase(t *testing.T) {
	const member = "192.0.2.12"
	for _, ok := range []string{"http://127.0.0.1:8081", "https://127.0.0.1:443", "http://[::1]:8081", "http://192.0.2.12:8081", "http://[::ffff:192.0.2.12]:80"} {
		if !ValidProbeBase(ok, member) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{
		"http://evil.example.com:80", "https://203.0.113.7:443", "http://198.51.100.9:8081", // a host name and foreign addresses
		"http://192.0.2.11:8081",                         // another member
		"http://127.0.0.2:8081", "http://localhost:8081", // only 127.0.0.1
		"http://192.0.2.12", "http://192.0.2.12:0", "http://192.0.2.12:65536", "http://192.0.2.12:08081", "http://192.0.2.12:x", // port
		"http://user@192.0.2.12:8081", "http://192.0.2.12:8081/x", "http://192.0.2.12:8081?a=b", "http://192.0.2.12:8081#f",
		"ftp://192.0.2.12:8081", "//192.0.2.12:8081", "", "http://[fe80::1%25eth0]:8081",
	} {
		if ValidProbeBase(bad, member) {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A peer that reports a foreign health check address never reaches a script or
// a keepalived.conf: the member script is blocked, not rendered.
func TestPeerProbeBaseOnlyItsOwn(t *testing.T) {
	for _, base := range []string{"http://evil.example.com:80", "https://203.0.113.7:443", "http://198.51.100.9:8081", "http://192.0.2.11:8081"} {
		s := fixture4()
		_, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, &PeerFacts{Iface: "ens18", ProbeBase: base})
		var be *BlockedError
		if !errors.As(err, &be) {
			t.Fatalf("%s: want a BlockedError, got %v", base, err)
		}
	}
	s := fixture4()
	so, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, &PeerFacts{Iface: "ens18", ProbeBase: "http://192.0.2.12:8081"})
	if err != nil || !strings.Contains(so.Conf, "http://192.0.2.12:8081/.dunree/health") {
		t.Fatalf("a member's own address must be accepted: %v", err)
	}
}

func TestScriptGuardsAreIPOnly(t *testing.T) {
	if reScriptProbe.MatchString("http://evil.example.com:80/.dunree/health") || reScriptProbe.MatchString("http://127.0.0.1/.dunree/health") {
		t.Error("the script variable accepts a host name or no port")
	}
	if !reScriptProbe.MatchString("http://[::1]:8081/.dunree/health") || !reScriptProbe.MatchString("https://192.0.2.12:443/.dunree/health") {
		t.Error("the script variable refuses an IP literal")
	}
	if err := checkScript("/usr/bin/curl -fsS --max-time 2 -o /dev/null http://evil.example.com:80/.dunree/health"); err == nil {
		t.Error("checkScript accepts a host name")
	}
	if err := checkScript("/usr/bin/curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8081/.dunree/health"); err != nil {
		t.Error(err)
	}
}

// The script made on one page for a member and the script that member makes for
// itself carry the same priority, and both say that an override is in play.
func TestPeerPriorityMatchesSelf(t *testing.T) {
	s := fixture4()
	s.Main = "192.0.2.11"
	ApplyMain(&s)
	// on node-b: its own override
	l := Local{PriorityOverride: 200}
	self, err := Script(&s, &l, envFor("192.0.2.12/24"), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	// on node-a: the script for node-b, told about the override by node-b
	peer, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, &PeerFacts{Iface: "ens18", ProbeBase: "http://127.0.0.1:8081", Priority: 200})
	if err != nil {
		t.Fatal(err)
	}
	for name, so := range map[string]*ScriptOutput{"self": self, "peer": peer} {
		if !strings.Contains(so.Conf, "priority 200") || so.Role != "Main server" {
			t.Errorf("%s: priority/role: %s", name, so.Role)
		}
		if !strings.Contains(strings.Join(so.Warnings, "|"), "has its own priority") && !strings.Contains(strings.Join(so.Warnings, "|"), "its own priority (200)") {
			t.Errorf("%s: no warning about the override: %v", name, so.Warnings)
		}
	}
	// without an override nothing is said and the shared numbers apply
	plain, err := Script(&s, nil, envFor("192.0.2.12/24"), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(plain.Warnings, "|"), "own priority") || !strings.Contains(plain.Conf, "priority 100") {
		t.Errorf("plain: %v", plain.Warnings)
	}
	// out of range numbers from a peer are ignored
	bad, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, &PeerFacts{Iface: "ens18", Priority: 999})
	if err != nil || !strings.Contains(bad.Conf, "priority 100") {
		t.Errorf("a priority outside 1..254 must be ignored: %v", err)
	}
}

// The password is in the paste. The command line starts with a space so bash
// with HISTCONTROL=ignorespace keeps none of it.
func TestWrappedPasteStartsWithSpace(t *testing.T) {
	s := fixture4()
	so, err := Script(&s, nil, envFor("192.0.2.12/24"), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for _, line := range strings.Split(so.Script, "\n") {
		if !strings.HasPrefix(line, "#") {
			first = line
			break
		}
	}
	if !strings.HasPrefix(first, " if [") {
		t.Errorf("the first command line must start with one space, got %q", first)
	}
	if strings.HasPrefix(so.Inner, " ") {
		t.Error("the downloaded file must not start with a space")
	}
	if strings.Contains(so.Script, "sudo password") {
		t.Error("the script comment must not talk about a sudo password")
	}
}

func TestMarkerCarriesFloatingIPAndPeers(t *testing.T) {
	m, ok := ParseMarker([]byte("fingerprint=3f9a1c2e\nmember=192.0.2.12\nvip=192.0.2.10\npeers=192.0.2.11 192.0.2.13\n"))
	if !ok || m.VIP != "192.0.2.10" || len(m.Peers) != 2 || m.Peers[0] != "192.0.2.11" {
		t.Fatalf("%+v", m)
	}
	m, _ = ParseMarker([]byte("fingerprint=3f9a1c2e\nvip=evil.example\npeers=x 192.0.2.11 y\n"))
	if m.VIP != "" || len(m.Peers) != 1 {
		t.Errorf("only addresses may pass: %+v", m)
	}
	// the script writes both
	b, s := readyBackup(t)
	b.run(b.script(s, "192.0.2.12/24", -1))
	mk, ok := ReadMarker(filepath.Join(b.root, "etc/keepalived/dunree-installed"))
	if !ok || mk.VIP != "192.0.2.10" || len(mk.Peers) != 1 || mk.Peers[0] != "192.0.2.11" || strings.Contains(b.read("etc/keepalived/dunree-installed"), testPass) {
		t.Errorf("script marker: %+v", mk)
	}
}

func TestNodeStateUnlinkedAndStoppedProxy(t *testing.T) {
	base := NodeFacts{Reachable: true, KeepalivedBin: true, Installed: true, InstalledFP: "aaaaaaaa", CurrentFP: "aaaaaaaa", KeepalivedUp: Yes, SomeoneHolds: true}
	f := NodeFacts{Reachable: true, NoBlock: true, CurrentFP: "aaaaaaaa"}
	if got := NodeState(f); got != NodeUnknown {
		t.Errorf("a server that answers without a floating IP block must be unknown, not waiting: %s", got)
	}
	f.Installed, f.KeepalivedBin, f.InstalledFP = true, true, "aaaaaaaa"
	f.NoBlock = false
	f.KeepalivedUp = Yes
	if got := NodeState(f); got != NodeFault {
		t.Errorf("sanity: %s", got)
	}
	// 503: the proxy of that server is stopped, so it is a fault, not "standing by"
	p := base
	p.ProbeOK = No
	if got := NodeState(p); got != NodeFault {
		t.Errorf("stopped proxy: %s", got)
	}
	p.Held = true
	if got := NodeState(p); got != NodeHolding {
		t.Errorf("a server that still holds the address is holding: %s", got)
	}
	// the answer is the same for the marker of an unlinked server (installed, no block fields missing)
	u := base
	u.NoBlock = true
	if got := NodeState(u); got != NodeStandby {
		t.Errorf("a server with a marker is judged by it: %s", got)
	}
}

// ---- the installer's refusals and rollbacks, run in the sandbox ----

func TestSandboxForeignKeepalivedConf(t *testing.T) {
	const own = "vrrp_instance DB {\n  state MASTER\n  interface ens18\n}\n"
	b, s := readyBackup(t)
	b.write("etc/keepalived/keepalived.conf", own)
	b.set("active", true)
	out, code := b.run(b.script(s, "192.0.2.12/24", -1))
	if code == 0 || !strings.Contains(out, "already has its own keepalived setup") || !strings.Contains(out, "Your previous keepalived setup was not changed") {
		t.Fatalf("%d\n%s", code, out)
	}
	if b.read("etc/keepalived/keepalived.conf") != own || strings.Contains(b.calls(), "restart") || strings.Contains(b.calls(), "apt-get") {
		t.Errorf("something was changed: %s", b.calls())
	}
	if len(b.files()) != 2 { // os-release and the foreign conf
		t.Errorf("files: %v", b.files())
	}
	// a file Dunree made is replaced as before, and an empty one counts as none
	b2, s2 := readyBackup(t)
	b2.write("etc/keepalived/keepalived.conf", "# Generated by Dunree 1.0.0 for member \"node-b\" (192.0.2.12). Settings fingerprint: 11111111\nold\n")
	if out, code := b2.run(b2.script(s2, "192.0.2.12/24", -1)); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	b3, s3 := readyBackup(t)
	b3.write("etc/keepalived/keepalived.conf", "")
	if out, code := b3.run(b3.script(s3, "192.0.2.12/24", -1)); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestSandboxFloatingIPAlreadyUsed(t *testing.T) {
	t.Run("the router's address", func(t *testing.T) {
		b, s := readyBackup(t)
		os.WriteFile(filepath.Join(b.st, "ip-route4.txt"), []byte("default via 192.0.2.10 dev ens18 proto dhcp metric 100\n"), 0o644)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "is the address of your router") || !strings.Contains(out, "previous keepalived setup was not changed") {
			t.Fatalf("%d\n%s", code, out)
		}
		if hasFile(b, "etc/keepalived/keepalived.conf") || strings.Contains(b.calls(), "systemctl restart") {
			t.Error("the script went on")
		}
	})
	t.Run("the router's IPv6 address", func(t *testing.T) {
		b := newSandbox(t)
		b.host("ens18", "2001:db8::12", true, "2001:db8::10")
		os.WriteFile(filepath.Join(b.st, "ip-route6.txt"), []byte("default via 2001:db8::10 dev ens18 proto ra metric 1024\n"), 0o644)
		s := fixture6()
		out, code := b.run(b.script(s, "2001:db8::12/64", -1))
		if code == 0 || !strings.Contains(out, "is the address of your router") {
			t.Fatalf("%d\n%s", code, out)
		}
	})
	t.Run("another router is fine", func(t *testing.T) {
		b, s := readyBackup(t)
		os.WriteFile(filepath.Join(b.st, "ip-route4.txt"), []byte("default via 192.0.2.1 dev ens18\n"), 0o644)
		if out, code := b.run(b.script(s, "192.0.2.12/24", -1)); code != 0 {
			t.Fatalf("%d\n%s", code, out)
		}
	})
	t.Run("already on this server and keepalived is not running", func(t *testing.T) {
		b, s := readyBackup(t)
		b.host("ens18", "192.0.2.12", false, "192.0.2.10")
		os.WriteFile(b.ipFile, append([]byte(b.read0(b.ipFile)), []byte("2: ens18    inet 192.0.2.10/24 scope global secondary ens18\n")...), 0o644)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "already set on this server") {
			t.Fatalf("%d\n%s", code, out)
		}
		// when keepalived runs and holds it, a repeated run is normal
		b.set("active", true)
		if out, code := b.run(b.script(s, "192.0.2.12/24", -1)); code != 0 {
			t.Fatalf("a running keepalived may hold the floating IP: %d\n%s", code, out)
		}
	})
}

func (b *sandbox) read0(abs string) string {
	d, _ := os.ReadFile(abs)
	return string(d)
}

const natFirst = "*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/24 -o ens18 -j MASQUERADE\nCOMMIT\n\n*filter\n:ufw-before-input - [0 0]\n-A ufw-before-input -i lo -j ACCEPT\nCOMMIT\n"

func TestSandboxUFWFilterSectionOnly(t *testing.T) {
	b, s := readyBackup(t)
	b.set("ufw-active", true)
	b.write("etc/ufw/before.rules", natFirst)
	out, code := b.run(b.script(s, "192.0.2.12/24", -1))
	if code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	r := b.read("etc/ufw/before.rules")
	nat, filter, _ := strings.Cut(r, "*filter")
	if strings.Contains(nat, "vrrp") || !strings.Contains(filter, "-A ufw-before-input -p vrrp -s 192.0.2.11 -j ACCEPT") {
		t.Fatalf("the rule must land in the filter table only:\n%s", r)
	}
	if strings.Count(b.calls(), "ufw reload") != 1 {
		t.Errorf("reloads:\n%s", b.calls())
	}
	// no filter table at all: the rule is not added and the script goes on
	b2, s2 := readyBackup(t)
	b2.set("ufw-active", true)
	b2.write("etc/ufw/before.rules", "*nat\nCOMMIT\n")
	out, code = b2.run(b2.script(s2, "192.0.2.12/24", -1))
	if code != 0 || b2.read("etc/ufw/before.rules") != "*nat\nCOMMIT\n" || !strings.Contains(out, "Could not find the end of the filter rules") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestSandboxUFWRollbackReloadsAgain(t *testing.T) {
	// the first reload fails (the new rule), the second (the old rules) works
	b, s := readyBackup(t)
	b.set("ufw-active", true)
	os.WriteFile(filepath.Join(b.st, "ufw-fail"), []byte("1"), 0o644)
	b.write("etc/ufw/before.rules", rulesFile)
	out, code := b.run(b.script(s, "192.0.2.12/24", -1))
	if code == 0 || !strings.Contains(out, "put back and ufw was reloaded") || strings.Contains(out, "could not load your old rules") {
		t.Fatalf("%d\n%s", code, out)
	}
	if b.read("etc/ufw/before.rules") != rulesFile || strings.Count(b.calls(), "ufw reload") != 2 {
		t.Errorf("rules restored: %v, reloads:\n%s", b.read("etc/ufw/before.rules") == rulesFile, b.calls())
	}
	// both reloads fail: the script says so plainly and names the command
	b2, s2 := readyBackup(t)
	b2.set("ufw-active", true)
	b2.set("ufw-fail", true)
	b2.write("etc/ufw/before.rules", rulesFile)
	out, code = b2.run(b2.script(s2, "192.0.2.12/24", -1))
	if code == 0 || strings.Contains(out, "put back and ufw was reloaded") || !strings.Contains(out, "ufw reload") || !strings.Contains(out, "could not load your old rules") {
		t.Fatalf("%d\n%s", code, out)
	}
	if b2.read("etc/ufw/before.rules") != rulesFile {
		t.Error("the file on disk must still be the old one")
	}
}

const generatedOld = "# Generated by Dunree 1.0.0 for member \"node-b\" (192.0.2.12). Settings fingerprint: 11111111\nvrrp_instance VI_DUNREE {\n  priority 100\n  auth_pass OldPass12\n}\n"

func TestSandboxFailedStartPutsOldSetupBack(t *testing.T) {
	t.Run("old setup and keepalived was running", func(t *testing.T) {
		b, s := readyBackup(t)
		b.write("etc/keepalived/keepalived.conf", generatedOld)
		b.set("active", true)
		os.WriteFile(filepath.Join(b.st, "fail-start"), []byte("1"), 0o644) // the new setup fails once, the old one starts
		s.VRID = 77
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "keepalived did not start") || !strings.Contains(out, "Your previous keepalived setup was put back and restarted.") {
			t.Fatalf("%d\n%s", code, out)
		}
		if b.read("etc/keepalived/keepalived.conf") != generatedOld {
			t.Errorf("the old file is not back:\n%s", b.read("etc/keepalived/keepalived.conf"))
		}
		if !hasFile0(filepath.Join(b.st, "active")) {
			t.Error("keepalived must run again")
		}
		if strings.Contains(b.calls(), "systemctl enable") || hasFile(b, "etc/keepalived/dunree-installed") {
			t.Errorf("a failed start must not enable or mark anything:\n%s", b.calls())
		}
		if strings.Contains(out, "OldPass12") {
			t.Error("the old password was printed")
		}
	})
	t.Run("old setup and keepalived was stopped", func(t *testing.T) {
		b, s := readyBackup(t)
		b.write("etc/keepalived/keepalived.conf", generatedOld)
		b.set("fail-start", true)
		s.VRID = 77
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "Your previous keepalived setup was put back.") || strings.Contains(out, "and restarted") {
			t.Fatalf("%d\n%s", code, out)
		}
		if b.read("etc/keepalived/keepalived.conf") != generatedOld || hasFile0(filepath.Join(b.st, "active")) {
			t.Error("the old file must be back and keepalived must stay stopped")
		}
	})
	t.Run("no old setup", func(t *testing.T) {
		b, s := readyBackup(t)
		b.set("fail-start", true)
		out, code := b.run(b.script(s, "192.0.2.12/24", -1))
		if code == 0 || !strings.Contains(out, "The new keepalived setup was removed again") {
			t.Fatalf("%d\n%s", code, out)
		}
		if hasFile(b, "etc/keepalived/keepalived.conf") || hasFile(b, "etc/keepalived/dunree-installed") || strings.Contains(b.calls(), "systemctl enable") {
			t.Errorf("nothing of the new setup may stay: %v\n%s", b.files(), b.calls())
		}
	})
	t.Run("a good start enables only after it started", func(t *testing.T) {
		b, s := readyBackup(t)
		b.run(b.script(s, "192.0.2.12/24", -1))
		c := b.calls()
		if strings.Index(c, "systemctl restart keepalived") < 0 || strings.Index(c, "systemctl enable keepalived") < strings.Index(c, "systemctl restart keepalived") {
			t.Errorf("order:\n%s", c)
		}
	})
}

func hasFile0(abs string) bool {
	_, err := os.Stat(abs)
	return err == nil
}
