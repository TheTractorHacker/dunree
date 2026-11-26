package vip

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tmpPaths(t *testing.T) Paths {
	d := t.TempDir()
	return Paths{
		KeepalivedBins: []string{filepath.Join(d, "sbin", "keepalived")},
		EnabledLink:    filepath.Join(d, "wants", "keepalived.service"),
		PidFile:        filepath.Join(d, "run", "keepalived.pid"),
		ProcDir:        filepath.Join(d, "proc"),
		ConfFile:       filepath.Join(d, "etc", "keepalived.conf"),
		ARPFile:        filepath.Join(d, "arp"),
		UFWConf:        filepath.Join(d, "ufw.conf"),
	}
}

func write(t *testing.T, path, data string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStatusNothingInstalled(t *testing.T) {
	s := fixture4()
	p := tmpPaths(t)
	st := ReadStatus(&s, nil, fakeLister{ifs: envFor("192.0.2.11/24").Interfaces}, p, envFor("192.0.2.11/24"))
	if st.Held || !st.IsMember || st.Interface != "ens18" || st.Prefix != 24 || st.MemberLabel != "node-a" {
		t.Errorf("%+v", st)
	}
	if st.KeepalivedFound != No || st.KeepalivedOn != No || st.KeepalivedUp != No || st.ConfigMatches != Unknown {
		t.Errorf("%+v", st)
	}
}

func TestStatusHeldAndRunning(t *testing.T) {
	s := fixture4()
	env := envFor("192.0.2.11/24")
	env.Interfaces[1].Addrs = append(env.Interfaces[1].Addrs, pfx("192.0.2.10/24"))
	p := tmpPaths(t)
	write(t, p.KeepalivedBins[0], "x")
	write(t, p.EnabledLink, "")
	write(t, p.PidFile, "1234\n")
	write(t, filepath.Join(p.ProcDir, "1234", "comm"), "keepalived\n")
	conf := gen(t, s, nil, env, -1)
	write(t, p.ConfFile, conf.KeepalivedConf)
	st := ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, p, env)
	if !st.Held || st.HeldInterface != "ens18" || st.KeepalivedFound != Yes || st.KeepalivedOn != Yes || st.KeepalivedUp != Yes || st.ConfigMatches != Yes {
		t.Errorf("%+v", st)
	}
	// settings changed since generation
	s.VRID = 77
	st = ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, p, env)
	if st.ConfigMatches != No {
		t.Errorf("a changed setting must show a mismatch: %+v", st)
	}
	// pid of another program
	write(t, filepath.Join(p.ProcDir, "1234", "comm"), "sshd\n")
	if st = ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, p, env); st.KeepalivedUp != No {
		t.Errorf("a pid that is not keepalived: %+v", st)
	}
	// garbage pid file is unknown, never an error
	write(t, p.PidFile, "abc")
	if st = ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, p, env); st.KeepalivedUp != Unknown {
		t.Errorf("garbage pid: %+v", st)
	}
}

func TestStatusNotMemberAndListError(t *testing.T) {
	s := fixture4()
	env := envFor("198.51.100.5/24")
	st := ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, tmpPaths(t), env)
	if st.IsMember {
		t.Error("not a member")
	}
	st = ReadStatus(&s, nil, fakeLister{err: errors.New("boom")}, tmpPaths(t), env)
	if st.Error == "" {
		t.Error("interface error must be reported as a line, not a failure")
	}
}

func TestStatusUnreadableConfIsUnknown(t *testing.T) {
	s := fixture4()
	env := envFor("192.0.2.11/24")
	p := tmpPaths(t)
	write(t, p.ConfFile, "# hand written, no fingerprint\n")
	st := ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, p, env)
	if st.ConfigMatches != Unknown {
		t.Errorf("%+v", st)
	}
}

func TestUFWAndReaderCache(t *testing.T) {
	p := tmpPaths(t)
	write(t, p.UFWConf, "# c\nENABLED=yes\n")
	if !ReadUFWEnabled(p.UFWConf) {
		t.Error("ufw enabled not read")
	}
	write(t, p.UFWConf, "ENABLED=no\n")
	if ReadUFWEnabled(p.UFWConf) || ReadUFWEnabled("/nonexistent") {
		t.Error("ufw disabled misread")
	}
	now := time.Unix(1000, 0)
	r := &Reader{Now: func() time.Time { return now }}
	n := 0
	build := func() Status { n++; return Status{Held: n > 1} }
	r.Get(build)
	r.Get(build)
	if n != 1 {
		t.Errorf("cache miss within the TTL: %d", n)
	}
	now = now.Add(6 * time.Second)
	if st := r.Get(build); n != 2 || !st.Held {
		t.Errorf("cache not refreshed: %d", n)
	}
	r.Invalidate()
	r.Get(build)
	if n != 3 {
		t.Error("invalidate did not drop the cache")
	}
}

func TestPreflight(t *testing.T) {
	s := fixture4()
	env := envFor("192.0.2.11/24")
	p := tmpPaths(t)
	pe := &PreflightEnv{
		Lister: fakeLister{ifs: env.Interfaces}, Paths: p,
		HTTPGet: func(string) (int, error) { return 200, nil },
		Dial:    func(string, time.Duration) (bool, bool) { return false, false },
	}
	// peers do not answer: warn, still no block
	cs := Preflight(&s, nil, env, pe)
	if HasBlock(cs) {
		t.Errorf("unexpected block: %+v", cs)
	}
	find := func(cs []Check, id string) *Check {
		for i := range cs {
			if cs[i].ID == id {
				return &cs[i]
			}
		}
		return nil
	}
	if c := find(cs, "health"); c == nil || c.Level != "ok" {
		t.Errorf("health: %+v", c)
	}
	if c := find(cs, "peer-node-b"); c == nil || c.Level != "warn" {
		t.Errorf("peer: %+v", c)
	}
	if c := find(cs, "vip-free"); c == nil || c.Level != "ok" {
		t.Errorf("vip-free: %+v", c)
	}
	// health 403 and 503 and network error
	for code, want := range map[int]string{403: "block", 503: "warn"} {
		pe.HTTPGet = func(string) (int, error) { return code, nil }
		if c := find(Preflight(&s, nil, env, pe), "health"); c == nil || c.Level != want {
			t.Errorf("code %d: %+v", code, c)
		}
	}
	pe.HTTPGet = func(string) (int, error) { return 0, errors.New("no answer") }
	if c := find(Preflight(&s, nil, env, pe), "health"); c == nil || c.Level != "block" {
		t.Errorf("network error: %+v", c)
	}
	pe.HTTPGet = func(string) (int, error) { return 200, nil }
	// VIP answers on a port: warn
	pe.Dial = func(a string, _ time.Duration) (bool, bool) { return strings.HasPrefix(a, "192.0.2.10:"), false }
	if c := find(Preflight(&s, nil, env, pe), "vip-free"); c == nil || c.Level != "warn" {
		t.Errorf("vip in use: %+v", c)
	}
	// ARP entry
	pe.Dial = func(string, time.Duration) (bool, bool) { return false, false }
	write(t, p.ARPFile, "IP address HW type Flags HW address Mask Device\n192.0.2.10 0x1 0x2 aa:bb:cc:dd:ee:ff * ens18\n")
	if c := find(Preflight(&s, nil, env, pe), "vip-free"); c == nil || c.Level != "warn" || !strings.Contains(c.Message, "ARP") {
		t.Errorf("arp: %+v", c)
	}
	// held by a peer: skipped
	pe.HeldBy = "node-b"
	if c := find(Preflight(&s, nil, env, pe), "vip-free"); c == nil || c.Level != "info" {
		t.Errorf("held by peer: %+v", c)
	}
	pe.HeldBy = ""
	// not a member, cluster auth without secret, old followers
	if cs := Preflight(&s, nil, envFor("198.51.100.5/24"), &PreflightEnv{Lister: fakeLister{ifs: envFor("198.51.100.5/24").Interfaces}, Paths: p}); !HasBlock(cs) {
		t.Error("not a member must block")
	}
	s.Auth, s.Password = AuthCluster, ""
	if cs := Preflight(&s, nil, env, pe); !HasBlock(cs) || find(cs, "auth").Level != "block" {
		t.Error("cluster auth without secret must block")
	}
	s = fixture4()
	pe.OldFollowers = []string{"node-b"}
	if c := find(Preflight(&s, nil, env, pe), "old-followers"); c == nil || c.Level != "warn" {
		t.Errorf("old followers: %+v", c)
	}
	// allow-list excludes the probe: block
	env.Listener.HealthAllow = []string{"198.51.100.0/24"}
	if cs := Preflight(&s, nil, env, pe); !HasBlock(cs) {
		t.Error("allow-list must block")
	}
	// incomplete settings block generation but not saving
	empty := Defaults(false)
	if cs := Preflight(&empty, nil, env, pe); !HasBlock(cs) {
		t.Error("empty settings must block")
	}
}
