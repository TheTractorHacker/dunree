package vip

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMainDerivesPriorities(t *testing.T) {
	s := fixture4()
	s.Members = append(s.Members, Member{Label: "node-c", Address: "192.0.2.13", Priority: 5})
	s.Main = "192.0.2.12"
	if err := ApplyMain(&s); err != nil {
		t.Fatal(err)
	}
	got := []int{s.Members[0].Priority, s.Members[1].Priority, s.Members[2].Priority}
	if got[0] != 100 || got[1] != 150 || got[2] != 99 {
		t.Fatalf("priorities %v", got)
	}
	if err := ValidateShared(&s); err != nil {
		t.Fatal(err)
	}
	// Main that is not a member
	s.Main = "192.0.2.99"
	if err := ApplyMain(&s); err == nil {
		t.Error("ApplyMain accepted a non-member")
	}
	if err := ValidateShared(&s); err == nil || !strings.Contains(err.Error(), "main") {
		t.Errorf("validate: %v", err)
	}
	// hand-edited file where main is not the highest
	s = fixture4()
	s.Main = "192.0.2.12"
	if err := ValidateShared(&s); err == nil {
		t.Error("main without the highest priority accepted")
	}
	// Main with no members at all
	e := Defaults(false)
	e.Main = "192.0.2.12"
	if err := ValidateShared(&e); err == nil {
		t.Error("main without members accepted")
	}
	// manual mode is untouched
	s = fixture4()
	if err := ApplyMain(&s); err != nil || s.Members[0].Priority != 150 || s.Members[1].Priority != 100 {
		t.Errorf("manual mode changed: %+v %v", s.Members, err)
	}
}

func TestMainMapsToScriptRoles(t *testing.T) {
	s := fixture4()
	s.Main = "192.0.2.12" // "node-b is my priority"
	ApplyMain(&s)
	a, err := Script(&s, nil, envFor("192.0.2.11/24"), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Script(&s, nil, envFor("192.0.2.12/24"), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Role != "Backup server" || b.Role != "Main server" {
		t.Fatalf("roles %q %q", a.Role, b.Role)
	}
	if !strings.Contains(b.Conf, "priority 150") || !strings.Contains(a.Conf, "priority 100") {
		t.Error("priorities not in the configs")
	}
	// the same member picked from the other node (member index) gives the same role
	pb, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, &PeerFacts{Iface: "ens19", ProbeBase: "http://127.0.0.1:9000"})
	if err != nil || pb.Role != "Main server" || len(pb.Guessed) != 0 || !strings.Contains(pb.Script, "D_IFACE='ens19'") || !strings.Contains(pb.Script, "D_PROBE='http://127.0.0.1:9000/.dunree/health'") {
		t.Fatalf("peer script: %v %+v", err, pb)
	}
	// without peer facts the guess is named
	pg, err := Script(&s, nil, envFor("192.0.2.11/24"), 1, nil)
	if err != nil || strings.Join(pg.Guessed, ",") != "interface,healthUrl" {
		t.Fatalf("guessed: %v %v", err, pg)
	}
	// the title carries the member name and address
	if !strings.Contains(b.Script, "installer for node-b (192.0.2.12) - Main server\n") {
		t.Error("title")
	}
}

func TestAdvancedOverrideStillApplies(t *testing.T) {
	s := fixture4()
	s.Main = "192.0.2.11"
	ApplyMain(&s)
	l := Local{PriorityOverride: 200, Interface: "bond0"}
	so, err := Script(&s, &l, envFor("192.0.2.12/24"), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(so.Conf, "priority 200") || !strings.Contains(so.Script, "D_IFACE='bond0'") || so.Role != "Main server" {
		t.Errorf("override ignored: role %s", so.Role)
	}
}

func TestOldSettingsLoadUnchanged(t *testing.T) {
	old := `{"enabled":true,"vip":"192.0.2.10","prefix":24,"vrid":51,"advertInt":1,"transport":"unicast",` +
		`"members":[{"label":"node-a","address":"192.0.2.11","priority":150},{"label":"node-b","address":"192.0.2.12","priority":100}],` +
		`"auth":"password","password":"Xb7kQ2mT","preempt":true,"preemptDelay":60,` +
		`"health":{"interval":2,"timeout":3,"fall":3,"rise":2},"notifyLog":false,"garpRefresh":0}`
	s, err := ParseShared([]byte(old), Defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	if s.Main != "" || s.DHCPChecked {
		t.Fatal("new fields appeared")
	}
	if err := ValidateShared(&s); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "main") || strings.Contains(string(b), "dhcpChecked") {
		t.Errorf("re-saved file carries new keys: %s", b)
	}
	if string(b) != old {
		t.Errorf("re-save differs:\n%s\n%s", b, old)
	}
	// identical settings: identical fingerprint and config as the stored golden of the old code
	want := fixture4()
	if Fingerprint(&s, "Xb7kQ2mT") != Fingerprint(&want, "Xb7kQ2mT") {
		t.Error("fingerprint of old settings changed")
	}
	out, err := Generate(&s, nil, envFor("192.0.2.12/24"), -1)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "v4_backup_unicast", out.KeepalivedConf)
	// the new keys round trip
	s.Main, s.DHCPChecked = "192.0.2.11", true
	b, _ = json.Marshal(s)
	if _, err := ParseShared(b, Defaults(false)); err != nil {
		t.Errorf("new keys refused: %v", err)
	}
}

func TestSuggest(t *testing.T) {
	dir := t.TempDir()
	arp := filepath.Join(dir, "arp")
	os.WriteFile(arp, []byte("IP address       HW type     Flags       HW address            Mask     Device\n"+
		"192.0.2.10       0x1         0x2         aa:bb:cc:00:00:01     *        ens18\n"+
		"192.0.2.11       0x1         0x2         aa:bb:cc:00:00:02     *        ens18\n"+
		"192.0.2.12       0x1         0x0         00:00:00:00:00:00     *        ens18\n"), 0o644)
	route := filepath.Join(dir, "route")
	// default via 192.0.2.1 (0100 02C0 little endian hex)
	os.WriteFile(route, []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"+
		"ens18\t00000000\t0100C000\t0003\t0\t0\t100\t00000000\n"), 0o644)
	// 192.0.2.1 = C0 00 02 01 -> little endian hex 010200C0
	os.WriteFile(route, []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"+
		"ens18\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\n"), 0o644)
	lister := fakeLister{ifs: []IfaceInfo{{Name: "ens18", Up: true, Addrs: []netip.Prefix{pfx("192.0.2.12/16")}}}}
	var mu atomic.Int32
	hosts := map[string]bool{}
	var hmu = make(chan struct{}, 1)
	answered := map[string]bool{"192.0.2.13": true} // .13 answers on port 22
	dial := func(addr string, _ time.Duration) (bool, bool) {
		host := addr[:strings.LastIndex(addr, ":")]
		hmu <- struct{}{}
		hosts[host] = true
		<-hmu
		mu.Add(1)
		return answered[host] && strings.HasSuffix(addr, ":22"), false
	}
	res, err := Suggest(SuggestInput{Base: netip.MustParseAddr("192.0.2.12"), Members: []string{"192.0.2.11", "192.0.2.12", "192.0.2.14"},
		Lister: lister, Paths: Paths{ARPFile: arp, RouteFile: route}, Dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	// /16 host: only its /24 is searched
	if res.Network.CIDR != "192.0.2.0/24" || res.Network.First != "192.0.2.1" || res.Network.Last != "192.0.2.254" || res.Gateway != "192.0.2.1" {
		t.Errorf("network %+v gw %q", res.Network, res.Gateway)
	}
	var got []string
	for _, c := range res.Candidates {
		got = append(got, c.Address)
		if c.Reason == "" {
			t.Error("reason missing")
		}
	}
	// .10 (ARP), .11/.12/.14 (members), .13 (answers) are out; first three left in order
	if strings.Join(got, ",") != "192.0.2.15,192.0.2.16,192.0.2.17" {
		t.Errorf("candidates %v", got)
	}
	if len(hosts) > SuggestMaxProbes {
		t.Errorf("%d hosts probed", len(hosts))
	}
	for h := range hosts {
		switch h {
		case "192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.14", "192.0.2.1":
			t.Errorf("excluded address %s was probed", h)
		}
	}
	if !hosts["192.0.2.13"] {
		t.Error("the answering address was not probed")
	}
	// everything answers: no candidates, never an error
	res, err = Suggest(SuggestInput{Base: netip.MustParseAddr("192.0.2.12"), Lister: lister, Dial: func(string, time.Duration) (bool, bool) { return true, false }})
	if err != nil || len(res.Candidates) != 0 {
		t.Errorf("busy network: %v %+v", err, res)
	}
	if _, err := Suggest(SuggestInput{Base: netip.MustParseAddr("2001:db8::1")}); err == nil {
		t.Error("IPv6 accepted")
	}
}

func TestSuggestBase(t *testing.T) {
	ifs := []IfaceInfo{{Name: "lo", Up: true, Addrs: []netip.Prefix{pfx("127.0.0.1/8")}}, {Name: "ens18", Up: true, Addrs: []netip.Prefix{pfx("192.0.2.12/24")}}}
	if a, err := SuggestBase("", []string{"192.0.2.11", "192.0.2.12"}, ifs); err != nil || a.String() != "192.0.2.12" {
		t.Errorf("member: %v %v", a, err)
	}
	if a, err := SuggestBase("", nil, ifs); err != nil || a.String() != "192.0.2.12" {
		t.Errorf("first: %v %v", a, err)
	}
	if a, err := SuggestBase("198.51.100.7", nil, ifs); err != nil || a.String() != "198.51.100.7" {
		t.Errorf("near: %v %v", a, err)
	}
	if _, err := SuggestBase("x'; id", nil, ifs); err == nil {
		t.Error("hostile near accepted")
	}
}

func TestMarker(t *testing.T) {
	good := "fingerprint=3f9a1c2e\nmember=192.0.2.12\ngeneratedBy=node-a (192.0.2.11)\nversion=1.0.0\ninstalledAt=2026-01-01T00:00:00Z\nweird=1\n"
	m, ok := ParseMarker([]byte(good))
	if !ok || m.Fingerprint != "3f9a1c2e" || m.Member != "192.0.2.12" || m.GeneratedBy != "node-a (192.0.2.11)" {
		t.Fatalf("%+v %v", m, ok)
	}
	for _, bad := range []string{"", "fingerprint=zz\n", "fingerprint=3f9a1c2e'; id\n", strings.Repeat("a=b\n", 400) + "fingerprint=3f9a1c2e\n"} {
		if m, ok := ParseMarker([]byte(bad)); ok {
			t.Errorf("accepted %q -> %+v", bad[:min(len(bad), 20)], m)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "m")
	os.WriteFile(p, []byte(good), 0o644)
	if m, ok := ReadMarker(p); !ok || m.Fingerprint != "3f9a1c2e" {
		t.Error("ReadMarker")
	}
	if _, ok := ReadMarker(filepath.Join(dir, "none")); ok {
		t.Error("missing file")
	}
	os.WriteFile(p, []byte(good+strings.Repeat("x", 2000)), 0o644)
	if _, ok := ReadMarker(p); ok {
		t.Error("oversized marker accepted")
	}
	// the script's marker lines match the parser
	b, s := readyBackup(t)
	b.run(b.script(s, "192.0.2.12/24", -1))
	mk, ok := ReadMarker(filepath.Join(b.root, "etc/keepalived/dunree-installed"))
	if !ok || mk.Member != "192.0.2.12" || mk.GeneratedBy != "node-b (192.0.2.12)" || mk.Version != "1.0.0-test" {
		t.Errorf("script marker: %+v %v", mk, ok)
	}
	// ReadStatus sees it
	env := envFor("192.0.2.12/24")
	st := ReadStatus(&s, nil, fakeLister{ifs: env.Interfaces}, Paths{MarkerFile: filepath.Join(b.root, "etc/keepalived/dunree-installed")}, env)
	if !st.Installed || st.MarkerFinger != mk.Fingerprint {
		t.Errorf("status: %+v", st)
	}
}

func TestNodeState(t *testing.T) {
	base := NodeFacts{Reachable: true, KeepalivedBin: true, Installed: true, InstalledFP: "aaaaaaaa", CurrentFP: "aaaaaaaa", KeepalivedUp: Yes}
	cases := []struct {
		name string
		mod  func(f *NodeFacts)
		want string
	}{
		{"unreachable", func(f *NodeFacts) { f.Reachable = false }, NodeUnknown},
		{"old", func(f *NodeFacts) { f.OldVersion = true }, NodeOldVersion},
		{"no keepalived", func(f *NodeFacts) { f.KeepalivedBin = false }, NodeWaiting},
		{"no marker", func(f *NodeFacts) { f.Installed = false }, NodeWaiting},
		{"outdated", func(f *NodeFacts) { f.InstalledFP = "bbbbbbbb" }, NodeOutdated},
		{"stopped", func(f *NodeFacts) { f.KeepalivedUp = No }, NodeStopped},
		{"holding", func(f *NodeFacts) { f.Held, f.SomeoneHolds = true, true }, NodeHolding},
		{"standby", func(f *NodeFacts) { f.SomeoneHolds = true }, NodeStandby},
		{"fault", func(f *NodeFacts) {}, NodeFault},
		{"order: unreachable beats old", func(f *NodeFacts) { f.Reachable, f.OldVersion = false, true }, NodeUnknown},
		{"order: waiting beats outdated", func(f *NodeFacts) { f.Installed, f.InstalledFP = false, "bbbbbbbb" }, NodeWaiting},
	}
	for _, c := range cases {
		f := base
		c.mod(&f)
		if got := NodeState(f); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// Every field a validator can return has a label key.
func TestEveryFieldHasALabel(t *testing.T) {
	src, err := os.ReadFile("validate.go")
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`fe\("([^"]+)"`),
		regexp.MustCompile(`fe\(f\+"([^"]+)"`),
		regexp.MustCompile(`checkInt\("([^"]+)"`),
	} {
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			f := m[1]
			if strings.HasPrefix(m[0], "fe(f+") {
				f = "members[0]" + f
			}
			fields = append(fields, f)
		}
	}
	if len(fields) < 20 {
		t.Fatalf("only %d fields found: the scan broke", len(fields))
	}
	for _, f := range fields {
		if _, _, ok := FieldLabelKey(f); !ok {
			t.Errorf("field %q has no label key", f)
		}
	}
	if k, n, ok := FieldLabelKey("members[3].priority"); !ok || n != 3 || k != "vip.field.member.priority" {
		t.Errorf("%s %d %v", k, n, ok)
	}
	if _, _, ok := FieldLabelKey("nonsense"); ok {
		t.Error("unknown field mapped")
	}
}
