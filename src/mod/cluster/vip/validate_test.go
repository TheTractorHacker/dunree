package vip

import (
	"strconv"
	"strings"
	"testing"
)

func mut(f func(s *Shared)) Shared {
	s := fixture4()
	f(&s)
	return s
}

func TestValidateAccepts(t *testing.T) {
	s := fixture4()
	if err := ValidateShared(&s); err != nil {
		t.Fatal(err)
	}
	s6 := fixture6()
	if err := ValidateShared(&s6); err != nil {
		t.Fatal(err)
	}
	// a disabled, empty configuration may be stored
	d := Defaults(false)
	if err := ValidateShared(&d); err != nil {
		t.Fatalf("empty disabled settings: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]Shared{
		"enabled without vip": mut(func(s *Shared) { s.VIP = ""; s.Members = nil }),
		"one member":          mut(func(s *Shared) { s.Members = s.Members[:1] }),
		"nine members": mut(func(s *Shared) {
			for i := 0; i < 7; i++ {
				s.Members = append(s.Members, Member{Label: "x", Address: "192.0.2." + strconv.Itoa(20+i), Priority: 10 + i})
			}
		}),
		"zone":                      mut(func(s *Shared) { s.VIP = "fe80::1%eth0" }),
		"zone on member":            mut(func(s *Shared) { s.Members[0].Address = "192.0.2.11%eth0" }),
		"unspecified":               mut(func(s *Shared) { s.VIP = "0.0.0.0" }),
		"loopback":                  mut(func(s *Shared) { s.VIP = "127.0.0.1" }),
		"multicast":                 mut(func(s *Shared) { s.VIP = "224.0.0.18" }),
		"link local":                mut(func(s *Shared) { s.VIP = "169.254.1.1" }),
		"v4 mapped":                 mut(func(s *Shared) { s.VIP = "::ffff:192.0.2.10" }),
		"network address":           mut(func(s *Shared) { s.VIP = "192.0.2.0" }),
		"broadcast address":         mut(func(s *Shared) { s.VIP = "192.0.2.255" }),
		"member broadcast":          mut(func(s *Shared) { s.Members[0].Address = "192.0.2.255" }),
		"slash 31":                  mut(func(s *Shared) { s.Prefix = 31 }),
		"slash 32":                  mut(func(s *Shared) { s.Prefix = 32 }),
		"prefix 0":                  mut(func(s *Shared) { s.Prefix = 0 }),
		"prefix 33":                 mut(func(s *Shared) { s.Prefix = 33 }),
		"member outside prefix":     mut(func(s *Shared) { s.Members[1].Address = "198.51.100.5" }),
		"family mix":                mut(func(s *Shared) { s.Members[1].Address = "2001:db8::12" }),
		"vip equals member":         mut(func(s *Shared) { s.Members[1].Address = "192.0.2.10" }),
		"duplicate address":         mut(func(s *Shared) { s.Members[1].Address = "192.0.2.11" }),
		"duplicate priority":        mut(func(s *Shared) { s.Members[1].Priority = 150 }),
		"priority 255":              mut(func(s *Shared) { s.Members[1].Priority = 255 }),
		"priority 0":                mut(func(s *Shared) { s.Members[1].Priority = 0 }),
		"vrid 0":                    mut(func(s *Shared) { s.VRID = 0 }),
		"vrid 256":                  mut(func(s *Shared) { s.VRID = 256 }),
		"advert 11":                 mut(func(s *Shared) { s.AdvertInt = 11 }),
		"preempt delay 1001":        mut(func(s *Shared) { s.PreemptDelay = 1001 }),
		"garp negative":             mut(func(s *Shared) { s.GarpRefresh = -1 }),
		"health timeout 1":          mut(func(s *Shared) { s.Health.Timeout = 1 }),
		"health fall 0":             mut(func(s *Shared) { s.Health.Fall = 0 }),
		"health rise 11":            mut(func(s *Shared) { s.Health.Rise = 11 }),
		"health interval 61":        mut(func(s *Shared) { s.Health.Interval = 61 }),
		"password 9 chars":          mut(func(s *Shared) { s.Password = "123456789" }),
		"password empty (password)": mut(func(s *Shared) { s.Password = "" }),
		"password newline":          mut(func(s *Shared) { s.Password = "ab\ncd" }),
		"password brace":            mut(func(s *Shared) { s.Password = "a}b" }),
		"password quote":            mut(func(s *Shared) { s.Password = `a"b` }),
		"password space":            mut(func(s *Shared) { s.Password = "a b" }),
		"password unicode":          mut(func(s *Shared) { s.Password = "pässword" }),
		"bad transport":             mut(func(s *Shared) { s.Transport = "broadcast" }),
		"bad auth":                  mut(func(s *Shared) { s.Auth = "ah" }),
		"label newline":             mut(func(s *Shared) { s.Members[0].Label = "a\n}\nvrrp_instance X {" }),
		"label brace":               mut(func(s *Shared) { s.Members[0].Label = "a{b" }),
		"label quote":               mut(func(s *Shared) { s.Members[0].Label = `a"b` }),
		"label unicode":             mut(func(s *Shared) { s.Members[0].Label = "nöde" }),
		"label empty":               mut(func(s *Shared) { s.Members[0].Label = "" }),
		"label long":                mut(func(s *Shared) { s.Members[0].Label = strings.Repeat("a", 33) }),
		"hint alias":                mut(func(s *Shared) { s.Members[0].InterfaceHint = "eth0:1" }),
		"hint newline":              mut(func(s *Shared) { s.Members[0].InterfaceHint = "eth0\nx" }),
		"vip with spaces":           mut(func(s *Shared) { s.VIP = " 192.0.2.10" }),
		"vip non canonical":         mut(func(s *Shared) { s.VIP = "192.000.002.010" }),
		"vip with newline":          mut(func(s *Shared) { s.VIP = "192.0.2.10\nfoo" }),
		"vip with brace":            mut(func(s *Shared) { s.VIP = "192.0.2.10}" }),
		"vip unicode digits":        mut(func(s *Shared) { s.VIP = "１９２.0.2.10" }),
		"v6 uncanonical":            mut(func(s *Shared) { *s = fixture6(); s.VIP = "2001:DB8:0:0:0:0:0:10" }),
		"vip empty but members":     mut(func(s *Shared) { s.VIP = "" }),
	}
	for name, s := range cases {
		s := s
		if err := ValidateShared(&s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInterfaceNames(t *testing.T) {
	good := []string{"eth0", "ens18", "bond0", "vlan20", "eth0.20", "br-lan", "a"}
	bad := []string{"", "eth0:1", "eth/0", "eth@x", "eth 0", `eth"0`, "eth0\n", ".", "..", ".eth", "-eth", "abcdefghijklmnop", "ethé", "eth{", "eth#"}
	for _, n := range good {
		if !ValidInterfaceName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range bad {
		if ValidInterfaceName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestLocalValidation(t *testing.T) {
	s := fixture4()
	ok := []Local{{}, {Interface: "ens18"}, {SourceAddress: "192.0.2.11"}, {PriorityOverride: 5}, {HealthTarget: "auto"}, {HealthTarget: "http://127.0.0.1:8081"}, {HealthTarget: "https://[::1]:9443/"}}
	for _, l := range ok {
		l := l
		if err := ValidateLocal(&l, &s); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
	bad := []Local{
		{Interface: "eth0:1"}, {Interface: "a b"}, {SourceAddress: "192.0.2.99"}, {SourceAddress: "bad"}, {PriorityOverride: 255}, {PriorityOverride: -1},
		{HealthTarget: "http://192.0.2.11:8081"}, {HealthTarget: "http://localhost:8081"}, {HealthTarget: "ftp://127.0.0.1:1"},
		{HealthTarget: "http://127.0.0.1"}, {HealthTarget: "http://127.0.0.1:0"}, {HealthTarget: "http://127.0.0.1:99999"},
		{HealthTarget: "http://user@127.0.0.1:80"}, {HealthTarget: "http://127.0.0.1:80/x"}, {HealthTarget: "http://127.0.0.1:80?a=b"},
		{HealthTarget: "http://127.0.0.1:80#f"}, {HealthTarget: "http://127.0.0.1:80\n"}, {HealthTarget: "http://127.0.0.1:80 -o /etc/passwd"},
	}
	for _, l := range bad {
		l := l
		if err := ValidateLocal(&l, &s); err == nil {
			t.Errorf("%+v accepted", l)
		}
	}
}

func TestParseStrict(t *testing.T) {
	def := Defaults(false)
	if _, err := ParseShared([]byte(`{"vip":"192.0.2.10","bogus":1}`), def); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := ParseShared([]byte(`{"vrid":"51"}`), def); err == nil {
		t.Error("a string for a number accepted")
	}
	if _, err := ParseShared([]byte(`{"vrid":51} {"vrid":52}`), def); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ParseShared([]byte(`{"vrid":5.5}`), def); err == nil {
		t.Error("fractional number accepted")
	}
	if _, err := ParseShared([]byte(`{"vrid":0x10}`), def); err == nil {
		t.Error("hex accepted")
	}
	big := `{"members":[` + strings.Repeat(`{"label":"a","address":"192.0.2.1","priority":1},`, 600) + `]}`
	if _, err := ParseShared([]byte(big), def); err == nil {
		t.Error("document over 16 KiB accepted")
	}
	s, err := ParseShared([]byte(`{"vip":"192.0.2.10"}`), def)
	if err != nil || s.VRID != 51 || !s.Preempt || s.Health.Fall != 3 {
		t.Errorf("defaults not kept: %+v %v", s, err)
	}
	if _, err := ParseLocal([]byte(`{"interface":"eth0","x":1}`)); err == nil {
		t.Error("unknown local field accepted")
	}
}

// Injection attempts against every free text field: either validation fails
// or the rendered file contains no extra keyword.
func TestInjectionNeverRendersExtraBlocks(t *testing.T) {
	evil := []string{"x\n}\nvrrp_instance EVIL {", "a{b", `a"b`, "a b", "ä", "a#b", "a!b", "a;b", "a$b", "a\\b", "a\x00b", "a\rb", "a`b"}
	for _, e := range evil {
		for field := 0; field < 5; field++ {
			s := fixture4()
			l := &Local{}
			switch field {
			case 0:
				s.Members[0].Label = e
			case 1:
				s.Password = e
			case 2:
				s.Members[0].InterfaceHint = e
			case 3:
				l.Interface = e
			case 4:
				l.HealthTarget = e
			}
			o, err := Generate(&s, l, envFor("192.0.2.11/24"), -1)
			if err != nil {
				continue
			}
			if strings.Contains(o.KeepalivedConf, "EVIL") || strings.Count(o.KeepalivedConf, "vrrp_instance") != 1 {
				t.Errorf("field %d value %q reached the config:\n%s", field, e, o.KeepalivedConf)
			}
		}
	}
}

// tokenize is a tiny keepalived tokenizer used by the fuzz test: it checks
// the block structure and that only known keywords start a line.
func structureOK(conf string) bool {
	known := map[string]bool{
		"global_defs": true, "enable_script_security": true, "script_user": true, "vrrp_version": true, "vrrp_garp_master_refresh": true,
		"vrrp_script": true, "script": true, "interval": true, "timeout": true, "fall": true, "rise": true, "init_fail": true,
		"vrrp_instance": true, "state": true, "nopreempt": true, "interface": true, "native_ipv6": true, "virtual_router_id": true,
		"priority": true, "advert_int": true, "preempt_delay": true, "unicast_src_ip": true, "unicast_peer": true,
		"authentication": true, "auth_type": true, "auth_pass": true, "virtual_ipaddress": true,
		"notify_master": true, "notify_backup": true, "notify_fault": true, "track_script": true, "chk_dunree": true, "}": true,
	}
	depth := 0
	inList := false
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if t == "}" {
			depth--
			inList = false
			if depth < 0 {
				return false
			}
			continue
		}
		f := strings.Fields(t)
		if strings.HasSuffix(t, "{") {
			depth++
			inList = f[0] == "unicast_peer" || f[0] == "virtual_ipaddress" || f[0] == "track_script"
			if !known[f[0]] {
				return false
			}
			continue
		}
		if inList {
			continue //addresses and the fixed script name
		}
		if !known[f[0]] {
			return false
		}
	}
	return depth == 0
}

func FuzzVIPConfig(f *testing.F) {
	f.Add(`{"enabled":true,"vip":"192.0.2.10","prefix":24,"members":[{"label":"a","address":"192.0.2.11","priority":150},{"label":"b","address":"192.0.2.12","priority":100}],"auth":"password","password":"abc"}`, "ens18", "auto")
	f.Add(`{"enabled":true,"vip":"192.0.2.10\n}","prefix":24}`, "eth0\n}", "http://127.0.0.1:1")
	f.Fuzz(func(t *testing.T, doc, iface, target string) {
		s, err := ParseShared([]byte(doc), Defaults(false))
		if err != nil {
			return
		}
		l := &Local{Interface: iface, HealthTarget: target}
		env := envFor("192.0.2.11/24")
		out, err := Generate(&s, l, env, -1)
		if err != nil {
			return
		}
		if !structureOK(out.KeepalivedConf) {
			t.Fatalf("unexpected structure:\n%s", out.KeepalivedConf)
		}
		for _, line := range strings.Split(out.InstallCommands, "\n") {
			_ = line
		}
		if strings.Count(out.InstallCommands, "DUNREE_EOF") != 2 {
			t.Fatal("heredoc delimiter in output")
		}
	})
}
