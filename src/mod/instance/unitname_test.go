// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package instance

import (
	"errors"
	"strings"
	"testing"
)

func TestChooseUnitNamesWhatIsInstalled(t *testing.T) {
	installed := func(names ...string) func(string) UnitStatus {
		return func(n string) UnitStatus {
			for _, x := range names {
				if x == n {
					return UnitStatus{Available: true, Exists: true}
				}
			}
			return UnitStatus{Available: true}
		}
	}
	for _, c := range []struct {
		own   string
		query func(string) UnitStatus
		want  string
	}{
		{"zoraxy.service", installed("dunree.service"), "zoraxy"}, // legacy-compat: the unit this process runs under wins
		{"", installed("dunree.service", "zoraxy.service"), "dunree"},
		{"", installed("zoraxy.service"), "zoraxy"}, // legacy-compat: install upgraded in place
		{"", installed(), "dunree"},
		{"", nil, "dunree"},
	} {
		if got := ChooseUnit(c.own, c.query); got != c.want {
			t.Errorf("ChooseUnit(%q) = %q, want %q", c.own, got, c.want)
		}
	}
}

func TestSelfCommandFollowsTheFileName(t *testing.T) {
	for exe, want := range map[string]string{
		"/opt/dunree/dunree":          "./dunree",
		"/opt/zoraxy/zoraxy":          "./zoraxy", // legacy-compat: file name kept by an in-place update
		"/tmp/go-build123/exe/server": "./dunree",
		"":                            "./dunree",
	} {
		got := selfCommand(func() (string, error) { return exe, nil })
		if got != want {
			t.Errorf("selfCommand(%q) = %q, want %q", exe, got, want)
		}
	}
	if got := selfCommand(func() (string, error) { return "", errors.New("x") }); got != "./dunree" {
		t.Errorf("error case = %q", got)
	}
}

func TestAdviceUsesTheProductNamesByDefault(t *testing.T) {
	old := SelfCommand
	SelfCommand = "./dunree"
	defer func() { SelfCommand = old }()
	if g := HolderLine(ProcInfo{Pid: 9}, ""); !strings.Contains(g, "sudo ./dunree -doctor") {
		t.Errorf("hidden holder advice: %s", g)
	}
	hand := ProcInfo{Pid: 8, Exe: "/x/dunree", State: 'S', Visible: true, Scope: "session-2.scope"}
	if g := HolderLine(hand, ""); !strings.Contains(g, "sudo systemctl stop dunree") {
		t.Errorf("default unit: %s", g)
	}
	if _, cmds := (ProcInfo{Pid: 5}).Explain(""); !strings.Contains(strings.Join(cmds, " "), "sudo ./dunree -doctor") {
		t.Errorf("Explain advice: %v", cmds)
	}
}
