// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package instance

import (
	"os"
	"path/filepath"
	"strings"
)

// Service and program names used in the advice the doctor and the lock messages print.
//
// A new install runs as dunree.service with a program file called dunree. An install that was
// updated in place keeps its file name and its unit (zoraxy, zoraxy.service, plan row 37/38 of // legacy-compat
// docs/rebrand/plan.md), so the advice must name what is really there.
const (
	ProductUnit = "dunree"
	LegacyUnit  = "zoraxy" // legacy-compat: the unit of an install upgraded in place
)

// SelfCommand is how an administrator starts this program from its folder: "./dunree", or
// "./zoraxy" when the running file still has the old name. Tests may replace it.
var SelfCommand = selfCommand(os.Executable)

func selfCommand(exe func() (string, error)) string {
	p, err := exe()
	if err != nil || p == "" {
		return "./" + ProductUnit
	}
	base := filepath.Base(p)
	if !IsDunreeName(strings.TrimSuffix(base, ".exe")) && !IsDunreeName(base) {
		return "./" + ProductUnit
	}
	return "./" + base
}

// ChooseUnit picks the systemd unit to name in advice: own (the unit this process runs under) when
// set; else dunree when that unit is installed; else zoraxy when only the unit of an upgraded install
// exists; else dunree. query is QueryUnit in production and a fixture in tests (nil = do not ask).
func ChooseUnit(own string, query func(string) UnitStatus) string {
	if u := strings.TrimSuffix(own, ".service"); u != "" {
		return u
	}
	if query != nil {
		if query(ProductUnit + ".service").Exists {
			return ProductUnit
		}
		if query(LegacyUnit + ".service").Exists {
			return LegacyUnit
		}
	}
	return ProductUnit
}
