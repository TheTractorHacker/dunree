// Copyright (c) 2026 Foley IT. Part of Dunree, licensed under AGPL-3.0.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// start.sh refuses to start next to a running service, under either service name, and starts the
// program file that is in the folder: dunree, or zoraxy on an install upgraded in place.
func TestStartScriptKnowsBothNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script, err := filepath.Abs("start.sh")
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, activeUnit string, files []string, force bool) (string, int) {
		t.Helper()
		dir, bin := t.TempDir(), t.TempDir()
		write := func(name, body string) {
			if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		write("systemctl", `[ "$1" = is-active ] && [ "$2" = "`+activeUnit+`" ] && { echo active; exit 0; }; echo inactive; exit 3`)
		write("pgrep", "exit 1")
		write("sudo", `echo "SUDO $*"`)
		write("grep", "exit 1") // not inside a unit's cgroup
		for _, f := range files {
			os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o755)
		}
		cmd := exec.Command(sh, script)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
		if force {
			cmd.Env = append(cmd.Env, "FORCE=1")
		}
		out, _ := cmd.CombinedOutput()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		return string(out), code
	}

	if out, code := run(t, "dunree", []string{"dunree"}, false); code != 1 || !strings.Contains(out, "service 'dunree' is active") || !strings.Contains(out, "sudo systemctl restart dunree") {
		t.Errorf("dunree service running: code %d\n%s", code, out)
	}
	// legacy-compat: an install upgraded in place runs as zoraxy.service with the file ./zoraxy
	if out, code := run(t, "zoraxy", []string{"zoraxy"}, false); code != 1 || !strings.Contains(out, "service 'zoraxy' is active") || !strings.Contains(out, "sudo ./zoraxy -doctor") {
		t.Errorf("zoraxy service running: code %d\n%s", code, out)
	}
	if out, code := run(t, "none", []string{"dunree"}, false); code != 0 || !strings.Contains(out, "SUDO ./dunree") {
		t.Errorf("nothing running: code %d\n%s", code, out)
	}
	if out, _ := run(t, "none", []string{"zoraxy"}, true); !strings.Contains(out, "SUDO ./zoraxy") { // legacy-compat
		t.Errorf("old file name: %s", out)
	}
	if out, _ := run(t, "none", []string{"dunree", "zoraxy"}, true); !strings.Contains(out, "SUDO ./dunree") {
		t.Errorf("both files: the new name wins: %s", out)
	}
}
