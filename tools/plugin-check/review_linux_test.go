//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

/*
	Findings of the review of phase 3:
	- an interrupted kit ends the plugin it started and removes its scratch folder
	- a killed kit does not leave the plugin running
	- the plugin does not get the environment of the kit
	- a child of the plugin that left the process group is found and ended
*/

func buildFixture(t *testing.T, name, pkg string) string {
	t.Helper()
	if built.err != nil {
		t.Fatal(built.err)
	}
	out := filepath.Join(built.dir, name)
	if _, err := os.Stat(out); err != nil {
		if err := goBuild(".", out, pkg); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// lingering lists the helper processes of the escapee fixture that are running
func lingering() []int {
	var out []int
	for _, pid := range allPids() {
		raw, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if strings.Contains(string(raw), "\x00-escapee-linger") {
			if state, _, _, ok := readStat(pid); ok && state != 'Z' {
				out = append(out, pid)
			}
		}
	}
	return out
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestInterruptedKitEndsThePluginAndCleansUp(t *testing.T) {
	kitBin := buildFixture(t, "plugin-check", ".")
	o := testOptions(t, built.refs["fork-ref-ui-api"])
	for _, tc := range []struct {
		sig     syscall.Signal
		cleaned bool
	}{{syscall.SIGINT, true}, {syscall.SIGTERM, true}, {syscall.SIGKILL, false}} {
		t.Run(tc.sig.String(), func(t *testing.T) {
			tmp := t.TempDir()
			cmd := exec.Command(kitBin, "-ports", fmt.Sprintf("%d-%d", o.PortMin, o.PortMax), "-min-run", "60s", o.Binary)
			cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
			var errOut strings.Builder
			cmd.Stderr = &errOut
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			waitFor(t, 20*time.Second, "the kit to start the plugin", func() bool { return len(processesIn(tmp)) > 0 })
			time.Sleep(300 * time.Millisecond) //the kit is somewhere in its checks
			began := time.Now()
			cmd.Process.Signal(tc.sig)
			err := cmd.Wait()
			if tc.cleaned {
				if cmd.ProcessState.ExitCode() != 2 || !strings.Contains(errOut.String(), "ending the plugin") {
					t.Fatalf("exit of the interrupted kit: %v, %q", err, errOut.String())
				}
				if time.Since(began) > 8*time.Second {
					t.Fatalf("the interrupted kit took %s to end", time.Since(began))
				}
			}
			//the plugin is gone: at once after an interrupt, by the kernel after a kill
			waitFor(t, 3*time.Second, "the plugin to be gone", func() bool { return len(processesIn(tmp)) == 0 })
			left, _ := filepath.Glob(filepath.Join(tmp, "plugin-check-*"))
			if tc.cleaned && len(left) != 0 {
				t.Fatalf("the scratch folder was left behind: %v", left)
			}
		})
	}
}

func TestPluginDoesNotGetTheEnvironmentOfTheKit(t *testing.T) {
	bin := buildFixture(t, "escapee", "./testdata/escapee")
	t.Setenv("PLUGIN_CHECK_TEST_SECRET", "a-token-of-the-operator")
	t.Setenv("PLUGIN_CHECK_TEST_OTHER", "passed-on")
	o := testOptions(t, bin)
	o.Env = []string{"ESCAPEE_MODE=none"}
	rep := Run(o)
	out := strings.Join(rep.LogTail, "\n")
	if rep.Result != statusPass || statusOf(rep, "cleanup") != statusPass || !strings.Contains(out, "secret=false") || !strings.Contains(out, "mode=none") || strings.Contains(out, "home="+os.Getenv("HOME")+" ") {
		t.Fatalf("the plugin must not see the environment of the kit, and must get what -env names:\n%s", dump(rep))
	}
	k := &kit{o: Options{Env: []string{"PLUGIN_CHECK_TEST_OTHER", "A=b", "NOT_SET_ANYWHERE"}}, workDir: t.TempDir()}
	env := k.pluginEnv()
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, want := range []string{"\nPATH=", "\nHOME=" + k.workDir, "\nTMPDIR=" + k.workDir, "\nPLUGIN_CHECK_TEST_OTHER=passed-on\n", "\nA=b\n"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the environment of the plugin lacks %q: %q", want, env)
		}
	}
	if strings.Contains(joined, "SECRET") || strings.Contains(joined, "NOT_SET_ANYWHERE") || len(env) > 9 {
		t.Errorf("the environment of the plugin holds more than it should: %q", env)
	}
	//through the command line
	var stdout, stderr strings.Builder
	if code := run([]string{"-ports", fmt.Sprintf("%d-%d", o.PortMin, o.PortMax), "-min-run", "500ms", "-calls", "50", "-env", "ESCAPEE_MODE=none", "-env", "PLUGIN_CHECK_TEST_SECRET", "-json", bin}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "secret=true") {
		t.Fatalf("-env NAME passes one variable on: exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
}

func TestChildOutsideTheProcessGroupIsFoundAndEnded(t *testing.T) {
	bin := buildFixture(t, "escapee", "./testdata/escapee")
	if n := lingering(); len(n) != 0 {
		t.Fatalf("helpers of an earlier run are still there: %v", n)
	}
	for _, mode := range []string{"setsid", "double"} {
		t.Run(mode, func(t *testing.T) {
			o := testOptions(t, bin)
			o.Env = []string{"ESCAPEE_MODE=" + mode}
			rep := Run(o)
			var cleanup Check
			for _, c := range rep.Checks {
				if c.ID == "cleanup" {
					cleanup = c
				}
			}
			if cleanup.Status != statusWarn || !strings.Contains(cleanup.Detail, "left its process group") || fmt.Sprint(cleanup.Data["outside_group"]) == "0" {
				t.Fatalf("a helper outside the process group must be reported:\n%s", dump(rep))
			}
			if rep.Result != statusPass {
				t.Fatalf("a warning, not a failure:\n%s", dump(rep))
			}
			if n := lingering(); len(n) != 0 {
				for _, pid := range n {
					syscall.Kill(pid, syscall.SIGKILL)
				}
				t.Fatalf("the kit left the helper running: %v", n)
			}
		})
	}
}
