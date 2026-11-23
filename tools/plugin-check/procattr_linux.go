//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// childAttr: a process group of its own, as Zoraxy starts a plugin, and the kernel
// ends the child when the kit dies without cleaning up (SIGKILL, a crash). This
// covers the started process only, not what it starts itself.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// procID names one process: a process ID alone can be given to a new process
type procID struct {
	pid   int
	start uint64 //start time in clock ticks since boot
}

// readStat reads state, parent and start time of a process
func readStat(pid int) (state byte, ppid int, start uint64, ok bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, 0, false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')') //the name may contain spaces and brackets
	if i < 0 {
		return 0, 0, 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, 0, 0, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	start, err2 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, 0, false
	}
	return f[0][0], ppid, start, true
}

func allPids() []int {
	names, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make([]int, 0, len(names))
	for _, e := range names {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// descendants lists every process below root (children, their children, ...),
// whatever process group or session they are in
func descendants(root int) []procID {
	kids := map[int][]procID{}
	for _, pid := range allPids() {
		if _, ppid, start, ok := readStat(pid); ok {
			kids[ppid] = append(kids[ppid], procID{pid, start})
		}
	}
	var out []procID
	todo, seen := []int{root}, map[int]bool{root: true}
	for len(todo) > 0 && len(out) < 4096 {
		next := todo[0]
		todo = todo[1:]
		for _, c := range kids[next] {
			if !seen[c.pid] {
				seen[c.pid] = true
				out = append(out, c)
				todo = append(todo, c.pid)
			}
		}
	}
	return out
}

// alive: the same process (not a new one with its number) is still running
func (id procID) alive() bool {
	state, _, start, ok := readStat(id.pid)
	return ok && start == id.start && state != 'Z' && state != 'X'
}

func (id procID) kill() {
	if id.alive() {
		syscall.Kill(id.pid, syscall.SIGKILL)
	}
}

// processesIn lists the processes whose program file or working directory is
// inside dir: what a plugin left behind after it cut itself loose from its
// parent (double fork) is still found this way, as long as it did not also
// change its directory and run another program.
func processesIn(dir string) []procID {
	if dir == "" {
		return nil
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	prefix := strings.TrimRight(dir, "/") + "/"
	self := os.Getpid()
	var out []procID
	for _, pid := range allPids() {
		if pid == self {
			continue
		}
		base := "/proc/" + strconv.Itoa(pid)
		exe, _ := os.Readlink(base + "/exe")
		cwd, _ := os.Readlink(base + "/cwd")
		if strings.HasPrefix(exe, prefix) || strings.HasPrefix(cwd+"/", prefix) {
			if state, _, start, ok := readStat(pid); ok && state != 'Z' && state != 'X' {
				out = append(out, procID{pid, start})
			}
		}
	}
	return out
}

const tracksDescendants = true
