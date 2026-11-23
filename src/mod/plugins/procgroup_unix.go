//go:build !windows

package plugins

import (
	"os/exec"
	"syscall"
)

// setProcessGroup starts the plugin in a process group of its own, so that a stop
// also reaches the children of a start.sh (they used to survive it).
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalPluginProcess sends sig to the process group of the plugin, and to the
// process itself in case the group could not be created. Once the process has
// been reaped nothing is sent: its PID (which is also the group ID) can belong
// to another process by then.
func signalPluginProcess(proc *pluginProc, sig syscall.Signal) error {
	if proc.pid <= 1 {
		return nil
	}
	proc.sigMu.Lock()
	defer proc.sigMu.Unlock()
	if proc.groupClosed {
		return nil
	}
	if err := syscall.Kill(-proc.pid, sig); err == nil {
		return nil
	}
	return proc.cmd.Process.Signal(sig)
}

// waitPluginProcess waits for the plugin process to end, ends what is left of its
// process group (children it started) and reaps it.
//
// The group is killed while the ended plugin is still a zombie: until it is
// reaped its PID, and with it the group ID, cannot be given to another process,
// so the kill cannot hit a stranger. Where the exit cannot be seen without
// reaping (not Linux, or waitid failed) the group is killed directly after the
// reap instead, as before but without the wait for the last output in between.
func waitPluginProcess(proc *pluginProc) error {
	if proc.pid > 1 && waitExitNoReap(proc.pid) {
		proc.sigMu.Lock()
		syscall.Kill(-proc.pid, syscall.SIGKILL)
		proc.groupClosed = true
		proc.sigMu.Unlock()
		return proc.cmd.Wait()
	}
	err := proc.cmd.Wait()
	proc.sigMu.Lock()
	if proc.pid > 1 {
		syscall.Kill(-proc.pid, syscall.SIGKILL)
	}
	proc.groupClosed = true
	proc.sigMu.Unlock()
	return err
}
