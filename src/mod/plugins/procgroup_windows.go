//go:build windows

package plugins

import (
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {}

// signalPluginProcess: Windows has no signals, the process is ended
func signalPluginProcess(proc *pluginProc, sig syscall.Signal) error {
	return proc.cmd.Process.Kill()
}

func waitPluginProcess(proc *pluginProc) error { return proc.cmd.Wait() }
