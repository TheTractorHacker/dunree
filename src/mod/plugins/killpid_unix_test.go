//go:build !windows

package plugins

import "syscall"

// killPID ends a process the hard way, as a crash would (test helper)
func killPID(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
