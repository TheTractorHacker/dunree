//go:build windows

package plugins

import "os"

// killPID ends a process the hard way (test helper; the fault suite itself is not run on Windows)
func killPID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
