//go:build !windows && !linux

package plugins

// waitExitNoReap is only implemented on Linux (see procgroup_linux.go)
func waitExitNoReap(pid int) bool { return false }
