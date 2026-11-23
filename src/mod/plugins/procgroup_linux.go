//go:build linux

package plugins

import (
	"syscall"
	"unsafe"
)

const (
	waitidPPid   = 1          //P_PID
	waitExited   = 0x4        //WEXITED
	waitNoReap   = 0x01000000 //WNOWAIT: leave the child a zombie
	siginfoBytes = 128
)

// waitExitNoReap blocks until the child with this PID has ended and leaves it
// unreaped. It returns false when that could not be done.
func waitExitNoReap(pid int) bool {
	var info [siginfoBytes]byte
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, waitidPPid, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), waitExited|waitNoReap, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		return errno == 0
	}
}
