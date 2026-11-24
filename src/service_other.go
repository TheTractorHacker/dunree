//go:build !windows

package main

import (
	"fmt"
	"io"
)

// serviceControl: the "service" subcommand manages the Windows service only. Other systems use
// their own service manager with the files in packaging/.
func serviceControl(cmd *serviceCommand, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "dunree service "+cmd.Action+": this command manages the Windows service and is only available on Windows.")
	fmt.Fprintln(stderr, "Use the service manager of this system instead: the systemd unit (packaging/linux/dunree.service), the launchd job (packaging/macos/ie.foleyit.dunree.plist) or the rc script (packaging/freebsd/dunree).")
	return serviceExitUsage
}

// runUnderServiceManager: there is no Windows service manager here.
func runUnderServiceManager() bool { return false }
