//go:build !unix

package main

import (
	"fmt"
	"os"
)

// The kit starts the plugin in a process group of its own and ends it with
// signals, as Dunree does on Linux. That part is not written for this platform.
func main() {
	fmt.Fprintln(os.Stderr, "plugin-check runs on Linux and other Unix systems only")
	os.Exit(2)
}
