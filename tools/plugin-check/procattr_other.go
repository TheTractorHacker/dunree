//go:build unix && !linux

package main

import "syscall"

// Without /proc the kit only knows the process group of the plugin: a child that
// left the group is neither seen nor ended, and the plugin is not ended by the
// kernel when the kit is killed.
func childAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

type procID struct{ pid int }

func descendants(int) []procID    { return nil }
func (procID) alive() bool        { return false }
func (procID) kill()              {}
func processesIn(string) []procID { return nil }

const tracksDescendants = false
