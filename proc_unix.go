//go:build !windows

package main

import "syscall"

// sysProcAttrNewGroup puts tcpdump in its own process group so a Ctrl+C in
// the terminal doesn't kill it before we stop it cleanly.
func sysProcAttrNewGroup() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }
