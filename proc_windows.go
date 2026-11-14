//go:build windows

package main

import "syscall"

func sysProcAttrNewGroup() *syscall.SysProcAttr { return nil }
