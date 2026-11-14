//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import (
	"errors"
	"net"
	"syscall"
)

const mssSupported = false

func setMSS(syscall.RawConn, int) error {
	return errors.New("setting the TCP MSS is not supported on this platform")
}

func effectiveMSS(net.Conn) (int, bool) { return 0, false }
