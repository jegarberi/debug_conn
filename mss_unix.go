//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"net"
	"syscall"
)

const mssSupported = true

// setMSS sets TCP_MAXSEG on the socket before connect, so the SYN advertises
// it (the server then sends segments no larger than this) and our own
// outgoing segments are capped to it too.
func setMSS(c syscall.RawConn, mss int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
	})
	if err != nil {
		return err
	}
	return serr
}

// effectiveMSS reports the MSS the kernel settled on for a connected socket.
func effectiveMSS(conn net.Conn) (int, bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		v, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	}); err != nil || gerr != nil {
		return 0, false
	}
	return v, true
}
