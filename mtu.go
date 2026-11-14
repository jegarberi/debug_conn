package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// dialer returns a net.Dialer honouring -timeout and, if mss > 0, a TCP MSS.
func dialer(timeout time.Duration, mss int) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mss > 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error { return setMSS(c, mss) }
	}
	return d
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout())
}

// hsResult is the outcome of one TLS handshake attempt.
type hsResult struct {
	conn      *tls.Conn
	connected bool // TCP connect succeeded (failure was in the TLS phase)
	err       error
	dur       time.Duration
	mss       int // effective MSS reported by the kernel, 0 if unknown
}

// tlsHandshake dials TCP and runs the TLS handshake as two separate steps,
// so a failure can be attributed to the connect or to the handshake.
// smallHello drops the post-quantum key share, which shrinks the
// ClientHello from ~1.2-1.8 KB (two segments) to ~300 bytes.
func tlsHandshake(ctx context.Context, addr, sni string, timeout time.Duration, mss int, smallHello bool) hsResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	nc, err := dialer(timeout, mss).DialContext(ctx, "tcp", addr)
	if err != nil {
		return hsResult{err: err, dur: time.Since(start)}
	}
	res := hsResult{connected: true}
	res.mss, _ = effectiveMSS(nc)
	tcfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // the caller verifies, so it can still show the chain
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if smallHello {
		tcfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	tc := tls.Client(nc, tcfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		nc.Close()
		res.err, res.dur = err, time.Since(start)
		return res
	}
	res.conn, res.dur = tc, time.Since(start)
	return res
}

// probeStall runs when TCP connects but the TLS handshake times out: the
// classic sign of an MTU / path-MTU-discovery black hole, where small
// packets (SYN/ACK) pass but full-size ones are silently dropped.
// It retries with a small ClientHello and with reduced MSS values, then
// binary-searches the largest MSS that still works.
func probeStall(t *target, cfg *config, sni string, r *reporter) {
	timeout := min(cfg.timeout, 5*time.Second)
	r.blank()
	r.warn("TCP connected but the TLS handshake stalled: probing for an MTU black hole")
	r.info("(each failed attempt waits %s; use -retry=false to skip)", timeout)

	attempt := func(label string, mss int, small bool) bool {
		res := tlsHandshake(cfg.ctx(), t.addr(), sni, timeout, mss, small)
		if res.conn != nil {
			res.conn.Close()
		}
		eff := ""
		if res.mss > 0 {
			eff = fmt.Sprintf(" [kernel mss %d]", res.mss)
		}
		switch {
		case res.err == nil:
			r.ok("  %-34s handshake OK in %s%s", label, res.dur.Round(time.Millisecond), eff)
			return true
		case !res.connected:
			r.fail("  %-34s connect failed: %v", label, res.err)
		case isTimeout(res.err):
			r.fail("  %-34s timeout%s", label, eff)
		default:
			r.fail("  %-34s %v", label, res.err)
		}
		return false
	}
	if cfg.ctx().Err() != nil {
		return
	}

	smallOK := attempt("small ClientHello, default MSS", cfg.mss, true)
	if !mssSupported {
		r.warn("this platform can't set the TCP MSS; skipping the MSS probes")
		return
	}
	const floor = 536 // smallest MSS every IPv4 path must carry
	if !attempt(fmt.Sprintf("MSS %d", floor), floor, false) {
		r.blank()
		if smallOK {
			r.warn("conclusion: only the large ClientHello is dropped, even at the minimum MSS;")
			r.info("a middlebox on the path probably rejects post-quantum (ML-KEM/Kyber) key shares.")
		} else {
			r.warn("conclusion: the handshake fails even with tiny packets, so it is NOT an MTU problem.")
			r.info("Suspect a firewall / DPI device dropping TLS to this host, or the server itself.")
		}
		return
	}

	// Binary search between floor (works) and the default (fails).
	hi := 1460 // IPv4 over Ethernet
	if cfg.mss > 0 && cfg.mss < hi {
		hi = cfg.mss
	}
	if ip := net.ParseIP(t.host); ip != nil && ip.To4() == nil {
		hi = 1440 // IPv6 header is 20 bytes larger
	}
	lo := floor
	for steps := 0; hi-lo > 16 && steps < 5 && cfg.ctx().Err() == nil; steps++ {
		mid := (lo + hi) / 2
		if attempt(fmt.Sprintf("MSS %d", mid), mid, false) {
			lo = mid
		} else {
			hi = mid
		}
	}

	r.blank()
	r.warn("conclusion: MTU / PMTUD black hole. Full-size packets are dropped on the path")
	r.info("and the \"fragmentation needed\" ICMP that would fix it never arrives.")
	r.info("Largest MSS that worked: %d (failed at %d), so the path MTU is about %d bytes (IPv4).", lo, hi, lo+40)
	if smallOK {
		r.info("The small ClientHello also worked, so large packets are lost in the client->server direction.")
	} else {
		r.info("Even a small ClientHello failed, so at least the server->client direction (certificate")
		r.info("chain) loses large packets; the server can't see that your link is smaller than 1500.")
	}
	r.info("Fixes (any one):")
	r.info("  - router: enable TCP MSS clamping (\"clamp MSS to PMTU\") on that WAN link,")
	r.info("    or set the WAN MTU to its real value")
	r.info("  - Linux host: ip link set <dev> mtu %d   (or: ip route change <route> advmss %d)", lo+40, lo)
	r.info("  - confirm with: %s -mss %d %s", os.Args[0], lo, t.raw)
}
