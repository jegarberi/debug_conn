// debug_conn runs a set of connectivity tests against a website:
//
//	dns        - resolve the host (A/AAAA, CNAME)
//	traceroute - path to the host (uses system traceroute / tracepath / mtr)
//	tcp        - "telnet"-style TCP connect test, reads any banner
//	tls        - "openssl s_client -connect" style handshake + cert chain dump
//	http       - "curl -v" style request with per-phase timings
//
// Usage:
//
//	debug_conn                         # interactive TUI, asks for a target
//	debug_conn -tui https://example.com # TUI, starts testing right away
//	debug_conn [flags] <url|host[:port]>
//	debug_conn https://example.com
//	debug_conn -tests tcp,tls example.com:8443
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type target struct {
	raw    string
	scheme string
	host   string
	port   string
	path   string
	ip     string // pinned IP all connections go to ("" = not resolved)
	pinHow string // how ip was chosen, for the report
}

type config struct {
	timeout      time.Duration
	insecure     bool
	serverName   string
	maxHops      int
	method       string
	showBody     int
	mss          int    // TCP MSS to advertise (0 = kernel default)
	retry        bool   // on a stalled handshake, probe for MTU problems
	forceIP      string // -ip: connect here instead of the DNS answer
	prefer6      bool   // pin an IPv6 address when DNS returns both
	pcap         string // -pcap: write a packet capture here
	pcapIface    string
	tests        map[string]bool
	portOverride string
	context      context.Context // cancelled when the TUI quits or re-runs
}

func (c *config) ctx() context.Context {
	if c.context == nil {
		return context.Background()
	}
	return c.context
}

type testFunc func(*target, *config, *reporter) bool

var runners = map[string]testFunc{
	"dns": testDNS, "traceroute": testTraceroute, "tcp": testTCP, "tls": testTLS, "http": testHTTP,
}

// short descriptions shown in the TUI list
var testDesc = map[string]string{
	"dns":        "name resolution",
	"traceroute": "network path",
	"tcp":        "telnet host port",
	"tls":        "openssl s_client",
	"http":       "curl -v",
}

var allTests = []string{"dns", "traceroute", "tcp", "tls", "http"}

// ---------- output ----------

type level int

const (
	lvInfo level = iota
	lvOK
	lvWarn
	lvFail
	lvTitle
)

type line struct {
	lv   level
	text string
}

// reporter collects the output of one test. emit is called for every line,
// so the CLI can print it and the TUI can stream it into a panel.
type reporter struct{ emit func(line) }

func (r *reporter) out(lv level, format string, a ...any) {
	r.emit(line{lv, fmt.Sprintf(format, a...)})
}
func (r *reporter) ok(format string, a ...any)   { r.out(lvOK, format, a...) }
func (r *reporter) fail(format string, a ...any) { r.out(lvFail, format, a...) }
func (r *reporter) warn(format string, a ...any) { r.out(lvWarn, format, a...) }
func (r *reporter) info(format string, a ...any) { r.out(lvInfo, format, a...) }
func (r *reporter) blank()                       { r.emit(line{lvInfo, ""}) }
func (r *reporter) title(s string)               { r.emit(line{lvTitle, s}) }

var useColor = os.Getenv("NO_COLOR") == "" && isTerminal()

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func color(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// cliReporter prints straight to stdout; with -copy it also keeps a plain
// copy of the output for the clipboard.
var cliReport strings.Builder

var cliReporter = &reporter{emit: func(l line) {
	fmt.Println(formatLine(l, true))
	cliReport.WriteString(formatLine(l, false) + "\n")
}}

// ---------- target parsing ----------

func parseTarget(s, portOverride string) (*target, error) {
	t := &target{raw: s}
	if !strings.Contains(s, "://") {
		// host or host:port; guess scheme from port
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host, port = s, ""
		}
		t.host = strings.Trim(host, "[]")
		t.port = port
		switch port {
		case "80", "8080":
			t.scheme = "http"
		default:
			t.scheme = "https"
		}
		t.path = "/"
	} else {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		t.scheme = strings.ToLower(u.Scheme)
		t.host = u.Hostname()
		t.port = u.Port()
		t.path = u.RequestURI()
	}
	if portOverride != "" {
		t.port = portOverride
	}
	if t.port == "" {
		if t.scheme == "http" {
			t.port = "80"
		} else {
			t.port = "443"
		}
	}
	if t.host == "" {
		return nil, fmt.Errorf("no host in %q", s)
	}
	return t, nil
}

func (t *target) addr() string { return net.JoinHostPort(t.host, t.port) }

func (t *target) url() string {
	hp := t.host
	if strings.Contains(hp, ":") {
		hp = "[" + hp + "]"
	}
	if !(t.scheme == "https" && t.port == "443") && !(t.scheme == "http" && t.port == "80") {
		hp = net.JoinHostPort(t.host, t.port)
	}
	return t.scheme + "://" + hp + t.path
}

// ---------- DNS ----------

func testDNS(t *target, cfg *config, r *reporter) bool {
	r.title("dns")
	if ip := net.ParseIP(t.host); ip != nil {
		r.ok("%s is an IP literal, skipping resolution", t.host)
		if names, err := net.LookupAddr(t.host); err == nil && len(names) > 0 {
			r.info("PTR: %s", strings.Join(names, ", "))
		}
		return true
	}
	ctx, cancel := context.WithTimeout(cfg.ctx(), cfg.timeout)
	defer cancel()
	res := net.DefaultResolver

	start := time.Now()
	addrs, err := res.LookupIPAddr(ctx, t.host)
	dur := time.Since(start)
	if err != nil {
		r.fail("lookup %s: %v", t.host, err)
		return false
	}
	r.ok("resolved %s in %s", t.host, dur.Round(time.Microsecond))
	if cname, err := res.LookupCNAME(ctx, t.host); err == nil && strings.TrimSuffix(cname, ".") != t.host {
		r.info("CNAME: %s", cname)
	}
	for _, a := range addrs {
		kind := "A   "
		if a.IP.To4() == nil {
			kind = "AAAA"
		}
		ptr := ""
		if names, err := res.LookupAddr(ctx, a.IP.String()); err == nil && len(names) > 0 {
			ptr = "  (PTR " + names[0] + ")"
		}
		pin := ""
		if t.ip == a.IP.String() {
			pin = "  ← used for the tests"
		}
		r.info("%s %s%s%s", kind, a.IP, ptr, pin)
	}
	if cfg.forceIP != "" {
		r.warn("-ip %s given: tests connect there, ignoring these answers", cfg.forceIP)
	}
	return true
}

// ---------- traceroute ----------

func testTraceroute(t *target, cfg *config, r *reporter) bool {
	r.title("traceroute")
	hops := strconv.Itoa(cfg.maxHops)
	type cand struct {
		bin  string
		args []string
	}
	cands := []cand{
		{"traceroute", []string{"-n", "-w", "2", "-q", "1", "-m", hops, t.dialHost()}},
		{"tracepath", []string{"-n", "-m", hops, t.dialHost()}},
		{"mtr", []string{"-n", "-r", "-c", "1", "-m", hops, t.dialHost()}},
		{"tracert", []string{"-d", "-h", hops, t.dialHost()}}, // Windows
	}
	for _, c := range cands {
		path, err := exec.LookPath(c.bin)
		if err != nil {
			continue
		}
		r.info("running: %s %s", c.bin, strings.Join(c.args, " "))
		// traceroute can be slow: allow ~3s per hop
		ctx, cancel := context.WithTimeout(cfg.ctx(), time.Duration(cfg.maxHops)*3*time.Second+5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, c.args...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			r.fail("%v", err)
			return false
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			r.fail("start %s: %v", c.bin, err)
			continue
		}
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			r.info("%s", sc.Text())
		}
		if err := cmd.Wait(); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				r.warn("%s timed out", c.bin)
			} else {
				r.warn("%s exited: %v", c.bin, err)
			}
			return false
		}
		r.ok("%s finished", c.bin)
		return true
	}
	r.warn("no traceroute tool found (install traceroute, iputils-tracepath or mtr)")
	return false
}

// ---------- TCP (telnet) ----------

func testTCP(t *target, cfg *config, r *reporter) bool {
	r.title("tcp (telnet " + t.host + " " + t.port + ")")
	ctx, cancel := context.WithTimeout(cfg.ctx(), cfg.timeout)
	defer cancel()
	var ips []net.IPAddr
	if cfg.forceIP != "" || net.ParseIP(t.host) != nil {
		ips = []net.IPAddr{{IP: net.ParseIP(t.dialHost())}}
	} else {
		var err error
		ips, err = net.DefaultResolver.LookupIPAddr(ctx, t.host)
		if err != nil {
			r.fail("resolve: %v", err)
			return false
		}
	}
	allOK := true
	anyOK := false
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.IP.String(), t.port)
		start := time.Now()
		conn, err := dialer(cfg.timeout, cfg.mss).DialContext(cfg.ctx(), "tcp", addr)
		dur := time.Since(start)
		if err != nil {
			r.fail("connect %s: %v (%s)", addr, err, dur.Round(time.Microsecond))
			allOK = false
			continue
		}
		anyOK = true
		mssInfo := ""
		if m, ok := effectiveMSS(conn); ok {
			mssInfo = fmt.Sprintf(", mss %d", m)
		}
		if len(ips) > 1 && ip.IP.String() == t.ip {
			mssInfo += "; used by tls/http"
		}
		r.ok("connected to %s in %s (local %s%s)", addr, dur.Round(time.Microsecond), conn.LocalAddr(), mssInfo)
		// Some services (SMTP, SSH, FTP) send a banner; HTTP/TLS do not.
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			r.info("banner: %q", strings.TrimSpace(string(buf[:n])))
		}
		conn.Close()
	}
	if anyOK && !allOK {
		r.warn("some addresses unreachable")
	}
	return anyOK
}

// ---------- TLS (openssl s_client) ----------

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "TLSv1.0",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
}

func testTLS(t *target, cfg *config, r *reporter) bool {
	title := "tls (openssl s_client -connect " + t.dialAddr()
	if sn := tlsSNI(t, cfg); sn != "" {
		title += " -servername " + sn
	}
	r.title(title + ")")
	if t.scheme == "http" {
		r.warn("target scheme is http; attempting TLS on port %s anyway", t.port)
	}
	sni := tlsSNI(t, cfg)
	if cfg.mss > 0 {
		r.info("using MSS %d", cfg.mss)
	}
	res := tlsHandshake(cfg.ctx(), t.dialAddr(), sni, cfg.timeout, cfg.mss, false)
	dur := res.dur
	if res.err != nil {
		if !res.connected {
			r.fail("connect to %s: %v", t.dialAddr(), res.err)
			return false
		}
		r.fail("TCP connected, but the TLS handshake with %s failed: %v", t.dialAddr(), res.err)
		if cfg.retry && isTimeout(res.err) && cfg.ctx().Err() == nil {
			probeStall(t, cfg, sni, r)
		}
		return false
	}
	conn := res.conn
	defer conn.Close()
	st := conn.ConnectionState()
	r.ok("handshake completed in %s", dur.Round(time.Microsecond))
	r.info("Protocol : %s", tlsVersions[st.Version])
	r.info("Cipher   : %s", tls.CipherSuiteName(st.CipherSuite))
	r.info("ALPN     : %s", orNone(st.NegotiatedProtocol))
	r.info("SNI sent : %s", orNone(sni))
	r.info("Peer     : %s", conn.RemoteAddr())

	r.blank()
	r.info("Certificate chain:")
	now := time.Now()
	for i, c := range st.PeerCertificates {
		r.info(" %d s:%s", i, c.Subject.String())
		r.info("   i:%s", c.Issuer.String())
		r.info("   valid: %s -> %s", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		r.info("   key: %s, sig: %s, serial: %s", c.PublicKeyAlgorithm, c.SignatureAlgorithm, c.SerialNumber.Text(16))
		if i == 0 && len(c.DNSNames) > 0 {
			san := c.DNSNames
			if len(san) > 10 {
				san = append(san[:10:10], fmt.Sprintf("... (+%d more)", len(c.DNSNames)-10))
			}
			r.info("   SAN: %s", strings.Join(san, ", "))
		}
		if now.After(c.NotAfter) {
			r.fail("   certificate %d EXPIRED %s ago", i, now.Sub(c.NotAfter).Round(time.Hour))
		} else if now.Before(c.NotBefore) {
			r.fail("   certificate %d not yet valid", i)
		} else if left := c.NotAfter.Sub(now); left < 30*24*time.Hour {
			r.warn("   certificate %d expires in %s", i, left.Round(time.Hour))
		}
	}

	// Verify chain against system roots, like openssl's "Verify return code".
	r.blank()
	if len(st.PeerCertificates) == 0 {
		r.fail("server sent no certificates")
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := st.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       sni,
		Intermediates: inter,
	})
	if verr != nil {
		if cfg.insecure {
			r.warn("verify: %v (ignored, -insecure)", verr)
			return true
		}
		r.fail("verify: %v", verr)
		return false
	}
	r.ok("certificate chain verified for %q", sni)
	return true
}

// tlsSNI is the server name sent in the ClientHello: -servername, else the
// hostname (none for an IP literal, like openssl/curl).
func tlsSNI(t *target, cfg *config) string {
	if cfg.serverName != "" {
		return cfg.serverName
	}
	if net.ParseIP(t.host) == nil {
		return t.host
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// ---------- HTTP (curl) ----------

func testHTTP(t *target, cfg *config, r *reporter) bool {
	u := t.url()
	r.title("http (curl -v " + u + ")")
	var (
		tStart, tDNS0, tDNS1, tConn0, tConn1, tTLS0, tTLS1, tWrote, tFirst time.Time
		remote                                                             string
		reused                                                             bool
	)
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { tDNS0 = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { tDNS1 = time.Now() },
		ConnectStart:      func(_, _ string) { tConn0 = time.Now() },
		ConnectDone:       func(_, addr string, _ error) { tConn1 = time.Now(); remote = addr },
		TLSHandshakeStart: func() { tTLS0 = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { tTLS1 = time.Now() },
		GotConn:           func(i httptrace.GotConnInfo) { reused = i.Reused },
		WroteRequest:      func(httptrace.WroteRequestInfo) { tWrote = time.Now() },
		GotFirstResponseByte: func() {
			tFirst = time.Now()
		},
	}
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       pinnedDial(t, dialer(cfg.timeout, cfg.mss)),
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: cfg.insecure, ServerName: cfg.serverName},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.timeout * 3,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // don't follow, like curl without -L
		},
	}
	req, err := http.NewRequestWithContext(cfg.ctx(), cfg.method, u, nil)
	if err != nil {
		r.fail("%v", err)
		return false
	}
	req.Header.Set("User-Agent", "debug_conn/1.0")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	if p, _ := http.ProxyFromEnvironment(req); p != nil {
		r.info("using proxy %s", p)
	}
	if p, _ := http.ProxyFromEnvironment(req); p == nil && t.ip != "" && t.ip != t.host {
		r.info("* connecting to %s (Host header and SNI: %s)", t.dialAddr(), t.host)
	}
	r.info("> %s %s", req.Method, req.URL.RequestURI())
	r.info("> Host: %s", req.URL.Host)
	r.info("> User-Agent: %s", req.Header.Get("User-Agent"))

	tStart = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		r.fail("request: %v", err)
		// Connected but then stalled: retry once with a minimal MSS. If that
		// works, full-size packets are being dropped (see the tls test).
		if cfg.retry && isTimeout(err) && !tConn1.IsZero() && mssSupported && cfg.ctx().Err() == nil && cfg.mss != 536 {
			r.blank()
			r.warn("connected but no response; retrying once with MSS 536 to test for an MTU black hole")
			c2 := *cfg
			c2.mss, c2.retry, c2.showBody = 536, false, 0
			sub := &reporter{emit: func(line) {}}
			start := time.Now()
			if testHTTP(t, &c2, sub) {
				r.ok("with MSS 536 the request succeeded in %s", time.Since(start).Round(time.Millisecond))
				r.warn("conclusion: MTU / PMTUD black hole; run the tls test for the exact MTU and fixes")
			} else {
				r.fail("still failing with MSS 536, so packet size is not the problem")
			}
		}
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	tEnd := time.Now()

	r.info("< %s %s", resp.Proto, resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			r.info("< %s: %s", k, v)
		}
	}
	if cfg.showBody > 0 && len(body) > 0 {
		b := body
		if len(b) > cfg.showBody {
			b = b[:cfg.showBody]
		}
		r.blank()
		r.info("body (first %d of %d bytes):", len(b), len(body))
		for _, l := range strings.Split(string(b), "\n") {
			r.info("| %s", l)
		}
	}

	r.blank()
	d := func(a, b time.Time) string {
		if a.IsZero() || b.IsZero() {
			return "-"
		}
		return b.Sub(a).Round(time.Microsecond).String()
	}
	r.info("remote        : %s (reused=%v)", remote, reused)
	r.info("dns lookup    : %s", d(tDNS0, tDNS1))
	r.info("tcp connect   : %s", d(tConn0, tConn1))
	r.info("tls handshake : %s", d(tTLS0, tTLS1))
	r.info("server wait   : %s  (request sent -> first byte)", d(tWrote, tFirst))
	r.info("content xfer  : %s  (%d bytes)", d(tFirst, tEnd), len(body))
	r.info("total         : %s", d(tStart, tEnd))

	switch {
	case resp.StatusCode >= 500:
		r.fail("HTTP %d", resp.StatusCode)
		return false
	case resp.StatusCode >= 400:
		r.warn("HTTP %d", resp.StatusCode)
	case resp.StatusCode >= 300:
		r.ok("HTTP %d -> %s", resp.StatusCode, resp.Header.Get("Location"))
	default:
		r.ok("HTTP %d", resp.StatusCode)
	}
	return true
}

// pinnedDial sends connections for the target's host:port to the pinned IP,
// leaving the URL (and so the Host header and SNI) untouched. Connections to
// anything else, e.g. an HTTP proxy, are dialed normally.
func pinnedDial(t *target, d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if t.ip != "" && addr == t.addr() {
			addr = t.dialAddr()
		}
		return d.DialContext(ctx, network, addr)
	}
}

// ---------- main ----------

func main() {
	cfg := &config{}
	var testsFlag, portFlag string
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-operation timeout")
	flag.BoolVar(&cfg.insecure, "insecure", false, "don't fail on TLS verification errors (like curl -k)")
	flag.StringVar(&cfg.serverName, "servername", "", "TLS SNI override (like openssl -servername)")
	flag.IntVar(&cfg.maxHops, "hops", 30, "max traceroute hops")
	flag.StringVar(&cfg.method, "X", "GET", "HTTP method")
	flag.IntVar(&cfg.showBody, "body", 0, "print first N bytes of the HTTP body")
	flag.StringVar(&testsFlag, "tests", strings.Join(allTests, ","), "comma-separated tests to run: "+strings.Join(allTests, ","))
	flag.StringVar(&portFlag, "port", "", "override port")
	flag.IntVar(&cfg.mss, "mss", 0, "TCP MSS to advertise/use, e.g. 1200 (tests MTU problems; 0 = kernel default)")
	flag.BoolVar(&cfg.retry, "retry", true, "when TCP connects but TLS/HTTP stall, retry with smaller packets to diagnose MTU problems")
	flag.StringVar(&cfg.forceIP, "ip", "", "connect to this IP instead of the DNS answer; Host header and SNI keep the hostname (like curl --resolve)")
	flag.BoolVar(&cfg.prefer6, "6", false, "prefer an IPv6 address when DNS returns both")
	flag.StringVar(&cfg.pcap, "pcap", "", "write a packet capture (tcpdump, or dumpcap as fallback) of traffic to/from the target IP to this file")
	flag.StringVar(&cfg.pcapIface, "pcap-iface", "any", "interface for -pcap")
	var tuiMode, copyFlag bool
	flag.BoolVar(&copyFlag, "copy", false, "copy the report to the clipboard when done (TUI: press y)")
	flag.BoolVar(&tuiMode, "tui", false, "interactive terminal UI (default when no target is given)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <url|host[:port]>\n\nExamples:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                       # interactive TUI\n  %s -tui https://example.com\n  %s https://example.com\n  %s -tests tcp,tls example.com:8443\n  %s -insecure -body 200 http://10.0.0.1:8080/health\n\nFlags:\n", os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	var t *target
	switch {
	case flag.NArg() == 0 && isTerminal():
		tuiMode = true // no target: open the TUI and ask for one
	case flag.NArg() != 1:
		flag.Usage()
		os.Exit(2)
	default:
		var err error
		t, err = parseTarget(flag.Arg(0), portFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
	}
	cfg.portOverride = portFlag
	if cfg.mss != 0 && (cfg.mss < 88 || cfg.mss > 65495) {
		fmt.Fprintln(os.Stderr, "error: -mss must be between 88 and 65495")
		os.Exit(2)
	}
	if cfg.forceIP != "" {
		ip := net.ParseIP(strings.Trim(cfg.forceIP, "[]"))
		if ip == nil {
			fmt.Fprintln(os.Stderr, "error: -ip must be an IP address")
			os.Exit(2)
		}
		cfg.forceIP = ip.String()
	}
	if cfg.mss != 0 && !mssSupported {
		fmt.Fprintln(os.Stderr, "warning: -mss is not supported on this platform and will be ignored")
		cfg.mss = 0
	}
	testsSet := false
	flag.Visit(func(f *flag.Flag) { testsSet = testsSet || f.Name == "tests" })
	cfg.tests = map[string]bool{}
	for _, s := range strings.Split(testsFlag, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		switch s {
		case "telnet":
			s = "tcp"
		case "curl":
			s = "http"
		case "openssl", "ssl":
			s = "tls"
		case "trace":
			s = "traceroute"
		}
		if s != "" {
			cfg.tests[s] = true
		}
	}

	if tuiMode {
		if err := runTUI(t, cfg, testsSet); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	var pinErr error
	t.ip, t.pinHow, pinErr = resolvePin(cfg.ctx(), t, cfg)
	fmt.Print(reportHeader(t))
	cliReport.WriteString(reportHeader(t))
	if pinErr != nil {
		cliReporter.warn("could not resolve %s: %v", t.host, pinErr)
	}

	var capt *capture
	if cfg.pcap != "" {
		if t.ip == "" {
			cliReporter.fail("pcap: no IP to capture (resolution failed)")
		} else if c, err := startCapture(cfg.pcap, cfg.pcapIface, t.ip); err != nil {
			cliReporter.fail("pcap: %v", err)
		} else {
			capt = c
			cliReporter.ok("pcap: capturing %s on %s -> %s", c.filter, cfg.pcapIface, cfg.pcap)
		}
	}

	results := map[string]bool{}
	var ran []string
	for _, name := range selectedTests(t, cfg, testsSet) {
		ran = append(ran, name)
		results[name] = runners[name](t, cfg, cliReporter)
	}
	capSummary := ""
	if capt != nil {
		capSummary = capt.stop()
	}

	cliReporter.title("summary")
	failed := 0
	for _, name := range ran {
		if results[name] {
			cliReporter.ok("%s", name)
		} else {
			cliReporter.fail("%s", name)
			failed++
		}
	}
	if capSummary != "" {
		cliReporter.info("pcap: %s", capSummary)
	}
	if copyFlag {
		if how, err := copyToClipboard(cliReport.String()); err != nil {
			fmt.Fprintln(os.Stderr, "copy to clipboard failed:", err)
		} else {
			fmt.Fprintf(os.Stderr, "\nreport copied to clipboard via %s\n", how)
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// selectedTests returns the tests to run, in order. A plain http:// target
// skips TLS unless -tests named it explicitly.
func selectedTests(t *target, cfg *config, testsSet bool) []string {
	var out []string
	for _, name := range allTests {
		if !cfg.tests[name] {
			continue
		}
		if name == "tls" && t != nil && t.scheme == "http" && !testsSet {
			continue
		}
		out = append(out, name)
	}
	return out
}
