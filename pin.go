package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- IP pinning ----------
//
// The target is resolved once and every connection (tcp, tls, http,
// traceroute, packet capture) goes to that one IP, while TLS still sends the
// hostname as SNI and HTTP sends it as the Host header (like curl --resolve).
// That way all tests look at the same server even behind round-robin DNS,
// and -ip can aim the tests at a specific backend.

// resolvePin picks the IP all tests will use.
func resolvePin(ctx context.Context, t *target, cfg *config) (ip, how string, err error) {
	if cfg.forceIP != "" {
		return cfg.forceIP, "from -ip", nil
	}
	if p := net.ParseIP(t.host); p != nil {
		return p.String(), "IP literal", nil
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, t.host)
	if err != nil {
		return "", "", err
	}
	if len(addrs) == 0 {
		return "", "", fmt.Errorf("no addresses for %s", t.host)
	}
	want4 := !cfg.prefer6
	for _, a := range addrs {
		if (a.IP.To4() != nil) == want4 {
			return a.IP.String(), fmt.Sprintf("DNS, %d address(es)", len(addrs)), nil
		}
	}
	return addrs[0].IP.String(), fmt.Sprintf("DNS, %d address(es)", len(addrs)), nil
}

// dialHost is where connections go: the pinned IP if known, else the name.
func (t *target) dialHost() string {
	if t.ip != "" {
		return t.ip
	}
	return t.host
}

func (t *target) dialAddr() string { return net.JoinHostPort(t.dialHost(), t.port) }

// pinNote describes the pinning for test titles, e.g. "→ 200.1.116.233".
func (t *target) pinNote() string {
	if t.ip == "" || t.ip == t.host {
		return ""
	}
	return " → " + t.ip
}

// ---------- packet capture ----------

// capture runs tcpdump in the background, writing a pcap of all traffic to
// and from the pinned IP, plus ICMP (traceroute replies and "fragmentation
// needed" messages come from intermediate routers, not from the target).
type capture struct {
	path   string
	filter string
	cmd    *exec.Cmd
	done   chan struct{}

	mu      sync.Mutex
	stderr  []string
	packets string // set by stop
}

func pcapFilter(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("host %s or icmp6", ip)
	}
	return fmt.Sprintf("host %s or icmp", ip)
}

// startCapture launches tcpdump and waits until it is listening, so the
// first packets of the tests are not missed.
func startCapture(path, iface, ip string) (*capture, error) {
	bin, err := exec.LookPath("tcpdump")
	if err != nil {
		return nil, fmt.Errorf("tcpdump not found (install the tcpdump package)")
	}
	c := &capture{path: path, filter: pcapFilter(ip), done: make(chan struct{})}
	// --immediate-mode + -U: hand over and write each packet at once, so
	// nothing is lost in kernel buffers when we stop it (or get killed)
	// -s 0: full packets; -n: no DNS lookups for the capture itself
	args := []string{"-i", iface, "--immediate-mode", "-U", "-n", "-s", "0", "-w", path}
	if os.Geteuid() == 0 {
		args = append(args, "-Z", "root") // keep write access to path
	}
	args = append(args, c.filter)
	c.cmd = exec.Command(bin, args...)
	c.cmd.SysProcAttr = sysProcAttrNewGroup()
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := c.cmd.Start(); err != nil {
		return nil, err
	}
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			l := sc.Text()
			c.mu.Lock()
			c.stderr = append(c.stderr, l)
			c.mu.Unlock()
			if strings.Contains(l, "listening on") {
				select {
				case ready <- true:
				default:
				}
			}
		}
		ready <- false
	}()
	go func() { _ = c.cmd.Wait(); close(c.done) }()

	select {
	case ok := <-ready:
		if ok {
			return c, nil
		}
	case <-time.After(5 * time.Second):
		c.kill()
		return nil, fmt.Errorf("tcpdump did not start listening within 5s")
	}
	<-c.done
	return nil, fmt.Errorf("tcpdump failed: %s%s", c.lastErr(), privilegeHint(c.lastErr()))
}

func (c *capture) lastErr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stderr) == 0 {
		return "exited without output"
	}
	return c.stderr[len(c.stderr)-1]
}

func privilegeHint(msg string) string {
	m := strings.ToLower(msg)
	if strings.Contains(m, "permission") || strings.Contains(m, "operation not permitted") {
		return "\n  capturing needs root or capabilities, e.g.:\n" +
			"    sudo setcap cap_net_raw,cap_net_admin=eip $(command -v tcpdump)\n" +
			"  or run debug_conn with sudo"
	}
	return ""
}

func (c *capture) kill() {
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

var reCaptured = regexp.MustCompile(`(\d+) packets? captured`)

// stop ends the capture (SIGINT lets tcpdump flush and print its counters)
// and returns a one-line summary.
func (c *capture) stop() string {
	// give in-flight replies a moment to arrive
	time.Sleep(300 * time.Millisecond)
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Signal(syscall.SIGINT)
	}
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		c.kill()
		<-c.done
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := "?"
	for _, l := range c.stderr {
		if m := reCaptured.FindStringSubmatch(l); m != nil {
			n = m[1]
		}
	}
	c.packets = n
	return fmt.Sprintf("%s packets written to %s (filter: %s)", n, c.path, c.filter)
}
