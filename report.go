package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// formatLine renders one output line the way the CLI prints it.
// With colored=false it is plain text, suitable for a pasted report.
func formatLine(l line, colored bool) string {
	c := func(code, s string) string {
		if colored {
			return color(code, s)
		}
		return s
	}
	switch l.lv {
	case lvTitle:
		return "\n" + c("1;36", "==== "+strings.ToUpper(l.text)+" "+strings.Repeat("=", max(4, 60-len(l.text))))
	case lvOK:
		return c("32", "[ OK ] ") + l.text
	case lvWarn:
		return c("33", "[WARN] ") + l.text
	case lvFail:
		return c("31", "[FAIL] ") + l.text
	default:
		return "       " + l.text
	}
}

func reportHeader(t *target) string {
	return fmt.Sprintf("Target: %s  (host=%s port=%s scheme=%s)\nTime  : %s\n",
		t.raw, t.host, t.port, t.scheme, time.Now().Format(time.RFC3339))
}

// buildReport renders the TUI's test results as a plain-text report.
// If only is >= 0, just that test is included.
func buildReport(t *target, tests []*testState, only int) string {
	var b strings.Builder
	b.WriteString(reportHeader(t))
	var summary []line
	for i, ts := range tests {
		if only >= 0 && i != only {
			continue
		}
		if ts.status == stIdle {
			continue
		}
		b.WriteString(formatLine(line{lvTitle, ts.title}, false) + "\n")
		for _, l := range ts.lines {
			b.WriteString(formatLine(l, false) + "\n")
		}
		switch ts.status {
		case stOK:
			summary = append(summary, line{lvOK, fmt.Sprintf("%-10s %s", ts.name, ts.dur.Round(time.Millisecond))})
		case stFail:
			summary = append(summary, line{lvFail, fmt.Sprintf("%-10s %s", ts.name, ts.dur.Round(time.Millisecond))})
		case stRunning:
			summary = append(summary, line{lvWarn, fmt.Sprintf("%-10s still running", ts.name)})
		}
	}
	if len(summary) == 0 {
		b.WriteString("\n(no tests have been run yet)\n")
		return b.String()
	}
	b.WriteString(formatLine(line{lvTitle, "summary"}, false) + "\n")
	for _, l := range summary {
		b.WriteString(formatLine(l, false) + "\n")
	}
	return b.String()
}

// copyToClipboard puts text on the system clipboard. It tries the native
// clipboard tools first and falls back to the OSC 52 terminal escape, which
// also works over SSH in terminals that support it. Returns the method used.
func copyToClipboard(text string) (string, error) {
	type tool struct {
		bin  string
		args []string
		when bool
	}
	wayland := os.Getenv("WAYLAND_DISPLAY") != ""
	x11 := os.Getenv("DISPLAY") != ""
	tools := []tool{
		{"wl-copy", nil, wayland},
		{"xclip", []string{"-selection", "clipboard"}, x11},
		{"xsel", []string{"--clipboard", "--input"}, x11},
		{"pbcopy", nil, runtime.GOOS == "darwin"},
		{"clip.exe", nil, runtime.GOOS == "windows" || os.Getenv("WSL_DISTRO_NAME") != ""},
		// inside tmux: store in the tmux paste buffer; -w also forwards it to
		// the outer terminal's clipboard when set-clipboard allows it
		{"tmux", []string{"load-buffer", "-w", "-"}, os.Getenv("TMUX") != ""},
	}
	var errs []error
	for _, tl := range tools {
		if !tl.when {
			continue
		}
		path, err := exec.LookPath(tl.bin)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, tl.args...)
		cmd.Stdin = strings.NewReader(text)
		// stdout/stderr stay nil (/dev/null): xclip/xsel/wl-copy fork a child
		// that keeps serving the selection, and a captured pipe would make
		// Run wait for that child to exit.
		if err := cmd.Run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", tl.bin, err))
			continue
		}
		return tl.bin, nil
	}
	if err := copyOSC52(text); err != nil {
		errs = append(errs, err)
		return "", errors.Join(errs...)
	}
	return "OSC 52 (needs terminal support)", nil
}

// copyOSC52 asks the terminal emulator to set the clipboard.
func copyOSC52(text string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		tty = os.Stdout
	} else {
		defer tty.Close()
	}
	seq := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\x07"
	if os.Getenv("TMUX") != "" {
		// tmux passthrough: wrap and double the escape characters
		seq = "\x1bPtmux;" + strings.ReplaceAll(seq, "\x1b", "\x1b\x1b") + "\x1b\\"
	}
	_, err = tty.WriteString(seq)
	return err
}
