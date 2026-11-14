package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------- styles ----------

var (
	cGreen  = lipgloss.AdaptiveColor{Light: "#1a7f37", Dark: "#3fb950"}
	cRed    = lipgloss.AdaptiveColor{Light: "#cf222e", Dark: "#f85149"}
	cYellow = lipgloss.AdaptiveColor{Light: "#9a6700", Dark: "#d29922"}
	cAccent = lipgloss.AdaptiveColor{Light: "#0969da", Dark: "#58a6ff"}
	cDim    = lipgloss.AdaptiveColor{Light: "#8c959f", Dark: "#6e7681"}
	cBorder = lipgloss.AdaptiveColor{Light: "#d0d7de", Dark: "#30363d"}

	sOK      = lipgloss.NewStyle().Foreground(cGreen)
	sFail    = lipgloss.NewStyle().Foreground(cRed)
	sWarn    = lipgloss.NewStyle().Foreground(cYellow)
	sDim     = lipgloss.NewStyle().Foreground(cDim)
	sAccent  = lipgloss.NewStyle().Foreground(cAccent)
	sBold    = lipgloss.NewStyle().Bold(true)
	sHeading = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sBadge   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ffffff")).Background(cAccent).Padding(0, 1)
	sErr     = lipgloss.NewStyle().Bold(true).Foreground(cRed)
	sBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder)
	sBoxSel  = sBox.BorderForeground(cAccent)
	sCursor  = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
)

const listWidth = 30 // including border

// ---------- state ----------

type status int

const (
	stIdle status = iota
	stRunning
	stOK
	stFail
)

type testState struct {
	name    string
	enabled bool
	status  status
	title   string
	lines   []line
	warned  bool
	start   time.Time
	dur     time.Duration
	run     int // generation; stale messages from earlier runs are dropped
	cancel  context.CancelFunc
}

type lineMsg struct {
	idx, run int
	l        line
}

type clearNoticeMsg struct{ n int }

type copiedMsg struct {
	what, how string
	err       error
}

type doneMsg struct {
	idx, run int
	ok       bool
	dur      time.Duration
}

type model struct {
	cfg      *config
	testsSet bool
	target   *target

	tests  []*testState
	cursor int // 0 = overview, 1..n = tests

	input   textinput.Model
	editing bool
	errMsg  string
	notice  string // transient status line (e.g. "copied to clipboard")
	noticeN int

	vp     viewport.Model
	spin   spinner.Model
	events chan tea.Msg

	width, height int
	ready         bool
}

func runTUI(t *target, cfg *config, testsSet bool) error {
	m := newModel(t, cfg, testsSet)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	final, err := p.Run()
	if fm, ok := final.(*model); ok {
		fm.cancelAll()
	}
	return err
}

func newModel(t *target, cfg *config, testsSet bool) *model {
	m := &model{
		cfg:      cfg,
		testsSet: testsSet,
		target:   t,
		events:   make(chan tea.Msg, 1024),
	}
	for _, name := range allTests {
		m.tests = append(m.tests, &testState{name: name, title: name, enabled: cfg.tests[name]})
	}
	m.input = textinput.New()
	m.input.Prompt = ""
	m.input.Placeholder = "https://example.com  or  host:port"
	m.input.CharLimit = 512
	if t != nil {
		m.input.SetValue(t.raw)
		m.applyTLSDefault()
	} else {
		m.editing = true
		m.input.Focus()
	}
	m.spin = spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(sAccent))

	m.vp = viewport.New(0, 0)
	m.vp.MouseWheelEnabled = true
	m.vp.KeyMap = viewport.KeyMap{
		PageDown:     key.NewBinding(key.WithKeys("pgdown", " ", "f")),
		PageUp:       key.NewBinding(key.WithKeys("pgup", "b")),
		HalfPageDown: key.NewBinding(key.WithKeys("ctrl+d")),
		HalfPageUp:   key.NewBinding(key.WithKeys("ctrl+u")),
		Down:         key.NewBinding(key.WithKeys("shift+down", "J")),
		Up:           key.NewBinding(key.WithKeys("shift+up", "K")),
	}
	return m
}

// A plain http:// target skips TLS by default, unless -tests asked for it.
func (m *model) applyTLSDefault() {
	if m.testsSet || m.target == nil {
		return
	}
	for _, ts := range m.tests {
		if ts.name == "tls" {
			ts.enabled = m.target.scheme != "http" && m.cfg.tests["tls"]
		}
	}
}

func (m *model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spin.Tick, m.waitEvent(), textinput.Blink}
	if m.target != nil {
		m.runAll()
	}
	return tea.Batch(cmds...)
}

func (m *model) waitEvent() tea.Cmd {
	return func() tea.Msg { return <-m.events }
}

// ---------- running tests ----------

func (m *model) runAll() {
	for i, ts := range m.tests {
		if ts.enabled {
			m.runOne(i)
		}
	}
}

func (m *model) runOne(i int) {
	if m.target == nil {
		return
	}
	ts := m.tests[i]
	if ts.cancel != nil {
		ts.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	ts.cancel = cancel
	ts.run++
	ts.status = stRunning
	ts.lines = nil
	ts.warned = false
	ts.title = ts.name
	ts.start = time.Now()
	ts.dur = 0

	run, t, ch := ts.run, *m.target, m.events
	cfg := *m.cfg
	cfg.context = ctx
	fn := runners[ts.name]
	go func() {
		rep := &reporter{emit: func(l line) { ch <- lineMsg{i, run, l} }}
		start := time.Now()
		ok := false
		func() {
			defer func() {
				if p := recover(); p != nil {
					rep.fail("panic: %v", p)
					ok = false
				}
			}()
			ok = fn(&t, &cfg, rep)
		}()
		if ctx.Err() != nil {
			rep.warn("cancelled")
		}
		ch <- doneMsg{i, run, ok, time.Since(start)}
	}()
}

func (m *model) cancelAll() {
	for _, ts := range m.tests {
		if ts.cancel != nil {
			ts.cancel()
		}
	}
}

// ---------- update ----------

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ready = true
		m.layout()

	case lineMsg:
		ts := m.tests[msg.idx]
		if msg.run == ts.run {
			if msg.l.lv == lvTitle {
				ts.title = msg.l.text
			} else {
				ts.lines = append(ts.lines, msg.l)
				if msg.l.lv == lvWarn {
					ts.warned = true
				}
			}
		}
		cmds = append(cmds, m.waitEvent())

	case doneMsg:
		ts := m.tests[msg.idx]
		if msg.run == ts.run {
			ts.dur = msg.dur
			if msg.ok {
				ts.status = stOK
			} else {
				ts.status = stFail
			}
			ts.cancel = nil
		}
		cmds = append(cmds, m.waitEvent())

	case copiedMsg:
		if msg.err != nil {
			m.notice = sErr.Render("✗ copy failed: " + msg.err.Error())
		} else {
			m.notice = sOK.Render("✓ "+msg.what+" copied to clipboard") + sDim.Render(" via "+msg.how)
		}
		m.noticeN++
		n := m.noticeN
		cmds = append(cmds, tea.Tick(4*time.Second, func(time.Time) tea.Msg { return clearNoticeMsg{n} }))

	case clearNoticeMsg:
		if msg.n == m.noticeN {
			m.notice = ""
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		cmds = append(cmds, cmd)

	case tea.MouseMsg:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		cmds = append(cmds, cmd)

	case tea.KeyMsg:
		if m.editing {
			cmds = append(cmds, m.updateEditing(msg))
		} else {
			cmds = append(cmds, m.updateNormal(msg))
		}
	}

	m.refreshViewport()
	return m, tea.Batch(cmds...)
}

func (m *model) updateEditing(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		if m.target != nil {
			m.editing = false
			m.input.Blur()
			m.input.SetValue(m.target.raw)
			m.errMsg = ""
		}
		return nil
	case "enter":
		t, err := parseTarget(strings.TrimSpace(m.input.Value()), m.cfg.portOverride)
		if err != nil || strings.TrimSpace(m.input.Value()) == "" {
			if err == nil {
				err = fmt.Errorf("enter a target")
			}
			m.errMsg = err.Error()
			return nil
		}
		m.errMsg = ""
		m.target = t
		m.cancelAll()
		for _, ts := range m.tests { // forget results from the previous target
			ts.run++
			ts.status, ts.lines, ts.warned, ts.dur, ts.cancel, ts.title = stIdle, nil, false, 0, nil, ts.name
		}
		m.editing = false
		m.input.Blur()
		m.applyTLSDefault()
		m.cursor = 0
		m.runAll()
		return nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return cmd
}

func (m *model) updateNormal(msg tea.KeyMsg) tea.Cmd {
	prev := m.cursor
	switch msg.String() {
	case "q", "ctrl+c":
		m.cancelAll()
		return tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.tests) {
			m.cursor++
		}
	case "home", "g":
		m.vp.GotoTop()
	case "end", "G":
		m.vp.GotoBottom()
	case "e", "/":
		m.editing = true
		m.input.Focus()
		m.input.CursorEnd()
		return textinput.Blink
	case "x", "tab":
		if m.cursor > 0 {
			ts := m.tests[m.cursor-1]
			ts.enabled = !ts.enabled
		}
	case "enter", "r":
		if m.cursor == 0 {
			m.runAll()
		} else {
			m.runOne(m.cursor - 1)
		}
	case "R", "a":
		m.runAll()
	case "c":
		if m.cursor > 0 {
			if ts := m.tests[m.cursor-1]; ts.cancel != nil {
				ts.cancel()
			}
		} else {
			m.cancelAll()
		}
	case "y", "Y":
		if m.target == nil {
			return nil
		}
		only, what := -1, "report"
		if msg.String() == "Y" && m.cursor > 0 {
			only, what = m.cursor-1, m.tests[m.cursor-1].name+" report"
		}
		text := buildReport(m.target, m.tests, only)
		return func() tea.Msg {
			how, err := copyToClipboard(text)
			return copiedMsg{what, how, err}
		}
	case "i":
		m.cfg.insecure = !m.cfg.insecure
	case "1", "2", "3", "4", "5", "6":
		n := int(msg.String()[0] - '0')
		if n <= len(m.tests) {
			m.cursor = n
		}
	case "0", "o":
		m.cursor = 0
	default:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return cmd
	}
	if m.cursor != prev {
		m.refreshViewport()
		m.vp.GotoTop()
	}
	return nil
}

// ---------- layout / rendering ----------

func (m *model) bodyHeight() int { return max(3, m.height-2) } // header + footer

func (m *model) layout() {
	innerW := max(10, m.width-listWidth-2) // minus right box border
	m.vp.Width = max(10, innerW-2)         // minus horizontal padding
	m.vp.Height = max(1, m.bodyHeight()-3) // minus border(2) + panel title
	m.input.Width = max(10, m.width-40)
}

func (m *model) refreshViewport() {
	if !m.ready {
		return
	}
	follow := m.vp.AtBottom()
	m.vp.SetContent(m.renderContent(m.vp.Width))
	if follow {
		m.vp.GotoBottom()
	}
}

func renderLine(l line, width int) string {
	var prefix string
	style := lipgloss.NewStyle()
	switch l.lv {
	case lvOK:
		prefix = sOK.Render("✓ ")
	case lvFail:
		prefix, style = sFail.Render("✗ "), sFail
	case lvWarn:
		prefix, style = sWarn.Render("! "), sWarn
	case lvTitle:
		return sHeading.Width(width).Render(l.text)
	default:
		prefix = "  "
	}
	// wrap the text and indent continuation lines under the first one
	wrapped := style.Width(max(1, width-2)).Render(l.text)
	return prefix + strings.ReplaceAll(wrapped, "\n", "\n  ")
}

func (m *model) renderContent(width int) string {
	if m.target == nil {
		return sDim.Render("Type a URL or host[:port] above and press Enter.\n\n" +
			"Examples:\n  https://example.com\n  example.com:8443\n  http://10.0.0.1:8080/health")
	}
	var b strings.Builder
	write := func(ts *testState, withHeading bool) {
		if withHeading {
			b.WriteString(m.statusIcon(ts) + " " + sHeading.Render(strings.ToUpper(ts.title)) +
				"  " + sDim.Render(m.durString(ts)) + "\n")
		}
		switch {
		case !ts.enabled && ts.status == stIdle:
			b.WriteString(sDim.Render("  disabled (press x on this test to enable)") + "\n")
		case ts.status == stIdle:
			b.WriteString(sDim.Render("  not run yet — press r") + "\n")
		case len(ts.lines) == 0 && ts.status == stRunning:
			b.WriteString(sDim.Render("  running…") + "\n")
		}
		for _, l := range ts.lines {
			b.WriteString(renderLine(l, width) + "\n")
		}
	}
	if m.cursor == 0 {
		for i, ts := range m.tests {
			if i > 0 {
				b.WriteString("\n")
			}
			write(ts, true)
		}
	} else {
		write(m.tests[m.cursor-1], false)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m *model) statusIcon(ts *testState) string {
	switch {
	case ts.status == stRunning:
		return m.spin.View()
	case ts.status == stOK && ts.warned:
		return sWarn.Render("✓")
	case ts.status == stOK:
		return sOK.Render("✓")
	case ts.status == stFail:
		return sFail.Render("✗")
	case !ts.enabled:
		return sDim.Render("○")
	default:
		return sDim.Render("·")
	}
}

func (m *model) durString(ts *testState) string {
	switch ts.status {
	case stRunning:
		return time.Since(ts.start).Truncate(100 * time.Millisecond).String()
	case stOK, stFail:
		if ts.dur < time.Second {
			return ts.dur.Round(time.Millisecond).String()
		}
		return ts.dur.Round(10 * time.Millisecond).String()
	}
	return ""
}

func (m *model) summaryCounts() (okN, failN, runN int) {
	for _, ts := range m.tests {
		switch ts.status {
		case stOK:
			okN++
		case stFail:
			failN++
		case stRunning:
			runN++
		}
	}
	return
}

func (m *model) renderList(height int) string {
	inner := listWidth - 2
	var rows []string

	item := func(sel bool, icon, name, right, desc string, dim bool) {
		cur := "  "
		if sel {
			cur = sCursor.Render("▸ ")
		}
		nameS := sBold.Render(name)
		if dim {
			nameS = sDim.Render(name)
		} else if sel {
			nameS = sCursor.Render(name)
		}
		left := cur + icon + " " + nameS
		gap := max(1, inner-lipgloss.Width(left)-lipgloss.Width(right)-1)
		rows = append(rows, left+strings.Repeat(" ", gap)+sDim.Render(right))
		rows = append(rows, "    "+sDim.Render(desc))
	}

	okN, failN, runN := m.summaryCounts()
	sum := fmt.Sprintf("%d ok  %d fail", okN, failN)
	if runN > 0 {
		sum = fmt.Sprintf("%d running", runN)
	}
	icon := sDim.Render("◆")
	switch {
	case runN > 0:
		icon = m.spin.View()
	case failN > 0:
		icon = sFail.Render("◆")
	case okN > 0:
		icon = sOK.Render("◆")
	}
	item(m.cursor == 0, icon, "overview", "", sum, false)
	rows = append(rows, sDim.Render(strings.Repeat("─", inner)))

	for i, ts := range m.tests {
		item(m.cursor == i+1, m.statusIcon(ts), fmt.Sprintf("%d %s", i+1, ts.name),
			m.durString(ts), testDesc[ts.name], !ts.enabled)
	}

	opts := []string{"", sDim.Render(strings.Repeat("─", inner))}
	opts = append(opts, sDim.Render(fmt.Sprintf(" timeout  %s", m.cfg.timeout)))
	ins := sDim.Render("off")
	if m.cfg.insecure {
		ins = sWarn.Render("ON")
	}
	opts = append(opts, sDim.Render(" insecure ")+ins+sDim.Render("  (i)"))
	rows = append(rows, opts...)

	return sBox.Width(inner).Height(height - 2).Render(clipLines(strings.Join(rows, "\n"), height-2))
}

func (m *model) renderPanel(height int) string {
	innerW := max(10, m.width-listWidth-2)
	var title string
	if m.cursor == 0 {
		title = sHeading.Render("ALL TESTS")
	} else {
		ts := m.tests[m.cursor-1]
		title = m.statusIcon(ts) + " " + sHeading.Render(strings.ToUpper(ts.title)) + "  " + sDim.Render(m.durString(ts))
	}
	if pct := m.vp.ScrollPercent(); m.vp.TotalLineCount() > m.vp.Height {
		r := sDim.Render(fmt.Sprintf("%3.0f%%", pct*100))
		gap := max(1, innerW-2-lipgloss.Width(title)-lipgloss.Width(r))
		title += strings.Repeat(" ", gap) + r
	}
	body := title + "\n" + m.vp.View()
	return sBoxSel.Width(innerW).Height(height-2).Padding(0, 1).Render(clipLines(body, height-2))
}

func (m *model) View() string {
	if !m.ready {
		return "loading…"
	}
	// header
	var tgt string
	if m.editing {
		tgt = sAccent.Render("› ") + m.input.View()
	} else if m.target != nil {
		tgt = sBold.Render(m.target.url()) + sDim.Render(fmt.Sprintf("  (%s:%s)", m.target.host, m.target.port))
	}
	header := sBadge.Render("debug_conn") + " " + sDim.Render("target") + " " + tgt
	if m.errMsg != "" {
		header += "  " + sErr.Render(m.errMsg)
	}
	if m.notice != "" {
		header += "   " + m.notice
	}
	header = lipgloss.NewStyle().MaxWidth(m.width).Render(header)

	h := m.bodyHeight()
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.renderList(h), m.renderPanel(h))

	// footer
	var keys [][2]string
	if m.editing {
		keys = [][2]string{{"enter", "run"}, {"esc", "cancel"}, {"ctrl+c", "quit"}}
	} else {
		keys = [][2]string{
			{"↑↓", "select"}, {"r", "run"}, {"a", "run all"}, {"x", "toggle"},
			{"c", "cancel"}, {"e", "edit target"}, {"y/Y", "copy all/selected"}, {"pgup/pgdn", "scroll"}, {"q", "quit"},
		}
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, sAccent.Render(k[0])+" "+sDim.Render(k[1]))
	}
	footer := lipgloss.NewStyle().MaxWidth(m.width).Render(" " + strings.Join(parts, sDim.Render(" · ")))

	return header + "\n" + body + "\n" + footer
}

// clipLines keeps at most n lines so a panel never grows past the window.
func clipLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:max(0, n)]
	}
	return strings.Join(lines, "\n")
}
