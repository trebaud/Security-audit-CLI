package tui

// model.go — Bubbletea Model, Init, and Update
//
// State machine for the TUI. Uses a cursor-based navigation model (cursor int
// tracks the selected row) rather than a free-scroll viewport. The viewport is
// used only to clip/render the visible portion of the list and is scrolled
// programmatically to always keep the cursor row visible.

import (
	"sec-audit/checks"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// checkResultMsg is delivered to Update when a single check goroutine finishes.
type checkResultMsg struct {
	index int
	task  checks.Task
}

// tickMsg is defined for future use; spinner animation uses spinner.TickMsg.
type tickMsg time.Time

// Model holds all mutable state for the TUI.
type Model struct {
	tasks       []checks.Task  // one per check; starts as StatusRunning stubs
	checksToRun []checks.Check // original check list, kept for re-run
	cursor      int            // index of the currently selected row
	expanded    map[int]bool   // which rows have their detail panel open
	quitting    bool           // true after q/Ctrl+C → renders quit screen
	showHelp    bool           // true while the ? help overlay is shown

	spinner  spinner.Model
	viewport viewport.Model
	ready    bool // true once the first WindowSizeMsg has arrived
	width    int
	height   int
}

// New creates an initialized Model with all tasks pre-set to StatusRunning.
func New(checksToRun []checks.Check) Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = runningStyle

	tasks := make([]checks.Task, len(checksToRun))
	for i, c := range checksToRun {
		tasks[i] = checks.Task{
			ID:          c.ID(),
			Name:        placeholderName(c),
			Description: placeholderDesc(c),
			Status:      checks.StatusRunning,
			Message:     "running…",
		}
	}

	return Model{
		tasks:       tasks,
		checksToRun: checksToRun,
		expanded:    make(map[int]bool),
		spinner:     sp,
	}
}

// placeholderName returns a display name for a check before its Run() returns.
func placeholderName(c checks.Check) string {
	names := map[string]string{
		"ports":        "Open Ports",
		"ssh":          "SSH Config",
		"fileperm":     "File Perms",
		"aslr":         "ASLR",
		"sudoers":      "Sudoers",
		"firewall":     "Firewall",
		"suid":         "SUID/SGID",
		"auditd":       "Auditd",
		"passwdpolicy": "Passwd Policy",
		"stickybit":    "Sticky Bit",
	}
	if n, ok := names[c.ID()]; ok {
		return n
	}
	return c.ID()
}

// placeholderDesc returns the subtitle for a check before its Run() returns.
func placeholderDesc(c checks.Check) string {
	descs := map[string]string{
		"ports":        "Check for excessive listening services",
		"ssh":          "Verify SSH daemon hardening",
		"fileperm":     "World-writable files in /etc",
		"aslr":         "Address Space Layout Randomization",
		"sudoers":      "Detect NOPASSWD sudo rules",
		"firewall":     "Verify a firewall is active",
		"suid":         "SUID/SGID binaries outside expected paths",
		"auditd":       "Linux audit daemon status",
		"passwdpolicy": "Password aging and length policy",
		"stickybit":    "Sticky bit on world-writable dirs",
	}
	if d, ok := descs[c.ID()]; ok {
		return d
	}
	return ""
}

// Init fires all checks concurrently as tea.Cmds and starts the spinner.
func (m Model) Init() tea.Cmd {
	cmds := make([]tea.Cmd, len(m.checksToRun))
	for i, c := range m.checksToRun {
		i, c := i, c // capture loop vars
		cmds[i] = func() tea.Msg {
			return checkResultMsg{index: i, task: c.Run()}
		}
	}
	cmds = append(cmds, m.spinner.Tick)
	return tea.Batch(cmds...)
}

// Update is the pure state-transition function.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	// WindowSizeMsg: initialize or resize the viewport.
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 5 // title + summary + 2 blank lines
		footerHeight := 2 // key-hint + 1 blank
		vpHeight := m.height - headerHeight - footerHeight
		if vpHeight < 1 {
			vpHeight = 1
		}
		if !m.ready {
			m.viewport = viewport.New(m.width, vpHeight)
			m.ready = true
		} else {
			m.viewport.Width = m.width
			m.viewport.Height = vpHeight
		}
		m.viewport.SetContent(m.renderList())
		m.scrollToCursor()

	// checkResultMsg: a check finished — replace its RUNNING stub.
	case checkResultMsg:
		m.tasks[msg.index] = msg.task
		if m.ready {
			m.viewport.SetContent(m.renderList())
			m.scrollToCursor()
		}

	// spinner.TickMsg: advance the spinner animation frame.
	// Re-render the list so the spinner dots update, but preserve the cursor.
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
		if m.ready {
			// Save scroll position before SetContent (it does NOT reset YOffset
			// unless content shrinks past it, but be explicit for clarity).
			saved := m.viewport.YOffset
			m.viewport.SetContent(m.renderList())
			m.viewport.SetYOffset(saved)
		}

	// KeyMsg: keyboard input.
	case tea.KeyMsg:
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "?":
			m.showHelp = true

		case "r":
			return m.resetAndRerun()

		// Cursor navigation — move between rows, then scroll viewport to follow.
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.scrollToCursor()
			}

		case "down", "j":
			if m.cursor < len(m.tasks)-1 {
				m.cursor++
				m.scrollToCursor()
			}

		// Toggle the detail panel on the currently selected row.
		case "enter", " ":
			m.expanded[m.cursor] = !m.expanded[m.cursor]
			if m.ready {
				m.viewport.SetContent(m.renderList())
				m.scrollToCursor()
			}
		}
	}

	return m, tea.Batch(cmds...)
}

// rowTopLine returns the line index (0-based) within the rendered list where
// task i begins. Collapsed tasks take 3 lines; expanded tasks take 3 + 1 +
// len(Details) lines (the +1 is the blank separator before detail lines).
func (m Model) rowTopLine(i int) int {
	line := 0
	for j := 0; j < i; j++ {
		line += m.taskHeight(j)
	}
	return line
}

// taskHeight returns the number of rendered lines occupied by task i.
func (m Model) taskHeight(i int) int {
	if i < 0 || i >= len(m.tasks) {
		return 0
	}
	// Base: 1 (badge+name row) + 1 (description row) + 1 (blank separator)
	h := 3
	if m.expanded[i] && len(m.tasks[i].Details) > 0 {
		// 1 blank line before details + N detail lines
		h += 1 + len(m.tasks[i].Details)
	}
	return h
}

// scrollToCursor adjusts the viewport's YOffset so the cursor row is fully
// visible. Called after any operation that moves the cursor or changes task
// heights (expand/collapse, new result arriving).
func (m *Model) scrollToCursor() {
	if !m.ready {
		return
	}
	top := m.rowTopLine(m.cursor)
	bottom := top + m.taskHeight(m.cursor) - 1

	if top < m.viewport.YOffset {
		// Cursor row is above the visible area — scroll up to it.
		m.viewport.SetYOffset(top)
	} else if bottom >= m.viewport.YOffset+m.viewport.Height {
		// Cursor row's last line is below the visible area — scroll down.
		m.viewport.SetYOffset(bottom - m.viewport.Height + 1)
	}
}

// resetAndRerun resets all tasks to RUNNING and re-fires all checks.
func (m Model) resetAndRerun() (tea.Model, tea.Cmd) {
	for i := range m.tasks {
		m.tasks[i].Status = checks.StatusRunning
		m.tasks[i].Message = "running…"
		m.tasks[i].Details = nil
	}
	m.expanded = make(map[int]bool)
	m.cursor = 0
	if m.ready {
		m.viewport.SetContent(m.renderList())
		m.viewport.SetYOffset(0)
	}
	return m, m.Init()
}

// allDone returns true when no task is still RUNNING.
func (m Model) allDone() bool {
	for _, t := range m.tasks {
		if t.Status == checks.StatusRunning {
			return false
		}
	}
	return true
}
