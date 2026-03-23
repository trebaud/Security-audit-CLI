package tui

// model.go — Bubbletea Model, Init, and Update
//
// State machine for the TUI. Uses a cursor-based navigation model (cursor int
// tracks the selected row) rather than a free-scroll viewport. The viewport is
// used only to clip/render the visible portion of the list and is scrolled
// programmatically to always keep the cursor row visible.

import (
	"sec-audit/checks"
	"sort"
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
	cursor      int            // index of the currently selected row (display rank)
	expanded    map[int]bool   // which rows have their detail panel open (keyed by task index)
	quitting    bool           // true after q/Ctrl+C → renders quit screen
	showHelp    bool           // true while the ? help overlay is shown

	// loading is true while at least one check is still running.
	// During loading, the loading screen is shown instead of the task list.
	// This prevents the unsorted-then-sorted flash: the list is never shown
	// until all results are in and sorted order is stable.
	loading bool

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
		loading:     true, // show loading screen until all checks finish
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
		"secupdates":   "Sec Updates",
		"kernelupdate": "Kernel",
		"passwdfile":   "Auth Files",
		"sudol":        "Sudo -l",
		"shellhistory": "Shell History",
		"writablepath": "PATH Hijack",
		"cron":         "Cron Jobs",
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
		"secupdates":   "Pending security updates in package manager",
		"kernelupdate": "Running kernel vs latest installed version",
		"passwdfile":   "/etc/passwd & /etc/shadow permissions and content",
		"sudol":        "Current user's sudo privileges",
		"shellhistory": "Shell history files for embedded credentials",
		"writablepath": "World-writable directories in $PATH",
		"cron":         "Writable scripts in system cron jobs",
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
		// Only write content into the viewport once all results are in and
		// sorted order is stable. During loading we size the viewport but leave
		// it empty — writing partial results here causes a one-frame unsorted
		// flash when loading flips to false a moment later.
		if !m.loading {
			m.viewport.SetContent(m.renderList())
			m.scrollToCursor()
		}

	// checkResultMsg: a check finished — replace its RUNNING stub.
	case checkResultMsg:
		m.tasks[msg.index] = msg.task

		if m.allDone() {
			m.loading = false
			m.cursor = 0
			m.expanded = make(map[int]bool)
			if m.ready {
				// Viewport exists — populate it with the fully sorted list now,
				// before loading flips so there is zero chance of a stale frame.
				m.viewport.SetContent(m.renderList())
				m.viewport.SetYOffset(0)
			}
			// If !m.ready the viewport hasn't been created yet. The upcoming
			// WindowSizeMsg will call SetContent at that point (loading is
			// already false so it will take the !m.loading branch above).
		}

	// spinner.TickMsg: advance the spinner animation frame.
	// During loading the spinner is rendered directly in loadingView() so no
	// viewport update is needed. After loading it is no longer ticking.
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	// KeyMsg: keyboard input.
	case tea.KeyMsg:
		// Help overlay: any key dismisses it.
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

		// All keys below are only active once the results list is shown.
		// During loading, only q/ctrl+c is accepted (handled above).
		if m.loading {
			break
		}

		switch msg.String() {
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
			indexes := m.sortedIndexes()
			taskIdx := indexes[m.cursor]
			m.expanded[taskIdx] = !m.expanded[taskIdx]
			if m.ready {
				m.viewport.SetContent(m.renderList())
				m.scrollToCursor()
			}
		}
	}

	return m, tea.Batch(cmds...)
}

// rowTopLine returns the line index (0-based) within the rendered list where
// display rank `rank` begins. Uses sortedIndexes so it matches renderList.
func (m Model) rowTopLine(rank int) int {
	indexes := m.sortedIndexes()
	line := 0
	for r := 0; r < rank; r++ {
		line += m.taskHeight(indexes[r])
	}
	return line
}

// taskHeight returns the number of rendered lines occupied by task at taskIdx.
func (m Model) taskHeight(taskIdx int) int {
	if taskIdx < 0 || taskIdx >= len(m.tasks) {
		return 0
	}
	// Base: 1 (badge+name row) + 1 (description row) + 1 (blank separator)
	h := 3
	if m.expanded[taskIdx] && len(m.tasks[taskIdx].Details) > 0 {
		// 1 blank line before details + N detail lines
		h += 1 + len(m.tasks[taskIdx].Details)
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
	indexes := m.sortedIndexes()
	top := m.rowTopLine(m.cursor)
	bottom := top + m.taskHeight(indexes[m.cursor]) - 1

	if top < m.viewport.YOffset {
		m.viewport.SetYOffset(top)
	} else if bottom >= m.viewport.YOffset+m.viewport.Height {
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
	m.loading = true // show loading screen again during re-run
	if m.ready {
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

// sortedIndexes returns task indexes in display order:
// CRIT → FAIL → WARN → SKIP → PASS, stable within each group.
// This is only ever called after loading is complete (all checks done),
// so no guard for the running state is needed.
func (m Model) sortedIndexes() []int {
	indexes := make([]int, len(m.tasks))
	for i := range indexes {
		indexes[i] = i
	}
	severity := map[string]int{
		checks.StatusCritical: 0,
		checks.StatusFail:     1,
		checks.StatusWarn:     2,
		checks.StatusSkipped:  3,
		checks.StatusPass:     4,
		checks.StatusRunning:  5,
	}
	sort.SliceStable(indexes, func(a, b int) bool {
		return severity[m.tasks[indexes[a]].Status] < severity[m.tasks[indexes[b]].Status]
	})
	return indexes
}
