package tui

// view.go — Bubbletea View (pure rendering)
//
// View() is called after every Update() and returns the full terminal string.
// Layout:
//   [fixed]      title banner
//   [fixed]      summary bar  (N PASS  N WARN …)
//   [scrollable] task list    (inside viewport)
//   [fixed]      footer hint

import (
	"fmt"
	"sec-audit/checks"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// View is the Bubbletea View function.
func (m Model) View() string {
	if m.quitting {
		return m.quitView()
	}
	if !m.ready {
		return "\n  Initializing…\n"
	}
	if m.loading {
		return m.loadingView()
	}
	if m.showHelp {
		return m.helpView()
	}

	var sb strings.Builder

	// Fixed header
	sb.WriteString(titleStyle.Render("  SYSTEM SECURITY AUDIT  "))
	sb.WriteString("\n")
	sb.WriteString(m.summaryBar())
	sb.WriteString("\n\n")

	// Scrollable task list
	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	// Fixed footer
	sb.WriteString(helpStyle.Render("↑/↓ navigate  Enter expand/collapse  R re-run  ? help  Q quit"))

	return sb.String()
}

// loadingView renders the loading screen shown while checks are running.
// It shows only a spinner, a progress bar, and a counter — no check names,
// no badges, nothing that resembles the results list. The results list
// appears in one clean swap when the final check completes.
func (m Model) loadingView() string {
	done := 0
	for _, t := range m.tasks {
		if t.Status != checks.StatusRunning {
			done++
		}
	}
	total := len(m.tasks)

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("  SYSTEM SECURITY AUDIT  "))
	sb.WriteString("\n\n")

	// Spinner + label
	sb.WriteString(fmt.Sprintf("  %s  Running security checks…\n\n",
		runningStyle.Render(m.spinner.View())))

	// ASCII progress bar — filled with █, empty with ░, fixed 30 chars wide.
	const barWidth = 30
	filled := 0
	if total > 0 {
		filled = (done * barWidth) / total
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	sb.WriteString(fmt.Sprintf("  %s  %s\n\n",
		runningStyle.Render(bar),
		progressStyle.Render(fmt.Sprintf("%d / %d", done, total)),
	))

	// Footer — only quit is active during loading
	sb.WriteString(helpStyle.Render("  Q  quit"))

	return sb.String()
}

// renderList builds the full string content loaded into the viewport.
// Tasks are rendered in severity order (CRIT/FAIL → WARN → PASS/SKIP),
// but only once all checks have finished to avoid rows jumping during loading.
func (m Model) renderList() string {
	var sb strings.Builder

	indexes := m.sortedIndexes()

	for rank, i := range indexes {
		t := m.tasks[i]

		// Cursor indicator: ▶ on selected row (cursor tracks display rank).
		cursor := "  "
		if rank == m.cursor {
			cursor = cursorStyle.Render("▶ ")
		}

		// Status badge and message colour.
		badge, rowStyle := badgeAndStyle(t.Status)
		if t.Status == checks.StatusRunning {
			badge = runningStyle.Render("[" + m.spinner.View() + "]")
		}

		// Expand/collapse triangle.
		toggle := "▸"
		if m.expanded[i] {
			toggle = "▾"
		}

		// Name padded so the message column aligns across rows.
		name := fmt.Sprintf("%-14s", t.Name)

		// Row 1: cursor  toggle  badge  name  message
		sb.WriteString(fmt.Sprintf("%s%s %s %-20s %s\n",
			cursor, toggle, badge, name, rowStyle.Render(t.Message)))

		// Row 2: description subtitle, indented.
		sb.WriteString(descStyle.Render("      "+t.Description) + "\n")

		// Rows 3+: detail lines, only when expanded.
		// Each line is styled based on whether it is explanatory prose or data.
		if m.expanded[i] && len(t.Details) > 0 {
			sb.WriteString("\n")
			for _, d := range t.Details {
				if isExplanatoryLine(d) {
					sb.WriteString(explanatoryStyle.Render(d) + "\n")
				} else {
					sb.WriteString(detailStyle.Render(d) + "\n")
				}
			}
		}

		// Blank separator between tasks.
		sb.WriteString("\n")
	}

	return sb.String()
}

// isExplanatoryLine reports whether a detail line is prose/explanatory text
// (styled italic grey) vs. a data line (path, command, status flag, value).
//
// Data lines are identified by concrete markers:
//   - Start with [ — status badges like [OK], [FAIL], [WARN]
//   - Start with / — absolute file/dir paths
//   - Start with Fix: / sudo / echo / chmod / apt / dnf / systemctl — commands
//   - Start with a digit — counts, port numbers, version strings
//   - Contain  key=value  or  key: value  patterns (findings)
//
// Everything else is considered explanatory prose.
func isExplanatoryLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return true // blank lines use explanatory style (invisible either way)
	}

	// Known data-line prefixes.
	dataPrefixes := []string{
		"[",            // [OK], [FAIL], [WARN], [CRIT], [!]
		"/",            // absolute paths
		"Fix:", "fix:", // remediation commands
		"sudo ", "echo ", "chmod ", // shell commands
		"apt ", "apt-get ", "dnf ", // package manager commands
		"systemctl ", "service ", // service management
		"usermod ", "userdel ", // user management
		"visudo", "chage ", // auth tools
		"ufw ", "iptables ", "nft ", // firewall commands
		"sysctl ",              // kernel param commands
		"ausearch", "aureport", // audit tools
		"history ", "history -", // history commands
		"HISTCONTROL",  // shell variable
		"tcp ", "udp ", // port listing lines
		"running:", "newest ", // kernel update data
		"auditd ", // auditd findings
	}
	for _, p := range dataPrefixes {
		if strings.HasPrefix(t, p) {
			return false
		}
	}

	// Lines with key=value (e.g. PASS_MAX_DAYS=99999) are data.
	if strings.Contains(t, "=") && !strings.Contains(t, " = ") {
		return false
	}

	// Lines that start with a digit are data (counts, ports, versions).
	if len(t) > 0 && t[0] >= '0' && t[0] <= '9' {
		return false
	}

	// Lines referencing a file:linenum pattern (e.g. /home/user/.bash_history:148).
	if strings.Contains(t, ":") {
		parts := strings.SplitN(t, ":", 2)
		if len(parts[0]) > 0 && (parts[0][0] == '/' || strings.HasSuffix(parts[0], "history") || strings.HasSuffix(parts[0], "sudoers")) {
			return false
		}
	}

	// Everything else is explanatory prose.
	return true
}

// summaryBar renders the aggregate status counts line.
func (m Model) summaryBar() string {
	counts := map[string]int{}
	for _, t := range m.tasks {
		counts[t.Status]++
	}
	var parts []string
	if n := counts[checks.StatusPass]; n > 0 {
		parts = append(parts, summaryCountPass.Render(fmt.Sprintf("%d PASS", n)))
	}
	if n := counts[checks.StatusWarn]; n > 0 {
		parts = append(parts, summaryCountWarn.Render(fmt.Sprintf("%d WARN", n)))
	}
	if n := counts[checks.StatusFail]; n > 0 {
		parts = append(parts, summaryCountFail.Render(fmt.Sprintf("%d FAIL", n)))
	}
	if n := counts[checks.StatusCritical]; n > 0 {
		parts = append(parts, summaryCountCrit.Render(fmt.Sprintf("%d CRIT", n)))
	}
	if n := counts[checks.StatusSkipped]; n > 0 {
		parts = append(parts, summaryCountSkip.Render(fmt.Sprintf("%d SKIP", n)))
	}
	if n := counts[checks.StatusRunning]; n > 0 {
		parts = append(parts, runningStyle.Render(fmt.Sprintf("%d running", n)))
	}
	if len(parts) == 0 {
		return summaryStyle.Render("No checks loaded")
	}
	return summaryStyle.Render(strings.Join(parts, "  "))
}

// helpView renders the keybindings overlay.
func (m Model) helpView() string {
	content := strings.Join([]string{
		titleStyle.Render("  KEYBINDINGS  "),
		"",
		fmt.Sprintf("  %-20s %s", "↑ / k", "Move cursor up"),
		fmt.Sprintf("  %-20s %s", "↓ / j", "Move cursor down"),
		fmt.Sprintf("  %-20s %s", "Enter / Space", "Expand / collapse details"),
		fmt.Sprintf("  %-20s %s", "r", "Re-run all checks"),
		fmt.Sprintf("  %-20s %s", "?", "Toggle this help"),
		fmt.Sprintf("  %-20s %s", "q / Ctrl+C", "Quit"),
		"",
		helpStyle.Render("  Press any key to close"),
	}, "\n")
	return helpBoxStyle.Render(content)
}

// quitView renders the exit summary screen.
func (m Model) quitView() string {
	counts := map[string]int{}
	for _, t := range m.tasks {
		counts[t.Status]++
	}
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("  AUDIT COMPLETE  "))
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("  Ran %d check(s)\n\n", len(m.tasks)))
	if n := counts[checks.StatusPass]; n > 0 {
		sb.WriteString("  " + summaryCountPass.Render(fmt.Sprintf("%-6d PASS", n)) + "\n")
	}
	if n := counts[checks.StatusWarn]; n > 0 {
		sb.WriteString("  " + summaryCountWarn.Render(fmt.Sprintf("%-6d WARN", n)) + "\n")
	}
	if n := counts[checks.StatusFail]; n > 0 {
		sb.WriteString("  " + summaryCountFail.Render(fmt.Sprintf("%-6d FAIL", n)) + "\n")
	}
	if n := counts[checks.StatusCritical]; n > 0 {
		sb.WriteString("  " + summaryCountCrit.Render(fmt.Sprintf("%-6d CRIT", n)) + "\n")
	}
	if n := counts[checks.StatusSkipped]; n > 0 {
		sb.WriteString("  " + summaryCountSkip.Render(fmt.Sprintf("%-6d SKIP", n)) + "\n")
	}
	issues := counts[checks.StatusFail] + counts[checks.StatusCritical]
	sb.WriteString("\n")
	if issues > 0 {
		sb.WriteString(failStyle.Render(fmt.Sprintf("  %d issue(s) require attention.", issues)) + "\n")
	} else {
		sb.WriteString(passStyle.Render("  System looks clean. Stay safe!") + "\n")
	}
	return sb.String()
}

// badgeAndStyle returns the rendered status badge and lipgloss style for the
// message text, for a given status string.
func badgeAndStyle(status string) (badge string, msgStyle lipgloss.Style) {
	switch status {
	case checks.StatusPass:
		return passStyle.Render("[ OK ]"), passStyle
	case checks.StatusFail:
		return failStyle.Render("[ !! ]"), failStyle
	case checks.StatusWarn:
		return warnStyle.Render("[WRN ]"), warnStyle
	case checks.StatusCritical:
		return critStyle.Render("[CRIT]"), critStyle
	case checks.StatusSkipped:
		return skipStyle.Render("[SKIP]"), skipStyle
	default:
		return descStyle.Render("[    ]"), descStyle
	}
}
