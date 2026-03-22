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
	hint := "↑/↓ navigate  Enter expand/collapse  R re-run  ? help  Q quit"
	if !m.allDone() {
		hint = "running checks…  ↑/↓ navigate  Q quit"
	}
	sb.WriteString(helpStyle.Render(hint))

	return sb.String()
}

// renderList builds the full string content loaded into the viewport.
// Each task renders as 3 lines when collapsed, more when expanded.
func (m Model) renderList() string {
	var sb strings.Builder

	for i, t := range m.tasks {
		// Cursor indicator: ▶ on selected row, two spaces otherwise.
		cursor := "  "
		if i == m.cursor {
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
		if m.expanded[i] && len(t.Details) > 0 {
			sb.WriteString("\n")
			for _, d := range t.Details {
				sb.WriteString(detailStyle.Render(d) + "\n")
			}
		}

		// Blank separator between tasks.
		sb.WriteString("\n")
	}

	return sb.String()
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
