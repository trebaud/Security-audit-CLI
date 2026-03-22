package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/shirou/gopsutil/v3/net"
	"os"
	"os/exec"
	"strings"
)

// --- Styles ---
var (
	titleStyle = lipgloss.NewStyle().Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230")).Padding(0, 1).Bold(true)
	passStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	failStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	descStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

type AuditTask struct {
	Name        string
	Description string
	Status      string // "PASS", "FAIL", "WARN", "RUNNING"
	Message     string
	Details     []string
}

type model struct {
	tasks    []AuditTask
	cursor   int
	expanded map[int]bool
	quitting bool
}

func (m model) Init() tea.Cmd {
	return func() tea.Msg { return auditResultMsg(runAudit()) }
}

// --- Audit Logic ---
func runAudit() []AuditTask {
	tasks := []AuditTask{}

	// 1. Check Listening Ports
	conns, _ := net.Connections("all")
	listenCount := 0
	var portDetails []string
	for _, c := range conns {
		if c.Status == "LISTEN" {
			listenCount++
			proto := "tcp"
			if c.Type == 2 {
				proto = "udp"
			}
			portDetails = append(portDetails, fmt.Sprintf("  %-6s  local=%-22s  pid=%d", proto, fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port), c.Pid))
		}
	}
	portStatus := "PASS"
	if listenCount > 10 {
		portStatus = "WARN"
	}
	tasks = append(tasks, AuditTask{
		Name:        "Open Ports",
		Description: "Check for excessive listening services",
		Status:      portStatus,
		Message:     fmt.Sprintf("Found %d listening ports", listenCount),
		Details:     portDetails,
	})

	// 2. SSH Root Login
	sshCheck := AuditTask{Name: "SSH Config", Description: "Verify Root login is disabled"}
	out, _ := exec.Command("grep", "-i", "^PermitRootLogin yes", "/etc/ssh/sshd_config").Output()
	if len(out) > 0 {
		sshCheck.Status = "FAIL"
		sshCheck.Message = "Root Login is ENABLED"
		sshCheck.Details = []string{
			"  Matched line in /etc/ssh/sshd_config:",
			"    " + strings.TrimSpace(string(out)),
			"  Fix: set 'PermitRootLogin no' and restart sshd",
		}
	} else {
		sshCheck.Status = "PASS"
		sshCheck.Message = "Root Login disabled/not found"
		sshCheck.Details = []string{
			"  No 'PermitRootLogin yes' line found in /etc/ssh/sshd_config",
			"  Root SSH access appears to be disabled",
		}
	}
	tasks = append(tasks, sshCheck)

	// 3. World Writable Files
	findCmd := "find /etc -maxdepth 1 -perm -o+w -type f 2>/dev/null"
	out, _ = exec.Command("sh", "-c", findCmd).Output()
	fileList := strings.TrimSpace(string(out))
	if fileList != "" {
		var details []string
		for _, f := range strings.Split(fileList, "\n") {
			details = append(details, "  "+f)
		}
		details = append(details, "  Fix: chmod o-w <file> for each listed path")
		tasks = append(tasks, AuditTask{
			Name:        "File Perms",
			Description: "Checking for world-writable files in /etc",
			Status:      "FAIL",
			Message:     "Vulnerable files detected!",
			Details:     details,
		})
	} else {
		tasks = append(tasks, AuditTask{
			Name:        "File Perms",
			Description: "Checking for world-writable files in /etc",
			Status:      "PASS",
			Message:     "Permissions look secure",
			Details:     []string{"  No world-writable files found in /etc (depth 1)"},
		})
	}

	return tasks
}

// --- TUI Update/View ---
type auditResultMsg []AuditTask

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case auditResultMsg:
		m.tasks = msg
		m.expanded = make(map[int]bool)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.tasks)-1 {
				m.cursor++
			}
		case "enter", " ":
			if m.expanded == nil {
				m.expanded = make(map[int]bool)
			}
			m.expanded[m.cursor] = !m.expanded[m.cursor]
		}
	}
	return m, nil
}

var cursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Bold(true)
var detailStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("111"))

func (m model) View() string {
	if m.quitting {
		return "Audit Complete. Stay safe!\n"
	}

	s := titleStyle.Render(" SYSTEM SECURITY AUDIT ") + "\n\n"

	for i, t := range m.tasks {
		statusSign := "[  ]"
		style := descStyle

		switch t.Status {
		case "PASS":
			statusSign = passStyle.Render("[ OK ]")
			style = passStyle
		case "FAIL":
			statusSign = failStyle.Render("[!!]")
			style = failStyle
		case "WARN":
			statusSign = warnStyle.Render("[WRN]")
			style = warnStyle
		}

		cursor := "  "
		if i == m.cursor {
			cursor = cursorStyle.Render("▶ ")
		}

		expanded := m.expanded[i]
		toggle := "▸"
		if expanded {
			toggle = "▾"
		}

		s += fmt.Sprintf("%s%s %s %-15s %s\n", cursor, toggle, statusSign, t.Name, style.Render(t.Message))
		s += descStyle.Render("       "+t.Description) + "\n"

		if expanded {
			for _, d := range t.Details {
				s += detailStyle.Render(d) + "\n"
			}
		}
		s += "\n"
	}

	s += descStyle.Render("↑/↓ navigate  Enter toggle details  Q quit")
	return s
}

func main() {
	p := tea.NewProgram(model{})
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
