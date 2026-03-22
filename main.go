package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

var (
	headerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	listStyle   = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).PaddingLeft(2).BorderForeground(lipgloss.Color("63"))
)

type connection struct {
	PID    int32
	Name   string
	Port   uint32
	Status string
}

type model struct {
	connections []connection
	cursor      int
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up":
			if m.cursor > 0 { m.cursor-- }
		case "down":
			if m.cursor < len(m.connections)-1 { m.cursor++ }
		}
	}
	return m, nil
}

func (m model) View() string {
	var s strings.Builder
	s.WriteString(headerStyle.Render("Network Service Monitor (Q to quit)") + "\n\n")

	s.WriteString(fmt.Sprintf("%-10s %-20s %-10s %-15s\n", "PID", "PROCESS", "PORT", "STATUS"))
	s.WriteString(strings.Repeat("-", 60) + "\n")

	for i, c := range m.connections {
		cursor := " " 
		if m.cursor == i {
			cursor = ">"
		}
		row := fmt.Sprintf("%s %-9d %-19s %-9d %-14s\n", cursor, c.PID, c.Name, c.Port, c.Status)
		s.WriteString(row)
	}

	return s.String()
}

func getConnections() []connection {
	var results []connection
	conns, _ := net.Connections("all")

	for _, conn := range conns {
		if conn.Status == "LISTEN" || conn.Status == "ESTABLISHED" {
			name := "Unknown"
			p, err := process.NewProcess(conn.Pid)
			if err == nil {
				name, _ = p.Name()
			}

			results = append(results, connection{
				PID:    conn.Pid,
				Name:   name,
				Port:   conn.Laddr.Port,
				Status: conn.Status,
			})
		}
	}
	
	// Sort by port for a cleaner TUI
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	
	return results
}

func main() {
	m := model{connections: getConnections()}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
