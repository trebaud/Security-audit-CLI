package checks

// ports.go — Open Ports check
//
// WHY THIS MATTERS
// Every open (listening) port is a potential entry point for an attacker.
// Services that are not strictly necessary should be stopped and disabled.
// A high port count often indicates software installed without review, or
// development tools left running in production.
//
// HOW IT WORKS
// Uses gopsutil to enumerate all kernel-level socket connections in LISTEN
// state without requiring root privileges. This includes both TCP and UDP
// sockets on all interfaces.
//
// THRESHOLDS (opinionated defaults, adjust to your environment)
//   - ≤10 ports  → PASS  (typical hardened server)
//   - 11–20 ports → WARN  (investigate — more services than expected)
//   - >20 ports  → FAIL  (significant attack surface)

import (
	"fmt"
	"strings"

	psnet "github.com/shirou/gopsutil/v3/net"
)

// PortsCheck enumerates TCP/UDP services in LISTEN state via the kernel's
// netstat-equivalent interface (no shell command needed).
type PortsCheck struct{}

func (c *PortsCheck) ID() string { return "ports" }

func (c *PortsCheck) Run() Task {
	conns, err := psnet.Connections("all")
	if err != nil {
		return Task{
			ID:          c.ID(),
			Name:        "Open Ports",
			Description: "Check for excessive listening services",
			Status:      StatusWarn,
			Message:     "Could not enumerate connections: " + err.Error(),
		}
	}

	// Collect only sockets in LISTEN state (i.e. servers waiting for connections).
	// portLines holds the raw data lines reused for JSONDetails.
	var portLines []string
	var details []string
	listenCount := 0
	for _, conn := range conns {
		if conn.Status != "LISTEN" {
			continue
		}
		listenCount++

		// gopsutil encodes protocol as an integer: 1=TCP, 2=UDP.
		proto := "tcp"
		if conn.Type == 2 {
			proto = "udp"
		}
		line := fmt.Sprintf("%-6s  local=%-22s  pid=%d",
			proto,
			fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			conn.Pid,
		)
		portLines = append(portLines, line)
		details = append(details, "  "+line)
	}

	status := StatusPass
	message := fmt.Sprintf("%d listening ports — looks normal", listenCount)
	if listenCount > 20 {
		status = StatusFail
		message = fmt.Sprintf("%d listening ports — investigate", listenCount)
	} else if listenCount > 10 {
		status = StatusWarn
		message = fmt.Sprintf("%d listening ports — higher than usual", listenCount)
	}

	if len(details) == 0 {
		details = []string{"  No listening ports found"}
	}

	// Prepend a security-context header so the reader understands what they
	// are looking at when they expand this row in the TUI.
	header := []string{
		"  WHY IT MATTERS",
		"  Each listening port is an exposed service. Attackers scan for open",
		"  ports to find vulnerable software. Minimize your attack surface by",
		"  stopping any service you do not actively need.",
		"",
		"  HOW TO INVESTIGATE",
		"  Use 'ss -tlnp' or 'lsof -i -P -n' to see which process owns a port.",
		"  Stop unnecessary services with: systemctl stop <service>",
		"                               and: systemctl disable <service>",
		"",
		"  LISTENING SOCKETS FOUND",
	}
	details = append(header, details...)

	return Task{
		ID:          c.ID(),
		Name:        "Open Ports",
		Description: "Check for excessive listening services",
		Status:      status,
		Message:     message,
		Details:     details,
		JSONDetails: strings.Join(portLines, "\n"),
	}
}
