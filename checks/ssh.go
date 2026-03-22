package checks

// ssh.go — SSH Daemon Configuration check
//
// WHY THIS MATTERS
// SSH is the primary remote administration protocol on Linux servers and is
// therefore a constant target for brute-force and credential-stuffing attacks.
// Misconfigurations in sshd_config can allow direct root access, password
// guessing, or lateral movement via X11.
//
// HOW IT WORKS
// Reads /etc/ssh/sshd_config directly and scans for specific directive=value
// pairs that are known to be insecure. Commented-out lines are ignored. The
// check is case-insensitive to match sshd's own parsing behaviour.
//
// DIRECTIVES CHECKED
//   PermitRootLogin yes      → FAIL  (attacker can log in directly as root)
//   PasswordAuthentication yes → WARN (passwords are guessable; prefer keys)
//   X11Forwarding yes          → WARN (opens a tunnel to the X display server)
//   Protocol 1                 → FAIL (SSHv1 is cryptographically broken)

import (
	"fmt"
	"os"
	"strings"
)

// SSHCheck inspects /etc/ssh/sshd_config for known insecure directive values.
type SSHCheck struct{}

func (c *SSHCheck) ID() string { return "ssh" }

// sshDirective describes one directive/value pair to look for and how to
// classify it when found.
type sshDirective struct {
	pattern     string // directive keyword (matched case-insensitively)
	badValue    string // value that triggers the finding
	description string // one-line human explanation of the risk
	fix         string // concrete remediation command/instruction
	severity    string // StatusFail or StatusWarn
}

// sshDirectives lists every insecure sshd configuration pattern we check.
// Add new entries here to extend the check without changing Run().
var sshDirectives = []sshDirective{
	{
		pattern:     "PermitRootLogin",
		badValue:    "yes",
		description: "Direct root login over SSH is enabled",
		fix:         "Set 'PermitRootLogin no' and restart sshd",
		severity:    StatusFail,
	},
	{
		pattern:     "PasswordAuthentication",
		badValue:    "yes",
		description: "Password-based auth is allowed — prefer key-only",
		fix:         "Set 'PasswordAuthentication no' and restart sshd",
		severity:    StatusWarn,
	},
	{
		pattern:     "X11Forwarding",
		badValue:    "yes",
		description: "X11 forwarding enabled — unnecessary attack surface",
		fix:         "Set 'X11Forwarding no' and restart sshd",
		severity:    StatusWarn,
	},
	{
		pattern:     "Protocol",
		badValue:    "1",
		description: "SSHv1 protocol enabled — obsolete and cryptographically broken",
		fix:         "Remove 'Protocol 1' or set 'Protocol 2'",
		severity:    StatusFail,
	},
}

func (c *SSHCheck) Run() Task {
	const configPath = "/etc/ssh/sshd_config"

	data, err := os.ReadFile(configPath)
	if err != nil {
		return Task{
			ID:          c.ID(),
			Name:        "SSH Config",
			Description: "Verify SSH daemon hardening",
			Status:      StatusSkipped,
			Message:     fmt.Sprintf("Cannot read %s: %v", configPath, err),
			Details: []string{
				"  The SSH config file could not be read.",
				"  This check requires either root access or the file to be world-readable.",
				"  If sshd is not installed, this check is not applicable.",
			},
		}
	}

	lines := strings.Split(string(data), "\n")

	// worstStatus tracks the most severe finding so far: PASS < WARN < FAIL.
	worstStatus := StatusPass
	var issues []string
	var details []string

	// For each known-bad directive, scan every non-comment config line.
	for _, d := range sshDirectives {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Skip comments and empty lines — sshd ignores them too.
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) < 2 {
				continue
			}
			// Match "DirectiveName Value" case-insensitively.
			if strings.EqualFold(parts[0], d.pattern) && strings.EqualFold(parts[1], d.badValue) {
				issues = append(issues, fmt.Sprintf("  [%s] %s", d.severity, d.description))
				details = append(details,
					fmt.Sprintf("  [%s] %s", d.severity, d.description),
					fmt.Sprintf("    Found: %s", trimmed),
					fmt.Sprintf("    Fix:   %s", d.fix),
					"",
				)
				// Escalate the overall status only upward (PASS→WARN→FAIL).
				if worstStatus == StatusPass || (worstStatus == StatusWarn && d.severity == StatusFail) {
					worstStatus = d.severity
				}
			}
		}
	}

	if len(issues) == 0 {
		return Task{
			ID:          c.ID(),
			Name:        "SSH Config",
			Description: "Verify SSH daemon hardening",
			Status:      StatusPass,
			Message:     "No insecure SSH directives found",
			Details: []string{
				"  WHY IT MATTERS",
				"  SSH is the most common remote access vector targeted by attackers.",
				"  Misconfigurations can allow root login, brute-force password attacks,",
				"  or X11 tunnelling to bypass network controls.",
				"",
				"  CHECKED DIRECTIVES",
				"  PermitRootLogin     — should be 'no'",
				"  PasswordAuthentication — should be 'no' (use key-based auth)",
				"  X11Forwarding       — should be 'no'",
				"  Protocol            — should not include '1'",
				"",
				"  All directives look secure in " + configPath,
			},
		}
	}

	// Prepend a context header before the per-finding detail lines.
	header := []string{
		"  WHY IT MATTERS",
		"  The following insecure directives were found in " + configPath + ".",
		"  Each one increases the risk of unauthorized access to the system.",
		"",
		"  FINDINGS",
		"",
	}
	details = append(header, details...)

	return Task{
		ID:          c.ID(),
		Name:        "SSH Config",
		Description: "Verify SSH daemon hardening",
		Status:      worstStatus,
		Message:     fmt.Sprintf("%d insecure directive(s) found", len(issues)),
		Details:     details,
	}
}
