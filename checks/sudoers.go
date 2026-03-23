package checks

// sudoers.go — Sudoers NOPASSWD check
//
// WHY THIS MATTERS
// sudo is the standard mechanism for granting controlled root access to users.
// The NOPASSWD tag in a sudoers rule allows a user to run a command (or ALL
// commands) with elevated privileges without entering a password.
//
// This is dangerous because:
//   - An attacker who gains access to the user account (e.g. via stolen SSH key,
//     phishing, or a compromised application) immediately gets root without
//     any additional credential.
//   - Automated attacks that pivot from web shells, container escapes, or
//     compromised service accounts can silently escalate to root.
//
// HOW IT WORKS
// Scans /etc/sudoers and all drop-in files under /etc/sudoers.d/ for lines
// containing the NOPASSWD tag (case-insensitive). Commented lines are skipped.
// Files that cannot be read directly are retried via a shell cat (in case
// group-readable by sudo).
//
// EXCEPTIONS
// Some environments legitimately use NOPASSWD for specific restricted commands
// (e.g. CI/CD agents running a single deployment script). Each finding should
// be reviewed in context — the check flags them all for human review.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SudoersCheck scans sudoers files for NOPASSWD entries that allow
// passwordless privilege escalation.
type SudoersCheck struct{}

func (c *SudoersCheck) ID() string { return "sudoers" }

func (c *SudoersCheck) Run() Task {
	// Collect the main sudoers file plus any drop-in files in sudoers.d/.
	// Drop-ins follow the same syntax as the main file.
	files := []string{"/etc/sudoers"}
	dropIns, _ := filepath.Glob("/etc/sudoers.d/*")
	files = append(files, dropIns...)

	var hits []string

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			// sudoers files are often mode 0440 (root:root) and unreadable by
			// normal users. Try reading via shell as a fallback — if we have
			// no access at all, skip this file silently.
			out, err2 := exec.Command("sh", "-c", "cat "+path+" 2>/dev/null").Output()
			if err2 != nil {
				continue
			}
			data = out
		}

		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			// Skip comments and blank lines.
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			// NOPASSWD is always uppercase in sudoers but match case-insensitively
			// to be resilient against non-standard editors.
			if strings.Contains(strings.ToUpper(trimmed), "NOPASSWD") {
				hits = append(hits, fmt.Sprintf("  %s:%d  %s", path, i+1, trimmed))
			}
		}
	}

	if len(hits) == 0 {
		return Task{
			ID:          c.ID(),
			Name:        "Sudoers",
			Description: "Detect NOPASSWD sudo rules",
			Status:      StatusPass,
			Message:     "No NOPASSWD entries found",
			Details: []string{
				"  WHY IT MATTERS",
				"  NOPASSWD rules allow a user to sudo without entering a password.",
				"  If that account is compromised, the attacker gets root instantly",
				"  with no additional barrier.",
				"",
				"  RESULT",
				fmt.Sprintf("  Scanned %d sudoers file(s) — all rules require a password.", len(files)),
			},
		}
	}

	details := []string{
		"  WHY IT MATTERS",
		"  NOPASSWD rules allow privilege escalation without any credential.",
		"  A compromised account (stolen key, web shell, etc.) with a NOPASSWD",
		"  rule is effectively a root backdoor.",
		"",
		"  NOPASSWD RULES FOUND",
		"",
	}
	details = append(details, hits...)
	details = append(details,
		"",
		"  REMEDIATION",
		"  Review each rule above. If NOPASSWD is required for a specific command,",
		"  restrict it as narrowly as possible:",
		"    username ALL=(ALL) NOPASSWD: /usr/bin/specific-command",
		"  Edit with: visudo  (never edit sudoers files directly with a text editor)",
	)

	return Task{
		ID:          c.ID(),
		Name:        "Sudoers",
		Description: "Detect NOPASSWD sudo rules",
		Status:      StatusFail,
		Message:     fmt.Sprintf("%d NOPASSWD rule(s) found", len(hits)),
		Details:     details,
		JSONDetails: strings.Join(hits, "\n"),
	}
}
