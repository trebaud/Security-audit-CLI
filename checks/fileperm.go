package checks

// fileperm.go — World-Writable Files in /etc check
//
// WHY THIS MATTERS
// /etc contains the most security-sensitive configuration files on Linux:
// passwd, shadow, sudoers, crontab, sshd_config, fstab, and more.
// If any of these files are world-writable, a local attacker (or a compromised
// service running as a non-root user) can modify them to escalate privileges,
// install backdoors, or corrupt system behaviour.
//
// HOW IT WORKS
// Runs `find /etc -maxdepth 2 -perm -o+w -type f` which lists regular files
// where the "other" write bit (o+w) is set. Depth is capped at 2 to include
// first-level subdirectories (e.g. /etc/ssh/, /etc/sudoers.d/) without
// recursing into package caches or large trees.
//
// REMEDIATION
// For each listed file: chmod o-w <file>
// Then audit whether write access was intentional before removing it.

import (
	"fmt"
	"os/exec"
	"strings"
)

// FilePermCheck uses find(1) to locate world-writable files inside /etc.
type FilePermCheck struct{}

func (c *FilePermCheck) ID() string { return "fileperm" }

func (c *FilePermCheck) Run() Task {
	// -perm -o+w matches files where the "other write" bit is set.
	// 2>/dev/null suppresses "Permission denied" noise on restricted dirs.
	cmd := exec.Command("sh", "-c", "find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null")
	out, err := cmd.Output()

	fileList := strings.TrimSpace(string(out))

	// If find itself failed and produced no output, surface a warning.
	if err != nil && fileList == "" {
		return Task{
			ID:          c.ID(),
			Name:        "File Perms",
			Description: "World-writable files in /etc",
			Status:      StatusWarn,
			Message:     "find command failed: " + err.Error(),
			Details: []string{
				"  Could not complete the scan. Try running as root.",
			},
		}
	}

	// No world-writable files found — this is the desired outcome.
	if fileList == "" {
		return Task{
			ID:          c.ID(),
			Name:        "File Perms",
			Description: "World-writable files in /etc",
			Status:      StatusPass,
			Message:     "No world-writable files found",
			Details: []string{
				"  WHY IT MATTERS",
				"  /etc holds the most critical system configuration files.",
				"  World-writable files can be modified by any local user,",
				"  enabling privilege escalation or backdoor installation.",
				"",
				"  RESULT",
				"  Scanned /etc (depth 2) — no world-writable files found.",
				"  Permissions look secure.",
			},
		}
	}

	// One or more world-writable files were found — build the findings list.
	files := strings.Split(fileList, "\n")
	details := []string{
		"  WHY IT MATTERS",
		"  World-writable files in /etc can be modified by any local user.",
		"  An attacker with any shell access can overwrite these files to",
		"  inject malicious configuration, add cron jobs, or hijack sudo.",
		"",
		"  WORLD-WRITABLE FILES FOUND",
	}
	for _, f := range files {
		details = append(details, "    "+f)
	}
	details = append(details,
		"",
		"  REMEDIATION",
		"  Review each file above, then remove the world-write bit:",
		"    chmod o-w <file>",
		"  Verify the correct owner with: ls -la <file>",
	)

	return Task{
		ID:          c.ID(),
		Name:        "File Perms",
		Description: "World-writable files in /etc",
		Status:      StatusFail,
		Message:     fmt.Sprintf("%d world-writable file(s) in /etc", len(files)),
		Details:     details,
		JSONDetails: strings.Join(files, "\n"),
	}
}
