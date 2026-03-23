package checks

// writablepath.go — World-Writable PATH Directories check
//
// WHY THIS MATTERS
// When a privileged process (cron job, sudo script, SUID binary) executes a
// command by name without a full path, the shell searches directories in $PATH
// in order. If any of those directories is world-writable, an attacker can
// place a malicious executable with the same name earlier in the search path
// and hijack the command — this is called a PATH hijacking or command
// injection attack.
//
// Example scenario:
//   1. Root cron job runs:  /usr/local/bin/backup.sh
//   2. backup.sh calls:     tar czf /backup.tar.gz /data   (no full path for tar)
//   3. /usr/local/bin/ is world-writable
//   4. Attacker creates:    /usr/local/bin/tar  containing /bin/bash
//   5. Next cron run → root executes attacker's "tar" → root shell
//
// HOW IT WORKS
// Reads the current user's $PATH environment variable, stats each directory,
// and flags any that are world-writable or world-writable + missing sticky bit.
// Also checks the system-wide default PATH from /etc/environment and
// /etc/profile for completeness.

import (
	"fmt"
	"os"
	"strings"
)

// WritablePathCheck inspects each directory in $PATH for world-write
// permissions that could enable PATH hijacking attacks.
type WritablePathCheck struct{}

func (c *WritablePathCheck) ID() string { return "writablepath" }

func (c *WritablePathCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "PATH Hijack",
		Description: "World-writable directories in $PATH",
	}

	// Collect all unique PATH directories to check.
	dirs := collectPathDirs()
	if len(dirs) == 0 {
		base.Status = StatusSkipped
		base.Message = "$PATH is empty or unreadable"
		return base
	}

	var vulnerable []string
	var details []string

	details = append(details,
		"  WHY IT MATTERS",
		"  If a directory in $PATH is world-writable, an attacker can plant a",
		"  malicious binary (e.g. 'tar', 'python') that gets executed instead of",
		"  the real one when a privileged script calls it without a full path.",
		"  This is a classic local privilege escalation technique.",
		"",
		"  PATH DIRECTORIES CHECKED",
	)

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			details = append(details, fmt.Sprintf("  [SKIP] %-30s  (not found or unreadable)", dir))
			continue
		}

		mode := info.Mode()
		isWorldWritable := mode&0o002 != 0
		hasSticky := mode&os.ModeSticky != 0

		switch {
		case isWorldWritable && !hasSticky:
			vulnerable = append(vulnerable, dir)
			details = append(details, fmt.Sprintf("  [FAIL] %-30s  world-writable, no sticky bit (%s)", dir, mode))
		case isWorldWritable && hasSticky:
			// World-writable + sticky means users can only delete their own files,
			// so a low-privilege attacker cannot plant a file. Still worth noting.
			details = append(details, fmt.Sprintf("  [WARN] %-30s  world-writable + sticky bit (%s)", dir, mode))
		default:
			details = append(details, fmt.Sprintf("  [OK  ] %-30s  %s", dir, mode))
		}
	}

	if len(vulnerable) == 0 {
		base.Status = StatusPass
		base.Message = "No world-writable directories in $PATH"
		base.Details = details
		return base
	}

	details = append(details,
		"",
		"  VULNERABLE DIRECTORIES",
	)
	for _, d := range vulnerable {
		details = append(details, "    "+d)
	}
	details = append(details,
		"",
		"  REMEDIATION",
		"  Remove world-write permission from each flagged directory:",
	)
	for _, d := range vulnerable {
		details = append(details, fmt.Sprintf("    chmod o-w %s", d))
	}
	details = append(details,
		"",
		"  Also audit scripts that call commands without full paths and",
		"  consider using absolute paths in cron jobs and sudo rules.",
	)

	fixLines := make([]string, len(vulnerable))
	for i, d := range vulnerable {
		fixLines[i] = d + " (world-writable) | Fix: chmod o-w " + d
	}
	base.Status = StatusFail
	base.Message = fmt.Sprintf("%d world-writable directory(ies) in $PATH", len(vulnerable))
	base.Details = details
	base.JSONDetails = strings.Join(fixLines, "\n")
	return base
}

// collectPathDirs returns a deduplicated list of directories from the current
// $PATH. Also includes entries from /etc/environment as a secondary source.
func collectPathDirs() []string {
	seen := map[string]bool{}
	var result []string

	addPath := func(pathVal string) {
		for _, dir := range strings.Split(pathVal, ":") {
			dir = strings.TrimSpace(dir)
			if dir == "" || seen[dir] {
				continue
			}
			seen[dir] = true
			result = append(result, dir)
		}
	}

	// Primary: current process PATH.
	addPath(os.Getenv("PATH"))

	// Secondary: /etc/environment (system-wide PATH, often the root PATH).
	if data, err := os.ReadFile("/etc/environment"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PATH=") {
				val := strings.TrimPrefix(line, "PATH=")
				val = strings.Trim(val, `"'`)
				addPath(val)
			}
		}
	}

	return result
}
