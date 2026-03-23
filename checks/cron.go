package checks

// cron.go — Cron Job Security check
//
// WHY THIS MATTERS
// Cron jobs run on a schedule, often as root, without any interactive oversight.
// If the script or binary a cron job calls is world-writable, any user can
// replace or modify it to execute arbitrary code as root the next time the
// job runs. This is one of the most reliable local privilege escalation paths:
//
//   1. Identify a cron job running as root:
//        * * * * * root /usr/local/bin/cleanup.sh
//   2. Check if the script is writable:
//        ls -la /usr/local/bin/cleanup.sh  → -rwxrwxrwx
//   3. Append a reverse shell or SUID shell:
//        echo 'chmod +s /bin/bash' >> /usr/local/bin/cleanup.sh
//   4. Wait ≤ 1 minute → root shell.
//
// ADDITIONAL RISKS
//   - Cron scripts calling other scripts/binaries without full paths
//     (PATH hijacking — see writablepath.go).
//   - Cron directories (/etc/cron.d/, /etc/cron.daily/, etc.) that are
//     world-writable — an attacker can drop in new job files.
//   - Wildcard injection: scripts that use  tar /path/* or chown user *
//     are vulnerable to argument injection via specially-named files.
//
// HOW IT WORKS
// 1. Reads all system crontab locations: /etc/crontab, /etc/cron.d/*,
//    /etc/cron.{hourly,daily,weekly,monthly}/*.
// 2. Extracts the command field from each job line.
// 3. Resolves the first token (the script/binary path) and checks if it is
//    world-writable.
// 4. Also checks whether the cron directories themselves are world-writable.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CronCheck inspects system cron jobs for scripts and directories that are
// world-writable, enabling cron-based privilege escalation.
type CronCheck struct{}

func (c *CronCheck) ID() string { return "cron" }

// cronSources lists all filesystem locations that define system cron jobs.
var cronSources = []string{
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

func (c *CronCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Cron Jobs",
		Description: "Writable scripts in system cron jobs",
	}

	var issues []string
	var details []string

	details = append(details,
		"  WHY IT MATTERS",
		"  Cron jobs run on a schedule, typically as root. If the script a cron job",
		"  calls is world-writable, any user can modify it and gain code execution",
		"  as root the next time the job fires. This is a reliable privilege",
		"  escalation path that requires no exploit — just write access.",
		"",
	)

	// Collect all crontab files to analyse.
	var cronFiles []string
	for _, src := range cronSources {
		info, err := os.Stat(src)
		if err != nil {
			continue
		}
		if info.IsDir() {
			// Check the directory itself for world-write.
			if info.Mode()&0o002 != 0 {
				issues = append(issues, src+" dir is world-writable")
				details = append(details,
					fmt.Sprintf("  [FAIL] Directory %s is world-writable!", src),
					"         An attacker can drop new cron job files here.",
					fmt.Sprintf("         Fix: chmod o-w %s", src),
					"",
				)
			}
			// Collect files inside.
			entries, err := os.ReadDir(src)
			if err == nil {
				for _, e := range entries {
					if !e.IsDir() {
						cronFiles = append(cronFiles, filepath.Join(src, e.Name()))
					}
				}
			}
		} else {
			cronFiles = append(cronFiles, src)
		}
	}

	if len(cronFiles) == 0 {
		details = append(details, "  No system crontab files found.")
		base.Status = StatusPass
		base.Message = "No system cron jobs found"
		base.Details = details
		return base
	}

	details = append(details, fmt.Sprintf("  CRONTAB FILES SCANNED (%d)", len(cronFiles)))
	for _, f := range cronFiles {
		details = append(details, "    "+f)
	}
	details = append(details, "")

	// Parse each crontab file and check referenced scripts.
	checkedPaths := map[string]bool{} // avoid duplicate checks
	details = append(details, "  SCRIPT/BINARY PERMISSION CHECKS")

	for _, cronFile := range cronFiles {
		data, err := os.ReadFile(cronFile)
		if err != nil {
			details = append(details, fmt.Sprintf("  [SKIP] %s — cannot read: %v", cronFile, err))
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			// Skip comments, blank lines, and variable assignments.
			if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") && !strings.Contains(line, " ") {
				continue
			}

			// Parse the command out of the cron line.
			// /etc/crontab format: min hr dom mon dow user command
			// /etc/cron.d/* format: same
			// /etc/cron.daily/* are scripts themselves (no schedule fields)
			cmdPath := extractCronCommand(line, cronFile)
			if cmdPath == "" || checkedPaths[cmdPath] {
				continue
			}
			checkedPaths[cmdPath] = true

			info, err := os.Stat(cmdPath)
			if err != nil {
				// Path doesn't exist — worth flagging (dangling cron = hijack opportunity).
				details = append(details,
					fmt.Sprintf("  [WARN] %-40s  does not exist (dangling reference in %s)",
						cmdPath, filepath.Base(cronFile)))
				issues = append(issues, cmdPath+" does not exist")
				continue
			}

			mode := info.Mode()
			if mode&0o002 != 0 {
				issues = append(issues, cmdPath+" is world-writable")
				details = append(details,
					fmt.Sprintf("  [FAIL] %-40s  world-writable! (%s) in %s",
						cmdPath, mode, filepath.Base(cronFile)),
					fmt.Sprintf("         Fix: chmod o-w %s", cmdPath),
				)
			} else if mode&0o020 != 0 {
				details = append(details,
					fmt.Sprintf("  [WARN] %-40s  group-writable (%s) — verify group is trusted",
						cmdPath, mode))
			} else {
				details = append(details,
					fmt.Sprintf("  [OK  ] %-40s  %s", cmdPath, mode))
			}
		}
	}

	if len(issues) == 0 {
		base.Status = StatusPass
		base.Message = "All cron job scripts have safe permissions"
	} else {
		base.Status = StatusFail
		base.Message = fmt.Sprintf("%d writable cron script(s)/path(s) found", len(issues))
		details = append(details,
			"",
			"  GENERAL REMEDIATION",
			"  - chmod o-w <script> for each world-writable script above",
			"  - Ensure cron scripts use absolute paths for all commands",
			"  - Avoid wildcards in cron scripts (tar *, chown *) — see wildcard injection",
		)
		base.JSONDetails = strings.Join(issues, "\n")
	}

	base.Details = details
	return base
}

// extractCronCommand returns the absolute path of the first executable token
// in a cron job line, or empty string if the line is not parseable.
func extractCronCommand(line, sourceFile string) string {
	fields := strings.Fields(line)

	// /etc/crontab and /etc/cron.d/* have 7+ fields:
	//   min hr dom mon dow USER command [args...]
	// Scripts in /etc/cron.{daily,weekly,...}/ are themselves the command.
	isScheduledFile := sourceFile == "/etc/crontab" ||
		strings.Contains(sourceFile, "/cron.d/")

	var cmdField string
	if isScheduledFile {
		if len(fields) < 7 {
			return ""
		}
		cmdField = fields[6] // field index 6 = command (after user field)
	} else {
		// Drop-in script directories: the file IS the script (no schedule line).
		// But files inside might have shebang content with commands.
		if len(fields) < 1 {
			return ""
		}
		cmdField = fields[0]
	}

	// Only check absolute paths — relative paths are a problem for writablepath.
	if !strings.HasPrefix(cmdField, "/") {
		return ""
	}
	// Strip arguments — keep only the binary/script path.
	return cmdField
}
