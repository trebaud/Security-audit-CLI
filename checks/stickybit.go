package checks

// stickybit.go — Sticky Bit on World-Writable Directories check
//
// WHY THIS MATTERS
// Directories like /tmp, /var/tmp, and /dev/shm are world-writable — any user
// can create files there. This is intentional and necessary (e.g. temporary
// files, shared memory segments, IPC sockets).
//
// However, if the sticky bit (also called the "restricted deletion flag") is
// NOT set on such a directory, any user can delete or rename files created by
// other users. This enables two classes of attack:
//
//   1. Privilege Escalation via symlink/race condition:
//      An attacker can delete a file that a privileged process is about to
//      create (e.g. a temp file from a cron job running as root), and replace
//      it with a symlink pointing to /etc/passwd or another sensitive file.
//      The privileged process then writes to the symlink target — overwriting
//      the sensitive file.
//
//   2. Denial of Service:
//      An attacker can delete files created by other users or services,
//      causing application crashes, data loss, or service disruption.
//
// The sticky bit prevents these attacks by restricting deletion: only the file
// owner, the directory owner, or root can delete a file inside a sticky directory.
//
// HOW IT WORKS
// Uses os.Stat() to inspect the mode bits of /tmp, /var/tmp, and /dev/shm.
// Checks both that the directory is world-writable (o+w) AND that the sticky
// bit (os.ModeSticky) is set.

import (
	"fmt"
	"os"
	"strings"
)

// StickyBitCheck verifies that world-writable temporary directories have the
// sticky bit set to prevent file deletion by arbitrary users.
type StickyBitCheck struct{}

func (c *StickyBitCheck) ID() string { return "stickybit" }

// tempDirs is the list of world-writable directories that must have the
// sticky bit. These are the standard temporary storage locations on Linux.
var tempDirs = []string{
	"/tmp",     // primary temporary file location
	"/var/tmp", // persistent temporary files (survives reboots)
	"/dev/shm", // POSIX shared memory (RAM-backed tmpfs)
}

func (c *StickyBitCheck) Run() Task {
	var fails []string
	var perDirResults []string

	for _, dir := range tempDirs {
		info, err := os.Stat(dir)
		if err != nil {
			// Directory doesn't exist on this system — not applicable.
			perDirResults = append(perDirResults, fmt.Sprintf("  [SKIP] %-12s  not found on this system", dir))
			continue
		}

		mode := info.Mode()
		isWorldWritable := mode&0o002 != 0   // "other write" bit
		hasSticky := mode&os.ModeSticky != 0 // sticky/restricted-deletion bit

		switch {
		case !isWorldWritable:
			// Not world-writable → sticky bit is irrelevant → OK.
			perDirResults = append(perDirResults, fmt.Sprintf("  [OK  ] %-12s  not world-writable (%s)", dir, mode))
		case hasSticky:
			// World-writable AND sticky → properly protected.
			perDirResults = append(perDirResults, fmt.Sprintf("  [OK  ] %-12s  world-writable + sticky bit set (%s)", dir, mode))
		default:
			// World-writable WITHOUT sticky → vulnerable.
			fails = append(fails, dir)
			perDirResults = append(perDirResults, fmt.Sprintf("  [FAIL] %-12s  world-writable WITHOUT sticky bit (%s)", dir, mode))
		}
	}

	// Build details with a security context header.
	details := []string{
		"  WHY IT MATTERS",
		"  World-writable directories without the sticky bit allow any user to",
		"  delete files created by others. Attackers exploit this for symlink",
		"  attacks: delete a privileged process's temp file, replace with a",
		"  symlink to /etc/passwd or similar — the process then writes to it.",
		"  The sticky bit restricts deletion to the file owner only.",
		"",
		"  DIRECTORY STATUS",
	}
	details = append(details, perDirResults...)

	if len(fails) == 0 {
		return Task{
			ID:          c.ID(),
			Name:        "Sticky Bit",
			Description: "Sticky bit on world-writable dirs",
			Status:      StatusPass,
			Message:     "All temp directories are properly configured",
			Details:     details,
		}
	}

	// Add remediation commands for each failing directory.
	details = append(details, "")
	details = append(details, "  REMEDIATION")
	for _, dir := range fails {
		details = append(details, fmt.Sprintf("  chmod +t %s", dir))
	}
	details = append(details,
		"",
		"  Verify with: ls -ld /tmp  (look for 't' at the end, e.g. drwxrwxrwt)",
	)

	fixLines := make([]string, len(fails))
	for i, d := range fails {
		fixLines[i] = d + " (missing sticky bit) | Fix: chmod +t " + d
	}
	return Task{
		ID:          c.ID(),
		Name:        "Sticky Bit",
		Description: "Sticky bit on world-writable dirs",
		Status:      StatusFail,
		Message:     fmt.Sprintf("%d dir(s) missing sticky bit: %v", len(fails), fails),
		Details:     details,
		JSONDetails: strings.Join(fixLines, "\n"),
	}
}
