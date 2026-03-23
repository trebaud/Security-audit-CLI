package checks

// suid.go — SUID/SGID Binary check
//
// WHY THIS MATTERS
// SUID (Set User ID) and SGID (Set Group ID) are special Unix permission bits.
// When set on an executable, the binary runs with the privileges of its *owner*
// (SUID) or *group* (SGID) rather than the user who launched it.
//
// A small number of system utilities legitimately need SUID root (e.g. sudo,
// passwd, su, ping) because they perform privileged operations on behalf of
// unprivileged users.
//
// The risk:
//   - Any vulnerability in a SUID-root binary (buffer overflow, command
//     injection, path traversal) is an instant local privilege escalation to root.
//   - Attackers who gain limited shell access routinely enumerate SUID binaries
//     looking for old versions with known CVEs (e.g. pkexec CVE-2021-4034).
//   - Custom or third-party SUID binaries that are not well-audited are
//     particularly dangerous.
//
// HOW IT WORKS
// Runs `find` over common binary directories for files with SUID or SGID bits
// set (-perm /6000). Avoids /proc, /sys, and network filesystems. Each result
// is compared against a known-safe allowlist of standard Linux system binaries.
// Anything not in the allowlist is flagged for manual review.
//
// NOTE ON THE ALLOWLIST
// The allowlist reflects common Debian/Ubuntu/RHEL installs. Legitimate
// binaries vary by distribution and package set. Review each "[!]" entry
// and add to the allowlist if confirmed safe for your environment.

import (
	"fmt"
	"os/exec"
	"strings"
)

// SUIDCheck finds SUID/SGID binaries and flags any that are not in the
// known-safe allowlist of standard system utilities.
type SUIDCheck struct{}

func (c *SUIDCheck) ID() string { return "suid" }

// knownSafe is the set of SUID/SGID binaries that are expected and legitimate
// on standard Linux installations. Paths are absolute and match as-is.
// This list is deliberately conservative — when in doubt, flag it.
var knownSafe = map[string]bool{
	// Core authentication and privilege escalation tools
	"/usr/bin/sudo":    true, // the primary privilege escalation tool
	"/usr/bin/su":      true, // switch user — needs to read /etc/shadow
	"/usr/bin/passwd":  true, // change own password — needs to write /etc/shadow
	"/usr/bin/newgrp":  true, // change active group — needs /etc/shadow access
	"/usr/bin/gpasswd": true, // administer /etc/group
	"/usr/bin/chsh":    true, // change login shell — writes /etc/passwd
	"/usr/bin/chfn":    true, // change GECOS field — writes /etc/passwd
	"/usr/bin/expiry":  true, // check/enforce password expiry
	"/usr/bin/chage":   true, // change password aging info

	// Filesystem mounting — needs kernel mount capabilities
	"/usr/bin/mount":       true,
	"/usr/bin/umount":      true,
	"/usr/bin/fusermount":  true, // FUSE mounts for non-root users
	"/usr/bin/fusermount3": true,
	"/bin/mount":           true,
	"/bin/umount":          true,
	"/sbin/mount.nfs":      true,

	// Scheduling tools — need to write system spool dirs
	"/usr/bin/at":      true, // one-time job scheduling
	"/usr/bin/crontab": true, // per-user cron job management

	// Network tools — need raw socket access (some distros still use SUID)
	"/bin/ping": true,

	// Messaging
	"/usr/bin/wall":  true, // broadcast message to all terminals
	"/usr/bin/write": true, // write to another user's terminal

	// PolicyKit — privilege management framework
	"/usr/bin/pkexec": true, // polkit privilege escalation
	"/usr/lib/policykit-1/polkit-agent-helper-1": true,
	"/usr/libexec/polkit-agent-helper-1":         true,

	// SSH
	"/usr/bin/ssh-agent":           true,
	"/usr/lib/openssh/ssh-keysign": true, // host-based SSH auth

	// D-Bus — inter-process communication
	"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true,

	// PAM authentication helpers
	"/usr/sbin/pam_extrausers_chkpwd": true,
	"/usr/sbin/unix_chkpwd":           true, // PAM helper to check passwords
}

func (c *SUIDCheck) Run() Task {
	// Limit the scan to well-known binary directories. This intentionally
	// excludes /proc (pseudo-filesystem), /sys (kernel objects), /home (user
	// files should never be SUID), and network mounts (avoid hangs).
	dirs := "/usr/bin /usr/sbin /usr/lib /usr/libexec /bin /sbin /opt"
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("find %s -perm /6000 -type f 2>/dev/null", dirs))
	out, _ := cmd.Output()

	all := strings.TrimSpace(string(out))
	if all == "" {
		return Task{
			ID:          c.ID(),
			Name:        "SUID/SGID",
			Description: "SUID/SGID binaries outside expected paths",
			Status:      StatusPass,
			Message:     "No SUID/SGID binaries found in scanned paths",
			Details: []string{
				"  WHY IT MATTERS",
				"  SUID/SGID binaries run with elevated privileges (owner's UID/GID).",
				"  Any vulnerability in such a binary is an instant privilege escalation.",
				"",
				"  RESULT",
				"  No SUID/SGID binaries found in: " + dirs,
			},
		}
	}

	// Categorize each found binary as known-safe or unexpected.
	var unexpected []string
	var known []string
	for _, path := range strings.Split(all, "\n") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if knownSafe[path] {
			known = append(known, "  [known] "+path)
		} else {
			unexpected = append(unexpected, "  [!]     "+path)
		}
	}

	// Build the details section, always showing context first.
	details := []string{
		"  WHY IT MATTERS",
		"  SUID/SGID binaries run as their owner (often root) regardless of who",
		"  launches them. A vulnerability in any such binary (buffer overflow,",
		"  command injection, etc.) is a direct local privilege escalation to root.",
		"  Attackers routinely search for SUID binaries when they gain shell access.",
		"",
	}

	if len(unexpected) > 0 {
		details = append(details,
			"  UNEXPECTED SUID/SGID BINARIES (verify each manually)",
			"  These are NOT in the known-safe list — investigate before trusting them:",
			"",
		)
		details = append(details, unexpected...)
		details = append(details,
			"",
			"  HOW TO INVESTIGATE",
			"  Check the package owning a binary:  dpkg -S <path>  or  rpm -qf <path>",
			"  Check when it was modified:         ls -la <path>",
			"  Remove SUID if unneeded:            chmod u-s <path>",
			"",
		)
	}

	if len(known) > 0 {
		details = append(details, "  KNOWN-SAFE SUID/SGID BINARIES (standard system utilities)")
		details = append(details, known...)
	}

	if len(unexpected) > 0 {
		// Strip the "[!]     " prefix for clean JSON output.
		jsonLines := make([]string, len(unexpected))
		for i, u := range unexpected {
			jsonLines[i] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(u), "[!]"))
		}
		return Task{
			ID:          c.ID(),
			Name:        "SUID/SGID",
			Description: "SUID/SGID binaries outside expected paths",
			Status:      StatusWarn,
			Message:     fmt.Sprintf("%d unexpected SUID/SGID binary(ies)", len(unexpected)),
			Details:     details,
			JSONDetails: strings.Join(jsonLines, "\n"),
		}
	}

	return Task{
		ID:          c.ID(),
		Name:        "SUID/SGID",
		Description: "SUID/SGID binaries outside expected paths",
		Status:      StatusPass,
		Message:     fmt.Sprintf("%d SUID/SGID binaries — all known-safe", len(known)),
		Details:     details,
	}
}
