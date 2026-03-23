package checks

// auditd.go — Linux Audit Daemon check
//
// WHY THIS MATTERS
// The Linux Audit framework (auditd) is the kernel-level system call auditing
// subsystem. When active, it can log:
//   - Every file access (reads, writes, attribute changes)
//   - Every executed command
//   - Every privilege escalation attempt (sudo, su, setuid calls)
//   - Every login, logout, and authentication event
//   - Network connections, socket creation, and more
//
// Without auditd running, all of the above happens silently. If an attacker
// compromises the system, you have no audit trail to determine:
//   - What they accessed or exfiltrated
//   - Which commands they ran
//   - How they escalated privileges
//   - When and from where they connected
//
// Audit logs are critical for incident response and forensics. Many compliance
// frameworks (PCI-DSS, HIPAA, SOC 2, CIS Benchmarks) mandate audit logging.
//
// HOW IT WORKS
// First tries systemctl to query the auditd service state. Falls back to
// pgrep to look for the daemon process on systems without systemd.
//
// COMMON AUDIT RULES TO ENABLE
// After installing auditd, add rules to /etc/audit/rules.d/:
//   -w /etc/passwd -p wa -k identity
//   -w /etc/shadow -p wa -k identity
//   -w /etc/sudoers -p wa -k privilege_escalation
//   -a always,exit -F arch=b64 -S execve -k exec

import (
	"os/exec"
	"strings"
)

// AuditdCheck verifies that the Linux audit daemon (auditd) is installed
// and actively running.
type AuditdCheck struct{}

func (c *AuditdCheck) ID() string { return "auditd" }

func (c *AuditdCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Auditd",
		Description: "Linux audit daemon status",
	}

	// Primary method: use systemctl to query the service state.
	// systemctl is-active returns "active", "inactive", "failed", etc.
	if out, err := exec.Command("systemctl", "is-active", "auditd").Output(); err == nil {
		state := strings.TrimSpace(string(out))
		if state == "active" {
			base.Status = StatusPass
			base.Message = "auditd is active"
			base.Details = []string{
				"  WHY IT MATTERS",
				"  auditd logs privileged actions, file accesses, executed commands,",
				"  and authentication events at the kernel level. This data is essential",
				"  for detecting intrusions and performing forensic investigation.",
				"",
				"  RESULT",
				"  The audit daemon is running and recording system events.",
				"  Audit log:   /var/log/audit/audit.log",
				"  Config:      /etc/audit/auditd.conf",
				"  Rules:       /etc/audit/rules.d/",
				"",
				"  USEFUL COMMANDS",
				"  View recent events:   ausearch -ts recent",
				"  Search by user:       ausearch -ua <uid>",
				"  Search by file:       ausearch -f /etc/passwd",
				"  Generate report:      aureport --summary",
			}
			return base
		}
		// Installed but not running.
		base.Status = StatusWarn
		base.Message = "auditd is not running (state: " + state + ")"
		base.Details = []string{
			"  WHY IT MATTERS",
			"  auditd is installed but not currently running.",
			"  No system call auditing is active — activity is not being logged.",
			"",
			"  RESULT",
			"  systemctl reports auditd state: " + state,
			"",
			"  REMEDIATION",
			"  Start and enable auditd:  systemctl enable --now auditd",
		}
		base.JSONDetails = "auditd state: " + state + "\nFix: systemctl enable --now auditd"
		return base
	}

	// Fallback: no systemctl (non-systemd init) — look for the process.
	if out, err := exec.Command("pgrep", "-x", "auditd").Output(); err == nil && len(out) > 0 {
		base.Status = StatusPass
		base.Message = "auditd process found (pid " + strings.TrimSpace(string(out)) + ")"
		base.Details = []string{
			"  auditd is running (detected via pgrep — no systemctl available).",
			"  Audit log: /var/log/audit/audit.log",
		}
		return base
	}

	// auditd is neither running nor installed.
	base.Status = StatusWarn
	base.Message = "auditd not found"
	base.Details = []string{
		"  WHY IT MATTERS",
		"  Without auditd, there is no kernel-level audit trail.",
		"  If an attacker compromises the system, you will have no record of",
		"  what files were accessed, which commands were run, or how they",
		"  escalated privileges.",
		"",
		"  RESULT",
		"  auditd was not found via systemctl or pgrep.",
		"",
		"  REMEDIATION",
		"  Debian/Ubuntu:  apt install auditd && systemctl enable --now auditd",
		"  RHEL/Fedora:    dnf install audit  && systemctl enable --now auditd",
		"",
		"  Recommended starter rules file: /etc/audit/rules.d/hardening.rules",
		"    -w /etc/passwd   -p wa -k identity",
		"    -w /etc/shadow   -p wa -k identity",
		"    -w /etc/sudoers  -p wa -k privilege_escalation",
	}
	base.JSONDetails = "auditd not installed or not running\nFix (Debian/Ubuntu): apt install auditd && systemctl enable --now auditd\nFix (RHEL/Fedora): dnf install audit && systemctl enable --now auditd"
	return base
}
