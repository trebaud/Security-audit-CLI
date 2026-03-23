package checks

// secupdates.go — Pending Security Updates check
//
// WHY THIS MATTERS
// Unpatched software is the single most common root cause of system compromise.
// Security updates fix known, publicly-disclosed vulnerabilities (CVEs). Once a
// CVE is public, exploit code typically appears within hours to days. Every day
// a security patch goes unapplied is a window of exposure.
//
// This check queries the system's native package manager for pending security
// updates without actually installing anything (dry-run / simulation only).
//
// HOW IT WORKS — detection strategy per distro family:
//
//   Debian / Ubuntu
//     Primary:  /usr/lib/update-notifier/apt-check
//       Outputs "N_regular;N_security" to stderr. Zero-cost (uses cached data,
//       no network call). Falls back to apt-get -s dist-upgrade and filters
//       lines that mention a *-security pocket.
//
//   RHEL / Fedora / CentOS
//     dnf check-update --security (exit 100 = updates available, 0 = none)
//     Falls back to yum --security check-update.
//
//   openSUSE / SLES
//     zypper list-patches --category security
//
// IMPORTANT: none of these commands install anything. All are read-only queries
// against the locally cached package metadata. Run `apt update` / `dnf check-update`
// beforehand if you want fresh data — otherwise the check reflects the last
// `apt update` run.

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// SecurityUpdatesCheck queries the system package manager for pending security
// patches without installing anything.
type SecurityUpdatesCheck struct{}

func (c *SecurityUpdatesCheck) ID() string { return "secupdates" }

func (c *SecurityUpdatesCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Sec Updates",
		Description: "Pending security updates in package manager",
	}

	// ---- Debian / Ubuntu ----
	// /usr/lib/update-notifier/apt-check outputs "regular;security" to stderr.
	if out, err := exec.Command("/usr/lib/update-notifier/apt-check").CombinedOutput(); err == nil {
		return parseAptCheck(base, strings.TrimSpace(string(out)))
	}

	// Fallback for Debian/Ubuntu without update-notifier: use apt-get -s.
	if _, err := exec.LookPath("apt-get"); err == nil {
		return aptGetSimulate(base)
	}

	// ---- RHEL / Fedora / CentOS ----
	// dnf check-update --security exits 100 when security updates are pending,
	// 0 when none, other codes on error.
	if path, err := exec.LookPath("dnf"); err == nil {
		return dnfCheck(base, path)
	}
	if path, err := exec.LookPath("yum"); err == nil {
		return yumCheck(base, path)
	}

	// ---- openSUSE / SLES ----
	if path, err := exec.LookPath("zypper"); err == nil {
		return zypperCheck(base, path)
	}

	// No known package manager found.
	base.Status = StatusSkipped
	base.Message = "No supported package manager found"
	base.Details = []string{
		"  Probed: apt-get, dnf, yum, zypper — none found.",
		"  Manually check your distro's package manager for security updates.",
	}
	return base
}

// parseAptCheck parses the "N;M" output of /usr/lib/update-notifier/apt-check.
// N = total pending upgrades, M = security-only upgrades.
func parseAptCheck(base Task, raw string) Task {
	parts := strings.SplitN(raw, ";", 2)
	if len(parts) != 2 {
		base.Status = StatusWarn
		base.Message = "apt-check output unrecognised: " + raw
		return base
	}
	total, _ := strconv.Atoi(parts[0])
	security, _ := strconv.Atoi(parts[1])

	return buildAptResult(base, total, security, []string{
		fmt.Sprintf("  Source: /usr/lib/update-notifier/apt-check"),
		fmt.Sprintf("  Total pending upgrades:   %d", total),
		fmt.Sprintf("  Security-only upgrades:   %d", security),
	})
}

// aptGetSimulate uses `apt-get -s dist-upgrade` and counts lines that mention
// a *-security pocket in the package source annotation.
func aptGetSimulate(base Task) Task {
	out, err := exec.Command("apt-get", "-s", "dist-upgrade").Output()
	if err != nil {
		base.Status = StatusWarn
		base.Message = "apt-get simulation failed: " + err.Error()
		return base
	}

	var secPkgs []string
	total := 0
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		total++
		if strings.Contains(line, "-security") || strings.Contains(line, "Security") {
			// Extract just the package name (second field).
			fields := strings.Fields(line)
			if len(fields) > 1 {
				secPkgs = append(secPkgs, "    "+fields[1])
			}
		}
	}

	details := []string{
		"  Source: apt-get -s dist-upgrade",
		fmt.Sprintf("  Total pending upgrades:   %d", total),
		fmt.Sprintf("  From security pockets:    %d", len(secPkgs)),
	}
	if len(secPkgs) > 0 {
		details = append(details, "")
		details = append(details, "  Security packages:")
		details = append(details, secPkgs...)
	}

	return buildAptResult(base, total, len(secPkgs), details)
}

// buildAptResult assembles the final Task for apt-based systems.
func buildAptResult(base Task, total, security int, details []string) Task {
	header := []string{
		"  WHY IT MATTERS",
		"  Unpatched software is the leading cause of system compromise.",
		"  Security patches fix publicly-known CVEs — once a CVE is published,",
		"  working exploits typically appear within hours to days.",
		"  Apply security updates as soon as possible, ideally via automation.",
		"",
		"  RESULT",
	}
	footer := []string{
		"",
		"  REMEDIATION",
		"  Apply all pending updates:     sudo apt-get upgrade",
		"  Apply security updates only:   sudo apt-get upgrade --with-new-pkgs",
		"  Enable automatic updates:      sudo dpkg-reconfigure unattended-upgrades",
	}

	base.Details = append(append(header, details...), footer...)

	switch {
	case security > 0:
		base.Status = StatusFail
		base.Message = fmt.Sprintf("%d security update(s) pending — apply now", security)
		base.JSONDetails = fmt.Sprintf("%d security updates pending\nFix: sudo apt-get upgrade", security)
	case total > 0:
		base.Status = StatusWarn
		base.Message = fmt.Sprintf("%d pending update(s), none flagged as security", total)
		base.JSONDetails = fmt.Sprintf("%d pending updates (none flagged as security)\nFix: sudo apt-get upgrade", total)
	default:
		base.Status = StatusPass
		base.Message = "System is up to date"
	}
	return base
}

// dnfCheck runs `dnf check-update --security`.
// Exit code 100 = security updates available; 0 = none; other = error.
func dnfCheck(base Task, dnfPath string) Task {
	cmd := exec.Command(dnfPath, "check-update", "--security", "-q")
	out, err := cmd.Output()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			base.Status = StatusWarn
			base.Message = "dnf check-update failed: " + err.Error()
			return base
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var pkgs []string
	for _, l := range lines {
		if l != "" {
			pkgs = append(pkgs, "    "+l)
		}
	}

	header := []string{
		"  WHY IT MATTERS",
		"  Unpatched software is the leading cause of system compromise.",
		"  Apply security patches promptly to close known CVE windows.",
		"",
		"  RESULT",
		fmt.Sprintf("  Source: %s check-update --security", dnfPath),
		"",
	}
	footer := []string{
		"",
		"  REMEDIATION",
		fmt.Sprintf("  Apply security updates:  sudo %s upgrade --security", dnfPath),
		fmt.Sprintf("  Apply all updates:       sudo %s upgrade", dnfPath),
	}

	if exitCode == 100 {
		details := append(append(header, pkgs...), footer...)
		base.Status = StatusFail
		base.Message = fmt.Sprintf("%d security update(s) pending", len(pkgs))
		base.Details = details
		base.JSONDetails = fmt.Sprintf("%d security updates pending\n%s\nFix: sudo %s upgrade --security", len(pkgs), strings.Join(pkgs, "\n"), dnfPath)
	} else {
		base.Status = StatusPass
		base.Message = "No pending security updates"
		base.Details = append(header,
			"  No pending security updates found via dnf.",
		)
	}
	return base
}

// yumCheck runs `yum --security check-update` as a fallback.
func yumCheck(base Task, yumPath string) Task {
	cmd := exec.Command(yumPath, "--security", "check-update", "-q")
	out, err := cmd.Output()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			base.Status = StatusWarn
			base.Message = "yum check-update failed: " + err.Error()
			return base
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var pkgs []string
	for _, l := range lines {
		if l != "" {
			pkgs = append(pkgs, "    "+l)
		}
	}

	if exitCode == 100 {
		base.Status = StatusFail
		base.Message = fmt.Sprintf("%d security update(s) pending", len(pkgs))
		base.Details = append([]string{
			"  WHY IT MATTERS",
			"  Unpatched packages expose known CVEs. Apply security updates promptly.",
			"",
			"  REMEDIATION",
			"  sudo yum update --security",
		}, pkgs...)
	} else {
		base.Status = StatusPass
		base.Message = "No pending security updates"
		base.Details = []string{"  No pending security updates found via yum."}
	}
	return base
}

// zypperCheck lists security patches via zypper on SUSE systems.
func zypperCheck(base Task, zypperPath string) Task {
	out, err := exec.Command(zypperPath, "--non-interactive", "list-patches",
		"--category", "security").Output()
	if err != nil {
		base.Status = StatusWarn
		base.Message = "zypper list-patches failed: " + err.Error()
		return base
	}

	text := strings.TrimSpace(string(out))
	lines := strings.Split(text, "\n")
	// zypper output has a header; count non-header, non-separator lines.
	count := 0
	var details []string
	for _, l := range lines {
		if strings.HasPrefix(l, "|") && !strings.HasPrefix(l, "| Name") {
			count++
			details = append(details, "  "+l)
		}
	}

	if count > 0 {
		base.Status = StatusFail
		base.Message = fmt.Sprintf("%d security patch(es) pending", count)
		base.Details = append([]string{
			"  WHY IT MATTERS",
			"  Unpatched packages expose known CVEs.",
			"",
			"  REMEDIATION",
			"  sudo zypper patch --category security",
			"",
			"  PENDING PATCHES",
		}, details...)
	} else {
		base.Status = StatusPass
		base.Message = "No pending security patches"
		base.Details = []string{"  No security patches found via zypper."}
	}
	return base
}
