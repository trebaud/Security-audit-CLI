package checks

// kernelupdate.go — Kernel Update check
//
// WHY THIS MATTERS
// The Linux kernel is the most privileged piece of software on the system.
// Kernel vulnerabilities can allow local privilege escalation from any user
// to root, container escapes, information leaks, or remote code execution.
//
// High-profile examples:
//   - Dirty COW (CVE-2016-5195)       — any user → root in seconds
//   - Spectre / Meltdown (CVE-2017-*)  — cross-process memory disclosure
//   - Dirty Pipe (CVE-2022-0847)       — overwrite read-only files as any user
//   - pkexec / nimbuspwn (2022)        — local privilege escalation
//
// A new kernel package being installed does NOT automatically activate it —
// the system must be rebooted. This check detects that gap: a newer kernel
// is sitting on disk but the running kernel is still the old one.
//
// HOW IT WORKS
//
//   Debian / Ubuntu
//     Compares `uname -r` (running kernel) against installed linux-image-*
//     packages via `dpkg -l`. If a higher version is installed, a reboot is
//     needed to activate it.
//     Also checks /var/run/reboot-required (written by apt post-install hooks)
//     as a fast-path confirmation.
//
//   RHEL / Fedora / CentOS
//     Compares `uname -r` against installed kernel RPMs via `rpm -q kernel`.
//
//   Generic fallback
//     Checks /var/run/reboot-required and /proc/version_signature.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// KernelUpdateCheck compares the running kernel version with the newest
// kernel package installed on disk.
type KernelUpdateCheck struct{}

func (c *KernelUpdateCheck) ID() string { return "kernelupdate" }

func (c *KernelUpdateCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Kernel",
		Description: "Running kernel vs latest installed version",
	}

	// Read the currently running kernel version from the kernel itself.
	runningRaw, err := exec.Command("uname", "-r").Output()
	if err != nil {
		base.Status = StatusSkipped
		base.Message = "Cannot determine running kernel (uname failed)"
		return base
	}
	running := strings.TrimSpace(string(runningRaw))

	// ---- Debian / Ubuntu path ----
	if _, err := exec.LookPath("dpkg"); err == nil {
		return dpkgKernelCheck(base, running)
	}

	// ---- RHEL / Fedora / CentOS path ----
	if _, err := exec.LookPath("rpm"); err == nil {
		return rpmKernelCheck(base, running)
	}

	// ---- Generic fallback: /var/run/reboot-required ----
	return rebootRequiredCheck(base, running)
}

// dpkgKernelCheck finds all installed linux-image-* packages, sorts them by
// the dpkg version ordering, and compares the highest against the running kernel.
func dpkgKernelCheck(base Task, running string) Task {
	// List all installed kernel image packages.
	out, err := exec.Command("dpkg", "-l", "linux-image-*").Output()
	if err != nil {
		return rebootRequiredCheck(base, running)
	}

	// Parse "ii  linux-image-X.Y.Z-N-generic  version  arch  description" lines.
	type kernelPkg struct {
		name    string
		version string
	}
	var installed []kernelPkg
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "ii") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pkgName := fields[1]
		pkgVer := fields[2]
		// Only count versioned images (e.g. linux-image-6.1.0-28-amd64),
		// not meta-packages like linux-image-amd64.
		if strings.Count(pkgName, ".") < 2 {
			continue
		}
		installed = append(installed, kernelPkg{name: pkgName, version: pkgVer})
	}

	if len(installed) == 0 {
		return rebootRequiredCheck(base, running)
	}

	// Find the newest installed kernel package by dpkg --compare-versions.
	newest := installed[0]
	for _, pkg := range installed[1:] {
		// dpkg --compare-versions A gt B exits 0 if A > B.
		cmp := exec.Command("dpkg", "--compare-versions", pkg.version, "gt", newest.version)
		if cmp.Run() == nil {
			newest = pkg
		}
	}

	// Extract the kernel release string from the package name.
	// linux-image-6.1.0-28-amd64 → 6.1.0-28-amd64
	newestRelease := strings.TrimPrefix(newest.name, "linux-image-")

	details := buildKernelDetails(running, newestRelease, newest.name, newest.version)

	// Also check the fast-path reboot-required flag written by apt hooks.
	rebootRequired := false
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		rebootRequired = true
		details = append(details, "  /var/run/reboot-required exists — system needs a reboot")
	}

	if running == newestRelease || (!rebootRequired && running != newestRelease && strings.HasPrefix(newestRelease, running)) {
		base.Status = StatusPass
		base.Message = fmt.Sprintf("Running latest installed kernel (%s)", running)
		base.Details = details
		return base
	}

	if running != newestRelease || rebootRequired {
		base.Status = StatusFail
		base.Message = fmt.Sprintf("Reboot needed: running %s, newest installed %s", running, newestRelease)
		base.Details = append(details, "",
			"  REMEDIATION",
			"  Schedule a reboot to activate the new kernel:",
			"    sudo reboot",
			"  Verify after reboot: uname -r",
		)
		base.JSONDetails = fmt.Sprintf("running: %s\nnewest installed: %s\nFix: sudo reboot", running, newestRelease)
		return base
	}

	base.Status = StatusPass
	base.Message = fmt.Sprintf("Running latest installed kernel (%s)", running)
	base.Details = details
	return base
}

// rpmKernelCheck lists installed kernel RPMs and finds the newest.
func rpmKernelCheck(base Task, running string) Task {
	out, err := exec.Command("rpm", "-q", "kernel", "--queryformat",
		"%{VERSION}-%{RELEASE}.%{ARCH}\n").Output()
	if err != nil {
		return rebootRequiredCheck(base, running)
	}

	var versions []string
	for _, v := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		v = strings.TrimSpace(v)
		if v != "" {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return rebootRequiredCheck(base, running)
	}

	// The last line from rpm -q kernel is typically the newest.
	newest := versions[len(versions)-1]

	details := buildKernelDetails(running, newest, "kernel-"+newest, newest)
	details = append(details, "  All installed kernel versions:")
	for _, v := range versions {
		marker := "   "
		if v == running {
			marker = " ▶ "
		}
		details = append(details, fmt.Sprintf("  %s%s", marker, v))
	}

	if running == newest {
		base.Status = StatusPass
		base.Message = fmt.Sprintf("Running latest installed kernel (%s)", running)
		base.Details = details
	} else {
		base.Status = StatusFail
		base.Message = fmt.Sprintf("Reboot needed: running %s, newest %s", running, newest)
		base.Details = append(details, "",
			"  REMEDIATION",
			"  sudo reboot",
		)
		base.JSONDetails = fmt.Sprintf("running: %s\nnewest installed: %s\nFix: sudo reboot", running, newest)
	}
	return base
}

// rebootRequiredCheck is the generic fallback: look for /var/run/reboot-required.
func rebootRequiredCheck(base Task, running string) Task {
	details := []string{
		"  WHY IT MATTERS",
		"  A newer kernel may be installed but not yet active.",
		"  Kernel vulnerabilities (Dirty COW, Dirty Pipe, Spectre, etc.) require",
		"  a reboot to be mitigated once a patched kernel is installed.",
		"",
		fmt.Sprintf("  Running kernel: %s", running),
	}

	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		var pkgList []string
		if pkgData, err := os.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
			for _, pkg := range strings.Split(strings.TrimSpace(string(pkgData)), "\n") {
				if pkg != "" {
					pkgList = append(pkgList, pkg)
					details = append(details, "    "+pkg)
				}
			}
		}
		details = append(details, "",
			"  REMEDIATION",
			"  sudo reboot",
		)
		base.Status = StatusFail
		base.Message = "Reboot required (/var/run/reboot-required exists)"
		base.Details = details
		jsonD := fmt.Sprintf("running: %s\n/var/run/reboot-required exists", running)
		if len(pkgList) > 0 {
			jsonD += "\nPackages requiring reboot: " + strings.Join(pkgList, ", ")
		}
		jsonD += "\nFix: sudo reboot"
		base.JSONDetails = jsonD
		return base
	}

	base.Status = StatusPass
	base.Message = fmt.Sprintf("No reboot required (running %s)", running)
	base.Details = details
	return base
}

// buildKernelDetails produces the common WHY IT MATTERS + RESULT detail block.
func buildKernelDetails(running, newestRelease, pkgName, pkgVersion string) []string {
	upToDate := running == newestRelease
	statusLine := fmt.Sprintf("  Running:          %s", running)
	newestLine := fmt.Sprintf("  Newest installed: %s  (package: %s %s)", newestRelease, pkgName, pkgVersion)

	header := []string{
		"  WHY IT MATTERS",
		"  The kernel is the most privileged layer of the system. Kernel CVEs",
		"  can allow any local user to escalate to root, escape containers, or",
		"  leak memory across process boundaries. A patched kernel only protects",
		"  you after a reboot — a pending kernel update means you are still",
		"  running vulnerable code.",
		"",
		"  Notable kernel CVEs: Dirty COW (2016), Spectre/Meltdown (2018),",
		"  Dirty Pipe (2022) — all required a reboot to fully mitigate.",
		"",
		"  RESULT",
		statusLine,
		newestLine,
	}

	if upToDate {
		return append(header, "  ✓ Running kernel matches newest installed version.")
	}
	return append(header, "  ✗ Running kernel is OLDER than newest installed — reboot to activate patch.")
}
