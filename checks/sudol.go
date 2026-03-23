package checks

// sudol.go — sudo -l (Current User Sudo Privileges) check
//
// WHY THIS MATTERS
// `sudo -l` lists the commands the *currently running user* is allowed to
// execute as root (or another user). This is fundamentally different from
// the `sudoers` check (which greps config files for NOPASSWD):
//
//   sudoers check  → static analysis of /etc/sudoers and /etc/sudoers.d/*
//   sudo -l check  → live query of what THIS user can actually do right now
//
// Even rules that require a password are important: if a user can sudo ANY
// binary, an attacker who gains that user's credentials has a full root path.
//
// GTFOBins (https://gtfobins.github.io/) documents how almost every common
// Unix utility — vim, find, awk, python, perl, tar, git, man, less, etc. —
// can be abused to escape to a root shell when run via sudo.
//
// DETECTION
// Runs `sudo -l -n` (-n = non-interactive, never prompt for password).
// If the current user has no sudo privileges or sudo is not installed, the
// check reports accordingly without hanging waiting for a password.
//
// WHAT TO LOOK FOR
//   (ALL : ALL) ALL          → full root access
//   (root) NOPASSWD: /bin/X  → passwordless root for that binary
//   (root) /usr/bin/vim      → vim can open /etc/sudoers, etc. with :!bash
//   (root) /usr/bin/python*  → trivial os.system('/bin/bash') shell escape
//   (root) /usr/bin/find     → find . -exec /bin/sh \; -quit

import (
	"fmt"
	"os/exec"
	"strings"
)

// SudoLCheck runs `sudo -l` for the current user to enumerate actual sudo
// privileges, flagging any that could be leveraged for privilege escalation.
type SudoLCheck struct{}

func (c *SudoLCheck) ID() string { return "sudol" }

// gtfoBins is a curated list of binaries commonly abused for shell escapes
// when granted via sudo. Used to flag high-risk entries in sudo -l output.
// Reference: https://gtfobins.github.io/
var gtfoBins = []string{
	"bash", "sh", "zsh", "fish", "dash",
	"python", "python2", "python3", "ruby", "perl", "lua",
	"vim", "vi", "nano", "emacs",
	"find", "awk", "gawk", "nawk",
	"tar", "zip", "unzip",
	"man", "less", "more",
	"git",
	"apt", "apt-get", "dnf", "yum", "pip", "pip3",
	"docker", "podman",
	"nc", "ncat", "netcat",
	"curl", "wget",
	"node", "nodejs",
	"php",
	"rsync",
	"env",
	"tee",
	"cp", "mv",
	"chmod", "chown",
	"dd",
	"openssl",
}

func (c *SudoLCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Sudo -l",
		Description: "Current user's sudo privileges",
	}

	// -n = non-interactive: exit instead of prompting for a password.
	// This prevents the check from hanging.
	out, err := exec.Command("sudo", "-l", "-n").CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		// Common cases for non-zero exit:
		//   "sudo: a password is required" → user has sudo but -n blocked the prompt
		//   "Sorry, user X may not run sudo" → no sudo access
		if strings.Contains(output, "password is required") || strings.Contains(output, "a password is required") {
			// User has sudo privileges but we can't list them without a password.
			base.Status = StatusWarn
			base.Message = "User has sudo access but password required to list rules"
			base.Details = []string{
				"  WHY IT MATTERS",
				"  This user has sudo privileges. Run 'sudo -l' manually (with your",
				"  password) to see exactly which commands are allowed.",
				"  Then cross-reference each binary at https://gtfobins.github.io/",
				"",
				"  sudo -n exited: " + output,
			}
			return base
		}

		if strings.Contains(output, "may not run sudo") ||
			strings.Contains(output, "not allowed to run sudo") ||
			strings.Contains(output, "not in the sudoers") {
			base.Status = StatusPass
			base.Message = "Current user has no sudo privileges"
			base.Details = []string{
				"  WHY IT MATTERS",
				"  sudo grants controlled root access. A user with no sudo rules",
				"  cannot directly escalate via this vector.",
				"",
				"  RESULT",
				"  sudo -l reports: " + output,
			}
			return base
		}

		if strings.Contains(output, "command not found") || strings.Contains(strings.ToLower(output), "sudo: not found") {
			base.Status = StatusSkipped
			base.Message = "sudo is not installed"
			base.Details = []string{"  sudo binary not found on this system."}
			return base
		}

		// Unexpected error.
		base.Status = StatusWarn
		base.Message = "sudo -l returned an unexpected error"
		base.Details = []string{
			"  Error: " + output,
			"  Run 'sudo -l' manually to investigate.",
		}
		return base
	}

	// Parse the output to find (ALL) or NOPASSWD rules.
	lines := strings.Split(output, "\n")
	var ruleLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Rules look like:  (ALL : ALL) ALL   or   (root) NOPASSWD: /usr/bin/vim
		if strings.HasPrefix(trimmed, "(") {
			ruleLines = append(ruleLines, trimmed)
		}
	}

	if len(ruleLines) == 0 {
		base.Status = StatusPass
		base.Message = "No sudo rules found for current user"
		base.Details = []string{
			"  WHY IT MATTERS",
			"  sudo grants controlled root access. No rules means this user cannot",
			"  escalate via sudo.",
			"",
			"  Full sudo -l output:",
			"  " + output,
		}
		return base
	}

	// Check for ALL / NOPASSWD / GTFOBins matches.
	var nopasswdRules []string
	var gtfoMatches []string
	var allRules []string
	hasAllAll := false

	for _, rule := range ruleLines {
		upper := strings.ToUpper(rule)
		allRules = append(allRules, "    "+rule)

		if strings.Contains(upper, "NOPASSWD") {
			nopasswdRules = append(nopasswdRules, rule)
		}
		if strings.Contains(upper, "(ALL") && strings.Contains(upper, ") ALL") {
			hasAllAll = true
		}
		// Check each rule for known GTFOBins binaries.
		for _, bin := range gtfoBins {
			if strings.Contains(rule, "/"+bin) || strings.Contains(rule, " "+bin+" ") {
				gtfoMatches = append(gtfoMatches, fmt.Sprintf("    %-18s  in rule: %s", bin, rule))
				break
			}
		}
	}

	details := []string{
		"  WHY IT MATTERS",
		"  Any binary granted via sudo can potentially be used to escape to a root",
		"  shell. Even password-protected rules matter — a compromised password",
		"  immediately grants root. Check https://gtfobins.github.io/ for each binary.",
		"",
		"  SUDO RULES FOR CURRENT USER",
	}
	details = append(details, allRules...)

	if hasAllAll {
		details = append(details, "",
			"  [FAIL] User can run ALL commands as ALL users — effectively root.",
		)
	}
	if len(nopasswdRules) > 0 {
		details = append(details, "",
			"  [FAIL] NOPASSWD rules (no credential barrier):")
		for _, r := range nopasswdRules {
			details = append(details, "    "+r)
		}
	}
	if len(gtfoMatches) > 0 {
		details = append(details, "",
			"  [WARN] GTFOBins matches — these binaries have known shell escape techniques:",
		)
		details = append(details, gtfoMatches...)
		details = append(details, "",
			"  Reference: https://gtfobins.github.io/",
		)
	}

	details = append(details, "",
		"  REMEDIATION",
		"  Restrict sudo rules to the minimum necessary commands.",
		"  Prefer specific paths over wildcards. Audit with: sudo -l",
	)

	// Determine worst status.
	var jsonLines []string
	jsonLines = append(jsonLines, allRules...)
	if len(nopasswdRules) > 0 {
		jsonLines = append(jsonLines, "NOPASSWD rules: "+strings.Join(nopasswdRules, ", "))
	}
	if len(gtfoMatches) > 0 {
		jsonLines = append(jsonLines, "GTFOBins matches:")
		jsonLines = append(jsonLines, gtfoMatches...)
	}

	if hasAllAll || len(nopasswdRules) > 0 {
		base.Status = StatusFail
		if hasAllAll {
			base.Message = "Full root sudo access granted to current user"
		} else {
			base.Message = fmt.Sprintf("%d NOPASSWD sudo rule(s) — no credential barrier", len(nopasswdRules))
		}
	} else if len(gtfoMatches) > 0 {
		base.Status = StatusWarn
		base.Message = fmt.Sprintf("%d sudo rule(s) include GTFOBins-exploitable binaries", len(gtfoMatches))
	} else {
		base.Status = StatusWarn
		base.Message = fmt.Sprintf("%d sudo rule(s) found — review manually", len(ruleLines))
	}

	base.Details = details
	base.JSONDetails = strings.Join(jsonLines, "\n")
	return base
}
