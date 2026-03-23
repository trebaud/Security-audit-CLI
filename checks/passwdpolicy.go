package checks

// passwdpolicy.go — Password Policy check
//
// WHY THIS MATTERS
// Password aging and minimum-length policies are a baseline defense against
// credential-based attacks:
//
//   PASS_MAX_DAYS  — forces password rotation. If a password is stolen (via
//     phishing, database leak, or shoulder surfing), it becomes useless once
//     the account's password expires. NIST SP 800-63B recommends ≤90 days
//     for accounts without MFA.
//
//   PASS_MIN_LEN   — short passwords are trivially brute-forced or guessed.
//     A minimum of 8 characters is the absolute floor (NIST recommends 12+).
//
//   PASS_WARN_AGE  — advance notice before a password expires prevents users
//     from being locked out and reusing old passwords in a rush.
//
//   PASS_MIN_DAYS  — prevents users from immediately cycling back to their
//     old password right after a forced change.
//
// NOTE: /etc/login.defs applies to accounts managed by shadow-utils (useradd,
// passwd, etc.). PAM-based authentication may have its own policy via
// pam_pwquality/pam_passwdqc in /etc/pam.d/. This check covers login.defs only.
//
// HOW IT WORKS
// Reads /etc/login.defs line by line, parses KEY VALUE pairs, and compares
// each numeric value against opinionated security thresholds. Commented lines
// and non-numeric values are skipped.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PasswordPolicyCheck parses /etc/login.defs and flags weak password policy
// settings according to common security baselines.
type PasswordPolicyCheck struct{}

func (c *PasswordPolicyCheck) ID() string { return "passwdpolicy" }

// policyParam describes one login.defs directive and the thresholds that
// constitute a security weakness.
type policyParam struct {
	key         string // directive name as it appears in login.defs
	warnIfOver  int    // flag if value > this (0 = not checked)
	warnIfUnder int    // flag if value < this (0 = not checked)
	description string // human-readable label
}

// policyParams lists the login.defs directives we audit and their thresholds.
// Thresholds are based on CIS Benchmark Level 1 and NIST SP 800-63B guidance.
var policyParams = []policyParam{
	{
		key:         "PASS_MAX_DAYS",
		warnIfOver:  90,
		description: "Maximum password age (days) — should be ≤90",
	},
	{
		key:         "PASS_MIN_DAYS",
		description: "Minimum days between password changes — 1 prevents instant cycling",
	},
	{
		key:         "PASS_MIN_LEN",
		warnIfUnder: 8,
		description: "Minimum password length — should be ≥8 (NIST recommends ≥12)",
	},
	{
		key:         "PASS_WARN_AGE",
		warnIfUnder: 7,
		description: "Days before expiry to warn user — should be ≥7",
	},
}

func (c *PasswordPolicyCheck) Run() Task {
	const path = "/etc/login.defs"

	data, err := os.ReadFile(path)
	if err != nil {
		return Task{
			ID:          c.ID(),
			Name:        "Passwd Policy",
			Description: "Password aging and length policy",
			Status:      StatusSkipped,
			Message:     "Cannot read " + path,
			Details: []string{
				"  " + err.Error(),
				"  /etc/login.defs controls default password policy for shadow-utils.",
			},
		}
	}

	// Parse KEY VALUE pairs from login.defs, ignoring comments and blanks.
	values := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		// Only store values that parse cleanly as integers.
		if n, err := strconv.Atoi(fields[1]); err == nil {
			values[fields[0]] = n
		}
	}

	var issues []string
	var details []string

	// Evaluate each parameter against its threshold.
	for _, p := range policyParams {
		v, ok := values[p.key]
		if !ok {
			// Not set in login.defs — system defaults apply (often permissive).
			details = append(details, fmt.Sprintf("  [    ] %-16s  not set — using system default", p.key))
			continue
		}

		label := "OK  "
		annotation := ""

		if p.warnIfOver > 0 && v > p.warnIfOver {
			label = "WARN"
			annotation = fmt.Sprintf("  ← should be ≤%d", p.warnIfOver)
			issues = append(issues, fmt.Sprintf("%s=%d (>%d)", p.key, v, p.warnIfOver))
		}
		if p.warnIfUnder > 0 && v < p.warnIfUnder {
			label = "WARN"
			annotation = fmt.Sprintf("  ← should be ≥%d", p.warnIfUnder)
			issues = append(issues, fmt.Sprintf("%s=%d (<%d)", p.key, v, p.warnIfUnder))
		}

		details = append(details, fmt.Sprintf("  [%s] %-16s = %-6d%s  (%s)",
			label, p.key, v, annotation, p.description))
	}

	// Build the full details block with a context header.
	header := []string{
		"  WHY IT MATTERS",
		"  Password aging policies limit the window of exposure when a credential",
		"  is stolen. Short passwords are trivially brute-forced. These settings",
		"  apply to all accounts managed by shadow-utils (useradd, passwd, etc.).",
		"",
		"  SETTINGS IN " + path,
		"",
	}
	fullDetails := append(header, details...)

	if len(issues) == 0 {
		return Task{
			ID:          c.ID(),
			Name:        "Passwd Policy",
			Description: "Password aging and length policy",
			Status:      StatusPass,
			Message:     "Password policy looks good",
			Details:     fullDetails,
		}
	}

	fullDetails = append(fullDetails,
		"",
		"  REMEDIATION",
		"  Edit /etc/login.defs and adjust the flagged values.",
		"  Changes apply to new accounts and next password-change events.",
		"  To enforce retroactively:  chage -M 90 <username>",
	)

	return Task{
		ID:          c.ID(),
		Name:        "Passwd Policy",
		Description: "Password aging and length policy",
		Status:      StatusWarn,
		Message:     fmt.Sprintf("%d weak setting(s): %s", len(issues), strings.Join(issues, ", ")),
		Details:     fullDetails,
		JSONDetails: strings.Join(issues, "\n") + "\nFix: edit /etc/login.defs",
	}
}
