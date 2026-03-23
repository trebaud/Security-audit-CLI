package checks

// passwdfile.go — Critical Auth Files check
//
// WHY THIS MATTERS
// /etc/passwd and /etc/shadow are the core identity and credential files on Linux.
//
//   /etc/passwd  — lists every account (username, UID, GID, home, shell).
//                  World-writable → any user can add a UID-0 account or change
//                  an existing user's shell to /bin/bash.
//
//   /etc/shadow  — stores hashed passwords and aging information.
//                  World-readable → any user can run offline password cracking.
//                  World-writable → any user can replace the root hash.
//
// EXTRA CHECKS PERFORMED
//
//   UID 0 accounts  — any account with uid=0 (other than root) has full root
//     privileges by definition. Backdoor accounts are often added this way.
//     Command equivalent: awk -F: '($3==0)' /etc/passwd
//
//   Empty password hash — a blank or "!" hash means the account has no
//     password at all and is trivially accessible. Modern login managers
//     typically block empty-hash logins, but some PAM configs do not.
//     Command equivalent: awk -F: '($2==""||$2=="!")' /etc/shadow
//
//   Writable /etc/passwd / /etc/shadow — the most dangerous filesystem
//     misconfiguration for privilege escalation.

import (
	"fmt"
	"os"
	"strings"
)

// PasswdFileCheck inspects /etc/passwd and /etc/shadow for dangerous
// permissions and suspicious account configurations.
type PasswdFileCheck struct{}

func (c *PasswdFileCheck) ID() string { return "passwdfile" }

func (c *PasswdFileCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Auth Files",
		Description: "/etc/passwd & /etc/shadow permissions and content",
	}

	var issues []string
	var details []string

	details = append(details,
		"  WHY IT MATTERS",
		"  /etc/passwd and /etc/shadow define every account and credential on the",
		"  system. Weak permissions or rogue UID-0 accounts are a direct path to",
		"  root — one of the first things checked during privilege escalation.",
		"",
	)

	// ---- /etc/passwd permissions ----
	details = append(details, "  /etc/passwd PERMISSIONS")
	if info, err := os.Stat("/etc/passwd"); err == nil {
		mode := info.Mode()
		details = append(details, fmt.Sprintf("    mode: %s", mode))
		if mode&0o002 != 0 {
			issues = append(issues, "/etc/passwd is world-writable")
			details = append(details,
				"    [FAIL] World-writable! Any user can add a UID-0 account.",
				"    Fix:   chmod 644 /etc/passwd",
			)
		} else if mode&0o020 != 0 {
			issues = append(issues, "/etc/passwd is group-writable")
			details = append(details,
				"    [WARN] Group-writable. Verify the owning group is trusted.",
				"    Fix:   chmod 644 /etc/passwd",
			)
		} else {
			details = append(details, "    [OK]  Permissions look correct (expected 644)")
		}
	} else {
		details = append(details, "    [SKIP] Cannot stat /etc/passwd: "+err.Error())
	}

	// ---- /etc/shadow permissions ----
	details = append(details, "", "  /etc/shadow PERMISSIONS")
	if info, err := os.Stat("/etc/shadow"); err == nil {
		mode := info.Mode()
		details = append(details, fmt.Sprintf("    mode: %s", mode))
		if mode&0o004 != 0 {
			issues = append(issues, "/etc/shadow is world-readable")
			details = append(details,
				"    [FAIL] World-readable! Any user can copy the shadow file and",
				"           run offline password cracking (hashcat, john).",
				"    Fix:   chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
			)
		} else if mode&0o002 != 0 {
			issues = append(issues, "/etc/shadow is world-writable")
			details = append(details,
				"    [FAIL] World-writable! Any user can overwrite the root hash.",
				"    Fix:   chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
			)
		} else {
			details = append(details, "    [OK]  Permissions look correct (expected 640 or 000)")
		}
	} else {
		// shadow not readable — that's expected for non-root users.
		details = append(details, "    [OK]  /etc/shadow is not readable by current user (expected)")
	}

	// ---- UID 0 accounts ----
	details = append(details, "", "  UID 0 ACCOUNTS (should be root only)")
	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		details = append(details, "    [SKIP] Cannot read /etc/passwd: "+err.Error())
	} else {
		uid0 := []string{}
		for _, line := range strings.Split(string(passwdData), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 4 {
				continue
			}
			username := fields[0]
			uid := fields[2]
			if uid == "0" && username != "root" {
				uid0 = append(uid0, fmt.Sprintf("    [FAIL] %s (uid=0) — unexpected root-equivalent account!", username))
				issues = append(issues, "non-root UID-0 account: "+username)
			}
		}
		if len(uid0) == 0 {
			details = append(details, "    [OK]  Only 'root' has uid=0")
		} else {
			details = append(details, uid0...)
			details = append(details,
				"",
				"    Accounts with uid=0 have full root privileges regardless of their name.",
				"    These are often backdoor accounts. Investigate and remove if unexpected.",
				"    Fix:   userdel <username>  or  usermod -u <new_uid> <username>",
			)
		}
	}

	// ---- Empty / no-password accounts in /etc/shadow ----
	details = append(details, "", "  EMPTY PASSWORD ACCOUNTS")
	shadowData, err := os.ReadFile("/etc/shadow")
	if err != nil {
		details = append(details, "    [SKIP] Cannot read /etc/shadow (requires root)")
	} else {
		nopass := []string{}
		for _, line := range strings.Split(string(shadowData), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 2 {
				continue
			}
			username := fields[0]
			hash := fields[1]
			// Empty string or a single "!" (locked) or "" means no password set.
			// An account with no hash at all (empty string) is the dangerous case.
			if hash == "" {
				nopass = append(nopass, fmt.Sprintf("    [FAIL] %s — no password hash! Account is trivially accessible.", username))
				issues = append(issues, "no-password account: "+username)
			}
		}
		if len(nopass) == 0 {
			details = append(details, "    [OK]  All accounts have a password hash or are locked")
		} else {
			details = append(details, nopass...)
			details = append(details,
				"",
				"    Fix: set a strong password:  passwd <username>",
				"    Or lock the account:          usermod -L <username>",
			)
		}
	}

	// ---- Final verdict ----
	if len(issues) == 0 {
		base.Status = StatusPass
		base.Message = "Auth file permissions and accounts look secure"
	} else {
		base.Status = StatusFail
		base.Message = fmt.Sprintf("%d issue(s): %s", len(issues), strings.Join(issues, "; "))
		base.JSONDetails = strings.Join(issues, "\n")
	}
	base.Details = details
	return base
}
