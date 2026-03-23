package checks

// shellhistory.go — Shell History Credential Leak check
//
// WHY THIS MATTERS
// Shell history files (.bash_history, .zsh_history, etc.) record every command
// a user has typed. Developers and sysadmins frequently type passwords directly
// into commands as arguments — a bad practice, but extremely common:
//
//   mysql -u root -pMySuperPassword
//   curl -u admin:hunter2 https://api.example.com/
//   sshpass -p 'secret' ssh user@host
//   export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
//   psql postgresql://user:password@localhost/db
//   openssl enc -k "mypassword" -in secret.txt
//
// These credentials are stored in plaintext on disk, readable by anyone with
// access to the file (or by an attacker who has escalated to that user).
//
// HOW IT WORKS
// Scans the history files for the current user and, if running as root, for
// all other users. Uses regex-style keyword matching for common credential
// patterns: -p, -password, :password@, PASS=, SECRET=, TOKEN=, KEY=, etc.
//
// IMPORTANT: this check does NOT extract or display the actual credential
// values — it only reports that a suspicious command was found and the
// approximate line number, so the operator can review and rotate credentials.

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ShellHistoryCheck scans shell history files for command patterns that
// commonly contain embedded credentials.
type ShellHistoryCheck struct{}

func (c *ShellHistoryCheck) ID() string { return "shellhistory" }

// suspiciousPatterns is a list of lowercase substrings that, when found in a
// history line, suggest a credential may be present. Matched case-insensitively.
var suspiciousPatterns = []string{
	"-ppassword", "-p ", "password=", "passwd=", "pass=",
	"secret=", "secret_key", "secretkey",
	"token=", "api_key", "apikey", "api_token",
	"aws_secret", "aws_access_key",
	"private_key", "privatekey",
	"sshpass", "sshpass -p",
	":password@", "://user:", "://admin:",
	"curl -u ", "wget --user", "wget --password",
	"mysql -p", "mysql --password",
	"psql postgresql://", "psql postgres://",
	"openssl enc -k", "openssl enc -pass",
	"gpg --passphrase",
	"ldapsearch -w ", "ldapadd -w ",
	"export.*pass", "export.*secret", "export.*token", "export.*key",
}

// historyFiles lists the shell history file paths relative to a user's home.
var historyFiles = []string{
	".bash_history",
	".zsh_history",
	".sh_history",
	".ash_history",
	".fish_history",
	".local/share/fish/fish_history",
}

func (c *ShellHistoryCheck) Run() Task {
	base := Task{
		ID:          c.ID(),
		Name:        "Shell History",
		Description: "Shell history files for embedded credentials",
	}

	// Collect all home directories to scan.
	homes := collectHomes()

	type hit struct {
		file string
		line int
		cmd  string
	}
	var hits []hit
	var scanned []string

	for _, home := range homes {
		for _, histFile := range historyFiles {
			path := filepath.Join(home, histFile)
			f, err := os.Open(path)
			if err != nil {
				continue // file doesn't exist or not readable — skip silently
			}
			scanned = append(scanned, path)
			scanner := bufio.NewScanner(f)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				lower := strings.ToLower(line)
				for _, pat := range suspiciousPatterns {
					if strings.Contains(lower, pat) {
						// Redact anything after an = sign or -p flag to avoid
						// displaying actual credential values in the TUI.
						display := redactCredential(line)
						hits = append(hits, hit{file: path, line: lineNum, cmd: display})
						break // one hit per line is enough
					}
				}
			}
			f.Close()
		}
	}

	details := []string{
		"  WHY IT MATTERS",
		"  Credentials typed as command arguments are saved verbatim in shell",
		"  history. An attacker who reads ~/.bash_history immediately obtains",
		"  passwords for databases, APIs, SSH, and cloud providers.",
		"",
	}

	if len(scanned) == 0 {
		details = append(details, "  No history files found or readable.")
		base.Status = StatusPass
		base.Message = "No shell history files found"
		base.Details = details
		return base
	}

	details = append(details, fmt.Sprintf("  Scanned %d history file(s):", len(scanned)))
	for _, s := range scanned {
		details = append(details, "    "+s)
	}

	if len(hits) == 0 {
		details = append(details, "",
			"  No credential-like patterns found in history.",
			"  (Checked for: passwords, tokens, API keys, sshpass, curl -u, etc.)",
		)
		base.Status = StatusPass
		base.Message = fmt.Sprintf("No credential patterns in %d history file(s)", len(scanned))
		base.Details = details
		return base
	}

	details = append(details, "",
		fmt.Sprintf("  SUSPICIOUS LINES FOUND (%d)", len(hits)),
		"  (Values are partially redacted — review the actual file to confirm)",
		"",
	)
	for _, h := range hits {
		details = append(details, fmt.Sprintf("  %s:%d", h.file, h.line))
		details = append(details, "    "+h.cmd)
	}
	details = append(details,
		"",
		"  REMEDIATION",
		"  1. Rotate any credentials that may have been exposed.",
		"  2. Clear history:  history -c && > ~/.bash_history",
		"  3. Prevent future leaks: use a password manager or credential file",
		"     (e.g. ~/.my.cnf for MySQL, ~/.netrc for curl/wget).",
		"  4. Set HISTCONTROL=ignorespace in ~/.bashrc so commands prefixed",
		"     with a space are not saved to history.",
	)

	var jsonLines []string
	for _, h := range hits {
		jsonLines = append(jsonLines, fmt.Sprintf("%s:%d  %s", h.file, h.line, h.cmd))
	}
	base.Status = StatusFail
	base.Message = fmt.Sprintf("%d potential credential leak(s) in shell history", len(hits))
	base.Details = details
	base.JSONDetails = strings.Join(jsonLines, "\n")
	return base
}

// collectHomes returns the home directories to scan.
// For root: scans /root plus all home dirs under /home.
// For non-root: only scans the current user's home.
func collectHomes() []string {
	current, err := user.Current()
	if err != nil {
		return nil
	}

	homes := []string{current.HomeDir}

	// If running as root, also scan other users' home directories.
	if current.Uid == "0" {
		entries, err := os.ReadDir("/home")
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					p := filepath.Join("/home", e.Name())
					if p != current.HomeDir {
						homes = append(homes, p)
					}
				}
			}
		}
		// Also include /root if it's not the current home.
		if current.HomeDir != "/root" {
			homes = append(homes, "/root")
		}
	}

	return homes
}

// redactCredential replaces the value portion of common credential patterns
// with "[REDACTED]" so the TUI doesn't display actual secrets.
func redactCredential(line string) string {
	// For lines that are very long, truncate display.
	if len(line) > 120 {
		line = line[:120] + "…"
	}

	// Redact common value patterns after = or -p.
	redactMarkers := []string{
		"password=", "passwd=", "pass=", "secret=", "token=",
		"api_key=", "apikey=", "aws_secret_access_key=",
	}
	lower := strings.ToLower(line)
	for _, marker := range redactMarkers {
		idx := strings.Index(lower, marker)
		if idx >= 0 {
			valueStart := idx + len(marker)
			if valueStart < len(line) {
				// Find end of the value token (space or end of string).
				end := strings.IndexAny(line[valueStart:], " \t'\"")
				if end < 0 {
					end = len(line) - valueStart
				}
				if end > 0 {
					line = line[:valueStart] + "[REDACTED]" + line[valueStart+end:]
				}
			}
		}
	}
	return line
}
