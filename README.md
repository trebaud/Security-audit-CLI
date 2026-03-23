# sec-audit

A unix security auditing CLI. Runs a suite of hardening checks against the local system and presents results in an interactive TUI, plain text, or JSON.

Designed for quick security posture assessment on servers, workstations, and CI pipelines without external dependencies or root required for most checks.

## Build

```sh
git clone <repo>
cd sec-audit
go build -o sec-audit .
```

Requires Go 1.24+.

## Usage

```
sec-audit [flags]

  -output  tui|plain|json|auto   Output format (default: auto — tui if TTY, plain otherwise)
  -json                          Shorthand for -output=json
  -checks  <id1,id2,...>         Run only specific checks (default: all)
  -no-color                      Disable ANSI colors in plain output
  -list                          Print all available check IDs and exit
```

### Examples

```sh
# Interactive TUI (default when run in a terminal)
./sec-audit

# Plain text report with color
./sec-audit -output=plain

# Full JSON report
./sec-audit -json

# Save JSON report to file
./sec-audit -json > report.json

# Run a subset of checks
./sec-audit -checks=ssh,aslr,firewall,sudol

# List all available check IDs
./sec-audit -list
```

## Checks

| ID             | What it checks                                                         |
|----------------|------------------------------------------------------------------------|
| `ports`        | Listening TCP/UDP services. Warns above 10, fails above 20.            |
| `ssh`          | sshd_config: PermitRootLogin, PasswordAuthentication, X11Forwarding, Protocol |
| `fileperm`     | World-writable files in /etc (depth 2)                                 |
| `aslr`         | /proc/sys/kernel/randomize_va_space — must be 2 for full ASLR          |
| `sudoers`      | /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries                 |
| `firewall`     | Active packet filter: probes ufw, nftables, iptables in order          |
| `suid`         | SUID/SGID binaries not on known-safe allowlist                         |
| `auditd`       | Linux audit daemon running (systemctl / pgrep fallback)                |
| `passwdpolicy` | /etc/login.defs: PASS_MAX_DAYS (<=90), PASS_MIN_LEN (>=8), PASS_WARN_AGE (>=7) |
| `stickybit`    | Sticky bit on /tmp, /var/tmp, /dev/shm                                 |
| `secupdates`   | Pending security updates via apt-check / dnf / zypper (dry-run only)  |
| `kernelupdate` | Running kernel vs. newest installed package — detects reboot-needed    |
| `passwdfile`   | /etc/passwd and /etc/shadow permissions, UID-0 accounts, empty hashes |
| `sudol`        | sudo -l for current user: full root grants, NOPASSWD rules, GTFOBins matches |
| `shellhistory` | Shell history files (~/.bash_history, ~/.zsh_history, etc.) for credential patterns |
| `writablepath` | World-writable directories in $PATH (PATH hijacking)                   |
| `cron`         | Writable scripts/dirs referenced by system cron jobs                   |


Details expand to show findings, affected paths, and remediation commands. Checks are sorted by severity: CRIT > FAIL > WARN > SKIP > PASS.

## JSON output schema

```json
{
  "generated_at": "2026-01-02T15:04:05-05:00",
  "hostname":     "myserver",
  "os":           "Ubuntu 24.04.4 LTS",
  "kernel":       "6.1.0-28-amd64",
  "checks_run":   17,
  "summary": { "PASS": 6, "WARN": 5, "FAIL": 4, "CRIT": 0, "SKIP": 1 },
  "results": [
    {
      "id":          "firewall",
      "name":        "Firewall",
      "description": "Verify a firewall is active",
      "status":      "FAIL",
      "message":     "No firewall detected (ufw/nft/iptables)",
      "details":     "No firewall active (probed: ufw, nftables, iptables)\nFix: apt install ufw && ufw allow ssh && ufw enable"
    }
  ]
}
```

## Privilege notes

Most checks run without root. The following checks produce better results or additional findings when run as root:

- `passwdfile` — reads /etc/shadow for empty hashes
- `sudoers` — reads /etc/sudoers (mode 0440)
- `shellhistory` — scans all users under /home in addition to current user
- `secupdates` — some apt configurations require elevated access

## Adding a check

1. Create `checks/<name>.go` implementing the `checks.Check` interface (`ID() string`, `Run() Task`).
2. Populate both `Task.Details` (TUI expanded view) and `Task.JSONDetails` (JSON output).
3. Register it in the `All()` slice in `checks/checks.go`.
4. Add its display name and description to the placeholder maps in `tui/model.go`.
