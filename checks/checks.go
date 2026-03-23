// Package checks provides a registry of security checks that can be run
// against the local system. Each check is a self-contained unit that inspects
// one aspect of system hardening, produces a human-readable result, and
// returns structured data consumed by the TUI and plain/JSON output modes.
//
// Adding a new check:
//  1. Create a new file in this package (e.g. mycheck.go).
//  2. Define a struct that implements the Check interface (ID + Run).
//  3. Register it in the All() slice below.
package checks

// Status constants represent the outcome of a security check, ordered from
// best to worst outcome.
const (
	// StatusPass means the check found no issues.
	StatusPass = "PASS"

	// StatusWarn means the check found a configuration that is not ideal but
	// not immediately exploitable — worth investigating.
	StatusWarn = "WARN"

	// StatusFail means the check found a concrete security misconfiguration
	// that should be remediated.
	StatusFail = "FAIL"

	// StatusCritical is reserved for checks that detect conditions that are
	// actively dangerous (e.g. empty root password).
	StatusCritical = "CRIT"

	// StatusSkipped means the check could not run (e.g. file not found,
	// insufficient privileges). It is not a verdict on security.
	StatusSkipped = "SKIP"

	// StatusRunning is a transient state used by the TUI while the goroutine
	// executing this check has not yet returned.
	StatusRunning = "RUNNING"
)

// Task holds the result of a single security check. It is produced by
// Check.Run() and consumed by both the TUI renderer and the plain/JSON
// output functions in main.go.
type Task struct {
	// ID is the stable, machine-readable identifier (matches Check.ID()).
	// Used for --checks filtering and JSON output.
	ID string

	// Name is a short (≤15 char) display name shown in the TUI row.
	Name string

	// Description is a one-line subtitle rendered below the name.
	Description string

	// Status is one of the Status* constants above.
	Status string

	// Message is a concise one-line result summary (e.g. "3 listening ports").
	Message string

	// Details contains multi-line content shown when a TUI row is expanded
	// (Enter/Space). It should include:
	//   - What was found
	//   - Why it matters (security context / threat model)
	//   - How to fix it
	Details []string

	// JSONDetails is a compact string used exclusively in JSON report output.
	// It should contain only raw findings data: affected paths, values, and
	// fix commands — no explanatory prose, no section headers, no [OK] lines.
	// Empty string is valid for PASS results where Message is self-sufficient.
	JSONDetails string
}

// Check is the interface every security check must implement. Implementations
// live in individual files within this package.
type Check interface {
	// ID returns a stable, lower-case, hyphen-free identifier used for
	// the --checks CLI filter (e.g. "ssh", "aslr").
	ID() string

	// Run executes the check synchronously and returns a fully-populated Task.
	// It must never panic; errors should be surfaced in the returned Task with
	// an appropriate Status (StatusSkipped or StatusWarn).
	Run() Task
}

// All returns every registered check in the order they appear in the TUI.
// The ordering is roughly: network → auth → filesystem → kernel → services → updates.
func All() []Check {
	return []Check{
		&PortsCheck{},           // network: listening services
		&SSHCheck{},             // auth: SSH daemon hardening
		&FilePermCheck{},        // filesystem: world-writable /etc files
		&ASLRCheck{},            // kernel: memory layout randomization
		&SudoersCheck{},         // auth: passwordless privilege escalation
		&FirewallCheck{},        // network: packet filtering
		&SUIDCheck{},            // filesystem: setuid/setgid binaries
		&AuditdCheck{},          // services: kernel audit logging
		&PasswordPolicyCheck{},  // auth: password aging & complexity
		&StickyBitCheck{},       // filesystem: temp directory protections
		&SecurityUpdatesCheck{}, // updates: pending security patches
		&KernelUpdateCheck{},    // updates: running vs installed kernel
		&PasswdFileCheck{},      // auth: UID-0 accounts, shadow perms, empty passwords
		&SudoLCheck{},           // auth: current user's live sudo privileges
		&ShellHistoryCheck{},    // auth: credential patterns in shell history
		&WritablePathCheck{},    // filesystem: world-writable dirs in $PATH
		&CronCheck{},            // filesystem: writable scripts in system cron jobs
	}
}

// ByID returns the subset of checks whose IDs are in the provided slice.
// The returned slice preserves the same order as All(). If ids is empty,
// All() is returned unmodified — i.e. omitting --checks runs everything.
func ByID(ids []string) []Check {
	if len(ids) == 0 {
		return All()
	}
	// Build a set for O(1) membership testing.
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	var out []Check
	for _, c := range All() {
		if set[c.ID()] {
			out = append(out, c)
		}
	}
	return out
}
