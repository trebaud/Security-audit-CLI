// Command sec-audit is an interactive Linux security auditing tool.
//
// It runs a suite of security checks against the local system and presents
// the results in an interactive TUI (terminal user interface) or as plain
// text / JSON for scripting and CI pipelines.
//
// USAGE
//
//	sec-audit [flags]
//
// FLAGS
//
//	--output  tui|plain|json   Output format.
//	                           "auto" (default) uses "tui" when stdout is a TTY,
//	                           otherwise falls back to "plain".
//	--json                     Shorthand for --output=json. Prints a full JSON
//	                           report with metadata envelope to stdout and exits.
//	--checks  <ids>            Comma-separated list of check IDs to run.
//	                           Omit to run all checks.
//	--no-color                 Disable ANSI escape codes in plain output.
//	                           Useful when piping to files or other tools.
//	--list                     Print all available check IDs and exit.
//
// EXAMPLES
//
//	sec-audit                              # interactive TUI, all checks
//	sec-audit --output=plain               # non-interactive, coloured text
//	sec-audit --json                       # full JSON report to stdout
//	sec-audit --json | jq '.summary'       # parse with jq
//	sec-audit --json > report.json         # save report to file
//	sec-audit --checks=aslr,ssh            # run only two specific checks
//	sec-audit --output=plain --no-color    # plain text, no colour (for log files)
//
// JSON REPORT SCHEMA
//
//	{
//	  "generated_at": "2006-01-02T15:04:05Z07:00",
//	  "hostname":     "myserver",
//	  "os":           "Ubuntu 24.04.4 LTS",
//	  "kernel":       "6.1.0-28-amd64",
//	  "checks_run":   17,
//	  "summary": {
//	    "PASS": 6, "WARN": 5, "FAIL": 4, "SKIP": 1, "CRIT": 0
//	  },
//	  "results": [
//	    {
//	      "id":          "ssh",
//	      "name":        "SSH Config",
//	      "description": "Verify SSH daemon hardening",
//	      "status":      "FAIL",
//	      "message":     "2 insecure directive(s) found",
//	      "details":     ["  WHY IT MATTERS", "  ...", "  Fix: ..."]
//	    }, ...
//	  ]
//	}
//
// ARCHITECTURE
//
//	main.go          — entry point, flag parsing, output dispatch
//	checks/          — one file per security check; Check interface + registry
//	tui/             — Bubbletea TUI: model, view, styles
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"sec-audit/checks"
	"sec-audit/tui"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sys/unix"
)

func main() {
	// -------------------------------------------------------------------------
	// Flag definitions
	// -------------------------------------------------------------------------

	// outputFlag controls the rendering mode.
	// "auto" selects "tui" when stdout is a terminal, "plain" otherwise —
	// so the tool is safely pipeable without explicit flags.
	outputFlag := flag.String("output", "auto",
		`Output format: tui, plain, json
  tui   — interactive terminal UI (default when stdout is a TTY)
  plain — line-by-line text report with ANSI colours
  json  — full JSON report with metadata envelope (see --json)
  auto  — tui if TTY, plain otherwise`)

	// jsonFlag is a convenient shorthand for --output=json.
	// It prints a complete JSON report (with hostname, OS, kernel, timestamp,
	// summary counts, and all check details) to stdout and exits.
	// Ideal for: saving reports, piping to jq, SIEM ingestion, CI pipelines.
	jsonFlag := flag.Bool("json", false, "Print full JSON report to stdout and exit (shorthand for --output=json)")

	// checksFlag allows running only a subset of the registered checks.
	// e.g. --checks=aslr,ssh runs just those two.
	checksFlag := flag.String("checks", "",
		"Comma-separated check IDs to run (default: all)\n"+
			"Run --list to see all available IDs.")

	// noColor disables ANSI escape sequences in plain output.
	// Useful when capturing output to a log file or piping to tools that
	// do not understand colour codes.
	noColor := flag.Bool("no-color", false, "Disable ANSI colors in plain output")

	// listChecks prints available check IDs and exits without running anything.
	listChecks := flag.Bool("list", false, "Print available check IDs and exit")

	flag.Parse()

	// --json is a shorthand that overrides --output.
	if *jsonFlag {
		*outputFlag = "json"
	}

	// -------------------------------------------------------------------------
	// --list: print available check IDs and exit
	// -------------------------------------------------------------------------
	if *listChecks {
		fmt.Println("Available checks:")
		for _, c := range checks.All() {
			fmt.Printf("  %-16s\n", c.ID())
		}
		os.Exit(0)
	}

	// -------------------------------------------------------------------------
	// Resolve which checks to run
	// -------------------------------------------------------------------------
	// Parse the comma-separated --checks value into individual IDs.
	// Empty string means "run all" — ByID() handles this case.
	var ids []string
	if *checksFlag != "" {
		for _, id := range strings.Split(*checksFlag, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				ids = append(ids, id)
			}
		}
	}

	selected := checks.ByID(ids)
	if len(selected) == 0 {
		// ByID returns nil only when IDs were specified but none matched.
		fmt.Fprintln(os.Stderr, "error: no matching checks found for --checks value")
		fmt.Fprintln(os.Stderr, "Run with --list to see available check IDs.")
		os.Exit(1)
	}

	// -------------------------------------------------------------------------
	// Resolve output format
	// -------------------------------------------------------------------------
	// "auto" defers the decision to runtime: TTY → tui, pipe/file → plain.
	format := *outputFlag
	if format == "auto" {
		if isTTY() {
			format = "tui"
		} else {
			format = "plain"
		}
	}

	switch format {
	case "tui":
		runTUI(selected)
	case "plain":
		// color=true unless --no-color was passed.
		runPlain(selected, !*noColor)
	case "json":
		runJSON(selected)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown output format %q (use: tui, plain, json)\n", format)
		os.Exit(1)
	}
}

// isTTY reports whether stdout is connected to an interactive terminal.
// It uses the TIOCGETA ioctl to probe the file descriptor rather than
// checking environment variables, which can be spoofed.
//
// If stdout is a pipe, a regular file, or a network socket, this returns false
// and the "auto" output mode falls back to plain text.
func isTTY() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	return err == nil
}

// runTUI launches the interactive Bubbletea program in alt-screen mode.
// Alt-screen keeps the terminal contents intact after the program exits —
// the original shell session is restored when the user presses q.
func runTUI(selected []checks.Check) {
	m := tui.New(selected)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}

// runPlain executes all checks sequentially and prints a human-readable text
// report to stdout. Each check prints one result line plus its description.
// A summary table is appended at the end.
//
// color controls whether ANSI escape codes are included. Pass false when the
// output will be captured to a file or processed by another tool.
func runPlain(selected []checks.Check, color bool) {
	fmt.Println("=== SYSTEM SECURITY AUDIT ===")
	fmt.Println()

	results := make([]checks.Task, len(selected))
	for i, c := range selected {
		t := c.Run()
		results[i] = t

		// Format: [PASS] CheckName    result message
		badge := fmt.Sprintf("[%-4s]", t.Status)
		line := fmt.Sprintf("%-8s %-16s %s", badge, t.Name, t.Message)
		if color {
			line = colorize(t.Status, line)
		}
		fmt.Println(line)

		// Description on the next line, indented.
		fmt.Printf("         %s\n", t.Description)
		fmt.Println()
	}

	// ---- Summary table ----
	counts := map[string]int{}
	for _, t := range results {
		counts[t.Status]++
	}
	fmt.Println("--- Summary ---")
	// Print statuses in severity order; skip zero counts.
	for _, s := range []string{
		checks.StatusPass,
		checks.StatusWarn,
		checks.StatusFail,
		checks.StatusCritical,
		checks.StatusSkipped,
	} {
		if n := counts[s]; n > 0 {
			line := fmt.Sprintf("  %-8s %d", s, n)
			if color {
				line = colorize(s, line)
			}
			fmt.Println(line)
		}
	}
}

// runJSON executes all checks and writes a complete JSON report to stdout.
//
// The report is a single JSON object with a metadata envelope. Schema:
//
//	{
//	  "generated_at": "<RFC3339 timestamp>",
//	  "hostname":     "<system hostname>",
//	  "os":           "<distro name and version>",
//	  "kernel":       "<uname -r output>",
//	  "checks_run":   <int>,
//	  "summary": { "PASS": <int>, "WARN": <int>, "FAIL": <int>, "CRIT": <int>, "SKIP": <int> },
//	  "results": [
//	    {
//	      "id":          "<check id>",
//	      "name":        "<display name>",
//	      "description": "<one-line description>",
//	      "status":      "PASS|WARN|FAIL|CRIT|SKIP",
//	      "message":     "<one-line result summary>",
//	      "details":     "<condensed multi-line findings and remediation>"
//	    }
//	  ]
//	}
func runJSON(selected []checks.Check) {
	// jsonResult is the per-check output structure.
	// Details is a plain string — condensed findings and fix hints only,
	// with section headers and decorative whitespace stripped out.
	type jsonResult struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
		Message     string `json:"message"`
		Details     string `json:"details"`
	}

	type jsonSummary struct {
		Pass     int `json:"PASS"`
		Warn     int `json:"WARN"`
		Fail     int `json:"FAIL"`
		Critical int `json:"CRIT"`
		Skipped  int `json:"SKIP"`
	}

	type jsonReport struct {
		GeneratedAt time.Time    `json:"generated_at"`
		Hostname    string       `json:"hostname"`
		OS          string       `json:"os"`
		Kernel      string       `json:"kernel"`
		ChecksRun   int          `json:"checks_run"`
		Summary     jsonSummary  `json:"summary"`
		Results     []jsonResult `json:"results"`
	}

	hostname, _ := os.Hostname()
	kernel := strings.TrimSpace(runCommand("uname", "-r"))
	osName := readOSName()

	results := make([]jsonResult, len(selected))
	summary := jsonSummary{}

	for i, c := range selected {
		t := c.Run()

		results[i] = jsonResult{
			ID:          t.ID,
			Name:        t.Name,
			Description: t.Description,
			Status:      t.Status,
			Message:     t.Message,
			Details:     t.JSONDetails,
		}

		switch t.Status {
		case checks.StatusPass:
			summary.Pass++
		case checks.StatusWarn:
			summary.Warn++
		case checks.StatusFail:
			summary.Fail++
		case checks.StatusCritical:
			summary.Critical++
		case checks.StatusSkipped:
			summary.Skipped++
		}
	}

	report := jsonReport{
		GeneratedAt: time.Now(),
		Hostname:    hostname,
		OS:          osName,
		Kernel:      kernel,
		ChecksRun:   len(selected),
		Summary:     summary,
		Results:     results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "json encode error: %v\n", err)
		os.Exit(1)
	}
}

// runCommand executes a binary with the given arguments and returns its
// combined stdout output as a string. Returns an empty string on error.
// Used for lightweight metadata collection (uname, etc.) only.
func runCommand(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// readOSName reads the PRETTY_NAME field from /etc/os-release to get a
// human-readable OS description (e.g. "Ubuntu 24.04.4 LTS").
// Falls back to /etc/issue, then to a generic "Linux" label.
func readOSName() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				val := strings.TrimPrefix(line, "PRETTY_NAME=")
				return strings.Trim(val, `"`)
			}
		}
	}
	if data, err := os.ReadFile("/etc/issue"); err == nil {
		line := strings.TrimSpace(strings.Split(string(data), "\n")[0])
		// /etc/issue often contains escape sequences like \n \l — strip them.
		line = strings.ReplaceAll(line, `\n`, "")
		line = strings.ReplaceAll(line, `\l`, "")
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return "Linux"
}

// colorize wraps text in ANSI SGR escape codes matching the given status.
// The reset sequence (\033[0m) is always appended to avoid colour bleed.
// This function is only called when color=true in runPlain().
func colorize(status, text string) string {
	// ANSI colour codes per status.
	// These intentionally mirror the Lipgloss styles in tui/styles.go.
	codes := map[string]string{
		checks.StatusPass:     "\033[32m",   // green
		checks.StatusWarn:     "\033[33m",   // orange/yellow
		checks.StatusFail:     "\033[1;31m", // bold red
		checks.StatusCritical: "\033[1;35m", // bold magenta
		checks.StatusSkipped:  "\033[90m",   // dark grey
	}
	const reset = "\033[0m"
	if code, ok := codes[status]; ok {
		return code + text + reset
	}
	return text
}
