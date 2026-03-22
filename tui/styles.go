// Package tui implements the interactive terminal user interface for sec-audit
// using the Charmbracelet Bubbletea framework (Elm-like architecture).
//
// Files in this package:
//
//	styles.go — all Lipgloss style definitions (colors, borders, padding)
//	model.go  — Bubbletea Model struct, Init, Update (state machine)
//	view.go   — View function and rendering helpers (pure string output)
package tui

import "github.com/charmbracelet/lipgloss"

// --- Title & Header ---

// titleStyle renders the top banner. Slate-purple background with cream text.
var titleStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("62")).
	Foreground(lipgloss.Color("230")).
	Padding(0, 2).
	Bold(true)

// summaryStyle renders the aggregate status line (e.g. "3 PASS  1 WARN  2 FAIL").
var summaryStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("244")).
	PaddingLeft(1)

// --- Status badge styles (applied to the [OK]/[!!]/[WRN] badges and messages) ---

// passStyle: green — check found no issues.
var passStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("42"))

// failStyle: bright red bold — check found a concrete security misconfiguration.
var failStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("196")).
	Bold(true)

// warnStyle: orange — check found a suboptimal but not immediately critical config.
var warnStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("214"))

// critStyle: magenta bold — reserved for actively dangerous conditions.
var critStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("201")).
	Bold(true)

// skipStyle: grey — check was not able to run (e.g. missing file, no privileges).
var skipStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("244"))

// runningStyle: blue — check is currently executing (transient TUI state).
var runningStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("33"))

// --- Row content styles ---

// descStyle: mid-grey — secondary text (description subtitles, footer hint).
var descStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("244"))

// cursorStyle: cream bold — the ▶ cursor indicating the selected row.
// NOTE: cursor rendering is handled by the viewport; this style is kept for
// potential future use (e.g. cursor-based selection mode).
var cursorStyle = lipgloss.NewStyle(). //nolint:unused
					Foreground(lipgloss.Color("230")).
					Bold(true)

// detailStyle: soft blue — expanded detail lines shown below a selected row.
var detailStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("111"))

// --- Footer & overlays ---

// helpStyle: dark grey — footer key-hint line and help overlay body text.
var helpStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("240"))

// helpBoxStyle: rounded border in the title purple — wraps the help overlay.
var helpBoxStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.Color("62")).
	Padding(1, 2)

// --- Summary bar count styles ---
// Each status count in the summary bar uses its own styled variant so they
// are visually distinct at a glance.

var summaryCountPass = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
var summaryCountWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
var summaryCountFail = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
var summaryCountCrit = lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Bold(true)
var summaryCountSkip = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
