// Package ui centralizes pwnlibc's terminal output formatting: ANSI colors,
// the [+]/[i]/[*]/[!]/[-]/[>] status symbols, and the TTY/NO_COLOR/CI
// detection that decides whether any of that decoration is safe to emit.
//
// Formatting is deliberately separate from command logic: every subcommand
// builds its human-readable strings by calling the functions here rather
// than embedding ANSI codes or color logic itself, so "does this respect
// --no-color/--json/CI" only has to be gotten right once.
package ui

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ANSI SGR codes. Only a fixed, small palette is used project-wide (see
// README "Terminal Colours"): green/blue/yellow/red for the five status
// symbols, cyan for inline paths/versions/BuildIDs, dim for secondary text.
const (
	codeReset  = "\033[0m"
	codeGreen  = "\033[32m"
	codeBlue   = "\033[34m"
	codeYellow = "\033[33m"
	codeRed    = "\033[31m"
	codeCyan   = "\033[36m"
	codeDim    = "\033[2m"
)

var colorEnabled = detectColorDefault()

// detectColorDefault applies the standard precedence: NO_COLOR always wins
// over everything else (https://no-color.org), then fall back to whether
// stdout is actually a terminal -- redirected/piped output and CI log
// capture should never contain raw escape codes.
func detectColorDefault() bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// SetColorEnabled lets the CLI's --no-color flag (or an explicit --color)
// override the auto-detected default. Call this once, early, from the root
// command's flag parsing.
func SetColorEnabled(v bool) { colorEnabled = v }

// ColorEnabled reports the current effective setting.
func ColorEnabled() bool { return colorEnabled }

func colorize(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + codeReset
}

// Cyan highlights an inline value -- paths, versions, BuildIDs -- within an
// otherwise plain message.
func Cyan(s string) string { return colorize(codeCyan, s) }

// Dim de-emphasizes secondary/supplementary detail.
func Dim(s string) string { return colorize(codeDim, s) }

// The five status-line builders below always prefix with a plain-ASCII
// bracketed symbol (readable with color disabled) and color only the
// symbol itself, never the whole line -- so meaning survives NO_COLOR and
// low-contrast themes alike.
func Success(format string, a ...interface{}) string {
	return colorize(codeGreen, "[+]") + " " + fmt.Sprintf(format, a...)
}

func Info(format string, a ...interface{}) string {
	return colorize(codeBlue, "[i]") + " " + fmt.Sprintf(format, a...)
}

func Step(format string, a ...interface{}) string {
	return colorize(codeBlue, "[*]") + " " + fmt.Sprintf(format, a...)
}

func Action(format string, a ...interface{}) string {
	return colorize(codeCyan, "[>]") + " " + fmt.Sprintf(format, a...)
}

func Warn(format string, a ...interface{}) string {
	return colorize(codeYellow, "[!]") + " " + fmt.Sprintf(format, a...)
}

func Error(format string, a ...interface{}) string {
	return colorize(codeRed, "[-]") + " " + fmt.Sprintf(format, a...)
}

// Fprintln* are thin convenience wrappers so callers don't need a separate
// fmt import purely to print one status line.
func FprintSuccess(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintln(w, Success(format, a...))
}
func FprintInfo(w io.Writer, format string, a ...interface{}) { fmt.Fprintln(w, Info(format, a...)) }
func FprintStep(w io.Writer, format string, a ...interface{}) { fmt.Fprintln(w, Step(format, a...)) }
func FprintAction(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintln(w, Action(format, a...))
}
func FprintWarn(w io.Writer, format string, a ...interface{})  { fmt.Fprintln(w, Warn(format, a...)) }
func FprintError(w io.Writer, format string, a ...interface{}) { fmt.Fprintln(w, Error(format, a...)) }

// IsInteractive reports whether w is connected to a terminal. Used to gate
// the banner and progress bars -- anything that would corrupt redirected
// output, JSON, or CI logs.
func IsInteractive(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// InCI reports whether pwnlibc appears to be running inside a CI system.
// GitHub Actions, GitLab CI, Travis, CircleCI, and most others all set the
// generic CI=true convention; this deliberately doesn't try to enumerate
// every vendor-specific variable beyond that.
func InCI() bool {
	v, set := os.LookupEnv("CI")
	return set && v != "" && v != "0" && v != "false"
}
