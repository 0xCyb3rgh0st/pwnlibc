package ui

import (
	"fmt"
	"strings"
)

// Box renders a lightweight labeled summary block, e.g.:
//
//	╭─ glibc identification
//	│ File          libc.so.6
//	│ BuildID       6938...aa3d
//	╰─ Match confirmed
//
// Unlike the banner, this uses light Unicode box-drawing characters --
// acceptable here since it's regular command output (not something that
// has to survive being pasted into an arbitrary CI log renderer verbatim
// as ASCII art), and box-drawing has been safe in every terminal this
// project targets (Linux/macOS/WSL2/Windows Terminal/GitHub Actions logs)
// for years.
func Box(title string, rows [][2]string, footer string) string {
	maxLabel := 0
	for _, r := range rows {
		if len(r[0]) > maxLabel {
			maxLabel = len(r[0])
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "╭─ %s\n", title)
	for _, r := range rows {
		fmt.Fprintf(&b, "│ %-*s %s\n", maxLabel, r[0], r[1])
	}
	fmt.Fprintf(&b, "╰─ %s", footer)
	return b.String()
}
