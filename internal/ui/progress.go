package ui

import (
	"fmt"
	"io"
)

const barWidth = 30

// Progress renders a single-line, carriage-return-updated progress bar.
// It always writes to the writer given at construction (callers should
// pass os.Stderr, following curl/wget/pip convention, so stdout stays
// clean for piping and --json never gets progress bytes mixed in) and is a
// complete no-op unless that writer is an interactive terminal -- so it
// never spams CI logs, redirected files, or scripts with hundreds of
// percentage lines. Deliberately uses only "\r" (near-universally
// supported) rather than cursor-movement escapes, so it degrades safely
// even on terminals with partial ANSI support.
type Progress struct {
	w      io.Writer
	label  string
	total  int64
	active bool
}

// NewProgress starts tracking a total-byte operation. If w isn't an
// interactive terminal or total is unknown (<=0), the returned Progress is
// inert: Update/Finish become no-ops.
func NewProgress(w io.Writer, label string, total int64) *Progress {
	return &Progress{w: w, label: label, total: total, active: total > 0 && IsInteractive(w)}
}

// Update redraws the bar in place for n bytes transferred so far.
func (p *Progress) Update(n int64) {
	if !p.active {
		return
	}
	frac := float64(n) / float64(p.total)
	if frac > 1 {
		frac = 1
	}
	filled := int(frac * barWidth)
	bar := make([]byte, barWidth)
	for i := range bar {
		if i < filled {
			bar[i] = '#'
		} else {
			bar[i] = '-'
		}
	}
	fmt.Fprintf(p.w, "\r%s [%s] %3.0f%%", p.label, bar, frac*100)
}

// Finish clears the progress line so the caller's subsequent [+]/[-]
// status line prints cleanly instead of appending after the bar.
func (p *Progress) Finish() {
	if !p.active {
		return
	}
	fmt.Fprint(p.w, "\r\033[K")
}
