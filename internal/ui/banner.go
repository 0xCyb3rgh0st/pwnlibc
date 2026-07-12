package ui

import (
	"fmt"
	"io"

	"golang.org/x/term"
)

// fullBanner is pure ASCII (no box-drawing or other Unicode) specifically
// so it renders identically in Linux/macOS terminals, WSL2, Docker
// terminals, Windows Terminal, and GitHub Actions log viewers -- none of
// which can be assumed to share a Unicode-aware monospace font.
const fullBanner = `                                  __  _ __
    ____ _      ______  / /_(_) /_  _____
   / __ \ | /| / / __ \/ __/ / __ \/ ___/
  / /_/ / |/ |/ / / / / /_/ / /_/ / /__
 / .___/|__/|__/_/ /_/\__/_/_.___/\___/
/_/

  glibc management for CTF and binary exploitation`

// compactBanner is the narrow-terminal fallback. Kept pure ASCII (+/-/|)
// rather than Unicode box-drawing for the same cross-environment
// compatibility reason as fullBanner.
const compactBanner = `+----------------------------------------+
|                pwnlibc                  |
|  glibc toolkit for CTF and pwn work     |
+----------------------------------------+`

// fullBannerWidth is the widest line in fullBanner; below this terminal
// width the compact banner is used instead so it doesn't wrap.
const fullBannerWidth = 60

// Banner returns the banner text sized for the given writer's terminal
// width (falling back to the full banner if width can't be determined,
// e.g. because it isn't a terminal at all -- callers gate that separately
// via ShouldShowBanner).
func Banner(w io.Writer) string {
	if f, ok := w.(interface{ Fd() uintptr }); ok {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 0 && width < fullBannerWidth {
			return compactBanner
		}
	}
	return fullBanner
}

// BannerOptions controls whether ShouldShowBanner allows the banner.
type BannerOptions struct {
	JSON     bool // --json was set
	NoBanner bool // --no-banner was set
}

// ShouldShowBanner implements the suppression rules: never for --json or
// --no-banner, never in CI, never when stdout isn't an interactive
// terminal (covers redirected output and piped/scripted invocations).
func ShouldShowBanner(w io.Writer, opts BannerOptions) bool {
	if opts.JSON || opts.NoBanner || InCI() {
		return false
	}
	return IsInteractive(w)
}

// PrintBanner writes the appropriately-sized banner to w followed by a
// blank line, with no suppression logic -- used by the explicit `banner`
// subcommand, which should always show something when asked directly.
func PrintBanner(w io.Writer) {
	_, _ = fmt.Fprintln(w, Banner(w))
	_, _ = fmt.Fprintln(w)
}
