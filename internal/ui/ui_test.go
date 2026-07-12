package ui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestColorDisabledProducesPlainText(t *testing.T) {
	prev := ColorEnabled()
	defer SetColorEnabled(prev)

	SetColorEnabled(false)
	got := Success("downloaded %s", "glibc 2.35")
	if strings.Contains(got, "\033[") {
		t.Errorf("expected no ANSI escapes with color disabled, got %q", got)
	}
	if got != "[+] downloaded glibc 2.35" {
		t.Errorf("got %q", got)
	}
}

func TestColorEnabledWrapsOnlyTheSymbol(t *testing.T) {
	prev := ColorEnabled()
	defer SetColorEnabled(prev)

	SetColorEnabled(true)
	got := Error("no match found")
	if !strings.Contains(got, "\033[31m[-]\033[0m") {
		t.Errorf("expected the [-] symbol wrapped in red, got %q", got)
	}
	if !strings.HasSuffix(got, "no match found") {
		t.Errorf("expected the message body to remain plain, got %q", got)
	}
}

func TestAllSeveritiesKeepTheirPlainTextSymbol(t *testing.T) {
	prev := ColorEnabled()
	defer SetColorEnabled(prev)
	SetColorEnabled(false)

	cases := map[string]string{
		Success("x"): "[+]",
		Info("x"):    "[i]",
		Step("x"):    "[*]",
		Action("x"):  "[>]",
		Warn("x"):    "[!]",
		Error("x"):   "[-]",
	}
	for msg, wantPrefix := range cases {
		if !strings.HasPrefix(msg, wantPrefix) {
			t.Errorf("expected %q to start with %q", msg, wantPrefix)
		}
	}
}

func TestIsInteractiveFalseForBuffer(t *testing.T) {
	var buf bytes.Buffer
	if IsInteractive(&buf) {
		t.Error("a bytes.Buffer has no Fd(); expected IsInteractive to be false")
	}
}

func TestInCIRespectsCIEnvVar(t *testing.T) {
	orig, had := os.LookupEnv("CI")
	defer func() {
		if had {
			os.Setenv("CI", orig)
		} else {
			os.Unsetenv("CI")
		}
	}()

	os.Setenv("CI", "true")
	if !InCI() {
		t.Error("expected InCI() true when CI=true")
	}
	os.Setenv("CI", "")
	if InCI() {
		t.Error("expected InCI() false when CI is empty")
	}
	os.Unsetenv("CI")
	if InCI() {
		t.Error("expected InCI() false when CI is unset")
	}
}

func TestShouldShowBannerSuppressedByJSONAndNoBanner(t *testing.T) {
	var buf bytes.Buffer // never a terminal, but that's not what we're isolating here
	if ShouldShowBanner(&buf, BannerOptions{JSON: true}) {
		t.Error("--json should always suppress the banner")
	}
	if ShouldShowBanner(&buf, BannerOptions{NoBanner: true}) {
		t.Error("--no-banner should always suppress the banner")
	}
}

func TestShouldShowBannerSuppressedWhenNotInteractive(t *testing.T) {
	var buf bytes.Buffer
	if ShouldShowBanner(&buf, BannerOptions{}) {
		t.Error("a non-terminal writer should never show the banner")
	}
}

func TestShouldShowBannerSuppressedInCI(t *testing.T) {
	orig, had := os.LookupEnv("CI")
	defer func() {
		if had {
			os.Setenv("CI", orig)
		} else {
			os.Unsetenv("CI")
		}
	}()
	os.Setenv("CI", "true")

	var buf bytes.Buffer
	if ShouldShowBanner(&buf, BannerOptions{}) {
		t.Error("CI=true should suppress the banner even if other checks would pass")
	}
}

func TestBannerFallsBackToFullWhenWidthUnknown(t *testing.T) {
	var buf bytes.Buffer // no Fd(): width can't be determined
	got := Banner(&buf)
	if got != fullBanner {
		t.Error("expected the full banner when terminal width can't be determined")
	}
}

func TestProgressInertWhenNotInteractive(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "downloading", 100)
	p.Update(50)
	p.Finish()
	if buf.Len() != 0 {
		t.Errorf("expected no output from a non-interactive Progress, got %q", buf.String())
	}
}

func TestProgressInertWhenTotalUnknown(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "downloading", 0)
	p.Update(50)
	if buf.Len() != 0 {
		t.Errorf("expected no output when total is unknown, got %q", buf.String())
	}
}

func TestBoxAlignsLabels(t *testing.T) {
	got := Box("glibc identification", [][2]string{
		{"File", "libc.so.6"},
		{"BuildID", "deadbeef"},
	}, "Match confirmed")

	lines := strings.Split(got, "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d: %q", len(lines), got)
	}
	if lines[0] != "╭─ glibc identification" {
		t.Errorf("got title line %q", lines[0])
	}
	if lines[1] != "│ File    libc.so.6" {
		t.Errorf("got row 1 %q", lines[1])
	}
	if lines[2] != "│ BuildID deadbeef" {
		t.Errorf("got row 2 %q", lines[2])
	}
	if lines[3] != "╰─ Match confirmed" {
		t.Errorf("got footer %q", lines[3])
	}
}

func TestBoxEmptyRows(t *testing.T) {
	got := Box("title", nil, "footer")
	if got != "╭─ title\n╰─ footer" {
		t.Errorf("got %q", got)
	}
}
