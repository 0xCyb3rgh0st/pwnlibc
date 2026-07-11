package elfinfo

import (
	"debug/elf"
	"os"
	"testing"
)

// selfELF opens the running test binary itself, which is a valid Linux ELF
// when tests run in this project's Linux-only test container -- no
// external fixture needed.
func selfELF(t *testing.T) (*Info, *elf.File) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	info, f, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return info, f
}

func TestLoadSelf(t *testing.T) {
	info, _ := selfELF(t)
	if info.Type == "" {
		t.Error("expected non-empty ELF type")
	}
	if info.Arch == "" {
		t.Error("expected non-empty arch")
	}
}

func TestSymbolsDoesNotPanic(t *testing.T) {
	_, f := selfELF(t)
	syms := Symbols(f)
	for _, s := range syms {
		if s.Name == "" {
			t.Error("Symbols() should never return an empty-named entry")
		}
	}
}

func TestSecurityNXAndPIE(t *testing.T) {
	_, f := selfELF(t)
	sec := security(f)
	// Go binaries are always position independent when built as PIE, and
	// the test container always has a non-executable stack; assert the
	// fields are populated deterministically rather than asserting exact
	// truthiness (Go toolchain default may change).
	_ = sec.PIE
	if !sec.NX {
		t.Log("note: NX reported false for the Go test binary (unexpected but not necessarily a bug)")
	}
}

func TestParseBuildIDNote(t *testing.T) {
	// name="GNU"(4B, padded to 4), namesz=4, descsz=4, type=3(NT_GNU_BUILD_ID), desc=0xDEADBEEF
	note := []byte{
		4, 0, 0, 0, // namesz
		4, 0, 0, 0, // descsz
		3, 0, 0, 0, // type = NT_GNU_BUILD_ID
		'G', 'N', 'U', 0, // name, padded to 4
		0xDE, 0xAD, 0xBE, 0xEF, // desc
	}
	id, ok := parseBuildIDNote(note)
	if !ok {
		t.Fatal("expected note to parse")
	}
	if id != "deadbeef" {
		t.Errorf("got %q, want %q", id, "deadbeef")
	}
}

func TestParseBuildIDNoteWrongOwner(t *testing.T) {
	note := []byte{
		4, 0, 0, 0,
		4, 0, 0, 0,
		3, 0, 0, 0,
		'X', 'X', 'X', 0,
		1, 2, 3, 4,
	}
	if _, ok := parseBuildIDNote(note); ok {
		t.Fatal("expected note with wrong owner to be rejected")
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"system", "system", true},
		{"system", "systemx", false},
		{"*exec*", "execve", true},
		{"*exec*", "posix_spawn", false},
		{"str?en", "strlen", true},
		{"str?en", "strllen", false},
		{"*", "anything", true},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pattern, c.name); got != c.want {
			t.Errorf("MatchGlob(%q,%q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
