// Package elfinfo extracts everything pwnlibc needs from an ELF file using
// only the Go standard library's debug/elf — no shelling out to readelf,
// nm, or pyelftools like the original tool.
package elfinfo

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"pwnlibc/internal/pwnerr"
)

// Symbol is one exported/dynamic symbol with its value (offset from the
// module base for a PIE/shared object).
type Symbol struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Size  uint64 `json:"size"`
}

// Security bundles the classic checksec-style hardening flags.
type Security struct {
	RELRO       string `json:"relro"` // "none", "partial", "full"
	NX          bool   `json:"nx"`
	Canary      bool   `json:"canary"`
	PIE         bool   `json:"pie"`
	RPath       string `json:"rpath,omitempty"`
	RunPath     string `json:"runpath,omitempty"`
	Stripped    bool   `json:"stripped"`
	Interpreter string `json:"interpreter,omitempty"`
}

// Info is the full extracted profile of one ELF file.
type Info struct {
	Path     string   `json:"path"`
	Arch     string   `json:"arch"`
	Type     string   `json:"type"`
	BuildID  string   `json:"build_id,omitempty"`
	Security Security `json:"security"`
	Symbols  []Symbol `json:"-"` // omitted from default JSON; large, exposed via search/diff
}

// Load parses path and extracts BuildID + security attributes. Symbols are
// loaded separately via Symbols()/DynamicSymbols() since callers rarely
// need every symbol dumped to JSON.
func Load(path string) (*Info, *elf.File, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, pwnerr.Wrap(pwnerr.CodeNotELF, fmt.Sprintf("not a valid ELF file: %s", path), err)
	}

	info := &Info{
		Path: path,
		Arch: f.Machine.String(),
		Type: f.Type.String(),
	}
	info.BuildID = buildID(f)
	info.Security = security(f)
	return info, f, nil
}

func buildID(f *elf.File) string {
	for _, sec := range f.Sections {
		if sec.Name != ".note.gnu.build-id" {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		if id, ok := parseBuildIDNote(data); ok {
			return id
		}
	}
	// Fall back to PT_NOTE program headers (stripped section headers still
	// leave PT_NOTE segments intact in most real-world glibc builds).
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_NOTE {
			continue
		}
		data := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(data, 0); err != nil {
			continue
		}
		if id, ok := parseBuildIDNote(data); ok {
			return id
		}
	}
	return ""
}

// parseBuildIDNote walks ELF notes looking for NT_GNU_BUILD_ID (type 3)
// under owner "GNU".
func parseBuildIDNote(data []byte) (string, bool) {
	for len(data) >= 12 {
		nameSz := u32(data[0:4])
		descSz := u32(data[4:8])
		noteType := u32(data[8:12])
		off := 12
		nameEnd := off + int(align4(nameSz))
		if nameEnd > len(data) {
			return "", false
		}
		name := strings.TrimRight(string(data[off:off+int(nameSz)]), "\x00")
		off = nameEnd
		descEnd := off + int(align4(descSz))
		if descEnd > len(data) {
			return "", false
		}
		desc := data[off : off+int(descSz)]
		if name == "GNU" && noteType == 3 {
			return hex.EncodeToString(desc), true
		}
		data = data[descEnd:]
	}
	return "", false
}

func align4(n uint32) uint32 {
	return (n + 3) &^ 3
}

func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func security(f *elf.File) Security {
	s := Security{RELRO: "none", NX: false, PIE: f.Type == elf.ET_DYN}

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			s.RELRO = "partial"
		}
		if prog.Type == elf.PT_GNU_STACK {
			s.NX = prog.Flags&elf.PF_X == 0
		}
	}

	if dynTags, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range dynTags {
			if v&uint64(elf.DF_BIND_NOW) != 0 && s.RELRO == "partial" {
				s.RELRO = "full"
			}
		}
	}
	if dynTags, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range dynTags {
			const dfP1Now = 0x1 // DF_1_NOW
			if v&dfP1Now != 0 && s.RELRO == "partial" {
				s.RELRO = "full"
			}
		}
	}

	if syms, err := f.DynamicSymbols(); err == nil {
		for _, sym := range syms {
			if sym.Name == "__stack_chk_fail" {
				s.Canary = true
				break
			}
		}
	}

	if strs, err := f.DynString(elf.DT_RPATH); err == nil && len(strs) > 0 {
		s.RPath = strings.Join(strs, ":")
	}
	if strs, err := f.DynString(elf.DT_RUNPATH); err == nil && len(strs) > 0 {
		s.RunPath = strings.Join(strs, ":")
	}

	symtab, _ := f.Symbols()
	s.Stripped = len(symtab) == 0

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			data := make([]byte, prog.Filesz)
			if _, err := prog.ReadAt(data, 0); err == nil {
				s.Interpreter = strings.TrimRight(string(data), "\x00")
			}
		}
	}

	return s
}

// Symbols returns the dynamic symbol table (what glibc.so exports) plus
// the regular symbol table when present (unstripped builds), deduplicated
// by name with the dynamic-table value winning on conflict.
func Symbols(f *elf.File) []Symbol {
	byName := map[string]Symbol{}
	if dsyms, err := f.DynamicSymbols(); err == nil {
		for _, s := range dsyms {
			if s.Name == "" || s.Value == 0 {
				continue
			}
			byName[s.Name] = Symbol{Name: s.Name, Value: s.Value, Size: s.Size}
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == "" || s.Value == 0 {
				continue
			}
			if _, exists := byName[s.Name]; !exists {
				byName[s.Name] = Symbol{Name: s.Name, Value: s.Value, Size: s.Size}
			}
		}
	}
	out := make([]Symbol, 0, len(byName))
	for _, s := range byName {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MatchGlob reports whether name matches a simple '*'/'?' glob pattern.
func MatchGlob(pattern, name string) bool {
	ok, err := simpleGlobMatch(pattern, name)
	return err == nil && ok
}

// simpleGlobMatch implements '*' and '?' without touching the filesystem
// (path/filepath.Match treats '/' specially, which symbol names don't need,
// but do contain characters like '@' from versioned symbols that are fine
// as literals either way).
func simpleGlobMatch(pattern, name string) (bool, error) {
	return globMatch([]rune(pattern), []rune(name)), nil
}

func globMatch(pattern, name []rune) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	switch pattern[0] {
	case '*':
		if globMatch(pattern[1:], name) {
			return true
		}
		for i := 0; i < len(name); i++ {
			if globMatch(pattern[1:], name[i+1:]) {
				return true
			}
		}
		return false
	case '?':
		if len(name) == 0 {
			return false
		}
		return globMatch(pattern[1:], name[1:])
	default:
		if len(name) == 0 || name[0] != pattern[0] {
			return false
		}
		return globMatch(pattern[1:], name[1:])
	}
}

// StringsInDataSections scans .rodata/.data/.data.rel.ro for occurrences of
// needle (used by `search --libc x --str "/bin/sh"`), returning file
// offsets where it was found.
func StringsInDataSections(f *elf.File, needle string) ([]uint64, error) {
	var offsets []uint64
	nb := []byte(needle)
	for _, name := range []string{".rodata", ".data", ".data.rel.ro"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		start := 0
		for {
			idx := indexBytes(data[start:], nb)
			if idx < 0 {
				break
			}
			offsets = append(offsets, sec.Addr+uint64(start+idx))
			start += idx + 1
		}
	}
	return offsets, nil
}

func indexBytes(haystack, needle []byte) int {
	n, m := len(haystack), len(needle)
	if m == 0 || m > n {
		return -1
	}
	for i := 0; i+m <= n; i++ {
		if string(haystack[i:i+m]) == string(needle) {
			return i
		}
	}
	return -1
}
