// Package diffcmd compares two ELF files (typically two glibc versions):
// symbol additions/removals/offset-changes and security-attribute
// transitions, computed natively via debug/elf.
package diffcmd

import (
	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
)

// SymbolDelta describes one symbol's change between file A and file B.
type SymbolDelta struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"` // "added", "removed", "moved"
	ValueA *uint64 `json:"value_a,omitempty"`
	ValueB *uint64 `json:"value_b,omitempty"`
}

// SecurityDelta describes one hardening attribute's change.
type SecurityDelta struct {
	Attribute string `json:"attribute"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

// Result is the full diff between two files.
type Result struct {
	PathA          string          `json:"path_a"`
	PathB          string          `json:"path_b"`
	SymbolsAdded   []SymbolDelta   `json:"symbols_added"`
	SymbolsRemoved []SymbolDelta   `json:"symbols_removed"`
	SymbolsMoved   []SymbolDelta   `json:"symbols_moved"`
	Security       []SecurityDelta `json:"security_changes"`
}

// Diff computes the full delta between two loaded ELF profiles.
func Diff(pathA string, infoA *elfinfo.Info, symsA []elfinfo.Symbol, pathB string, infoB *elfinfo.Info, symsB []elfinfo.Symbol) *Result {
	res := &Result{PathA: pathA, PathB: pathB}

	byNameA := map[string]elfinfo.Symbol{}
	for _, s := range symsA {
		byNameA[s.Name] = s
	}
	byNameB := map[string]elfinfo.Symbol{}
	for _, s := range symsB {
		byNameB[s.Name] = s
	}

	for name, sb := range byNameB {
		sa, ok := byNameA[name]
		if !ok {
			v := sb.Value
			res.SymbolsAdded = append(res.SymbolsAdded, SymbolDelta{Name: name, Kind: "added", ValueB: &v})
			continue
		}
		if sa.Value != sb.Value {
			va, vb := sa.Value, sb.Value
			res.SymbolsMoved = append(res.SymbolsMoved, SymbolDelta{Name: name, Kind: "moved", ValueA: &va, ValueB: &vb})
		}
	}
	for name, sa := range byNameA {
		if _, ok := byNameB[name]; !ok {
			v := sa.Value
			res.SymbolsRemoved = append(res.SymbolsRemoved, SymbolDelta{Name: name, Kind: "removed", ValueA: &v})
		}
	}

	res.Security = diffSecurity(infoA.Security, infoB.Security)
	return res
}

func diffSecurity(a, b elfinfo.Security) []SecurityDelta {
	var out []SecurityDelta
	add := func(attr, before, after string) {
		if before != after {
			out = append(out, SecurityDelta{Attribute: attr, Before: before, After: after})
		}
	}
	add("RELRO", a.RELRO, b.RELRO)
	add("NX", boolStr(a.NX), boolStr(b.NX))
	add("Canary", boolStr(a.Canary), boolStr(b.Canary))
	add("PIE", boolStr(a.PIE), boolStr(b.PIE))
	add("RUNPATH", a.RunPath, b.RunPath)
	add("RPATH", a.RPath, b.RPath)
	add("Stripped", boolStr(a.Stripped), boolStr(b.Stripped))
	return out
}

func boolStr(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
