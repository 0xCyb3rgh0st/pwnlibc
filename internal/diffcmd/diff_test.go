package diffcmd

import (
	"testing"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
)

func TestDiffSymbols(t *testing.T) {
	symsA := []elfinfo.Symbol{
		{Name: "system", Value: 0x100},
		{Name: "removed_fn", Value: 0x200},
		{Name: "moved_fn", Value: 0x300},
	}
	symsB := []elfinfo.Symbol{
		{Name: "system", Value: 0x100},
		{Name: "moved_fn", Value: 0x999},
		{Name: "added_fn", Value: 0x400},
	}
	infoA := &elfinfo.Info{Security: elfinfo.Security{RELRO: "partial", NX: true}}
	infoB := &elfinfo.Info{Security: elfinfo.Security{RELRO: "full", NX: true}}

	result := Diff("a", infoA, symsA, "b", infoB, symsB)

	if len(result.SymbolsAdded) != 1 || result.SymbolsAdded[0].Name != "added_fn" {
		t.Errorf("SymbolsAdded = %+v", result.SymbolsAdded)
	}
	if len(result.SymbolsRemoved) != 1 || result.SymbolsRemoved[0].Name != "removed_fn" {
		t.Errorf("SymbolsRemoved = %+v", result.SymbolsRemoved)
	}
	if len(result.SymbolsMoved) != 1 || result.SymbolsMoved[0].Name != "moved_fn" {
		t.Errorf("SymbolsMoved = %+v", result.SymbolsMoved)
	}
	if *result.SymbolsMoved[0].ValueA != 0x300 || *result.SymbolsMoved[0].ValueB != 0x999 {
		t.Errorf("moved_fn values = %x -> %x", *result.SymbolsMoved[0].ValueA, *result.SymbolsMoved[0].ValueB)
	}

	foundRelroChange := false
	for _, s := range result.Security {
		if s.Attribute == "RELRO" {
			foundRelroChange = true
			if s.Before != "partial" || s.After != "full" {
				t.Errorf("RELRO change = %s -> %s", s.Before, s.After)
			}
		}
		if s.Attribute == "NX" {
			t.Error("NX did not change between A and B, should not appear in the diff")
		}
	}
	if !foundRelroChange {
		t.Error("expected a RELRO security change to be reported")
	}
}

func TestDiffNoChanges(t *testing.T) {
	syms := []elfinfo.Symbol{{Name: "system", Value: 0x100}}
	info := &elfinfo.Info{Security: elfinfo.Security{RELRO: "full"}}
	result := Diff("a", info, syms, "b", info, syms)
	if len(result.SymbolsAdded)+len(result.SymbolsRemoved)+len(result.SymbolsMoved) != 0 {
		t.Errorf("expected no symbol deltas, got %+v", result)
	}
	if len(result.Security) != 0 {
		t.Errorf("expected no security deltas, got %+v", result.Security)
	}
}
