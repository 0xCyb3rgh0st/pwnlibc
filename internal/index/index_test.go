package index

import (
	"path/filepath"
	"testing"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
)

func openTestIndex(t *testing.T) *Index {
	t.Helper()
	idx, err := Open(filepath.Join(t.TempDir(), "index.bbolt"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

func TestIndexAndLookupBuildID(t *testing.T) {
	idx := openTestIndex(t)
	syms := []elfinfo.Symbol{{Name: "system", Value: 0x111}}
	if err := idx.IndexVersion("2.31-0ubuntu9.9_amd64", "abc123", syms); err != nil {
		t.Fatalf("IndexVersion: %v", err)
	}

	got, ok := idx.LookupBuildID("abc123")
	if !ok || got != "2.31-0ubuntu9.9_amd64" {
		t.Errorf("LookupBuildID = %q, %v", got, ok)
	}

	if _, ok := idx.LookupBuildID("does-not-exist"); ok {
		t.Error("expected lookup of unknown BuildID to fail")
	}

	gotSyms, err := idx.Symbols("2.31-0ubuntu9.9_amd64")
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	if len(gotSyms) != 1 || gotSyms[0].Name != "system" {
		t.Errorf("got symbols %+v", gotSyms)
	}
}

func TestAllVersionsSorted(t *testing.T) {
	idx := openTestIndex(t)
	_ = idx.IndexVersion("2.35-0ubuntu3_amd64", "b1", nil)
	_ = idx.IndexVersion("2.27-3ubuntu1_amd64", "a1", nil)

	versions, err := idx.AllVersions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].VersionArch != "2.27-3ubuntu1_amd64" {
		t.Errorf("got %+v", versions)
	}
}

func TestIdentifyByFingerprint(t *testing.T) {
	idx := openTestIndex(t)
	_ = idx.IndexVersion("2.31-0ubuntu9.9_amd64", "", []elfinfo.Symbol{
		{Name: "system", Value: 0x100}, {Name: "printf", Value: 0x200},
		{Name: "puts", Value: 0x300}, {Name: "execve", Value: 0x400},
		{Name: "malloc", Value: 0x500}, {Name: "free", Value: 0x600},
	})
	_ = idx.IndexVersion("2.35-0ubuntu3_amd64", "", []elfinfo.Symbol{
		{Name: "system", Value: 0x999}, {Name: "printf", Value: 0x888},
	})

	target := []elfinfo.Symbol{
		{Name: "system", Value: 0x100}, {Name: "printf", Value: 0x200},
		{Name: "puts", Value: 0x300}, {Name: "execve", Value: 0x400},
		{Name: "malloc", Value: 0x500}, {Name: "free", Value: 0x600},
	}
	scores, err := idx.IdentifyByFingerprint(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) == 0 {
		t.Fatal("expected at least one candidate")
	}
	if scores[0].VersionArch != "2.31-0ubuntu9.9_amd64" {
		t.Errorf("expected the exact-matching version to rank first, got %+v", scores)
	}
	if scores[0].Matched != scores[0].Compared {
		t.Errorf("expected a perfect match for the identical fingerprint, got %+v", scores[0])
	}
}
