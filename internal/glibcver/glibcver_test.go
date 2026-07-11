package glibcver

import "testing"

func TestOrdinalOrdersCorrectly(t *testing.T) {
	// The classic float-parse bug: "2.5" as a float (2.5) > "2.19" (2.19),
	// but glibc 2.5 predates 2.19. Ordinal must get this the right way round.
	o5, ok := Ordinal("2.5")
	if !ok {
		t.Fatal("expected 2.5 to parse")
	}
	o19, ok := Ordinal("2.19-0ubuntu1")
	if !ok {
		t.Fatal("expected 2.19-0ubuntu1 to parse")
	}
	if o5 >= o19 {
		t.Errorf("Ordinal(2.5)=%d should be < Ordinal(2.19-...)=%d", o5, o19)
	}
}

func TestOrdinalUnparseable(t *testing.T) {
	if _, ok := Ordinal("not-a-version"); ok {
		t.Error("expected unparseable version to return ok=false")
	}
	if _, ok := Ordinal("2"); ok {
		t.Error("expected a version with no minor component to return ok=false")
	}
}

func TestOrdinalStripsGlibcPrefixAndSuffix(t *testing.T) {
	a, ok := Ordinal("glibc-2.31")
	if !ok {
		t.Fatal("expected glibc-2.31 to parse")
	}
	b, ok := Ordinal("2.31-0ubuntu9.9")
	if !ok {
		t.Fatal("expected 2.31-0ubuntu9.9 to parse")
	}
	if a != b {
		t.Errorf("expected matching ordinals, got %d vs %d", a, b)
	}
}
