package vulndb

import "testing"

func TestAllLoadsEmbeddedData(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("expected embedded vulns.json to contain entries")
	}
}

func TestAffectedByKnownRange(t *testing.T) {
	// GHOST (CVE-2015-0235) is curated as affecting 2.2 <= v < 2.17.
	entries := AffectedBy("2.15-0ubuntu10")
	found := false
	for _, e := range entries {
		if e.ID == "CVE-2015-0235" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2015-0235 to affect 2.15, got %+v", entries)
	}
}

func TestAffectedByOutOfRange(t *testing.T) {
	entries := AffectedBy("2.15-0ubuntu10")
	for _, e := range entries {
		if e.ID == "CVE-2023-4911" {
			t.Errorf("CVE-2023-4911 (Looney Tunables, >=2.34) should not affect 2.15")
		}
	}
}

func TestAffectedByUnparseableVersion(t *testing.T) {
	if entries := AffectedBy("not-a-version"); entries != nil {
		t.Errorf("expected nil for unparseable version, got %+v", entries)
	}
}
