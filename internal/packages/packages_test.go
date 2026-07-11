package packages

import "testing"

const samplePoolListing = `<html><body>
<a href="libc6_2.31-0ubuntu9.9_amd64.deb">libc6_2.31-0ubuntu9.9_amd64.deb</a> 01-Jan-2024 12:00 3.5M
<a href="libc6-dbg_2.31-0ubuntu9.9_amd64.deb">libc6-dbg_2.31-0ubuntu9.9_amd64.deb</a> 01-Jan-2024 12:00 3.5M
<a href="libc6_2.31-0ubuntu9.9_i386.deb">libc6_2.31-0ubuntu9.9_i386.deb</a> 01-Jan-2024 12:00 3.2M
<a href="libc6-dev_2.31-0ubuntu9.9_amd64.deb">libc6-dev_2.31-0ubuntu9.9_amd64.deb</a> 01-Jan-2024 12:00 1.1M
<a href="../">../</a>
</body></html>`

func TestParsePoolListing(t *testing.T) {
	pkgs := ParsePoolListing([]byte(samplePoolListing), "tuna", false)
	if len(pkgs) != 4 {
		t.Fatalf("got %d packages, want 4: %+v", len(pkgs), pkgs)
	}
	var main *Package
	for i := range pkgs {
		if pkgs[i].Name == "libc6" && pkgs[i].Arch == "amd64" {
			main = &pkgs[i]
		}
	}
	if main == nil {
		t.Fatal("expected to find libc6 amd64 package")
	}
	if main.Version != "2.31-0ubuntu9.9" {
		t.Errorf("got version %q, want %q", main.Version, "2.31-0ubuntu9.9")
	}
	if main.VersionArch() != "2.31-0ubuntu9.9_amd64" {
		t.Errorf("got VersionArch %q", main.VersionArch())
	}
}

func TestMergeDedupesAcrossMirrors(t *testing.T) {
	a := ParsePoolListing([]byte(samplePoolListing), "tuna", false)
	b := ParsePoolListing([]byte(samplePoolListing), "ustc", false)
	merged := Merge(a, b)
	if len(merged) != 4 {
		t.Fatalf("got %d merged packages, want 4", len(merged))
	}
	for _, p := range merged {
		if len(p.Mirrors) != 2 {
			t.Errorf("package %q: got mirrors %v, want 2 entries", p.Filename, p.Mirrors)
		}
	}
}

func TestFindVersionArch(t *testing.T) {
	list := &List{Packages: ParsePoolListing([]byte(samplePoolListing), "tuna", false)}

	main, dbg, err := list.FindVersionArch("2.31-0ubuntu9.9_amd64", true)
	if err != nil {
		t.Fatalf("FindVersionArch: %v", err)
	}
	if main.Filename != "libc6_2.31-0ubuntu9.9_amd64.deb" {
		t.Errorf("got main %q", main.Filename)
	}
	if dbg == nil || dbg.Filename != "libc6-dbg_2.31-0ubuntu9.9_amd64.deb" {
		t.Errorf("got dbg %+v", dbg)
	}

	if _, _, err := list.FindVersionArch("9.99-nonexistent_amd64", false); err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestSearchByVersionPrefix(t *testing.T) {
	list := &List{Packages: ParsePoolListing([]byte(samplePoolListing), "tuna", false)}
	results := list.SearchByVersionPrefix("2.31")
	if len(results) != 2 { // amd64 + i386 libc6 entries, libc6-dev excluded by Name filter
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}
	if len(list.SearchByVersionPrefix("9.99")) != 0 {
		t.Fatal("expected no matches for a version that doesn't exist")
	}
}
