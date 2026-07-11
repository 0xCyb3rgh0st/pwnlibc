package buildsrc

import "testing"

func TestImageForKnownVersions(t *testing.T) {
	cases := []struct {
		version string
		want    string
	}{
		{"2.19", "ubuntu:14.04"},
		{"2.23-0ubuntu11", "ubuntu:16.04"},
		{"2.27-3ubuntu1.6", "ubuntu:18.04"},
		{"2.31-0ubuntu9.9", "ubuntu:20.04"},
		{"2.35-0ubuntu3.8", "ubuntu:22.04"},
		{"2.40-1ubuntu3", "ubuntu:24.04"},
	}
	for _, c := range cases {
		got, err := ImageFor(c.version)
		if err != nil {
			t.Errorf("ImageFor(%q): %v", c.version, err)
			continue
		}
		if got != c.want {
			t.Errorf("ImageFor(%q) = %q, want %q", c.version, got, c.want)
		}
	}
}

func TestImageForTooOld(t *testing.T) {
	if _, err := ImageFor("2.5"); err == nil {
		t.Error("expected error for a glibc version older than any known image")
	}
}

func TestImageForUnparseable(t *testing.T) {
	if _, err := ImageFor("not-a-version"); err == nil {
		t.Error("expected error for an unparseable version string")
	}
}
