package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeTar(t *testing.T, entries []tar.Header, contents map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, hdr := range entries {
		h := hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(contents[h.Name]))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("WriteHeader(%s): %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(contents[h.Name]); err != nil {
				t.Fatalf("Write(%s): %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func acceptAll(name string) (string, bool) { return name, true }

func TestSafeExtractTarNormal(t *testing.T) {
	tarBytes := writeTar(t,
		[]tar.Header{{Name: "lib/foo.so", Typeflag: tar.TypeReg, Mode: 0o644}},
		map[string][]byte{"lib/foo.so": []byte("hello")},
	)
	dest := t.TempDir()
	written, err := SafeExtractTar(bytes.NewReader(tarBytes), dest, acceptAll)
	if err != nil {
		t.Fatalf("SafeExtractTar: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("got %d written files, want 1", len(written))
	}
	data, err := os.ReadFile(filepath.Join(dest, "lib/foo.so"))
	if err != nil {
		t.Fatalf("reading extracted file: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q, want %q", data, "hello")
	}
}

func TestSafeExtractTarPreservesExecutableBit(t *testing.T) {
	tarBytes := writeTar(t,
		[]tar.Header{{Name: "ld-2.31.so", Typeflag: tar.TypeReg, Mode: 0o755}},
		map[string][]byte{"ld-2.31.so": []byte("fake-loader")},
	)
	dest := t.TempDir()
	if _, err := SafeExtractTar(bytes.NewReader(tarBytes), dest, acceptAll); err != nil {
		t.Fatalf("SafeExtractTar: %v", err)
	}
	info, err := os.Stat(filepath.Join(dest, "ld-2.31.so"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("expected the executable bit to survive extraction, got mode %v", info.Mode())
	}
}

func TestSafeExtractTarRejectsPathTraversal(t *testing.T) {
	tarBytes := writeTar(t,
		[]tar.Header{{Name: "../../../../etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644}},
		map[string][]byte{"../../../../etc/passwd": []byte("pwned")},
	)
	dest := t.TempDir()
	if _, err := SafeExtractTar(bytes.NewReader(tarBytes), dest, acceptAll); err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
	// Must not have escaped: nothing written outside dest.
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "etc", "passwd")); statErr == nil {
		t.Fatal("path traversal actually wrote outside destDir")
	}
}

func TestSafeExtractTarSkipsUnsafeSymlink(t *testing.T) {
	tarBytes := writeTar(t,
		[]tar.Header{{
			Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "../../../../etc/passwd", Mode: 0o777,
		}},
		nil,
	)
	dest := t.TempDir()
	written, err := SafeExtractTar(bytes.NewReader(tarBytes), dest, acceptAll)
	if err != nil {
		t.Fatalf("SafeExtractTar should skip (not error on) unsafe symlinks: %v", err)
	}
	if len(written) != 0 {
		t.Fatalf("expected the unsafe symlink to be skipped, got %v", written)
	}
}

func TestSafeExtractTarFilterRejectsEntry(t *testing.T) {
	tarBytes := writeTar(t,
		[]tar.Header{{Name: "skip-me.txt", Typeflag: tar.TypeReg, Mode: 0o644}},
		map[string][]byte{"skip-me.txt": []byte("x")},
	)
	dest := t.TempDir()
	written, err := SafeExtractTar(bytes.NewReader(tarBytes), dest, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 0 {
		t.Fatalf("expected filter to reject all entries, got %v", written)
	}
}

func TestDecompressGzip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("payload"))
	_ = gz.Close()

	r, err := Decompress("data.tar.gz", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	// A single Read may legitimately return the final bytes together with
	// io.EOF in one call, so drain with io.ReadAll rather than asserting on
	// one Read's error.
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decompressed data: %v", err)
	}
	if string(out) != "payload" {
		t.Errorf("got %q, want %q", out, "payload")
	}
}

func TestDecompressUnknownSuffix(t *testing.T) {
	if _, err := Decompress("data.tar.rar", bytes.NewReader(nil)); err == nil {
		t.Fatal("expected error for unsupported compression suffix")
	}
}
