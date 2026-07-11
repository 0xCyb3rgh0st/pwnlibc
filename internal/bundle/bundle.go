// Package bundle packs/unpacks the whole libs/ cache as a single tar.gz so
// it can be carried into an air-gapped CTF environment that can't reach any
// mirror.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pwnlibc/internal/archive"
)

// Export writes every file under libsDir into a gzip-compressed tar at destTar.
func Export(libsDir, destTar string) (int, error) {
	out, err := os.Create(destTar)
	if err != nil {
		return 0, err
	}
	defer func() { _ = out.Close() }()

	gz := gzip.NewWriter(out)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	count := 0
	err = filepath.Walk(libsDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(libsDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

// Import extracts a bundle produced by Export into libsDir, using the same
// path-traversal / symlink-escape guards as regular .deb extraction.
func Import(srcTar, libsDir string) ([]string, error) {
	in, err := os.Open(srcTar)
	if err != nil {
		return nil, err
	}
	defer func() { _ = in.Close() }()

	gz, err := gzip.NewReader(in)
	if err != nil {
		return nil, fmt.Errorf("not a gzip bundle: %w", err)
	}
	defer func() { _ = gz.Close() }()

	if err := os.MkdirAll(libsDir, 0o755); err != nil {
		return nil, err
	}

	return archive.SafeExtractTar(gz, libsDir, func(name string) (string, bool) {
		return strings.TrimPrefix(name, "/"), true
	})
}
