package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Decompress wraps r with the decompressor matching the data.tar.* suffix
// found on member.Name (.gz, .xz, .zst), or returns r unchanged for a plain
// .tar member.
func Decompress(name string, r io.Reader) (io.Reader, error) {
	switch {
	case strings.HasSuffix(name, ".gz"):
		return gzip.NewReader(r)
	case strings.HasSuffix(name, ".xz"):
		return xz.NewReader(r)
	case strings.HasSuffix(name, ".zst"):
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return zr.IOReadCloser(), nil
	case strings.HasSuffix(name, ".tar"):
		return r, nil
	default:
		return nil, fmt.Errorf("unsupported archive member %q: unknown compression", name)
	}
}

// maxExtractedTotal bounds total decompressed bytes written per Extract
// call, defending against decompression-bomb style .deb files.
const maxExtractedTotal = 2 << 30 // 2 GiB

// FilterFunc decides whether a tar entry should be extracted and, if so,
// the destination path (relative to destDir) to write it to.
type FilterFunc func(tarName string) (relDest string, ok bool)

// SafeExtractTar reads a tar stream and writes selected entries under
// destDir, rejecting anything that would escape destDir (path traversal,
// absolute paths, symlink/hardlink targets outside destDir) and enforcing
// a total-size cap.
func SafeExtractTar(r io.Reader, destDir string, filter FilterFunc) ([]string, error) {
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(r)
	var written []string
	var total int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		relDest, ok := filter(hdr.Name)
		if !ok {
			continue
		}

		targetPath, err := safeJoin(absDest, relDest)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", hdr.Name, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return nil, err
			}
			total += hdr.Size
			if total > maxExtractedTotal {
				return nil, fmt.Errorf("archive exceeds %d byte extraction cap (possible decompression bomb)", maxExtractedTotal)
			}
			// Preserve the archive's own file mode rather than hardcoding one:
			// ld.so specifically must keep its executable bit, since the
			// kernel execve()s it directly as the ELF interpreter (PT_INTERP)
			// -- losing +x here produces a confusing "permission denied" on
			// the *patched binary*, not on ld.so itself.
			mode := os.FileMode(hdr.Mode & 0o777)
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return nil, err
			}
			if _, err := io.CopyN(out, tr, hdr.Size); err != nil && err != io.EOF {
				_ = out.Close()
				return nil, fmt.Errorf("writing %q: %w", targetPath, err)
			}
			_ = out.Close()
			written = append(written, targetPath)
		case tar.TypeSymlink, tar.TypeLink:
			// Only allow links whose resolved target stays within destDir;
			// this is the classic zip-slip / tar-slip escape vector.
			linkTarget := hdr.Linkname
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(targetPath), linkTarget)
			}
			if _, err := safeJoin(absDest, mustRel(absDest, linkTarget)); err != nil {
				// Skip unsafe links rather than aborting the whole extraction;
				// glibc debs don't rely on symlinks pointing outside the pkg.
				continue
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return nil, err
			}
			_ = os.Remove(targetPath)
			if err := os.Symlink(hdr.Linkname, targetPath); err != nil {
				continue // best-effort; not fatal for our extraction needs
			}
			written = append(written, targetPath)
		}
	}
	return written, nil
}

// safeJoin joins base and rel, rejecting (rather than silently clamping)
// anything that would escape base: absolute paths and any ".." component
// that survives Clean. Silently clamping traversal attempts into base would
// still be memory-safe, but it lets unrelated hostile entries collide onto
// the same clamped path and overwrite each other, which is its own hazard —
// reject outright instead.
func safeJoin(base, rel string) (string, error) {
	cleanRel := filepath.Clean(rel)
	if filepath.IsAbs(cleanRel) || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path escapes destination: %q", rel)
	}
	joined := filepath.Join(base, cleanRel)
	if joined != base && !strings.HasPrefix(joined, base+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path escapes destination: %q", rel)
	}
	return joined, nil
}

func mustRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return rel
}
