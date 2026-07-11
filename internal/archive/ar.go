// Package archive handles unpacking .deb files (a Unix "ar" archive
// containing debian-binary, control.tar.*, and data.tar.*) and safely
// extracting the compressed tarballs inside, guarding against path
// traversal, symlink escapes, and decompression bombs.
package archive

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ArEntry is one member of a Unix ar archive.
type ArEntry struct {
	Name string
	Data []byte
}

const arMagic = "!<arch>\n"

// ParseAr splits a .deb (or any ar archive) into its named members.
func ParseAr(data []byte) ([]ArEntry, error) {
	if len(data) < len(arMagic) || string(data[:len(arMagic)]) != arMagic {
		return nil, fmt.Errorf("not an ar archive (bad magic)")
	}
	r := bytes.NewReader(data[len(arMagic):])
	var entries []ArEntry
	header := make([]byte, 60)
	for {
		_, err := io.ReadFull(r, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("truncated ar header: %w", err)
		}
		name := strings.TrimRight(string(header[0:16]), " ")
		name = strings.TrimSuffix(name, "/") // GNU ar appends '/' to short names
		sizeStr := strings.TrimSpace(string(header[48:58]))
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("invalid ar member size for %q: %q", name, sizeStr)
		}
		const maxMemberSize = 1 << 30 // 1GiB guard against corrupt/hostile size fields
		if size > maxMemberSize {
			return nil, fmt.Errorf("ar member %q too large (%d bytes)", name, size)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("truncated ar member %q: %w", name, err)
		}
		if size%2 == 1 {
			// ar members are 2-byte aligned; skip the pad byte.
			if _, err := r.Seek(1, io.SeekCurrent); err != nil {
				break
			}
		}
		entries = append(entries, ArEntry{Name: name, Data: body})
	}
	return entries, nil
}

// FindMember returns the first member whose name starts with any of the
// given prefixes (used to locate "data.tar" regardless of its compression
// suffix: .gz, .xz, .zst).
func FindMember(entries []ArEntry, prefixes ...string) (*ArEntry, bool) {
	for i := range entries {
		for _, p := range prefixes {
			if strings.HasPrefix(entries[i].Name, p) {
				return &entries[i], true
			}
		}
	}
	return nil, false
}
