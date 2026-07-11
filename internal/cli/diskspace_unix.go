//go:build unix

package cli

import "golang.org/x/sys/unix"

// freeBytes reports available disk space at path on Linux/macOS/BSD.
func freeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
