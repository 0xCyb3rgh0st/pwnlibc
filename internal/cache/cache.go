// Package cache resolves on-disk paths used by pwnlibc's persistent state:
// the bbolt symbol/fingerprint index, the aggregated package list, and
// per-version provenance manifests.
package cache

import (
	"os"
	"path/filepath"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/config"
)

// Paths bundles the resolved filesystem locations derived from Config.
type Paths struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Paths {
	return &Paths{cfg: cfg}
}

// IndexDB is the bbolt database file backing internal/index.
func (p *Paths) IndexDB() string {
	return filepath.Join(p.cfg.CacheDir, "index.bbolt")
}

// PackageList is the aggregated apt-package list cache written by `mirror update`.
func (p *Paths) PackageList() string {
	return filepath.Join(p.cfg.CacheDir, "packages.json")
}

// VersionDir returns libs/<version>/<arch>.
func (p *Paths) VersionDir(version, arch string) string {
	return filepath.Join(p.cfg.LibsDir, version, arch)
}

// ProvenanceFile returns the PROVENANCE.json path for a given version/arch dir.
func (p *Paths) ProvenanceFile(version, arch string) string {
	return filepath.Join(p.VersionDir(version, arch), "PROVENANCE.json")
}

// DebCacheDir is where raw .deb files are kept when --keep-deb is set.
func (p *Paths) DebCacheDir() string {
	return filepath.Join(p.cfg.CacheDir, "debs")
}

// EnsureAll creates every directory this Paths value may need to write to.
func (p *Paths) EnsureAll() error {
	for _, d := range []string{p.cfg.LibsDir, p.cfg.CacheDir, p.DebCacheDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
