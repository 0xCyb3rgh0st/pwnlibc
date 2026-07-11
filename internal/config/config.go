// Package config loads pwnlibc's YAML configuration: storage paths, mirror
// priority, and user-defined custom mirrors.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Mirror is a user-defined apt-style mirror the user wants added to the
// built-in list (tuna/ustc/ubuntu-archive/old-releases).
type Mirror struct {
	Name    string `yaml:"name"`
	BaseURL string `yaml:"base_url"`
	// Fallback mirrors are only tried after all non-fallback mirrors fail.
	Fallback bool `yaml:"fallback"`
}

// Config is the full pwnlibc configuration.
type Config struct {
	// LibsDir is where downloaded/extracted glibc versions are stored.
	LibsDir string `yaml:"libs_dir"`
	// CacheDir holds the symbol/fingerprint index and package list cache.
	CacheDir string `yaml:"cache_dir"`
	// MirrorPriority overrides the default try-order of built-in mirror names.
	MirrorPriority []string `yaml:"mirror_priority"`
	// CustomMirrors are additional mirrors merged into the registry.
	CustomMirrors []Mirror `yaml:"custom_mirrors"`
	// DownloadTimeoutSeconds bounds a single mirror attempt.
	DownloadTimeoutSeconds int `yaml:"download_timeout_seconds"`
	// MaxRetries bounds retry attempts per mirror before giving up on it.
	MaxRetries int `yaml:"max_retries"`
}

// Default returns the built-in defaults, used when no config file exists.
func Default() *Config {
	return &Config{
		LibsDir:                "/data/libs",
		CacheDir:               defaultCacheDir(),
		MirrorPriority:         []string{"tuna", "ustc", "ubuntu-archive", "old-releases"},
		CustomMirrors:          nil,
		DownloadTimeoutSeconds: 20,
		MaxRetries:             3,
	}
}

func defaultCacheDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "pwnlibc")
	}
	return "/tmp/pwnlibc-cache"
}

// Load reads config from path if it exists, overlaying onto defaults. A
// missing file is not an error — Default() is returned unchanged.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// EnsureDirs creates LibsDir and CacheDir if they don't already exist.
func (c *Config) EnsureDirs() error {
	if err := os.MkdirAll(c.LibsDir, 0o755); err != nil {
		return err
	}
	return os.MkdirAll(c.CacheDir, 0o755)
}
