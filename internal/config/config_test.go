package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	def := Default()
	if cfg.LibsDir != def.LibsDir || cfg.MaxRetries != def.MaxRetries {
		t.Errorf("expected defaults, got %+v", cfg)
	}
}

func TestLoadOverlaysFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "libs_dir: /custom/libs\nmax_retries: 7\nmirror_priority: [\"ustc\"]\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LibsDir != "/custom/libs" {
		t.Errorf("got LibsDir %q", cfg.LibsDir)
	}
	if cfg.MaxRetries != 7 {
		t.Errorf("got MaxRetries %d", cfg.MaxRetries)
	}
	if len(cfg.MirrorPriority) != 1 || cfg.MirrorPriority[0] != "ustc" {
		t.Errorf("got MirrorPriority %v", cfg.MirrorPriority)
	}
	// Fields not set in the file should keep their defaults.
	if cfg.CacheDir == "" {
		t.Error("expected CacheDir to retain its default")
	}
}

func TestEnsureDirsCreatesStorage(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{LibsDir: filepath.Join(root, "libs"), CacheDir: filepath.Join(root, "cache")}
	if err := cfg.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	for _, d := range []string{cfg.LibsDir, cfg.CacheDir} {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			t.Errorf("expected %s to exist as a directory", d)
		}
	}
}
