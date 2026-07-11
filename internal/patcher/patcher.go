// Package patcher implements pwninit-style ELF patching: rewrite a target
// binary's PT_INTERP to point at a specific ld.so and set its RPATH/RUNPATH
// to a specific libc directory, so it runs against the exact glibc version
// a CTF challenge shipped with.
//
// This shells out to `patchelf` (bundled in the pwnlibc runtime image)
// rather than reimplementing ELF program-header rewriting, since patchelf
// is the well-tested standard tool for this and getting it wrong corrupts
// the binary.
package patcher

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"pwnlibc/internal/pwnerr"
)

// Result describes what was patched and where the output landed.
type Result struct {
	OutputPath  string `json:"output_path"`
	Interpreter string `json:"interpreter"`
	RPath       string `json:"rpath"`
}

// FindLoader locates the dynamic loader (ld-*.so / ld-linux*.so.2) inside a
// downloaded libc directory.
func FindLoader(libDir string) (string, error) {
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return "", err
	}
	// Prefer the versioned real file over the generic symlink so the patched
	// binary keeps working even if the directory is later reorganized.
	var symlinkCandidate string
	for _, e := range entries {
		name := e.Name()
		switch {
		case matchesPrefix(name, "ld-linux") && !e.IsDir():
			info, _ := e.Info()
			if info != nil && info.Mode()&os.ModeSymlink != 0 {
				symlinkCandidate = filepath.Join(libDir, name)
				continue
			}
			return filepath.Join(libDir, name), nil
		case matchesPrefix(name, "ld-") && !e.IsDir():
			return filepath.Join(libDir, name), nil
		}
	}
	if symlinkCandidate != "" {
		return symlinkCandidate, nil
	}
	return "", fmt.Errorf("no ld.so found under %s", libDir)
}

func matchesPrefix(name, prefix string) bool {
	return len(name) >= len(prefix) && name[:len(prefix)] == prefix
}

// Patch copies srcBinary to outPath (if different) and rewrites its
// interpreter + rpath in place via patchelf.
func Patch(srcBinary, ldPath, libDir, outPath string) (*Result, error) {
	if _, err := exec.LookPath("patchelf"); err != nil {
		return nil, pwnerr.Wrap(pwnerr.CodeIO, "patchelf not found on PATH (it ships in the pwnlibc runtime image)", err)
	}

	if outPath != srcBinary {
		if err := copyFile(srcBinary, outPath); err != nil {
			return nil, pwnerr.Wrap(pwnerr.CodeIO, "copying binary before patching", err)
		}
	}
	if err := os.Chmod(outPath, 0o755); err != nil {
		return nil, err
	}

	absLd, err := filepath.Abs(ldPath)
	if err != nil {
		return nil, err
	}
	absLib, err := filepath.Abs(libDir)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("patchelf", "--set-interpreter", absLd, "--set-rpath", absLib, outPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, pwnerr.Wrap(pwnerr.CodeIO, fmt.Sprintf("patchelf failed: %s", string(out)), err)
	}

	return &Result{OutputPath: outPath, Interpreter: absLd, RPath: absLib}, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)
	return err
}
