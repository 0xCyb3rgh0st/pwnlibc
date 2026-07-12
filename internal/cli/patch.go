package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/identify"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/libcrip"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/patcher"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
)

func newPatchCmd() *cobra.Command {
	var (
		explicitVersionArch string
		outPath             string
		noDownload          bool
	)

	cmd := &cobra.Command{
		Use:   "patch <binary>",
		Short: "pwninit-style patch: auto-detect (or use --version) the required glibc, download it, and rewrite the binary's interpreter/RPATH",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binary := args[0]
			versionArch := explicitVersionArch
			human := !app.JSON
			out := cmd.OutOrStdout()

			if versionArch == "" {
				if human {
					ui.FprintStep(out, "Inspecting ELF binary")
				}
				var err error
				versionArch, err = autoIdentifyVersion(binary)
				if err != nil {
					return fmt.Errorf("auto-detecting glibc version (pass --version to skip this): %w", err)
				}
			}
			if human {
				ui.FprintSuccess(out, "Required glibc identified: %s", ui.Cyan(versionArch))
			}

			// Split "2.31-0ubuntu9.9_amd64" into version + arch to resolve
			// (or create) the libs directory, downloading it if missing.
			version, arch, err := splitVersionArch(versionArch)
			if err != nil {
				return err
			}
			libDir := app.Paths.VersionDir(version, arch)
			if !dirHasLibc(libDir) {
				if noDownload {
					return fmt.Errorf("glibc %s not present locally and --no-download was set; run `pwnlibc download %s` first", versionArch, versionArch)
				}
				if err := runDownload(versionArch, "", false, false); err != nil {
					return fmt.Errorf("downloading matched glibc %s: %w", versionArch, err)
				}
			} else if human {
				ui.FprintSuccess(out, "Dynamic loader available locally")
			}

			ldPath, err := patcher.FindLoader(libDir)
			if err != nil {
				return err
			}

			outPathResolved := outPath
			if outPathResolved == "" {
				outPathResolved = binary + "_patched"
			}
			result, err := patcher.Patch(binary, ldPath, libDir, outPathResolved)
			if err != nil {
				return err
			}
			if human {
				ui.FprintSuccess(out, "RPATH updated")
				ui.FprintSuccess(out, "Interpreter updated")
				ui.FprintSuccess(out, "Patched binary: %s", ui.Cyan(result.OutputPath))
			}

			app.EmitResult(map[string]interface{}{
				"version_arch": versionArch,
				"result":       result,
			}, func() {})
			return nil
		},
	}

	cmd.Flags().StringVar(&explicitVersionArch, "version", "", "explicit version_arch (e.g. 2.31-0ubuntu9.9_amd64), skips auto-detection")
	cmd.Flags().StringVar(&outPath, "out", "", "output path (default: <binary>_patched)")
	cmd.Flags().BoolVar(&noDownload, "no-download", false, "fail instead of auto-downloading a missing glibc version")
	return cmd
}

// autoIdentifyVersion determines which glibc a challenge binary needs. It
// deliberately does NOT try to BuildID/fingerprint the challenge binary
// itself: a regular executable's glibc-provided symbols (system, malloc,
// ...) are *undefined* imports in its own .dynsym, not exported definitions
// with real addresses, so there's nothing there to fingerprint against.
// CTF challenges conventionally ship the matching libc.so.6 alongside the
// binary -- that co-located file is what actually has a real BuildID and
// real symbol offsets to identify.
func autoIdentifyVersion(path string) (string, error) {
	target, err := findCoLocatedLibc(path)
	if err != nil {
		return "", err
	}

	info, f, err := elfinfo.Load(target)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	symbols := elfinfo.Symbols(f)

	idx, err := app.OpenIndex()
	if err != nil {
		return "", err
	}
	defer func() { _ = idx.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := identify.Identify(ctx, idx, libcrip.NewClient(), info, symbols, false)
	if err != nil {
		return "", err
	}
	if result.VersionArch == "" {
		return "", fmt.Errorf("could not determine glibc version from %s", target)
	}
	return result.VersionArch, nil
}

// findCoLocatedLibc looks in binary's directory for a file matching the
// conventional libc naming patterns CTF challenges ship alongside a binary
// (libc.so.6, libc-2.31.so, libc6_2.31...). Returns an error naming what to
// do instead (--version) if none is found, rather than silently trying to
// fingerprint the wrong file.
func findCoLocatedLibc(binary string) (string, error) {
	dir := filepath.Dir(binary)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("scanning %s for a co-located libc: %w", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Join(dir, name) == binary {
			continue
		}
		if name == "libc.so.6" || (strings.HasPrefix(name, "libc") && strings.Contains(name, ".so")) {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf(
		"no libc.so.6 (or similarly named file) found next to %s -- "+
			"pwnlibc can only auto-detect a version from a libc file's own BuildID/symbols, "+
			"not from the challenge binary itself; pass --version explicitly", binary)
}
