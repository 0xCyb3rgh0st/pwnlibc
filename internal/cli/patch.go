package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"pwnlibc/internal/elfinfo"
	"pwnlibc/internal/identify"
	"pwnlibc/internal/libcrip"
	"pwnlibc/internal/patcher"
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

			if versionArch == "" {
				var err error
				versionArch, err = autoIdentifyVersion(binary)
				if err != nil {
					return fmt.Errorf("auto-detecting glibc version (pass --version to skip this): %w", err)
				}
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
			}

			ldPath, err := patcher.FindLoader(libDir)
			if err != nil {
				return err
			}

			out := outPath
			if out == "" {
				out = binary + "_patched"
			}
			result, err := patcher.Patch(binary, ldPath, libDir, out)
			if err != nil {
				return err
			}

			app.EmitResult(map[string]interface{}{
				"version_arch": versionArch,
				"result":       result,
			}, func() {
				fmt.Printf("patched %s -> %s\n", binary, result.OutputPath)
				fmt.Printf("  interpreter: %s\n", result.Interpreter)
				fmt.Printf("  rpath:       %s\n", result.RPath)
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&explicitVersionArch, "version", "", "explicit version_arch (e.g. 2.31-0ubuntu9.9_amd64), skips auto-detection")
	cmd.Flags().StringVar(&outPath, "out", "", "output path (default: <binary>_patched)")
	cmd.Flags().BoolVar(&noDownload, "no-download", false, "fail instead of auto-downloading a missing glibc version")
	return cmd
}

func autoIdentifyVersion(path string) (string, error) {
	info, f, err := elfinfo.Load(path)
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
		return "", fmt.Errorf("could not determine glibc version from %s", path)
	}
	return result.VersionArch, nil
}
