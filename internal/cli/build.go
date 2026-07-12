package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/buildsrc"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
)

func newBuildCmd() *cobra.Command {
	var (
		prefix    string
		noDocker  bool
		outDirOpt string
	)

	cmd := &cobra.Command{
		Use:   "build <version> <arch>",
		Short: "Compile glibc from source inside a period-correct Ubuntu container",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, arch := args[0], args[1]
			if noDocker {
				return fmt.Errorf("--no-docker host builds aren't supported: pwnlibc itself only ever runs inside Docker, so there is no host toolchain to fall back to; run without --no-docker (requires the build-src compose profile with the Docker socket mounted)")
			}

			outDir := outDirOpt
			if outDir == "" {
				outDir = filepath.Join(app.Config.LibsDir, "build", version, arch)
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			hostOutDir, err := hostPath(outDir)
			if err != nil {
				return fmt.Errorf("resolving host-visible output path: %w", err)
			}

			image, err := buildsrc.ImageFor(version)
			if err != nil {
				return err
			}
			ui.FprintStep(os.Stderr, "Building glibc %s (%s) using %s -- this can take a long time", ui.Cyan(version), arch, ui.Cyan(image))

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()
			err = buildsrc.Build(ctx, buildsrc.Options{
				Version: version, Arch: arch, Prefix: prefix, OutDir: hostOutDir, LogW: os.Stderr,
			})
			if err != nil {
				return err
			}

			app.EmitResult(map[string]interface{}{
				"version": version, "arch": arch, "image": image, "out_dir": outDir,
			}, func() {
				ui.FprintSuccess(os.Stdout, "Built glibc %s (%s) -> %s", ui.Cyan(version), arch, ui.Cyan(outDir))
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&prefix, "prefix", "/usr", "install prefix inside the build container")
	cmd.Flags().BoolVar(&noDocker, "no-docker", false, "unsupported: pwnlibc has no host toolchain to fall back to")
	cmd.Flags().StringVar(&outDirOpt, "out", "", "output directory (default: libs/build/<version>/<arch>)")
	return cmd
}
