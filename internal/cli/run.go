package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/buildsrc"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/patcher"
)

func newRunCmd() *cobra.Command {
	var (
		explicitVersionArch string
		noPatch             bool
	)

	cmd := &cobra.Command{
		Use:   "run <binary>",
		Short: "Launch a disposable container (matched glibc + gdb) to reproduce a challenge immediately",
		Long: "run auto-detects (or uses --version) the challenge's glibc, patches a copy of the binary against it " +
			"unless --no-patch, then drops you into gdb inside a throwaway container running the matching Ubuntu " +
			"release. Requires the build-src compose profile (Docker socket mounted) and the binary to live under " +
			"./workdir on the host.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binary := args[0]
			if err := buildsrc.DockerAvailable(cmd.Context()); err != nil {
				return err
			}

			versionArch := explicitVersionArch
			target := binary
			if !noPatch {
				var err error
				if versionArch == "" {
					versionArch, err = autoIdentifyVersion(binary)
					if err != nil {
						return fmt.Errorf("auto-detecting glibc version (pass --version or --no-patch): %w", err)
					}
				}
				version, arch, err := splitVersionArch(versionArch)
				if err != nil {
					return err
				}
				libDir := app.Paths.VersionDir(version, arch)
				if !dirHasLibc(libDir) {
					if err := runDownload(versionArch, "", false, false); err != nil {
						return fmt.Errorf("downloading matched glibc %s: %w", versionArch, err)
					}
				}
				ldPath, err := patcher.FindLoader(libDir)
				if err != nil {
					return err
				}
				patched := binary + "_patched"
				if _, err := patcher.Patch(binary, ldPath, libDir, patched); err != nil {
					return err
				}
				target = patched
			} else if versionArch == "" {
				versionArch, _ = autoIdentifyVersion(binary)
			}

			image := "ubuntu:22.04"
			if versionArch != "" {
				if version, _, err := splitVersionArch(versionArch); err == nil {
					if img, err := buildsrc.ImageFor(version); err == nil {
						image = img
					}
				}
			}

			hostBinDir, err := hostPath(filepath.Dir(target))
			if err != nil {
				return err
			}

			dockerArgs := []string{
				"run", "--rm", "-it",
				"-v", hostBinDir + ":/chal",
				"-w", "/chal",
				image, "bash", "-c",
				"apt-get update -qq >/dev/null && apt-get install -y -qq gdb >/dev/null && exec gdb ./" + filepath.Base(target),
			}

			fmt.Fprintf(os.Stderr, "launching %s (glibc %s)...\n", image, versionArch)
			dcmd := exec.CommandContext(cmd.Context(), "docker", dockerArgs...)
			dcmd.Stdin, dcmd.Stdout, dcmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return dcmd.Run()
		},
	}

	cmd.Flags().StringVar(&explicitVersionArch, "version", "", "explicit version_arch, skips auto-detection")
	cmd.Flags().BoolVar(&noPatch, "no-patch", false, "run the binary as-is instead of patching a copy first")
	return cmd
}
