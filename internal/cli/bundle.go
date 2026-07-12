package cli

import (
	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/bundle"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
)

func newBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Export/import the whole libs/ cache as a tarball, for air-gapped CTF environments",
	}
	cmd.AddCommand(newBundleExportCmd(), newBundleImportCmd())
	return cmd
}

func newBundleExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export <dest.tar.gz>",
		Short: "Pack the local libs/ cache into a single tarball",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := bundle.Export(app.Config.LibsDir, args[0])
			if err != nil {
				return err
			}
			app.EmitResult(map[string]interface{}{"dest": args[0], "files": count}, func() {
				ui.FprintSuccess(cmd.OutOrStdout(), "Exported %d files -> %s", count, ui.Cyan(args[0]))
			})
			return nil
		},
	}
}

func newBundleImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <src.tar.gz>",
		Short: "Unpack a bundle produced by `bundle export` into the local libs/ cache",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			written, err := bundle.Import(args[0], app.Config.LibsDir)
			if err != nil {
				return err
			}
			app.EmitResult(map[string]interface{}{"src": args[0], "files": len(written)}, func() {
				ui.FprintSuccess(cmd.OutOrStdout(), "Imported %d files -> %s", len(written), ui.Cyan(app.Config.LibsDir))
			})
			return nil
		},
	}
}
