package cli

import (
	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
)

func newBannerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "banner",
		Short: "Print the pwnlibc banner",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Unlike the automatic help-path banner, an explicit `banner`
			// invocation always prints something when asked directly --
			// it only still respects --no-color/NO_COLOR for the text
			// itself and --json (banner has no JSON representation).
			if jsonOutput {
				return nil
			}
			ui.PrintBanner(cmd.OutOrStdout())
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the pwnlibc version",
		RunE: func(cmd *cobra.Command, args []string) error {
			app.EmitResult(map[string]interface{}{"version": Version}, func() {
				cmd.Printf("pwnlibc version %s\n", Version)
			})
			return nil
		},
	}
}
