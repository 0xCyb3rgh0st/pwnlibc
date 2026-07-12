package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/identify"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/libcrip"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
)

func newIdentifyCmd() *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "identify <file>",
		Short: "Identify which glibc version a file is via BuildID or symbol fingerprint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			info, f, err := elfinfo.Load(args[0])
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			symbols := elfinfo.Symbols(f)

			idx, err := app.OpenIndex()
			if err != nil {
				return err
			}
			defer func() { _ = idx.Close() }()

			var client *libcrip.Client
			if !offline {
				client = libcrip.NewClient()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			result, err := identify.Identify(ctx, idx, client, info, symbols, offline)
			if err != nil {
				return err
			}

			app.EmitResult(result, func() {
				if result.Method == identify.MethodNone {
					fmt.Println(ui.Error("no match found (try `pwnlibc download` more versions to grow the local index, or drop --offline)"))
					return
				}

				rows := [][2]string{
					{"File", ui.Cyan(args[0])},
					{"Architecture", info.Arch},
				}
				if result.BuildID != "" {
					rows = append(rows, [2]string{"BuildID", ui.Cyan(result.BuildID)})
				}
				rows = append(rows,
					[2]string{"Version", ui.Cyan(result.VersionArch)},
					[2]string{"Method", string(result.Method)},
					[2]string{"Confidence", result.Confidence},
				)
				fmt.Println(ui.Box("glibc identification", rows, "Match confirmed"))

				for _, c := range result.Candidates[min(1, len(result.Candidates)):] {
					fmt.Println(ui.Dim(fmt.Sprintf("  candidate: %-24s %d/%d anchors matched", c.VersionArch, c.Matched, c.Compared)))
				}
			})
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "skip the libc.rip network lookup, use only the local index")
	return cmd
}
