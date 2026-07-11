package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"pwnlibc/internal/elfinfo"
	"pwnlibc/internal/identify"
	"pwnlibc/internal/libcrip"
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
				switch result.Method {
				case identify.MethodNone:
					fmt.Println("no match found (try `pwnlibc download` more versions to grow the local index, or drop --offline)")
				default:
					fmt.Printf("%-24s method=%-16s confidence=%s\n", result.VersionArch, result.Method, result.Confidence)
					if result.BuildID != "" {
						fmt.Printf("  build-id: %s\n", result.BuildID)
					}
					for _, c := range result.Candidates[min(1, len(result.Candidates)):] {
						fmt.Printf("  candidate: %-24s %d/%d anchors matched\n", c.VersionArch, c.Matched, c.Compared)
					}
				}
			})
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "skip the libc.rip network lookup, use only the local index")
	return cmd
}
