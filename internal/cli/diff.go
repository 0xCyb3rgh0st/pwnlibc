package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/diffcmd"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
)

func newDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <a> <b>",
		Short: "Compare symbols and security attributes between two libc/ELF files",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			infoA, fA, err := elfinfo.Load(args[0])
			if err != nil {
				return err
			}
			defer func() { _ = fA.Close() }()
			infoB, fB, err := elfinfo.Load(args[1])
			if err != nil {
				return err
			}
			defer func() { _ = fB.Close() }()

			result := diffcmd.Diff(args[0], infoA, elfinfo.Symbols(fA), args[1], infoB, elfinfo.Symbols(fB))

			app.EmitResult(result, func() {
				fmt.Printf("%s -> %s\n", args[0], args[1])
				fmt.Printf("  +%d symbols added, -%d removed, ~%d moved\n",
					len(result.SymbolsAdded), len(result.SymbolsRemoved), len(result.SymbolsMoved))
				for _, s := range result.Security {
					fmt.Printf("  %-10s %s -> %s\n", s.Attribute, s.Before, s.After)
				}
				if len(result.SymbolsMoved) > 0 {
					fmt.Println("  moved symbols:")
					for _, s := range result.SymbolsMoved {
						fmt.Printf("    %-32s 0x%x -> 0x%x\n", s.Name, *s.ValueA, *s.ValueB)
					}
				}
			})
			return nil
		},
	}
}
