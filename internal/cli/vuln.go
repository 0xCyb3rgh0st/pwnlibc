package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/vulndb"
)

func newVulnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vuln <version>",
		Short: "Show known CVEs affecting a glibc version (curated, best-effort — verify against NVD)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries := vulndb.AffectedBy(args[0])
			app.EmitResult(entries, func() {
				if len(entries) == 0 {
					fmt.Println("no curated CVE entries match this version (this list is not exhaustive — check NVD)")
					return
				}
				for _, e := range entries {
					name := e.ID
					if e.Name != "" {
						name = fmt.Sprintf("%s (%s)", e.ID, e.Name)
					}
					fmt.Printf("%-40s severity=%s\n  %s\n", name, e.Severity, e.Description)
				}
			})
			return nil
		},
	}
}
