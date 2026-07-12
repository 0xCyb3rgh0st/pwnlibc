package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
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
					fmt.Println(ui.Info("no curated CVE entries match this version (this list is not exhaustive — check NVD)"))
					return
				}
				for _, e := range entries {
					name := e.ID
					if e.Name != "" {
						name = fmt.Sprintf("%s (%s)", e.ID, e.Name)
					}
					var warn func(string, ...interface{}) string
					if e.Severity == "high" || e.Severity == "critical" {
						warn = ui.Warn
					} else {
						warn = ui.Info
					}
					// Pad the plain name before colorizing -- coloring first
					// would count invisible ANSI bytes toward the %-40s
					// width and misalign the severity column.
					padded := fmt.Sprintf("%-40s", name)
					fmt.Println(warn("%s severity=%s", ui.Cyan(padded), e.Severity))
					fmt.Printf("    %s\n", e.Description)
				}
			})
			return nil
		},
	}
}
