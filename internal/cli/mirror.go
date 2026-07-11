package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"pwnlibc/internal/fetch"
	"pwnlibc/internal/packages"
)

func newMirrorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mirror",
		Short: "Manage and refresh the apt mirrors pwnlibc downloads glibc from",
	}
	cmd.AddCommand(newMirrorListCmd(), newMirrorUpdateCmd())
	return cmd
}

func newMirrorListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured mirrors and whether they're primary or fallback",
		RunE: func(cmd *cobra.Command, args []string) error {
			mlist := app.Registry.All()
			type row struct {
				Name     string `json:"name"`
				BaseURL  string `json:"base_url"`
				Fallback bool   `json:"fallback"`
			}
			var rows []row
			for _, m := range mlist {
				rows = append(rows, row{Name: m.Name, BaseURL: m.BaseURL, Fallback: m.Fallback})
			}
			app.EmitResult(rows, func() {
				for _, r := range rows {
					kind := "primary"
					if r.Fallback {
						kind = "fallback"
					}
					fmt.Printf("%-16s %-8s %s\n", r.Name, kind, r.BaseURL)
				}
			})
			return nil
		},
	}
}

func newMirrorUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Refresh the aggregated package list from all configured mirrors",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			var lists [][]packages.Package
			var errs []string
			for _, m := range app.Registry.All() {
				resp, err := fetch.GetWithRetry(ctx, m.PoolURL(), fetch.Options{
					Timeout:    time.Duration(app.Config.DownloadTimeoutSeconds) * time.Second,
					MaxRetries: app.Config.MaxRetries,
				})
				if err != nil {
					app.Registry.RecordFailure(m.Name)
					errs = append(errs, fmt.Sprintf("%s: %v", m.Name, err))
					continue
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					app.Registry.RecordFailure(m.Name)
					errs = append(errs, fmt.Sprintf("%s: %v", m.Name, err))
					continue
				}
				app.Registry.RecordSuccess(m.Name)
				lists = append(lists, packages.ParsePoolListing(body, m.Name, m.Fallback))
			}

			merged := packages.Merge(lists...)
			list := &packages.List{UpdatedAt: time.Now().UTC().Format(time.RFC3339), Packages: merged}
			if err := list.Save(app.Paths.PackageList()); err != nil {
				return fmt.Errorf("saving package list: %w", err)
			}

			app.EmitResult(map[string]interface{}{
				"packages_indexed": len(merged),
				"mirror_errors":    errs,
			}, func() {
				fmt.Printf("indexed %d packages across %d mirrors\n", len(merged), len(app.Registry.All())-len(errs))
				for _, e := range errs {
					fmt.Printf("  warning: %s\n", e)
				}
			})
			return nil
		},
	}
}
