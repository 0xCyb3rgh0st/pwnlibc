// Package cli wires pwnlibc's Cobra command tree together. Each subcommand
// lives in its own file; this file holds the shared application context
// every command pulls its dependencies from.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"pwnlibc/internal/cache"
	"pwnlibc/internal/config"
	"pwnlibc/internal/index"
	"pwnlibc/internal/jsonout"
	"pwnlibc/internal/mirrors"
)

// Version is set via -ldflags at build time.
var Version = "dev"

// App bundles the resources most subcommands need, resolved once in
// PersistentPreRunE and reused down the command tree.
type App struct {
	Config   *config.Config
	Paths    *cache.Paths
	Registry *mirrors.Registry
	JSON     bool
}

func (a *App) OpenIndex() (*index.Index, error) {
	return index.Open(a.Paths.IndexDB())
}

// EmitResult prints data as pretty JSON (--json) or hands off to a
// human-readable printer function.
func (a *App) EmitResult(data interface{}, human func()) {
	if a.JSON {
		_ = jsonout.Emit(os.Stdout, data)
		return
	}
	human()
}

// EmitError prints an error consistently in both modes and returns the
// process exit code the caller should use.
func (a *App) EmitError(err error) {
	if a.JSON {
		_ = jsonout.EmitError(os.Stdout, jsonout.CodeOf(err), err)
		return
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
}

var (
	app        = &App{}
	cfgPath    string
	jsonOutput bool
)

// NewRootCmd builds the full pwnlibc command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pwnlibc",
		Short:         "All-in-one glibc version manager for CTF/pwn work",
		Long:          "pwnlibc downloads, identifies, diffs, patches, and builds glibc versions for binary exploitation work.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			if err := cfg.EnsureDirs(); err != nil {
				return fmt.Errorf("preparing storage directories: %w", err)
			}
			app.Config = cfg
			app.Paths = cache.New(cfg)
			if err := app.Paths.EnsureAll(); err != nil {
				return err
			}
			app.Registry = mirrors.NewRegistry(cfg)
			app.JSON = jsonOutput
			return nil
		},
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "", "path to config.yaml (default: none, built-in defaults)")
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON instead of human-readable output")

	root.AddCommand(
		newMirrorCmd(),
		newDownloadCmd(),
		newSearchCmd(),
		newIdentifyCmd(),
		newDiffCmd(),
		newBuildCmd(),
		newVulnCmd(),
		newPatchCmd(),
		newRunCmd(),
		newBundleCmd(),
		newDoctorCmd(),
		newCompletionCmd(),
	)
	return root
}

// Execute runs the full command tree and returns the process exit code.
// Errors are always surfaced via App.EmitError (respecting --json) instead
// of relying on Cobra's default stderr printing, since PersistentPreRunE is
// what actually populates `app` (jsonOutput isn't known before flag parsing).
func Execute() int {
	if err := NewRootCmd().Execute(); err != nil {
		app.EmitError(err)
		return 1
	}
	return 0
}
