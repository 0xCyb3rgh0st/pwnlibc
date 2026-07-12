// Package cli wires pwnlibc's Cobra command tree together. Each subcommand
// lives in its own file; this file holds the shared application context
// every command pulls its dependencies from.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/cache"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/config"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/index"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/jsonout"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/mirrors"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
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
	ui.FprintError(os.Stderr, "%v", err)
}

var (
	app        = &App{}
	cfgPath    string
	jsonOutput bool
	noColor    bool
	noBanner   bool
)

// applyUIFlags pushes --no-color into the ui package. It's called from both
// PersistentPreRunE (the normal command path) and the custom help function
// (which Cobra reaches via a separate path that skips PersistentPreRunE
// entirely for --help), since both need it and neither alone covers both
// invocation shapes. Flags are already parsed by the time either runs.
func applyUIFlags() {
	if noColor {
		ui.SetColorEnabled(false)
	}
}

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
			applyUIFlags()
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
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output (also honors the NO_COLOR env var)")
	root.PersistentFlags().BoolVar(&noBanner, "no-banner", false, "never print the banner, even on an interactive terminal")

	// Cobra reaches this for both `pwnlibc --help`/`-h` and bare `pwnlibc`
	// (a non-runnable root with subcommands falls back to help), and -- since
	// it's inherited by every child that doesn't set its own -- also for
	// `pwnlibc <subcommand> --help`. Flags are already parsed by the time
	// Cobra calls this, even on the --help path where PersistentPreRunE is
	// skipped entirely -- see applyUIFlags.
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		applyUIFlags()
		out := cmd.OutOrStdout()
		// Only the bare root command shows the banner ("pwnlibc" or
		// "pwnlibc --help") -- not every subcommand's --help, which would
		// get noisy fast across a dozen commands.
		if cmd.Parent() == nil && ui.ShouldShowBanner(out, ui.BannerOptions{JSON: jsonOutput, NoBanner: noBanner}) {
			ui.PrintBanner(out)
		}
		if s := cmd.Long; s != "" {
			_, _ = fmt.Fprintln(out, s)
			_, _ = fmt.Fprintln(out)
		} else if s := cmd.Short; s != "" {
			_, _ = fmt.Fprintln(out, s)
			_, _ = fmt.Fprintln(out)
		}
		if cmd.Runnable() || cmd.HasSubCommands() {
			_, _ = fmt.Fprintln(out, cmd.UsageString())
		}
	})

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
		newBannerCmd(),
		newVersionCmd(),
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
