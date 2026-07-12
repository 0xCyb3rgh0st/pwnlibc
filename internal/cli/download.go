package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/archive"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/fetch"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/packages"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/ui"
)

// triplets maps a Debian arch name to its multiarch library directory
// component, so we know which files inside the .deb belong to the shared
// libraries (as opposed to docs, locale data, etc).
var triplets = map[string]string{
	"amd64": "x86_64-linux-gnu",
	"i386":  "i386-linux-gnu",
	"arm64": "aarch64-linux-gnu",
	"armhf": "arm-linux-gnueabihf",
}

// Provenance is the audit-trail manifest written alongside every download.
type Provenance struct {
	Version       string    `json:"version"`
	Arch          string    `json:"arch"`
	MirrorName    string    `json:"mirror_name"`
	SourceURL     string    `json:"source_url"`
	SHA256        string    `json:"sha256"`
	DebFilename   string    `json:"deb_filename"`
	DownloadedAt  time.Time `json:"downloaded_at"`
	ToolVersion   string    `json:"tool_version"`
	DebugIncluded bool      `json:"debug_included"`
}

func newDownloadCmd() *cobra.Command {
	var (
		mirrorName string
		keepDeb    bool
		noDbg      bool
	)

	cmd := &cobra.Command{
		Use:   "download <version_arch>",
		Short: "Download and extract a glibc version, e.g. `pwnlibc download 2.31-0ubuntu9.9_amd64`",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDownload(args[0], mirrorName, keepDeb, !noDbg)
		},
	}
	cmd.Flags().StringVar(&mirrorName, "mirror", "", "restrict to a single mirror by name")
	cmd.Flags().BoolVar(&keepDeb, "keep-deb", false, "keep the raw .deb files in the cache dir")
	cmd.Flags().BoolVar(&noDbg, "no-dbg", false, "skip downloading the libc6-dbg debug symbols package")
	return cmd
}

func runDownload(versionArch, mirrorName string, keepDeb, wantDbg bool) error {
	list, err := loadPackageList()
	if err != nil {
		return err
	}
	main, dbg, err := list.FindVersionArch(versionArch, wantDbg)
	if err != nil {
		return err
	}

	triplet, ok := triplets[main.Arch]
	if !ok {
		return fmt.Errorf("unsupported architecture %q (known: amd64, i386, arm64, armhf)", main.Arch)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	destDir := app.Paths.VersionDir(main.Version, main.Arch)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	human := !app.JSON
	if human {
		ui.FprintStep(os.Stdout, "Searching Ubuntu package mirrors")
		ui.FprintAction(os.Stdout, "Package: %s", ui.Cyan(main.Filename))
	}

	mainResult, err := downloadAndExtractDeb(ctx, *main, mirrorName, destDir, keepDeb, libFilter(triplet), human)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", main.Filename, err)
	}
	if human {
		ui.FprintSuccess(os.Stdout, "Package downloaded (mirror: %s)", ui.Cyan(mainResult.MirrorName))
		// We compute and record this hash ourselves rather than checking it
		// against a third-party value: Ubuntu's apt Packages index only
		// lists checksums for the currently-active release, not the
		// historical versions the pool directory still serves, so there's
		// no authoritative source to verify against for most downloads.
		ui.FprintSuccess(os.Stdout, "SHA-256 recorded: %s", ui.Cyan(mainResult.SHA256))
		ui.FprintSuccess(os.Stdout, "Package extracted safely")
	}

	debugIncluded := false
	if wantDbg && dbg != nil {
		if _, err := downloadAndExtractDeb(ctx, *dbg, mirrorName, filepath.Join(destDir, ".debug"), keepDeb, debugFilter(), false); err != nil {
			// Debug symbols are a bonus, not fatal to the core download.
			if human {
				ui.FprintWarn(os.Stderr, "failed to download debug symbols: %v", err)
			}
		} else {
			debugIncluded = true
			if human {
				ui.FprintSuccess(os.Stdout, "Debug symbols included")
			}
		}
	}

	libcPath, err := findMainLibc(destDir)
	if err != nil {
		return fmt.Errorf("extraction succeeded but couldn't locate libc.so.6: %w", err)
	}
	info, f, err := elfinfo.Load(libcPath)
	if err != nil {
		return err
	}
	symbols := elfinfo.Symbols(f)
	_ = f.Close()

	idx, err := app.OpenIndex()
	if err != nil {
		return err
	}
	defer func() { _ = idx.Close() }()
	if err := idx.IndexVersion(versionArch, info.BuildID, symbols); err != nil {
		return fmt.Errorf("indexing downloaded version: %w", err)
	}
	if human && info.BuildID != "" {
		ui.FprintSuccess(os.Stdout, "Indexed BuildID: %s", ui.Cyan(info.BuildID))
	}

	prov := Provenance{
		Version: main.Version, Arch: main.Arch, MirrorName: mainResult.MirrorName,
		SourceURL: mainResult.URL, SHA256: mainResult.SHA256, DebFilename: main.Filename,
		DownloadedAt: time.Now().UTC(), ToolVersion: cliVersion(), DebugIncluded: debugIncluded,
	}
	provData, _ := json.MarshalIndent(prov, "", "  ")
	if err := os.WriteFile(app.Paths.ProvenanceFile(main.Version, main.Arch), provData, 0o644); err != nil {
		return fmt.Errorf("writing provenance manifest: %w", err)
	}
	if human {
		ui.FprintSuccess(os.Stdout, "Provenance written to %s", ui.Cyan("PROVENANCE.json"))
	}

	app.EmitResult(map[string]interface{}{
		"version_arch":   versionArch,
		"dest_dir":       destDir,
		"libc_path":      libcPath,
		"build_id":       info.BuildID,
		"debug_included": debugIncluded,
		"provenance":     prov,
	}, func() {
		ui.FprintSuccess(os.Stdout, "glibc %s ready at %s", ui.Cyan(versionArch), ui.Cyan(destDir))
	})
	return nil
}

func cliVersion() string { return Version }

func downloadAndExtractDeb(ctx context.Context, pkg packages.Package, mirrorName, destDir string, keepDeb bool, filter archive.FilterFunc, showProgress bool) (*fetch.Result, error) {
	candidates := buildCandidates(pkg, mirrorName)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no mirrors known to host %s (restricted to %q?)", pkg.Filename, mirrorName)
	}

	debPath := filepath.Join(app.Paths.DebCacheDir(), pkg.Filename)
	opts := fetch.Options{
		Timeout:    time.Duration(app.Config.DownloadTimeoutSeconds) * time.Second,
		MaxRetries: app.Config.MaxRetries,
	}
	if showProgress {
		var prog *ui.Progress
		opts.OnProgress = func(written, total int64) {
			if prog == nil {
				prog = ui.NewProgress(os.Stderr, "Downloading "+pkg.Filename, total)
			}
			prog.Update(written)
			if total > 0 && written >= total {
				prog.Finish()
			}
		}
	}
	result, err := fetch.DownloadFileRacing(ctx, candidates, debPath, opts)
	if err != nil {
		for _, c := range candidates {
			app.Registry.RecordFailure(c.MirrorName)
		}
		return nil, err
	}
	app.Registry.RecordSuccess(result.MirrorName)

	if !keepDeb {
		defer func() { _ = os.Remove(debPath) }()
	}

	data, err := os.ReadFile(debPath)
	if err != nil {
		return nil, err
	}
	entries, err := archive.ParseAr(data)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid .deb (ar) archive: %w", pkg.Filename, err)
	}
	dataMember, ok := archive.FindMember(entries, "data.tar")
	if !ok {
		return nil, fmt.Errorf("%s has no data.tar member", pkg.Filename)
	}
	decompressed, err := archive.Decompress(dataMember.Name, bytes.NewReader(dataMember.Data))
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", dataMember.Name, err)
	}
	if _, err := archive.SafeExtractTar(decompressed, destDir, filter); err != nil {
		return nil, fmt.Errorf("extracting %s: %w", pkg.Filename, err)
	}
	return result, nil
}

func buildCandidates(pkg packages.Package, restrictMirror string) []fetch.Candidate {
	var out []fetch.Candidate
	for _, m := range app.Registry.Ranked() {
		if restrictMirror != "" && m.Name != restrictMirror {
			continue
		}
		if !contains(pkg.Mirrors, m.Name) {
			continue
		}
		out = append(out, fetch.Candidate{MirrorName: m.Name, URL: m.PoolURL() + pkg.Filename})
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// libFilter keeps only shared-object files belonging to the target arch's
// multiarch triplet, flattened directly into destDir.
func libFilter(triplet string) archive.FilterFunc {
	return func(tarName string) (string, bool) {
		if !strings.Contains(tarName, "/"+triplet+"/") {
			return "", false
		}
		base := filepath.Base(tarName)
		if !strings.Contains(base, ".so") {
			return "", false
		}
		return base, true
	}
}

// debugFilter keeps everything under usr/lib/debug/, preserving its
// relative structure (build-id links and/or classic path layout both work
// this way) under destDir.
func debugFilter() archive.FilterFunc {
	return func(tarName string) (string, bool) {
		idx := strings.Index(tarName, "usr/lib/debug/")
		if idx < 0 {
			return "", false
		}
		return tarName[idx+len("usr/lib/debug/"):], true
	}
}

// findMainLibc locates the primary libc shared object among the flattened
// extracted files.
func findMainLibc(destDir string) (string, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return "", err
	}
	var fallback string
	for _, e := range entries {
		name := e.Name()
		if name == "libc.so.6" {
			return filepath.Join(destDir, name), nil
		}
		if strings.HasPrefix(name, "libc-") && strings.HasSuffix(name, ".so") {
			fallback = filepath.Join(destDir, name)
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no libc.so.6 or libc-*.so found under %s", destDir)
}
