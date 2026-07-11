package cli

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"pwnlibc/internal/buildsrc"
	"pwnlibc/internal/mirrors"
)

// Check is one doctor diagnostic result.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Self-check: Docker reachability, disk space, mirror reachability, cache integrity",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := runDoctorChecks(cmd.Context())
			allOK := true
			for _, c := range checks {
				if !c.OK {
					allOK = false
				}
			}
			app.EmitResult(map[string]interface{}{"ok": allOK, "checks": checks}, func() {
				for _, c := range checks {
					status := "OK  "
					if !c.OK {
						status = "FAIL"
					}
					fmt.Printf("[%s] %-24s %s\n", status, c.Name, c.Detail)
				}
			})
			if !allOK {
				return fmt.Errorf("one or more checks failed")
			}
			return nil
		},
	}
}

func runDoctorChecks(ctx context.Context) []Check {
	var checks []Check

	if err := buildsrc.DockerAvailable(ctx); err != nil {
		checks = append(checks, Check{"docker-socket", false, "not reachable (only needed for `build`/`run`): " + err.Error()})
	} else {
		checks = append(checks, Check{"docker-socket", true, "reachable"})
	}

	checks = append(checks, Check{"libs-dir", dirWritable(app.Config.LibsDir), app.Config.LibsDir})
	checks = append(checks, Check{"cache-dir", dirWritable(app.Config.CacheDir), app.Config.CacheDir})

	if free, err := freeBytes(app.Config.LibsDir); err == nil {
		ok := free > 500*1024*1024
		detail := fmt.Sprintf("%.1f MiB free", float64(free)/(1024*1024))
		checks = append(checks, Check{"disk-space", ok, detail})
	}

	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	reachable := 0
	for _, m := range app.Registry.All() {
		if err := mirrors.Probe(probeCtx, m, 5*time.Second); err == nil {
			reachable++
		}
	}
	checks = append(checks, Check{"mirrors", reachable > 0, fmt.Sprintf("%d/%d reachable", reachable, len(app.Registry.All()))})

	idx, err := app.OpenIndex()
	if err != nil {
		checks = append(checks, Check{"local-index", false, err.Error()})
	} else {
		versions, verr := idx.AllVersions()
		_ = idx.Close()
		checks = append(checks, Check{"local-index", verr == nil, fmt.Sprintf("%d versions indexed", len(versions))})
	}

	return checks
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".pwnlibc-doctor-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func freeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
