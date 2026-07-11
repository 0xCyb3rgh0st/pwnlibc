// Package buildsrc compiles glibc from source inside a period-correct
// Ubuntu base image (selected by version, since old glibc releases need an
// old-enough gcc/binutils to build cleanly), driven via `docker run`.
package buildsrc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"

	"pwnlibc/internal/glibcver"
	"pwnlibc/internal/pwnerr"
)

// imageForVersion maps a glibc minor version floor to the Ubuntu release
// whose toolchain built it, so `apt-get source glibc` finds a matching
// source package and the resulting binary matches what a same-version
// challenge binary actually links against.
var imageTable = []struct {
	minVersion string
	image      string
}{
	{"2.19", "ubuntu:14.04"},
	{"2.23", "ubuntu:16.04"},
	{"2.27", "ubuntu:18.04"},
	{"2.31", "ubuntu:20.04"},
	{"2.35", "ubuntu:22.04"},
	{"2.39", "ubuntu:24.04"},
}

// ImageFor returns the best-matching Ubuntu base image tag for a glibc
// version like "2.31" or "2.31-0ubuntu9.9".
func ImageFor(version string) (string, error) {
	target, ok := glibcver.Ordinal(version)
	if !ok {
		return "", pwnerr.New(pwnerr.CodeInvalidInput, fmt.Sprintf("cannot parse glibc version %q", version))
	}

	type row struct {
		floor int
		image string
	}
	rows := make([]row, 0, len(imageTable))
	for _, r := range imageTable {
		floor, ok := glibcver.Ordinal(r.minVersion)
		if !ok {
			continue
		}
		rows = append(rows, row{floor: floor, image: r.image})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].floor < rows[j].floor })

	best := ""
	for _, r := range rows {
		if target >= r.floor {
			best = r.image
		}
	}
	if best == "" {
		return "", pwnerr.New(pwnerr.CodeInvalidInput, fmt.Sprintf("no known Ubuntu base image for glibc %s (too old)", version))
	}
	return best, nil
}

// Options controls a source build.
type Options struct {
	Version string
	Arch    string // amd64, i386 - passed through as dpkg arch for the container
	Prefix  string // install prefix inside the container/output volume
	OutDir  string // host directory bind-mounted to receive the built glibc
	LogW    io.Writer
}

// buildScript is executed inside the selected Ubuntu image. It fetches the
// glibc source package matching the running distro's default glibc version
// family via apt, then configures/builds/installs it to Prefix. This mirrors
// what a from-scratch "reproduce the exact challenge glibc" build looks
// like: same distro, same toolchain, same source package.
const buildScript = `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
dpkg --add-architecture %[3]s || true
apt-get update -qq
apt-get build-dep -y -qq glibc || apt-get install -y -qq build-essential bison gawk texinfo gettext python3
apt-get source -qq glibc
SRC_DIR=$(find . -maxdepth 1 -type d -name 'glibc-*' | head -n1)
if [ -z "$SRC_DIR" ]; then echo "no glibc source directory found after apt-get source" >&2; exit 1; fi
mkdir -p build && cd build
"../$SRC_DIR/configure" --prefix="%[1]s" --enable-add-ons 2>&1 | tee configure.log
make -j"$(nproc)" 2>&1 | tee make.log
make install DESTDIR=/out 2>&1 | tee install.log
echo "BUILD_OK %[2]s"
`

// DockerAvailable checks whether the docker CLI can reach a daemon.
func DockerAvailable(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	if out, err := cmd.CombinedOutput(); err != nil {
		return pwnerr.Wrap(pwnerr.CodeDockerUnavailable, fmt.Sprintf("docker not reachable: %s", strings.TrimSpace(string(out))), err)
	}
	return nil
}

// Build runs the containerized glibc source build. It streams container
// output to opts.LogW as it happens and returns an error if the container
// exits non-zero or never prints the BUILD_OK sentinel.
func Build(ctx context.Context, opts Options) error {
	if err := DockerAvailable(ctx); err != nil {
		return err
	}
	image, err := ImageFor(opts.Version)
	if err != nil {
		return err
	}
	if opts.Prefix == "" {
		opts.Prefix = "/usr"
	}

	script := fmt.Sprintf(buildScript, opts.Prefix, opts.Version, opts.Arch)

	args := []string{
		"run", "--rm",
		"-v", opts.OutDir + ":/out",
		"--platform", "linux/" + dockerArch(opts.Arch),
		image, "bash", "-c", script,
	}
	cmd := exec.CommandContext(ctx, "docker", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout // interleave; build logs are easier to follow in one stream

	if err := cmd.Start(); err != nil {
		return pwnerr.Wrap(pwnerr.CodeDockerUnavailable, "starting build container", err)
	}

	sawOK := false
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if opts.LogW != nil {
			fmt.Fprintln(opts.LogW, line)
		}
		if strings.HasPrefix(line, "BUILD_OK") {
			sawOK = true
		}
	}

	if err := cmd.Wait(); err != nil {
		return pwnerr.Wrap(pwnerr.CodeIO, "glibc source build failed", err)
	}
	if !sawOK {
		return pwnerr.New(pwnerr.CodeIO, "build container exited cleanly but never reported success")
	}
	return nil
}

func dockerArch(arch string) string {
	switch arch {
	case "i386":
		return "386"
	case "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}
