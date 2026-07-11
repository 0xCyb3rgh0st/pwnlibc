package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hostPath translates a path as seen inside the pwnlibc container back to
// its equivalent path on the Docker host. This is required because `build`
// and `run` shell out to `docker run` against the *host* daemon (via the
// mounted socket) — bind-mount sources in that call are resolved by the
// host daemon, not from pwnlibc's own container filesystem view. The
// docker-compose.yml `cli` and `build-src` services export HOST_LIBS_DIR /
// HOST_WORKDIR_DIR (derived from ${PWD}) precisely so this translation is
// possible; only paths under /data/libs or /data/workdir are reachable this
// way, which is why `run`/`patch` document dropping challenge files into
// ./workdir.
func hostPath(containerPath string) (string, error) {
	abs, err := filepath.Abs(containerPath)
	if err != nil {
		return "", err
	}
	if rel, ok := underRoot(abs, "/data/libs", os.Getenv("HOST_LIBS_DIR")); ok {
		return rel, nil
	}
	if rel, ok := underRoot(abs, "/data/workdir", os.Getenv("HOST_WORKDIR_DIR")); ok {
		return rel, nil
	}
	return "", fmt.Errorf(
		"%q is outside /data/libs and /data/workdir; nested docker mounts (used by `build`/`run`) can only reach files under those paths. "+
			"Drop challenge binaries into ./workdir on the host (mounted at /data/workdir).", containerPath)
}

func underRoot(abs, containerRoot, hostRoot string) (string, bool) {
	if hostRoot == "" {
		return "", false
	}
	if abs != containerRoot && !strings.HasPrefix(abs, containerRoot+string(filepath.Separator)) {
		return "", false
	}
	rel, err := filepath.Rel(containerRoot, abs)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return hostRoot, true
	}
	return filepath.ToSlash(filepath.Join(hostRoot, rel)), true
}
