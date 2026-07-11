package cli

import (
	"fmt"
	"strings"
)

// splitVersionArch splits "2.31-0ubuntu9.9_amd64" into ("2.31-0ubuntu9.9", "amd64").
func splitVersionArch(versionArch string) (version, arch string, err error) {
	idx := strings.LastIndex(versionArch, "_")
	if idx < 0 {
		return "", "", fmt.Errorf("expected <version>_<arch>, got %q", versionArch)
	}
	return versionArch[:idx], versionArch[idx+1:], nil
}

func dirHasLibc(dir string) bool {
	_, err := findMainLibc(dir)
	return err == nil
}
