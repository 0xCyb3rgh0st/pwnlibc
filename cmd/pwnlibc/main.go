// Command pwnlibc is the entry point for the pwnlibc CLI.
package main

import (
	"os"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/cli"
)

// cli.Version is overridden directly at build time via:
//
//	go build -ldflags "-X github.com/0xCyb3rgh0st/pwnlibc/internal/cli.Version=$(git describe --tags)"
//
// main previously held its own `version` copy and assigned it into
// cli.Version at startup, which silently discarded the linked-in value
// every time (main.version was never itself an -X target) -- both the
// Docker image and the GoReleaser binaries were shipping "dev" for every
// release as a result.
func main() {
	os.Exit(cli.Execute())
}
