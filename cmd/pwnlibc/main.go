// Command pwnlibc is the entry point for the pwnlibc CLI.
package main

import (
	"os"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/cli"
)

// version is overridden at build time via:
//
//	go build -ldflags "-X github.com/0xCyb3rgh0st/pwnlibc/internal/cli.Version=$(git describe --tags)"
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Execute())
}
