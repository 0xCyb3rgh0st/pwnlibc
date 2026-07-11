// Command pwnlibc is the entry point for the pwnlibc CLI.
package main

import (
	"os"

	"pwnlibc/internal/cli"
)

// version is overridden at build time via:
//
//	go build -ldflags "-X pwnlibc/internal/cli.Version=$(git describe --tags)"
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Execute())
}
