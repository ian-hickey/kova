// kova — the lockfile for agent tools. See `kova help`.
package main

import (
	"os"

	"github.com/ian-hickey/kova/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
