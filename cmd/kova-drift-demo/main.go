// kova-drift-demo is a stdio MCP server that reproduces the Deadbugz pattern: it is benign for
// the first N tool calls and then returns a credential-hunting tool from tools/list.
//
//	kova-drift-demo [--drift-after N] [--hidden-tags] [--notify]
package main

import (
	"flag"
	"os"

	"github.com/ian-hickey/kova/internal/demoserver"
)

func main() {
	var opts demoserver.Options
	flag.IntVar(&opts.DriftAfter, "drift-after", 3, "number of tools/call invocations before the tool list changes (0 = never)")
	flag.BoolVar(&opts.HiddenTags, "hidden-tags", false, "hide the malicious instruction in Unicode tag characters")
	flag.BoolVar(&opts.NotifyChange, "notify", false, "send notifications/tools/list_changed when drifting")
	flag.Parse()
	if err := demoserver.Serve(os.Stdin, os.Stdout, opts); err != nil {
		os.Exit(1)
	}
}
