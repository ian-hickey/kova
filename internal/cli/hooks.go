package cli

import (
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/hooks"
)

func (a *App) cmdHooks(args []string) int {
	if len(args) == 0 {
		return a.errorf("usage: kova hooks install|uninstall|status [--harness h]")
	}
	fs := newFlags("hooks")
	h := fs.String("harness", "", "limit to one harness")
	if err := fs.Parse(args[1:]); err != nil {
		return a.errorf("%v", err)
	}
	targets := harness.Present(a.Home)
	if *h != "" {
		targets = []string{*h}
	}
	var (
		res []hooks.Status
		err error
	)
	switch args[0] {
	case "install":
		res, err = hooks.Install(a.Home, kovaBin(), targets)
	case "uninstall", "remove":
		res, err = hooks.Uninstall(a.Home, kovaBin(), targets)
	case "status":
		res = hooks.Check(a.Home, kovaBin())
	default:
		return a.errorf("unknown hooks subcommand %q", args[0])
	}
	if err != nil {
		return a.errorf("%v", err)
	}
	if a.JSON {
		a.json(res)
		return ExitOK
	}
	if args[0] == "uninstall" || args[0] == "remove" {
		for _, r := range res {
			if r.Supported && r.File != "" {
				a.printf("  ✓ %-12s kova hooks removed from %s\n", r.Harness, r.File)
			}
		}
		return ExitOK
	}
	for _, r := range res {
		switch {
		case r.Installed:
			a.printf("  ✓ %-12s %s\n", r.Harness, r.File)
		case !r.Supported:
			a.printf("  – %-12s %s\n", r.Harness, r.Note)
		case r.Note != "":
			a.printf("  – %-12s %s\n", r.Harness, r.Note)
		default:
			a.printf("  ✗ %-12s not installed\n", r.Harness)
		}
	}
	return ExitOK
}
