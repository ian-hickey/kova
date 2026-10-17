package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
)

const projectLockfile = "kova.lock"

// cmdLock writes a project-scoped lockfile (./kova.lock) meant to be committed: every instruction
// file, MCP config and hook config inside the repo, keyed by relative path, independent of the
// developer's machine. `kova verify --ci` checks a checkout against it.
func (a *App) cmdLock(args []string) int {
	fs := newFlags("lock")
	out := fs.String("out", projectLockfile, "where to write the project lockfile")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	res, err := harness.Discover(harness.Options{Home: a.Home, CWD: a.CWD, KovaBinary: kovaBin(), AllHarnesses: true})
	if err != nil {
		return a.errorf("%v", err)
	}
	lf := projectEntries(res, a.CWD)
	lf.Generator = generator()
	path := *out
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.CWD, path)
	}
	if err := lf.Save(path); err != nil {
		return a.errorf("%v", err)
	}
	if a.JSON {
		a.json(map[string]any{"path": path, "entries": len(lf.Entries)})
		return ExitOK
	}
	a.printf("Wrote %s with %d project artifacts. Commit it; `kova verify --ci` fails a checkout that adds or changes any of them.\n", path, len(lf.Entries))
	for _, k := range lf.SortedKeys() {
		a.printf("  %s\n", k)
	}
	return ExitOK
}

// projectEntries keeps only artifacts that live inside the project tree, with machine-neutral keys.
func projectEntries(res *harness.Result, cwd string) *lockfile.Lockfile {
	lf := lockfile.New(generator())
	lf.MachineID = "project"
	lf.Projects = []string{"."}
	for key, e := range res.Entries {
		if e.Scope != "project" && e.Scope != harness.ScopeDescendant {
			continue
		}
		if e.Path == "" || !strings.HasPrefix(e.Path, cwd+string(filepath.Separator)) {
			continue
		}
		cp := *e
		cp.Path = "./" + filepath.ToSlash(strings.TrimPrefix(e.Path, cwd+string(filepath.Separator)))
		cp.Project = "."
		cp.Approved = true
		// Key is already display-relative ("./…") for project artifacts.
		lf.Entries[key] = &cp
	}
	return lf
}

// verifyCI compares the checkout at a.CWD against ./kova.lock. Strict: no auto-accept.
func (a *App) verifyCI(lockPath string) int {
	if !filepath.IsAbs(lockPath) {
		lockPath = filepath.Join(a.CWD, lockPath)
	}
	pinned, err := lockfile.Load(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return a.errorf("no %s in %s — run `kova lock` and commit it", projectLockfile, a.CWD)
		}
		return a.errorf("%v", err)
	}
	res, err := harness.Discover(harness.Options{Home: a.Home, CWD: a.CWD, KovaBinary: kovaBin(), AllHarnesses: true})
	if err != nil {
		return a.errorf("%v", err)
	}
	live := projectEntries(res, a.CWD)
	changes := lockfile.Diff(pinned.Entries, live.Entries, map[string]bool{".": true})
	if a.JSON {
		a.json(map[string]any{"lockfile": lockPath, "entries": len(pinned.Entries), "changes": changes, "status": map[bool]string{true: "clean", false: "drift"}[len(changes) == 0]})
	} else if len(changes) == 0 {
		a.printf("✓ CI: %d project artifacts match %s\n", len(pinned.Entries), filepath.Base(lockPath))
	} else {
		a.printf("✗ CI: %d change(s) to agent instruction/config files in this checkout\n\n", len(changes))
		for _, c := range changes {
			a.printf("  [%-8s] %-26s %s\n             %s\n", c.Severity, c.Kind, c.Key, c.Message)
		}
		a.printf("\nIf intended, run `kova lock` locally, review the diff of %s, and commit it with the change.\n", projectLockfile)
	}
	if len(changes) > 0 {
		return ExitDrift
	}
	return ExitOK
}

var _ = fmt.Sprint
var _ = time.Now
