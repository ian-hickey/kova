package cli

import (
	"path/filepath"
	"strings"

	"github.com/ian-hickey/kova/internal/gitsrc"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
)

// gitTrust decides whether a changed artifact is explained by git: a branch switch, pull, rebase
// or stash pop of content the team's repository already holds. Two layers, like any other
// package manager's lock:
//
//  1. The committed project lockfile (./kova.lock at the repository root or the project root)
//     pins the artifact at exactly the hash now on disk. The lock itself must be tracked, clean
//     and on the remote. Covers every project artifact, MCP servers and hooks included: the lock
//     diff is reviewed in the pull request, where `kova verify --ci` already fails a checkout
//     that disagrees with it.
//  2. Without a lock pin, an instruction file that is tracked, identical to HEAD and whose last
//     commit is on a remote-tracking ref. Text only: a server or hook config is a process, and
//     nothing scores it. Local-only commits never qualify, so an agent cannot launder an
//     unobserved write by committing it.
type gitTrust struct {
	home  string
	ix    *gitsrc.Index
	locks map[string]*projectLock // lock path -> parsed (nil when absent or untrusted)
}

// projectLock is a committed kova.lock resolved against the directory it was written in.
type projectLock struct {
	dir    string
	src    *gitsrc.Source
	byPath map[string]*lockfile.Entry // absolute path -> entry
	byKey  map[string]*lockfile.Entry
}

// gitAcceptKinds are the changes git can explain. Removals are already info, scanner kinds carry
// flags that block acceptance anyway, and live tool-list drift has nothing to do with a checkout.
var gitAcceptKinds = map[lockfile.ChangeKind]bool{
	lockfile.ChangeModified: true, lockfile.ChangeAdded: true, lockfile.ChangeHooks: true,
	lockfile.ChangeMCPConfig: true, lockfile.ChangeMCPAdded: true, lockfile.ChangeMemory: true,
	lockfile.ChangeInstructionAdded: true,
}

// newGitTrust collects every path the changes touch (plus the candidate lock files next to them)
// so git is asked once per repository rather than once per file.
func (a *App) newGitTrust(changes []lockfile.Change, live map[string]*lockfile.Entry) *gitTrust {
	var paths []string
	seen := map[string]bool{}
	addPath := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}
	for _, c := range changes {
		if !gitAcceptKinds[c.Kind] {
			continue
		}
		e := live[c.Key]
		if e == nil {
			continue
		}
		if e.Path != "" {
			addPath(e.Path)
		}
		for _, dir := range lockDirs(e) {
			addPath(filepath.Join(dir, projectLockfile))
		}
	}
	return &gitTrust{home: a.Home, ix: gitsrc.New(paths), locks: map[string]*projectLock{}}
}

// lockDirs lists where a committed kova.lock for this entry could live: the repository root and,
// when `kova lock` was run in a sub-project, that project's root.
func lockDirs(e *lockfile.Entry) []string {
	var dirs []string
	add := func(d string) {
		if d == "" {
			return
		}
		d = filepath.Clean(d)
		for _, x := range dirs {
			if x == d {
				return
			}
		}
		dirs = append(dirs, d)
	}
	if e.Path != "" {
		add(gitsrc.RepoRoot(e.Path))
	}
	if e.Project != "" && e.Project != "." {
		add(e.Project)
	}
	return dirs
}

// lock loads and caches the committed lockfile at dir, nil unless it is tracked, clean and on
// the remote.
func (g *gitTrust) lock(dir string) *projectLock {
	path := filepath.Join(dir, projectLockfile)
	if pl, ok := g.locks[path]; ok {
		return pl
	}
	g.locks[path] = nil
	src := g.ix.Trusted(path)
	if src == nil {
		return nil
	}
	lf, err := lockfile.Load(path)
	if err != nil {
		return nil
	}
	pl := &projectLock{dir: dir, src: src, byPath: map[string]*lockfile.Entry{}, byKey: map[string]*lockfile.Entry{}}
	for key, e := range lf.Entries {
		pl.byKey[key] = e
		if strings.HasPrefix(e.Path, "./") {
			pl.byPath[filepath.Clean(filepath.Join(dir, filepath.FromSlash(e.Path[2:])))] = e
		}
	}
	g.locks[path] = pl
	return pl
}

// lockPin returns the committed lock that pins this live entry at its current hash, if any.
func (g *gitTrust) lockPin(key string, live *lockfile.Entry) *projectLock {
	if live == nil || live.Hash == "" {
		return nil
	}
	for _, dir := range lockDirs(live) {
		pl := g.lock(dir)
		if pl == nil {
			continue
		}
		var pe *lockfile.Entry
		if live.Path != "" {
			pe = pl.byPath[filepath.Clean(live.Path)]
		}
		if pe == nil {
			pe = pl.byKey[key]
		}
		if pe != nil && pe.Type == live.Type && pe.Hash == live.Hash {
			return pl
		}
	}
	return nil
}

// fileSource returns the trusted git provenance of an instruction file, or nil.
func (g *gitTrust) fileSource(live *lockfile.Entry) *gitsrc.Source {
	if live == nil || live.Path == "" || !instructionType(live.Type) {
		return nil
	}
	return g.ix.Trusted(live.Path)
}

// describe is the human-readable provenance used in messages and event details.
func describe(src *gitsrc.Source) string {
	if src == nil {
		return ""
	}
	s := src.Commit + " by " + src.Author
	if src.Subject != "" {
		s += ": " + src.Subject
	}
	return s
}

func sourceDetails(src *gitsrc.Source, viaLock bool) map[string]any {
	d := map[string]any{"source": "git"}
	if src != nil {
		d["commit"], d["author"], d["subject"] = src.Commit, src.Author, src.Subject
	}
	if viaLock {
		d["lock"] = true
	}
	return d
}

// gitKnown extends the guard's escape hatches to content that arrived through git: the same two
// layers verify applies, evaluated for one file at a time (the guard only gets here for a file
// that is already unknown or changed, never on the common path). The scanner must be quiet
// about the file, exactly as for an observed edit.
func (a *App) gitKnown(lf *lockfile.Lockfile) func(path, hash string) bool {
	quiet := a.textClean(lf)
	var g *gitTrust
	return func(path, hash string) bool {
		if path == "" || hash == "" {
			return false
		}
		key := harness.InstructionKey(path, a.Home)
		if lf.SeenHashes[hash] == key {
			return quiet(path)
		}
		if g == nil {
			g = &gitTrust{home: a.Home, ix: gitsrc.New(nil), locks: map[string]*projectLock{}}
		}
		live := &lockfile.Entry{Path: path, Hash: hash, Type: lockfile.TypeMemory}
		if parts := strings.SplitN(key, ":", 3); len(parts) == 3 {
			live.Type = lockfile.ArtifactType(parts[1])
		}
		if g.lockPin(key, live) != nil {
			return quiet(path)
		}
		if g.ix.Trusted(path) != nil {
			return quiet(path)
		}
		return false
	}
}
