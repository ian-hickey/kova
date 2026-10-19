// Package gitsrc answers one question about a file on disk: did its current content arrive
// through git? A file that is tracked, identical to HEAD, and whose last commit is reachable from
// a remote-tracking ref was put there by a checkout, pull, rebase or stash pop of content the
// team's repository already holds, not by an unwatched write on this machine. kova treats such
// content like a lockfile change in any other package manager: the lock travels with the branch.
//
// Everything here shells out to git, so it is only consulted for files that already differ from
// the pin (never on the clean session-start path) and every command has a short timeout. A
// missing git, a repo with no commits, or a repo with no remote makes nothing trusted.
package gitsrc

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Timeout bounds every git invocation.
var Timeout = 3 * time.Second

// Source describes where a clean, tracked file's content came from.
type Source struct {
	Root    string `json:"-"`
	Rel     string `json:"-"`
	Commit  string `json:"commit"`  // abbreviated hash of the last commit that touched the file
	Author  string `json:"author"`  // author name of that commit
	Subject string `json:"subject"` // its subject line, capped
	Remote  bool   `json:"remote"`  // that commit is reachable from a remote-tracking ref
}

// RepoRoot returns the nearest ancestor of path (inclusive) that holds a .git directory or file
// (worktrees and submodules keep a file), or "" when the path is not inside a repository.
func RepoRoot(path string) string {
	d := filepath.Clean(path)
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		d = filepath.Dir(d)
	}
	for {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

// Index resolves git provenance for a batch of paths with as few git invocations as possible:
// one `ls-files` and one `diff --name-only HEAD` per repository, then one `log -1` per path that
// turns out clean and one `branch -r --contains` per distinct commit.
type Index struct {
	roots   map[string]*repoState // repo root -> state
	byPath  map[string]string     // clean path -> repo root ("" when not clean)
	sources map[string]*Source    // clean path -> provenance (lazy)
	remote  map[string]bool       // full commit hash -> reachable from a remote ref
	git     string
}

type repoState struct {
	tracked map[string]bool // rel -> tracked
	dirty   map[string]bool // rel -> differs from HEAD (index or worktree)
	ok      bool            // git answered for this root
}

// New groups paths by repository and runs the per-repo queries. Paths outside any repository,
// or in a repository git cannot answer for, are simply never clean.
func New(paths []string) *Index {
	ix := &Index{roots: map[string]*repoState{}, byPath: map[string]string{}, sources: map[string]*Source{}, remote: map[string]bool{}}
	ix.git, _ = exec.LookPath("git")
	if ix.git == "" {
		return ix
	}
	byRoot := map[string][]string{}
	for _, p := range paths {
		p = filepath.Clean(p)
		if _, seen := ix.byPath[p]; seen {
			continue
		}
		ix.byPath[p] = ""
		root := RepoRoot(p)
		if root == "" {
			continue
		}
		byRoot[root] = append(byRoot[root], p)
	}
	for root, ps := range byRoot {
		st := &repoState{tracked: map[string]bool{}, dirty: map[string]bool{}}
		ix.roots[root] = st
		rels := make([]string, 0, len(ps))
		for _, p := range ps {
			if rel, err := filepath.Rel(root, p); err == nil {
				rels = append(rels, filepath.ToSlash(rel))
			}
		}
		if len(rels) == 0 {
			continue
		}
		lsArgs := append([]string{"ls-files", "-z", "--"}, rels...)
		out, err := ix.run(root, lsArgs...)
		if err != nil {
			continue
		}
		for _, rel := range splitZ(out) {
			st.tracked[rel] = true
		}
		diffArgs := append([]string{"diff", "--name-only", "-z", "HEAD", "--"}, rels...)
		out, err = ix.run(root, diffArgs...)
		if err != nil {
			continue // no HEAD yet (fresh repo): nothing is clean
		}
		for _, rel := range splitZ(out) {
			st.dirty[rel] = true
		}
		st.ok = true
		for _, p := range ps {
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if st.tracked[rel] && !st.dirty[rel] {
				ix.byPath[p] = root
			}
		}
	}
	return ix
}

// Clean reports whether path is tracked and identical to HEAD (index and worktree).
func (ix *Index) Clean(path string) bool {
	return ix != nil && ix.byPath[filepath.Clean(path)] != ""
}

// Source returns the provenance of a clean path, or nil when the path is not clean or git
// could not describe it. Paths not passed to New are resolved on demand.
func (ix *Index) Source(path string) *Source {
	if ix == nil || ix.git == "" {
		return nil
	}
	path = filepath.Clean(path)
	if _, seen := ix.byPath[path]; !seen {
		extra := New([]string{path})
		ix.byPath[path] = extra.byPath[path]
	}
	root := ix.byPath[path]
	if root == "" {
		return nil
	}
	if s, ok := ix.sources[path]; ok {
		return s
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil
	}
	rel = filepath.ToSlash(rel)
	out, err := ix.run(root, "log", "-1", "--format=%H%x00%h%x00%an%x00%s", "--", rel)
	if err != nil {
		ix.sources[path] = nil
		return nil
	}
	parts := strings.SplitN(strings.TrimRight(string(out), "\n"), "\x00", 4)
	if len(parts) < 4 || parts[0] == "" {
		ix.sources[path] = nil
		return nil
	}
	s := &Source{Root: root, Rel: rel, Commit: parts[1], Author: parts[2], Subject: parts[3]}
	if len(s.Subject) > 120 {
		s.Subject = s.Subject[:117] + "…"
	}
	s.Remote = ix.onRemote(root, parts[0])
	ix.sources[path] = s
	return s
}

// Trusted is the bar for accepting content without a human: clean, tracked and already on a
// remote. A local-only commit (an agent committing its own unobserved write, say) does not pass.
func (ix *Index) Trusted(path string) *Source {
	s := ix.Source(path)
	if s == nil || !s.Remote {
		return nil
	}
	return s
}

func (ix *Index) onRemote(root, commit string) bool {
	if v, ok := ix.remote[commit]; ok {
		return v
	}
	out, err := ix.run(root, "branch", "-r", "--contains", commit)
	v := err == nil && strings.TrimSpace(string(out)) != ""
	ix.remote[commit] = v
	return v
}

func (ix *Index) run(root string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ix.git, args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func splitZ(b []byte) []string {
	var out []string
	for _, p := range bytes.Split(b, []byte{0}) {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}
