package harness

import (
	"os"
	"path/filepath"
	"strings"
)

// MainWorktree returns the root of the main checkout when dir is inside a git worktree
// (a checkout whose .git is a file pointing at <main>/.git/worktrees/<name>), the repo root when
// dir is inside an ordinary checkout, and "" when dir is not in a git repository at all.
func MainWorktree(dir string) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		g := filepath.Join(d, ".git")
		if st, err := os.Stat(g); err == nil {
			if st.IsDir() {
				return d
			}
			b, err := os.ReadFile(g)
			if err != nil {
				return ""
			}
			line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "gitdir:"))
			line = filepath.ToSlash(line)
			if i := strings.Index(line, "/.git/worktrees/"); i >= 0 {
				return filepath.FromSlash(line[:i])
			}
			return d
		}
		if d == filepath.Dir(d) {
			return ""
		}
	}
}

// IsWorktreeOf reports whether dir is a secondary git worktree whose main checkout is main.
func IsWorktreeOf(dir, main string) bool {
	m := MainWorktree(dir)
	return m != "" && filepath.Clean(m) != filepath.Clean(dir) && filepath.Clean(m) == filepath.Clean(main)
}
