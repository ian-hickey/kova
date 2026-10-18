package harness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMainWorktree(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "repo")
	wt := filepath.Join(root, "repo-feature")
	_ = os.MkdirAll(filepath.Join(main, ".git", "worktrees", "feature"), 0o755)
	_ = os.MkdirAll(filepath.Join(wt, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+filepath.Join(main, ".git", "worktrees", "feature")+"\n"), 0o644)

	if got := MainWorktree(filepath.Join(wt, "sub")); got != main {
		t.Fatalf("worktree should resolve to main checkout: got %q want %q", got, main)
	}
	if got := MainWorktree(main); got != main {
		t.Fatalf("main checkout resolves to itself: got %q", got)
	}
	if got := MainWorktree(root); got != "" {
		t.Fatalf("non-repo dir should resolve to empty: got %q", got)
	}
	if !IsWorktreeOf(wt, main) || IsWorktreeOf(main, main) {
		t.Fatalf("IsWorktreeOf wrong")
	}
}
