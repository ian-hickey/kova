package gitsrc

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test Author", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=Test Author", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// A repo with a bare "origin": content pushed there is trusted, a local-only commit is clean but
// not trusted, an edited working copy is not clean, an untracked file is nothing.
func TestIndexTrust(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	remote := filepath.Join(base, "origin.git")
	git(t, base, "init", "--bare", "-q", remote)
	repo := filepath.Join(base, "repo")
	git(t, base, "init", "-q", "-b", "main", repo)
	git(t, repo, "remote", "add", "origin", remote)
	claude := filepath.Join(repo, "CLAUDE.md")
	_ = os.WriteFile(claude, []byte("# one\n"), 0o600)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "docs: first")
	git(t, repo, "push", "-q", "-u", "origin", "main")

	if RepoRoot(claude) != repo {
		t.Fatalf("RepoRoot(%s) = %q", claude, RepoRoot(claude))
	}
	if RepoRoot(filepath.Join(base, "nowhere", "x")) != "" {
		t.Fatal("a path outside any repo must have no root")
	}

	ix := New([]string{claude})
	if !ix.Clean(claude) {
		t.Fatal("committed and pushed file should be clean")
	}
	src := ix.Trusted(claude)
	if src == nil || src.Author != "Test Author" || src.Subject != "docs: first" || !src.Remote {
		t.Fatalf("expected a trusted source, got %+v", src)
	}

	// Local-only commit: clean, but not on the remote → not trusted.
	_ = os.WriteFile(claude, []byte("# two\n"), 0o600)
	git(t, repo, "commit", "-q", "-am", "local only")
	ix = New([]string{claude})
	if !ix.Clean(claude) {
		t.Fatal("committed file should be clean")
	}
	if s := ix.Source(claude); s == nil || s.Remote {
		t.Fatalf("local commit must not be on the remote: %+v", s)
	}
	if ix.Trusted(claude) != nil {
		t.Fatal("local-only commit must not be trusted")
	}
	git(t, repo, "push", "-q", "origin", "main")
	if New([]string{claude}).Trusted(claude) == nil {
		t.Fatal("after push the same content is trusted")
	}

	// Dirty working copy: not clean.
	_ = os.WriteFile(claude, []byte("# two\nextra\n"), 0o600)
	if New([]string{claude}).Clean(claude) {
		t.Fatal("edited file must not be clean")
	}
	// Staged but uncommitted: still not clean (differs from HEAD).
	git(t, repo, "add", "CLAUDE.md")
	if New([]string{claude}).Clean(claude) {
		t.Fatal("staged edit must not be clean")
	}
	git(t, repo, "checkout", "-q", "HEAD", "--", "CLAUDE.md")
	git(t, repo, "reset", "-q")

	// Untracked file: not clean, no source.
	agents := filepath.Join(repo, "AGENTS.md")
	_ = os.WriteFile(agents, []byte("x\n"), 0o600)
	ix = New([]string{claude, agents})
	if ix.Clean(agents) || ix.Source(agents) != nil {
		t.Fatal("untracked file must not be clean")
	}
	if !ix.Clean(claude) {
		t.Fatal("the tracked file in the same batch is still clean")
	}
	// On-demand resolution of a path not passed to New.
	if New(nil).Trusted(claude) == nil {
		t.Fatal("Source should resolve paths lazily")
	}
}

// Branch switch: the file content changes to what the other branch (on the remote) holds.
func TestBranchSwitchIsTrusted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	remote := filepath.Join(base, "origin.git")
	git(t, base, "init", "--bare", "-q", remote)
	repo := filepath.Join(base, "repo")
	git(t, base, "init", "-q", "-b", "main", repo)
	git(t, repo, "remote", "add", "origin", remote)
	claude := filepath.Join(repo, "CLAUDE.md")
	_ = os.WriteFile(claude, []byte("main\n"), 0o600)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "main")
	git(t, repo, "push", "-q", "-u", "origin", "main")
	git(t, repo, "checkout", "-q", "-b", "feature")
	_ = os.WriteFile(claude, []byte("feature\n"), 0o600)
	git(t, repo, "commit", "-q", "-am", "feat: feature rules")
	git(t, repo, "push", "-q", "-u", "origin", "feature")
	git(t, repo, "checkout", "-q", "main")
	git(t, repo, "checkout", "-q", "feature")
	src := New([]string{claude}).Trusted(claude)
	if src == nil || src.Subject != "feat: feature rules" {
		t.Fatalf("expected trusted feature content, got %+v", src)
	}
}
