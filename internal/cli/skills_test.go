package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	kovaskill "github.com/ian-hickey/kova/skills/kova-verify"
)

func TestSkillsRefreshRewritesStaleCopiesAndRepins(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{}}`), 0o600)
	_ = os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{}`), 0o600)
	stale := filepath.Join(home, ".claude", "skills", "kova-verify")
	_ = os.MkdirAll(stale, 0o700)
	_ = os.WriteFile(filepath.Join(stale, "SKILL.md"), []byte("---\nname: kova-verify\ndescription: old\n---\n# old text\n"), 0o644)
	other := filepath.Join(home, ".claude", "skills", "graphify")
	_ = os.MkdirAll(other, 0o700)
	_ = os.WriteFile(filepath.Join(other, "SKILL.md"), []byte("---\nname: graphify\n---\nleave me\n"), 0o644)
	t.Setenv("KOVA_HOME", filepath.Join(home, ".kova"))
	t.Setenv("HOME", home)
	t.Setenv("PATH", home) // no `claude` CLI
	var out, errb bytes.Buffer
	a := &App{Stdout: &out, Stderr: &errb, Home: home, CWD: home}
	if code := a.cmdInit([]string{"--no-hooks", "--no-mcp"}); code != ExitOK {
		t.Fatalf("init: %s %s", out.String(), errb.String())
	}
	// init already refreshed it; make it stale again to exercise the command on its own.
	_ = os.WriteFile(filepath.Join(stale, "SKILL.md"), []byte("---\nname: kova-verify\n---\nstale again\n"), 0o644)
	if code := a.cmdSkills([]string{"refresh"}); code != ExitOK {
		t.Fatalf("skills refresh: %s", errb.String())
	}
	got, _ := os.ReadFile(filepath.Join(stale, "SKILL.md"))
	if string(got) != kovaskill.SkillMD {
		t.Fatal("stale skill copy was not rewritten from the embedded text")
	}
	if g, _ := os.ReadFile(filepath.Join(other, "SKILL.md")); string(g) != "---\nname: graphify\n---\nleave me\n" {
		t.Fatal("other skills must be untouched")
	}
	// The rewrite is kova's own action: verify is clean afterwards (re-pinned, no drift).
	r, err := a.runVerify(false, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "clean" {
		t.Fatalf("skill refresh must not register as drift: %+v", r.Changes)
	}
}
