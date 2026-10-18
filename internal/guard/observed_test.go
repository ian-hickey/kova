package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateWithObservedEdits(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "CLAUDE.md")
	_ = os.WriteFile(f, []byte("# rules\n"), 0o600)
	req := Request{Tool: "Read", Paths: []string{f}, CWD: root}
	// Pinned with a stale hash: denied by default.
	pins := Pins{f: "sha256:stale"}
	if d := Evaluate(req, pins, root); d.Allow {
		t.Fatal("changed file must be denied without an observation")
	}
	// The same state, but the current content was produced by an observed tool call: allowed.
	seen := func(path, hash string) bool { return path == f && strings.HasPrefix(hash, "sha256:") }
	if d := EvaluateWith(req, pins, root, seen); !d.Allow {
		t.Fatalf("observed edit should be allowed: %s", d.Reason)
	}
	// Unknown file (not pinned at all) that the agent just created: allowed too.
	if d := EvaluateWith(req, Pins{}, root, seen); !d.Allow {
		t.Fatalf("observed new file should be allowed: %s", d.Reason)
	}
	// An observation for different content (out-of-band change since) does not help.
	if d := EvaluateWith(req, pins, root, func(string, string) bool { return false }); d.Allow {
		t.Fatal("non-matching observation must still deny")
	}
}

func TestWriteTargets(t *testing.T) {
	cwd := "/work/proj"
	got := WriteTargets("cat README.md && printf 'x' > CLAUDE.md; cp a.txt .claude/rules/x.md", cwd)
	want := map[string]bool{"/work/proj/CLAUDE.md": true, "/work/proj/.claude/rules/x.md": true}
	for _, g := range got {
		delete(want, g)
	}
	if len(want) != 0 {
		t.Fatalf("missing targets %v in %v", want, got)
	}
	for _, g := range got {
		if strings.HasSuffix(g, "README.md") {
			t.Fatalf("a read-only mention must not be a write target: %v", got)
		}
	}
	if len(WriteTargets("ls -la ~/.kova && cat CLAUDE.md", cwd)) != 0 {
		t.Fatal("no write verb: no targets")
	}
}
