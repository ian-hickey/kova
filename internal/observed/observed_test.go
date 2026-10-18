package observed

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordMatchAndPrune(t *testing.T) {
	dir := t.TempDir()
	l := Open(filepath.Join(dir, "observed.json"))
	f := filepath.Join(dir, "CLAUDE.md")
	l.Record(Touch{Path: f, Hash: "sha256:a", Tool: "Edit"})
	if _, ok := l.Match(f, "sha256:a"); !ok {
		t.Fatal("expected a match on the observed hash")
	}
	if _, ok := l.Match(f, "sha256:b"); ok {
		t.Fatal("a different hash (out-of-band change) must not match")
	}
	if _, ok := l.Match(filepath.Join(dir, "other.md"), "sha256:a"); ok {
		t.Fatal("other paths must not match")
	}
	// Stale observations expire.
	l.Record(Touch{Path: f, Hash: "sha256:a", At: time.Now().Add(-MaxAge - time.Hour)})
	if _, ok := l.Match(f, "sha256:a"); ok {
		t.Fatal("stale observation must not match")
	}
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	if n := len(Open(l.path).m); n != 0 {
		t.Fatalf("stale entries should be pruned on save, got %d", n)
	}
	l.Record(Touch{Path: f, Hash: "sha256:c"})
	_ = l.Save()
	if _, ok := Open(l.path).Match(f, "sha256:c"); !ok {
		t.Fatal("observation did not persist")
	}
}
