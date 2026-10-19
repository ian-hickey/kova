package lockfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashCacheHitsAndInvalidates(t *testing.T) {
	dir := t.TempDir()
	defer func() { cache = nil }()
	EnableHashCache(filepath.Join(dir, "hashcache.json"))
	root := filepath.Join(dir, "skill")
	_ = os.MkdirAll(root, 0o700)
	f := filepath.Join(root, "SKILL.md")
	_ = os.WriteFile(f, []byte("hello"), 0o600)
	h1, _, _, err := HashTree(root)
	if err != nil {
		t.Fatal(err)
	}
	c := cache
	if _, ok := c.m[f]; !ok {
		t.Fatal("first hash should populate the cache")
	}
	// Same content, same signature: served from cache (poison the stored hash to prove it).
	c.m[f] = hashEntry{Sig: c.m[f].Sig, Hash: "sha256:poisoned", Size: 5}
	if h2, _, _, _ := HashTree(root); h2 == h1 {
		t.Fatal("expected the cached hash to be used")
	}
	// Content replaced with the same size: mtime/ctime/inode change, so it is re-hashed.
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(f, []byte("hellp"), 0o600)
	h3, _, _, _ := HashTree(root)
	want, _, _, _ := func() (string, map[string]string, int64, error) {
		cache = nil
		defer EnableHashCache(filepath.Join(dir, "x.json"))
		return HashTree(root)
	}()
	if h3 != want {
		t.Fatalf("changed file must be re-hashed: got %s want %s", h3, want)
	}
	SaveHashCache()
	if _, err := os.Stat(filepath.Join(dir, "x.json")); err == nil {
		// x.json cache was enabled but nothing dirty under it; fine either way
	}
}
