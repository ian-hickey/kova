package scan

import (
	"encoding/json"
	"os"
	"sync"
)

// Scan results cached by content hash. A plugin or skill tree whose tree hash has not changed
// cannot produce different findings, so re-reading and regex-scanning its files at every session
// start is wasted work (it was ~75% of kova's session-start time on a machine with a dozen
// plugins). Keyed by hash, never by path, so a moved or copied tree is still scanned once.
type scanCache struct {
	mu    sync.Mutex
	path  string
	m     map[string][]Finding
	dirty bool
}

var cache *scanCache

// EnableCache loads (or starts) the findings cache at path.
func EnableCache(path string) {
	c := &scanCache{path: path, m: map[string][]Finding{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &c.m)
	}
	cache = c
}

// SaveCache persists the cache when anything changed.
func SaveCache() {
	c := cache
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return
	}
	if len(c.m) > 5000 {
		c.m = map[string][]Finding{}
	}
	data, err := json.Marshal(c.m)
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, c.path)
	}
	c.dirty = false
}

// TreeCached is Tree with the cache in front of it; key is the tree's content hash.
func TreeCached(root, key string) ([]Finding, error) {
	c := cache
	if c == nil || key == "" {
		return Tree(root)
	}
	c.mu.Lock()
	fs, ok := c.m[key]
	c.mu.Unlock()
	if ok {
		out := make([]Finding, len(fs))
		copy(out, fs)
		return out, nil
	}
	fs, err := Tree(root)
	if err != nil {
		return fs, err
	}
	c.mu.Lock()
	stored := make([]Finding, len(fs))
	copy(stored, fs)
	if stored == nil {
		stored = []Finding{}
	}
	c.m[key] = stored
	c.dirty = true
	c.mu.Unlock()
	return fs, nil
}
