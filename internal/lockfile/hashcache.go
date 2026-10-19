package lockfile

import (
	"encoding/json"
	"os"
	"sync"
)

// hashCache remembers file hashes keyed by path and a stat signature (size, mtime, ctime, inode),
// the same trick git's index uses, so that re-hashing a few thousand plugin and skill files at
// every session start costs stats instead of reads. A file whose signature changed is re-hashed;
// a file whose content is replaced with the same size and a faked mtime still changes ctime and
// inode on every mainstream filesystem, which is why those are part of the key.
type hashCache struct {
	mu    sync.Mutex
	path  string
	m     map[string]hashEntry
	dirty bool
}

type hashEntry struct {
	Sig  statSig `json:"sig"`
	Hash string  `json:"hash"`
	Size int64   `json:"size"`
}

type statSig struct {
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
	Ctime int64  `json:"ctime"`
	Ino   uint64 `json:"ino"`
}

var cache *hashCache

// EnableHashCache loads (or starts) the cache at path. Call once per process before discovery;
// SaveHashCache writes it back. Without this, HashTree reads every file.
func EnableHashCache(path string) {
	c := &hashCache{path: path, m: map[string]hashEntry{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &c.m)
	}
	cache = c
}

// SaveHashCache persists the cache when anything changed.
func SaveHashCache() {
	c := cache
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return
	}
	if len(c.m) > 50000 { // runaway protection: start over rather than grow without bound
		c.m = map[string]hashEntry{}
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

// hashFileCached is HashFile with the cache in front of it.
func hashFileCached(path string) (string, int64, error) {
	c := cache
	if c == nil {
		return HashFile(path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	sig := sigOf(st)
	c.mu.Lock()
	e, ok := c.m[path]
	c.mu.Unlock()
	if ok && e.Sig == sig {
		return e.Hash, e.Size, nil
	}
	h, n, err := HashFile(path)
	if err != nil {
		return "", 0, err
	}
	c.mu.Lock()
	c.m[path] = hashEntry{Sig: sig, Hash: h, Size: n}
	c.dirty = true
	c.mu.Unlock()
	return h, n, nil
}
