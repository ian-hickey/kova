// Package observed records instruction files the agent edited THROUGH THE HARNESS, so that kova can
// tell an edit the user watched happen (Claude Code's Edit tool writing CLAUDE.md, a memory note
// appended by the agent) from a change nobody saw (a CLAUDE.md that appeared in node_modules after
// an install, hooks rewritten between sessions). The former is routine work and must not block the
// agent or queue an approval; the latter is the supply chain and keeps today's rules.
//
// A PostToolUse hook (`kova touched`) runs after every Edit/Write/MultiEdit/NotebookEdit/Bash call
// and stores the path and the sha256 of the file as it was left. verify and the guard accept a
// pinned file's new content only when it is byte-identical to what an observed call produced: a
// later out-of-band change to the same file no longer matches and is reported as before.
package observed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ian-hickey/kova/internal/store"
)

// MaxAge bounds how long an observation stays valid; MaxEntries bounds the file.
const (
	MaxAge     = 7 * 24 * time.Hour
	MaxEntries = 1000
)

// Touch is one observed write.
type Touch struct {
	Path    string    `json:"path"`
	Hash    string    `json:"hash"` // sha256:<hex> of the file right after the call
	At      time.Time `json:"at"`
	Harness string    `json:"harness,omitempty"`
	Session string    `json:"session,omitempty"`
	Tool    string    `json:"tool,omitempty"`
	// Bounded: the file content equals the previous known text with the tool's DECLARED edit
	// applied (or the Write tool's full content). Only bounded observations are vouched for.
	Bounded bool `json:"bounded"`
}

// FilePath is the default log location (~/.kova/observed.json).
func FilePath() string { return filepath.Join(store.Dir(), "observed.json") }

// Log is the on-disk map of path -> latest observed write.
type Log struct {
	path string
	mu   sync.Mutex
	m    map[string]Touch
}

// Open loads the log at path (missing is fine).
func Open(path string) *Log {
	l := &Log{path: path, m: map[string]Touch{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &l.m)
	}
	return l
}

func clean(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return filepath.Clean(p)
}

// Record stores an observation (latest write per path wins).
func (l *Log) Record(t Touch) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.At.IsZero() {
		t.At = time.Now().UTC()
	}
	t.Path = clean(t.Path)
	l.m[t.Path] = t
}

// Match reports whether path's current content (hash) is exactly what an observed call left there.
func (l *Log) Match(path, hash string) (Touch, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.m[clean(path)]
	if !ok || !t.Bounded || t.Hash != hash || time.Since(t.At) > MaxAge {
		return Touch{}, false
	}
	return t, true
}

// Latest returns the most recent observation for path, bounded or not.
func (l *Log) Latest(path string) (Touch, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.m[clean(path)]
	if !ok || time.Since(t.At) > MaxAge {
		return Touch{}, false
	}
	return t, true
}

// Save writes the log, dropping stale entries and keeping the newest MaxEntries.
func (l *Log) Save() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-MaxAge)
	all := make([]Touch, 0, len(l.m))
	for _, t := range l.m {
		if t.At.After(cutoff) {
			all = append(all, t)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].At.After(all[j].At) })
	if len(all) > MaxEntries {
		all = all[:MaxEntries]
	}
	l.m = map[string]Touch{}
	for _, t := range all {
		l.m[t.Path] = t
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(l.m)
	if err != nil {
		return err
	}
	return os.WriteFile(l.path, data, 0o600)
}
