package cli

import (
	"path/filepath"
	"strings"

	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/lockfile"
)

// migrateProjectKeys renames machine-lockfile entries whose names predate the current key
// format: pre-v0.1.4 "./x" names (which collided across projects and worktrees) and pre-v0.1.5
// Windows names written with backslashes ("~\\workspace\\x"). Both become the home-relative,
// forward-slash name. When the new key is already pinned (a later version re-pinned the same
// file under the new name) the stale key is dropped and the older first-seen time kept, so the
// same artifact is never reported as removed under one spelling and added under another.
// Returns true when anything changed.
func (a *App) migrateProjectKeys(lf *lockfile.Lockfile) bool {
	changed := false
	for key, e := range lf.Entries {
		if e.Path == "" || !(strings.HasPrefix(e.Name, "./") || strings.Contains(e.Name, "\\")) {
			continue
		}
		newName := a.tilde(e.Path)
		newKey := lockfile.Key(e.Harness, e.Type, newName)
		if newKey == key {
			continue
		}
		if cur, exists := lf.Entries[newKey]; !exists {
			e.Name = newName
			lf.Entries[newKey] = e
		} else if !e.FirstSeen.IsZero() && (cur.FirstSeen.IsZero() || e.FirstSeen.Before(cur.FirstSeen)) {
			cur.FirstSeen = e.FirstSeen
		}
		delete(lf.Entries, key)
		changed = true
	}
	return changed
}

// worktreeTwin finds, for a live project-scoped file inside a secondary git worktree, the pinned
// entry for the same relative file in the main checkout. Nil when not in a worktree, when the
// main checkout is not pinned, or when the file has no counterpart.
func (a *App) worktreeTwin(lf *lockfile.Lockfile, live *lockfile.Entry) *lockfile.Entry {
	if live == nil || live.Path == "" || live.Project == "" {
		return nil
	}
	main := harness.MainWorktree(live.Project)
	if main == "" || filepath.Clean(main) == filepath.Clean(live.Project) {
		return nil
	}
	rel, err := filepath.Rel(live.Project, live.Path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil
	}
	twinKey := lockfile.Key(live.Harness, live.Type, a.tilde(filepath.Join(main, rel)))
	return lf.Entries[twinKey]
}

// worktreePins extends the guard's known-file set: inside a secondary worktree, every pinned
// instruction file of the main checkout is also known at the corresponding worktree path, with
// the same hash. Identical files pass; edited or extra ones are still unknown/changed.
func worktreePins(pins map[string]string, root string) {
	main := harness.MainWorktree(root)
	if main == "" || filepath.Clean(main) == filepath.Clean(root) {
		return
	}
	prefix := filepath.Clean(main) + string(filepath.Separator)
	for p, h := range pins {
		if strings.HasPrefix(p, prefix) {
			wp := filepath.Join(root, strings.TrimPrefix(p, prefix))
			if _, ok := pins[wp]; !ok {
				pins[wp] = h
			}
		}
	}
}
