package cli

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/ian-hickey/kova/internal/guard"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/observed"
	"github.com/ian-hickey/kova/internal/scan"
)

// cmdTouched is the PostToolUse / AfterTool / afterFileEdit hook entrypoint. It records which
// instruction files the agent just wrote (and their resulting hash) so verify and the guard can
// treat those edits as observed work rather than unreviewed drift. Silent, fast, always exits 0.
func (a *App) cmdTouched(args []string) int {
	fs := newFlags("touched")
	harnessName := fs.String("harness", "", "harness that invoked the hook")
	_ = fs.Parse(args)
	data, _ := io.ReadAll(io.LimitReader(a.Stdin, 8<<20))
	var in map[string]any
	_ = json.Unmarshal(data, &in)
	str := func(m map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	cwd := str(in, "cwd", "workspace_root")
	if cwd == "" {
		cwd = a.CWD
	}
	tool := str(in, "tool_name")
	ti, _ := in["tool_input"].(map[string]any)
	if ti == nil {
		ti = in // Cursor puts fields at the top level
	}
	var paths []string
	for _, k := range []string{"file_path", "notebook_path", "path"} {
		if v := str(ti, k); v != "" {
			paths = append(paths, v)
		}
	}
	if cmd := str(ti, "command"); cmd != "" {
		paths = append(paths, guard.WriteTargets(cmd, cwd)...)
	}
	if len(paths) == 0 {
		return ExitOK
	}

	// Only files kova cares about: instruction surfaces by name, or anything already pinned.
	var pinned map[string]bool
	isPinned := func(p string) bool {
		if pinned == nil {
			pinned = map[string]bool{}
			if lf, err := a.loadLockfile(); err == nil {
				for _, e := range lf.Entries {
					if e.Path != "" {
						pinned[filepath.Clean(e.Path)] = true
					}
				}
			}
		}
		return pinned[filepath.Clean(p)]
	}
	log := observed.Open(observed.FilePath())
	recorded := false
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		p = filepath.Clean(p)
		if !scan.IsInstructionSurface(p) && !isPinned(p) {
			continue
		}
		h, _, err := lockfile.HashFile(p)
		if err != nil {
			continue // deleted or unreadable: nothing to observe
		}
		log.Record(observed.Touch{Path: p, Hash: h, Harness: *harnessName, Session: str(in, "session_id", "conversation_id"), Tool: tool})
		recorded = true
	}
	if recorded {
		_ = log.Save()
	}
	return ExitOK
}
