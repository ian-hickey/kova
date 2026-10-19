package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/observed"
	"github.com/ian-hickey/kova/internal/scan"
)

// cmdTouched is the PostToolUse / AfterTool / afterFileEdit hook entrypoint. It records which
// instruction file the agent just wrote and, crucially, checks that the file now contains exactly
// what the tool call DECLARED it would write: the previous observed (or pinned) text with the
// tool's old_string→new_string edits applied, or the Write tool's full content. Only such a
// BOUNDED observation lets verify and the guard treat the change as the agent's own work. If a
// postinstall script had appended to the file first, the declared edit no longer reproduces the
// file and the change is reported like any other unobserved one. Silent, fast, always exits 0.
func (a *App) cmdTouched(args []string) int {
	fs := newFlags("touched")
	harnessName := fs.String("harness", "", "harness that invoked the hook")
	_ = fs.Parse(args)
	data, _ := io.ReadAll(io.LimitReader(a.Stdin, 16<<20))
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
	path := str(ti, "file_path", "notebook_path", "path")
	if path == "" {
		return ExitOK
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if !scan.IsInstructionSurface(path) && !a.isPinnedPath(path) {
		return ExitOK
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		return ExitOK // deleted or unreadable: nothing to observe
	}
	curHash := lockfile.HashBytes(cur)
	edit := declaredEdit(tool, ti)
	bounded := a.reproduces(path, cur, edit)

	log := observed.Open(observed.FilePath())
	log.Record(observed.Touch{Path: path, Hash: curHash, Harness: *harnessName, Session: str(in, "session_id", "conversation_id"), Tool: tool, Bounded: bounded})
	_ = log.Save()
	if bounded {
		// Keep the observed text so the next edit in this session can be bounded against it.
		_ = lockfile.PutBlob(lockfile.BlobsDirFor(lockfilePath()), curHash, cur)
	}
	return ExitOK
}

// declared is what a tool call said it would do to the file.
type declared struct {
	full  *string // Write / write_file: the whole content
	edits []struct {
		old, new string
		all      bool
	}
}

func declaredEdit(tool string, ti map[string]any) declared {
	var d declared
	if c, ok := ti["content"].(string); ok && (tool == "Write" || tool == "write_file" || tool == "" || strings.EqualFold(tool, "write")) {
		d.full = &c
		return d
	}
	add := func(m map[string]any) {
		o, _ := m["old_string"].(string)
		n, _ := m["new_string"].(string)
		all, _ := m["replace_all"].(bool)
		if o != "" || n != "" {
			d.edits = append(d.edits, struct {
				old, new string
				all      bool
			}{o, n, all})
		}
	}
	if arr, ok := ti["edits"].([]any); ok { // MultiEdit, Cursor afterFileEdit
		for _, e := range arr {
			if m, ok := e.(map[string]any); ok {
				add(m)
			}
		}
	} else {
		add(ti) // Edit, Gemini replace
	}
	return d
}

// reproduces checks that applying the declared edit to the last known text yields the file on disk.
func (a *App) reproduces(path string, cur []byte, d declared) bool {
	if d.full != nil {
		return *d.full == string(cur)
	}
	if len(d.edits) == 0 {
		return false // notebook edits, shell writes: no declared edit to bound against
	}
	base, ok := a.lastKnownText(path)
	if !ok {
		return false
	}
	text := string(base)
	for _, e := range d.edits {
		if e.old == "" {
			return false
		}
		if !strings.Contains(text, e.old) {
			return false
		}
		if e.all {
			text = strings.ReplaceAll(text, e.old, e.new)
		} else {
			text = strings.Replace(text, e.old, e.new, 1)
		}
	}
	return text == string(cur)
}

// lastKnownText is the most recent text kova vouches for: the last bounded observation of the
// file in this or a recent session, else the pinned blob.
func (a *App) lastKnownText(path string) ([]byte, bool) {
	dir := lockfile.BlobsDirFor(lockfilePath())
	if t, ok := observed.Open(observed.FilePath()).Latest(path); ok && t.Bounded {
		if b, ok := lockfile.GetBlob(dir, t.Hash); ok {
			return b, true
		}
	}
	if lf, err := a.loadLockfile(); err == nil {
		for _, e := range lf.Entries {
			if e.Path != "" && filepath.Clean(e.Path) == path {
				return lockfile.GetBlob(dir, e.Hash)
			}
		}
	}
	return nil, false
}

func (a *App) isPinnedPath(p string) bool {
	lf, err := a.loadLockfile()
	if err != nil {
		return false
	}
	for _, e := range lf.Entries {
		if e.Path != "" && filepath.Clean(e.Path) == p {
			return true
		}
	}
	return false
}
