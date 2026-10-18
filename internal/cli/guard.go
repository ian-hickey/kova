package cli

import (
	"encoding/json"
	"fmt"
	"github.com/ian-hickey/kova/internal/harness"
	"github.com/ian-hickey/kova/internal/hooks"
	"github.com/ian-hickey/kova/internal/store"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/guard"
	"github.com/ian-hickey/kova/internal/lockfile"
)

// cmdGuard is the PreToolUse / BeforeTool / beforeReadFile hook: it denies tool calls that would
// make the harness load an unreviewed instruction file. It must be fast and must fail open on
// its own errors (a broken guard should never lock a developer out of their editor).
func (a *App) cmdGuard(args []string) int {
	fs := newFlags("guard")
	harnessName := fs.String("harness", "", "harness invoking the hook")
	_ = fs.Parse(args)
	if *harnessName != "" && !hookDialects[*harnessName] {
		return a.errorf("guard --harness %s: no hook dialect for this harness (kova installs hooks for %s)", *harnessName, strings.Join(hookDialectNames(), ", "))
	}

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
		if roots, ok := in["workspace_roots"].([]any); ok && len(roots) > 0 {
			cwd, _ = roots[0].(string)
		}
	}
	if cwd == "" {
		cwd = a.CWD
	}
	req := guard.Request{Tool: str(in, "tool_name"), CWD: cwd}
	if req.Tool == "" {
		req.Tool = map[string]string{lockfile.HarnessCursor: "read_file"}[*harnessName]
		if req.Tool == "" {
			req.Tool = "tool"
		}
	}
	ti, _ := in["tool_input"].(map[string]any)
	if ti == nil {
		ti = in // Cursor puts fields at the top level
	}
	for _, k := range []string{"file_path", "path", "notebook_path", "directory", "dir_path"} {
		if v := str(ti, k); v != "" {
			req.Paths = append(req.Paths, v)
		}
	}
	if arr, ok := ti["paths"].([]any); ok {
		for _, p := range arr {
			if s, ok := p.(string); ok {
				req.Paths = append(req.Paths, s)
			}
		}
	}
	if arr, ok := ti["edits"].([]any); ok && len(arr) > 0 { // MultiEdit carries file_path at top level; nothing extra
		_ = arr
	}
	req.Command = str(ti, "command")
	if req.Tool == "Glob" || req.Tool == "Grep" || req.Tool == "glob" || req.Tool == "search_file_content" {
		if len(req.Paths) == 0 {
			req.Paths = append(req.Paths, cwd)
		}
	}

	if t := guard.CheckTamper(req, store.Dir(), hooks.HookFiles(a.Home, cwd)); t.Blocked {
		_ = cloud.RecordEvent(cloud.EventRecord{
			Source: "guard", Kind: lockfile.ChangeTamperBlocked, Severity: lockfile.SevHigh, Harness: *harnessName,
			Key: "guard:tamper", Name: t.Target, Message: "guard denied an agent attempt to change kova state, hook wiring or approvals",
			Details: map[string]any{"tool": req.Tool, "paths": req.Paths, "command": ledgerExcerpt(req.Command), "target": t.Target, "cwd": cwd},
		})
		if lf, err := a.loadLockfile(); err == nil {
			go a.bestEffortSync(lf, nil, "drift", false, 2*time.Second)
		}
		return a.guardRespond(*harnessName, guard.Decision{Allow: false, Reason: t.Reason})
	}
	lf, err := a.loadLockfile()
	if err != nil {
		return a.guardRespond(*harnessName, guard.Decision{Allow: true}) // no lockfile: nothing to enforce yet
	}
	root := cwd
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	pins := guard.PinsFrom(lf)
	worktreePins(pins, root)
	dec := guard.EvaluateWith(req, pins, root, a.observedClean(lf))
	if !dec.Allow {
		// One event per offending file per day: a denial is the control working, and the same
		// file being denied twenty times in a session is one fact. The key is the file's would-be
		// lockfile key so approving/pinning the file closes the event.
		file := firstOr(dec.Unknown, dec.Changed)
		key := harness.InstructionKey(file, a.Home)
		if !recentlyRecorded(key, lockfile.ChangeInstructionBlocked, 24*time.Hour) {
			_ = cloud.RecordEvent(cloud.EventRecord{
				Source: "guard", Kind: lockfile.ChangeInstructionBlocked, Severity: lockfile.SevMedium, Harness: *harnessName,
				Key: key, Name: file, Path: file, Message: "guard denied a tool call that would load this unreviewed instruction file",
				Details: map[string]any{"tool": req.Tool, "paths": req.Paths, "command": ledgerExcerpt(req.Command), "unknown_files": dec.Unknown, "changed_files": dec.Changed, "cwd": cwd},
			})
			go a.bestEffortSync(lf, nil, "drift", false, 2*time.Second)
		}
	}
	return a.guardRespond(*harnessName, dec)
}

func firstOr(a, b []string) string {
	if len(a) > 0 {
		return a[0]
	}
	if len(b) > 0 {
		return b[0]
	}
	return ""
}

// guardRespond emits the deny/allow in each harness's dialect.
func (a *App) guardRespond(harnessName string, d guard.Decision) int {
	switch harnessName {
	case lockfile.HarnessCursor:
		if d.Allow {
			fmt.Fprintln(a.Stdout, `{"permission": "allow"}`)
		} else {
			out, _ := json.Marshal(map[string]any{"permission": "deny", "user_message": d.Reason, "agent_message": d.Reason})
			fmt.Fprintln(a.Stdout, string(out))
		}
		return ExitOK
	case lockfile.HarnessGeminiCLI:
		if d.Allow {
			return ExitOK
		}
		out, _ := json.Marshal(map[string]any{"decision": "deny", "reason": d.Reason})
		fmt.Fprintln(a.Stdout, string(out))
		fmt.Fprintln(a.Stderr, d.Reason)
		return 2 // Gemini CLI and Claude Code both treat exit 2 as "block, feed stderr to the model"
	default: // Claude Code
		if d.Allow {
			return ExitOK
		}
		out, _ := json.Marshal(map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": d.Reason,
			},
		})
		fmt.Fprintln(a.Stdout, string(out))
		return ExitOK
	}
}

var _ = os.Getenv

// recentlyRecorded reports whether a local event with this key and kind exists within window.
func recentlyRecorded(key string, kind lockfile.ChangeKind, window time.Duration) bool {
	events, _ := cloud.Events()
	cutoff := time.Now().Add(-window)
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.At.Before(cutoff) {
			break
		}
		if e.Key == key && e.Kind == kind {
			return true
		}
	}
	return false
}

func ledgerExcerpt(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
