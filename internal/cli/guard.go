package cli

import (
	"encoding/json"
	"fmt"
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

	lf, err := a.loadLockfile()
	if err != nil {
		return a.guardRespond(*harnessName, guard.Decision{Allow: true}) // no lockfile: nothing to enforce yet
	}
	root := cwd
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	dec := guard.Evaluate(req, guard.PinsFrom(lf), root)
	if !dec.Allow {
		_ = cloud.RecordEvent(cloud.EventRecord{
			Source: "guard", Kind: lockfile.ChangeInstructionBlocked, Severity: lockfile.SevHigh, Harness: *harnessName,
			Key: "guard:" + req.Tool, Name: firstOr(dec.Unknown, dec.Changed), Message: "blocked a tool call that would load an unreviewed instruction file",
			Details: map[string]any{"tool": req.Tool, "paths": req.Paths, "command": req.Command, "unknown_files": dec.Unknown, "changed_files": dec.Changed, "cwd": cwd},
		})
		go a.bestEffortSync(lf, nil, "drift", false, 2*time.Second)
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
