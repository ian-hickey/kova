// Package hooks installs kova into each harness's hook system so that every session starts
// with `kova verify` and every shell command the agent runs passes through the install ledger.
package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

// Status describes hook state for one harness.
type Status struct {
	Harness   string `json:"harness"`
	Supported bool   `json:"supported"`
	Installed bool   `json:"installed"`
	File      string `json:"file,omitempty"`
	Note      string `json:"note,omitempty"`
}

func settingsFile(home, harness string) (string, bool) {
	switch harness {
	case lockfile.HarnessClaudeCode:
		return filepath.Join(home, ".claude", "settings.json"), true
	case lockfile.HarnessGeminiCLI:
		return filepath.Join(home, ".gemini", "settings.json"), true
	case lockfile.HarnessCursor:
		return filepath.Join(home, ".cursor", "hooks.json"), true
	default:
		return "", false
	}
}

const codexNote = "Codex CLI has no hook system yet. Run `kova verify` from your shell profile or a cron job; MCP servers defined in ~/.codex/config.toml are pinned by `kova verify --mcp`."

// unsupportedNote explains, per harness, why kova installs no hooks there.
func unsupportedNote(harness string) string {
	switch harness {
	case lockfile.HarnessGitHubCopilot:
		return "GitHub Copilot hooks exist for the CLI and coding agent (.github/hooks/*.json) but kova does not install into them yet; the files are pinned. Run `kova verify` from your shell profile, or wrap stdio MCP servers with `kova wrap`."
	case lockfile.HarnessClaudeDesktop:
		return "Claude Desktop has no hook system. Its MCP servers are pinned and can be routed through `kova wrap`; run `kova verify` from your shell profile."
	case lockfile.HarnessWindsurf:
		return "Windsurf Cascade hooks (~/.codeium/windsurf/hooks.json) are pinned but kova does not install into them yet. Run `kova verify` from your shell profile, or wrap stdio MCP servers with `kova wrap`."
	case lockfile.HarnessCline:
		return "Cline / Roo Code have no hook system. Their MCP servers are pinned and can be routed through `kova wrap`; run `kova verify` from your shell profile."
	default:
		return codexNote
	}
}

// Check reports current hook status for every harness.
func Check(home, kovaBin string) []Status {
	var out []Status
	for _, h := range lockfile.AllHarnesses {
		file, ok := settingsFile(home, h)
		st := Status{Harness: h, Supported: ok, File: file}
		if !ok {
			st.Note = unsupportedNote(h)
			out = append(out, st)
			continue
		}
		m, err := readJSON(file)
		if err == nil {
			st.Installed = containsKova(m["hooks"], kovaBin)
		}
		out = append(out, st)
	}
	return out
}

// Install writes kova hooks into each requested harness (idempotent; replaces older kova hooks).
func Install(home, kovaBin string, harnesses []string) ([]Status, error) {
	var out []Status
	for _, h := range harnesses {
		file, ok := settingsFile(home, h)
		if !ok {
			out = append(out, Status{Harness: h, Supported: false, Note: unsupportedNote(h)})
			continue
		}
		// Only install where the harness actually exists; don't create ~/.gemini on a machine without Gemini.
		if !dirExists(filepath.Dir(file)) {
			out = append(out, Status{Harness: h, Supported: true, File: file, Note: "harness not installed on this machine; skipped"})
			continue
		}
		m, err := readJSON(file)
		if err != nil && !os.IsNotExist(err) {
			return out, fmt.Errorf("%s: %w", file, err)
		}
		if m == nil {
			m = map[string]any{}
		}
		backup(file)
		m["hooks"] = removeKova(m["hooks"], kovaBin, h)
		m["hooks"] = addKova(m["hooks"], kovaBin, h)
		if err := writeJSON(file, m); err != nil {
			return out, err
		}
		out = append(out, Status{Harness: h, Supported: true, Installed: true, File: file})
	}
	return out, nil
}

// Uninstall removes kova hooks from each harness.
func Uninstall(home, kovaBin string, harnesses []string) ([]Status, error) {
	var out []Status
	for _, h := range harnesses {
		file, ok := settingsFile(home, h)
		if !ok || !fileExists(file) {
			out = append(out, Status{Harness: h, Supported: ok, File: file})
			continue
		}
		m, err := readJSON(file)
		if err != nil {
			return out, fmt.Errorf("%s: %w", file, err)
		}
		backup(file)
		cleaned := removeKova(m["hooks"], kovaBin, h)
		if isEmptyHooks(cleaned) {
			delete(m, "hooks")
			if h == lockfile.HarnessCursor && len(m) <= 1 { // only "version" left
				_ = os.Remove(file)
				out = append(out, Status{Harness: h, Supported: true, File: file})
				continue
			}
		} else {
			m["hooks"] = cleaned
		}
		if err := writeJSON(file, m); err != nil {
			return out, err
		}
		out = append(out, Status{Harness: h, Supported: true, File: file})
	}
	return out, nil
}

// ───────────────────────────── per-harness hook shapes ─────────────────────────────

// hookCmd builds the hook command line. The binary path is written with forward slashes: Claude
// Code and Cursor run hooks through a POSIX shell (Git Bash on Windows), where backslashes are escapes.
func hookCmd(kovaBin, args string) string { return quote(filepath.ToSlash(kovaBin)) + " " + args }

func quote(p string) string {
	if strings.ContainsAny(p, " \t\"'") {
		return `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
	}
	return p
}

func addKova(hooks any, kovaBin, harness string) any {
	m, _ := hooks.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	switch harness {
	case lockfile.HarnessClaudeCode:
		m["SessionStart"] = appendGroup(m["SessionStart"], map[string]any{
			"hooks": []any{map[string]any{"type": "command", "command": hookCmd(kovaBin, "verify --hook claude-code"), "timeout": 30}},
		})
		m["PreToolUse"] = appendGroup(m["PreToolUse"], map[string]any{
			"matcher": "Bash",
			"hooks":   []any{map[string]any{"type": "command", "command": hookCmd(kovaBin, "ledger record --harness claude-code"), "timeout": 10}},
		})
		m["PreToolUse"] = appendGroup(m["PreToolUse"], map[string]any{
			"matcher": "Read|Edit|MultiEdit|Write|Glob|Grep|Bash|NotebookEdit",
			"hooks":   []any{map[string]any{"type": "command", "command": hookCmd(kovaBin, "guard --harness claude-code"), "timeout": 10}},
		})
		m["PostToolUse"] = appendGroup(m["PostToolUse"], map[string]any{
			"matcher": "Edit|MultiEdit|Write|NotebookEdit",
			"hooks":   []any{map[string]any{"type": "command", "command": hookCmd(kovaBin, "touched --harness claude-code"), "timeout": 10}},
		})
	case lockfile.HarnessGeminiCLI:
		m["SessionStart"] = appendGroup(m["SessionStart"], map[string]any{
			"hooks": []any{map[string]any{"name": "kova-verify", "type": "command", "command": hookCmd(kovaBin, "verify --hook gemini-cli"), "timeout": 30000}},
		})
		m["BeforeTool"] = appendGroup(m["BeforeTool"], map[string]any{
			"matcher": "run_shell_command",
			"hooks":   []any{map[string]any{"name": "kova-ledger", "type": "command", "command": hookCmd(kovaBin, "ledger record --harness gemini-cli"), "timeout": 10000}},
		})
		m["BeforeTool"] = appendGroup(m["BeforeTool"], map[string]any{
			"matcher": "read_file|read_many_files|write_file|replace|glob|search_file_content|list_directory|run_shell_command",
			"hooks":   []any{map[string]any{"name": "kova-guard", "type": "command", "command": hookCmd(kovaBin, "guard --harness gemini-cli"), "timeout": 10000}},
		})
		m["AfterTool"] = appendGroup(m["AfterTool"], map[string]any{
			"matcher": "write_file|replace",
			"hooks":   []any{map[string]any{"name": "kova-touched", "type": "command", "command": hookCmd(kovaBin, "touched --harness gemini-cli"), "timeout": 10000}},
		})
	case lockfile.HarnessCursor:
		m["beforeSubmitPrompt"] = appendGroup(m["beforeSubmitPrompt"], map[string]any{"command": hookCmd(kovaBin, "verify --hook cursor")})
		m["beforeShellExecution"] = appendGroup(m["beforeShellExecution"], map[string]any{"command": hookCmd(kovaBin, "ledger record --harness cursor")})
		m["beforeReadFile"] = appendGroup(m["beforeReadFile"], map[string]any{"command": hookCmd(kovaBin, "guard --harness cursor")})
		m["afterFileEdit"] = appendGroup(m["afterFileEdit"], map[string]any{"command": hookCmd(kovaBin, "touched --harness cursor")})
	}
	return m
}

func appendGroup(existing any, group map[string]any) []any {
	arr, _ := existing.([]any)
	return append(arr, group)
}

// removeKova strips any hook entries invoking kova, preserving everything else.
func removeKova(hooks any, kovaBin, harness string) any {
	m, ok := hooks.(map[string]any)
	if !ok {
		return hooks
	}
	out := map[string]any{}
	for ev, groupsAny := range m {
		groups, ok := groupsAny.([]any)
		if !ok {
			out[ev] = groupsAny
			continue
		}
		var kept []any
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				kept = append(kept, g)
				continue
			}
			if inner, ok := gm["hooks"].([]any); ok {
				var innerKept []any
				for _, hk := range inner {
					if !isKova(hk, kovaBin) {
						innerKept = append(innerKept, hk)
					}
				}
				if len(innerKept) == 0 {
					continue
				}
				cp := map[string]any{}
				for k, v := range gm {
					cp[k] = v
				}
				cp["hooks"] = innerKept
				kept = append(kept, cp)
			} else if !isKova(g, kovaBin) {
				kept = append(kept, g)
			}
		}
		if len(kept) > 0 {
			out[ev] = kept
		}
	}
	return out
}

func isKova(h any, kovaBin string) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	cmd, _ := m["command"].(string)
	b := filepath.Base(kovaBin)
	return strings.Contains(cmd, b+" verify --hook") || strings.Contains(cmd, b+" ledger record") || strings.Contains(cmd, b+" guard ") || strings.Contains(cmd, b+" touched ")
}

func containsKova(hooks any, kovaBin string) bool {
	m, ok := hooks.(map[string]any)
	if !ok {
		return false
	}
	for _, groupsAny := range m {
		groups, _ := groupsAny.([]any)
		for _, g := range groups {
			gm, _ := g.(map[string]any)
			if isKova(g, kovaBin) {
				return true
			}
			inner, _ := gm["hooks"].([]any)
			for _, hk := range inner {
				if isKova(hk, kovaBin) {
					return true
				}
			}
		}
	}
	return false
}

func isEmptyHooks(h any) bool {
	m, ok := h.(map[string]any)
	return !ok || len(m) == 0
}

// ───────────────────────────── file helpers ─────────────────────────────

func readJSON(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func writeJSON(path string, m map[string]any) error {
	if filepath.Base(path) == "hooks.json" { // Cursor requires a version field
		if _, ok := m["version"]; !ok {
			m["version"] = 1
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func backup(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	name := fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405Z"), strings.ReplaceAll(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator), "_"))
	_ = os.WriteFile(filepath.Join(store.BackupDir(), name), b, 0o600)
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }
func dirExists(p string) bool  { st, err := os.Stat(p); return err == nil && st.IsDir() }

// HookFiles lists the settings files kova installs hooks into for this home and project: the
// files an agent must not rewrite (the guard protects them).
func HookFiles(home, cwd string) []string {
	out := []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(home, ".gemini", "settings.json"),
		filepath.Join(home, ".cursor", "hooks.json"),
	}
	if cwd != "" {
		out = append(out, filepath.Join(cwd, ".claude", "settings.json"), filepath.Join(cwd, ".claude", "settings.local.json"), filepath.Join(cwd, ".cursor", "hooks.json"))
	}
	return out
}
