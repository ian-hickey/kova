package harness

import (
	"os"
	"path/filepath"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// Location is one file kova looks in for MCP server definitions. `kova doctor` prints these so a
// user can see which places were checked and which exist before asking why a server is missing.
type Location struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Scope   string `json:"scope"`
	Exists  bool   `json:"exists"`
	Note    string `json:"note,omitempty"`
}

// MCPLocations lists every MCP config file discovery consults for this home/cwd.
func MCPLocations(home, cwd string) []Location {
	var out []Location
	add := func(h, p, scope, note string) {
		if p == "" {
			return
		}
		_, err := os.Stat(p)
		out = append(out, Location{Harness: h, Path: p, Scope: scope, Exists: err == nil, Note: note})
	}
	proj := func(rel string) string {
		if cwd == "" {
			return ""
		}
		return filepath.Join(cwd, rel)
	}

	h := lockfile.HarnessClaudeCode
	add(h, filepath.Join(home, ".claude.json"), "user + local", "top-level mcpServers (user) and projects[<dir>].mcpServers (local; the `claude mcp add` default)")
	add(h, proj(".mcp.json"), "project", "")
	add(h, filepath.Join(claudeManagedDir(), "managed-mcp.json"), "system", "MDM-managed; pinned, never wrapped")
	if m, err := readJSON(filepath.Join(home, ".claude", "plugins", "installed_plugins.json")); err == nil {
		if plugins, ok := m["plugins"].(map[string]any); ok {
			for id, vAny := range plugins {
				for _, v := range asList(vAny) {
					if vm, ok := v.(map[string]any); ok {
						if ip, ok := vm["installPath"].(string); ok {
							add(h, filepath.Join(ip, ".mcp.json"), "plugin", "shipped by plugin "+id+"; pinned, never wrapped")
							add(h, filepath.Join(ip, ".claude-plugin", "plugin.json"), "plugin", "plugin manifest of "+id+"; inline mcpServers are pinned, never wrapped")
						}
					}
				}
			}
		}
	}

	add(lockfile.HarnessCodex, filepath.Join(home, ".codex", "config.toml"), "user", "[mcp_servers] table; TOML is not rewritten by wrap")
	add(lockfile.HarnessGeminiCLI, filepath.Join(home, ".gemini", "settings.json"), "user", "")
	add(lockfile.HarnessGeminiCLI, proj(".gemini/settings.json"), "project", "")
	add(lockfile.HarnessCursor, filepath.Join(home, ".cursor", "mcp.json"), "user", "")
	add(lockfile.HarnessCursor, proj(".cursor/mcp.json"), "project", "")
	for _, u := range vscodeUserDirs(home) {
		add(lockfile.HarnessGitHubCopilot, filepath.Join(u, "mcp.json"), "user", "VS Code `servers` map")
	}
	add(lockfile.HarnessGitHubCopilot, proj(".vscode/mcp.json"), "project", "VS Code `servers` map")
	add(lockfile.HarnessGitHubCopilot, filepath.Join(home, ".copilot", "mcp-config.json"), "user", "Copilot CLI")
	if d := claudeDesktopDir(home); d != "" {
		add(lockfile.HarnessClaudeDesktop, filepath.Join(d, "claude_desktop_config.json"), "user", "")
		add(lockfile.HarnessClaudeDesktop, filepath.Join(d, "Claude Extensions"), "extension", "one directory per installed .mcpb/.dxt extension; its manifest.json server is pinned, never wrapped. Account-level connectors are not on disk.")
	}
	add(lockfile.HarnessWindsurf, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "user", "")
	cl, roo := clineStorageDirs(home)
	for _, d := range cl {
		add(lockfile.HarnessCline, filepath.Join(d, "settings", "cline_mcp_settings.json"), "user", "Cline")
	}
	for _, d := range roo {
		add(lockfile.HarnessCline, filepath.Join(d, "settings", "mcp_settings.json"), "user", "Roo Code")
	}
	add(lockfile.HarnessCline, proj(".roo/mcp.json"), "project", "Roo Code")
	return out
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}
