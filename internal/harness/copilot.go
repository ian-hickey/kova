package harness

import (
	"path/filepath"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// GitHub Copilot covers two surfaces that share the same project-level files: the Copilot CLI
// (~/.copilot) and Copilot agent mode inside VS Code (the VS Code user directory). Either one
// being present makes the harness present.
func copilotPresent(c *ctx) bool {
	return isDir(filepath.Join(c.Home, ".copilot")) || len(vscodeUserDirs(c.Home)) > 0
}

func copilotDiscover(c *ctx) {
	h := lockfile.HarnessGitHubCopilot

	// VS Code user profile: mcp.json uses a top-level "servers" map (not "mcpServers") whose
	// entries carry "type": stdio|http|sse. parseMCPConfig already understands that shape, so the
	// JSON path is simply ["servers", <name>] and stdio entries are wrappable.
	for _, user := range vscodeUserDirs(c.Home) {
		c.addMCPFromJSON(h, filepath.Join(user, "mcp.json"), "user", "servers")
		prompts := filepath.Join(user, "prompts")
		c.addGlob(h, lockfile.TypeCommand, filepath.Join(prompts, "*.prompt.md"), "user")
		c.addGlob(h, lockfile.TypeRules, filepath.Join(prompts, "*.instructions.md"), "user")
		c.addGlob(h, lockfile.TypeAgent, filepath.Join(prompts, "*.agent.md"), "user")
	}

	// Copilot CLI
	dot := filepath.Join(c.Home, ".copilot")
	c.addMCPFromJSON(h, filepath.Join(dot, "mcp-config.json"), "user", "mcpServers")
	c.addFile(h, lockfile.TypeConfig, filepath.Join(dot, "config.json"), "user")

	if c.CWD != "" {
		c.addFile(h, lockfile.TypeMemory, c.proj(".github/copilot-instructions.md"), "project")
		c.addWalk(h, lockfile.TypeRules, c.proj(".github/instructions"), "project", ".instructions.md")
		c.addWalk(h, lockfile.TypeCommand, c.proj(".github/prompts"), "project", ".prompt.md")
		c.addWalk(h, lockfile.TypeAgent, c.proj(".github/agents"), "project", ".agent.md")
		c.addMCPFromJSON(h, c.proj(".vscode/mcp.json"), "project", "servers")
		c.addFile(h, lockfile.TypeMemory, c.proj("AGENTS.md"), "project")
		// Copilot coding-agent / CLI hooks live in .github/hooks/*.json. Pinned as files; kova does
		// not install its own hooks there yet.
		c.addGlob(h, lockfile.TypeHooks, c.proj(".github/hooks/*.json"), "project")
	}
}
