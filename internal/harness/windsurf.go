package harness

import (
	"path/filepath"

	"github.com/ian-hickey/kova/internal/lockfile"
)

func windsurfPresent(c *ctx) bool { return isDir(filepath.Join(c.Home, ".codeium", "windsurf")) }

func windsurfDiscover(c *ctx) {
	h := lockfile.HarnessWindsurf
	dot := filepath.Join(c.Home, ".codeium", "windsurf")

	c.addMCPFromJSON(h, filepath.Join(dot, "mcp_config.json"), "user", "mcpServers")
	c.addFile(h, lockfile.TypeMemory, filepath.Join(dot, "memories", "global_rules.md"), "user")
	// Cascade hooks. Pinned whole (the file shape is not something kova installs into yet).
	c.addFile(h, lockfile.TypeHooks, filepath.Join(dot, "hooks.json"), "user")

	if c.CWD != "" {
		c.addFile(h, lockfile.TypeRules, c.proj(".windsurfrules"), "project")
		c.addWalk(h, lockfile.TypeRules, c.proj(".windsurf/rules"), "project", ".md")
		// Workflows are invoked as /slash commands, like Claude Code's .claude/commands.
		c.addWalk(h, lockfile.TypeCommand, c.proj(".windsurf/workflows"), "project", ".md")
		c.addFile(h, lockfile.TypeMemory, c.proj("AGENTS.md"), "project")
	}
}
