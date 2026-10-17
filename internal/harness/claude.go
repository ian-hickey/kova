package harness

import (
	"path/filepath"
	"strings"

	"github.com/ian-hickey/kova/internal/lockfile"
)

func claudePresent(c *ctx) bool {
	return isDir(filepath.Join(c.Home, ".claude")) || exists(filepath.Join(c.Home, ".claude.json"))
}

// ProjectSlug mirrors Claude Code's project directory naming under ~/.claude/projects.
func ProjectSlug(abs string) string {
	return strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-", ".", "-").Replace(abs)
}

func claudeDiscover(c *ctx) {
	h := lockfile.HarnessClaudeCode
	dot := filepath.Join(c.Home, ".claude")

	// Skills
	c.addSkillDirs(h, filepath.Join(dot, "skills"), "user")
	if p := c.proj(".claude/skills"); p != "" {
		c.addSkillDirs(h, p, "project")
	}

	// Plugins: the install manifest plus every cached plugin version that is installed.
	plugDir := filepath.Join(dot, "plugins")
	c.addFile(h, lockfile.TypePlugin, filepath.Join(plugDir, "installed_plugins.json"), "user")
	c.addFile(h, lockfile.TypePlugin, filepath.Join(plugDir, "known_marketplaces.json"), "user")
	if m, err := readJSON(filepath.Join(plugDir, "installed_plugins.json")); err == nil {
		if plugins, ok := m["plugins"].(map[string]any); ok {
			for id, versionsAny := range plugins {
				versions, _ := versionsAny.([]any)
				for _, vAny := range versions {
					v, _ := vAny.(map[string]any)
					if ip, ok := v["installPath"].(string); ok && isDir(ip) {
						c.addTree(h, lockfile.TypePlugin, id, ip, "user")
					}
				}
			}
		}
	}
	// Plugins installed from local marketplaces (repos/) that aren't in the cache.
	if matches, _ := filepath.Glob(filepath.Join(plugDir, "marketplaces", "*")); len(matches) > 0 {
		for _, m := range matches {
			if isDir(m) {
				c.addTree(h, lockfile.TypePlugin, "marketplace:"+filepath.Base(m), m, "user")
			}
		}
	}

	// MCP servers: user scope and project-local scope live in ~/.claude.json; project scope in .mcp.json
	claudeJSON := filepath.Join(c.Home, ".claude.json")
	c.addMCPFromJSON(h, claudeJSON, "user", "mcpServers")
	if c.CWD != "" {
		c.addMCPFromJSON(h, claudeJSON, "project", "projects", c.CWD, "mcpServers")
		c.addMCPFromJSON(h, c.proj(".mcp.json"), "project", "mcpServers")
	}

	// Hooks (run outside the sandbox with full user permissions)
	c.addHooks(h, filepath.Join(dot, "settings.json"), "user")
	c.addHooks(h, filepath.Join(dot, "settings.local.json"), "user")
	if c.CWD != "" {
		c.addHooks(h, c.proj(".claude/settings.json"), "project")
		c.addHooks(h, c.proj(".claude/settings.local.json"), "project")
	}

	// Memory & instruction files
	c.addFile(h, lockfile.TypeMemory, filepath.Join(dot, "CLAUDE.md"), "user")
	c.addGlob(h, lockfile.TypeRules, filepath.Join(dot, "rules", "*.md"), "user")
	if c.CWD != "" {
		c.addFile(h, lockfile.TypeMemory, c.proj("CLAUDE.md"), "project")
		c.addFile(h, lockfile.TypeMemory, c.proj("CLAUDE.local.md"), "project")
		c.addFile(h, lockfile.TypeMemory, c.proj(".claude/CLAUDE.md"), "project")
		c.addGlob(h, lockfile.TypeRules, c.proj(".claude/rules/*.md"), "project")
		c.addGlob(h, lockfile.TypeCommand, c.proj(".claude/commands/*.md"), "project")
		c.addGlob(h, lockfile.TypeCommand, c.proj(".claude/commands/*/*.md"), "project")
		c.addGlob(h, lockfile.TypeAgent, c.proj(".claude/agents/*.md"), "project")
		// Auto-memory written by Claude itself; the ClawHavoc persistence vector.
		memDir := filepath.Join(dot, "projects", ProjectSlug(c.CWD), "memory")
		c.addGlob(h, lockfile.TypeMemory, filepath.Join(memDir, "*.md"), ScopeAutoMemory)
	}
	c.addGlob(h, lockfile.TypeCommand, filepath.Join(dot, "commands", "*.md"), "user")
	c.addGlob(h, lockfile.TypeAgent, filepath.Join(dot, "agents", "*.md"), "user")
}
