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
	volatile := []string{"lastUpdated", "last_updated", "installedAt", "installed_at", "updatedAt", "updated_at", "lastFetched", "lastSync", "lastSyncAt", "fetchedAt", "lastRefresh", "timestamp", "lastChecked"}
	c.addJSONFile(h, lockfile.TypePlugin, filepath.Join(plugDir, "installed_plugins.json"), "user", volatile...)
	c.addJSONFile(h, lockfile.TypePlugin, filepath.Join(plugDir, "known_marketplaces.json"), "user", volatile...)
	if m, err := readJSON(filepath.Join(plugDir, "installed_plugins.json")); err == nil {
		if plugins, ok := m["plugins"].(map[string]any); ok {
			for id, versionsAny := range plugins {
				versions, _ := versionsAny.([]any)
				for _, vAny := range versions {
					v, _ := vAny.(map[string]any)
					if ip, ok := v["installPath"].(string); ok && isDir(ip) {
						c.addTree(h, lockfile.TypePlugin, id, ip, "user")
						c.addPluginMCP(h, id, ip)
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

	// MCP servers. `claude mcp add` defaults to LOCAL scope: the server is stored in the home
	// .claude.json under projects[<dir it was added from>].mcpServers, so one machine's servers are
	// spread across project directories. User scope is the top-level mcpServers; project scope is
	// the repo's .mcp.json.
	claudeJSON := filepath.Join(c.Home, ".claude.json")
	c.addMCPFromJSON(h, claudeJSON, "user", "mcpServers")
	if c.CWD != "" {
		c.addMCPFromJSON(h, claudeJSON, "project", "projects", c.CWD, "mcpServers")
		c.addMCPFromJSON(h, c.proj(".mcp.json"), "project", "mcpServers")
	}
	c.addClaudeLocalMCP(h, claudeJSON)
	// Managed (MDM-deployed) servers: pinned, never rewritten.
	managed := filepath.Join(claudeManagedDir(), "managed-mcp.json")
	if exists(managed) {
		if m, err := readJSON(managed); err == nil {
			if servers, ok := m["mcpServers"].(map[string]any); ok {
				c.addMCPServersOpt(h, managed, ScopeSystem, servers, []string{"mcpServers"}, mcpOpts{readOnly: true})
			}
		}
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

// addClaudeLocalMCP pins the local-scope servers of every project directory recorded in the home
// .claude.json except the current one (which claudeDiscover pins under plain names). Names get an
// "@<dir>" suffix so the same server added from two repos stays distinguishable, and the JSON
// path is kept exact so `kova wrap` can rewrite them.
func (c *ctx) addClaudeLocalMCP(h, claudeJSON string) {
	if !exists(claudeJSON) {
		return
	}
	m, err := readJSON(claudeJSON)
	if err != nil {
		return
	}
	projects, _ := m["projects"].(map[string]any)
	for dir, pAny := range projects {
		if c.CWD != "" && filepath.Clean(dir) == filepath.Clean(c.CWD) {
			continue
		}
		p, _ := pAny.(map[string]any)
		servers, ok := p["mcpServers"].(map[string]any)
		if !ok || len(servers) == 0 {
			continue
		}
		suffix := "@" + filepath.Base(dir)
		c.addMCPServersOpt(h, claudeJSON, "local", servers, []string{"projects", dir, "mcpServers"},
			mcpOpts{rename: func(n string) string { return n + suffix }})
	}
}

// addPluginMCP pins MCP servers a plugin ships in its own .mcp.json. The plugin cache is replaced
// on update, so these are pinned (config + tools) but never wrapped; ${CLAUDE_PLUGIN_ROOT} is
// expanded so the pinned command is the one that actually runs.
func (c *ctx) addPluginMCP(h, pluginID, root string) {
	// A plugin declares servers either in <root>/.mcp.json or in .claude-plugin/plugin.json,
	// where "mcpServers" is an inline object or a path (relative to the plugin root) to a JSON file.
	file := filepath.Join(root, ".mcp.json")
	var servers map[string]any
	jsonPath := []string{"mcpServers"}
	if m, err := readJSON(file); err == nil {
		servers, _ = m["mcpServers"].(map[string]any)
	}
	if servers == nil {
		manifest := filepath.Join(root, ".claude-plugin", "plugin.json")
		m, err := readJSON(manifest)
		if err != nil {
			return
		}
		switch v := m["mcpServers"].(type) {
		case map[string]any:
			file, servers = manifest, v
		case string:
			rel := strings.ReplaceAll(v, "${CLAUDE_PLUGIN_ROOT}", root)
			if !filepath.IsAbs(rel) {
				rel = filepath.Join(root, rel)
			}
			mm, err := readJSON(rel)
			if err != nil {
				return
			}
			file = rel
			servers, _ = mm["mcpServers"].(map[string]any)
			if servers == nil { // some files are the bare servers map
				servers = mm
				jsonPath = nil
			}
		}
	}
	if len(servers) == 0 {
		return
	}
	expand := func(s string) string { return strings.ReplaceAll(s, "${CLAUDE_PLUGIN_ROOT}", root) }
	c.addMCPServersOpt(h, file, "plugin", servers, jsonPath, mcpOpts{
		readOnly: true,
		rename:   func(n string) string { return n + "@" + pluginID },
		fix: func(cfg *lockfile.MCPConfig) {
			cfg.Command = expand(cfg.Command)
			for i := range cfg.Args {
				cfg.Args[i] = expand(cfg.Args[i])
			}
			for k, v := range cfg.Env {
				cfg.Env[k] = expand(v)
			}
		},
	})
}
