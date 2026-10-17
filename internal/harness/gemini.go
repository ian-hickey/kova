package harness

import (
	"path/filepath"

	"github.com/ian-hickey/kova/internal/lockfile"
)

func geminiPresent(c *ctx) bool { return isDir(filepath.Join(c.Home, ".gemini")) }

func geminiDiscover(c *ctx) {
	h := lockfile.HarnessGeminiCLI
	dot := filepath.Join(c.Home, ".gemini")

	settings := filepath.Join(dot, "settings.json")
	c.addMCPFromJSON(h, settings, "user", "mcpServers")
	c.addHooks(h, settings, "user")
	if c.CWD != "" {
		c.addMCPFromJSON(h, c.proj(".gemini/settings.json"), "project", "mcpServers")
		c.addHooks(h, c.proj(".gemini/settings.json"), "project")
	}

	// Extensions bundle MCP servers + context files; pin each extension directory.
	if matches, _ := filepath.Glob(filepath.Join(dot, "extensions", "*")); len(matches) > 0 {
		for _, m := range matches {
			if isDir(m) {
				c.addTree(h, lockfile.TypeExtension, filepath.Base(m), m, "user")
			}
		}
	}
	c.addSkillDirs(h, filepath.Join(dot, "skills"), "user")
	if c.CWD != "" {
		c.addSkillDirs(h, c.proj(".gemini/skills"), "project")
	}

	c.addFile(h, lockfile.TypeMemory, filepath.Join(dot, "GEMINI.md"), "user")
	if c.CWD != "" {
		c.addFile(h, lockfile.TypeMemory, c.proj("GEMINI.md"), "project")
		c.addFile(h, lockfile.TypeMemory, c.proj(".gemini/GEMINI.md"), "project")
	}
}
