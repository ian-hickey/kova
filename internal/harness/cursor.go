package harness

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ian-hickey/kova/internal/lockfile"
)

func cursorPresent(c *ctx) bool { return isDir(filepath.Join(c.Home, ".cursor")) }

func cursorDiscover(c *ctx) {
	h := lockfile.HarnessCursor
	dot := filepath.Join(c.Home, ".cursor")

	c.addMCPFromJSON(h, filepath.Join(dot, "mcp.json"), "user", "mcpServers")
	c.addHooks(h, filepath.Join(dot, "hooks.json"), "user")
	c.addSkillDirs(h, filepath.Join(dot, "skills"), "user")
	c.addSkillDirs(h, filepath.Join(dot, "skills-cursor"), "user")

	if c.CWD != "" {
		c.addMCPFromJSON(h, c.proj(".cursor/mcp.json"), "project", "mcpServers")
		c.addHooks(h, c.proj(".cursor/hooks.json"), "project")
		c.addFile(h, lockfile.TypeRules, c.proj(".cursorrules"), "project")
		c.addFile(h, lockfile.TypeMemory, c.proj("AGENTS.md"), "project")
		c.addSkillDirs(h, c.proj(".cursor/skills"), "project")
		// Rules can be nested: .cursor/rules/**/*.mdc
		rulesRoot := c.proj(".cursor/rules")
		_ = filepath.WalkDir(rulesRoot, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(p, ".mdc") || strings.HasSuffix(p, ".md") {
				c.addFile(h, lockfile.TypeRules, p, "project")
			}
			return nil
		})
	}
}
