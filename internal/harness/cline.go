package harness

import (
	"os"
	"path/filepath"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// Cline and Roo Code (a Cline fork) are VS Code extensions with the same config shapes; both are
// reported under the single harness "cline".
const (
	clineStorage = "saoudrizwan.claude-dev"
	rooStorage   = "rooveterinaryinc.roo-cline"
)

// clineStorageDirs returns the existing globalStorage directories for Cline and Roo across every
// VS Code user directory.
func clineStorageDirs(home string) (cline, roo []string) {
	for _, user := range vscodeUserDirs(home) {
		if p := filepath.Join(user, "globalStorage", clineStorage); isDir(p) {
			cline = append(cline, p)
		}
		if p := filepath.Join(user, "globalStorage", rooStorage); isDir(p) {
			roo = append(roo, p)
		}
	}
	return cline, roo
}

func clinePresent(c *ctx) bool {
	cline, roo := clineStorageDirs(c.Home)
	return len(cline)+len(roo) > 0
}

func clineDiscover(c *ctx) {
	h := lockfile.HarnessCline
	clineDirs, rooDirs := clineStorageDirs(c.Home)

	for _, d := range clineDirs {
		c.addMCPFromJSON(h, filepath.Join(d, "settings", "cline_mcp_settings.json"), "user", "mcpServers")
	}
	for _, d := range rooDirs {
		c.addMCPFromJSON(h, filepath.Join(d, "settings", "mcp_settings.json"), "user", "mcpServers")
	}
	// Global rules
	c.addGlob(h, lockfile.TypeRules, filepath.Join(c.Home, "Documents", "Cline", "Rules", "*.md"), "user")
	c.addWalk(h, lockfile.TypeRules, filepath.Join(c.Home, ".roo", "rules"), "user", ".md")

	if c.CWD != "" {
		// .clinerules is either a single file or a directory of markdown files.
		if rules := c.proj(".clinerules"); isDir(rules) {
			c.addWalk(h, lockfile.TypeRules, rules, "project", ".md")
		} else if st, err := os.Stat(rules); err == nil && !st.IsDir() {
			c.addFile(h, lockfile.TypeRules, rules, "project")
		}
		c.addWalk(h, lockfile.TypeRules, c.proj(".roo/rules"), "project", ".md")
		c.addFile(h, lockfile.TypeRules, c.proj(".roomodes"), "project")
		c.addMCPFromJSON(h, c.proj(".roo/mcp.json"), "project", "mcpServers")
		c.addFile(h, lockfile.TypeMemory, c.proj("AGENTS.md"), "project")
	}
}
