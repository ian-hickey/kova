package harness

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/ian-hickey/kova/internal/lockfile"
)

// claudeDesktopDir returns the Claude Desktop config directory if it exists. Every platform
// layout is probed so fixtures built with the macOS layout work everywhere.
func claudeDesktopDir(home string) string {
	candidates := []string{
		filepath.Join(home, "Library", "Application Support", "Claude"), // macOS
		filepath.Join(home, ".config", "Claude"),                        // Linux
	}
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			candidates = append([]string{filepath.Join(appdata, "Claude")}, candidates...)
		}
	}
	for _, p := range candidates {
		if isDir(p) {
			return p
		}
	}
	return ""
}

func claudeDesktopPresent(c *ctx) bool { return claudeDesktopDir(c.Home) != "" }

func claudeDesktopDiscover(c *ctx) {
	h := lockfile.HarnessClaudeDesktop
	dir := claudeDesktopDir(c.Home)
	if dir == "" {
		return
	}

	// MCP servers (user scope; stdio entries are wrappable like any JSON config).
	c.addMCPFromJSON(h, filepath.Join(dir, "claude_desktop_config.json"), "user", "mcpServers")

	// Desktop Extensions (.dxt / .mcpb bundles) are unpacked one directory per extension.
	if matches, _ := filepath.Glob(filepath.Join(dir, "Claude Extensions", "*")); len(matches) > 0 {
		for _, m := range matches {
			if isDir(m) {
				c.addTree(h, lockfile.TypePlugin, filepath.Base(m), m, "user")
			}
		}
	}
	// Claude Desktop has no hooks and reads no instruction files from disk.
}
