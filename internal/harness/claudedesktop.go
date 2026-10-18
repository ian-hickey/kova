package harness

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
				c.addDesktopExtensionMCP(h, m)
			}
		}
	}
	// Claude Desktop has no hooks and reads no instruction files from disk.
}

// addDesktopExtensionMCP surfaces the MCP server an unpacked extension declares in its
// manifest.json (MCPB format: "server": {"mcp_config": {"command", "args", "env"}}). The
// extension directory is replaced on update, so the server is pinned but never rewritten;
// ${__dirname} is expanded to the extension directory so the pinned command is the real one.
func (c *ctx) addDesktopExtensionMCP(h, extDir string) {
	file := filepath.Join(extDir, "manifest.json")
	m, err := readJSON(file)
	if err != nil {
		return
	}
	server, _ := m["server"].(map[string]any)
	cfg, ok := server["mcp_config"].(map[string]any)
	if !ok {
		return
	}
	name, _ := m["name"].(string)
	if name == "" {
		name = filepath.Base(extDir)
	}
	expand := func(s string) string { return strings.ReplaceAll(s, "${__dirname}", extDir) }
	c.addMCPServersOpt(h, file, "extension", map[string]any{name: cfg}, []string{"server", "mcp_config"}, mcpOpts{
		readOnly: true,
		fix: func(mc *lockfile.MCPConfig) {
			mc.Command = expand(mc.Command)
			for i := range mc.Args {
				mc.Args[i] = expand(mc.Args[i])
			}
			for k, v := range mc.Env {
				mc.Env[k] = expand(v)
			}
		},
	})
}
