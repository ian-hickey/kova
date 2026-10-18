package harness

import (
	"os"
	"path/filepath"
	"runtime"
)

// claudeManagedDir is where Claude Code reads MDM/managed policy (managed-settings.json,
// managed-mcp.json, CLAUDE.md) on this OS.
func claudeManagedDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "ClaudeCode")
		}
		return filepath.Join("C:\\", "ProgramData", "ClaudeCode")
	}
	return "/etc/claude-code"
}
