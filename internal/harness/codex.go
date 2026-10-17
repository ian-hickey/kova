package harness

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/scan"
)

func codexPresent(c *ctx) bool { return isDir(filepath.Join(c.Home, ".codex")) }

func codexDiscover(c *ctx) {
	h := lockfile.HarnessCodex
	dot := filepath.Join(c.Home, ".codex")

	// Skills (Codex reads ~/.codex/skills and the cross-agent .agents/skills convention)
	c.addSkillDirs(h, filepath.Join(dot, "skills"), "user")
	c.addSkillDirs(h, filepath.Join(c.Home, ".agents", "skills"), "user")
	if c.CWD != "" {
		c.addSkillDirs(h, c.proj(".codex/skills"), "project")
		c.addSkillDirs(h, c.proj(".agents/skills"), "project")
	}

	// MCP servers from config.toml ([mcp_servers.<name>])
	cfgFile := filepath.Join(dot, "config.toml")
	if exists(cfgFile) {
		var m map[string]any
		if _, err := toml.DecodeFile(cfgFile, &m); err != nil {
			c.warn("%s: %v", cfgFile, err)
		} else if servers, ok := m["mcp_servers"].(map[string]any); ok {
			for name, def := range servers {
				cfg, ok := parseMCPConfig(def)
				if !ok {
					continue
				}
				orig, wrapped := Unwrap(cfg, c.KovaBinary)
				configHash := lockfile.HashJSON(orig)
				e := &lockfile.Entry{Type: lockfile.TypeMCPServer, Harness: h, Name: name, Scope: "user", Path: cfgFile,
					Hash: configHash, ConfigHash: configHash, MCP: &orig}
				if wrapped {
					e.Wrapped = &orig
				}
				canon, _ := lockfile.CanonicalJSON(orig)
				c.add(e, scan.Text(c.display(cfgFile)+"#"+name, canon))
				c.res.MCP = append(c.res.MCP, MCPRef{Key: lockfile.Key(h, lockfile.TypeMCPServer, name), Name: name, Harness: h,
					Scope: "user", Config: orig, Wrapped: wrapped, ConfigFile: cfgFile, Wrappable: false})
			}
		}
		// Hooks (if a future Codex version defines them in config.toml they will be pinned here too)
		if hooks, ok := m["hooks"]; ok {
			canon, _ := lockfile.CanonicalJSON(hooks)
			c.add(&lockfile.Entry{Type: lockfile.TypeHooks, Harness: h, Name: c.display(cfgFile), Scope: "user", Path: cfgFile,
				Hash: lockfile.HashBytes(canon), Size: int64(len(canon))}, scan.Text(c.display(cfgFile), canon))
		}
	}
	c.addHooks(h, filepath.Join(dot, "hooks.json"), "user")

	// Memory / instructions
	c.addFile(h, lockfile.TypeMemory, filepath.Join(dot, "AGENTS.md"), "user")
	c.addFile(h, lockfile.TypeMemory, filepath.Join(dot, "instructions.md"), "user")
	if c.CWD != "" {
		c.addFile(h, lockfile.TypeMemory, c.proj("AGENTS.md"), "project")
		c.addFile(h, lockfile.TypeMemory, c.proj("AGENTS.override.md"), "project")
	}
	if st, err := os.Stat(filepath.Join(dot, "memories")); err == nil && st.IsDir() {
		c.addGlob(h, lockfile.TypeMemory, filepath.Join(dot, "memories", "*.md"), ScopeAutoMemory)
	}
	_ = fmt.Sprint
}
