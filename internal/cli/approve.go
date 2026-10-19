package cli

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/store"
)

func (a *App) cmdApprove(args []string) int {
	fs := newFlags("approve")
	all := fs.Bool("all", false, "accept every detected change")
	withMCP := fs.Bool("mcp", false, "re-pin tool definitions for approved MCP servers by connecting to them")
	mcpTimeout := fs.Duration("mcp-timeout", 25*time.Second, "per-server timeout")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	keys := fs.Args()
	if !*all && len(keys) == 0 {
		return a.errorf("specify entry keys (as printed by `kova verify`), `mcp:<name>`, or --all")
	}

	if why := notHuman(); why != "" {
		return a.errorf("approve is a human decision and must run in your own terminal: %s. (Set KOVA_ALLOW_AGENT_APPROVE=1 only for scripted provisioning you control.)", why)
	}
	lf, err := a.loadLockfile()
	if err != nil {
		return a.errorf("%v", err)
	}
	disc, err := a.discover()
	if err != nil {
		return a.errorf("%v", err)
	}
	// Account connectors live in `claude mcp list`, not on disk: carry the pinned ones (or a recent
	// inventory) into the live set, exactly as verify does, so `approve --all` never mistakes an
	// unqueried connector for a removed one and drops its pin.
	a.mergeConnectors(disc, lf, false, true)
	active := map[string]bool{}
	if a.CWD != "" {
		active[a.CWD] = true
	}
	changes := lockfile.Diff(lf.Entries, disc.Entries, active)

	matches := func(key string) bool {
		if *all {
			return true
		}
		for _, k := range keys {
			if k == key {
				return true
			}
			// shorthand: mcp:<name>, skill:<name>, or just the trailing name
			if strings.HasPrefix(k, "mcp:") && strings.Contains(key, ":mcp_server:"+strings.TrimPrefix(k, "mcp:")) {
				return true
			}
			if strings.HasPrefix(k, "skill:") && strings.Contains(key, ":skill:"+strings.TrimPrefix(k, "skill:")) {
				return true
			}
			if strings.HasSuffix(key, ":"+k) {
				return true
			}
			// A path or a bare file name: match the entry it names.
			if e := disc.Entries[key]; e != nil && e.Path != "" {
				if filepath.Clean(k) == filepath.Clean(e.Path) || filepath.Base(k) == k && filepath.Base(e.Path) == k {
					return true
				}
				if a.tilde(filepath.Clean(k)) == a.tilde(filepath.Clean(e.Path)) {
					return true
				}
			}
			if strings.HasSuffix(key, "/"+k) {
				return true
			}
		}
		return false
	}

	now := time.Now().UTC()
	approved := 0
	var mcpKeys []string
	for _, c := range changes {
		if !matches(c.Key) {
			continue
		}
		approved++
		live := disc.Entries[c.Key]
		if live == nil {
			// Approving a removal (artifact_removed, mcp_server_removed, a hooks or connector entry
			// that disappeared) drops the stale pin; otherwise it would be reported again forever.
			delete(lf.Entries, c.Key)
			continue
		}
		if prev, ok := lf.Entries[c.Key]; ok {
			live.FirstSeen = prev.FirstSeen
			if live.Type == lockfile.TypeMCPServer && c.Kind != lockfile.ChangeMCPTools {
				live.ToolsHash, live.Tools, live.ToolsPinnedAt = prev.ToolsHash, prev.Tools, prev.ToolsPinnedAt
			}
		}
		live.Approved = true
		live.UpdatedAt = now
		lf.Entries[c.Key] = live
		if live.Hash != "" && live.Type != lockfile.TypeMCPServer {
			if lf.ApprovedHashes == nil {
				lf.ApprovedHashes = map[string]string{}
			}
			if _, seen := lf.ApprovedHashes[live.Hash]; !seen {
				lf.ApprovedHashes[live.Hash] = c.Key
			}
		}
		if live.Type == lockfile.TypeMCPServer {
			mcpKeys = append(mcpKeys, c.Key)
		}
	}

	// Explicitly named MCP servers with no config change still get a tools re-pin when requested
	// (this is how you accept an intended tools/list change caught by the proxy).
	for _, k := range keys {
		if strings.HasPrefix(k, "mcp:") {
			name := strings.TrimPrefix(k, "mcp:")
			for key, e := range lf.Entries {
				if e.Type == lockfile.TypeMCPServer && e.Name == name && !contains(mcpKeys, key) {
					mcpKeys = append(mcpKeys, key)
					e.Approved = true
					approved++
				}
			}
		}
	}

	repinned := 0
	if len(mcpKeys) > 0 && (*withMCP || *all || anyMCPNamed(keys)) {
		var refs = disc.MCP[:0:0]
		for _, r := range disc.MCP {
			if contains(mcpKeys, r.Key) {
				refs = append(refs, r)
			}
		}
		for _, r := range a.pinMCP(refs, lf, *mcpTimeout, false) {
			if r.err != nil {
				a.printf("  ✗ %s: %v\n", r.ref.Key, r.err)
			} else {
				repinned++
				a.printf("  ✓ re-pinned %s (%d tools, %s)\n", r.ref.Key, r.toolCount, shortHash(r.hash))
			}
		}
	}

	if err := lf.Save(store.LockfilePath()); err != nil {
		return a.errorf("save: %v", err)
	}
	a.bestEffortSync(lf, disc.Harnesses, "", true, 6*time.Second)
	if a.JSON {
		a.json(map[string]any{"approved": approved, "repinned_mcp": repinned, "entries": len(lf.Entries)})
		return ExitOK
	}
	if approved == 0 {
		a.printf("Nothing matched. Run `kova verify` to list pending changes and pass a key exactly as printed\n")
		a.printf("(quote keys that contain ~ so the shell does not expand it), a file path, or a bare file name.\n")
		for _, k := range keys {
			if strings.HasPrefix(k, "claude-code:memory:/") || strings.HasPrefix(k, "claude-code:rules:/") {
				a.printf("Hint: %q looks like a key whose ~ was expanded by your shell; try quoting it.\n", k)
			}
		}
		return ExitDrift
	}
	a.printf("Approved %d change(s). Lockfile now pins %d artifacts.\n", approved, len(lf.Entries))
	return ExitOK
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func anyMCPNamed(keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, "mcp:") || strings.Contains(k, ":mcp_server:") {
			return true
		}
	}
	return false
}

// notHuman explains why this process does not look like a person at a terminal: it is running
// inside an agent session (Claude Code and friends export marker variables into the shells they
// spawn) or its stdin is not a TTY. Empty when it is fine to approve.
func notHuman() string {
	if os.Getenv("KOVA_ALLOW_AGENT_APPROVE") == "1" {
		return ""
	}
	if why := agentSession(); why != "" {
		return why
	}
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice == 0 {
		return "stdin is not a terminal"
	}
	return ""
}

// agentSession reports the harness environment variable that says this process was started by
// an agent, or "" when none is set. Scripts and CI pass; agent tool calls do not.
func agentSession() string {
	for _, v := range []string{"CLAUDECODE", "CLAUDE_CODE", "CURSOR_AGENT", "GEMINI_CLI", "CODEX_SANDBOX", "COPILOT_AGENT"} {
		if os.Getenv(v) != "" {
			return "running inside an agent session (" + v + " is set)"
		}
	}
	return ""
}
