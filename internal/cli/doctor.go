package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ian-hickey/kova/internal/harness"
)

// cmdDoctor explains what discovery sees on this machine: which harnesses are present, every MCP
// config location checked, and for each discovered server whether it can be wrapped and why not.
func (a *App) cmdDoctor(args []string) int {
	fs := newFlags("doctor")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	disc, err := a.discover()
	if err != nil {
		return a.errorf("%v", err)
	}
	locs := harness.MCPLocations(a.Home, a.CWD)
	lf, _ := a.loadLockfile()

	type server struct {
		Key         string `json:"key"`
		Harness     string `json:"harness"`
		Scope       string `json:"scope"`
		Transport   string `json:"transport"`
		File        string `json:"file"`
		Wrappable   bool   `json:"wrappable"`
		Wrapped     bool   `json:"wrapped"`
		ToolsPinned bool   `json:"tools_pinned"`
		Reason      string `json:"reason"`
	}
	var servers []server
	for _, r := range disc.MCP {
		s := server{Key: r.Key, Harness: r.Harness, Scope: r.Scope, Transport: r.Config.Transport,
			File: r.ConfigFile, Wrappable: r.Wrappable, Wrapped: r.Wrapped}
		if lf != nil {
			if e := lf.Entries[r.Key]; e != nil && e.ToolsHash != "" {
				s.ToolsPinned = true
			}
		}
		switch {
		case r.Wrapped:
			s.Reason = "wrapped (proxied)"
		case r.Wrappable:
			s.Reason = "wrappable: run `kova wrap --all`"
		default:
			s.Reason = wrapReason(r, "wrap")
		}
		servers = append(servers, s)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Key < servers[j].Key })

	if a.JSON {
		a.json(map[string]any{"harnesses": disc.Harnesses, "locations": locs, "servers": servers, "warnings": disc.Warnings})
		return ExitOK
	}

	a.printf("kova %s\nhome     %s\nproject  %s\n\n", Version, a.Home, orDash(a.CWD))
	a.printf("Harnesses present: %s\n\n", strings.Join(disc.Harnesses, ", "))
	a.printf("MCP config locations checked (✓ exists, – absent):\n")
	for _, l := range locs {
		mark := "–"
		if l.Exists {
			mark = "✓"
		}
		line := fmt.Sprintf("  %s %-15s %-13s %s", mark, l.Harness, l.Scope, a.tilde(l.Path))
		if l.Note != "" {
			line += "\n" + strings.Repeat(" ", 34) + l.Note
		}
		a.printf("%s\n", line)
	}
	a.printf("\nMCP servers discovered: %d\n", len(servers))
	for _, s := range servers {
		state := "config"
		if s.ToolsPinned {
			state = "config+tools"
		}
		a.printf("  %-44s %-7s %-6s %-13s %s\n", s.Key, s.Scope, s.Transport, state, s.Reason)
	}
	if len(disc.Warnings) > 0 {
		a.printf("\nWarnings:\n")
		for _, w := range disc.Warnings {
			a.printf("  ! %s\n", w)
		}
	}
	a.printf(`
If a server you use is missing:
  - Claude Code: run ` + "`claude mcp list`" + ` inside the project where it works. Servers added with
    ` + "`claude mcp add`" + ` default to local scope and live in the home .claude.json under that
    project; kova pins every project's local servers (suffix @<dir>). Run doctor from that
    project to see its project-scope .mcp.json too.
  - IDE-managed servers (Cline, Roo, VS Code profiles) are found only in the profile directories
    listed above. MCP servers contributed by VS Code extensions, and Claude Desktop account
    connectors, are not stored on disk and cannot be pinned from outside the app.
  - Remote (http/sse) servers are pinned but not proxied. Plugin-shipped and managed servers are
    pinned but never rewritten. Only stdio servers in JSON files can be wrapped.
`)
	return ExitOK
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func (a *App) tilde(p string) string {
	if a.Home != "" && strings.HasPrefix(p, a.Home) {
		return "~" + strings.TrimPrefix(p, a.Home)
	}
	return p
}
