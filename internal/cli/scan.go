package cli

import (
	"context"
	"os"
	"time"

	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/mcp"
	"github.com/ian-hickey/kova/internal/scan"
)

func (a *App) cmdScan(args []string) int {
	fs := newFlags("scan")
	mcpMode := fs.Bool("mcp", false, "treat arguments after -- as an MCP server command to connect to and inspect")
	url := fs.String("url", "", "scan a remote (streamable HTTP) MCP server")
	timeout := fs.Duration("timeout", 25*time.Second, "MCP connect timeout")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}

	if *mcpMode || *url != "" {
		cfg := lockfile.MCPConfig{Transport: "stdio"}
		if *url != "" {
			cfg = lockfile.MCPConfig{Transport: "http", URL: *url}
		} else if len(rest) == 0 {
			return a.errorf("usage: kova scan --mcp -- <command> [args]")
		} else {
			cfg.Command, cfg.Args = rest[0], rest[1:]
		}
		snap, err := mcp.Connect(context.Background(), cfg, *timeout)
		if err != nil {
			return a.errorf("connect: %v", err)
		}
		type toolReport struct {
			Name     string         `json:"name"`
			Findings []scan.Finding `json:"findings,omitempty"`
		}
		var reports []toolReport
		total := 0
		for _, t := range snap.Tools {
			fs := scan.Text("tool:"+t.Name, []byte(t.Description+"\n"+string(t.InputSchema)))
			total += len(fs)
			reports = append(reports, toolReport{Name: t.Name, Findings: fs})
		}
		instrFindings := scan.Text("instructions", []byte(snap.Instructions))
		total += len(instrFindings)
		if a.JSON {
			a.json(map[string]any{"server": snap.ServerName, "version": snap.ServerVersion, "tools_hash": snap.ToolsHash,
				"tool_count": len(snap.Tools), "tools": reports, "instruction_findings": instrFindings, "finding_count": total})
		} else {
			a.printf("%s %s — %d tools, pin %s\n", snap.ServerName, snap.ServerVersion, len(snap.Tools), shortHash(snap.ToolsHash))
			for _, r := range reports {
				mark := "✓"
				if len(r.Findings) > 0 {
					mark = "✗"
				}
				a.printf("  %s %s\n", mark, r.Name)
				for _, f := range r.Findings {
					a.printf("      %s: %s%s\n", f.Rule, f.Detail, excerptSuffix(f.Excerpt))
				}
			}
			for _, f := range instrFindings {
				a.printf("  ✗ server instructions: %s: %s%s\n", f.Rule, f.Detail, excerptSuffix(f.Excerpt))
			}
		}
		if total > 0 {
			return ExitDrift
		}
		return ExitOK
	}

	if len(rest) == 0 {
		return a.errorf("usage: kova scan <path> | kova scan --mcp -- <command> [args] | kova scan --url <http-url>")
	}
	var all []scan.Finding
	for _, p := range rest {
		st, err := os.Stat(p)
		if err != nil {
			return a.errorf("%v", err)
		}
		var fs []scan.Finding
		if st.IsDir() {
			fs, err = scan.Tree(p)
		} else {
			fs, err = scan.File(p)
		}
		if err != nil {
			return a.errorf("%v", err)
		}
		all = append(all, fs...)
	}
	if a.JSON {
		a.json(map[string]any{"findings": all, "count": len(all)})
	} else if len(all) == 0 {
		a.printf("✓ no hidden characters or suspicious instructions found\n")
	} else {
		a.printf("✗ %d finding(s)\n", len(all))
		for _, f := range all {
			a.printf("  %s:%d  %s — %s%s\n", f.File, f.Line, f.Rule, f.Detail, excerptSuffix(f.Excerpt))
		}
	}
	if len(all) > 0 {
		return ExitDrift
	}
	return ExitOK
}
