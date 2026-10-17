package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ian-hickey/kova/internal/cloud"
	"github.com/ian-hickey/kova/internal/lockfile"
	"github.com/ian-hickey/kova/internal/mcp"
	"github.com/ian-hickey/kova/internal/store"
)

// cmdProxy is the entrypoint harnesses launch for wrapped stdio MCP servers:
//
//	kova proxy --name linear [--enforce] [--no-net] -- npx -y @linear/mcp
func (a *App) cmdProxy(args []string) int {
	fs := newFlags("proxy")
	name := fs.String("name", "", "server name as configured in the harness")
	enforce := fs.Bool("enforce", false, "replace a drifted tools/list with an error (default: alert and pass through)")
	noNet := fs.Bool("no-net", false, "disable network destination snapshots around tool calls")
	harnessName := fs.String("harness", "", "harness the server is configured in (for lockfile lookup)")
	if err := fs.Parse(args); err != nil {
		return a.errorf("%v", err)
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 || *name == "" {
		return a.errorf("usage: kova proxy --name <server> [--enforce] -- <command> [args]")
	}
	cfg := cloud.LoadConfig()
	doEnforce := *enforce || cfg.Enforce
	netWatch := cfg.NetWatch && !*noNet

	// Find the lockfile entry for this server (prefer the given harness, else any match by name).
	var pinned *lockfile.Entry
	var pinnedKey string
	lf, err := a.loadLockfile()
	if err == nil {
		for k, e := range lf.Entries {
			if e.Type == lockfile.TypeMCPServer && e.Name == *name && (*harnessName == "" || e.Harness == *harnessName) {
				pinned, pinnedKey = e, k
				if e.Harness == *harnessName {
					break
				}
			}
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	opts := mcp.ProxyOptions{
		Name:     *name,
		Config:   lockfile.MCPConfig{Transport: "stdio", Command: rest[0], Args: rest[1:]},
		Pinned:   pinned,
		Enforce:  doEnforce,
		NetWatch: netWatch,
		Stdin:    a.Stdin, Stdout: a.Stdout, Stderr: a.Stderr,
		OnEvent: func(ev mcp.Event) {
			rec := cloud.EventRecord{Source: "proxy", Kind: ev.Kind, Severity: ev.Severity, Key: pinnedKey, Name: *name,
				ArtifactType: lockfile.TypeMCPServer, Message: ev.Message, Details: ev.Details}
			if pinned != nil {
				rec.Harness = pinned.Harness
				rec.ExpectedHash = pinned.ToolsHash
			}
			if h, ok := ev.Details["actual_hash"].(string); ok {
				rec.ActualHash = h
			}
			_ = cloud.RecordEvent(rec)
			if lf != nil {
				go a.bestEffortSync(lf, nil, "drift", false, 3*time.Second)
			}
		},
		OnPin: func(hash string, tools []lockfile.Tool, instructions string, count int) {
			// Trust on first use: record the pin so the next session is verified against it.
			if lf == nil || pinned == nil || pinnedKey == "" {
				return
			}
			now := time.Now().UTC()
			pinned.ToolsHash, pinned.Tools, pinned.ToolsPinnedAt = hash, tools, &now
			_ = lf.Save(store.LockfilePath())
		},
	}
	if err := mcp.RunProxy(ctx, opts); err != nil {
		return a.errorf("%v", err)
	}
	return ExitOK
}
